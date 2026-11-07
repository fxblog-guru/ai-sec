// nuclei and zap each have two ways to run, and they are not equivalent. Nothing here executes
// either of them: the spawn is injected, so the tests describe the decision
// rather than the machine they happen to run on.
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import nuclei, { resolveRunner, resetRunner, isLoopback, IMAGE } from '../adapters/scanners/nuclei/adapter.mjs';
import zap, { resolveZap, resetZap } from '../adapters/scanners/zap/adapter.mjs';

beforeEach(() => { resetRunner(); resetZap(); });

const native = () => ({ error: null, status: 0, stdout: 'v3.11.1\n', stderr: '' });
const missing = () => ({ error: new Error('ENOENT'), status: null, stdout: '', stderr: '' });
const image = () => ({ error: null, status: 0, stdout: '3.11.1\n', stderr: '' });
const noImage = () => ({ error: null, status: 1, stdout: '', stderr: 'No such image' });

const spawner = (map) => (cmd) => (map[cmd] ?? missing)();

test('the binary on PATH wins; the container is the fallback', () => {
  const r = resolveRunner({ spawn: spawner({ nuclei: native, docker: image }) });
  assert.equal(r.kind, 'native');
});

test('without the binary, a pulled image is enough to run', () => {
  const r = resolveRunner({ spawn: spawner({ docker: image }) });
  assert.equal(r.kind, 'docker');
  // The image's own version label, not the tag we asked for: a tag is a name
  // somebody can move.
  assert.match(r.version, /3\.11\.1/);
});

test('neither is "not installed", and the install line names both routes', async () => {
  resolveRunner({ spawn: spawner({ docker: noImage }) });
  const d = await nuclei.detect();
  assert.equal(d.ok, false);
  assert.match(d.install, /docker pull/);
  assert.match(d.install, /projectdiscovery/);
});

test('detect says which route it found, because the two are not the same tool', async () => {
  resolveRunner({ spawn: spawner({ docker: image }) });
  const d = await nuclei.detect();
  assert.equal(d.ok, true);
  assert.equal(d.runner, 'docker');
});

// --- the loopback refusal

test('inside a container 127.0.0.1 is the container, so the run is refused', async () => {
  resolveRunner({ spawn: spawner({ docker: image }) });
  const pf = await nuclei.preflight({ target: { root: 'http://127.0.0.1:8080' } });
  assert.equal(pf.ok, false);
  assert.match(pf.reason, /container/);
  assert.match(pf.unblock, /binary/);
});

test('the refusal is about the container, not about loopback', async () => {
  resolveRunner({ spawn: spawner({ nuclei: native }) });
  const pf = await nuclei.preflight({ target: { root: 'http://127.0.0.1:8080' } });
  assert.equal(pf.ok, true, 'the binary reaches the host loopback perfectly well');
});

test('a host the container can reach is not refused', async () => {
  resolveRunner({ spawn: spawner({ docker: image }) });
  const pf = await nuclei.preflight({ target: { root: 'http://staging.example.test' } });
  assert.equal(pf.ok, true);
});

test('the target is never rewritten to reach it', async () => {
  // host.docker.internal is the usual workaround and it sends traffic to a name
  // that was never checked against scope.allow_hosts. A refusal is the honest
  // answer; a rewrite is a scanner choosing its own target.
  resolveRunner({ spawn: spawner({ docker: image }) });
  const cmd = nuclei.scanCommand({ target: { root: 'http://staging.example.test' }, tier: 'T2' });
  assert.ok(!JSON.stringify(cmd).includes('host.docker.internal'));
  assert.ok(cmd.args.includes('http://staging.example.test'));
});

test('isLoopback knows the names for this machine', () => {
  for (const o of ['http://127.0.0.1:1', 'http://localhost', 'http://[::1]:7', 'http://0.0.0.0:3000']) {
    assert.equal(isLoopback(o), true, o);
  }
  assert.equal(isLoopback('http://example.test'), false);
  assert.equal(isLoopback('not a url'), false);
});

// --- the command itself

test('the container run is the same scan, wrapped', () => {
  resolveRunner({ spawn: spawner({ docker: image }) });
  const cmd = nuclei.scanCommand({ target: { root: 'http://staging.example.test' }, tier: 'T2' });
  assert.equal(cmd.cmd, 'docker');
  assert.deepEqual(cmd.args.slice(0, 3), ['run', '--rm', '--network']);
  assert.ok(cmd.args.includes(IMAGE));
  assert.ok(cmd.args.includes('-no-interactsh'), 'out-of-band needs its own conversation, either way');
  assert.ok(cmd.args.includes('-exclude-tags'), 'and T2 still excludes the intrusive templates');
});

test('the image is pinned, so a baseline is taken against a known version', () => {
  assert.match(IMAGE, /:v\d+\.\d+\.\d+$/, '`latest` moves under the baseline without saying so');
});

// --- zap: installed is not the same as able to run this scan
//
// The desktop package and the container are not interchangeable. The packaged
// `zap-baseline.py` is a thing the container has; a winget install gives you
// `zap.bat`, which has no passive-only mode at all. Before this, `detect` found
// zap.bat, said yes, and the run then failed with "zap-baseline.py ENOENT".

test('zap names which runner it found', async () => {
  resetZap();
  resolveZap({ spawn: (cmd) => (cmd === 'zap.bat' ? { error: null, status: 0 } : { error: new Error('ENOENT') }) });
  const d = await zap.detect();
  assert.equal(d.ok, true);
  assert.equal(d.runner, 'desktop');
});

test('a desktop install cannot run the passive baseline, and says so', async () => {
  resetZap();
  resolveZap({ spawn: (cmd) => (cmd === 'zap.bat' ? { error: null, status: 0 } : { error: new Error('ENOENT') }) });
  const pf = await zap.preflight({ tier: 'T1' });
  assert.equal(pf.ok, false);
  assert.match(pf.reason, /baseline/i);
  assert.match(pf.unblock, /container|T3/i);
});

test('the packaged scripts can, and are preferred', async () => {
  resetZap();
  resolveZap({ spawn: (cmd) => (cmd === 'zap-baseline.py' ? { error: null, status: 0 } : { error: new Error('ENOENT') }) });
  assert.equal((await zap.detect()).runner, 'packaged');
  assert.equal((await zap.preflight({ tier: 'T1' })).ok, true);
  const cmd = zap.scanCommand({ runDir: 'd', target: { root: 'http://127.0.0.1:1' }, tier: 'T1' });
  assert.equal(cmd.cmd, 'zap-baseline.py');
});

test('the desktop runner is an active scan, so it is T3 and nothing less', async () => {
  resetZap();
  resolveZap({ spawn: (cmd) => (cmd === 'zap.bat' ? { error: null, status: 0 } : { error: new Error('ENOENT') }) });
  assert.equal((await zap.preflight({ tier: 'T3' })).ok, true);
  const cmd = zap.scanCommand({ runDir: 'd', target: { root: 'http://127.0.0.1:1' }, tier: 'T3' });
  assert.equal(cmd.cmd, 'zap.bat');
  assert.ok(cmd.args.includes('-cmd'), 'headless, not the desktop window');
  assert.ok(cmd.args.includes('-quickurl'));
});
