// End to end on the fake scanner: nothing installed, every run state reachable.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, readdirSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { scan, loadScope, ScopeError } from '../lib/scan.mjs';

function tmpRoot() {
  return mkdtempSync(join(tmpdir(), 'ai-sec-'));
}

function writeScope(root, slug, scope) {
  const dir = join(root, '.sec', slug);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'scope.json'), JSON.stringify(scope), 'utf8');
}

const base = (root, over = {}) => ({
  root, slug: 'test', scanners: ['fake'], baseline: 'none', ...over,
});

test('a default T0 run completes and produces the two-layer result', async (t) => {
  const root = tmpRoot();
  t.after(() => rmSync(root, { recursive: true, force: true }));

  const out = await scan(base(root));
  assert.equal(out.ok, true);
  assert.equal(out.run_state, 'done');
  assert.equal(out.exit_code, 0);

  const r = out.result;
  assert.equal(r.schema, 'sec-result/v1');
  assert.ok(r.rules.length > 0, 'rules[] catalogue is populated');
  assert.ok(r.findings.length > 0, 'findings[] is populated');

  // two layers: every finding points at a rule, and no finding repeats the background
  for (const f of r.findings) {
    assert.ok(r.rules.some((rule) => rule.rule_id === f.rule_id), `no rule for ${f.rule_id}`);
    assert.equal(f.background, undefined, 'instance must not carry type-level prose');
  }
  assert.equal(r.standards.owasp_top10, '2025');
});

test('no secret reaches any artifact on disk', async (t) => {
  const root = tmpRoot();
  t.after(() => rmSync(root, { recursive: true, force: true }));

  const out = await scan(base(root));
  const files = walk(out.runDir);
  assert.ok(files.length > 0);
  for (const f of files) {
    const text = readFileSync(f, 'utf8');
    assert.ok(!text.includes('AKIAIOSFODNN7EXAMPLE'), `secret leaked into ${f}`);
  }
  // and it is present in redacted form, so we know the path was exercised
  const findings = JSON.parse(readFileSync(join(out.runDir, 'findings.json'), 'utf8'));
  const cred = findings.find((x) => x.rule_id === 'hardcoded-credential');
  assert.match(cred.evidence, /<redacted:aws-access-key:20:AKIA>/);
});

test('a clean scan that reported coverage is done', async (t) => {
  const root = tmpRoot();
  t.after(() => rmSync(root, { recursive: true, force: true }));

  const out = await scan(base(root, { scanner_options: { fake: { mode: 'clean' } } }));
  assert.equal(out.run_state, 'done');
  assert.equal(out.result.findings.length, 0);
});

test('a scanner that examined nothing makes the run degraded, not done', async (t) => {
  const root = tmpRoot();
  t.after(() => rmSync(root, { recursive: true, force: true }));

  const out = await scan(base(root, { scanner_options: { fake: { mode: 'nothing' } } }));
  assert.equal(out.run_state, 'not_evaluable');
  assert.notEqual(out.exit_code, 0, 'silence must never exit 0');
});

test('a failing scanner makes the run degraded or worse', async (t) => {
  const root = tmpRoot();
  t.after(() => rmSync(root, { recursive: true, force: true }));

  const out = await scan(base(root, { scanner_options: { fake: { mode: 'fail' } } }));
  assert.notEqual(out.run_state, 'done');
  assert.notEqual(out.exit_code, 0);
  const joined = out.result.not_evaluable.map((n) => n.reason).join(' ');
  assert.match(joined, /exited|error/i);
});

test('a timeout is recorded and never passes', async (t) => {
  const root = tmpRoot();
  t.after(() => rmSync(root, { recursive: true, force: true }));

  const out = await scan(base(root, { scanner_options: { fake: { mode: 'timeout' } } }));
  assert.notEqual(out.run_state, 'done');
  const joined = out.result.not_evaluable.map((n) => n.reason).join(' ');
  assert.match(joined, /timed out/);
});

test('the gates run before anything is written', async (t) => {
  const root = tmpRoot();
  t.after(() => rmSync(root, { recursive: true, force: true }));
  writeScope(root, 'test', { max_tier: 'T0', environment: 'prod-eu', production: false });

  const out = await scan(base(root));
  assert.equal(out.ok, false);
  assert.equal(out.exit_code, 2);
  assert.equal(out.refused.gate, 'G1-production');
  assert.throws(() => readdirSync(join(root, '.sec', 'test', 'runs')), 'no run folder may exist');
});

test('a spec may not raise its own ceiling', async (t) => {
  const root = tmpRoot();
  t.after(() => rmSync(root, { recursive: true, force: true }));

  const out = await scan({ ...base(root), max_tier: 'T4', tier: 'T4' });
  assert.equal(out.exit_code, 2);
  assert.equal(out.refused.gate, 'G4-spec-override');
});

test('a tier above the ceiling is refused even without an override', async (t) => {
  const root = tmpRoot();
  t.after(() => rmSync(root, { recursive: true, force: true }));

  const out = await scan(base(root, { tier: 'T3' }));
  assert.equal(out.exit_code, 2);
  assert.equal(out.refused.gate, 'G3-tier-ceiling');
});

test('an unreadable target is not evaluable, not clean', async (t) => {
  const root = tmpRoot();
  t.after(() => rmSync(root, { recursive: true, force: true }));

  const out = await scan(base(root, { target_path: join(root, 'does-not-exist') }));
  assert.equal(out.run_state, 'not_evaluable');
  assert.equal(out.exit_code, 3);
});

test('the second run compares against a baseline', async (t) => {
  const root = tmpRoot();
  t.after(() => rmSync(root, { recursive: true, force: true }));

  const first = await scan(base(root));
  const baseline = { findings: first.result.findings };

  const second = await scan(base(root, { baseline }));
  assert.equal(second.result.summary.new, 0, 'nothing is new the second time');
  assert.equal(second.result.summary.unchanged, first.result.findings.length);
  for (const f of second.result.findings) {
    assert.ok(['unchanged', 'updated'].includes(f.baseline_state));
  }
});

test('a baseline false positive is not re-reported', async (t) => {
  const root = tmpRoot();
  t.after(() => rmSync(root, { recursive: true, force: true }));

  const first = await scan(base(root));
  const target = first.result.findings[0];
  const baseline = {
    findings: [{ ...target, status: 'false_positive', reason: 'reviewed and dismissed' }],
  };

  const second = await scan(base(root, { baseline }));
  const same = second.result.findings.find((f) => f.fingerprint === target.fingerprint);
  assert.equal(same.status, 'false_positive');
  assert.equal(second.result.summary.suppressed, 1);
});

test('scanCommand and parse are given the same directory', async (t) => {
  // A report written where parse does not look loses every finding, silently.
  // Found by scanning ai-sec with ai-sec: gitleaks said "leaks found: 2" and the
  // run reported none, because the two halves disagreed about the path.
  const root = tmpRoot();
  t.after(() => rmSync(root, { recursive: true, force: true }));

  const seen = { command: null, parse: null };
  const probeAdapter = {
    name: 'pathcheck', tool: 'pathcheck', tiers: ['T0'], modules: ['M1'],
    detect: async () => ({ ok: true, version: '1' }),
    scanCommand: ({ runDir: d }) => {
      seen.command = d;
      return { cmd: process.execPath, args: ['-e', 'process.stdout.write("{}")'], timeout_s: 30 };
    },
    parse: async ({ runDir: d }) => {
      seen.parse = d;
      return { findings: [], coverage: [{ kind: 'files', detail: 'x', count: 1 }], errors: [] };
    },
  };

  const { SCANNERS } = await import('../adapters/index.mjs');
  SCANNERS.pathcheck = probeAdapter;
  try {
    await scan(base(root, { scanners: ['pathcheck'] }));
    assert.ok(seen.command, 'scanCommand was never called');
    assert.equal(seen.command, seen.parse,
      'scanCommand and parse must receive the same directory');
  } finally {
    delete SCANNERS.pathcheck;
  }
});

test('a byte-order mark in scope.json does not crash the tool', async (t) => {
  const root = tmpRoot();
  t.after(() => rmSync(root, { recursive: true, force: true }));

  // what Notepad and Windows PowerShell leave behind
  const dir = join(root, '.sec', 'test');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'scope.json'), `﻿${JSON.stringify({ max_tier: 'T0', environment: 'local' })}`, 'utf8');

  const out = await scan(base(root));
  assert.equal(out.ok, true, 'an invisible character must not break the run');
  assert.equal(out.run_state, 'done');
});

test('malformed scope.json gives a readable error, not a stack trace', (t) => {
  const root = tmpRoot();
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const dir = join(root, '.sec', 'test');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'scope.json'), '{ not json', 'utf8');

  assert.throws(() => loadScope(root, 'test'), (e) => {
    assert.ok(e instanceof ScopeError);
    assert.match(e.message, /is not valid JSON/);
    return true;
  });
});

test('auto-stop aborts the run when traffic leaves the recorded scope', async (t) => {
  const root = tmpRoot();
  t.after(() => rmSync(root, { recursive: true, force: true }));
  writeScope(root, 'test', {
    max_tier: 'T2', environment: 'local', allow_hosts: ['127.0.0.1'],
    authorization: { basis: 'practice-app', granted_at: new Date().toISOString().slice(0, 10) },
  });

  const out = await scan(base(root, {
    tier: 'T2', target: 'repo', scanner_options: { fake: { mode: 'hostile' } },
  }));

  assert.equal(out.run_state, 'aborted', 'an out-of-scope request must stop the run');
  assert.equal(out.exit_code, 5);
  assert.equal(out.result.auto_stop.rule, 'out-of-scope-host');
  assert.ok(out.result.not_evaluable.some((n) => /auto-stopped/.test(n.reason)),
    'the ledger must record what the stop left unexamined');
});

test('a T0 run has no signals to evaluate, and is not aborted by them', async (t) => {
  const root = tmpRoot();
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const out = await scan(base(root, { scanner_options: { fake: { mode: 'hostile' } } }));
  assert.equal(out.run_state, 'done', 'T0 sends nothing, so there is no traffic to stop');
  assert.equal(out.result.auto_stop, undefined);
});

function walk(dir) {
  const out = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) out.push(...walk(p));
    else out.push(p);
  }
  return out;
}

test('a scanner that refuses the target does not cover the modules it claims', async (t) => {
  // "Installed" and "ran" are different questions, and a module counted as
  // covered by a scanner that never ran is the quietest kind of pass there is.
  const root = tmpRoot();
  t.after(() => rmSync(root, { recursive: true, force: true }));

  let ran = false;
  const refuses = {
    name: 'refuser', tool: 'refuser', tiers: ['T0'], modules: ['M11'],
    detect: async () => ({ ok: true, version: '1' }),
    preflight: async () => ({ ok: false, reason: 'this target is not one it can read', unblock: 'point it elsewhere' }),
    scanCommand: () => {
      ran = true;
      return { cmd: process.execPath, args: ['-e', 'process.stdout.write("{}")'], timeout_s: 30 };
    },
    parse: async () => ({ findings: [], coverage: [{ kind: 'files', detail: 'x', count: 1 }], errors: [] }),
  };

  const { SCANNERS } = await import('../adapters/index.mjs');
  SCANNERS.refuser = refuses;
  try {
    const out = await scan(base(root, { scanners: ['fake', 'refuser'], modules: ['M1', 'M11'] }));
    assert.equal(ran, false, 'a refused scanner is not run');

    const ledger = out.result.not_evaluable;
    assert.ok(ledger.some((n) => n.check === 'scanner refuser' && /not one it can read/.test(n.reason)));
    assert.ok(ledger.some((n) => n.check === 'module M11'),
      'the module it would have covered is uncovered, because it did not run');
  } finally {
    delete SCANNERS.refuser;
  }
});

test('a scanner with no preflight is unaffected', async (t) => {
  const root = tmpRoot();
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const out = await scan(base(root));
  assert.equal(out.run_state, 'done');
  assert.ok(!out.result.not_evaluable.some((n) => /^scanner fake$/.test(n.check)));
});
