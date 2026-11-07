// A scanner that ran and still could not do one of its jobs.
//
// This is the quietest failure the bundle has: trivy against a repository with
// no lockfile reports zero dependency CVEs, and zero reads exactly like clean.
// OWASP Juice Shop is that repository — M2 sat at `unmeasured` for two
// milestones and nothing in the output said why.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import trivy, { dependencyManifests, DEPENDENCY_MANIFESTS } from '../adapters/scanners/trivy/adapter.mjs';
import { buildLedger } from '../lib/coverage.mjs';
import { scan } from '../lib/scan.mjs';
import { scorecard, grade, GRADES, benchmarkFor } from '../lib/scorecard.mjs';

function temp(files) {
  const dir = mkdtempSync(join(tmpdir(), 'sec-degraded-'));
  for (const [rel, body] of Object.entries(files)) {
    const full = join(dir, rel);
    mkdirSync(join(full, '..'), { recursive: true });
    writeFileSync(full, body, 'utf8');
  }
  return dir;
}

test('a range is not a version: package.json alone is not a manifest trivy can resolve', () => {
  assert.equal(DEPENDENCY_MANIFESTS.has('package.json'), false);
  assert.equal(DEPENDENCY_MANIFESTS.has('package-lock.json'), true);

  const dir = temp({ 'package.json': '{"dependencies":{"express":"^4.17.0"}}' });
  try {
    assert.deepEqual(dependencyManifests(dir), []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a lockfile anywhere under the target counts', () => {
  const dir = temp({ 'services/api/package-lock.json': '{}' });
  try {
    assert.deepEqual(dependencyManifests(dir), ['services/api/package-lock.json']);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('an installed tree counts, and node_modules is not walked to find it', () => {
  const dir = temp({
    'node_modules/.package-lock.json': '{}',
    'node_modules/express/package-lock.json': '{}', // would be found if we walked in
  });
  try {
    assert.deepEqual(dependencyManifests(dir), ['node_modules/.package-lock.json']);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('preflight does not skip trivy: misconfig and secrets still run without a lockfile', async () => {
  const dir = temp({ 'package.json': '{}' });
  try {
    const pf = await trivy.preflight({ target: { root: dir } });
    assert.equal(pf.ok, true, 'a missing lockfile must not cost the whole scanner');
    assert.equal(pf.degraded.length, 1);
    assert.deepEqual(pf.degraded[0].modules, ['M2']);
    assert.match(pf.degraded[0].capability, /dependency/i);
    assert.match(pf.degraded[0].reason, /nothing was read, not/i);
    assert.ok(pf.degraded[0].unblock.length > 20, 'a gap with no way out is a complaint, not a ledger entry');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('with a lockfile there is nothing to report', async () => {
  const dir = temp({ 'package-lock.json': '{"lockfileVersion":3}' });
  try {
    const pf = await trivy.preflight({ target: { root: dir } });
    assert.equal(pf.ok, true);
    assert.equal(pf.degraded, undefined);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a degraded capability reaches the coverage ledger', () => {
  const ledger = buildLedger({
    results: [{ name: 'trivy', parsed: { findings: [], coverage: [{ kind: 'files', detail: 'x' }] } }],
    degraded: [{
      scanner: 'trivy', capability: 'dependency CVEs', modules: ['M2'],
      reason: 'no lockfile', unblock: 'commit one',
    }],
  });
  const entry = ledger.not_evaluable.find((e) => e.check === 'trivy: dependency CVEs');
  assert.ok(entry, 'a capability that could not run must be in the ledger');
  assert.equal(entry.reason, 'no lockfile');
  assert.deepEqual(entry.modules, ['M2']);
});

test('a blind module is not graded `failing`: that would blame the rules', () => {
  assert.equal(grade({ planted: 3, found: 0, installed: 1, blind: false }), 'failing');
  assert.equal(grade({ planted: 3, found: 0, installed: 1, blind: true }), 'blind');
  assert.equal(grade({ planted: 0, found: 0, installed: 1, blind: true }), 'blind');
  assert.equal(grade({ planted: 0, found: 0, installed: 1, blind: false }), 'unmeasured');
});

test('a blind capability that cost nothing does not downgrade a module that found everything', () => {
  assert.equal(
    grade({ planted: 2, found: 2, installed: 1, blind: true, benchmarkTrust: 'external' }),
    'measured',
  );
});

test('`blind` ranks below `unmeasured` and above `no-engine`', () => {
  assert.equal(GRADES.indexOf('blind'), GRADES.indexOf('no-engine') + 1);
  assert.ok(GRADES.indexOf('blind') < GRADES.indexOf('unmeasured'));
});

test('the scorecard turns the run\'s degradation into a blind spot on that module', () => {
  const rows = scorecard({
    findings: [],
    expected: { defects: [{ id: 'dep', modules: ['M2'], cwe: 'CWE-1104' }] },
    engines: { trivy: { modules: ['M2'], installed: true } },
    modules: ['M2'],
    degraded: [{
      scanner: 'trivy', capability: 'dependency CVEs', modules: ['M2'],
      reason: 'no lockfile was found', unblock: 'commit one',
    }],
  });
  assert.equal(rows[0].grade, 'blind');
  assert.equal(rows[0].blind_spots.length, 1);
  assert.match(rows[0].blind_spots[0], /trivy could not check dependency CVEs/);
  assert.match(rows[0].blind_spots[0], /no lockfile was found/);
});

test('a module nothing reported degraded is graded exactly as before', () => {
  const rows = scorecard({
    findings: [],
    expected: { defects: [{ id: 'dep', modules: ['M2'], cwe: 'CWE-1104' }] },
    engines: { trivy: { modules: ['M2'], installed: true } },
    modules: ['M2'],
    degraded: [],
  });
  assert.equal(rows[0].grade, 'failing');
  assert.deepEqual(rows[0].blind_spots, []);
});

// ---------------------------------------------------------------------------
// `expected.json` is a conventional filename, not a reserved one.

test('a target that ships its own expected.json is not read as an answer key', () => {
  const dir = temp({ 'expected.json': '{"cases":[{"input":1,"output":2}]}' });
  try {
    const b = benchmarkFor({ target: { path: dir } });
    assert.deepEqual(b.expected, {}, 'somebody else\'s fixture must not become our scorecard');
    assert.match(b.source, /ignored/);
    assert.match(b.source, /defects/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a malformed answer key reports itself instead of taking the command down', () => {
  const dir = temp({ 'expected.json': '{ not json' });
  try {
    const b = benchmarkFor({ target: { path: dir } });
    assert.deepEqual(b.expected, {});
    assert.match(b.source, /not valid JSON/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a real answer key still declares its own trust', () => {
  const ours = temp({ 'expected.json': JSON.stringify({ defects: [{ id: 'a' }] }) });
  const theirs = temp({ 'expected.json': JSON.stringify({ corpus: 'OWASP/juice-shop', defects: [{ id: 'a' }] }) });
  try {
    assert.equal(benchmarkFor({ target: { path: ours } }).trust, 'self');
    assert.equal(benchmarkFor({ target: { path: theirs } }).trust, 'external');
    assert.match(benchmarkFor({ target: { path: theirs } }).source, /code we did not write/);
  } finally {
    rmSync(ours, { recursive: true, force: true });
    rmSync(theirs, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// End to end: an adapter's partial refusal has to survive the whole run, or the
// only place it exists is a log line nobody reads.

test('a partial refusal survives the run: result, ledger, and the report', async (t) => {
  const root = mkdtempSync(join(tmpdir(), 'ai-sec-degraded-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));

  const out = await scan({
    root, slug: 'test', scanners: ['fake'], baseline: 'none',
    scanner_options: { fake: { blind: 'dependency CVEs', blind_modules: ['M2'] } },
  });

  assert.equal(out.ok, true, 'a blind capability is not a failed run');
  assert.deepEqual(out.result.degraded.map((d) => d.scanner), ['fake']);
  assert.deepEqual(out.result.degraded[0].modules, ['M2']);

  const entry = out.result.not_evaluable.find((e) => e.check === 'fake: dependency CVEs');
  assert.ok(entry, 'the ledger is where a reader looks for what was not checked');
  assert.match(entry.unblock, /drop the `blind` option/);
});

test('without the option the same run carries nothing', async (t) => {
  const root = mkdtempSync(join(tmpdir(), 'ai-sec-degraded-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));

  const out = await scan({ root, slug: 'test', scanners: ['fake'], baseline: 'none' });
  assert.deepEqual(out.result.degraded, []);
  assert.equal(out.result.not_evaluable.some((e) => /dependency CVEs/.test(e.check)), false);
});
