// Memory across runs â€” pillar P2.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { promote, verify, judge, readBaseline, appendLesson, readLessons, lessonsFile } from '../lib/baseline.mjs';

// Fingerprints are sha256 hex in real runs; short stand-ins hide prefix bugs.
const FP_A = 'a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1';
const FP_B = 'b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2';

const result = (over = {}) => ({
  run_id: 'r1',
  run_state: 'done',
  scope: { environment: 'local', tier: 'T0' },
  standards: { owasp_top10: '2025' },
  findings: [
    { fingerprint: FP_A, rule_id: 'sql-injection', severity: 'High', confidence: 'Firm', status: 'open', location: { file: 'a.js' } },
    { fingerprint: FP_B, rule_id: 'weak-randomness', severity: 'Medium', confidence: 'Tentative', status: 'open', location: { file: 'b.js' } },
  ],
  not_evaluable: [],
  ...over,
});

function tmp(t) {
  const root = mkdtempSync(join(tmpdir(), 'ai-sec-bl-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return root;
}

test('a done run can be promoted', (t) => {
  const root = tmp(t);
  const r = promote(root, 's', result());
  assert.equal(r.ok, true);
  assert.equal(r.count, 2);
  assert.equal(readBaseline(root, 's').findings.length, 2);
});

test('a degraded run may not become a baseline', (t) => {
  const root = tmp(t);
  const r = promote(root, 's', result({ run_state: 'degraded' }));
  assert.equal(r.ok, false);
  assert.match(r.reason, /only a done run/);
  assert.equal(readBaseline(root, 's'), null);
});

test('--force can override, because sometimes you mean it', (t) => {
  const root = tmp(t);
  assert.equal(promote(root, 's', result({ run_state: 'degraded' }), { force: true }).ok, true);
});

test('a human verdict survives the next promotion', (t) => {
  const root = tmp(t);
  promote(root, 's', result());
  judge(root, 's', FP_B, 'false_positive', 'only ever used for a cache key');

  // a later run promotes again; the judgement must not be lost
  const r = promote(root, 's', result({ run_id: 'r2' }));
  assert.equal(r.carried, 1);
  const after = readBaseline(root, 's').findings.find((f) => f.fingerprint === FP_B);
  assert.equal(after.status, 'false_positive');
  assert.match(after.reason, /cache key/);
});

test('judge accepts the short fingerprint the report actually prints', (t) => {
  // The report prints 12 characters; asking for all 64 is a tax on doing the right thing.
  const root = tmp(t);
  promote(root, 's', result({
    findings: [{ fingerprint: 'abcdef0123456789aaaa', rule_id: 'x', severity: 'High', confidence: 'Firm', status: 'open', location: {} }],
  }));
  const r = judge(root, 's', 'abcdef012345', 'false_positive', 'fixture');
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.fingerprint, 'abcdef0123456789aaaa', 'it resolves to the full hash');
});

test('an ambiguous prefix is refused rather than guessed', (t) => {
  const root = tmp(t);
  promote(root, 's', result({
    findings: [
      { fingerprint: 'abcdef0000000001', rule_id: 'x', severity: 'High', confidence: 'Firm', status: 'open', location: {} },
      { fingerprint: 'abcdef0000000002', rule_id: 'y', severity: 'High', confidence: 'Firm', status: 'open', location: {} },
    ],
  }));
  const r = judge(root, 's', 'abcdef00', 'false_positive', 'x');
  assert.equal(r.ok, false);
  assert.match(r.reason, /matches 2 findings/);
});

test('too short a prefix is refused', (t) => {
  const root = tmp(t);
  promote(root, 's', result());
  // 'a1a1' matches FP_A, but four characters collide too easily to act on
  const r = judge(root, 's', 'a1a1', 'fixed', 'x');
  assert.equal(r.ok, false);
  assert.match(r.reason, /at least 8 characters/);
});

test('judging an unknown fingerprint is refused, not silently ignored', (t) => {
  const root = tmp(t);
  promote(root, 's', result());
  // long enough to pass the length check, so this tests "unknown", not "too short"
  const r = judge(root, 's', 'c3c3c3c3c3c3c3c3', 'false_positive', 'x');
  assert.equal(r.ok, false);
});

test('an unknown status is refused', (t) => {
  const root = tmp(t);
  promote(root, 's', result());
  assert.equal(judge(root, 's', FP_A, 'probably-fine', 'x').ok, false);
});

test('judging before there is a baseline is refused', (t) => {
  const root = tmp(t);
  assert.equal(judge(root, 's', FP_A, 'fixed', 'x').ok, false);
});

test('lessons accumulate under a dated heading', (t) => {
  const root = tmp(t);
  appendLesson(root, 's', 'Tenant scoping lives in BaseRepository.scoped().');
  appendLesson(root, 's', ['legacy/ is dead code.', 'migrations/ take no user input.']);

  const text = readLessons(root, 's');
  assert.match(text, /# Lessons/);
  assert.match(text, /BaseRepository\.scoped/);
  assert.match(text, /legacy\/ is dead code/);
  assert.equal((text.match(/^## \d{4}-/gm) ?? []).length, 2);
});

test('a lesson carrying a credential is refused outright', (t) => {
  const root = tmp(t);
  const r = appendLesson(root, 's', 'the staging key is AKIAIOSFODNN7EXAMPLE');
  assert.equal(r.ok, false);
  assert.match(r.reason, /credential/);
  assert.equal(readLessons(root, 's'), null);
});

test('the baseline file never contains a secret', (t) => {
  const root = tmp(t);
  promote(root, 's', result({
    findings: [{ fingerprint: FP_A, rule_id: 'hardcoded-credential', severity: 'Critical', confidence: 'Firm', status: 'open', location: { file: 'c.js' }, evidence: 'AKIAIOSFODNN7EXAMPLE' }],
  }));
  const text = readFileSync(join(root, '.sec', 's', 'baseline', 'local.json'), 'utf8');
  assert.ok(!text.includes('AKIAIOSFODNN7EXAMPLE'));
});

test('lessons and baseline live where the next run will look', (t) => {
  const root = tmp(t);
  appendLesson(root, 's', 'x');
  assert.equal(lessonsFile(root, 's'), join(root, '.sec', 's', 'lessons.md'));
});

const verifiable = (over = {}) => ({
  run_id: '20260101-000000-aaaa',
  run_state: 'done',
  scope: { environment: 'local' },
  findings: [{
    fingerprint: 'd4'.repeat(32), rule_id: 'sql-injection',
    location: { file: 'db.js', line: 8 },
    severity: 'High', confidence: 'Firm', status: 'open', tools: ['builtin'],
    ...over,
  }],
  not_evaluable: [],
});

test('the baseline records which tool reported a finding', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'ai-sec-verify0-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));

  promote(root, 'p', verifiable());
  assert.deepEqual(readBaseline(root, 'p', 'local').findings[0].tools, ['builtin'],
    'without this, verify cannot tell whether the verifier is the finder');
});

test('a verification is recorded through the baseline, with the same care as judge', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'ai-sec-verify-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const fp = 'd4'.repeat(32);
  promote(root, 'p', verifiable());

  const own = verify(root, 'p', fp.slice(0, 12), {
    verdict: 'confirmed', verifier: 'builtin', method: 'reproduced',
    reason: 'the tool that reported it must not be the one that confirms it',
  });
  assert.equal(own.ok, false, 'independence is checked against the baseline, not only in memory');

  const short = verify(root, 'p', 'd4', {
    verdict: 'rejected', verifier: 'luan', method: 'manual-review',
    reason: 'a constant table name, so no input reaches it',
  });
  assert.equal(short.ok, false);
  assert.match(short.reason, /8 characters/);

  const ok = verify(root, 'p', fp.slice(0, 12), {
    verdict: 'needs_validation', verifier: 'luan', method: 'source-trace',
    reason: 'no running instance to try it against',
  });
  assert.equal(ok.ok, true);

  const stored = readBaseline(root, 'p', 'local').findings[0];
  assert.equal(stored.verification.verdict, 'needs_validation');
  assert.equal(stored.severity, null, 'a blocked hypothesis has demonstrated nothing');
  assert.equal(stored.potential_severity, 'High');
});

test('a verification reason is redacted before it is stored', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'ai-sec-verify2-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const fp = 'd4'.repeat(32);
  promote(root, 'p', verifiable({ rule_id: 'hardcoded-credential', tools: ['gitleaks'] }));

  verify(root, 'p', fp.slice(0, 12), {
    verdict: 'rejected', verifier: 'luan', method: 'manual-review',
    reason: 'it is the published documentation key AKIAIOSFODNN7EXAMPLE, not ours',
  });

  const stored = readBaseline(root, 'p', 'local').findings[0];
  assert.ok(!JSON.stringify(stored).includes('AKIAIOSFODNN7EXAMPLE'),
    'a reason explaining a secret must not carry the secret into the baseline');
  assert.match(stored.verification.reason, /redacted/);
});
