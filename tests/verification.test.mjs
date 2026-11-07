// The step whose job is to fail a finding. docs/verification.md.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  checkVerification, applyVerification, unverified, verificationSummary,
  VERDICTS, CONFIRMING_METHODS,
} from '../controller/verification.mjs';

const finding = (over = {}) => ({
  fingerprint: 'a'.repeat(64),
  rule_id: 'sql-injection',
  severity: 'High',
  confidence: 'Firm',
  status: 'open',
  tools: ['builtin', 'semgrep'],
  ...over,
});

const good = {
  verdict: 'confirmed',
  verifier: 'luan',
  method: 'reproduced',
  reason: 'sent the payload against a local instance and read another order back',
};

test('the one who checks is never the one who found it', () => {
  for (const tool of ['builtin', 'SEMGREP']) {
    const r = checkVerification(finding(), { ...good, verifier: tool });
    assert.equal(r.ok, false);
    assert.match(r.error, /cannot verify it/);
  }
  assert.equal(checkVerification(finding(), good).ok, true);
});

test('a finding that does not say who reported it cannot be verified at all', () => {
  // Not knowing is not the same as knowing it was someone else. The first version
  // read an absent `tools` and found no conflict, so `builtin` confirmed its own
  // SQL injection.
  const r = checkVerification(finding({ tools: [] }), good);
  assert.equal(r.ok, false);
  assert.match(r.error, /independence cannot be/);
  assert.match(r.error, /promote/, 'and it says what would fix it');
});

test('confirmed needs evidence that can establish it', () => {
  for (const method of ['source-trace', 'manual-review']) {
    const r = checkVerification(finding(), { ...good, method });
    assert.equal(r.ok, false);
    assert.match(r.error, /needs_validation instead/);
  }
  for (const method of CONFIRMING_METHODS) {
    assert.equal(checkVerification(finding(), { ...good, method }).ok, true);
  }
});

test('reading the code cannot confirm what reading the code produced', () => {
  assert.ok(!CONFIRMING_METHODS.includes('source-trace'));
});

test('an anonymous verdict is refused', () => {
  const r = checkVerification(finding(), { ...good, verifier: '  ' });
  assert.equal(r.ok, false);
  assert.match(r.error, /names who made it/);
});

test('a verdict carries a reason', () => {
  const r = checkVerification(finding(), { ...good, verdict: 'rejected', method: 'manual-review', reason: 'nah' });
  assert.equal(r.ok, false);
  assert.match(r.error, /reason/);
});

test('an unknown verdict or method is refused rather than stored', () => {
  assert.equal(checkVerification(finding(), { ...good, verdict: 'probably' }).ok, false);
  assert.equal(checkVerification(finding(), { ...good, method: 'vibes' }).ok, false);
  assert.deepEqual(VERDICTS, ['confirmed', 'needs_validation', 'rejected']);
});

// --- what a verdict does to the finding

test('needs_validation drops the severity and keeps what it would have been', () => {
  // A severity is a claim about demonstrated impact, and a blocked hypothesis has
  // demonstrated nothing. This project shipped Critical/Tentative twice: once for
  // a dropdown label, once for a PKCE challenge.
  const out = applyVerification(finding(), {
    verdict: 'needs_validation', verifier: 'luan', method: 'source-trace',
    reason: 'no running instance to try it against',
  });
  assert.equal(out.severity, null);
  assert.equal(out.potential_severity, 'High');
  assert.equal(out.status, 'open', 'it is still open; nobody has settled it');
  assert.match(out.blocked_on, /no running instance/);
});

test('rejected suppresses the finding and keeps the reason', () => {
  const out = applyVerification(finding(), {
    verdict: 'rejected', verifier: 'luan', method: 'manual-review',
    reason: 'the table name is a constant, so no input reaches the query',
  });
  assert.equal(out.status, 'false_positive');
  assert.equal(out.severity, null);
  assert.match(out.suppressed_reason, /constant/);
});

test('confirmed by reproduction is what Certain has always meant', () => {
  const out = applyVerification(finding({ confidence: 'Firm' }), good);
  assert.equal(out.confidence, 'Certain');
  assert.equal(out.severity, 'High', 'a confirmed finding keeps its severity');
  assert.equal(out.verification.verifier, 'luan');
  assert.ok(out.verification.at, 'and when it was decided');
});

// --- a run nobody checked is not a clean run

test('findings nobody has tried to break are counted', () => {
  const open = [
    finding(),
    finding({ fingerprint: 'b'.repeat(64), verification: { verdict: 'confirmed' } }),
    finding({ fingerprint: 'c'.repeat(64), status: 'false_positive' }),
  ];
  assert.equal(unverified(open).length, 1, 'suppressed findings are not awaiting a verdict');
  assert.deepEqual(verificationSummary(open), {
    confirmed: 1, needs_validation: 0, rejected: 0, unverified: 1,
  });
});
