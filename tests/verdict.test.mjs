// The verdict, and the one rule that matters: could-not-look is not found-nothing.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { verdict, atOrAbove, BAR } from '../lib/verdict.mjs';

const result = (over = {}) => ({
  run_state: 'done',
  standards: { wstg: 'v4.2', asvs: '5.0.0', owasp_top10: '2025', cvss: '3.1' },
  findings: [],
  not_evaluable: [],
  ...over,
});

const f = (over = {}) => ({
  fingerprint: 'fp', rule_id: 'r', severity: 'High', confidence: 'Firm',
  status: 'open', baseline_state: 'unchanged', location: { file: 'a.js', line: 1 }, ...over,
});

const emptyBaseline = { findings: [] };

test('a clean run with full coverage passes', () => {
  const v = verdict(result(), { baseline: emptyBaseline });
  assert.equal(v.outcome, 'PASS');
  assert.equal(v.exit_code, 0);
  assert.match(v.summary, /every selected check was evaluated/);
});

test('a PASS with a non-empty ledger says so first', () => {
  const v = verdict(result({ not_evaluable: [{ check: 'module M7', reason: 'no scanner' }] }), { baseline: emptyBaseline });
  assert.equal(v.outcome, 'PASS');
  assert.match(v.notes[0], /qualified/);
  assert.equal(v.coverage_gaps, 1);
});

test('not_evaluable outranks the findings', () => {
  const v = verdict(result({ run_state: 'not_evaluable', findings: [f()] }), { baseline: emptyBaseline });
  assert.equal(v.outcome, 'NOT_EVALUABLE');
  assert.equal(v.exit_code, 3);
});

test('an aborted run is never a pass', () => {
  const v = verdict(result({ run_state: 'aborted' }), { baseline: emptyBaseline });
  assert.equal(v.outcome, 'NOT_EVALUABLE');
});

test('no baseline is NOT_EVALUABLE until bootstrapped', () => {
  assert.equal(verdict(result(), { baseline: null }).outcome, 'NOT_EVALUABLE');
  assert.equal(verdict(result(), { baseline: null, bootstrap: true }).outcome, 'PASS');
});

test('a degraded run can still fail, and says it is degraded', () => {
  const v = verdict(result({ run_state: 'degraded', findings: [f()] }), { baseline: emptyBaseline });
  assert.equal(v.outcome, 'FAIL');
  assert.ok(v.notes.some((n) => /degraded/.test(n)));
});

test('High/Firm fails; High/Tentative only warns', () => {
  assert.equal(verdict(result({ findings: [f()] }), { baseline: emptyBaseline }).outcome, 'FAIL');
  assert.equal(
    verdict(result({ findings: [f({ confidence: 'Tentative' })] }), { baseline: emptyBaseline }).outcome,
    'WARN',
  );
});

test('Medium warns however confident we are', () => {
  const v = verdict(result({ findings: [f({ severity: 'Medium', confidence: 'Certain' })] }), { baseline: emptyBaseline });
  assert.equal(v.outcome, 'WARN');
  assert.equal(v.exit_code, 0);
});

test('a new finding over the bar is called out as new', () => {
  const v = verdict(result({ findings: [f({ baseline_state: 'new' })] }), { baseline: emptyBaseline });
  assert.equal(v.outcome, 'FAIL');
  assert.match(v.summary, /new finding/);
});

test('a suppressed finding does not fail the run, but is listed', () => {
  const v = verdict(
    result({ findings: [f({ status: 'false_positive', suppressed_reason: 'migration only' })] }),
    { baseline: emptyBaseline },
  );
  assert.equal(v.outcome, 'PASS');
  assert.equal(v.suppressed.length, 1);
  assert.equal(v.suppressed[0].reason, 'migration only');
});

test('Low findings alone do not warn', () => {
  const v = verdict(result({ findings: [f({ severity: 'Low', confidence: 'Firm' })] }), { baseline: emptyBaseline });
  assert.equal(v.outcome, 'PASS');
});

test('the bar is severity AND confidence', () => {
  assert.equal(atOrAbove(f({ severity: 'Critical', confidence: 'Certain' }), BAR), true);
  assert.equal(atOrAbove(f({ severity: 'Critical', confidence: 'Tentative' }), BAR), false);
  assert.equal(atOrAbove(f({ severity: 'Medium', confidence: 'Certain' }), BAR), false);
});

test('the verdict always names the standards it was scored against', () => {
  const v = verdict(result(), { baseline: emptyBaseline });
  assert.equal(v.standards.owasp_top10, '2025');
});

// --- hardening notes must not be able to fail a build on their own

const hardeningResult = (findings) => ({
  run_state: 'done', standards: { wstg: '4.2', asvs: '5.0.0', owasp_top10: '2025', cvss: '3.1' },
  not_evaluable: [], findings,
});

test('a missing security header alone does not fail or warn', () => {
  const v = verdict(hardeningResult([
    {
      fingerprint: 'a'.repeat(64), rule_id: 'missing-referrer-policy', finding_class: 'hardening',
      severity: 'Medium', confidence: 'Firm', status: 'open', baseline_state: 'new', location: { file: '/' },
    },
  ]), { bootstrap: true });

  assert.equal(v.outcome, 'PASS', 'a layer that is missing while another holds is not a way in');
  assert.equal(v.hardening.length, 1, 'and it is still reported in full');
  assert.match(v.notes.join(' '), /hardening note/);
});

test('a hardening note never hides a real finding', () => {
  const v = verdict(hardeningResult([
    {
      fingerprint: 'a'.repeat(64), rule_id: 'missing-referrer-policy', finding_class: 'hardening',
      severity: 'Medium', confidence: 'Firm', status: 'open', baseline_state: 'new', location: { file: '/' },
    },
    {
      fingerprint: 'b'.repeat(64), rule_id: 'sql-injection', finding_class: 'vulnerability',
      severity: 'High', confidence: 'Firm', status: 'open', baseline_state: 'new', location: { file: 'db.js', line: 8 },
    },
  ]), { bootstrap: true });

  assert.equal(v.outcome, 'FAIL');
  assert.equal(v.findings.length, 1);
  assert.equal(v.findings[0].rule_id, 'sql-injection');
});

test('an undeclared class is treated as a vulnerability, so the gate cannot be dodged', () => {
  const v = verdict(hardeningResult([
    {
      fingerprint: 'c'.repeat(64), rule_id: 'sql-injection',
      severity: 'High', confidence: 'Firm', status: 'open', baseline_state: 'new', location: { file: 'db.js', line: 8 },
    },
  ]), { bootstrap: true });
  assert.equal(v.outcome, 'FAIL');
});
