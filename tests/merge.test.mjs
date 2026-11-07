// Findings are merged, never summed. CONTRACTS §7.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  mergeFindings, resolveConfidence, maxSeverity, diffBaseline, summarize, confidenceFor,
} from '../controller/merge.mjs';
import { fingerprint, normalizedLocation } from '../controller/fingerprint.mjs';

const at = (file, symbol, line) => ({ file, symbol, line });

const partial = (over = {}) => ({
  rule_id: 'sql-injection',
  location: at('src/db.js', 'getOrder', 10),
  insertion_point: { kind: 'body-parameter', name: 'id' },
  severity: 'High',
  detection_method: 'pattern',
  tool: 'tool-a',
  ...over,
});

test('the same issue from two tools is one finding, not two', () => {
  const out = mergeFindings([
    partial({ tool: 'tool-a' }),
    partial({ tool: 'tool-b' }),
  ]);
  assert.equal(out.length, 1);
  assert.equal(out[0].sources.length, 2);
});

test('severity is the highest proposed, never averaged', () => {
  const out = mergeFindings([
    partial({ severity: 'Low', tool: 'a' }),
    partial({ severity: 'Critical', tool: 'b' }),
  ]);
  assert.equal(out[0].severity, 'Critical');
  assert.equal(maxSeverity(['Low', 'Medium', 'Info']), 'Medium');
});

test('a tool severity never becomes the final severity', () => {
  const out = mergeFindings([partial({ severity: 'Medium', reported_severity: 'CRITICAL' })]);
  assert.equal(out[0].severity, 'Medium');
  assert.equal(out[0].sources[0].reported_severity, 'CRITICAL');
});

test('confidence follows the detection method', () => {
  assert.equal(confidenceFor('pattern'), 'Tentative');
  assert.equal(confidenceFor('dataflow'), 'Firm');
  assert.equal(confidenceFor('config'), 'Firm');
  assert.equal(confidenceFor('reproduced'), 'Certain');
  assert.equal(confidenceFor('out-of-band'), 'Certain');
});

test('two tools using the SAME technique do not promote confidence', () => {
  const conf = resolveConfidence([
    { detection_method: 'pattern' },
    { detection_method: 'pattern' },
  ]);
  assert.equal(conf, 'Tentative', 'same technique twice is one piece of evidence');
});

test('two tools using DIFFERENT techniques promote Tentative to Firm', () => {
  const conf = resolveConfidence([
    { detection_method: 'pattern' },
    { detection_method: 'config' },
  ]);
  assert.equal(conf, 'Firm');
});

test('corroboration never reaches Certain on its own', () => {
  const conf = resolveConfidence([
    { detection_method: 'pattern' },
    { detection_method: 'dataflow' },
    { detection_method: 'config' },
  ]);
  assert.equal(conf, 'Firm');
});

test('Certain is reached only by reproduction or an out-of-band interaction', () => {
  assert.equal(resolveConfidence([{ detection_method: 'reproduced' }]), 'Certain');
  assert.equal(resolveConfidence([{ detection_method: 'out-of-band' }]), 'Certain');
  assert.equal(resolveConfidence([{ detection_method: 'dataflow' }]), 'Firm');
});

test('a line shift does not change the fingerprint when the symbol resolves', () => {
  const a = fingerprint({ rule_id: 'x', location: at('src/db.js', 'getOrder', 10), insertion_point: null });
  const b = fingerprint({ rule_id: 'x', location: at('src/db.js', 'getOrder', 99), insertion_point: null });
  assert.equal(a, b);
});

test('a different insertion point is a different finding', () => {
  const out = mergeFindings([
    partial({ insertion_point: { kind: 'body-parameter', name: 'id' } }),
    partial({ insertion_point: { kind: 'body-parameter', name: 'name' } }),
  ]);
  assert.equal(out.length, 2);
});

test('path separators are normalized so Windows and POSIX agree', () => {
  assert.equal(normalizedLocation({ file: 'src\\db.js', line: 3 }), 'src/db.js:3');
  assert.equal(normalizedLocation({ file: './src/db.js', symbol: 'f' }), 'src/db.js#f');
});

test('a baseline false positive is suppressed by fingerprint, not by rule', () => {
  const one = partial({ location: at('src/db.js', 'getOrder', 10) });
  const two = partial({ location: at('src/other.js', 'getThing', 20) });
  const fp = fingerprint(one);

  const out = mergeFindings([one, two], {
    baseline: { findings: [{ fingerprint: fp, status: 'false_positive', reason: 'migration only' }] },
  });
  const suppressed = out.filter((f) => f.status === 'false_positive');
  assert.equal(suppressed.length, 1, 'only the matching fingerprint is suppressed');
  assert.equal(out.filter((f) => f.status === 'open').length, 1, 'the sibling stays open');
});

test('diffBaseline reports new, unchanged and fixed', () => {
  const current = mergeFindings([partial({ location: at('a.js', 'f', 1) })]);
  const baseline = {
    findings: [
      { fingerprint: current[0].fingerprint, severity: 'High', confidence: 'Tentative', status: 'open' },
      { fingerprint: 'gone-fingerprint', severity: 'Low', confidence: 'Firm', status: 'open' },
    ],
  };
  const diff = diffBaseline(current, baseline);
  assert.equal(diff.new, 0);
  assert.equal(diff.unchanged, 1);
  assert.equal(diff.fixed, 1);
});

test('with no baseline everything is new', () => {
  const current = mergeFindings([partial()]);
  const diff = diffBaseline(current, null);
  assert.equal(diff.new, 1);
  assert.equal(current[0].baseline_state, 'new');
});

test('the summary is a severity x confidence matrix, and excludes suppressed findings', () => {
  const one = partial({ location: at('a.js', 'f', 1), detection_method: 'dataflow' });
  const two = partial({ location: at('b.js', 'g', 1), severity: 'Low' });
  const s = summarize(mergeFindings([one, two], {
    baseline: { findings: [{ fingerprint: fingerprint(two), status: 'false_positive' }] },
  }));
  assert.equal(s.by_severity_confidence.High.Firm, 1);
  assert.equal(s.by_severity_confidence.Low.Tentative, 0);
  assert.equal(s.suppressed, 1);
});

// --- the distinction a CWE family cannot make

const header = (id, subtype, cwe = 'CWE-200') => ({
  rule_id: id,
  rule: { classification: { cwe: [cwe] } },
  location: at('/', null, null),
  insertion_point: null,
  severity: 'Low',
  detection_method: 'config',
  subtype,
  tool: 'probe',
});

test('two defects of one family at one location stay two findings when the adapter says so', () => {
  // Referrer-Policy and X-Powered-By are both CWE-200 on `/`. Merging them kept
  // whichever arrived first and silently dropped the other, which is how the
  // dynamic benchmark found seven planted header defects and reported four.
  const out = mergeFindings([
    header('missing-referrer-policy', 'referrer-policy'),
    header('technology-banner', 'x-powered-by'),
  ]);
  assert.equal(out.length, 2, 'two different fixes are two defects');
});

test('the same defect from two tools still merges, because the subtype names the defect', () => {
  const out = mergeFindings([
    header('missing-referrer-policy', 'referrer-policy'),
    { ...header('zap-10063', 'referrer-policy'), tool: 'zap' },
  ]);
  assert.equal(out.length, 1, 'the subtype is the defect\'s name, not the rule\'s');
  assert.deepEqual(out[0].tools, ['probe', 'zap']);
});

test('a finding with no subtype keeps the fingerprint it had before subtypes existed', () => {
  const f = partial();
  assert.equal(fingerprint(f), fingerprint({ ...f, subtype: null }));
  assert.equal(fingerprint(f), fingerprint({ ...f, subtype: '  ' }));
  assert.notEqual(fingerprint(f), fingerprint({ ...f, subtype: 'something' }));
});

test('one tool reporting two of its own rules at one location says so rather than losing one', () => {
  // The safety net for every adapter that has not declared a subtype. The
  // family still wins the merge; what it may not do is win it quietly.
  const out = mergeFindings([
    header('missing-referrer-policy', null),
    header('technology-banner', null),
  ]);
  assert.equal(out.length, 1, 'without a subtype the family is still the identity');
  assert.deepEqual(out[0].collapsed, ['missing-referrer-policy', 'technology-banner']);
});

test('two tools agreeing is not a collapse', () => {
  const out = mergeFindings([
    header('missing-referrer-policy', null),
    { ...header('zap-10063', null), tool: 'zap' },
  ]);
  assert.equal(out[0].collapsed, undefined, 'that is corroboration, which is the point of merging');
});

test('two instances inside one symbol are one finding that names both lines', () => {
  // The fingerprint prefers `file#symbol` so it survives an edit above it. The
  // cost: two streamText calls in one handler object were one fingerprint, and
  // the second left no trace. Merging them is right; losing the line is not.
  const out = mergeFindings([
    partial({ location: at('artifacts/code/server.ts', 'codeDocumentHandler', 18) }),
    partial({ location: at('artifacts/code/server.ts', 'codeDocumentHandler', 40) }),
  ]);
  assert.equal(out.length, 1, 'one defect, one identity');
  assert.deepEqual(out[0].occurrences,
    ['artifacts/code/server.ts:18', 'artifacts/code/server.ts:40'],
    'and nobody fixes one call site and closes the finding');
});

test('a finding in one place carries no occurrence list', () => {
  assert.equal(mergeFindings([partial()])[0].occurrences, undefined);
});
