// Measurement, and the honesty rules around it. A scorecard that flatters the
// tool is worse than none: it converts "we have not checked" into a number.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { scorecard, grade, formatScorecard } from '../lib/scorecard.mjs';

const RULES = [
  { rule_id: 'sql-injection', classification: { cwe: ['CWE-89'] } },
  { rule_id: 'prompt-injection', classification: { cwe: ['CWE-1427'] } },
  { rule_id: 'semgrep.something', classification: { cwe: ['CWE-22'] } },
];

const finding = (rule_id, file, modules) => ({ rule_id, location: { file }, modules });

const EXPECTED = {
  defects: [
    { id: 'sqli', file: 'db.js', cwe: 'CWE-89', modules: ['M1', 'M6'] },
    { id: 'injection-prompt', file: 'bot.js', cwe: 'CWE-1427', modules: ['M14'] },
  ],
};

const ENGINES = {
  builtin: { modules: ['M1', 'M6', 'M14'], installed: true },
  semgrep: { modules: ['M1', 'M6'], installed: true },
  zap: { modules: ['M13'], installed: false },
};

const run = (findings, extra = {}) => scorecard({
  findings, rules: RULES, expected: EXPECTED, engines: ENGINES,
  modules: ['M1', 'M6', 'M13', 'M14'], ...extra,
});

test('a planted defect that was found counts, one that was missed is named', () => {
  const rows = run([finding('sql-injection', 'db.js', ['M1', 'M6'])]);
  const m1 = rows.find((r) => r.module === 'M1');
  assert.equal(m1.planted, 1);
  assert.equal(m1.found, 1);
  assert.equal(m1.recall, 1);

  const m14 = rows.find((r) => r.module === 'M14');
  assert.equal(m14.found, 0);
  assert.deepEqual(m14.missed, ['injection-prompt'], 'a miss is named, not just counted');
  assert.equal(m14.grade, 'failing');
});

test('full marks on our own fixture is self-measured, never measured', () => {
  // M6's lesson, made into a grade: a fixture you wrote cannot surprise you.
  const findings = [
    finding('sql-injection', 'db.js', ['M1', 'M6']),
    finding('prompt-injection', 'bot.js', ['M14']),
  ];
  assert.equal(run(findings).find((r) => r.module === 'M14').grade, 'self-measured');
  assert.equal(
    run(findings, { benchmarkTrust: 'external' }).find((r) => r.module === 'M14').grade,
    'measured',
    'a corpus nobody here authored is what earns the stronger word',
  );
});

test('a module with no installed engine is not merely unmeasured', () => {
  const m13 = run([]).find((r) => r.module === 'M13');
  assert.equal(m13.grade, 'no-engine');
  assert.equal(m13.installed_engines, 0);
  assert.equal(m13.engines.length, 1, 'the engine is still listed, with its state');
});

test('an engine with nothing planted to find is unmeasured, which is not a pass', () => {
  const rows = scorecard({
    findings: [], rules: RULES, expected: { defects: [] }, engines: ENGINES, modules: ['M1'],
  });
  assert.equal(rows[0].grade, 'unmeasured');
});

test('a finding the benchmark never planted is unaccounted, not a false positive', () => {
  // A second engine reports real things we did not plant. Counting those as
  // failures would punish the tool for working, so they are flagged for judgement.
  const rows = run([
    finding('sql-injection', 'db.js', ['M1', 'M6']),
    finding('semgrep.something', 'upload.js', ['M1']),
  ]);
  const m1 = rows.find((r) => r.module === 'M1');
  assert.equal(m1.reported, 2);
  assert.equal(m1.unaccounted, 1);
  assert.deepEqual(m1.unaccounted_rules, ['semgrep.something']);
  assert.equal(m1.grade, 'self-measured', 'an unverified extra does not lower recall');
});

test('a finding the benchmark accepted is accounted for', () => {
  const rows = scorecard({
    findings: [finding('semgrep.something', 'upload.js', ['M1'])],
    rules: RULES,
    expected: { defects: [], accepted: ['semgrep.something'] },
    engines: ENGINES, modules: ['M1'],
  });
  assert.equal(rows[0].unaccounted, 0);
});

test('a blind spot is one sentence, not thirty-one characters', () => {
  const rows = scorecard({
    findings: [], rules: [], expected: {}, engines: ENGINES, modules: ['M11'],
    blindSpots: { M11: 'business logic cannot be settled statically' },
  });
  assert.equal(rows[0].blind_spots.length, 1, 'iterating a string yields its characters');
});

test('grade never calls an unchecked module good', () => {
  assert.equal(grade({ planted: 0, found: 0, installed: 0 }), 'no-engine');
  assert.equal(grade({ planted: 0, found: 0, installed: 2 }), 'unmeasured');
  assert.equal(grade({ planted: 3, found: 0, installed: 2 }), 'failing');
  assert.equal(grade({ planted: 3, found: 1, installed: 2 }), 'partial');
});

test('the printed card names its benchmark, because every number depends on it', () => {
  const text = formatScorecard(run([]), { source: 'mock/expected.json (written by us)' });
  assert.match(text, /mock\/expected\.json/);
  assert.match(text, /self-measured/);
  assert.match(text, /unaccounted.*unverified, not wrong/s);
});

test('a defect that is a class, not a line, can be keyed on something other than one CWE', () => {
  // NodeGoat's "vulnerable dependencies" was recorded as CWE-1104. Trivy files
  // each CVE under that CVE's own weakness, so the card reported a miss while
  // fifty-two findings sat in the file it named.
  const rows = scorecard({
    findings: [
      { rule_id: 'cve:CVE-2021-23358', location: { file: 'package-lock.json' }, modules: ['M2'] },
    ],
    rules: [{ rule_id: 'cve:CVE-2021-23358', classification: { cwe: ['CWE-94'] } }],
    expected: {
      defects: [{
        id: 'deps', file: 'package-lock.json', cwe: 'CWE-1104',
        rule_id_prefix: 'cve:', modules: ['M2'],
      }],
    },
    engines: { trivy: { modules: ['M2'], installed: true } },
    modules: ['M2'],
  });
  assert.equal(rows[0].found, 1, 'the CWE never matches; the rule prefix does');
  assert.equal(rows[0].unaccounted, 0);
});

test('issue_type also keys a defect, for scanners that agree on the family only', () => {
  const rows = scorecard({
    findings: [{ rule_id: 'x', issue_type: 'ssrf', location: { file: 'r.js' }, modules: ['M6'] }],
    rules: [{ rule_id: 'x', classification: { cwe: [] } }],
    expected: { defects: [{ id: 's', file: 'r.js', issue_type: 'ssrf', modules: ['M6'] }] },
    engines: { builtin: { modules: ['M6'], installed: true } },
    modules: ['M6'],
  });
  assert.equal(rows[0].found, 1);
});
