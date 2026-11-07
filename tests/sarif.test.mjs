// SARIF is a projection of sec-result/v1, not a translation.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { toSarif, fromSarif, SARIF_VERSION } from '../lib/sarif.mjs';

const result = {
  run_id: 'r1',
  run_state: 'done',
  standards: { owasp_top10: '2025', cvss: '3.1' },
  rules: [{
    rule_id: 'sql-injection',
    name: 'SQL injection',
    background: 'Input reaches a query unparameterized.',
    remediation: 'Bind every user value as a parameter.',
    classification: { cwe: ['CWE-89'], owasp: ['A05:2025'], wstg: ['WSTG-v42-INPV-05'], asvs: ['v5.0.0-1.2.5'], api: [] },
    typical_severity: 'High',
    references: ['https://cwe.mitre.org/data/definitions/89.html'],
  }],
  findings: [
    {
      fingerprint: 'abc123', rule_id: 'sql-injection',
      location: { file: 'src/db.js', symbol: 'getOrder', line: 142 },
      insertion_point: { kind: 'body-parameter', name: 'orderId' },
      severity: 'High', confidence: 'Firm', status: 'open',
      detection_method: 'dataflow', detail: 'orderId flows into db.raw',
      evidence: 'db.raw(`...${orderId}`)', modules: ['M1'],
      sources: [{ tool: 'builtin' }], baseline_state: 'new',
    },
    {
      fingerprint: 'def456', rule_id: 'sql-injection',
      location: { file: 'test/db.test.js', line: 9 },
      severity: 'Info', confidence: 'Tentative', status: 'false_positive',
      suppressed_reason: 'test fixture', detection_method: 'pattern',
      detail: 'in a test', evidence: '', modules: ['M1'], sources: [],
    },
  ],
  coverage: [{ kind: 'files', detail: 'read', count: 24 }],
  not_evaluable: [{ check: 'module M2', reason: 'trivy not installed', unblock: 'install trivy' }],
};

const sarif = toSarif(result, { toolVersion: '0.4.0' });
const run = sarif.runs[0];

test('it is valid-shaped SARIF 2.1.0', () => {
  assert.equal(sarif.version, SARIF_VERSION);
  assert.ok(sarif.$schema.includes('sarif-schema-2.1.0'));
  assert.equal(run.tool.driver.name, 'ai-sec');
  assert.equal(run.automationDetails.id, 'r1');
});

test('rules[] becomes tool.driver.rules[] and findings[] becomes results[]', () => {
  assert.equal(run.tool.driver.rules.length, 1);
  assert.equal(run.tool.driver.rules[0].id, 'sql-injection');
  assert.equal(run.results[0].ruleId, 'sql-injection');
  assert.equal(run.results[0].ruleIndex, 0);
});

test('a suppressed finding is not exported as an open result', () => {
  assert.equal(run.results.length, 1, 'the false positive must not travel as a live alert');
  assert.equal(run.properties.suppressed, 1, 'but its existence is still recorded');
});

test('severity maps to level, and the number travels in security-severity', () => {
  assert.equal(run.results[0].level, 'error');
  assert.equal(Number(run.tool.driver.rules[0].properties['security-severity']), 8.0);
});

test('confidence travels as precision, since SARIF has no confidence field', () => {
  assert.equal(run.results[0].properties.confidence, 'Firm');
  assert.equal(run.results[0].properties.precision, 'high');
});

test('the fingerprint becomes the key GitHub actually reads', () => {
  assert.equal(run.results[0].partialFingerprints.primaryLocationLineHash, 'abc123');
});

test('classification becomes tags', () => {
  const tags = run.tool.driver.rules[0].properties.tags;
  assert.ok(tags.includes('CWE-89'));
  assert.ok(tags.includes('A05:2025'));
  assert.ok(tags.includes('WSTG-v42-INPV-05'));
  assert.ok(tags.includes('ASVS-v5.0.0-1.2.5'));
});

test('the location carries file, line and the enclosing symbol', () => {
  const loc = run.results[0].locations[0];
  assert.equal(loc.physicalLocation.artifactLocation.uri, 'src/db.js');
  assert.equal(loc.physicalLocation.region.startLine, 142);
  assert.equal(loc.logicalLocations[0].name, 'getOrder');
});

test('the coverage ledger survives the export', () => {
  // SARIF has no home for this, and dropping it turns a thin run into a clean one.
  assert.equal(run.properties.not_evaluable.length, 1);
  assert.equal(run.properties.run_state, 'done');
  assert.equal(run.properties.coverage.length, 1);
});

// --- import

test('importing someone else\'s SARIF starts everything at Tentative', () => {
  const { findings } = fromSarif(sarif);
  assert.ok(findings.length > 0);
  for (const f of findings) {
    assert.equal(f.detection_method, 'pattern', 'we did not see how it was found');
  }
});

test('import reads security-severity in preference to level', () => {
  const foreign = {
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'other', rules: [{ id: 'x', properties: { 'security-severity': '9.5', tags: ['CWE-79'] }, defaultConfiguration: { level: 'note' } }] } },
      results: [{ ruleId: 'x', ruleIndex: 0, message: { text: 'found' }, locations: [{ physicalLocation: { artifactLocation: { uri: 'a.js' } } }] }],
    }],
  };
  const { findings, rules } = fromSarif(foreign);
  assert.equal(findings[0].severity, 'Critical', '9.5 outranks the note level');
  assert.deepEqual(rules[0].classification.cwe, ['CWE-79']);
});

test('a non-failing SARIF result is not imported as a finding', () => {
  const passing = {
    version: '2.1.0',
    runs: [{ tool: { driver: { name: 'other', rules: [] } }, results: [{ ruleId: 'x', kind: 'pass', message: { text: 'ok' } }] }],
  };
  assert.equal(fromSarif(passing).findings.length, 0);
});

test('a round trip keeps rule identity and location', () => {
  const back = fromSarif(sarif);
  assert.equal(back.findings[0].rule_id, 'sql-injection');
  assert.equal(back.findings[0].location.file, 'src/db.js');
  assert.equal(back.findings[0].location.line, 142);
  assert.equal(back.rules[0].classification.owasp[0], 'A05:2025');
});
