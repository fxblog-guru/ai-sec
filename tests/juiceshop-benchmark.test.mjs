// The Juice Shop answer key, checked against the code that has to satisfy it.
//
// The corpus itself is not in this repository and must not be: it is 1,468 files
// of somebody else's deliberately vulnerable application. What is here is the
// recorded answers, and answers drift — a rule gets renamed, a module list
// changes, and the benchmark goes on reporting a score for a question nobody
// asks any more.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

import { RULES } from '../adapters/scanners/builtin/rules.mjs';
import { ALL_MODULES } from '../lib/scan.mjs';
import { scorecard } from '../lib/scorecard.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const expected = JSON.parse(readFileSync(join(ROOT, 'benchmarks', 'juiceshop-expected.json'), 'utf8'));
// The pattern rules, plus everything the structural and cross-file checks emit.
// Those are not in RULES because they are not patterns, and leaving them out
// made this test report a real rule as missing.
const EMITTED = ['structural.mjs', 'crossfile.mjs']
  .map((f) => readFileSync(join(ROOT, 'adapters', 'scanners', 'builtin', f), 'utf8'))
  .join('\n');
const ruleIds = new Set([
  ...RULES.map((r) => r.id),
  ...[...EMITTED.matchAll(/rule_id:\s*'([a-z0-9-]+)'/g)].map((m) => m[1]),
]);

const DETECTABLE = ['static', 'static-blocked', 'judgement', 'dynamic'];

test('the benchmark declares the corpus, which is what earns `measured`', () => {
  assert.equal(typeof expected.corpus, 'string');
  assert.ok(expected.corpus.length > 0, 'without `corpus` the grade silently drops to self-measured');
  assert.match(expected.authored_by, /annotation/i, 'the answers come from the target, not from us');
});

test('every defect is complete enough to be scored and argued with', () => {
  for (const d of expected.defects) {
    assert.ok(d.id, 'a defect needs an id');
    assert.ok(d.file, `${d.id}: a defect names the file it is in`);
    assert.ok(d.cause, `${d.id}: a defect says what the cause is`);
    assert.ok(Array.isArray(d.not_the_cause) && d.not_the_cause.length > 0,
      `${d.id}: a defect names at least one wrong diagnosis, or the benchmark cannot tell a lucky hit from a correct one`);
    assert.ok(d.source, `${d.id}: a defect cites the annotation it came from`);
    for (const m of d.modules) assert.ok(ALL_MODULES.includes(m), `${d.id}: unknown module ${m}`);
  }
});

test('every rule the benchmark expects still exists under that name', () => {
  // The failure this prevents: `nosql-operator-injection` gets renamed, the
  // benchmark stops matching it, and the scorecard reports a regression that is
  // really a rename — or worse, reports `partial` and nobody looks.
  for (const d of expected.defects) {
    if (!d.rule_id_prefix) continue;
    const hit = [...ruleIds].some((id) => id.startsWith(d.rule_id_prefix));
    assert.ok(hit, `${d.id} expects rule ${d.rule_id_prefix}, which no built-in rule provides`);
  }
});

test('every rule in the accepted list exists too', () => {
  for (const id of expected.accepted ?? []) {
    assert.ok(ruleIds.has(id), `accepted names ${id}, which is not a rule`);
  }
});

test('a defect we do not find says why, and a defect we find does not', () => {
  for (const d of expected.defects) {
    assert.ok(DETECTABLE.includes(d.detectable), `${d.id}: detectable must be one of ${DETECTABLE.join(', ')}`);
    if (d.detectable === 'static') {
      assert.ok(d.rule_id_prefix, `${d.id} is marked detectable and names no rule`);
      assert.equal(d.why_missed, undefined, `${d.id} is marked detectable and explains a miss`);
      // A defect that was out of reach and is not any more keeps the receipt.
      // Quietly flipping `detectable` is how a benchmark becomes a mirror.
      if (d.was_missed_until) {
        assert.ok(d.was_missed_until.length > 60, `${d.id}: say what changed, not that something did`);
      }
    } else {
      assert.ok(d.why_missed, `${d.id} is not statically detectable and must say why — a silent gap is the thing this project refuses`);
      assert.ok(d.why_missed.length > 40, `${d.id}: "${d.why_missed}" is too short to be a reason`);
    }
  }
});

test('the misses are kept in the denominator', () => {
  // Deleting the questions you cannot answer turns a benchmark into a
  // decoration. At the time of writing five of sixteen are out of reach.
  const out = expected.defects.filter((d) => d.detectable !== 'static');
  assert.ok(out.length > 0, 'a benchmark with nothing out of reach is a benchmark we wrote for ourselves');
  assert.ok(
    out.length < expected.defects.length / 2,
    'if most of the benchmark is out of reach, the grade it produces is not about the scanner',
  );
});

test('the recorded answers grade as `measured`, not `self-measured`', () => {
  // A finding per statically-detectable defect, to prove the wiring: the grade
  // depends on `corpus` being present, and losing that field is silent.
  const findings = expected.defects
    .filter((d) => d.detectable === 'static')
    .map((d) => ({
      rule_id: d.rule_id_prefix, modules: d.modules, code_role: 'application',
      location: { file: d.file },
    }));
  const rows = scorecard({
    findings,
    expected,
    engines: { builtin: { modules: ALL_MODULES, installed: true } },
    benchmarkTrust: 'external',
  });
  const m14 = rows.find((r) => r.module === 'M14');
  assert.equal(m14.grade, 'measured', 'M14 is graded on code nobody here wrote');

  const selfGraded = scorecard({
    findings, expected, engines: { builtin: { modules: ALL_MODULES, installed: true } },
  }).find((r) => r.module === 'M14');
  assert.equal(selfGraded.grade, 'self-measured', 'and without the external trust it is not');
});

test('a defect reached through an occurrence counts as found', () => {
  // `occurrences` had been printed in reports since M15 and never scored. The
  // cross-file check anchors a finding at the helper that causes the defect and
  // lists the call site the benchmark recorded — which the scorecard read as a
  // miss, while holding the answer in a field it did not look at.
  const planted = expected.defects.find((d) => d.id === 'weak-password-hash');
  const atTheHelper = [{
    rule_id: planted.rule_id_prefix,
    modules: planted.modules,
    code_role: 'application',
    location: { file: 'lib/insecurity.ts', line: 41 },
    occurrences: [`${planted.file}:73`],
  }];
  const row = scorecard({
    findings: atTheHelper, expected,
    engines: { builtin: { modules: ALL_MODULES, installed: true } },
    benchmarkTrust: 'external',
  }).find((r) => r.module === 'M12');
  assert.equal(row.found, 1, 'the call site is named, so the defect is found');
  assert.equal(row.grade, 'measured');
});

test('a test-suite finding can neither satisfy a defect nor count against one', () => {
  const planted = expected.defects.find((d) => d.detectable === 'static');
  const inTest = [{
    rule_id: planted.rule_id_prefix, modules: planted.modules, code_role: 'test',
    location: { file: planted.file },
  }];
  const row = scorecard({
    findings: inTest, expected,
    engines: { builtin: { modules: ALL_MODULES, installed: true } },
    benchmarkTrust: 'external',
  }).find((r) => r.module === planted.modules[0]);
  assert.equal(row.found, 0, 'a fixture does not prove the application has the defect');
  assert.equal(row.unaccounted, 0, 'nor is it an unexplained extra');
});
