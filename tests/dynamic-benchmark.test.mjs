// The dynamic benchmark, as a test.
//
// Every other benchmark in this repository grades a module by reading files.
// This one starts a server, sends requests and reads the answers, so "M13 finds
// a stack trace in a response" stops meaning "a regular expression recognised
// the shape of one". The two kinds of evidence are not interchangeable and the
// scorecard now has both.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { runDynamicBenchmark, DYNAMIC_MODULES, assertOwnLoopbackTarget } from '../benchmarks/dynamic/run.mjs';
import expected from '../benchmarks/dynamic/expected.json' with { type: 'json' };

const run = await runDynamicBenchmark();

test('the benchmark ran at all', () => {
  assert.equal(run.ok, true, run.reason ?? '');
  assert.equal(run.result.scope.tier, 'T2');
});

test('every planted defect is found', () => {
  const missed = run.rows.flatMap((r) => r.missed);
  assert.deepEqual([...new Set(missed)], [], 'a benchmark is only worth the misses it reports');
  assert.equal(
    run.rows.filter((r) => r.grade === 'self-measured').length,
    DYNAMIC_MODULES.length,
  );
});

test('the deliberately correct endpoint is not reported', () => {
  // /api/profile/:id is the orders handler plus an ownership check. A benchmark
  // of nothing but defects measures recall and rewards a tool that reports
  // everything.
  assert.deepEqual(run.forbidden, []);
  assert.ok((expected.must_not_report ?? []).length > 0, 'and the file still carries one');
});

test('the cross-account finding was reproduced, not inferred', () => {
  const f = (run.result.findings ?? []).find((x) => x.rule_id === 'cross-account-object-read');
  assert.ok(f);
  assert.equal(f.confidence, 'Certain', 'two sessions, one object, identical bytes');
  assert.equal(f.detection_method, 'reproduced');
});

test('nothing in the result carries another account\'s data or a session cookie', () => {
  const text = JSON.stringify(run.result);
  assert.ok(!text.includes('session-for-'), 'cookies go in the environment and stay there');
  assert.ok(!text.includes('4242'), 'the order body is evidence by digest, never by quotation');
});

test('this benchmark can never grade better than self-measured', () => {
  // We wrote the target. What it adds is the kind of evidence, not its
  // independence; NodeGoat is the one that can surprise us.
  assert.ok(!run.rows.some((r) => r.grade === 'measured'));
});

test('a target this harness did not start is refused', () => {
  assert.throws(() => assertOwnLoopbackTarget('http://example.test:80', 80), /127\.0\.0\.1/);
  assert.throws(() => assertOwnLoopbackTarget('http://127.0.0.1:9', 10), /port/);
});
