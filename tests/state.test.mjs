import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createState, move, canMove, worstOf, exitCodeFor, isTerminal } from '../controller/state.mjs';
import { makeEvent, shouldWake } from '../controller/events.mjs';

test('the happy path walks preparing -> scanning -> merging -> done', () => {
  const s = createState('r1');
  move(s, 'scanning');
  move(s, 'merging');
  move(s, 'done');
  assert.equal(s.state, 'done');
  assert.equal(s.history.length, 4);
  assert.ok(s.finished_at);
});

test('a terminal state is written exactly once', () => {
  const s = createState('r1');
  move(s, 'done');
  assert.equal(canMove('done', 'degraded'), false);
  assert.throws(() => move(s, 'degraded'), /illegal state move/);
});

test('precedence is aborted > not_evaluable > degraded > done', () => {
  assert.equal(worstOf('done', 'degraded'), 'degraded');
  assert.equal(worstOf('degraded', 'not_evaluable'), 'not_evaluable');
  assert.equal(worstOf('not_evaluable', 'aborted'), 'aborted');
  assert.equal(worstOf('done'), 'done');
});

test('exit codes follow the contract', () => {
  assert.equal(exitCodeFor('done'), 0);
  assert.equal(exitCodeFor('not_evaluable'), 3);
  assert.equal(exitCodeFor('degraded'), 4);
  assert.equal(exitCodeFor('aborted'), 5);
  assert.equal(isTerminal('scanning'), false);
});

test('events are redacted at creation, not at the call site', () => {
  const e = makeEvent('scanner_finished', 'found AKIAIOSFODNN7EXAMPLE', {
    data: { evidence: 'AKIAIOSFODNN7EXAMPLE' },
  });
  assert.ok(!e.summary.includes('AKIAIOSFODNN7EXAMPLE'));
  assert.ok(!JSON.stringify(e.data).includes('AKIAIOSFODNN7EXAMPLE'));
});

test('an unknown event type is refused', () => {
  assert.throws(() => makeEvent('something_else', 'x'), /unknown event type/);
});

test('critical events wake the AI even with no budget left', () => {
  assert.equal(shouldWake(makeEvent('run_finished', 'x'), { budgetLeft: 0 }), true);
  assert.equal(shouldWake(makeEvent('gate_refused', 'x'), { budgetLeft: 0 }), true);
  assert.equal(shouldWake(makeEvent('scanner_finished', 'x'), { budgetLeft: 0 }), false);
  assert.equal(shouldWake(makeEvent('scanner_failed', 'x', { severity: 'warn' }), { budgetLeft: 5 }), true);
});
