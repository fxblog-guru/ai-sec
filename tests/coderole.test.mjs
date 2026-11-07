// What kind of code a finding sits in.
//
// Scanning OWASP Juice Shop produced 246 findings; 188 were hardcoded
// credentials in its test suite, printed above the SQL injection in its login
// route because `Critical` sorts before `High`. The report was accurate and
// nobody would have read past the first screen.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  codeRole, classify, isApplicationCode, roleSummary, CODE_ROLES, NON_APPLICATION,
} from '../controller/coderole.mjs';
import { verdict } from '../lib/verdict.mjs';
import { buildLedger } from '../lib/coverage.mjs';

test('the shapes a test file comes in are all recognised', () => {
  for (const p of [
    'test/api/login.test.ts',
    'tests/unit/auth.js',
    '__tests__/user.spec.tsx',
    'src/app/forgot-password.component.spec.ts',
    'test/cypress/e2e/search.spec.ts',
    'e2e/checkout.ts',
    'internal/auth/handler_test.go',
  ]) {
    assert.equal(codeRole(p), 'test', p);
  }
});

test('fixtures, examples, vendored and generated code are told apart', () => {
  assert.equal(codeRole('test/fixtures/users.json'), 'test'); // the outer label wins
  assert.equal(codeRole('src/fixtures/users.json'), 'fixture');
  assert.equal(codeRole('examples/quickstart/server.js'), 'example');
  assert.equal(codeRole('node_modules/lodash/index.js'), 'vendored');
  assert.equal(codeRole('vendor/github.com/x/y.go'), 'vendored');
  assert.equal(codeRole('dist/main.js'), 'generated');
  assert.equal(codeRole('frontend/assets/three.min.js'), 'generated');
});

test('anything unrecognised is application code', () => {
  // The safe direction: calling a handler a test hides a real finding, while
  // calling a test a handler only costs the reader some attention.
  for (const p of ['routes/login.ts', 'server.ts', 'lib/insecurity.ts', 'attestation/notes.md', '']) {
    assert.equal(codeRole(p), 'application', p);
  }
  assert.equal(codeRole(undefined), 'application');
});

test('a windows path classifies the same as a posix one', () => {
  assert.equal(codeRole('test\\api\\login.test.ts'), 'test');
});

test('every role the module names is one codeRole can return', () => {
  const reachable = new Set([
    codeRole('routes/a.ts'), codeRole('test/a.ts'), codeRole('src/fixtures/a.ts'),
    codeRole('examples/a.ts'), codeRole('dist/a.js'), codeRole('node_modules/a/b.js'),
  ]);
  assert.deepEqual([...reachable].sort(), [...CODE_ROLES].sort());
  assert.ok(!NON_APPLICATION.includes('application'));
});

test('a finding outside the application cannot keep a confidence it has not earned', () => {
  const f = classify({ location: { file: 'test/api/login.test.ts' }, confidence: 'Firm' });
  assert.equal(f.code_role, 'test');
  assert.equal(f.confidence, 'Tentative');
  assert.equal(f.reported_confidence, 'Firm', 'what the scanner said is kept, not erased');
  assert.equal(isApplicationCode(f), false);
});

test('an application finding is labelled and otherwise untouched', () => {
  const f = classify({ location: { file: 'routes/login.ts' }, confidence: 'Firm' });
  assert.equal(f.code_role, 'application');
  assert.equal(f.confidence, 'Firm');
  assert.equal(f.reported_confidence, undefined);
});

test('a finding in a test file is reported and does not fail the build', () => {
  const inTest = {
    status: 'open', severity: 'Critical', confidence: 'Firm', code_role: 'test',
    rule_id: 'hardcoded-credential', baseline_state: 'new',
  };
  const v = verdict(
    { run_state: 'done', findings: [inTest], not_evaluable: [] },
    { bootstrap: true },
  );
  assert.notEqual(v.outcome, 'FAIL', 'a fixture must not fail a build on its own');
  assert.ok(
    v.notes.some((n) => /non-application|test, fixture/.test(n)),
    'and the reader is told they were set aside',
  );
});

test('the same finding in a route does fail the build', () => {
  const inApp = {
    status: 'open', severity: 'Critical', confidence: 'Firm', code_role: 'application',
    rule_id: 'hardcoded-credential', baseline_state: 'new',
  };
  const v = verdict(
    { run_state: 'done', findings: [inApp], not_evaluable: [] },
    { bootstrap: true },
  );
  assert.equal(v.outcome, 'FAIL');
});

test('the count never lives only in the total', () => {
  const findings = [
    { code_role: 'test' }, { code_role: 'test' }, { code_role: 'generated' }, { code_role: 'application' },
  ];
  assert.deepEqual(roleSummary(findings), { test: 2, generated: 1 });

  const ledger = buildLedger({
    results: [], selectedModules: [], coveredModules: [], findings, tier: 'T0', maxTier: 'T0',
  });
  const entry = ledger.not_evaluable.find((e) => e.check === 'non-application code');
  assert.ok(entry, 'the ledger says how many were set aside');
  assert.match(entry.reason, /3 of 4/);
  assert.match(entry.unblock, /still a credential/);
});

test('a run that is all test findings does not report a silent pass', () => {
  const findings = [{ code_role: 'test', status: 'open', severity: 'Critical', confidence: 'Firm' }];
  const ledger = buildLedger({
    results: [], selectedModules: [], coveredModules: [], findings, tier: 'T0', maxTier: 'T0',
  });
  assert.ok(ledger.not_evaluable.some((e) => e.check === 'non-application code'));
});
