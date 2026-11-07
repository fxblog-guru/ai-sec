// Gate conformance. Every case here must fail when its gate is removed —
// tests/mutate.mjs proves that.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { scanRepo } from '../adapters/scanners/builtin/engine.mjs';

import {
  gateProduction, gateHostAllowlist, gateTierCeiling, gateSpecOverride, gateRedaction,
  checkGates, isProductionLabel, hostIsProduction, evaluateAutoStop, tierRank,
} from '../controller/rules.mjs';
import * as redactor from '../controller/redact.mjs';

const today = () => new Date().toISOString().slice(0, 10);
const scopeT0 = { max_tier: 'T0', environment: 'local', allow_hosts: [], production: false };

test('production labels: prod/prd are production, product is not', () => {
  for (const l of ['prod', 'prod1', 'prd', 'prd-eu', 'production', 'PROD']) {
    assert.equal(isProductionLabel(l), true, `${l} should be production`);
  }
  for (const l of ['product', 'products', 'product-api', 'staging', 'dev', 'uat']) {
    assert.equal(isProductionLabel(l), false, `${l} should not be production`);
  }
});

test('G1 refuses a production scope', () => {
  assert.equal(gateProduction({ ...scopeT0, production: true }, {}).ok, false);
  assert.equal(gateProduction({ ...scopeT0, environment: 'prod-eu' }, {}).ok, false);
  assert.equal(gateProduction({ ...scopeT0, environment: 'Production' }, {}).ok, false);
  assert.equal(gateProduction(scopeT0, {}).ok, true);
});

test('G1 refuses a production host, and allows a product host', () => {
  assert.equal(hostIsProduction('api.prod.example.com'), true);
  assert.equal(hostIsProduction('product-api.example.com'), false);
  assert.equal(gateProduction(scopeT0, { target_url: 'https://api.prod.example.com' }).ok, false);
  assert.equal(gateProduction(scopeT0, { target_url: 'https://product.example.com' }).ok, true);
});

test('G2 refuses a host outside the allowlist', () => {
  const scope = { ...scopeT0, allow_hosts: ['localhost'] };
  assert.equal(gateHostAllowlist(scope, { target_url: 'http://localhost:3000' }).ok, true);
  assert.equal(gateHostAllowlist(scope, { target_url: 'http://elsewhere.test' }).ok, false);
  // nothing to reach is not a refusal
  assert.equal(gateHostAllowlist(scope, {}).ok, true);
});

test('G2 refuses credentials in the URL', () => {
  const scope = { ...scopeT0, allow_hosts: ['localhost'] };
  assert.equal(gateHostAllowlist(scope, { target_url: 'http://u:p@localhost' }).ok, false);
  assert.equal(gateHostAllowlist(scope, { target_url: 'http://localhost?token=abc123' }).ok, false);
  assert.equal(gateHostAllowlist(scope, { target_url: 'http://localhost?page=2' }).ok, true);
});

test('G3 refuses a tier above the project ceiling', () => {
  assert.equal(tierRank('T3') > tierRank('T0'), true);
  assert.equal(gateTierCeiling(scopeT0, { tier: 'T0' }).ok, true);
  assert.equal(gateTierCeiling(scopeT0, { tier: 'T2' }).ok, false);
  assert.equal(gateTierCeiling(scopeT0, { tier: 'T9' }).ok, false);
});

test('G3 requires a current authorization above T0', () => {
  const base = { ...scopeT0, max_tier: 'T3' };
  assert.equal(gateTierCeiling(base, { tier: 'T2' }).ok, false, 'no authorization record');

  const good = { ...base, authorization: { basis: 'staging', granted_at: today() } };
  assert.equal(gateTierCeiling(good, { tier: 'T2' }).ok, true);

  const stale = { ...base, authorization: { basis: 'staging', granted_at: '2020-01-01' } };
  assert.equal(gateTierCeiling(stale, { tier: 'T2' }).ok, false, 'stale authorization');

  const badBasis = { ...base, authorization: { basis: 'because-i-said-so', granted_at: today() } };
  assert.equal(gateTierCeiling(badBasis, { tier: 'T2' }).ok, false, 'unknown basis');
});

test('G4 refuses a spec that tries to widen its own permissions', () => {
  assert.equal(gateSpecOverride({ tier: 'T0' }).ok, true);
  for (const k of ['allow_hosts', 'max_tier', 'authorization', 'production']) {
    assert.equal(gateSpecOverride({ [k]: 'anything' }).ok, false, `${k} must be refused in a spec`);
  }
});

test('G5 refuses to proceed without a working redactor', () => {
  assert.equal(gateRedaction(redactor).ok, true);
  assert.equal(gateRedaction({}).ok, false);
  assert.equal(gateRedaction({ redactText: (s) => s, redactDeep: (v) => v }).ok, false);
});

test('checkGates stops at the first refusal', () => {
  const r = checkGates({
    scope: { ...scopeT0, production: true },
    spec: { tier: 'T0' },
    rawSpec: { tier: 'T0' },
    redactor,
  });
  assert.equal(r.ok, false);
  assert.equal(r.refused.gate, 'G1-production');
});

test('checkGates passes a plain T0 repo run', () => {
  const r = checkGates({ scope: scopeT0, spec: { tier: 'T0' }, rawSpec: { tier: 'T0' }, redactor });
  assert.equal(r.ok, true, r.refused?.reason);
});

test('auto-stop fires on each hard rule', () => {
  assert.equal(evaluateAutoStop({}).stop, false);
  assert.equal(evaluateAutoStop({ out_of_scope_requests: 1 }).rule, 'out-of-scope-host');
  assert.equal(evaluateAutoStop({ consecutive_errors: 5 }).rule, 'consecutive-errors');
  assert.equal(evaluateAutoStop({ unintended_writes: 1 }).rule, 'unintended-write');
  assert.equal(evaluateAutoStop({ auth_failure_rate: 1, requests: 20 }).rule, 'auth-lockout');
  assert.equal(evaluateAutoStop({ tier_exceeded: true }).rule, 'tier-exceeded');
});

test('autoescape turned off is the cause of a stored XSS, not a style choice', () => {
  // NodeGoat's A3 is one line in server.js, with the fix commented out below it.
  // Reviewing the profile handler alone finds an encoder being called and moves on.
  const dir = mkdtempSync(join(tmpdir(), 'ai-sec-esc-'));
  try {
    writeFileSync(join(dir, 'server.js'), [
      'swig.setDefaults({',
      '  // Autoescape disabled',
      '  autoescape: false',
      '});',
    ].join('\n'), 'utf8');

    const hit = scanRepo(dir).findings.find((f) => f.rule_id === 'template-autoescape-disabled');
    assert.ok(hit);
    assert.equal(hit.severity, 'High');
    assert.deepEqual(hit.rule.classification.cwe, ['CWE-79']);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('autoescape left on is not reported', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ai-sec-esc2-'));
  try {
    writeFileSync(join(dir, 'server.js'), 'swig.setDefaults({ autoescape: true });\n', 'utf8');
    assert.equal(
      scanRepo(dir).findings.filter((f) => f.rule_id === 'template-autoescape-disabled').length,
      0,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a validator can be the vulnerability', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ai-sec-redos-'));
  try {
    writeFileSync(join(dir, 'profile.js'), 'const regexPattern = /([0-9]+)+\#/;\n', 'utf8');
    const hit = scanRepo(dir).findings.find((f) => f.rule_id === 'redos-nested-quantifier');
    assert.ok(hit, 'a quantified group that is itself quantified');
    assert.deepEqual(hit.rule.classification.cwe, ['CWE-1333']);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('an ordinary regex is not called catastrophic', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ai-sec-redos2-'));
  try {
    writeFileSync(join(dir, 'profile.js'), 'const ok = /([0-9]+)\#/;\nconst also = /^[a-z]+$/;\n', 'utf8');
    assert.equal(
      scanRepo(dir).findings.filter((f) => f.rule_id === 'redos-nested-quantifier').length,
      0,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
