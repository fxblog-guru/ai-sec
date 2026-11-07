// Fault injection: break the thing, and the matching doctor check must fail.
// A doctor that stays green while a gate would refuse is itself a defect.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { doctor } from '../lib/doctor.mjs';

function withScope(scope) {
  const root = mkdtempSync(join(tmpdir(), 'ai-sec-doc-'));
  const dir = join(root, '.sec', 'test');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'scope.json'), JSON.stringify(scope), 'utf8');
  return root;
}

const find = (report, name) => report.checks.find((c) => c.name === name);
const today = () => new Date().toISOString().slice(0, 10);

test('a clean default project passes', async () => {
  const root = mkdtempSync(join(tmpdir(), 'ai-sec-doc-'));
  try {
    const r = await doctor({ root, slug: 'test' });
    assert.equal(r.ok, true, JSON.stringify(r.failed));
    assert.equal(find(r, 'redaction').status, 'ok');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fault: a production scope fails the production check', async () => {
  const root = withScope({ production: true, environment: 'local', max_tier: 'T0' });
  try {
    const r = await doctor({ root, slug: 'test' });
    assert.equal(r.ok, false);
    assert.equal(find(r, 'production').status, 'fail');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fault: a production environment name fails', async () => {
  const root = withScope({ environment: 'prod-eu', max_tier: 'T0' });
  try {
    const r = await doctor({ root, slug: 'test' });
    assert.equal(find(r, 'environment-name').status, 'fail');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fault: a production host in the allowlist fails', async () => {
  const root = withScope({ environment: 'staging', max_tier: 'T0', allow_hosts: ['api.prod.example.com'] });
  try {
    const r = await doctor({ root, slug: 'test' });
    assert.equal(find(r, 'allow-hosts').status, 'fail');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fault: a raised ceiling without authorization fails', async () => {
  const root = withScope({ environment: 'staging', max_tier: 'T3' });
  try {
    const r = await doctor({ root, slug: 'test' });
    assert.equal(find(r, 'authorization').status, 'fail');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fault: a stale authorization fails', async () => {
  const root = withScope({
    environment: 'staging', max_tier: 'T3',
    authorization: { basis: 'staging', granted_at: '2020-01-01' },
  });
  try {
    const r = await doctor({ root, slug: 'test' });
    assert.equal(find(r, 'authorization').status, 'fail');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('a current authorization at a raised ceiling passes', async () => {
  const root = withScope({
    environment: 'staging', max_tier: 'T3',
    authorization: { basis: 'staging', granted_at: today() },
  });
  try {
    const r = await doctor({ root, slug: 'test' });
    assert.equal(find(r, 'authorization').status, 'ok');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fault: a credential in scope.json fails', async () => {
  const root = withScope({
    environment: 'staging', max_tier: 'T0',
    note: 'AKIAIOSFODNN7EXAMPLE',
  });
  try {
    const r = await doctor({ root, slug: 'test' });
    assert.equal(find(r, 'scope-secrets').status, 'fail');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('an unknown tier ceiling fails', async () => {
  const root = withScope({ environment: 'staging', max_tier: 'T9' });
  try {
    const r = await doctor({ root, slug: 'test' });
    assert.equal(find(r, 'tier-ceiling').status, 'fail');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
