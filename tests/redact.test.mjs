// Gate G5. Removing the redactor must make this file fail. CONTRACTS §8.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { redactText, redactDeep, containsSecret, placeholder } from '../controller/redact.mjs';

const SECRETS = [
  ['aws', 'AKIAIOSFODNN7EXAMPLE'],
  ['github', 'ghp_0123456789abcdefghijklmnopqrstuvwxyz'],
  ['google', 'AIzaSyA1234567890abcdefghijklmnopqrstuv'],
  ['openai', 'sk-abcdefghijklmnopqrstuvwxyz0123456789'],
  ['jwt', 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk'],
];

for (const [name, secret] of SECRETS) {
  test(`redacts a ${name} credential`, () => {
    const out = redactText(`const key = "${secret}"`);
    assert.ok(!out.includes(secret), `${name} secret survived redaction: ${out}`);
    assert.match(out, /<redacted:/);
  });
}

test('the placeholder keeps type, length and four characters — and nothing more', () => {
  const p = placeholder('aws-access-key', 'AKIAIOSFODNN7EXAMPLE');
  assert.equal(p, '<redacted:aws-access-key:20:AKIA>');
  assert.ok(!p.includes('IOSFODNN7EXAMPLE'));
});

test('redacts a private key block', () => {
  const pem = '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----';
  const out = redactText(pem);
  assert.ok(!out.includes('MIIEowIBAAKCAQEA'));
});

test('redacts credentials embedded in a URL', () => {
  const out = redactText('postgres://admin:hunter2@db.internal:5432/app');
  assert.ok(!out.includes('hunter2'), out);
});

test('redactDeep walks nested structures and secret-named keys', () => {
  const input = {
    findings: [{ evidence: 'token = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"' }],
    config: { password: 'hunter2', nested: { api_key: 'abcd1234abcd1234' } },
    safe: 'nothing here',
  };
  const out = redactDeep(input);
  const json = JSON.stringify(out);
  assert.ok(!json.includes('ghp_0123456789abcdefghijklmnopqrstuvwxyz'));
  assert.ok(!json.includes('hunter2'));
  assert.ok(!json.includes('abcd1234abcd1234'));
  assert.equal(out.safe, 'nothing here');
});

test('redactDeep survives a cycle', () => {
  const a = { name: 'a' };
  a.self = a;
  assert.doesNotThrow(() => redactDeep(a));
});

test('containsSecret detects what redaction removes', () => {
  assert.equal(containsSecret('AKIAIOSFODNN7EXAMPLE'), true);
  assert.equal(containsSecret('just some prose'), false);
  assert.equal(containsSecret(redactText('AKIAIOSFODNN7EXAMPLE')), false);
});

test('ordinary text is left alone', () => {
  const prose = 'The order id flows into a raw query on line 142.';
  assert.equal(redactText(prose), prose);
});
