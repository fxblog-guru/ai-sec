// One hop across a call boundary.
//
// Every static blind spot this project had recorded was the same sentence: no
// regular expression crosses a call boundary. Juice Shop put a number on it —
// M12 scored 0 of 1 and graded `failing`, because the password setter names a
// helper and the helper is in another file.
//
// These tests pin the three things that make the hop safe to trust: it resolves
// only what this target defines, it says so when it cannot resolve, and it
// reports one defect rather than one per call site.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';

import {
  collectDefinitions, collectPasswordSinks, weakPasswordHashBehindHelper,
  collectModelFields, collectAutoCrud, autoCrudExposesPrivilegedField,
} from '../adapters/scanners/builtin/crossfile.mjs';
import { callerIdentityFetchedAndUnused } from '../adapters/scanners/builtin/structural.mjs';
import { scanRepo } from '../adapters/scanners/builtin/engine.mjs';

function repoWith(files) {
  const dir = mkdtempSync(join(tmpdir(), 'sec-xfile-'));
  for (const [name, body] of Object.entries(files)) {
    const p = join(dir, name);
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, body, 'utf8');
  }
  return dir;
}

const run = (files, fn) => {
  const dir = repoWith(files);
  try {
    return fn(scanRepo(dir));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
};

const MD5_HELPER = "export const hash = (data) => crypto.createHash('md5').update(data).digest('hex')\n";
const SETTER = [
  'const model = {',
  '  password: {',
  '    set (clearTextPassword) {',
  "      this.setDataValue('password', security.hash(clearTextPassword))",
  '    }',
  '  }',
  '}',
].join('\n');

test('a password hashed through a helper in another file is found', () => {
  const ids = run({ 'lib/insecurity.js': MD5_HELPER, 'models/user.js': SETTER },
    (r) => r.findings.map((f) => f.rule_id));
  assert.ok(ids.includes('weak-password-hash-via-helper'));
});

test('the finding points at the helper and lists the call site', () => {
  run({ 'lib/insecurity.js': MD5_HELPER, 'models/user.js': SETTER }, (r) => {
    const f = r.findings.find((x) => x.rule_id === 'weak-password-hash-via-helper');
    assert.equal(f.location.file, 'lib/insecurity.js', 'the helper is the line that changes');
    assert.equal(f.location.symbol, 'hash');
    assert.ok(f.occurrences.some((o) => o.startsWith('models/user.js:')), 'the call site is where it shows');
  });
});

test('a helper that uses a key derivation function is not a finding', () => {
  const ids = run({
    'lib/insecurity.js': 'export const hash = async (data) => await argon2.hash(data)\n',
    'models/user.js': SETTER,
  }, (r) => r.findings.map((f) => f.rule_id));
  assert.ok(!ids.includes('weak-password-hash-via-helper'));
});

test('twenty call sites are one defect, not twenty', () => {
  const files = { 'lib/insecurity.js': MD5_HELPER };
  for (let i = 0; i < 20; i += 1) files[`routes/r${i}.js`] = `security.hash(req.body.password)\n`;
  run(files, (r) => {
    const hits = r.findings.filter((f) => f.rule_id === 'weak-password-hash-via-helper');
    assert.equal(hits.length, 1, 'one fix at the helper closes all of them');
    assert.equal(hits[0].occurrences.length, 20, 'and every call site is still named');
  });
});

test('a helper that cannot be resolved becomes a coverage gap, not a pass', () => {
  // The honest outcome when the hash comes from a package: we did not establish
  // how the password is stored, and the ledger says which call we could not follow.
  run({ 'models/user.js': "import { hashPassword } from 'some-pkg'\nuser.password = hashPassword(req.body.password)\n" },
    (r) => {
      const gap = r.errors.find((e) => e.kind === 'unresolved-helper');
      assert.ok(gap, 'an unresolved hashing call is reported');
      assert.match(gap.detail, /hashPassword/);
      assert.match(gap.unblock, /by hand/);
    });
});

test('an ordinary call on a line that mentions a password is not a gap', () => {
  run({ 'routes/me.js': 'res.json({ email: user.email, password: null })\n' }, (r) => {
    assert.equal(r.errors.find((e) => e.kind === 'unresolved-helper'), undefined);
  });
});

test('definitions and sinks are collected separately and mean nothing alone', () => {
  const defs = collectDefinitions('lib/a.js', MD5_HELPER.split('\n'), MD5_HELPER);
  assert.equal(defs[0].name, 'hash');
  const sinks = collectPasswordSinks('models/u.js', SETTER.split('\n'));
  assert.ok(sinks.some((s) => s.name === 'hash' && s.qualifier === 'security'));
  // Neither on its own is a finding: the pair is.
  assert.deepEqual(weakPasswordHashBehindHelper({ definitions: defs, passwordSinks: [] }).findings, []);
  assert.deepEqual(weakPasswordHashBehindHelper({ definitions: [], passwordSinks: sinks }).findings, []);
});

// --- generated CRUD over a model that carries authority

const MODEL = 'export class UserModel {\n  declare email: string\n  declare role: CreationOptional<string>\n}\n';
const FINALE = [
  'finale.initialize({ app, sequelize: seq })',
  'const autoModels = [',
  "  { name: 'User', exclude: ['password'], model: UserModel }",
  ']',
].join('\n');

test('a generated resource that does not exclude the role field is found', () => {
  run({ 'models/user.ts': MODEL, 'server.ts': FINALE }, (r) => {
    const f = r.findings.find((x) => x.rule_id === 'auto-crud-exposes-privileged-field');
    assert.ok(f, 'the gap between two lists is the defect');
    assert.equal(f.location.file, 'server.ts');
    assert.match(f.detail, /role/);
    assert.ok(f.occurrences.some((o) => o.startsWith('models/user.ts:')));
  });
});

test('excluding the field closes it', () => {
  const ids = run({
    'models/user.ts': MODEL,
    'server.ts': FINALE.replace("exclude: ['password']", "exclude: ['password', 'role']"),
  }, (r) => r.findings.map((f) => f.rule_id));
  assert.ok(!ids.includes('auto-crud-exposes-privileged-field'));
});

test('a model with no privileged column is not a finding', () => {
  const ids = run({
    'models/product.ts': 'export class ProductModel {\n  declare name: string\n}\n',
    'server.ts': FINALE.replace("name: 'User'", "name: 'Product'"),
  }, (r) => r.findings.map((f) => f.rule_id));
  assert.ok(!ids.includes('auto-crud-exposes-privileged-field'));
});

test('a hand-written route over the same model is out of scope for this check', () => {
  // The check is about a generator publishing columns, not about every handler.
  assert.deepEqual(
    autoCrudExposesPrivilegedField({
      modelFields: collectModelFields('models/user.ts', MODEL),
      autoCrud: collectAutoCrud('server.ts', "app.post('/api/Users', create)"),
    }),
    [],
  );
});

// --- the caller is fetched and then ignored

test('a handler that looks up the account and never uses it is found', () => {
  const src = [
    'export function updateReviews () {',
    '  return (req, res) => {',
    '    const user = security.authenticatedUsers.from(req)',
    '    db.reviewsCollection.update({ _id: req.body.id }, { $set: { message: req.body.message } })',
    '  }',
    '}',
  ].join('\n');
  const out = callerIdentityFetchedAndUnused('routes/r.js', src.split('\n'), src);
  assert.equal(out.length, 1);
  assert.equal(out[0].rule_id, 'caller-identity-fetched-and-unused');
  assert.match(out[0].detail, /`user` is bound here and never read again/);
});

test('a handler that puts the account into the filter is not a finding', () => {
  const src = [
    'export function updateReviews () {',
    '  return (req, res) => {',
    '    const user = security.authenticatedUsers.from(req)',
    '    db.reviewsCollection.update({ _id: req.body.id, author: user.data.email }, { $set: {} })',
    '  }',
    '}',
  ].join('\n');
  assert.deepEqual(callerIdentityFetchedAndUnused('routes/r.js', src.split('\n'), src), []);
});

test('a scope that reads nothing from a store is not a finding', () => {
  const src = [
    'export function ping () {',
    '  return (req, res) => {',
    '    const user = req.session.user',
    '    res.json({ ok: true })',
    '  }',
    '}',
  ].join('\n');
  assert.deepEqual(callerIdentityFetchedAndUnused('routes/r.js', src.split('\n'), src), []);
});
