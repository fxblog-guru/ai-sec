// The eight rules that scanning OWASP Juice Shop asked for.
//
// Each one is paired with the shape it must NOT fire on. A rule that only has a
// positive test is a rule nobody has checked the cost of: `nosql-operator-injection`
// passed its positive test and reported an ordinary Sequelize profile update as
// NoSQL injection, which names the wrong cause and sends someone to fix the
// wrong line.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';

import { scanRepo } from '../adapters/scanners/builtin/engine.mjs';

function repoWith(files) {
  const dir = mkdtempSync(join(tmpdir(), 'sec-rules-'));
  for (const [name, body] of Object.entries(files)) {
    const p = join(dir, name);
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, body, 'utf8');
  }
  return dir;
}

function idsFor(files) {
  const dir = repoWith(files);
  try {
    return (scanRepo(dir).findings ?? []).map((f) => f.rule_id);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const fires = (id, files) => assert.ok(idsFor(files).includes(id), `${id} did not fire`);
const quiet = (id, files) => assert.ok(!idsFor(files).includes(id), `${id} fired and should not have`);

test('bypass-framework-escaping: the escape hatch with a value in it', () => {
  fires('bypass-framework-escaping', {
    'src/a.ts': 'this.html = this.sanitizer.bypassSecurityTrustHtml(row.description)\n',
  });
});

test('bypass-framework-escaping: a literal is the case the API exists for', () => {
  quiet('bypass-framework-escaping', {
    'src/a.ts': "this.html = this.sanitizer.bypassSecurityTrustHtml('<b>static</b>')\n",
  });
});

test('nosql-operator-injection: a request value as a lookup key', () => {
  fires('nosql-operator-injection', {
    'src/a.js': [
      'function update(req, res) {',
      '  db.reviewsCollection.update(',
      '    { _id: req.body.id },',
      '    { $set: { message: req.body.message } }',
      '  )',
      '}',
    ].join('\n'),
  });
});

test('nosql-operator-injection: a Sequelize update is a different defect', () => {
  // The real miss: `user.update({ username: req.body.username })` is not an
  // operator injection, and reporting it as one names the wrong cause.
  quiet('nosql-operator-injection', {
    'src/a.js': [
      'async function save(req, res) {',
      '  const saved = await user.update({ username: req.body.username })',
      '  res.json(saved)',
      '}',
    ].join('\n'),
  });
});

test('nosql-operator-injection: a sequelize where clause binds its values', () => {
  quiet('nosql-operator-injection', {
    'src/a.js': [
      'async function credit(req, res) {',
      '  await WalletModel.increment({ balance: 10 }, { where: { UserId: req.body.UserId } })',
      '}',
    ].join('\n'),
  });
});

test('commented-out-authorization: the guard is still in the file', () => {
  fires('commented-out-authorization', {
    'src/server.js': [
      "app.post('/api/Products', security.isAuthorized())",
      "// app.put('/api/Products/:id', security.isAuthorized())",
      "app.delete('/api/Products/:id', security.denyAll())",
    ].join('\n'),
  });
});

test('commented-out-authorization: a live guard is not a finding', () => {
  quiet('commented-out-authorization', {
    'src/server.js': "app.put('/api/Products/:id', security.isAuthorized(), update)\n",
  });
});

test('commented-out-authorization: a commented route without a guard is not this', () => {
  quiet('commented-out-authorization', {
    'src/server.js': "// app.get('/api/health', sendOk)\n",
  });
});

test('rate-limit-keyed-on-client-header: the key is a header', () => {
  fires('rate-limit-keyed-on-client-header', {
    'src/server.js': [
      'app.use(rateLimit({',
      '  max: 100,',
      "  keyGenerator ({ headers, ip }) { return headers['X-Forwarded-For'] ?? ip }",
      '}))',
    ].join('\n'),
  });
});

test('rate-limit-keyed-on-client-header: keying on the address is the fix, not the bug', () => {
  quiet('rate-limit-keyed-on-client-header', {
    'src/server.js': [
      'app.use(rateLimit({',
      '  max: 100,',
      '  keyGenerator (req) { return req.ip }',
      '}))',
    ].join('\n'),
  });
});

test('directory-listing-enabled: serveIndex makes a directory browsable', () => {
  fires('directory-listing-enabled', {
    'src/server.js': "app.use('/ftp', serveIndex('ftp', { icons: true }))\n",
  });
});

test('directory-listing-enabled: serving files is not listing them', () => {
  quiet('directory-listing-enabled', {
    'src/server.js': "app.use('/public', express.static('public'))\n",
  });
});

test('exposed-operational-endpoint: /metrics with nothing in front of it', () => {
  fires('exposed-operational-endpoint', {
    'src/server.js': "app.get('/metrics', asyncHandler(serveMetrics()))\n",
  });
});

test('exposed-operational-endpoint: the same route behind a guard is not a finding', () => {
  quiet('exposed-operational-endpoint', {
    'src/server.js': "app.get('/metrics', requireAuth(), asyncHandler(serveMetrics()))\n",
  });
});

test('allowlist-matched-by-substring: includes() is not an origin comparison', () => {
  fires('allowlist-matched-by-substring', {
    'src/a.js': [
      'function isRedirectAllowed (url) {',
      '  let allowed = false',
      '  for (const allowedUrl of redirectAllowlist) {',
      '    allowed = allowed || url.includes(allowedUrl)',
      '  }',
      '  return allowed',
      '}',
    ].join('\n'),
  });
});

test('allowlist-matched-by-substring: comparing the parsed origin is the fix', () => {
  quiet('allowlist-matched-by-substring', {
    'src/a.js': [
      'function isRedirectAllowed (url) {',
      '  return redirectAllowlist.has(new URL(url).origin)',
      '}',
    ].join('\n'),
  });
});

test('tool-bound-stated-only-in-prose: the limit is in the sentence, not the schema', () => {
  fires('tool-bound-stated-only-in-prose', {
    'src/chat.js': [
      'const couponTool = tool({',
      '  inputSchema: z.object({',
      "    discount: z.number().describe('The discount percentage for the coupon (maximum 10)')",
      '  }),',
      '  execute: async ({ discount }) => ({ code: generateCoupon(discount) })',
      '})',
    ].join('\n'),
  });
});

test('tool-bound-stated-only-in-prose: a schema that encodes the bound is quiet', () => {
  quiet('tool-bound-stated-only-in-prose', {
    'src/chat.js': [
      'const couponTool = tool({',
      '  inputSchema: z.object({',
      "    discount: z.number().max(10).describe('The discount percentage (maximum 10)')",
      '  }),',
      '  execute: async ({ discount }) => ({ code: generateCoupon(discount) })',
      '})',
    ].join('\n'),
  });
});

test('tool-bound-stated-only-in-prose: prose with no bound in it is documentation', () => {
  quiet('tool-bound-stated-only-in-prose', {
    'src/chat.js': [
      'const lookupTool = tool({',
      '  inputSchema: z.object({',
      "    city: z.string().describe('The city to look the forecast up for')",
      '  })',
      '})',
    ].join('\n'),
  });
});

test('a rule that declares a subtype carries it onto the finding', () => {
  const dir = repoWith({
    'src/server.js': "app.use('/ftp', serveIndex('ftp'))\n",
  });
  try {
    const f = (scanRepo(dir).findings ?? []).find((x) => x.rule_id === 'directory-listing-enabled');
    assert.equal(f.subtype, 'directory-listing');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a rule that declares none does not get an empty one', () => {
  // A subtype changes the fingerprint. Handing every rule one would re-identify
  // every finding already sitting in somebody's baseline.
  const dir = repoWith({ 'src/a.js': 'db.query(`SELECT * FROM t WHERE id = ${req.body.id}`)\n' });
  try {
    const f = (scanRepo(dir).findings ?? []).find((x) => x.rule_id === 'sql-injection');
    assert.ok(f, 'sql-injection still fires');
    assert.equal('subtype' in f, false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
