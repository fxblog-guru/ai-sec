// Repo-wide structural checks: the findings that are about the target as a whole.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { routesWithoutAnyGuard, REPO_CHECKS } from '../adapters/scanners/builtin/structural.mjs';
import { scanRepo } from '../adapters/scanners/builtin/engine.mjs';

test('routes with no guard anywhere is a finding, not just a note on another command', () => {
  // `sec discover` has always printed "routes but no authorization guard was
  // detected" and called it the headline. Nothing turned it into a finding, so it
  // never reached a verdict, a baseline or CI. On OWASP NodeGoat that meant 22
  // routes and no guard produced nothing, while forty dependency CVEs did.
  const out = routesWithoutAnyGuard({ routeFiles: ['app/routes/index.js'], routesSeen: 22, guardsSeen: 0 });
  assert.equal(out.length, 1);
  assert.equal(out[0].rule_id, 'no-authorization-guard');
  assert.deepEqual(out[0].rule.classification.cwe, ['CWE-306']);
  assert.match(out[0].detail, /22 route\(s\)/);
  assert.equal(out[0].detection_method, 'pattern',
    'absence of evidence in files we can read is not proof; a gateway is a real answer');
});

test('one guard anywhere is enough to silence it', () => {
  assert.deepEqual(routesWithoutAnyGuard({ routeFiles: ['a.js'], routesSeen: 9, guardsSeen: 1 }), []);
});

test('a target with no routes is not accused of failing to guard them', () => {
  assert.deepEqual(routesWithoutAnyGuard({ routeFiles: [], routesSeen: 0, guardsSeen: 0 }), []);
});

test('the engine counts routes and guards across the whole target', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ai-sec-repo-'));
  try {
    mkdirSync(join(dir, 'routes'), { recursive: true });
    writeFileSync(join(dir, 'routes', 'a.js'),
      "app.get('/one', h);\napp.post('/two', h);\n", 'utf8');
    writeFileSync(join(dir, 'routes', 'b.js'), "app.get('/three', h);\n", 'utf8');

    const hit = scanRepo(dir).findings.find((f) => f.rule_id === 'no-authorization-guard');
    assert.ok(hit, 'the relationship spans files, so no per-file check can see it');
    assert.match(hit.detail, /3 route\(s\)/);
    assert.match(hit.detail, /2 file\(s\)/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a guard in a different file than the routes still counts', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ai-sec-repo2-'));
  try {
    writeFileSync(join(dir, 'routes.js'), "app.get('/one', h);\n", 'utf8');
    writeFileSync(join(dir, 'server.js'), 'app.use(requireAuth);\n', 'utf8');
    assert.equal(
      scanRepo(dir).findings.filter((f) => f.rule_id === 'no-authorization-guard').length,
      0,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('mock/ has a guard, so it is not reported', () => {
  assert.equal(
    scanRepo('mock').findings.filter((f) => f.rule_id === 'no-authorization-guard').length,
    0,
    'mock registers requireAdmin; the finding there is the ORDER, not the absence',
  );
});

test('every repo check tolerates an empty target', () => {
  for (const check of REPO_CHECKS) {
    assert.deepEqual(check({}), [], 'a check that throws on nothing cannot run on a fresh repo');
  }
});

test('a guard passed as a route argument counts as a guard', () => {
  // NodeGoat registers `app.get("/profile", isLoggedIn, handler)` and never calls
  // app.use with a guard. Matching only the use form reported "no authorization
  // guard anywhere" on an application that has one — and that false positive was
  // propping up M5's grade until it was removed.
  const dir = mkdtempSync(join(tmpdir(), 'ai-sec-argguard-'));
  try {
    writeFileSync(join(dir, 'routes.js'),
      'app.get("/profile", isLoggedIn, displayProfile);\napp.get("/memos", isLoggedIn, listMemos);\n', 'utf8');
    assert.equal(
      scanRepo(dir).findings.filter((f) => f.rule_id === 'no-authorization-guard').length,
      0,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a plain handler argument is not mistaken for a guard', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ai-sec-argguard2-'));
  try {
    writeFileSync(join(dir, 'routes.js'),
      'app.get("/items", parseQuery, listItems);\n', 'utf8');
    assert.equal(
      scanRepo(dir).findings.filter((f) => f.rule_id === 'no-authorization-guard').length,
      1,
      'parseQuery answers no question about who may do what',
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('ssrf is found through whichever http client the target chose', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ai-sec-ssrf-'));
  try {
    // NodeGoat uses needle, which the rule did not know, so a textbook SSRF was
    // invisible while forty dependency CVEs were reported.
    writeFileSync(join(dir, 'research.js'), [
      'function research(req, res) {',
      '  const url = req.query.url + req.query.symbol;',
      '  return needle.get(url, (error, response, body) => res.write(body));',
      '}',
    ].join('\n'), 'utf8');

    const hit = scanRepo(dir).findings.find((f) => f.rule_id === 'ssrf');
    assert.ok(hit, 'an unlisted client is a silent miss, not a smaller finding');
    assert.equal(hit.detection_method, 'dataflow');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// --- IDOR: the defect is a relationship and an absence, not a bad line

import { objectReferenceWithoutOwnershipCheck } from '../adapters/scanners/builtin/structural.mjs';

const idor = (src) => objectReferenceWithoutOwnershipCheck('h.js', src.split('\n'), src);

test('an identity from the URL used to read data, with no caller check, is reported', () => {
  const out = idor([
    'this.displayAllocations = (req, res, next) => {',
    '  const {',
    '    userId',
    '  } = req.params;',
    '  allocationsDAO.getByUserIdAndThreshold(userId, threshold, cb);',
    '};',
  ].join('\n'));

  assert.equal(out.length, 1, 'the binding spans three lines; a per-line regex misses it');
  assert.equal(out[0].location.symbol, 'displayAllocations',
    'this.x = () => is how every handler here is written, and the symbol is in the fingerprint');
  assert.deepEqual(out[0].rule.classification.cwe, ['CWE-639']);
  assert.equal(out[0].insertion_point.name, 'userId');
});

test('taking the identity from the session instead is not reported', () => {
  const out = idor([
    'this.displayAllocations = (req, res) => {',
    '  const { userId } = req.session;',
    '  const { threshold } = req.query;',
    '  allocationsDAO.getByUserIdAndThreshold(userId, threshold, cb);',
    '};',
  ].join('\n'));
  assert.deepEqual(out, []);
});

test('a fix in a comment is not a fix', () => {
  // NodeGoat carries its own remediation commented out directly above the defect.
  // Reading req.session there would silence the check on the one file it exists for.
  const out = idor([
    'this.displayAllocations = (req, res) => {',
    '  /*',
    '  // Fix for A4 - take user id from session instead of from URL param',
    '  const { userId } = req.session;',
    '  */',
    '  const { userId } = req.params;',
    '  allocationsDAO.getByUserIdAndThreshold(userId, threshold, cb);',
    '};',
  ].join('\n'));
  assert.equal(out.length, 1, 'commented-out code must not count as a check');
});

test('a scope that is not an identity is not an IDOR', () => {
  // A threshold, a page number or a sort order comes from the request by design.
  const out = idor([
    'this.list = (req, res) => {',
    '  const { threshold } = req.query;',
    '  allocationsDAO.findBy(threshold, cb);',
    '};',
  ].join('\n'));
  assert.deepEqual(out, []);
});

test('an identity that is never used to read anything is not reported', () => {
  const out = idor([
    'this.echo = (req, res) => {',
    '  const { userId } = req.params;',
    '  res.json({ userId });',
    '};',
  ].join('\n'));
  assert.deepEqual(out, [], 'nothing is fetched with it, so nothing crosses a boundary');
});

test('it is Tentative, because an admin endpoint legitimately names another user', () => {
  const out = idor([
    'this.get = (req, res) => {',
    '  const { userId } = req.params;',
    '  userDAO.findById(userId, cb);',
    '};',
  ].join('\n'));
  assert.equal(out[0].detection_method, 'pattern');
});

// --- Sensitive fields written as they arrived

import { sensitiveFieldStoredInCleartext } from '../adapters/scanners/builtin/structural.mjs';

const cleartext = (src) => sensitiveFieldStoredInCleartext('dao.js', src.split('\n'), src);

test('a national id written straight to storage is reported', () => {
  const out = cleartext([
    'this.updateUser = (userId, ssn, dob, callback) => {',
    '  const user = {};',
    '  user.ssn = ssn;',
    '  user.dob = dob;',
    '  users.updateOne({ _id: userId }, { $set: user }, callback);',
    '};',
  ].join('\n'));
  assert.equal(out.length, 2);
  assert.deepEqual(out.map((f) => f.rule.classification.cwe[0]), ['CWE-311', 'CWE-311']);
  assert.match(out[0].detail, /ssn/);
});

test('a field that is encrypted first is not reported', () => {
  const out = cleartext([
    'this.updateUser = (userId, ssn, callback) => {',
    '  const user = {};',
    '  user.ssn = encrypt(ssn);',
    '  users.updateOne({ _id: userId }, { $set: user }, callback);',
    '};',
  ].join('\n'));
  assert.deepEqual(out, []);
});

test('an encrypted version sitting in a comment does not count', () => {
  // NodeGoat defines encrypt(), writes a comment saying to use it for SSN and
  // date of birth, and then assigns both raw with the fix commented out below.
  const out = cleartext([
    'this.updateUser = (userId, ssn, callback) => {',
    '  const user = {};',
    '  user.ssn = ssn;',
    '  // Store encrypted ssn',
    '  // user.ssn = encrypt(ssn);',
    '  users.updateOne({ _id: userId }, { $set: user }, callback);',
    '};',
  ].join('\n'));
  assert.equal(out.length, 1);
});

test('a field nobody could call sensitive is left alone', () => {
  const out = cleartext([
    'this.updateUser = (userId, nickname, callback) => {',
    '  const user = {};',
    '  user.nickname = nickname;',
    '  users.updateOne({ _id: userId }, { $set: user }, callback);',
    '};',
  ].join('\n'));
  assert.deepEqual(out, []);
});

test('reading a sensitive field from the request is not storing it', () => {
  const out = cleartext([
    'this.handle = (req, res) => {',
    '  const body = {};',
    '  body.ssn = req.body.ssn;',
    '  res.json(body);',
    '};',
  ].join('\n'));
  assert.deepEqual(out, [], 'nothing here writes to storage');
});

// --- Authorization middleware that exists and is applied by nothing

import { authorizationMiddlewareNeverUsed } from '../adapters/scanners/builtin/structural.mjs';

test('a guard the author wrote and no route uses is reported', () => {
  const out = authorizationMiddlewareNeverUsed({
    authzDefined: new Map([['isAdmin', { file: 'routes/index.js', line: 27 }]]),
    guardNamesUsed: new Set(['isLoggedIn']),
  });
  assert.equal(out.length, 1);
  assert.deepEqual(out[0].rule.classification.cwe, ['CWE-862']);
  assert.equal(out[0].detection_method, 'config',
    'unlike "no guard anywhere", this does not depend on enforcement we cannot see');
  assert.match(out[0].detail, /isAdmin/);
});

test('a guard that is applied is not reported', () => {
  assert.deepEqual(authorizationMiddlewareNeverUsed({
    authzDefined: new Map([['requireAdmin', { file: 'a.js', line: 1 }]]),
    guardNamesUsed: new Set(['requireAdmin']),
  }), []);
});

test('a codebase with no authorization middleware at all says nothing here', () => {
  assert.deepEqual(authorizationMiddlewareNeverUsed({}), [],
    'that is the no-guard check\'s job, and it answers a different question');
});

test('a route registration inside a comment does not count as applying a guard', () => {
  // NodeGoat keeps the working registrations — the ones that pass through
  // isAdmin — in a block comment directly below the vulnerable pair. Counting
  // commented text would report the guard as applied and hide the defect.
  const dir = mkdtempSync(join(tmpdir(), 'ai-sec-authz-'));
  try {
    writeFileSync(join(dir, 'index.js'), [
      'const isAdmin = sessionHandler.isAdminUserMiddleware;',
      'app.get("/benefits", isLoggedIn, benefitsHandler.display);',
      '/* Fix for A7 - checks user role',
      ' app.get("/benefits", isLoggedIn, isAdmin, benefitsHandler.display);',
      ' */',
    ].join('\n'), 'utf8');

    const hits = scanRepo(dir).findings.filter((f) => f.rule_id === 'authorization-middleware-unused');
    assert.equal(hits.length, 1, 'the commented fix must not silence the finding it describes');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a middleware applied as the second route argument is applied', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ai-sec-authz2-'));
  try {
    writeFileSync(join(dir, 'index.js'), [
      'const isAdmin = sessionHandler.isAdminUserMiddleware;',
      'app.get("/benefits", isLoggedIn, isAdmin, benefitsHandler.display);',
    ].join('\n'), 'utf8');

    assert.equal(
      scanRepo(dir).findings.filter((f) => f.rule_id === 'authorization-middleware-unused').length,
      0,
      'capturing only the first middleware would call this unapplied',
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a lookup table whose name contains "allow" is not middleware', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ai-sec-authz3-'));
  try {
    writeFileSync(join(dir, 'a.js'), [
      'const ALLOWED_ACTIONS = { refund: doRefund, close: doClose };',
      '',
      'async function classify(req, res) {',
      '  return res.json(ALLOWED_ACTIONS);',
      '}',
    ].join('\n'), 'utf8');

    assert.equal(
      scanRepo(dir).findings.filter((f) => f.rule_id === 'authorization-middleware-unused').length,
      0,
      'a finding like that teaches a reader to stop reading',
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
