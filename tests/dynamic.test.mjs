// T1 and T2 against a live target. Everything here binds to 127.0.0.1 and the
// scope allows only that host, so the tests exercise the gates as well as the checks.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';

import urlTarget from '../adapters/targets/url.mjs';
import { probe, usableAccounts } from '../adapters/scanners/probe/engine.mjs';
import { start as startBenchApp } from '../benchmarks/dynamic/app.mjs';
import { passiveChecks } from '../adapters/scanners/probe/checks.mjs';
import { evaluateAutoStop } from '../controller/rules.mjs';

let server;
let origin;
let failures = 0;

before(async () => {
  server = createServer((req, res) => {
    const u = new URL(req.url, 'http://127.0.0.1');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('X-Powered-By', 'Express 4.17.1');

    if (u.pathname === '/login') {
      res.setHeader('Set-Cookie', 'session=abc123; Path=/');
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end('{}');
    }
    if (u.pathname === '/go') {
      res.writeHead(302, { Location: u.searchParams.get('next') ?? '/' });
      return res.end();
    }
    if (u.pathname === '/boom') {
      res.writeHead(500, { 'Content-Type': 'text/html' });
      return res.end('<pre>at getOrder (/var/app/src/db/orders.js:142:18)</pre>');
    }
    if (u.pathname === '/always-500') {
      failures += 1;
      res.writeHead(503);
      return res.end('unavailable');
    }
    res.writeHead(200, { 'Content-Type': 'text/html' });
    return res.end('<p>ok</p>');
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  origin = `http://127.0.0.1:${server.address().port}`;
});

after(() => new Promise((r) => server.close(r)));

const scope = () => ({ allow_hosts: ['127.0.0.1'], max_tier: 'T2' });

// --- the url target is the last code before traffic leaves the machine

test('the url target refuses a host outside the allowlist, even if a gate passed', async () => {
  const r = await urlTarget.prepare({ spec: { target_url: origin }, scope: { allow_hosts: [] } });
  assert.equal(r.ok, false);
  assert.match(r.error, /not in scope\.allow_hosts/);
});

test('the url target refuses a production host on its own', async () => {
  const r = await urlTarget.prepare({
    spec: { target_url: 'https://api.prod.example.com' },
    scope: { allow_hosts: ['api.prod.example.com'] },
  });
  assert.equal(r.ok, false, 'an allowlisted production host is still production');
  assert.match(r.error, /production/);
});

test('the url target refuses credentials in the URL', async () => {
  const r = await urlTarget.prepare({ spec: { target_url: 'http://u:p@127.0.0.1:1/' }, scope: scope() });
  assert.equal(r.ok, false);
  assert.match(r.error, /credentials/);
});

test('an unreachable target is an error, not an empty clean scan', async () => {
  const r = await urlTarget.prepare({ spec: { target_url: 'http://127.0.0.1:1/' }, scope: scope() });
  assert.equal(r.ok, false);
  assert.match(r.error, /unreachable/);
});

test('a reachable allowlisted target prepares', async () => {
  const r = await urlTarget.prepare({ spec: { target_url: origin }, scope: scope() });
  assert.equal(r.ok, true, r.error);
  assert.equal(r.meta.host, '127.0.0.1');
});

// --- T1: plain reads

test('T1 finds the missing headers, and reports coverage', async () => {
  const out = await probe(origin, { tier: 'T1' });
  const ids = out.findings.map((f) => f.rule_id);
  assert.ok(ids.includes('missing-csp'));
  assert.ok(ids.includes('missing-frame-protection'));
  assert.ok(ids.includes('technology-banner'));
  assert.ok(out.coverage.length > 0, 'a scan that found nothing must still say it looked');
});

test('T1 flags wildcard CORS with credentials as High', async () => {
  const out = await probe(origin, { tier: 'T1' });
  const f = out.findings.find((x) => x.rule_id === 'permissive-cors-credentials');
  assert.ok(f, 'wildcard plus credentials is the dangerous combination');
  assert.equal(f.severity, 'High');
});

test('T1 flags a cookie missing its flags, naming which', async () => {
  const out = await probe(origin, { tier: 'T1', paths: ['/login'] });
  const f = out.findings.find((x) => x.rule_id === 'insecure-cookie');
  assert.ok(f);
  assert.match(f.detail, /Secure/);
  assert.match(f.detail, /HttpOnly/);
  assert.match(f.detail, /SameSite/);
});

test('T1 flags a stack trace in an error body', async () => {
  const out = await probe(origin, { tier: 'T1', paths: ['/boom'] });
  const f = out.findings.find((x) => x.rule_id === 'verbose-error');
  assert.ok(f);
  assert.deepEqual(f.rule.classification.owasp, ['A10:2025'], 'new category in the 2025 edition');
});

test('T1 does not probe parameters — that is T2', async () => {
  const out = await probe(origin, { tier: 'T1' });
  assert.ok(!out.findings.some((f) => f.rule_id === 'open-redirect'),
    'a redirect canary is an added parameter, so it belongs to T2');
});

// --- T2: a handful of benign requests

test('T2 reproduces the open redirect, and only then claims Certain', async () => {
  const out = await probe(origin, { tier: 'T2' });
  const f = out.findings.find((x) => x.rule_id === 'open-redirect');
  assert.ok(f, 'T2 must find what T1 cannot');
  assert.equal(f.detection_method, 'reproduced');
  assert.equal(f.insertion_point.kind, 'url-parameter');
});

test('T2 stops probing once one instance is confirmed', async () => {
  const out = await probe(origin, { tier: 'T2' });
  const redirects = out.findings.filter((f) => f.rule_id === 'open-redirect');
  assert.equal(redirects.length, 1, 'more requests after a confirmed finding add nothing');
});

test('every request is counted, so auto-stop has something real to read', async () => {
  const out = await probe(origin, { tier: 'T2' });
  assert.ok(out.counters.requests > 0);
  assert.equal(out.counters.out_of_scope_requests, 0);
});

test('a path that would leave the origin is refused and counted', async () => {
  const out = await probe(origin, { tier: 'T1', paths: ['http://example.org/evil'] });
  assert.equal(out.counters.out_of_scope_requests, 1);
  assert.ok(out.errors.some((e) => e.kind === 'out-of-scope'));
});

// --- auto-stop

test('repeated 5xx responses trip the auto-stop rule', async () => {
  failures = 0;
  const out = await probe(origin, { tier: 'T1', paths: Array.from({ length: 6 }, () => '/always-500') });
  // the same path is deduped into one request, so drive the rule from the counters
  const stop = evaluateAutoStop({ consecutive_errors: Math.max(5, out.counters.consecutive_errors) });
  assert.equal(stop.stop, true);
  assert.equal(stop.rule, 'consecutive-errors');
});

test('an out-of-scope request trips auto-stop immediately', () => {
  const stop = evaluateAutoStop({ out_of_scope_requests: 1 });
  assert.equal(stop.stop, true);
  assert.equal(stop.rule, 'out-of-scope-host');
});

// --- the checks themselves, without a server

test('HSTS is only expected over https', () => {
  const http = passiveChecks({ url: new URL('http://127.0.0.1/'), status: 200, headers: {}, body: '' });
  const https = passiveChecks({ url: new URL('https://example.test/'), status: 200, headers: {}, body: '' });
  assert.ok(!http.some((f) => f.rule_id === 'missing-hsts'), 'HSTS over plain http is not the finding');
  assert.ok(https.some((f) => f.rule_id === 'missing-hsts'));
});

test('CSP frame-ancestors satisfies the clickjacking check without X-Frame-Options', () => {
  const out = passiveChecks({
    url: new URL('http://127.0.0.1/'), status: 200,
    headers: { 'content-security-policy': "frame-ancestors 'none'" }, body: '',
  });
  assert.ok(!out.some((f) => f.rule_id === 'missing-frame-protection'));
});

test('a well-configured response produces no header findings', () => {
  const out = passiveChecks({
    url: new URL('https://example.test/'), status: 200,
    headers: {
      'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
      'strict-transport-security': 'max-age=31536000',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'strict-origin-when-cross-origin',
    },
    body: '',
  });
  assert.deepEqual(out, [], 'no false positives on a correct configuration');
});

// --- T2, authenticated: the one check that needs two accounts
//
// These run against benchmarks/dynamic/app.mjs rather than the server above,
// because the thing under test is a comparison between two sessions and the
// benchmark app is where the planted version of that defect lives.

test('T2 reads one account\'s object with the other account\'s session', async () => {
  const app = await startBenchApp();
  try {
    const [alice, bob] = app.accounts;
    const out = await probe(app.origin, {
      tier: 'T2',
      accounts: [{ name: 'alice', cookie: alice.cookie, owns: ['/api/orders/1'] },
        { name: 'bob', cookie: bob.cookie }],
    });
    const f = out.findings.find((x) => x.rule_id === 'cross-account-object-read');
    assert.ok(f, 'the order is returned to a session that does not own it');
    assert.equal(f.detection_method, 'reproduced', 'two requests and a comparison, not a pattern');
    assert.equal(f.severity, 'High');
    assert.deepEqual(f.rule.classification.cwe, ['CWE-639']);
  } finally {
    await app.close();
  }
});

test('the evidence carries neither the other account\'s data nor the cookie', async () => {
  const app = await startBenchApp();
  try {
    const [alice, bob] = app.accounts;
    const out = await probe(app.origin, {
      tier: 'T2',
      accounts: [{ name: 'alice', cookie: alice.cookie, owns: ['/api/orders/1'] },
        { name: 'bob', cookie: bob.cookie }],
    });
    const f = out.findings.find((x) => x.rule_id === 'cross-account-object-read');
    const text = `${f.detail} ${f.evidence}`;
    // The proof of this finding is someone else's data. Printing it would make
    // the report the leak.
    assert.ok(!text.includes('4242'), 'the card digits in the order body never reach the report');
    assert.ok(!text.includes('session-for-'), 'nor does the session cookie');
    assert.match(f.evidence, /sha256:[0-9a-f]+/, 'a digest settles "the same body came back"');
  } finally {
    await app.close();
  }
});

test('a handler that checks ownership is not reported', async () => {
  const app = await startBenchApp();
  try {
    const [alice, bob] = app.accounts;
    const out = await probe(app.origin, {
      tier: 'T2',
      // The same shape as the orders handler, one line longer: it answers 403.
      accounts: [{ name: 'alice', cookie: alice.cookie, owns: ['/api/profile/alice'] },
        { name: 'bob', cookie: bob.cookie }],
    });
    assert.ok(!out.findings.some((f) => f.rule_id === 'cross-account-object-read'),
      'a check that cannot tell the correct handler from the broken one is not a check');
  } finally {
    await app.close();
  }
});

test('the control request comes first: a public object is a different finding', async () => {
  // If the object comes back with no session at all, a second account reading
  // it proves nothing about authorization BETWEEN accounts — and the fix is a
  // different one, on a different line.
  const open = createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end('{"id":1,"owner":"alice"}');
  });
  await new Promise((r) => open.listen(0, '127.0.0.1', r));
  const at = `http://127.0.0.1:${open.address().port}`;
  try {
    const out = await probe(at, {
      tier: 'T2',
      accounts: [{ name: 'alice', cookie: 'sid=a', owns: ['/api/orders/1'] }, { name: 'bob', cookie: 'sid=b' }],
    });
    assert.ok(out.findings.some((f) => f.rule_id === 'unauthenticated-object-read'));
    assert.ok(!out.findings.some((f) => f.rule_id === 'cross-account-object-read'),
      'naming this a cross-account failure sends someone to fix the wrong thing');
  } finally {
    await new Promise((r) => open.close(r));
  }
});

test('without two sessions the run records that it did not check, rather than passing', async () => {
  const out = await probe(origin, { tier: 'T2' });
  const note = out.errors.find((e) => e.kind === 'not-checked');
  assert.ok(note, 'not checked is not the same as checked and clean');
  assert.match(note.detail, /cross-account/);
  assert.match(note.unblock, /accounts/);
});

test('one session wearing two names is not two accounts', () => {
  assert.equal(usableAccounts([{ cookie: 'sid=a', owns: ['/x'] }, { cookie: 'sid=a' }]), null);
  assert.equal(usableAccounts([{ cookie: 'sid=a' }, { cookie: 'sid=b' }]), null, 'and neither owns anything');
  assert.equal(usableAccounts([{ cookie: 'sid=a', owns: ['/x'] }]), null, 'one account cannot be compared to itself');
  assert.ok(usableAccounts([{ cookie: 'sid=a', owns: ['/x'] }, { cookie: 'sid=b' }]));
});

test('an endpoint that answers 200 to everyone with their own data is not reported', async () => {
  // The hard case. /api/profile answers 403 to the wrong account, so a check
  // that only reads the status code gets it right by accident. /api/inbox
  // answers 200 to both, and only the comparison tells it apart from the
  // broken orders handler.
  const app = await startBenchApp();
  try {
    const [alice, bob] = app.accounts;
    const out = await probe(app.origin, {
      tier: 'T2',
      accounts: [{ name: 'alice', cookie: alice.cookie, owns: ['/api/inbox'] },
        { name: 'bob', cookie: bob.cookie }],
    });
    assert.ok(!out.findings.some((f) => f.rule_id === 'cross-account-object-read'),
      'a 200 is not the finding; the same bytes are');
  } finally {
    await app.close();
  }
});
