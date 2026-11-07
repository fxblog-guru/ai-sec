// The built-in scanner against the planted defects in mock/.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

import { scanRepo, enclosingSymbol, unreachedModelSdks } from '../adapters/scanners/builtin/engine.mjs';
import { MODEL_CALL, MODEL_SDK_IMPORT, SOURCE_RE } from '../adapters/scanners/builtin/rules.mjs';
import { STATIC_BLIND_SPOTS } from '../lib/discover.mjs';
import { routesBeforeGuard, queriesWithoutTenant } from '../adapters/scanners/builtin/structural.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const MOCK = join(ROOT, 'mock');
const EXPECTED = JSON.parse(readFileSync(join(MOCK, 'expected.json'), 'utf8'));

const scan = scanRepo(MOCK);
const has = (id) => scan.findings.some((f) => f.rule_id === id);
const at = (id) => scan.findings.find((f) => f.rule_id === id);

test('the scan reports coverage, so a clean result would be meaningful', () => {
  assert.ok(scan.coverage.length > 0);
  assert.ok(scan.coverage.some((c) => c.kind === 'languages' && c.detail === 'javascript'));
  assert.ok(scan.coverage.find((c) => c.kind === 'files').count > 0);
});

for (const id of ['sql-injection', 'path-traversal', 'ssrf', 'open-redirect',
  'weak-randomness', 'weak-password-hash', 'hardcoded-credential',
  'container-runs-as-root', 'permissive-cors']) {
  test(`finds the planted ${id}`, () => {
    assert.ok(has(id), `${id} not found in mock/`);
  });
}

test('a secret finding never carries the secret itself', () => {
  const f = at('hardcoded-credential');
  assert.ok(!f.evidence.includes('AKIAIOSFODNN7EXAMPLE'), 'the matched line must not be carried');
  assert.match(f.evidence, /config\/settings\.js:\d+/, 'location only');
});

test('a dataflow rule claims dataflow only when a source is in scope', () => {
  assert.equal(at('sql-injection').detection_method, 'dataflow');
  // weak-randomness is a pattern rule: it never claims more than it saw
  assert.equal(at('weak-randomness').detection_method, 'pattern');
});

test('findings carry their classification and the enclosing symbol', () => {
  const f = at('sql-injection');
  assert.deepEqual(f.rule.classification.cwe, ['CWE-89']);
  assert.deepEqual(f.rule.classification.owasp, ['A05:2025']);
  assert.equal(f.location.symbol, 'getOrder');
});

test('a route registered before its guard is found, with the ordering as the reason', () => {
  const f = at('authz-before-guard');
  assert.ok(f, 'authz-before-guard not found');
  assert.match(f.detail, /registered on line \d+, above \w+ on line \d+/);
  assert.match(f.detail, /guard never runs/);
  assert.deepEqual(f.rule.classification.cwe, ['CWE-862']);
});

test('a query missing its tenant predicate is found, and is NOT called injection', () => {
  const f = at('missing-tenant-predicate');
  assert.ok(f, 'missing-tenant-predicate not found');
  assert.equal(f.location.symbol, 'findOrder');
  assert.match(f.detail, /not injectable/);
  assert.deepEqual(f.rule.classification.cwe, ['CWE-639']);
  // the whole point: it is an access-control failure, not an injection one
  assert.deepEqual(f.rule.classification.owasp, ['A01:2025']);
});

test('the tenant check stays Tentative, because it was inferred and not proved', () => {
  assert.equal(at('missing-tenant-predicate').detection_method, 'pattern');
});

test('the scoped sibling query is not flagged', () => {
  const inDb = scan.findings.filter(
    (f) => f.rule_id === 'missing-tenant-predicate' && f.location.file === 'app/db.js',
  );
  assert.equal(inDb.length, 1, 'only findOrder, not listOrders');
});

test('structural checks need their precondition', () => {
  // no guard registered at all: nothing to be "before"
  assert.deepEqual(routesBeforeGuard('r.js', ["router.delete('/admin/x', h)"]), []);
  // no sign of multi-tenancy: we do not guess
  assert.deepEqual(queriesWithoutTenant('d.js', ["db.query('SELECT 1')"], "db.query('SELECT 1')"), []);
});

test('every expected defect with a rule is found; gaps are explicit', () => {
  const foundCwes = new Set(scan.findings.flatMap((f) => f.rule.classification.cwe));
  const missing = EXPECTED.defects
    .filter((d) => !foundCwes.has(d.cwe))
    .map((d) => `${d.id} (${d.cwe})`);
  // M2 covers the static rules; the dependency CVE needs trivy, which may not be installed.
  assert.deepEqual(missing, [], `expected defects not found: ${missing.join(', ')}`);
});

test('a sink with no taint source in scope is not reported at all', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ai-sec-taint-'));
  try {
    // a raw query built from a constant: the sink is there, the source is not
    writeFileSync(join(dir, 'safe.js'), [
      'const TABLE = "orders";',
      'function listAll() {',
      '  return db.raw(`SELECT * FROM ${TABLE}`);',
      '}',
    ].join('\n'), 'utf8');

    const out = scanRepo(dir);
    assert.equal(
      out.findings.filter((x) => x.rule_id === 'sql-injection').length,
      0,
      'a sink without a source must not be reported as injection',
    );
    assert.ok(out.coverage.length > 0, 'and the file was still examined');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the same sink WITH a source is reported, as dataflow', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ai-sec-taint2-'));
  try {
    writeFileSync(join(dir, 'unsafe.js'), [
      'function listAll(req) {',
      '  const table = req.query.table;',
      '  return db.raw(`SELECT * FROM ${table}`);',
      '}',
    ].join('\n'), 'utf8');

    const out = scanRepo(dir);
    const hit = out.findings.find((x) => x.rule_id === 'sql-injection');
    assert.ok(hit, 'a sink reached by a source must be reported');
    assert.equal(hit.detection_method, 'dataflow');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('enclosingSymbol walks up to the declaration', () => {
  const lines = ['function outer() {', '  const x = 1;', '  db.raw(`${x}`);', '}'];
  assert.equal(enclosingSymbol(lines, 2), 'outer');
});

test('node_modules and .git are never walked', () => {
  assert.ok(!scan.findings.some((f) => /node_modules|\.git\//.test(f.location.file)));
});

// --- three defects found by scanning repositories this tool had never seen.
// Each one made the tool less trustworthy than reporting nothing at all.

test('a word in a neighbouring function does not satisfy `near`', () => {
  // Real code, screen-spider/src/antlogin.js: hasCredentials() sits six lines
  // above createPkce(), whose sha256 is the S256 challenge RFC 7636 requires.
  // A +/-25 line window read "credentials" and called it a stored password.
  const dir = mkdtempSync(join(tmpdir(), 'ai-sec-near-'));
  try {
    writeFileSync(join(dir, 'pkce.js'), [
      'function hasCredentials(profile) {',
      '  return fs.existsSync(path.join(configDir(), "credentials", profile));',
      '}',
      '',
      'function createPkce(bytes = 32) {',
      '  const verifier = randomBytes(bytes).toString("base64url");',
      '  const challenge = createHash("sha256").update(verifier).digest("base64url");',
      '  return { verifier, challenge };',
      '}',
    ].join('\n'), 'utf8');

    assert.equal(
      scanRepo(dir).findings.filter((f) => f.rule_id === 'weak-password-hash').length,
      0,
      'the PKCE challenge is in a different function from the word "credentials"',
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a hash of an actual password in the same function is still reported', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ai-sec-near2-'));
  try {
    writeFileSync(join(dir, 'auth.js'), [
      'function storePassword(user, password) {',
      '  const digest = createHash("sha256").update(password).digest("hex");',
      '  return db.save(user, digest);',
      '}',
    ].join('\n'), 'utf8');

    assert.ok(
      scanRepo(dir).findings.some((f) => f.rule_id === 'weak-password-hash'),
      'tightening the window must not switch the rule off',
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a caption is not a credential', () => {
  // screen-spider/src/panel.html:683 — `apiKey: 'Direct API key'` is a label in a
  // dropdown, reported Critical. A tool that does that gets ignored.
  const dir = mkdtempSync(join(tmpdir(), 'ai-sec-caption-'));
  try {
    writeFileSync(join(dir, 'panel.js'), [
      "const names = { console: 'Claude Console sign-in', apiKey: 'Direct API key' };",
      "const real = { apiKey: 'sk-ant-9f2b7c41d8e60a35' };",
    ].join('\n'), 'utf8');

    const hits = scanRepo(dir).findings.filter((f) => f.rule_id === 'hardcoded-credential');
    assert.equal(hits.length, 1, 'the label is out, the key is in');
    assert.equal(hits[0].location.line, 2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a language the ruleset cannot read is a blind spot, not a clean result', () => {
  // 1005 Go files, zero findings, and a ledger that mentioned only the two
  // scanners that were not installed. Silence has to be explained.
  const dir = mkdtempSync(join(tmpdir(), 'ai-sec-golang-'));
  try {
    writeFileSync(join(dir, 'main.go'),
      'package main\n\nfunc main() {\n\tdb.Query("SELECT * FROM users WHERE id = " + r.URL.Query().Get("id"))\n}\n', 'utf8');

    const out = scanRepo(dir);
    const gap = out.errors.find((e) => e.kind === 'unsupported-language');
    assert.ok(gap, 'a Go file the rules cannot read must reach the coverage ledger');
    assert.match(gap.detail, /\bgo\b/);
    assert.match(gap.detail, /not examined, not clean/);
    assert.ok(gap.unblock, 'and say what would close the gap');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('JavaScript is not reported as a blind spot', () => {
  assert.equal(
    scan.errors.filter((e) => e.kind === 'unsupported-language').length,
    0,
    'the mock is JavaScript, which the ruleset does reach',
  );
});

test('a constant command at the top level is not injection', () => {
  // The first attempt at the fix above bounded the window by declarations only.
  // At the top level of a script there are none, so the window became the whole
  // file and a constant execFileSync borrowed a process.argv forty lines away.
  const dir = mkdtempSync(join(tmpdir(), 'ai-sec-toplevel-'));
  try {
    writeFileSync(join(dir, 'build.js'), [
      "const out = process.argv[2] || 'dist';",
      ...Array.from({ length: 40 }, (_, i) => `const step${i} = prepare(${i});`),
      "const listed = execFileSync('npm ls --omit=dev --parseable', { shell: true });",
    ].join('\n'), 'utf8');

    assert.equal(
      scanRepo(dir).findings.filter((f) => f.rule_id === 'command-injection').length,
      0,
      'a declaration boundary may narrow the window, never widen it',
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// --- what an AI application nobody here wrote exposed
//
// 169 files, eleven model calls through the Vercel AI SDK, and the first scan
// reported zero M14 findings with an empty ledger. Every shape the rules knew
// was an OpenAI or Google one.

test('a model call is recognised in more than one SDK\'s vocabulary', () => {
  for (const line of [
    'const r = await openai.chat.completions.create({ model });',
    'const r = await anthropic.messages.create({ model });',
    'const r = await model.generateContent(prompt);',
    'const result = streamText({ model: getLanguageModel(id) });',
    'const { text } = await generateText({ model });',
    'const o = await generateObject({ model, schema });',
  ]) {
    assert.match(line, MODEL_CALL, line);
  }
  assert.ok(!MODEL_CALL.test('const r = chain.invoke(input);'),
    'under-claim rather than over-claim: an unrecognised shape becomes a ledger entry, not a silent pass');
});

test('a repository that calls a model through an SDK we cannot read says so', () => {
  const gap = unreachedModelSdks({ modelSdkFiles: ['lib/agent.ts'], modelCallSites: 0 });
  assert.equal(gap.length, 1);
  assert.match(gap[0].detail, /not examined, not clean/);
  assert.match(gap[0].unblock, /MODEL_CALL/);
});

test('recognising even one call means the ruleset reached the SDK', () => {
  assert.deepEqual(unreachedModelSdks({ modelSdkFiles: ['lib/agent.ts'], modelCallSites: 3 }), []);
  assert.deepEqual(unreachedModelSdks({ modelSdkFiles: [], modelCallSites: 0 }), [],
    'and a repository with no model in it has no gap to report');
});

test('an import is what says a file talks to a model', () => {
  for (const line of [
    "import OpenAI from 'openai';",
    "import { streamText } from 'ai';",
    "import { anthropic } from '@ai-sdk/anthropic';",
    "const Anthropic = require('@anthropic-ai/sdk');",
  ]) {
    assert.match(line, MODEL_SDK_IMPORT, line);
  }
  assert.ok(!MODEL_SDK_IMPORT.test("import { ai } from './local-helper';"));
});

test('untrusted input is recognised beyond Express', () => {
  // A Next.js route handler takes a Web Request. Nothing in a real Next.js
  // codebase matched the Express shapes, so every taint rule stayed silent.
  for (const line of [
    'const body = await request.json();',
    'const text = await req.text();',
    'const form = await request.formData();',
    "const next = searchParams.get('next');",
    "const name = formData.get('name');",
    'const id = req.params.id;',
  ]) {
    assert.match(line, SOURCE_RE, line);
  }
  assert.ok(!SOURCE_RE.test('const id = document.content;'),
    'and a function argument from another module is still out of reach, which is a blind spot, not a source');
});

test('the blind spot M14 cannot cross is written down, not implied by a zero', () => {
  assert.match(STATIC_BLIND_SPOTS.M14, /indirect prompt injection/);
});
