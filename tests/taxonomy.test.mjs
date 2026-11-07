// Cross-tool identity. Until this layer existed, "merge, never sum" was a claim
// with nothing behind it: two scanners describing one defect produced two
// fingerprints, so they never met and corroboration never once fired.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { issueType, normalizeCwe, cwesOf, mergeClassification, findingClass } from '../controller/taxonomy.mjs';
import { HEADER_CHECKS } from '../adapters/scanners/probe/checks.mjs';
import trivy from '../adapters/scanners/trivy/adapter.mjs';
import { fingerprint } from '../controller/fingerprint.mjs';
import { mergeFindings } from '../controller/merge.mjs';
import { placeFinding, symbolAt } from '../controller/locate.mjs';

const at = (file, line, symbol = null) => ({ file, line, symbol });

const f = (tool, rule_id, cwe, location, extra = {}) => ({
  tool,
  rule_id,
  location,
  severity: 'High',
  detection_method: 'pattern',
  rule: { classification: { cwe: [].concat(cwe) } },
  ...extra,
});

test('a CWE is recognised however the scanner spells it', () => {
  assert.equal(normalizeCwe('CWE-79'), 'CWE-79');
  assert.equal(normalizeCwe('CWE-79: Cross-site Scripting'), 'CWE-79');
  assert.equal(normalizeCwe(79), null, 'a bare number is not a CWE reference');
  assert.equal(normalizeCwe(null), null);
});

test('two numbers for one defect resolve to one type', () => {
  // Semgrep files an MD5 password hash under CWE-327 (broken algorithm); our own
  // rule files it under CWE-916 (password hash with no KDF). Both are correct,
  // and keying on the number alone leaves them as two findings forever.
  const a = issueType(f('semgrep', 'md5-used-as-password', 'CWE-327', at('a.js', 1)));
  const b = issueType(f('builtin', 'weak-password-hash', 'CWE-916', at('a.js', 1)));
  assert.equal(a.type, b.type);
  assert.equal(a.basis, 'family');
});

test('an unmapped CWE is still better identity than a rule id', () => {
  const t = issueType(f('semgrep', 'some.long.rule.id', 'CWE-99999', at('a.js', 1)));
  assert.equal(t.type, 'cwe-99999');
  assert.equal(t.basis, 'cwe', 'two tools citing the same CWE can still agree');
});

test('with no CWE at all, identity falls back to the rule and says so', () => {
  const t = issueType({ rule_id: 'custom-check' });
  assert.equal(t.type, 'custom-check');
  assert.equal(t.basis, 'rule_id', 'cross-tool merging is not possible here, and that is recorded');
});

test('identity does not depend on which scanner spoke', () => {
  const a = f('semgrep', 'javascript.express.security.audit.express-open-redirect', 'CWE-601', at('r.js', 14));
  const b = f('builtin', 'open-redirect', 'CWE-601', at('r.js', 14));
  assert.equal(fingerprint(a), fingerprint(b));
});

test('different defects on the same line stay apart', () => {
  const a = f('builtin', 'sql-injection', 'CWE-89', at('d.js', 8));
  const b = f('builtin', 'hardcoded-credential', 'CWE-798', at('d.js', 8));
  assert.notEqual(fingerprint(a), fingerprint(b));
});

test('two scanners become one finding with both named', () => {
  const merged = mergeFindings([
    f('builtin', 'open-redirect', 'CWE-601', at('r.js', 14), { severity: 'Medium', detection_method: 'pattern' }),
    f('semgrep', 'js.express.open-redirect', 'CWE-601', at('r.js', 14), { severity: 'High', detection_method: 'dataflow' }),
  ]);
  assert.equal(merged.length, 1);
  assert.deepEqual(merged[0].tools, ['builtin', 'semgrep']);
  assert.equal(merged[0].severity, 'High', 'the highest proposed severity, never an average');
  assert.equal(merged[0].issue_type, 'open-redirect');
});

test('a severity disagreement is reported, not quietly resolved', () => {
  const merged = mergeFindings([
    f('builtin', 'open-redirect', 'CWE-601', at('r.js', 14), { severity: 'Medium' }),
    f('semgrep', 'js.open-redirect', 'CWE-601', at('r.js', 14), { severity: 'High' }),
  ]);
  const d = merged[0].severity_disagreement;
  assert.ok(d, 'taking the highest and saying nothing hides a real difference of opinion');
  assert.deepEqual(d.map((x) => x.severity), ['High', 'Medium'], 'worst first');
});

test('agreement is not a disagreement', () => {
  const merged = mergeFindings([
    f('builtin', 'open-redirect', 'CWE-601', at('r.js', 14), { severity: 'High' }),
    f('semgrep', 'js.open-redirect', 'CWE-601', at('r.js', 14), { severity: 'High' }),
  ]);
  assert.equal(merged[0].severity_disagreement, null);
});

test("the tool's own enum is kept but never compared", () => {
  // semgrep says WARNING, trivy says MEDIUM. Ranking those against Critical..Info
  // puts every one of them at the bottom.
  const merged = mergeFindings([
    f('semgrep', 'x', 'CWE-601', at('r.js', 14), { severity: 'High', reported_severity: 'WARNING' }),
    f('builtin', 'open-redirect', 'CWE-601', at('r.js', 14), { severity: 'Medium', reported_severity: 'Medium' }),
  ]);
  assert.equal(merged[0].severity_disagreement[0].severity, 'High');
  assert.equal(merged[0].severity_disagreement[0].reported, 'WARNING');
});

test('the instance carries no type-level prose, and the union of CWEs is available to the type', () => {
  const merged = mergeFindings([f('builtin', 'sql-injection', 'CWE-89', at('d.js', 8))]);
  assert.equal(merged[0].background, undefined);
  assert.equal(merged[0].remediation, undefined);
  assert.deepEqual(mergeClassification([{ cwe: ['CWE-89: SQLi'] }, { cwe: ['CWE-564'], owasp: ['A03:2025'] }]), {
    cwe: ['CWE-564', 'CWE-89'], owasp: ['A03:2025'], wstg: [], asvs: [], api: [],
  });
});

test('cwesOf reads either shape an adapter may produce', () => {
  assert.deepEqual(cwesOf({ rule: { classification: { cwe: ['CWE-22'] } } }), ['CWE-22']);
  assert.deepEqual(cwesOf({ classification: { cwe: 'CWE-22: traversal' } }), ['CWE-22']);
  assert.deepEqual(cwesOf({}), []);
});

// --- the symbol, which is the other half of identity

test('a scanner that names no symbol still merges with one that does', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ai-sec-sym-'));
  try {
    writeFileSync(join(dir, 'auth.js'), [
      'function hashPassword(password) {',
      '  return createHash("sha256").update(password).digest("hex");',
      '}',
    ].join('\n'), 'utf8');

    const withSymbol = placeFinding(f('builtin', 'weak-password-hash', 'CWE-916', at('auth.js', 2, 'hashPassword')), dir);
    const without = placeFinding(f('semgrep', 'md5-used-as-password', 'CWE-327', at('auth.js', 2)), dir);

    assert.equal(without.location.symbol, 'hashPassword', 'the controller resolves it for every adapter');
    assert.equal(fingerprint(withSymbol), fingerprint(without));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('symbolAt reads declarations in languages other than JavaScript', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ai-sec-sym2-'));
  try {
    writeFileSync(join(dir, 'main.go'), 'package main\n\nfunc HandleUser(w, r) {\n\tquery(r)\n}\n', 'utf8');
    writeFileSync(join(dir, 'app.py'), 'def load_user(uid):\n    return db.execute(uid)\n', 'utf8');
    assert.equal(symbolAt(dir, 'main.go', 4), 'HandleUser');
    assert.equal(symbolAt(dir, 'app.py', 2), 'load_user');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a file we cannot read leaves the symbol null rather than guessing', () => {
  assert.equal(symbolAt('/nowhere', 'missing.js', 3), null);
});

// --- vulnerability vs hardening
// "Defense-in-depth gaps are not vulnerabilities" — cloudflare/security-audit-skill.
// A missing Referrer-Policy and a SQL injection in one list teaches people to skim.

test('a hardening note is classed by the rule, not guessed here', () => {
  assert.equal(findingClass({ rule_id: 'x' }), 'vulnerability', 'the default is the stricter one');
  assert.equal(findingClass({ finding_class: 'hardening' }), 'hardening');
  assert.equal(findingClass({ rule: { finding_class: 'hardening' } }), 'hardening');
  assert.equal(findingClass({ finding_class: 'nonsense' }), 'vulnerability', 'an unknown class is not a loophole');
});

test('one scanner calling it a real failure outranks another calling it hardening', () => {
  const merged = mergeFindings([
    f('probe', 'missing-frame-protection', 'CWE-1021', at('/', null), { finding_class: 'hardening' }),
    f('zap', 'clickjacking-confirmed', 'CWE-1021', at('/', null), { finding_class: 'vulnerability' }),
  ]);
  assert.equal(merged.length, 1);
  assert.equal(merged[0].finding_class, 'vulnerability');
});

test('the defense-in-depth checks are declared hardening, not inferred', () => {
  const ids = HEADER_CHECKS.map((c) => c.id);
  assert.ok(ids.includes('missing-referrer-policy'));
  for (const c of HEADER_CHECKS) {
    assert.equal(c.finding_class, 'hardening', `${c.id} is a missing layer, not a way in`);
  }
});

test('trivy misconfigurations carry a CWE, or they can never merge', async () => {
  // Trivy supplies no CWE for Dockerfile checks. Without a map, `misconfig:DS-0002`
  // and `container-runs-as-root` were two findings on one line of one file.
  //
  // The first version of this test built the classification by hand from
  // MISCONF_CWE and asked issueType about it, which proves the table is right and
  // says nothing about whether the adapter reads it. The mutation that emptied the
  // adapter's cwe field survived. Go through parse(), which is the thing that runs.
  const parsed = await trivy.parse({
    exitCode: 0,
    stderr: '',
    stdout: JSON.stringify({
      Results: [{
        Target: 'Dockerfile',
        Misconfigurations: [
          { ID: 'DS-0002', Status: 'FAIL', Severity: 'HIGH', Title: "Image user should not be 'root'", CauseMetadata: { StartLine: 10 } },
          { ID: 'DS-0001', Status: 'FAIL', Severity: 'MEDIUM', Title: "':latest' tag used", CauseMetadata: { StartLine: 3 } },
        ],
      }],
    }),
  });

  const type = (id) => issueType(parsed.findings.find((f) => f.rule_id === `misconfig:${id}`));
  assert.equal(type('DS-0002').type, 'excessive-privilege');
  assert.equal(type('DS-0002').basis, 'family', 'a rule_id basis cannot merge with anything');
  assert.equal(type('DS-0001').type, 'vulnerable-dependency');
});

test('one scanner reporting several CVEs is not a disagreement with itself', () => {
  // On NodeGoat, trivy reported seven CVEs for `minimist` at several severities and
  // the report said "scanners disagree: trivy Critical, trivy Critical, trivy
  // Medium...". That tells a reader nothing and buries the real disagreements.
  const merged = mergeFindings([
    f('trivy', 'CVE-1', 'CWE-1104', at('package-lock.json', null), { severity: 'Critical' }),
    f('trivy', 'CVE-2', 'CWE-1104', at('package-lock.json', null), { severity: 'Medium' }),
  ]);
  assert.equal(merged[0].severity, 'Critical', 'the highest still wins');
  assert.equal(merged[0].severity_disagreement, null);
});

test('two scanners differing is still reported, once per tool', () => {
  const merged = mergeFindings([
    f('gitleaks', 'key', 'CWE-798', at('server.key', 1), { severity: 'Critical' }),
    f('semgrep', 'generic-key', 'CWE-798', at('server.key', 1), { severity: 'Low' }),
    f('semgrep', 'other-key', 'CWE-798', at('server.key', 1), { severity: 'Low' }),
  ]);
  const d = merged[0].severity_disagreement;
  assert.ok(d);
  assert.equal(d.length, 2, 'one row per tool, not one per finding');
  assert.deepEqual(d.map((x) => x.tool), ['gitleaks', 'semgrep']);
});
