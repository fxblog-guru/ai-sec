// The issue-type layer of the two-layer finding model (CONTRACTS §1).
//
// An instance is "this line, this input". A type is "what kind of defect this is".
// Every scanner names the type in its own vocabulary, so until something maps those
// vocabularies onto one, two tools reporting the same defect stay two findings:
//
//   builtin  open-redirect                                            Medium
//   semgrep  javascript.express.security.audit.express-open-redirect  High
//
// That is the same defect on the same line of the same file, counted twice and
// scored differently, in a tool whose entire reason to exist is "merge, never sum".
//
// CWE is the shared vocabulary — every scanner here already emits it — but it is
// not usable raw. Semgrep calls an MD5 password hash CWE-327 (broken algorithm);
// our own rule calls it CWE-916 (password hash without a KDF). Both are right.
// So CWEs are grouped into families, and the family is the identity.

/**
 * CWE -> canonical issue type.
 *
 * A family groups CWEs that describe one defect from different angles. Two
 * findings only ever merge when they also share a location, so a family being
 * broad costs little; a family being too narrow costs a duplicate in every report.
 */
export const ISSUE_FAMILIES = {
  'sql-injection': ['CWE-89', 'CWE-564', 'CWE-943'],
  'command-injection': ['CWE-77', 'CWE-78', 'CWE-88'],
  'code-injection': ['CWE-94', 'CWE-95', 'CWE-1336'],
  'path-traversal': ['CWE-22', 'CWE-23', 'CWE-35', 'CWE-36', 'CWE-73'],
  ssrf: ['CWE-918'],
  'open-redirect': ['CWE-601'],
  xss: ['CWE-79', 'CWE-80', 'CWE-83', 'CWE-116'],
  'unsafe-deserialization': ['CWE-502'],
  xxe: ['CWE-611', 'CWE-776'],
  'weak-randomness': ['CWE-330', 'CWE-338', 'CWE-340'],
  // Algorithm choice and password storage are reported under either number.
  'weak-crypto': ['CWE-261', 'CWE-326', 'CWE-327', 'CWE-328', 'CWE-759', 'CWE-760', 'CWE-916'],
  'cleartext-transport': ['CWE-319', 'CWE-311'],
  'hardcoded-credential': ['CWE-259', 'CWE-321', 'CWE-798'],
  'permissive-cors': ['CWE-346', 'CWE-942'],
  'information-exposure': ['CWE-200', 'CWE-209', 'CWE-489', 'CWE-532', 'CWE-430'],
  'excessive-privilege': ['CWE-250', 'CWE-266', 'CWE-269', 'CWE-732'],
  'missing-authz': ['CWE-285', 'CWE-566', 'CWE-639', 'CWE-862', 'CWE-863'],
  'missing-authn': ['CWE-287', 'CWE-306', 'CWE-287'],
  'session-handling': ['CWE-384', 'CWE-613', 'CWE-1004'],
  'clickjacking': ['CWE-1021'],
  csrf: ['CWE-352'],
  'vulnerable-dependency': ['CWE-937', 'CWE-1035', 'CWE-1104', 'CWE-1357'],
  'open-input-validation': ['CWE-20', 'CWE-1286'],
  // The AI/LLM entries MITRE has published so far. CWE-1427 is prompt injection;
  // CWE-1426 is trusting a generative model's output without validating it.
  'prompt-injection': ['CWE-1427'],
  'unvalidated-model-output': ['CWE-1426'],
  'resource-exhaustion': ['CWE-400', 'CWE-770', 'CWE-1333'],
};

/** CWE -> family, built once. */
const FAMILY_OF = new Map();
for (const [family, cwes] of Object.entries(ISSUE_FAMILIES)) {
  for (const c of cwes) FAMILY_OF.set(c, family);
}

const CWE_RE = /CWE-\d+/;

/** Normalize whatever a scanner put in the CWE field: "CWE-79: XSS" -> "CWE-79". */
export function normalizeCwe(value) {
  if (value == null) return null;
  const m = CWE_RE.exec(String(value));
  return m ? m[0] : null;
}

export function cwesOf(finding = {}) {
  const raw = finding.rule?.classification?.cwe ?? finding.classification?.cwe ?? [];
  const out = [];
  for (const c of [].concat(raw)) {
    const n = normalizeCwe(c);
    if (n && !out.includes(n)) out.push(n);
  }
  return out;
}

/**
 * The cross-tool identity of a finding.
 *
 * A mapped CWE gives a family shared by every scanner. An unmapped CWE is still
 * better than a rule id, because at least two tools citing CWE-1234 agree. Only
 * when there is no CWE at all do we fall back to the tool's own rule id — which
 * is where cross-tool merging stops being possible, so `basis` says so and the
 * coverage of this table can be measured instead of assumed.
 */
export function issueType(finding = {}) {
  const cwes = cwesOf(finding);
  for (const c of cwes) {
    const family = FAMILY_OF.get(c);
    if (family) return { type: family, basis: 'family', cwe: c };
  }
  if (cwes.length > 0) return { type: cwes[0].toLowerCase(), basis: 'cwe', cwe: cwes[0] };
  return { type: finding.rule_id ?? '', basis: 'rule_id', cwe: null };
}

/**
 * What a finding IS, as distinct from how bad it is.
 *
 *   vulnerability  a control is defeated and something crosses a boundary
 *   hardening      a layer that would have helped is absent, while another still holds
 *
 * Cloudflare's security-audit skill states the rule that this implements:
 * "Defense-in-depth gaps are not vulnerabilities." A missing `X-Frame-Options`
 * header on an API that returns JSON is worth saying and is not a way in, and a
 * report that files it next to a SQL injection teaches the reader to skim.
 *
 * It is a property of the issue type, declared by the rule, never inferred here.
 * Hardening notes are reported in full and never fail a build on their own.
 */
export const FINDING_CLASSES = ['vulnerability', 'hardening'];

export function findingClass(finding = {}) {
  const declared = finding.rule?.finding_class ?? finding.finding_class;
  return FINDING_CLASSES.includes(declared) ? declared : 'vulnerability';
}

export const isHardening = (f) => findingClass(f) === 'hardening';

/** Union of the classifications every contributing scanner supplied. */
export function mergeClassification(list = []) {
  const out = { cwe: [], owasp: [], wstg: [], asvs: [], api: [] };
  for (const c of list) {
    if (!c) continue;
    for (const key of Object.keys(out)) {
      for (const v of [].concat(c[key] ?? [])) {
        const s = key === 'cwe' ? normalizeCwe(v) : String(v);
        if (s && !out[key].includes(s)) out[key].push(s);
      }
    }
  }
  for (const key of Object.keys(out)) out[key].sort();
  return out;
}
