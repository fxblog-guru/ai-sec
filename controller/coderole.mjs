// What kind of code a finding is in. CONTRACTS §5.
//
// Found by scanning OWASP Juice Shop: 246 findings, and 188 of them were
// hardcoded credentials in its test suite. The report was technically correct
// and completely unusable, because the one SQL injection in a login route was
// three screens below a hundred fixtures named `password`.
//
// `verifying-findings` already told the reader to do this by hand — step 3 of
// the disproof checklist is "is it in test, mock, fixture or example code?".
// Leaving a mechanical judgement to the reader on every finding is how a tool
// trains people to skim it. NodeGoat was small enough to hide the problem; a
// real repository is mostly not application code.
//
// Nothing is dropped. A credential in a test file can be a live credential, and
// a rule that deleted it would be the leak. What changes is that it stops
// competing with the application findings for the reader's attention, and stops
// counting toward a verdict about the running system.

export const CODE_ROLES = ['application', 'test', 'fixture', 'example', 'generated', 'vendored'];

/** Roles whose findings say nothing about what is deployed. */
export const NON_APPLICATION = CODE_ROLES.filter((r) => r !== 'application');

const PATTERNS = [
  // Ordered: a fixture inside a test directory is a test, which is the more
  // useful label of the two.
  ['vendored', /(^|\/)(?:node_modules|bower_components|vendor|third_party|external)\//],
  ['generated', /(^|\/)(?:dist|build|out|coverage|\.next|\.nuxt|target)\/|\.min\.(?:js|css)$|\.(?:bundle|chunk)\.js$/],
  ['test', /(^|\/)(?:tests?|__tests__|spec|e2e|cypress|__snapshots__)\/|\.(?:test|spec)\.[cm]?[jt]sx?$|(^|\/)conftest\.py$|_test\.go$/],
  ['fixture', /(^|\/)(?:fixtures?|mocks?|__mocks__|stubs?|testdata|seeds?)\//],
  ['example', /(^|\/)(?:examples?|samples?|demos?|docs?\/examples?)\//],
];

/**
 * Classify a path. Unknown shapes are `application`, deliberately: calling
 * something a test when it is not hides a real finding, and the cost of the
 * other mistake is only that a test finding keeps the reader's attention.
 */
export function codeRole(file) {
  if (typeof file !== 'string' || file.length === 0) return 'application';
  const p = file.split('\\').join('/').toLowerCase();
  for (const [role, re] of PATTERNS) if (re.test(p)) return role;
  return 'application';
}

export const isApplicationCode = (f) => (f?.code_role ?? 'application') === 'application';

/**
 * Attach the role, and cap what a non-application finding may claim.
 *
 * A pattern matched in a fixture is evidence about the fixture. It may still be
 * worth acting on — a real key in a test file is a real key — but it has not
 * been shown to be reachable in anything that runs, so it cannot carry a
 * confidence that says otherwise.
 */
export function classify(finding = {}) {
  const role = codeRole(finding.location?.file);
  if (role === 'application') return { ...finding, code_role: role };
  return {
    ...finding,
    code_role: role,
    confidence: 'Tentative',
    reported_confidence: finding.confidence ?? null,
  };
}

/** One ledger entry per role present, so the count is never only in the total. */
export function roleSummary(findings = []) {
  const counts = {};
  for (const f of findings) {
    const r = f.code_role ?? 'application';
    if (r !== 'application') counts[r] = (counts[r] ?? 0) + 1;
  }
  return counts;
}
