// Passive and light-active HTTP checks. Pure Node, nothing installed.
//
// Everything here is T1 (read what the server already said) or T2 (a handful of
// benign requests). Nothing sends a payload the application could read as an attack.

const H = (name, background, remediation, cls, sev, mods) => ({
  name, background, remediation, classification: cls, typical_severity: sev, _modules: mods,
  references: ['https://owasp.org/www-project-secure-headers/'],
});

export const HEADER_CHECKS = [
  {
    id: 'missing-csp',
    finding_class: 'hardening',
    header: 'content-security-policy',
    severity: 'Medium', impact: 'MEDIUM', likelihood: 'MEDIUM',
    rule: H('Missing Content-Security-Policy',
      'Without a CSP the browser will execute any script the page can be made to include, so an injection anywhere becomes script execution.',
      "Add a Content-Security-Policy. Start with `default-src 'self'` and tighten; avoid 'unsafe-inline'.",
      { cwe: ['CWE-1021'], owasp: ['A02:2025'], wstg: ['WSTG-v42-CONF-07'], asvs: ['v5.0.0-3.4.1'], api: [] },
      'Medium', ['M3', 'M9']),
  },
  {
    id: 'missing-hsts',
    finding_class: 'hardening',
    header: 'strict-transport-security',
    httpsOnly: true,
    severity: 'Medium', impact: 'MEDIUM', likelihood: 'MEDIUM',
    rule: H('Missing Strict-Transport-Security',
      'Without HSTS a first request over plain HTTP can be intercepted and downgraded before the redirect to HTTPS happens.',
      'Send Strict-Transport-Security with a max-age of at least 31536000, and includeSubDomains once subdomains are ready.',
      { cwe: ['CWE-319'], owasp: ['A04:2025'], wstg: ['WSTG-v42-CONF-07'], asvs: ['v5.0.0-12.1.1'], api: [] },
      'Medium', ['M3', 'M12']),
  },
  {
    id: 'missing-x-content-type-options',
    finding_class: 'hardening',
    header: 'x-content-type-options',
    severity: 'Low', impact: 'LOW', likelihood: 'MEDIUM',
    rule: H('Missing X-Content-Type-Options',
      'Browsers may sniff a response as a type it was not served as, turning an uploaded file into executable script.',
      'Send X-Content-Type-Options: nosniff.',
      { cwe: ['CWE-430'], owasp: ['A02:2025'], wstg: ['WSTG-v42-CONF-07'], asvs: ['v5.0.0-3.4.3'], api: [] },
      'Low', ['M3', 'M9']),
  },
  {
    id: 'missing-frame-protection',
    finding_class: 'hardening',
    header: 'x-frame-options',
    alt: (h) => /frame-ancestors/i.test(h['content-security-policy'] ?? ''),
    severity: 'Medium', impact: 'MEDIUM', likelihood: 'LOW',
    rule: H('No clickjacking protection',
      'The page can be framed by another site and layered under invisible controls, so a victim clicks something they cannot see.',
      "Send Content-Security-Policy: frame-ancestors 'none' (or an allowlist), and X-Frame-Options: DENY for older browsers.",
      { cwe: ['CWE-1021'], owasp: ['A02:2025'], wstg: ['WSTG-v42-CLNT-09'], asvs: ['v5.0.0-3.4.2'], api: [] },
      'Medium', ['M3', 'M9']),
  },
  {
    id: 'missing-referrer-policy',
    finding_class: 'hardening',
    header: 'referrer-policy',
    severity: 'Low', impact: 'LOW', likelihood: 'LOW',
    rule: H('Missing Referrer-Policy',
      'Full URLs leak to third parties in the Referer header, and URLs often carry identifiers and tokens.',
      'Send Referrer-Policy: strict-origin-when-cross-origin or no-referrer.',
      { cwe: ['CWE-200'], owasp: ['A02:2025'], wstg: ['WSTG-v42-CONF-07'], asvs: ['v5.0.0-3.4.4'], api: [] },
      'Low', ['M3']),
  },
];

export const BANNER_HEADERS = ['x-powered-by', 'server', 'x-aspnet-version', 'x-generator'];

export const CORS_RULE = H('Permissive CORS with credentials',
  'A wildcard origin combined with credentials lets any site read authenticated responses from this application.',
  'Allowlist the origins that need access and echo only those. Never combine a wildcard with Access-Control-Allow-Credentials.',
  { cwe: ['CWE-942'], owasp: ['A02:2025'], wstg: ['WSTG-v42-CLNT-07'], asvs: ['v5.0.0-3.4.1'], api: ['API8:2023'] },
  'High', ['M3', 'M7', 'M9']);

export const COOKIE_RULE = H('Session cookie without protective flags',
  'A cookie without Secure travels over plain HTTP; without HttpOnly it is readable by script; without SameSite it rides along on cross-site requests.',
  'Set Secure, HttpOnly and SameSite=Lax (or Strict) on every session cookie.',
  { cwe: ['CWE-1004'], owasp: ['A07:2025'], wstg: ['WSTG-v42-SESS-02'], asvs: ['v5.0.0-7.1.1'], api: [] },
  'Medium', ['M3', 'M4']);

export const VERBOSE_ERROR_RULE = H('Verbose error exposes internals',
  'An error response carrying a stack trace reveals file paths, framework versions and internal structure, which maps the system for an attacker.',
  'Return a generic error to the client and keep the detail in server-side logs.',
  { cwe: ['CWE-209'], owasp: ['A10:2025'], wstg: ['WSTG-v42-ERRH-01'], asvs: ['v5.0.0-16.2.1'], api: [] },
  'Low', ['M13']);

export const BANNER_RULE = H('Technology disclosed in response headers',
  'Version banners tell an attacker exactly which published vulnerabilities to try first.',
  'Remove or blank X-Powered-By, Server and similar headers at the application or proxy.',
  { cwe: ['CWE-200'], owasp: ['A02:2025'], wstg: ['WSTG-v42-INFO-02'], asvs: ['v5.0.0-13.4.2'], api: [] },
  'Info', ['M3']);

export const OPEN_REDIRECT_RULE = H('Open redirect',
  'A redirect target taken from a parameter lets an attacker send users from a trusted origin to one they control.',
  'Allowlist redirect targets, or accept only a relative path.',
  { cwe: ['CWE-601'], owasp: ['A01:2025'], wstg: ['WSTG-v42-CLNT-04'], asvs: ['v5.0.0-3.2.1'], api: [] },
  'Medium', ['M1', 'M9']);

/** T1 — read what the server already said. Sends nothing of its own. */
export function passiveChecks({ url, status, headers, body }) {
  const out = [];
  const https = url.protocol === 'https:';
  // `subtype` is what keeps two defects of one CWE family at one URL apart.
  // Referrer-Policy and X-Powered-By are both CWE-200 on `/`, and without it
  // the merge treated them as one finding and kept whichever arrived first.
  const add = (id, rule, sev, impact, likelihood, detail, evidence, method = 'config', cls = 'vulnerability', subtype = null) =>
    out.push({
      rule_id: id, rule, location: { file: url.pathname || '/', symbol: null, line: null },
      insertion_point: null, severity: sev, impact, likelihood, subtype,
      detection_method: method, reported_severity: sev, detail, evidence,
      finding_class: cls, modules: rule._modules, tool: 'probe',
    });

  for (const c of HEADER_CHECKS) {
    if (c.httpsOnly && !https) continue;
    if (headers[c.header]) continue;
    if (c.alt && c.alt(headers)) continue;
    add(c.id, c.rule, c.severity, c.impact, c.likelihood,
      `${url.origin}${url.pathname} responded ${status} without ${c.header}.`,
      `${status} ${url.pathname} — header absent`,
      'config', c.finding_class, c.header);
  }

  const acao = headers['access-control-allow-origin'];
  const acac = headers['access-control-allow-credentials'];
  if (acao === '*' && String(acac).toLowerCase() === 'true') {
    add('permissive-cors-credentials', CORS_RULE, 'High', 'HIGH', 'MEDIUM',
      'Access-Control-Allow-Origin is * and Access-Control-Allow-Credentials is true.',
      `Access-Control-Allow-Origin: * / Access-Control-Allow-Credentials: ${acac}`);
  }

  for (const cookie of [].concat(headers['set-cookie'] ?? [])) {
    const name = String(cookie).split('=')[0];
    const missing = ['Secure', 'HttpOnly', 'SameSite'].filter((f) => !new RegExp(f, 'i').test(cookie));
    if (missing.length) {
      add('insecure-cookie', COOKIE_RULE, missing.includes('HttpOnly') ? 'Medium' : 'Low',
        'MEDIUM', 'MEDIUM',
        `Cookie "${name}" is set without ${missing.join(', ')}.`,
        `Set-Cookie: ${name}=… (${missing.join(', ')} missing)`,
        'config', 'vulnerability', `cookie:${name}`);
    }
  }

  for (const h of BANNER_HEADERS) {
    if (headers[h]) {
      add('technology-banner', BANNER_RULE, 'Info', 'LOW', 'LOW',
        `${h} discloses ${headers[h]}.`, `${h}: ${headers[h]}`,
        'config', 'vulnerability', h);
    }
  }

  if (status >= 500 && /\bat\s+\/|\.js:\d+|Traceback|Exception in|stack trace/i.test(body ?? '')) {
    add('verbose-error', VERBOSE_ERROR_RULE, 'Low', 'LOW', 'MEDIUM',
      `${url.pathname} returned ${status} with a stack trace in the body.`,
      String(body).slice(0, 160),
      'config', 'vulnerability', 'stack-trace');
  }

  return out;
}

/**
 * T2 — a handful of benign requests. An open-redirect probe is a normal-looking
 * navigation to a harmless host; nothing here would read as an attack.
 */
export const REDIRECT_PARAMS = ['next', 'url', 'redirect', 'return', 'returnTo', 'continue', 'dest'];
export const REDIRECT_CANARY = 'http://example.org/';

export function openRedirectFinding(url, param, location) {
  return {
    rule_id: 'open-redirect',
    rule: OPEN_REDIRECT_RULE,
    location: { file: url.pathname, symbol: null, line: null },
    insertion_point: { kind: 'url-parameter', name: param },
    severity: 'Medium', impact: 'MEDIUM', likelihood: 'MEDIUM',
    // We sent a request and the server redirected off-origin: observed, not inferred.
    detection_method: 'reproduced',
    reported_severity: 'Medium',
    detail: `${url.pathname}?${param}= redirected off-origin to ${location}.`,
    evidence: `GET ${url.pathname}?${param}=${REDIRECT_CANARY} → 302 Location: ${location}`,
    modules: OPEN_REDIRECT_RULE._modules,
    tool: 'probe',
  };
}

/**
 * T2, authenticated — the only check here that needs two accounts.
 *
 * Every other check in this file reads what one anonymous request came back
 * with. Authorization between accounts cannot be read off a single response:
 * the server answers "200" to the owner and to anyone else, and the difference
 * is who the data belongs to. So the evidence is a comparison, and a comparison
 * needs two sessions and a control.
 *
 * The three requests, in order, and why each one is there:
 *
 *   as the owner    establishes what the object looks like when the right
 *                   person asks. Without it there is nothing to compare to.
 *   with no session the control. If the object comes back anyway, a second
 *                   account reading it proves nothing about authorization
 *                   BETWEEN accounts — it is public, which is a different
 *                   finding with a different fix.
 *   as the other    the test.
 */
export const CROSS_ACCOUNT_RULE = H('Object readable by another account',
  'The object is returned to a session that does not own it, so any identifier a user can guess or enumerate reads another user\'s data. This is the defect behind most real breaches of customer records.',
  'Check ownership in the handler, against the session, for every object loaded by an identifier from the request. A guard on the route is not enough: it proves who is asking, not what they may read.',
  { cwe: ['CWE-639'], owasp: ['A01:2025'], wstg: ['WSTG-v42-ATHZ-04'], asvs: ['v5.0.0-8.1.1'], api: ['API1:2023'] },
  'High', ['M5', 'M8']);

export const UNAUTH_OBJECT_RULE = H('Object readable without a session',
  'The object is returned to a request carrying no session at all, so it is public to anyone who knows the URL.',
  'Require an authenticated session on the endpoint, then check ownership. Fix the authentication first: an ownership check runs on a session that is not there.',
  { cwe: ['CWE-306'], owasp: ['A01:2025'], wstg: ['WSTG-v42-ATHZ-01'], asvs: ['v5.0.0-8.1.1'], api: ['API1:2023'] },
  'High', ['M4', 'M5', 'M8']);

/**
 * What the response was, without what was in it.
 *
 * The proof of this finding is another account's data, and a report is read by
 * people who are not entitled to it — the finding would become the leak. A
 * digest and a length settle "the same body came back" and carry nothing.
 */
export function bodyEvidence(digest, bytes) {
  return `sha256:${digest} (${bytes} bytes; the body is another account's data and is not reproduced here)`;
}

export function crossAccountFinding(url, { owner, other, digest, bytes }) {
  return {
    rule_id: 'cross-account-object-read',
    rule: CROSS_ACCOUNT_RULE,
    location: { file: url.pathname, symbol: null, line: null },
    insertion_point: { kind: 'path-parameter', name: url.pathname.split('/').filter(Boolean).pop() ?? null },
    severity: 'High', impact: 'HIGH', likelihood: 'HIGH',
    // Two sessions, one object, identical bytes. Observed, not inferred.
    detection_method: 'reproduced',
    reported_severity: 'High',
    detail: `${url.pathname} returned the same object to "${other}" as to its owner "${owner}".`,
    evidence: `GET ${url.pathname} as "${other}" → 200, identical to the owner's response: ${bodyEvidence(digest, bytes)}`,
    modules: CROSS_ACCOUNT_RULE._modules,
    tool: 'probe',
  };
}

export function unauthenticatedObjectFinding(url, { owner, digest, bytes }) {
  return {
    rule_id: 'unauthenticated-object-read',
    rule: UNAUTH_OBJECT_RULE,
    location: { file: url.pathname, symbol: null, line: null },
    insertion_point: { kind: 'path-parameter', name: url.pathname.split('/').filter(Boolean).pop() ?? null },
    severity: 'High', impact: 'HIGH', likelihood: 'HIGH',
    detection_method: 'reproduced',
    reported_severity: 'High',
    detail: `${url.pathname} returned "${owner}"'s object to a request carrying no session.`,
    evidence: `GET ${url.pathname} with no cookie → 200, identical to the owner's response: ${bodyEvidence(digest, bytes)}`,
    modules: UNAUTH_OBJECT_RULE._modules,
    tool: 'probe',
  };
}
