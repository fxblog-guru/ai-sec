// Structural checks: the findings a line-by-line regex cannot reach.
//
// These are the two highest-value classes in most reviews, and neither shows up as
// a bad line of code — each is about a relationship between lines.
// See references/diagnostics.md in the security-review skill.

const ROUTE = /\b(?:router|app)\s*\.\s*(get|post|put|patch|delete|all)\s*\(\s*['"`]([^'"`]+)['"`]/;
const GUARD_USE = /\b(?:router|app)\s*\.\s*use\s*\(\s*([A-Za-z_$][\w$.]*)\s*\)/;
const GUARD_NAME = /auth|admin|require|ensure|protect|guard|permission|role|verify|authoriz|login|logged|signedin/i;
const PRIVILEGED = /admin|internal|manage|delete|billing|payment|user|account|setting|config|export|impersonat/i;

const AUTHZ_RULE = {
  name: 'Route registered before its authorization guard',
  background:
    'Express applies middleware in registration order. A route registered above router.use(guard) never passes through that guard, so the check exists in the file but never runs for this route. Reading the middleware alone makes the application look protected.',
  remediation:
    'Register the guard before any route it must cover, or attach it to the route explicitly. Prefer default-deny: mount the guard on the router and opt specific routes out, rather than remembering to opt each one in.',
  classification: { cwe: ['CWE-862'], owasp: ['A01:2025'], wstg: ['WSTG-v42-ATHZ-02'], asvs: ['v5.0.0-8.1.1'], api: ['API5:2023'] },
  typical_severity: 'High',
  references: ['https://cwe.mitre.org/data/definitions/862.html'],
};

const TENANT_RULE = {
  name: 'Query without a tenant predicate',
  background:
    'In a multi-tenant schema every query touching tenant data must carry a tenant predicate. This query is parameterized, so it is not injectable — but parameterization decides how values are bound, not which rows come back. A single query that bypasses the scoping layer returns another tenant\'s data.',
  remediation:
    'Route the query through the shared scoping layer, or add the tenant predicate explicitly. Enforce it at the database with row-level security so a forgotten predicate cannot leak.',
  classification: { cwe: ['CWE-639'], owasp: ['A01:2025'], wstg: ['WSTG-v42-ATHZ-04'], asvs: ['v5.0.0-8.2.1'], api: ['API1:2023'] },
  typical_severity: 'High',
  references: ['https://cwe.mitre.org/data/definitions/639.html'],
};

/**
 * A route registered above the router.use() that is supposed to guard it.
 * Reported only for routes that look privileged, to keep the noise down.
 */
export function routesBeforeGuard(rel, lines) {
  const guards = [];
  for (let i = 0; i < lines.length; i += 1) {
    const m = GUARD_USE.exec(lines[i]);
    if (m && GUARD_NAME.test(m[1])) guards.push({ line: i, name: m[1] });
  }
  if (guards.length === 0) return [];
  const firstGuard = guards[0];

  const out = [];
  for (let i = 0; i < firstGuard.line; i += 1) {
    const m = ROUTE.exec(lines[i]);
    if (!m) continue;
    const [, verb, path] = m;
    if (!PRIVILEGED.test(path)) continue;
    // an inline guard on the route itself is fine
    if (GUARD_NAME.test(lines[i].slice(m[0].length))) continue;

    out.push({
      rule_id: 'authz-before-guard',
      rule: AUTHZ_RULE,
      location: { file: rel, symbol: `${verb.toUpperCase()} ${path}`, line: i + 1 },
      insertion_point: null,
      severity: 'High',
      impact: 'HIGH',
      likelihood: 'MEDIUM',
      detection_method: 'dataflow', // established by the ordering, not by a pattern
      reported_severity: 'High',
      detail:
        `${verb.toUpperCase()} ${path} is registered on line ${i + 1}, above ` +
        `${firstGuard.name} on line ${firstGuard.line + 1}, so the guard never runs for it.`,
      evidence: `${lines[i].trim().slice(0, 160)}   // guard at line ${firstGuard.line + 1}`,
      modules: ['M5'],
      tool: 'builtin',
    });
  }
  return out;
}

const SCOPED = /\.\s*(?:scoped|forTenant|withTenant|tenantScope)\s*\(/;
const QUERY = /\b(?:db|knex|conn|client|pool|repo|repository|prisma|sequelize)\s*\.\s*(?:query|findOne|findMany|findFirst|select|execute|get)\s*\(/;
const TENANT_TERM = /tenant|org(?:ani[sz]ation)?|account|company|workspace|customer_id|site_id/i;

/**
 * A file that elsewhere scopes by tenant, but has a query that does not.
 * The precondition matters: without evidence the codebase is multi-tenant we would
 * be guessing, and a guess belongs at Tentative or not at all.
 */
export function queriesWithoutTenant(rel, lines, text) {
  const multiTenant = SCOPED.test(text) || TENANT_TERM.test(text);
  if (!multiTenant) return [];

  const out = [];
  for (let i = 0; i < lines.length; i += 1) {
    if (!QUERY.test(lines[i])) continue;
    if (SCOPED.test(lines[i])) continue;

    // Only the enclosing function counts. A neighbouring function that does scope
    // correctly is the reason this one stands out, not an excuse for it.
    const ctx = enclosingBody(lines, i);
    if (TENANT_TERM.test(ctx)) continue; // the predicate is in scope

    out.push({
      rule_id: 'missing-tenant-predicate',
      rule: TENANT_RULE,
      location: { file: rel, symbol: enclosing(lines, i), line: i + 1 },
      insertion_point: null,
      severity: 'High',
      impact: 'HIGH',
      likelihood: 'MEDIUM',
      // We saw the scoping layer used elsewhere and not here: a real comparison,
      // but not a proof that this row set crosses tenants.
      detection_method: 'pattern',
      reported_severity: 'High',
      detail:
        'This file scopes other queries by tenant, but this query carries no tenant predicate. ' +
        'It is parameterized, so it is not injectable — the risk is which rows it returns, not how they are bound.',
      evidence: lines[i].trim().slice(0, 200),
      modules: ['M5', 'M8'],
      tool: 'builtin',
    });
  }
  return out;
}

const DECL = /(?:async\s+)?function\s+[A-Za-z_$][\w$]*|(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*=\s*(?:async\s*)?(?:function|\()/;

/** The lines of the function containing `index`, bounded by the declarations around it. */
function enclosingBody(lines, index) {
  let start = 0;
  for (let i = index; i >= 0; i -= 1) {
    if (DECL.test(lines[i])) { start = i; break; }
  }
  let end = lines.length;
  for (let i = index + 1; i < lines.length; i += 1) {
    if (DECL.test(lines[i])) { end = i; break; }
  }
  return lines.slice(start, end).join('\n');
}

function enclosing(lines, index) {
  for (let i = index; i >= 0 && i > index - 40; i -= 1) {
    const m = ENCLOSING_DECL.exec(lines[i]);
    if (m) return m[1] ?? m[2] ?? m[3] ?? m[4];
  }
  return null;
}

/**
 * How a handler gets its name, in the forms people actually write.
 *
 * `this.displayAllocations = (req, res) => {}` is the shape of every handler in
 * NodeGoat, and without it the IDOR finding was attributed to the constructor
 * that contained it. The symbol goes into the fingerprint, so getting it wrong
 * costs more than a confusing line in a report: the finding moves whenever the
 * surrounding file does.
 */
const ENCLOSING_DECL = new RegExp([
  '(?:async\\s+)?function\\s+([A-Za-z_$][\\w$]*)',                               // function f()
  '(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)\\s*=\\s*(?:async\\s*)?(?:function|\\()', // const f = () =>
  'this\\s*\\.\\s*([A-Za-z_$][\\w$]*)\\s*=\\s*(?:async\\s*)?(?:function|\\()',   // this.f = () =>
  '^\\s*([A-Za-z_$][\\w$]*)\\s*:\\s*(?:async\\s*)?(?:function|\\()',             // { f: () => }
].join('|'));

const FETCHED_UNUSED_RULE = {
  name: 'The handler looks up who is asking and never uses it',
  background:
    'The authenticated account is read into a variable at the top of the handler and is not referred to again, while the handler goes on to read or write a stored object chosen entirely by the request. The lookup makes the code read as though ownership is enforced — to a reviewer, and to a scanner that treats "the caller is consulted" as the end of the question. It is the strongest possible disguise for broken object-level authorization, because the fix looks like it is already there.',
  remediation:
    'Put the account into the filter, so the query cannot return a row that belongs to someone else, rather than fetching the row and checking afterwards. If the handler genuinely does not need the caller, delete the lookup: a variable that exists only to look reassuring is worse than nothing.',
  classification: {
    cwe: ['CWE-639'], owasp: ['A01:2025'], wstg: ['WSTG-v42-ATHZ-04'],
    asvs: ['v5.0.0-8.1.1'], api: ['API1:2023'],
  },
  typical_severity: 'High',
  references: ['https://cwe.mitre.org/data/definitions/639.html'],
};

/** Who is asking, however this codebase spells it. */
const CALLER_BINDING =
  /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*[^;\n]*(?:authenticatedUsers|\breq(?:uest)?\s*\.\s*(?:user|session|auth)\b|currentUser|getUserId\s*\(|\bctx\s*\.\s*(?:session|state)\b)/g;

/** A write or read of stored data whose filter is the thing at issue. */
const STORE_WRITE =
  /\.\s*(?:update|updateOne|updateMany|find|findOne|findAll|remove|delete|deleteOne|deleteMany|destroy|save|increment|decrement)\s*\(/;

/**
 * The caller is fetched, and then ignored.
 *
 * This exists because `objectReferenceWithoutOwnershipCheck` treats "the caller
 * is consulted" as a clearing condition, and Juice Shop's review handler reads
 * the authenticated user on one line and filters on `req.body.id` on the next.
 * The clearing condition was clearing the exact case it should have caught — a
 * rule read something that was present and passed, which is this project's
 * failure mode with the sign flipped.
 */
export function callerIdentityFetchedAndUnused(rel, lines, text) {
  const out = [];
  const seen = new Set();
  const clean = stripJsComments(text);

  CALLER_BINDING.lastIndex = 0;
  let m;
  while ((m = CALLER_BINDING.exec(clean)) !== null) {
    const name = m[1];
    if (name.length < 3) continue; // `u` would match half of everything

    const i = clean.slice(0, m.index).split('\n').length - 1;
    const body = stripJsComments(enclosingBody(lines, i));
    if (!STORE_WRITE.test(body)) continue; // nothing is read or written here

    // Used anywhere other than the line that binds it?
    const uses = [...body.matchAll(new RegExp(`\\b${name}\\b`, 'g'))].length;
    if (uses > 1) continue;

    const symbol = enclosing(lines, i);
    const key = `${rel}#${symbol ?? i}`;
    if (seen.has(key)) continue;
    seen.add(key);

    out.push({
      rule_id: 'caller-identity-fetched-and-unused',
      rule: FETCHED_UNUSED_RULE,
      finding_class: 'vulnerability',
      subtype: 'ownership-looked-up-not-applied',
      location: { file: rel, symbol, line: i + 1 },
      insertion_point: null,
      severity: 'High', impact: 'HIGH', likelihood: 'MEDIUM',
      detection_method: 'pattern',
      reported_severity: 'High',
      detail: `\`${name}\` is bound here and never read again, while this scope writes or reads stored data`,
      evidence: lines[i].trim().slice(0, 200),
      modules: ['M5', 'M8'],
      tool: 'builtin',
    });
  }
  return out;
}

export const STRUCTURAL_CHECKS = [
  routesBeforeGuard,
  queriesWithoutTenant,
  objectReferenceWithoutOwnershipCheck,
  sensitiveFieldStoredInCleartext,
  callerIdentityFetchedAndUnused,
];

/** Checks that need the whole target, run once after every file has been read. */
export const REPO_CHECKS = [routesWithoutAnyGuard, authorizationMiddlewareNeverUsed];

// --- A repo-wide relationship, which no per-file check can see.

const NO_GUARD_RULE = {
  name: 'Routes with no authorization guard anywhere',
  background:
    'Every route in this target is registered without any middleware that reads as an authorization check, and no such middleware exists elsewhere in the code we could read. Either authorization is enforced somewhere this pass cannot see — a gateway, a proxy, a decorator we do not parse — or every route is reachable by anyone who can reach the service.',
  remediation:
    'Mount a default-deny guard on the router and opt specific routes out, rather than attaching a check to each route and relying on nobody forgetting. If enforcement genuinely lives outside this repository, record where, so the next run does not have to rediscover it.',
  classification: {
    cwe: ['CWE-306'], owasp: ['A01:2025'], wstg: ['WSTG-v42-ATHZ-01'],
    asvs: ['v5.0.0-8.1.1'], api: ['API5:2023'],
  },
  typical_severity: 'High',
  references: ['https://cwe.mitre.org/data/definitions/306.html'],
};

/**
 * Routes exist and nothing that looks like a guard does.
 *
 * `discover` already prints this as the headline — "routes but no authorization
 * guard was detected" — and nothing ever turned it into a finding, so it reached
 * a reader as a note on a different command and never reached a verdict, a
 * baseline or CI. On OWASP NodeGoat, 19 routes and no guard produced no finding
 * at all, while forty dependency CVEs did.
 *
 * It is Tentative on purpose. Absence of evidence in files we can read is not
 * proof: a gateway we cannot see is a real and common answer.
 */
export function routesWithoutAnyGuard({ routeFiles = [], guardsSeen = 0, routesSeen = 0 }) {
  if (routesSeen === 0 || guardsSeen > 0) return [];
  const where = routeFiles[0] ?? null;
  return [{
    rule_id: 'no-authorization-guard',
    rule: NO_GUARD_RULE,
    location: { file: where, symbol: null, line: null },
    insertion_point: null,
    severity: 'High',
    impact: 'HIGH',
    likelihood: 'MEDIUM',
    detection_method: 'pattern',
    reported_severity: 'High',
    detail:
      `${routesSeen} route(s) are registered across ${routeFiles.length} file(s) and no authorization ` +
      'middleware was found anywhere in this target. Confirm where authorization is enforced, or that it is not.',
    evidence: `${routesSeen} route(s), 0 guard(s)`,
    modules: ['M5', 'M7'],
    tool: 'builtin',
  }];
}

const IDOR_RULE = {
  name: 'Object reference taken from the request with no ownership check',
  background:
    'The identifier naming whose data to return is read from the URL or query string, and nothing in the handler compares it to the caller. Authentication answers who the caller is; it does not answer whose record this is. Any authenticated user can change the number in the URL and read another user\'s data, which needs no tooling and leaves normal-looking traffic in the logs.',
  remediation:
    'Take the identity from the session and the scope from the request, never the identity from the request. Where one user legitimately reads another\'s record, make that an explicit authorization decision at the point of use, and prefer unguessable identifiers so a missing check is not also a working enumeration.',
  classification: {
    cwe: ['CWE-639'], owasp: ['A01:2025'], wstg: ['WSTG-v42-ATHZ-04'],
    asvs: ['v5.0.0-8.2.1'], api: ['API1:2023'],
  },
  typical_severity: 'High',
  references: ['https://cwe.mitre.org/data/definitions/639.html'],
};

/** An identifier that names a principal, rather than a thing the principal owns. */
const IDENTITY_NAME = /^(?:user|owner|account|customer|member|employee|tenant|org|organisation|organization|company|profile)_?id$/i;

/** Where the request carries data the caller chose. */
const FROM_REQUEST = /\breq(?:uest)?\s*\.\s*(?:params|query|body)\b/;

/** The caller's own identity, however this codebase spells it. */
const CALLER_IDENTITY =
  /\breq(?:uest)?\s*\.\s*(?:session|user|auth)\b|\bres\s*\.\s*locals\s*\.\s*user\b|\bcurrentUser\b|\bgetUserId\s*\(|\bctx\s*\.\s*(?:session|state)\b/;

/** Something that reads or writes stored data using that identifier. */
const DATA_ACCESS = /\b(?:findOne|findById|findAll|getBy|findBy|updateBy|deleteBy|query|execute|aggregate|select|fetch)\w*\s*\(|\bDAO\b|\bdao\s*\.|\bRepository\b|\brepo\s*\./i;

/**
 * An identity from the request, used to fetch data, with no sign of the caller.
 *
 * OWASP NodeGoat's A4 is three lines of ordinary-looking code:
 *
 *     const { userId } = req.params;
 *     allocationsDAO.getByUserIdAndThreshold(userId, threshold, cb)
 *
 * Nothing on either line is wrong. The defect is the relationship between them
 * and the absence of a third line, which is why no pattern over single lines
 * finds it and why `routesBeforeGuard` does not either: the route IS guarded, by
 * `isLoggedIn`. Authenticated is not authorized.
 *
 * Reported Tentative on purpose. An admin endpoint legitimately takes a user id,
 * and the check cannot tell one from the other — it can only say that nobody in
 * this handler asked who was calling.
 */
export function objectReferenceWithoutOwnershipCheck(rel, lines, text) {
  const out = [];
  const seen = new Set();

  // Scanned over the whole text, not line by line: NodeGoat writes the binding
  // across three lines, and a per-line regex sees `} = req.params;` with the name
  // it needs on the line above.
  //
  //     const {
  //         userId
  //     } = req.params;
  const bindings = [
    /(?:const|let|var)\s*\{([^}]*)\}\s*=\s*req(?:uest)?\s*\.\s*(?:params|query|body)/g,
    /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*req(?:uest)?\s*\.\s*(?:params|query|body)\s*\.\s*([A-Za-z_$][\w$]*)/g,
  ];

  for (const re of bindings) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text)) !== null) {
      const names = [m[1], m[2]]
        .filter(Boolean)
        .flatMap((g) => g.split(',').map((s) => s.split(':').pop().trim()));

      const identity = names.find((n) => IDENTITY_NAME.test(n));
      if (!identity) continue;

      const i = text.slice(0, m.index).split('\n').length - 1;
      const body = enclosingBody(lines, i);
    if (CALLER_IDENTITY.test(stripJsComments(body))) continue; // the caller is consulted
    if (!DATA_ACCESS.test(body)) continue;                     // nothing is fetched with it

    const symbol = enclosing(lines, i);
    const key = `${rel}#${symbol ?? i}`;
    if (seen.has(key)) continue;
    seen.add(key);

    out.push({
      rule_id: 'idor-unchecked-object-reference',
      rule: IDOR_RULE,
      location: { file: rel, symbol, line: i + 1 },
      insertion_point: { kind: 'url-parameter', name: identity },
      severity: 'High',
      impact: 'HIGH',
      likelihood: 'HIGH',
      detection_method: 'pattern',
      reported_severity: 'High',
      detail:
        `\`${identity}\` is taken from the request and used to read stored data, and nothing in this ` +
        'handler compares it to the caller. Confirm whether one user may name another, or take the identity from the session.',
      evidence: (lines[i] ?? '').trim().slice(0, 200),
      modules: ['M5', 'M8'],
      tool: 'builtin',
      });
    }
  }
  return out;
}

/**
 * A fix in a comment is not a fix.
 *
 * NodeGoat carries its own remediation commented out, directly above the defect:
 *
 *     // Fix for A4 Insecure DOR - take user id from session instead of from URL
 *     // const { userId } = req.session;
 *
 * Reading `req.session` there would have silenced this check on the one file it
 * exists to find.
 */
function stripJsComments(text) {
  return text.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])\/\/[^\n]*/g, '$1');
}

const CLEARTEXT_RULE = {
  name: 'Sensitive field persisted in cleartext',
  background:
    'A field that identifies a person beyond repair — a national insurance or social security number, a date of birth, a bank account — is written to storage as it arrived. Transport encryption does not reach this: the risk is a backup, a replica, a logged query, an analytics export, or anyone with read access to the collection. Unlike a password, the holder cannot rotate it after a breach.',
  remediation:
    'Encrypt the field with a key the database does not hold, or do not store it at all. Where it is only ever compared, store a keyed hash instead of the value. Decide the same question for backups, exports and logs, which is where these usually leave.',
  classification: {
    cwe: ['CWE-311'], owasp: ['A02:2025'], wstg: ['WSTG-v42-CRYP-04'],
    asvs: ['v5.0.0-6.1.1'], api: ['API3:2023'],
  },
  typical_severity: 'High',
  references: ['https://cwe.mitre.org/data/definitions/311.html'],
};

/** Fields whose exposure cannot be undone by the person they belong to. */
const SENSITIVE_FIELD =
  /^(?:ssn|social_?security(?:_?number)?|nin|dob|date_?of_?birth|birth_?date|bank_?acc(?:ount)?(?:_?number)?|bank_?routing|routing_?number|iban|card_?number|credit_?card|cvv|passport(?:_?number)?|national_?id|tax_?id)$/i;

/** Something that turns a value into one that is safe to store. */
const PROTECTED =
  /\b(?:encrypt|cipher|seal|protect|tokeni[sz]e|hash|bcrypt|argon2|scrypt|hmac|createCipheriv)\s*\(/i;

/** Evidence that this object is on its way to storage. */
const PERSISTENCE =
  /\b(?:save|insert|insertOne|insertMany|update|updateOne|updateMany|findAndModify|replaceOne|upsert|create|put|set)\s*\(|\bcollection\s*\(|\bDAO\b|\bdao\s*\.|\bRepository\b/i;

/**
 * A sensitive field assigned straight from an argument, on its way to storage,
 * with nothing that protects it in scope.
 *
 * NodeGoat defines an `encrypt()` helper, writes a comment saying to use it for
 * SSN and date of birth, and then assigns both raw — with the protecting version
 * commented out directly below. The helper existing is why this is worth
 * reporting rather than guessing: the author already decided these fields needed
 * protecting.
 *
 * Tentative. A field can legitimately be written raw into a store that encrypts
 * at rest with a key this code never sees, and no pattern can tell from here.
 */
export function sensitiveFieldStoredInCleartext(rel, lines, text) {
  const out = [];
  const seen = new Set();
  const re = /(?:^|[^.\w])([A-Za-z_$][\w$]*)\s*\.\s*([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\s*[;,)\n]/g;

  re.lastIndex = 0;
  let m;
  while ((m = re.exec(text)) !== null) {
    const [, target, field, value] = m;
    if (!SENSITIVE_FIELD.test(field)) continue;
    if (target === 'req' || target === 'request') continue; // reading it, not storing it

    const i = text.slice(0, m.index).split('\n').length - 1;
    const body = stripJsComments(enclosingBody(lines, i));
    if (!PERSISTENCE.test(body)) continue;

    // Does anything in this scope protect that value before it is stored?
    const protectedHere = new RegExp(
      `${PROTECTED.source.slice(0, -2)}\\s*\\(\\s*${value}\\b`, 'i',
    ).test(body) || PROTECTED.test(`${field} = `) ;
    if (protectedHere) continue;

    const symbol = enclosing(lines, i);
    const key = `${rel}#${symbol ?? i}#${field}`;
    if (seen.has(key)) continue;
    seen.add(key);

    out.push({
      rule_id: 'sensitive-field-cleartext',
      rule: CLEARTEXT_RULE,
      location: { file: rel, symbol, line: i + 1 },
      insertion_point: null,
      severity: 'High',
      impact: 'HIGH',
      likelihood: 'MEDIUM',
      detection_method: 'pattern',
      reported_severity: 'High',
      detail:
        `\`${field}\` is assigned as it arrived and this scope writes to storage, with nothing that ` +
        'encrypts, tokenises or hashes it. Confirm whether the store protects it, or protect it here.',
      evidence: (lines[i] ?? '').trim().slice(0, 200),
      modules: ['M12', 'M8'],
      tool: 'builtin',
    });
  }
  return out;
}

const UNUSED_AUTHZ_RULE = {
  name: 'Authorization middleware defined but never applied',
  background:
    'This codebase defines middleware whose name describes an authorization decision — a role, a permission, an admin check — and no route passes through it. Somebody already decided these routes needed it. Authentication is still enforced, so every route looks protected and the application behaves normally for the people who test it: any authenticated user reaches the privileged routes by visiting the URL. Authenticated is not authorized.',
  remediation:
    'Apply the guard to the routes it was written for, and prefer default-deny — mount it and opt specific routes out, rather than remembering to opt each one in. If the check is genuinely obsolete, delete it, so the next reader is not told a control exists when it does not.',
  classification: {
    cwe: ['CWE-862'], owasp: ['A01:2025'], wstg: ['WSTG-v42-ATHZ-02'],
    asvs: ['v5.0.0-8.1.1'], api: ['API5:2023'],
  },
  typical_severity: 'High',
  references: ['https://cwe.mitre.org/data/definitions/862.html'],
};

/**
 * A name that answers "what may you do", as opposed to "who are you".
 *
 * The split matters: NodeGoat's routes all carry `isLoggedIn`, which is why the
 * no-guard check is silent on them and correctly so. The defect is that the
 * `isAdmin` middleware the author wrote is applied by nothing.
 */
const AUTHZ_NAME = /admin|role|permission|entitle|authoriz|\bcan[A-Z]|\ballow(?:ed)?[A-Z]?/;

/**
 * Middleware that decides authorization exists, and no route goes through it.
 *
 * In NodeGoat the working version sits directly below the vulnerable one, inside
 * a block comment:
 *
 *     app.get("/benefits", isLoggedIn, benefitsHandler.displayBenefits);
 *     // Fix for A7 - checks user role to implement Function Level Access Control
 *     //  app.get("/benefits", isLoggedIn, isAdmin, benefitsHandler.displayBenefits);
 *
 * which is the third time in this codebase that a remediation in a comment would
 * have hidden the defect it describes, so usages are counted after comments are
 * stripped. Firm rather than Tentative: unlike "no guard anywhere", this does not
 * depend on enforcement we cannot see. The control is here, named, and unused.
 */
export function authorizationMiddlewareNeverUsed({ authzDefined = new Map(), guardNamesUsed = new Set() }) {
  const unused = [...authzDefined].filter(([name]) => !guardNamesUsed.has(name));
  if (unused.length === 0) return [];

  const [name, where] = unused[0];
  const names = unused.map(([n]) => n);

  return [{
    rule_id: 'authorization-middleware-unused',
    rule: UNUSED_AUTHZ_RULE,
    location: { file: where.file, symbol: null, line: where.line },
    insertion_point: null,
    severity: 'High',
    impact: 'HIGH',
    likelihood: 'HIGH',
    detection_method: 'config',
    reported_severity: 'High',
    detail:
      `\`${name}\`${names.length > 1 ? ` and ${names.length - 1} other(s)` : ''} ` +
      'decide authorization and no route passes through them. Authentication may still be enforced, ' +
      'which is why the application looks protected: confirm which routes were meant to be privileged.',
    evidence: names.join(', '),
    modules: ['M5', 'M7'],
    tool: 'builtin',
  }];
}
