// One hop across a call boundary. CONTRACTS §3.
//
// Every static blind spot this project has recorded is the same sentence: no
// regular expression crosses a call boundary. M14's indirect prompt injection,
// M12's weak password hash, M4's password storage — all three are a sink that
// names a helper, and a helper that does the dangerous thing somewhere else.
//
// Juice Shop is the clean example:
//
//   models/user.ts:73    this.setDataValue('password', security.hash(clearTextPassword))
//   lib/insecurity.ts:41 export const hash = (data) => crypto.createHash('md5')...
//
// Nothing on line 73 is wrong. Nothing on line 41 mentions a password. The
// defect only exists in the pair, and scanning Juice Shop reported neither —
// M12 scored 0 of 1 and said `failing`, which was the correct grade for a tool
// that could not look.
//
// This resolves exactly ONE hop, only to a function defined in the same target,
// only by name. It is not a call graph and does not pretend to be: a helper that
// comes from a package, or that is reached through two hops, is a line in the
// coverage ledger rather than a silent pass. Under-claiming is the whole point —
// the alternative is a resolver that is wrong in ways nobody can see.

/** `export const name = (…) =>` / `const name = function` / `function name(` / `name(…) {` in a class or object. */
const DEFINITION =
  /(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*[:=][^=]*?=>|(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(/g;

/** How much of a helper we read. A digest call that is further down than this is out of reach, and said so. */
const BODY_LINES = 12;

/** A hash that is fast by design. Storing a password with one is the defect, whatever it is called. */
const FAST_DIGEST = /createHash\s*\(\s*['"`](?:md5|sha1|sha-1|sha256|sha-256|sha512|sha-512)['"`]|\bmd5\s*\(|\bsha1\s*\(/i;

/** A key derivation function, which is the fix. Its presence anywhere in the helper clears it. */
const KDF = /\bbcrypt\b|\bscrypt\b|\bargon2\b|pbkdf2|\bhash\s*\(\s*password\s*,\s*\d+|@node-rs\/argon2/i;

/** The field whose storage this is about. */
const PASSWORD_FIELD = /\bpass(?:word|wd)?\b|\bpwd\b|clearTextPassword|plainPassword/i;

/** `security.hash(x)` or `hashIt(x)` — the name we would have to resolve. */
const CALL = /(?:([A-Za-z_$][\w$]*)\s*\.\s*)?([A-Za-z_$][\w$]*)\s*\(/g;

const NOT_A_HELPER = new Set([
  'if', 'for', 'while', 'switch', 'catch', 'return', 'typeof', 'function',
  'require', 'import', 'String', 'Number', 'Boolean', 'Object', 'Array', 'JSON',
  'setDataValue', 'getDataValue', 'set', 'get', 'update', 'create', 'then', 'catch',
]);

const WEAK_HASH_RULE = {
  name: 'Password stored with a fast hash, through a helper',
  background:
    'The password is stored by a helper defined elsewhere in this codebase, and that helper uses a general-purpose digest. Fast hashes are built to be fast, which is exactly what an attacker with the database wants: a commodity GPU tries billions of candidates a second. Neither line looks wrong on its own, which is why this survives review — the setter names a helper, and the helper never mentions a password.',
  remediation:
    'Store passwords with a memory-hard key derivation function — argon2id, scrypt or bcrypt — with a per-password salt and a work factor you re-tune. Treat every existing hash as compromised and re-hash on next successful login.',
  classification: {
    cwe: ['CWE-916'], owasp: ['A02:2025'], wstg: ['WSTG-v42-ATHN-07'],
    asvs: ['v5.0.0-2.4.1'], api: [],
  },
  typical_severity: 'High',
  references: ['https://cwe.mitre.org/data/definitions/916.html'],
};

/**
 * Fields that decide what an account may do, rather than what it contains.
 *
 * Deliberately short. A long list turns this into "report every column", and
 * the check is only worth having while a hit means something.
 */
const PRIVILEGED_FIELD =
  /^(?:role|roles|isAdmin|is_admin|admin|permissions?|scopes?|grants?|privileges?|isStaff|is_staff|isSuperuser|verified|emailVerified|balance|credits?)$/i;

/** `declare role: string` / `role: { type: … }` / `role: DataTypes.STRING` — a model declaring a column. */
const FIELD_DECL = /(?:^|\n)\s*(?:declare\s+|public\s+|readonly\s+)?([A-Za-z_$][\w$]*)\s*[?!]?\s*:\s*(?:CreationOptional<|DataTypes\.|\{|Sequelize\.|String\b|Number\b|Boolean\b)/g;

/** An auto-generated CRUD layer. These hand every model column to the client unless told not to. */
const AUTO_CRUD = /\b(?:finale|epilogue)\s*\.\s*(?:initialize|resource)\s*\(|\bautoRoutes\s*\(|\bloopback\b/;

/** `{ name: 'User', exclude: ['password'], model: UserModel }` */
const RESOURCE_ENTRY = /\{\s*name:\s*['"`]([A-Za-z_$][\w$]*)['"`]\s*,\s*exclude:\s*\[([^\]]*)\]/g;

const AUTO_CRUD_RULE = {
  name: 'Generated CRUD endpoint exposes a privileged field',
  background:
    'A CRUD layer generated from the model publishes every column it was not told to exclude, for reading and for writing. The exclude list here names the obviously secret columns and not the one that decides what the account may do, so a registration can ask for it. Neither file is wrong on its own: the model declares a column and the resource lists exclusions — the defect is the gap between the two lists.',
  remediation:
    'Exclude the field from the generated resource, or stop generating write endpoints over a model that carries authority. Prefer an explicit allowlist of writable fields to a denylist of excluded ones: a denylist is wrong again every time a column is added.',
  classification: {
    cwe: ['CWE-915'], owasp: ['A01:2025'], wstg: ['WSTG-v42-BUSLOGIC-01'],
    asvs: ['v5.0.0-1.3.1'], api: ['API3:2023'],
  },
  typical_severity: 'High',
  references: ['https://cwe.mitre.org/data/definitions/915.html'],
};

/** Privileged columns a model file declares, keyed by the name the routing layer will use. */
export function collectModelFields(rel, text) {
  const base = rel.split('/').pop().replace(/\.[jt]sx?$/, '');
  if (!/(^|\/)models?\//.test(rel) && !/model/i.test(base)) return [];
  const model = base.replace(/[-_.]?model$/i, '');
  const name = model.charAt(0).toUpperCase() + model.slice(1);

  const out = [];
  FIELD_DECL.lastIndex = 0;
  let m;
  while ((m = FIELD_DECL.exec(text)) !== null) {
    if (!PRIVILEGED_FIELD.test(m[1])) continue;
    out.push({ model: name, field: m[1], file: rel, line: text.slice(0, m.index).split('\n').length + 1 });
  }
  return out;
}

/** Generated resources and what each one excludes. */
export function collectAutoCrud(rel, text) {
  if (!AUTO_CRUD.test(text)) return [];
  const out = [];
  RESOURCE_ENTRY.lastIndex = 0;
  let m;
  while ((m = RESOURCE_ENTRY.exec(text)) !== null) {
    const excluded = [...m[2].matchAll(/['"`]([^'"`]+)['"`]/g)].map((e) => e[1]);
    out.push({ name: m[1], excluded, file: rel, line: text.slice(0, m.index).split('\n').length });
  }
  return out;
}

/**
 * A model that carries authority, published by a generator that was never told
 * to hold that column back.
 */
export function autoCrudExposesPrivilegedField({ modelFields = [], autoCrud = [] } = {}) {
  const byModel = new Map();
  for (const f of modelFields) {
    if (!byModel.has(f.model)) byModel.set(f.model, []);
    byModel.get(f.model).push(f);
  }

  const findings = [];
  for (const res of autoCrud) {
    const fields = byModel.get(res.name);
    if (!fields) continue;
    const lower = new Set(res.excluded.map((e) => e.toLowerCase()));
    const exposed = fields.filter((f) => !lower.has(f.field.toLowerCase()));
    if (exposed.length === 0) continue;

    findings.push({
      rule_id: 'auto-crud-exposes-privileged-field',
      rule: AUTO_CRUD_RULE,
      finding_class: 'vulnerability',
      subtype: 'mass-assignment-generated',
      location: { file: res.file, symbol: res.name, line: res.line },
      occurrences: [...new Set(exposed.map((f) => `${f.file}:${f.line}`))].sort(),
      insertion_point: null,
      severity: 'High', impact: 'HIGH', likelihood: 'MEDIUM',
      detection_method: 'pattern',
      reported_severity: 'High',
      detail:
        `the generated ${res.name} resource excludes ${res.excluded.length > 0 ? res.excluded.join(', ') : 'nothing'}, `
        + `and the model declares ${exposed.map((f) => f.field).join(', ')}, which decides what the account may do`,
      evidence: `${res.file}:${res.line} ← ${exposed.map((f) => `${f.file}:${f.line} ${f.field}`).join(', ')}`,
      modules: ['M4', 'M5', 'M7'],
      tool: 'builtin',
    });
  }
  return findings;
}

/**
 * Every function this target defines, by name, with the first lines of its body.
 *
 * Collisions are kept rather than resolved: two files defining `hash` means we
 * do not know which one the call reached, and a resolver that picks one is
 * guessing. Both are checked, and a finding says which file it read.
 */
export function collectDefinitions(rel, lines, text) {
  const out = [];
  DEFINITION.lastIndex = 0;
  let m;
  while ((m = DEFINITION.exec(text)) !== null) {
    const name = m[1] ?? m[2];
    if (!name || NOT_A_HELPER.has(name)) continue;
    const line = text.slice(0, m.index).split('\n').length;
    out.push({ name, file: rel, line, body: lines.slice(line - 1, line - 1 + BODY_LINES).join('\n') });
  }
  return out;
}

/**
 * Places where a password is handed to a function call.
 *
 * The call site is where the finding belongs: it is the line someone has to
 * change, and it is the line that names the field.
 */
export function collectPasswordSinks(rel, lines) {
  const out = [];
  lines.forEach((raw, i) => {
    if (!PASSWORD_FIELD.test(raw)) return;
    if (/^\s*(?:\/\/|\*|#)/.test(raw)) return;
    CALL.lastIndex = 0;
    let m;
    while ((m = CALL.exec(raw)) !== null) {
      const [, obj, name] = m;
      if (NOT_A_HELPER.has(name)) continue;
      out.push({ file: rel, line: i + 1, name, qualifier: obj ?? null, source: raw.trim().slice(0, 200) });
    }
  });
  return out;
}

/**
 * Resolve each password sink one hop and report what the helper actually does.
 *
 * Three outcomes, and only one of them is a finding:
 *  - resolved, and the helper uses a fast digest  → a finding at the call site
 *  - resolved, and the helper uses a KDF          → nothing, correctly
 *  - unresolved                                   → a coverage gap, named
 */
export function weakPasswordHashBehindHelper({ definitions = [], passwordSinks = [] } = {}) {
  const byName = new Map();
  for (const d of definitions) {
    if (!byName.has(d.name)) byName.set(d.name, []);
    byName.get(d.name).push(d);
  }

  // Grouped by the helper, not by the call site. Twenty call sites sharing one
  // `createHash('md5')` are one defect with twenty instances, and one fix closes
  // all of them — `name the cause, not the symptom`, which this project tells
  // its own readers to do. Reporting twenty makes the fix look twenty times
  // bigger than it is, and hides that they are the same line.
  const hits = new Map();
  const unresolved = new Set();

  for (const sink of passwordSinks) {
    const defs = byName.get(sink.name);
    if (!defs) {
      // Only worth reporting when the call looks like it could be doing the
      // hashing. `res.json(user.password)` resolving to nothing is not a gap.
      if (/hash|encrypt|digest|derive|crypt/i.test(sink.name)) {
        unresolved.add(`${sink.qualifier ? `${sink.qualifier}.` : ''}${sink.name} (${sink.file}:${sink.line})`);
      }
      continue;
    }

    for (const def of defs) {
      if (KDF.test(def.body)) continue;
      if (!FAST_DIGEST.test(def.body)) continue;

      const key = `${def.file}:${def.line}:${def.name}`;
      if (!hits.has(key)) hits.set(key, { def, sites: new Set() });
      hits.get(key).sites.add(`${sink.file}:${sink.line}`);
    }
  }

  const findings = [];
  for (const { def, sites } of hits.values()) {
    const where = [...sites].sort();
    findings.push({
      rule_id: 'weak-password-hash-via-helper',
      rule: WEAK_HASH_RULE,
      finding_class: 'vulnerability',
      subtype: 'password-kdf-missing',
      // The helper is the line that changes. The call sites are where it shows.
      location: { file: def.file, symbol: def.name, line: def.line },
      occurrences: where,
      insertion_point: null,
      severity: 'High', impact: 'HIGH', likelihood: 'MEDIUM',
      // Two lines were read and joined. That is more than a pattern match and
      // less than a traced dataflow, and `pattern` is the honest label.
      detection_method: 'pattern',
      reported_severity: 'High',
      detail:
        `${def.name}() hashes with a general-purpose digest, and ${where.length} password `
        + `call site(s) reach it. One fix at ${def.file}:${def.line} closes all of them.`,
      evidence: `${def.file}:${def.line} ← ${where.slice(0, 3).join(', ')}${where.length > 3 ? ` (+${where.length - 3} more)` : ''}`,
      modules: ['M4', 'M12'],
      tool: 'builtin',
    });
  }

  const errors = [];
  if (unresolved.size > 0) {
    errors.push({
      kind: 'unresolved-helper',
      detail:
        `${unresolved.size} password-hashing call(s) name a function this pass could not resolve: `
        + `${[...unresolved].slice(0, 5).join(', ')}. How the password is stored was not established.`,
      unblock: 'the helper is imported from a package, or reached through more than one hop — read it by hand',
    });
  }

  return { findings, errors };
}
