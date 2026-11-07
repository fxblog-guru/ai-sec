// The built-in engine. Pure Node, no install, and deliberately modest:
// it reports what it can defend. A pattern hit is Tentative; only when the
// enclosing function also carries a taint source does it claim `dataflow`.
import { readFileSync } from 'node:fs';
import { relative, sep } from 'node:path';

import { walk } from '../../../lib/fswalk.mjs';
import { RULES, SOURCE_RE, MODEL_CALL, MODEL_SDK_IMPORT } from './rules.mjs';
import { STRUCTURAL_CHECKS, REPO_CHECKS } from './structural.mjs';
import {
  collectDefinitions, collectPasswordSinks, weakPasswordHashBehindHelper,
  collectModelFields, collectAutoCrud, autoCrudExposesPrivilegedField,
} from './crossfile.mjs';

export { walk };

/** The nearest enclosing function-ish declaration above a line. */
export function enclosingSymbol(lines, index) {
  const decl = [
    /(?:async\s+)?function\s+([A-Za-z_$][\w$]*)/,
    /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function|\()/,
    // `if (...) {` is not a declaration. Without the guard this returned `if`,
    // which then became part of the finding's fingerprint.
    /^\s*(?:async\s+)?(?!(?:if|for|while|switch|catch|return|typeof|await|do)\b)([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{/,
    /(?:class)\s+([A-Za-z_$][\w$]*)/,
  ];
  for (let i = index; i >= 0 && i > index - 80; i -= 1) {
    for (const re of decl) {
      const m = re.exec(lines[i]);
      if (m) return m[1];
    }
  }
  return null;
}

const DECL = /(?:async\s+)?function\s+[A-Za-z_$][\w$]*|(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*=\s*(?:async\s*)?(?:function|\(|\[|\{)/;

/**
 * The lines of the function containing `index`.
 *
 * A fixed ±25-line window crosses function boundaries, and both `near` and the
 * taint test then read words that are not in scope. That produced a real false
 * positive on a real repository: `hasCredentials()` sat six lines above a PKCE
 * `createHash('sha256')`, so an S256 challenge — which RFC 7636 requires — was
 * reported as a password stored without a KDF.
 *
 * Only JavaScript-ish files have declarations we can find, so everything else
 * keeps the window.
 *
 * The declaration boundary narrows the window; it never widens it. At the top
 * level of a script there is no enclosing declaration at all, and an unbounded
 * version of this read a whole build script as one scope: a constant
 * `execFileSync('npm ls ...')` picked up a `process.argv` forty lines away and
 * was reported High/Firm as command injection.
 */
function window(lines, index, { js = true, span = 25 } = {}) {
  let start = Math.max(0, index - span);
  let end = Math.min(lines.length, index + span);
  if (!js) return lines.slice(start, end).join('\n');

  for (let i = index; i >= start; i -= 1) {
    if (DECL.test(lines[i])) { start = i; break; }
  }
  for (let i = index + 1; i < end; i += 1) {
    if (DECL.test(lines[i])) { end = i; break; }
  }
  return stripComments(lines.slice(start, end).join('\n'));
}

/**
 * Prose is not a code fact.
 *
 * `near` reads the enclosing scope for a word, and a comment is part of that text.
 * The comment documenting a planted defect in `mock/` contains the phrase "a tool
 * the model may call", and that was enough to report the function above it as an
 * agent tool handler. M6 learned the same thing about frameworks: the word "rails"
 * in a markdown file made a Go repository a Rails app.
 */
export function stripComments(text) {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/(^|[^:])\/\/[^\n]*/g, '$1');
}

function detectLanguages(files) {
  const byExt = new Map();
  for (const f of files) {
    const ext = (f.match(/\.([a-z0-9]+)$/i)?.[1] ?? 'none').toLowerCase();
    byExt.set(ext, (byExt.get(ext) ?? 0) + 1);
  }
  const names = { js: 'javascript', mjs: 'javascript', cjs: 'javascript', jsx: 'javascript', ts: 'typescript', tsx: 'typescript', py: 'python', go: 'go', java: 'java', rb: 'ruby', php: 'php', cs: 'csharp' };
  const langs = new Map();
  for (const [ext, n] of byExt) {
    const lang = names[ext];
    if (lang) langs.set(lang, (langs.get(lang) ?? 0) + n);
  }
  return [...langs].map(([detail, count]) => ({ kind: 'languages', detail, count }));
}

// Route and guard shapes, counted across the whole target. Kept here rather than
// imported from lib/discover.mjs: a scanner must not depend on the controller.
const MODEL_CALL_G = new RegExp(MODEL_CALL.source, 'g');

const ROUTE_DECL_G = /\b(?:router|app)\s*\.\s*(?:get|post|put|patch|delete|all)\s*\(\s*['"`]/g;
// Middleware is attached two ways and both count. NodeGoat passes its guard as a
// route argument and never calls app.use with one, so matching only the use form
// reported "no authorization guard anywhere" on an application that has one.
// A check that fires on a guarded app is worse than no check at all: it is the
// finding people learn to skip, and the next one goes with it.
const GUARD_USE_G = /\b(?:use|before_request|middleware)\s*\(\s*([A-Za-z_$][\w$.]*)\s*\)/g;
// Every middleware between the path and the handler, not just the first. A route
// written `app.get("/x", isLoggedIn, isAdmin, handler)` uses both, and capturing
// only `isLoggedIn` would report `isAdmin` as defined-but-never-applied on an
// application that applies it.
const GUARD_ARG_G = /\b(?:router|app)\s*\.\s*(?:get|post|put|patch|delete|all)\s*\(\s*['"`][^'"`]*['"`]\s*,([^)]*)\)/g;
const GUARD_NAME = /auth|admin|require|ensure|protect|guard|permission|role|verify|authoriz|login|logged|signedin/i;

/** How middleware gets a name: a binding, a declaration, or a method on `this`. */
const AUTHZ_DEFN_G = new RegExp([
  '(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)\\s*=',
  '(?:async\\s+)?function\\s+([A-Za-z_$][\\w$]*)\\s*\\(',
  'this\\s*\\.\\s*([A-Za-z_$][\\w$]*)\\s*=',
].join('|'), 'g');

/**
 * A name that answers "what may you do", not "who are you".
 *
 * The distinction is the whole check. NodeGoat's routes all carry `isLoggedIn`,
 * so the no-guard check is silent and correctly so; the defect is that the
 * `isAdmin` middleware its author wrote is applied by nothing.
 */
const AUTHZ_DEFN_NAME = /admin|role|permission|entitle|authoriz|allow/i;

/** `canEdit`, `canDelete` — only meaningful with the capital, so tested separately. */
const AUTHZ_CAMEL = /\bcan[A-Z]/;

const isAuthzName = (n) => AUTHZ_DEFN_NAME.test(n) || AUTHZ_CAMEL.test(n);

/**
 * The name is not enough; the thing has to be middleware.
 *
 * `const ALLOWED_ACTIONS = { refund, escalate }` matches /allow/ and is a lookup
 * table, and `getAllNonAdminUsers` matches /admin/ and is a database method.
 * Reporting either as an unapplied authorization control is the kind of finding
 * that teaches a reader to stop reading.
 *
 * Middleware is recognised by its signature — a request, a response, and usually
 * a `next` — or by a source that names itself middleware or a guard.
 */
const MIDDLEWARE_SHAPE =
  /\(\s*(?:_|req\w*)\s*,\s*(?:_|res\w*)\s*(?:,\s*(?:_|next\w*)\s*)?\)|middleware|Guard\b|guard\b/i;

function looksLikeMiddleware(afterDefinition) {
  // Only the statement being defined, not whatever follows it. A 240-character
  // window reached past `const ALLOWED_ACTIONS = {...};` into the next function's
  // `(req, res)` and called a lookup table middleware.
  const window = afterDefinition.slice(0, 240);
  const end = Math.min(
    ...[window.indexOf(';'), window.indexOf('\n\n'), window.length]
      .filter((n) => n >= 0),
  );
  return MIDDLEWARE_SHAPE.test(window.slice(0, end));
}

const LANG_BY_EXT = {
  js: 'javascript', mjs: 'javascript', cjs: 'javascript', jsx: 'javascript',
  ts: 'typescript', tsx: 'typescript', py: 'python', go: 'go',
  java: 'java', rb: 'ruby', php: 'php', cs: 'csharp',
};

/** The language the ruleset reaches well enough to make silence mean something. */
const WELL_COVERED = new Set(['javascript', 'typescript']);

/**
 * Languages present in the target that the built-in ruleset cannot really read.
 *
 * `reach` is how many rules applied to each file. A file that only matched the
 * language-agnostic rules was searched for hardcoded credentials and little else.
 */
export function unreachedLanguages(reach, total = RULES.length) {
  const byLang = new Map();
  for (const [rel, applicable] of reach) {
    const lang = LANG_BY_EXT[(rel.match(/\.([a-z0-9]+)$/i)?.[1] ?? '').toLowerCase()];
    if (!lang || WELL_COVERED.has(lang)) continue;
    const cur = byLang.get(lang) ?? { files: 0, best: 0 };
    cur.files += 1;
    cur.best = Math.max(cur.best, applicable);
    byLang.set(lang, cur);
  }

  const out = [];
  for (const [lang, { files, best }] of byLang) {
    if (best >= total / 2) continue; // the ruleset does reach this language
    out.push({
      kind: 'unsupported-language',
      detail:
        `${files} ${lang} file(s): only ${best} of ${total} built-in rules apply to this language, ` +
        'so injection, XSS and crypto were not checked in them. Zero findings here means not examined, not clean.',
      unblock: 'install semgrep, which carries rules for this language, then re-run',
    });
  }
  return out.sort((a, b) => a.detail.localeCompare(b.detail));
}

/**
 * A repository that talks to a model through an SDK no M14 rule can read.
 *
 * The same shape as `unreachedLanguages`, for the same reason. Scanning a real
 * AI application produced zero findings, a `done` run and a ledger with nothing
 * in it — while eleven model calls sat in the source, made through an SDK whose
 * vocabulary none of the M14 rules knew. The import is the evidence that there
 * is something to check; recognising no call in those files is the evidence
 * that we did not check it.
 */
export function unreachedModelSdks({ modelSdkFiles = [], modelCallSites = 0 } = {}) {
  if (modelSdkFiles.length === 0 || modelCallSites > 0) return [];
  return [{
    kind: 'unrecognised-model-sdk',
    detail:
      `${modelSdkFiles.length} file(s) import a model SDK and no M14 rule recognised a model call `
      + 'in any of them, so prompt handling, model output and tool authority were not checked. '
      + 'Zero findings here means not examined, not clean.',
    unblock: 'add this SDK\'s call shape to MODEL_CALL in adapters/scanners/builtin/rules.mjs',
  }];
}

export function scanRepo(root, { maxFiles = 5000 } = {}) {
  const findings = [];
  const errors = [];
  const files = walk(root, { maxFiles });
  const reach = new Map();
  let scanned = 0;
  // Collected across every file, for the checks that are about the target as a
  // whole rather than about any one line in it.
  const repo = {
    routeFiles: [], routesSeen: 0, guardsSeen: 0,
    guardNamesUsed: new Set(), authzDefined: new Map(),
    modelSdkFiles: [], modelCallSites: 0,
    // One hop across a call boundary: what this target defines, and where a
    // password is handed to a call. Neither is a finding on its own.
    definitions: [], passwordSinks: [], modelFields: [], autoCrud: [],
  };

  for (const file of files) {
    let text;
    try {
      text = readFileSync(file, 'utf8');
    } catch (e) {
      errors.push({ kind: 'unreadable-file', detail: `${relative(root, file)}: ${e.code ?? e.message}` });
      continue;
    }
    if (text.includes('\u0000')) continue; // binary
    scanned += 1;

    // Placement (test vs production vs vendored) is decided once, in the controller.
    const rel = relative(root, file).split(sep).join('/');
    const lines = text.split(/\r?\n/);
    const isJs = /\.(?:js|mjs|cjs|ts|tsx|jsx)$/i.test(rel);

    // Relationships between lines, which no single-line pattern can reach.
    if (isJs) {
      for (const check of STRUCTURAL_CHECKS) {
        findings.push(...check(rel, lines, text));
      }
    }

    if (isJs) {
      repo.definitions.push(...collectDefinitions(rel, lines, text));
      repo.passwordSinks.push(...collectPasswordSinks(rel, lines));
      repo.modelFields.push(...collectModelFields(rel, text));
      repo.autoCrud.push(...collectAutoCrud(rel, text));
    }

    if (isJs) {
      const routes = text.match(ROUTE_DECL_G);
      if (routes) {
        repo.routesSeen += routes.length;
        repo.routeFiles.push(rel);
      }
      // Usages are counted from code only. NodeGoat keeps the working route
      // registrations — the ones that pass through `isAdmin` — inside a block
      // comment directly below the vulnerable pair, so counting the commented
      // text would report the guard as applied and hide the defect entirely.
      const code = stripComments(text);

      GUARD_USE_G.lastIndex = 0;
      let u;
      while ((u = GUARD_USE_G.exec(code)) !== null) {
        if (GUARD_NAME.test(u[1])) repo.guardsSeen += 1;
        repo.guardNamesUsed.add(u[1].split('.').pop());
      }

      GUARD_ARG_G.lastIndex = 0;
      let a;
      while ((a = GUARD_ARG_G.exec(code)) !== null) {
        for (const raw of a[1].split(',')) {
          const name = raw.trim().split('.').pop();
          if (!/^[A-Za-z_$][\w$]*$/.test(name)) continue;
          if (GUARD_NAME.test(name)) repo.guardsSeen += 1;
          repo.guardNamesUsed.add(name);
        }
      }

      // Does this file talk to a model, and did we recognise how? Counted from
      // code, like the guards: an SDK named in a comment is not an import.
      if (MODEL_SDK_IMPORT.test(code)) repo.modelSdkFiles.push(rel);
      MODEL_CALL_G.lastIndex = 0;
      while (MODEL_CALL_G.exec(code) !== null) repo.modelCallSites += 1;

      // Middleware that decides authorization, wherever it is named.
      AUTHZ_DEFN_G.lastIndex = 0;
      let d;
      while ((d = AUTHZ_DEFN_G.exec(code)) !== null) {
        const name = (d[1] ?? d[2] ?? d[3] ?? '').split('.').pop();
        if (!name || !isAuthzName(name)) continue;
        if (!looksLikeMiddleware(code.slice(d.index))) continue;
        if (repo.authzDefined.has(name)) continue;
        repo.authzDefined.set(name, { file: rel, line: code.slice(0, d.index).split('\n').length });
      }
    }

    let applicable = 0;
    for (const rule of RULES) {
      if (!rule.files.test(rel)) continue;
      applicable += 1;
      const re = new RegExp(rule.match.source, rule.match.flags.includes('g') ? rule.match.flags : `${rule.match.flags}g`);

      for (let i = 0; i < lines.length; i += 1) {
        re.lastIndex = 0;
        const m = re.exec(lines[i]);
        if (!m) continue;

        const ctx = window(lines, i, { js: isJs });
        if (rule.near && !rule.near.test(ctx)) continue;
        // Some defects are an absence: a model call with no token ceiling, a tool
        // handler with no authorization. The finding is that nothing nearby does it.
        if (rule.not_near && rule.not_near.test(ctx)) continue;

        // A rule marked `taint` only claims dataflow when a source is in scope.
        const tainted = rule.taint ? SOURCE_RE.test(ctx) : false;
        if (rule.taint && !tainted && !rule.report_without_source) continue;

        const method = rule.method ?? (tainted ? 'dataflow' : 'pattern');

        findings.push({
          rule_id: rule.id,
          rule: rule.rule,
          finding_class: rule.finding_class ?? 'vulnerability',
          // Only when the rule declares one: a subtype changes the fingerprint,
          // and giving every rule one would re-identify every finding that
          // already exists in somebody's baseline.
          ...(rule.subtype ? { subtype: rule.subtype } : {}),
          location: { file: rel, symbol: enclosingSymbol(lines, i), line: i + 1 },
          insertion_point: null,
          severity: rule.severity,
          impact: rule.impact ?? null,
          likelihood: rule.likelihood ?? null,
          detection_method: method,
          reported_severity: rule.severity,
          detail: rule.rule.name,
          // The redactor rewrites this before it is written; for a secret rule we
          // never carry the matched text at all.
          evidence: rule.secret ? `${rel}:${i + 1}` : lines[i].trim().slice(0, 200),
          modules: rule.modules,
          tool: 'builtin',
        });
      }
    }
    reach.set(rel, applicable);
  }

  // A language the ruleset barely reaches is a blind spot, not a clean result.
  // Scanning a 1005-file Go repository produced zero findings and a ledger that
  // said nothing about Go: the rules are written for JavaScript, so only the two
  // language-agnostic ones ever applied. That is the quiet pass design.md §7.4
  // forbids, and it reads exactly like a target with nothing wrong with it.
  for (const e of unreachedLanguages(reach)) errors.push(e);
  for (const e of unreachedModelSdks(repo)) errors.push(e);
  for (const check of REPO_CHECKS) findings.push(...check(repo));

  // Resolved after every file has been read, because the helper is usually in a
  // file the sink's own pass had not reached yet.
  const crossFile = weakPasswordHashBehindHelper(repo);
  findings.push(...crossFile.findings);
  for (const e of crossFile.errors) errors.push(e);
  findings.push(...autoCrudExposesPrivilegedField(repo));

  const coverage = [
    ...detectLanguages(files),
    { kind: 'files', detail: 'read', count: scanned },
    { kind: 'rules', detail: 'builtin ruleset', count: RULES.length },
  ];

  return { findings, coverage, errors };
}
