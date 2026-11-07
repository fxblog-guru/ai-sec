// Cross-cutting judgements about where a finding lives.
//
// These belong to the controller, not to an adapter. Found by scanning ai-sec with
// ai-sec: gitleaks reported absolute Windows paths and full severity for findings in
// tests/, because only the builtin engine knew to normalize and downgrade. Every
// scanner needs both, so neither can live in one of them.
import { readFileSync } from 'node:fs';
import { relative, isAbsolute, join, sep } from 'node:path';

/**
 * Paths whose contents do not ship, so a finding there is unlikely to be reachable.
 * The filename conventions differ by language and all of them matter: a Go repo
 * scanned with only the JavaScript convention reports every `_test.go` at full severity.
 */
export const NON_PRODUCTION_PATH = new RegExp([
  '(?:^|/)(?:tests?|__tests__|spec|specs|fixtures?|examples?|mocks?|__mocks__|testdata|e2e|benchmarks?)(?:/|$)',
  '\\.(?:test|spec)\\.[cm]?[jt]sx?$',   // foo.test.ts
  '_test\\.(?:go|py|rb|exs?)$',          // foo_test.go
  '(?:^|/)test_[^/]+\\.py$',             // test_foo.py
  '_spec\\.rb$',                         // foo_spec.rb
  'Test\\.(?:java|kt|cs)$',              // FooTest.java
].join('|'), 'i');

/** Vendored or generated code: present, but not ours to fix here. */
export const VENDORED_PATH =
  /(?:^|\/)(?:node_modules|vendor|third_party|dist|build|out|coverage|\.min\.)(?:\/|$)/i;

/**
 * Our own run artifacts. A scanner with its own walker will happily read
 * `.sec/.../raw/gitleaks.json` and report the findings inside it as new findings,
 * which grows every run. These are not findings about the target at all.
 */
export const ARTIFACT_PATH = new RegExp([
  '(?:^|/)\\.(?:sec|perf)(?:/|$)',       // our own runs, and ai-perf's
  '(?:^|/)worktrees?(?:/|$)',            // a git worktree is a second copy of the repo
  '(?:^|/)\\.sdlc/(?:reviews|scripts)(?:/|$)', // tooling state, not project source
].join('|'), 'i');

/**
 * Repo-relative, forward slashes. An absolute path makes a fingerprint machine-
 * specific, so the same finding looks new on a colleague's checkout and in CI.
 */
export function toRepoRelative(file, root) {
  if (typeof file !== 'string' || file === '') return '';
  const normalized = file.replace(/\\/g, '/');
  if (!root) return normalized.replace(/^\.\//, '');

  const rootN = String(root).replace(/\\/g, '/').replace(/\/+$/, '');
  if (normalized.toLowerCase().startsWith(`${rootN.toLowerCase()}/`)) {
    return normalized.slice(rootN.length + 1);
  }
  if (isAbsolute(file)) {
    const rel = relative(root, file);
    // outside the root: keep it absolute rather than emitting ../../.. noise
    if (!rel.startsWith('..')) return rel.split(sep).join('/');
  }
  return normalized.replace(/^\.\//, '');
}

/**
 * Declarations we can recognise without parsing. Covering several languages
 * matters: an adapter that reads Go or Python gets the same identity as one
 * that reads JavaScript, or its findings never merge with anything.
 */
const DECLARATION = [
  /(?:async\s+)?function\s+([A-Za-z_$][\w$]*)/,                        // function f()
  /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function|\()/, // const f = () =>
  /^\s*(?:export\s+)?(?:default\s+)?class\s+([A-Za-z_$][\w$]*)/,       // class C
  /^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)/,                             // def f  (python)
  /^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)/,                        // func f / method (go)
  /^\s*(?:public|private|protected|internal)[\w\s<>\[\],]*?\s([A-Za-z_]\w*)\s*\(/, // java/c#
  /^\s*def\s+([A-Za-z_]\w*)/,                                          // ruby
];

/** Read-through cache: a scan asks about the same file many times. */
const fileCache = new Map();

function linesOf(root, file) {
  const key = `${root}\u0000${file}`;
  if (fileCache.has(key)) return fileCache.get(key);
  let lines = null;
  try {
    const text = readFileSync(root ? join(root, file) : file, 'utf8');
    lines = text.includes('\u0000') ? null : text.split(/\r?\n/);
  } catch { lines = null; }
  if (fileCache.size > 2000) fileCache.clear();
  fileCache.set(key, lines);
  return lines;
}

/** The nearest declaration at or above `line` (1-indexed), or null. */
export function symbolAt(root, file, line) {
  const lines = linesOf(root, file);
  if (!lines) return null;
  const start = Math.min(line - 1, lines.length - 1);
  for (let i = start; i >= 0 && i > start - 80; i -= 1) {
    for (const re of DECLARATION) {
      const m = re.exec(lines[i]);
      if (m && m[1]) return m[1];
    }
  }
  return null;
}

export const isNonProduction = (file) => NON_PRODUCTION_PATH.test(file ?? '');
export const isVendored = (file) => VENDORED_PATH.test(file ?? '');
export const isArtifact = (file) => ARTIFACT_PATH.test(file ?? '');

/**
 * Normalize a partial finding's location and temper its severity by where it lives.
 * A credential in a test fixture is a hygiene note; the same string in shipped
 * configuration is an incident. Nothing is dropped — it is reported for what it is.
 */
export function placeFinding(partial, root) {
  const file = toRepoRelative(partial.location?.file, root);
  const location = { ...(partial.location ?? {}), file };

  // The fingerprint prefers `file#symbol` over `file:line`, so a finding that
  // names its symbol and one that does not are two different findings — and most
  // scanners do not name it. Semgrep and the builtin engine reported the same MD5
  // password hash on the same line and never merged, because one said
  // `app/auth.js#hashPassword` and the other `app/auth.js:11`.
  //
  // Resolving the symbol is a judgement about where a finding lives, so it is
  // decided once, here, for every adapter — the same lesson as path normalization.
  if (!location.symbol && Number.isInteger(location.line)) {
    location.symbol = symbolAt(root, file, location.line);
  }

  const located = { ...partial, location };

  if (isArtifact(file)) {
    // Not a finding about the target: our own run output, a worktree copy of files
    // already scanned, or another tool's state. The caller drops these and records
    // how many, so they leave the report without leaving silently.
    return { ...located, placement: 'artifact' };
  }
  if (isVendored(file)) {
    return {
      ...located,
      severity: 'Info',
      likelihood: 'LOW',
      detail: `${located.detail ?? ''} (in vendored or generated code, which this project does not author)`.trim(),
      placement: 'vendored',
    };
  }
  if (isNonProduction(file)) {
    return {
      ...located,
      severity: 'Info',
      likelihood: 'LOW',
      detail: `${located.detail ?? ''} (in test or example code, which is unlikely to be reachable in production)`.trim(),
      placement: 'non-production',
    };
  }
  return { ...located, placement: 'production' };
}
