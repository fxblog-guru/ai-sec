// Architectural invariants — pillar P5's measurable check.
//
// "Adding a scanner changes no skill." That only stays true if the registry is the
// single place scanners are named. These tests fail the moment it is not.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

import { SCANNERS, TARGETS, scannersForTier, EXPLICIT_ONLY } from '../adapters/index.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const read = (p) => readFileSync(join(ROOT, p), 'utf8');
const listDir = (p) => (existsSync(join(ROOT, p)) ? readdirSync(join(ROOT, p)) : []);

const SCANNER_NAMES = Object.keys(SCANNERS);

test('every scanner satisfies the adapter contract', async () => {
  for (const [name, s] of Object.entries(SCANNERS)) {
    assert.equal(s.name, name, `${name}: name must match its registry key`);
    assert.ok(typeof s.tool === 'string', `${name}: missing tool`);
    assert.ok(Array.isArray(s.tiers) && s.tiers.length, `${name}: missing tiers`);
    assert.ok(Array.isArray(s.modules) && s.modules.length, `${name}: missing modules`);
    assert.equal(typeof s.detect, 'function', `${name}: missing detect()`);
    assert.equal(typeof s.scanCommand, 'function', `${name}: missing scanCommand()`);
    assert.equal(typeof s.parse, 'function', `${name}: missing parse()`);

    const d = await s.detect();
    assert.equal(typeof d.ok, 'boolean', `${name}: detect() must report ok`);
    if (!d.ok) assert.ok(d.install, `${name}: an undetected scanner must say how to install it`);
  }
});

test('scanCommand is pure: it returns a command and touches nothing', () => {
  for (const [name, s] of Object.entries(SCANNERS)) {
    const cmd = s.scanCommand({
      runDir: join(ROOT, '.nonexistent'), target: { root: ROOT }, options: {}, depth: 'normal', accuracy: 'balanced',
    });
    assert.ok(cmd.cmd, `${name}: no cmd`);
    assert.ok(Array.isArray(cmd.args), `${name}: args must be an array`);
    assert.ok(cmd.timeout_s > 0, `${name}: every scan must be bounded by a timeout`);
  }
});

test('every target satisfies its contract', () => {
  for (const [name, t] of Object.entries(TARGETS)) {
    assert.equal(t.name, name);
    assert.equal(typeof t.prepare, 'function');
    assert.equal(typeof t.cleanup, 'function');
  }
});

/**
 * Strip comments before looking for imports. An import check that reads prose finds
 * `// require('express')` and calls it a dependency — which is the same mistake the
 * discovery matcher makes if you let it match a bare quoted word.
 */
function code(path) {
  return read(path)
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/^\s*\/\/.*$/gm, '')
    .replace(/([^:'"`\\])\/\/.*$/gm, '$1');
}

test('the registry is the ONLY place scanner adapters are imported', () => {
  const offenders = [];
  for (const dir of ['lib', 'controller', 'bin']) {
    for (const f of listDir(dir)) {
      if (!f.endsWith('.mjs')) continue;
      if (/from\s+['"].*adapters\/scanners\//.test(code(join(dir, f)))) offenders.push(`${dir}/${f}`);
    }
  }
  assert.deepEqual(offenders, [],
    'these import a scanner directly; adding a scanner would then mean editing them');
});

test('no skill hardcodes the scanner list', () => {
  // A skill may name a scanner as an example or an install hint. It must not enumerate
  // the full set, because that is the thing that would go stale on every addition.
  const offenders = [];
  for (const skill of listDir('skills')) {
    const file = join('skills', skill, 'SKILL.md');
    if (!existsSync(join(ROOT, file))) continue;
    const text = read(file);
    const named = SCANNER_NAMES.filter((n) => new RegExp(`\\b${n}\\b`).test(text));
    if (named.length === SCANNER_NAMES.length) offenders.push(`${file} names all of ${named.join(',')}`);
  }
  assert.deepEqual(offenders, [], 'a skill enumerating every scanner breaks "add one, change no skill"');
});

test('the fake scanner is never selected implicitly', () => {
  assert.ok(EXPLICIT_ONLY.has('fake'));
  const implicit = scannersForTier('T0').map((s) => s.name);
  assert.ok(!implicit.includes('fake'), 'fake must be opt-in, or every real run is contaminated');
  assert.ok(scannersForTier('T0', ['fake']).map((s) => s.name).includes('fake'), 'and opt-in must work');
});

test('a scanner only declares tiers it is allowed to run at', () => {
  const VALID = new Set(['T0', 'T1', 'T2', 'T3', 'T4']);
  for (const [name, s] of Object.entries(SCANNERS)) {
    for (const t of s.tiers) assert.ok(VALID.has(t), `${name}: unknown tier ${t}`);
  }
});

test('every command points at a skill that exists', () => {
  const skills = new Set(listDir('skills'));
  for (const f of listDir('commands')) {
    const text = read(join('commands', f));
    for (const m of text.matchAll(/Follow the `([a-z-]+)` skill/g)) {
      assert.ok(skills.has(m[1]), `${f} points at a missing skill: ${m[1]}`);
    }
  }
});

test('every skill has frontmatter with a name matching its folder', () => {
  for (const skill of listDir('skills')) {
    const file = join('skills', skill, 'SKILL.md');
    if (!existsSync(join(ROOT, file))) continue;
    const text = read(file);
    assert.match(text, /^---\n/, `${file}: no frontmatter`);
    const name = /^name:\s*(\S+)/m.exec(text)?.[1];
    assert.equal(name, skill, `${file}: frontmatter name must match the folder`);
    assert.match(text, /^description:\s*\S/m, `${file}: no description`);
  }
});

test('the controller has no runtime dependencies', () => {
  const pkg = JSON.parse(read('package.json'));
  assert.equal(pkg.dependencies, undefined, 'the controller must stay dependency-free');
  for (const dir of ['controller', 'lib']) {
    for (const f of listDir(dir)) {
      if (!f.endsWith('.mjs')) continue;
      for (const m of code(join(dir, f)).matchAll(/^\s*import\b[^'"]*from\s+['"]([^'"]+)['"]/gm)) {
        const spec = m[1];
        if (spec.startsWith('.')) continue; // our own modules
        assert.match(spec, /^node:/, `${dir}/${f} imports ${spec}; only node: builtins are allowed`);
      }
    }
  }
});

test('the standards baseline is stated in one place', () => {
  const scan = read('lib/scan.mjs');
  assert.match(scan, /owasp_top10:\s*'2025'/, 'the 2025 edition, not 2021');
  assert.match(scan, /asvs:\s*'5\.0\.0'/);
  assert.match(scan, /wstg:\s*'v4\.2'/);
});

test('no source file contains a control character', () => {
  // A substitution written with an unescaped \b put a literal 0x08 into a regex,
  // which then matched a backspace followed by `app.get(` — that is, nothing. The
  // check it belonged to silently found zero routes in a repository with 22, and
  // the only visible symptom was a finding that never appeared.
  const offenders = [];
  for (const f of sourceFiles()) {
    const text = readFileSync(join(ROOT, f), 'utf8');
    const m = /[\u0000-\u0008\u000B\u000C\u000E-\u001F]/.exec(text);
    if (m) {
      const line = text.slice(0, m.index).split('\n').length;
      offenders.push(`${f}:${line} U+${m[0].charCodeAt(0).toString(16).padStart(4, '0')}`);
    }
  }
  assert.deepEqual(offenders, [], 'a control character in source is never intentional');
});

/** Every .mjs the project ships, relative to the repo root. */
function sourceFiles() {
  const out = [];
  const walk = (dir) => {
    for (const e of readdirSync(join(ROOT, dir), { withFileTypes: true })) {
      if (e.name.startsWith('.') || e.name === 'node_modules') continue;
      const p = dir ? `${dir}/${e.name}` : e.name;
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith('.mjs')) out.push(p);
    }
  };
  walk('');
  return out;
}

test('the guard vocabulary is identical everywhere it is defined', () => {
  // Three copies, and they had already drifted: structural.mjs was missing
  // `login`. Each copy decides whether a name counts as an authorization check,
  // so a difference between them means the discovery pass and the scanner
  // disagree about whether an application is guarded at all.
  const defs = [];
  for (const f of sourceFiles()) {
    const m = /const GUARD_NAME = (\/[^\n]*\/i);/.exec(readFileSync(join(ROOT, f), 'utf8'));
    if (m) defs.push({ file: f, pattern: m[1] });
  }
  assert.ok(defs.length >= 2, 'expected more than one definition to compare');
  const distinct = [...new Set(defs.map((d) => d.pattern))];
  assert.equal(distinct.length, 1,
    `guard vocabularies differ:\n${defs.map((d) => `  ${d.file}: ${d.pattern}`).join('\n')}`);
});

test('every mutation can still apply to the code it guards', async () => {
  // An anchor goes stale the moment the line it quotes is edited, and the runner
  // only says so after fifteen minutes — by which time the behaviour has been
  // unguarded for however long. Three went stale in one afternoon: one line was
  // rewritten by a later fix, two were written with the wrong indentation and
  // never ran at all. npm test now notices in milliseconds.
  const { preflight } = await import('./mutate.mjs');
  assert.equal(preflight(), 0, 'see the output above for the anchors that no longer resolve');
});
