#!/usr/bin/env node
// Rebuild the Juice Shop answer key from the corpus itself.
//
// We did not decide what counts as a planted defect here. Juice Shop marks the
// exact line of each one in its own source:
//
//   models.sequelize.query(`SELECT ... '${req.body.email}' ...`) // vuln-code-snippet vuln-line loginAdminChallenge
//
// This reads those markers back out. Run it against a clone to check that
// `juiceshop-expected.json` still describes the version you are scanning —
// the corpus moves, and an answer key nobody re-derives is a claim, not a
// measurement.
//
//   node benchmarks/juiceshop.mjs /path/to/juice-shop
//
// `data/static/codefixes/` is excluded: those files are the exercise's
// alternative answers, both broken and fixed, and are not what the server runs.
import { readFileSync, readdirSync } from 'node:fs';
import { join, relative } from 'node:path';

const SKIP = new Set(['.git', 'node_modules', 'dist', 'build', 'coverage']);
const CODE = /\.(?:ts|js|tsx|jsx)$/;
const MARKER = /vuln-code-snippet vuln-line (.+)$/;

function* walk(dir) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (SKIP.has(e.name)) continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) yield* walk(p);
    else if (CODE.test(e.name)) yield p;
  }
}

export function annotatedDefects(root) {
  const out = [];
  for (const p of walk(root)) {
    const rel = relative(root, p).split('\\').join('/');
    if (rel.startsWith('data/static/codefixes/')) continue;
    readFileSync(p, 'utf8').split(/\r?\n/).forEach((line, i) => {
      const m = line.match(MARKER);
      if (m) out.push({ file: rel, line: i + 1, challenges: m[1].trim().split(/\s+/) });
    });
  }
  return out.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);
}

if (process.argv[1] && import.meta.url.endsWith(process.argv[1].split('\\').join('/').split('/').pop())) {
  const root = process.argv[2];
  if (!root) {
    process.stderr.write('usage: node benchmarks/juiceshop.mjs <path-to-juice-shop-clone>\n');
    process.exit(1);
  }
  const found = annotatedDefects(root);
  for (const d of found) process.stdout.write(`${d.file}:${d.line}  ${d.challenges.join(',')}\n`);
  const files = new Set(found.map((d) => d.file)).size;
  process.stdout.write(`\n${found.length} annotated vulnerable lines in ${files} files\n`);
  process.stdout.write('Compare against benchmarks/juiceshop-expected.json, which groups them into defects.\n');
}
