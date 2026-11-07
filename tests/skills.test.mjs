// The skills are the part of this bundle nobody runs, so nothing told us they had
// stopped being true.
//
// They sat untouched for ten milestones while the controller grew `sec verify`,
// `sec modules`, `sec status`, hardening notes, preflight refusals and three
// benchmark grades. A reader following them would have run an assessment that was
// correct for M5 and silently missing everything after it. That is this project's
// own failure mode — a thing read something absent and passed — in the one place
// it had no test.
//
// These are cheap checks. They cannot tell whether a skill gives good advice. They
// can tell whether it is describing a program that still exists.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { GRADES } from '../lib/scorecard.mjs';
import { VERDICTS, VERIFICATION_METHODS } from '../controller/verification.mjs';
import { FINDING_CLASSES } from '../controller/taxonomy.mjs';
import { CODE_ROLES } from '../controller/coderole.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const SKILLS = join(ROOT, 'skills');

const names = readdirSync(SKILLS, { withFileTypes: true })
  .filter((d) => d.isDirectory())
  .map((d) => d.name);

const skill = (name) => readFileSync(join(SKILLS, name, 'SKILL.md'), 'utf8');
const all = names.map(skill).join('\n');

/** Every `sec <word>` the CLI dispatches on, read from the source rather than listed here. */
function cliCommands() {
  const src = readFileSync(join(ROOT, 'bin', 'sec.mjs'), 'utf8');
  const found = new Set();
  for (const m of src.matchAll(/cmd === '([a-z]+)'/g)) found.add(m[1]);
  found.delete('help');
  found.delete('version');
  return [...found].sort();
}

/**
 * Every `sec <word>` any skill tells a reader to run.
 *
 * Only a command line or a code span counts. Prose says "the sec skills" and "a sec
 * assessment", and reading those as commands made this test report ghosts of its own.
 */
function skillCommands() {
  const found = new Set();
  for (const m of all.matchAll(/\bsec\.mjs ([a-z]+)|`sec ([a-z]+)[ `]/g)) {
    found.add(m[1] ?? m[2]);
  }
  return found;
}

test('every skill has the frontmatter the loader needs', () => {
  for (const name of names) {
    const text = skill(name);
    assert.match(text, /^---\n/, `${name}: no frontmatter`);
    assert.match(text, new RegExp(`\\nname: ${name}\\n`), `${name}: name does not match its directory`);
    assert.match(text, /\ndescription: .{40,}/, `${name}: description too thin to route on`);
  }
});

test('no skill tells a reader to run a command that does not exist', () => {
  const real = new Set(cliCommands());
  const referenced = skillCommands();
  const ghosts = [...referenced].filter((c) => !real.has(c));
  assert.deepEqual(ghosts, [], `skills reference commands the CLI does not have: ${ghosts.join(', ')}`);
});

test('every command the CLI has is named by at least one skill', () => {
  // A command no skill mentions is a feature the reader will never reach. If one
  // is deliberately internal, say so here rather than letting the set drift.
  const INTERNAL = new Set(['import']);
  const referenced = skillCommands();
  const orphans = cliCommands().filter((c) => !INTERNAL.has(c) && !referenced.has(c));
  assert.deepEqual(orphans, [], `the CLI has commands no skill mentions: ${orphans.join(', ')}`);
});

test('the vocabulary a reader has to act on is written down somewhere', () => {
  // These are the words that appear in output. A reader who meets `needs_validation`
  // or `unmeasured` for the first time in a terminal has been failed by the skills.
  for (const word of [...GRADES, ...VERDICTS, ...FINDING_CLASSES, ...VERIFICATION_METHODS, ...CODE_ROLES]) {
    assert.ok(all.includes(word), `no skill explains \`${word}\``);
  }
});

test('the standards baseline the skills state is the one the code classifies against', () => {
  // Two skills print this line to a reader. When the code starts citing a new
  // standard, the printed line must move with it.
  const protocol = skill('sec-protocol');
  for (const standard of ['WSTG', 'ASVS', 'OWASP Top 10', 'API Top 10', 'LLM Applications', 'CVSS']) {
    assert.ok(protocol.includes(standard), `sec-protocol does not state ${standard}`);
  }
  assert.ok(!protocol.includes('Top 10 2021'), 'sec-protocol cites a superseded OWASP edition');
});

test('every gate the controller can refuse with is explained to the reader', () => {
  const scoping = skill('scoping-the-assessment');
  const src = [
    readFileSync(join(ROOT, 'controller', 'rules.mjs'), 'utf8'),
  ].join('\n');
  const gates = [...new Set([...src.matchAll(/G\d-[a-z-]+/g)].map((m) => m[0]))];
  assert.ok(gates.length > 0, 'no gates found in the controller');
  for (const g of gates) {
    assert.ok(scoping.includes(g), `scoping-the-assessment does not say what to do about ${g}`);
  }
});
