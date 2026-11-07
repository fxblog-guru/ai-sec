// "What now?" — answered from project state. This command never asks anything.
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { readBaseline, readLessons } from './baseline.mjs';
import { loadScope } from './scan.mjs';

export function state(root, slug) {
  const dir = join(root, '.sec', slug);
  const runsDir = join(dir, 'runs');
  const runs = existsSync(runsDir) ? readdirSync(runsDir).sort() : [];
  const last = runs.length ? runs[runs.length - 1] : null;

  let lastResult = null;
  if (last) {
    const f = join(runsDir, last, 'result.json');
    if (existsSync(f)) {
      try { lastResult = JSON.parse(readFileSync(f, 'utf8')); } catch { /* unreadable */ }
    }
  }

  const scope = loadScope(root, slug);
  return {
    slug,
    has_scope_file: existsSync(join(dir, 'scope.json')),
    has_surface: existsSync(join(dir, 'surface.json')),
    scope,
    runs: runs.length,
    last_run: last,
    last_result: lastResult,
    baseline: readBaseline(root, slug, scope.environment),
    lessons: Boolean(readLessons(root, slug)),
  };
}

/** The next action, with the reason. One step at a time, never a wall of options. */
export function next(s) {
  if (!s.has_surface) {
    return { step: 'discover', command: 'sec discover', why: 'nothing is mapped yet; a scan without a surface is a guess' };
  }
  // Scope is worth writing before the first run, and after that only when the
  // defaults are actually in the way. Telling someone to go and write a config
  // file right after a scan that worked is advice nobody can act on.
  if (!s.has_scope_file && s.runs === 0) {
    return { step: 'scope', command: 'sec scope', why: 'no scope file, so defaults apply: T0 only, no hosts allowed' };
  }
  if (s.runs === 0) {
    return { step: 'scan', command: 'sec scan', why: 'the surface is mapped; run the static pass' };
  }
  if (!s.baseline) {
    return {
      step: 'baseline',
      command: 'sec baseline promote',
      why: 'there is a run but no baseline, so the next run cannot tell you what changed',
    };
  }

  const r = s.last_result;
  if (r && r.run_state !== 'done') {
    return {
      step: 'fix-coverage',
      command: 'sec doctor',
      why: `the last run was ${r.run_state}; something did not get examined`,
    };
  }
  const open = (r?.findings ?? []).filter((f) => f.status === 'open');
  const high = open.filter((f) => ['High', 'Critical'].includes(f.severity));
  if (high.length) {
    return {
      step: 'verify',
      command: 'sec report',
      why: `${high.length} finding(s) at High or above are open; confirm or dismiss them`,
    };
  }
  const gaps = r?.not_evaluable?.length ?? 0;
  if (gaps) {
    return {
      step: 'close-gaps',
      command: 'sec doctor',
      why: `${gaps} check(s) could not be evaluated; a clean result still has blind spots`,
    };
  }
  return { step: 'rescan', command: 'sec scan', why: 'everything above the bar is handled; re-scan after the next change' };
}

export function format(s) {
  const n = next(s);
  const lines = [`Project ${s.slug} — tier ceiling ${s.scope.max_tier}, environment ${s.scope.environment}`];

  lines.push('');
  lines.push(`  surface   ${s.has_surface ? 'mapped' : 'not mapped'}`);
  lines.push(`  scope     ${s.has_scope_file ? 'set' : 'defaults (T0, no hosts)'}`);
  lines.push(`  runs      ${s.runs}${s.last_run ? ` (last ${s.last_run}: ${s.last_result?.run_state ?? 'unreadable'})` : ''}`);
  lines.push(`  baseline  ${s.baseline ? `${s.baseline.findings.length} finding(s) from ${s.baseline.run_id}` : 'none'}`);
  lines.push(`  lessons   ${s.lessons ? 'recorded' : 'none'}`);

  if (s.last_result) {
    const open = s.last_result.findings.filter((f) => f.status === 'open');
    const bySev = {};
    for (const f of open) bySev[f.severity] = (bySev[f.severity] ?? 0) + 1;
    const parts = Object.entries(bySev).map(([k, v]) => `${v} ${k}`);
    lines.push(`  open      ${parts.join(', ') || 'none'}`);
    if (s.last_result.not_evaluable.length) {
      lines.push(`  gaps      ${s.last_result.not_evaluable.length} check(s) could not be evaluated`);
    }
  }

  lines.push('', `Next: ${n.command}`, `      ${n.why}`);
  return lines.join('\n');
}
