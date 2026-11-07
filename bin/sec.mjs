#!/usr/bin/env node
// ai-sec CLI. One command to start; sane defaults; a cost estimate before it runs.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolve, join } from 'node:path';

import { readFileSync as read, readdirSync, existsSync, mkdirSync, writeFileSync } from 'node:fs';

import { scan, ALL_MODULES, loadScope, ScopeError } from '../lib/scan.mjs';
import { doctor, formatDoctor } from '../lib/doctor.mjs';
import { scannersForTier, modulesCoveredBy, SCANNERS } from '../adapters/index.mjs';
import { SEVERITIES } from '../controller/merge.mjs';
import { ledgerIsEmpty } from '../lib/coverage.mjs';
import { verdict, formatVerdict } from '../lib/verdict.mjs';
import { promote, judge, verify, appendLesson, readLessons, readBaseline } from '../lib/baseline.mjs';
import { VERIFICATION_METHODS, verificationSummary, unverified } from '../controller/verification.mjs';
import { discover, formatSurface, STATIC_BLIND_SPOTS } from '../lib/discover.mjs';
import { scorecard, formatScorecard, benchmarkFor } from '../lib/scorecard.mjs';
import { toSarif, fromSarif } from '../lib/sarif.mjs';
import { state as projectState, format as formatHelp, next as nextStep } from '../lib/help.mjs';
import { isApplicationCode } from '../controller/coderole.mjs';

const ALL_SCANNERS = Object.values(SCANNERS);

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const VERSION = readFileSync(join(ROOT, 'VERSION'), 'utf8').trim();

function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const [k, inline] = a.slice(2).split('=');
      const next = argv[i + 1];
      if (inline !== undefined) out[k] = inline;
      else if (next && !next.startsWith('--')) { out[k] = next; i += 1; }
      else out[k] = true;
    } else out._.push(a);
  }
  return out;
}

const USAGE = `ai-sec ${VERSION}

  sec status [--slug default]              what is done, and the one next step
  sec discover [target] [--slug default]   map the attack surface
  sec doctor [--root .] [--slug default]
  sec modules [--slug default]          per-module measurement of the last run
  sec scan [target] [--tier T0] [--modules M1,M5] [--scanners builtin,gitleaks]
           [--accuracy balanced] [--depth normal] [--baseline none]
           [--slug default] [--json]
  sec report [--run latest] [--bootstrap] [--slug default]
  sec baseline promote [--run latest] [--slug default]
  sec verify <fingerprint> <confirmed|needs_validation|rejected> --by <who> [--via <method>] <reason>
  sec judge <fingerprint> <open|fixed|false_positive|accepted_risk> <reason>
  sec export [--run latest] [--out file.sarif]   project a run to SARIF 2.1.0
  sec import <file.sarif> [--tool name]          bring someone else's SARIF in
  sec lessons [add "<lesson>"]

Defaults: target = current directory, tier = T0 (static, sends nothing),
all applicable modules, accuracy balanced, depth normal.

Exit codes: 0 done/PASS/WARN · 1 error or FAIL · 2 refused · 3 not evaluable
            4 degraded · 5 aborted
`;

function runsDir(root, slug) {
  return join(root, '.sec', slug, 'runs');
}

function resolveRun(root, slug, which = 'latest') {
  const dir = runsDir(root, slug);
  if (!existsSync(dir)) return null;
  if (which && which !== 'latest') return join(dir, which);
  const runs = readdirSync(dir).sort();
  return runs.length ? join(dir, runs[runs.length - 1]) : null;
}

function loadResult(runDir) {
  const file = join(runDir, 'result.json');
  return existsSync(file) ? JSON.parse(read(file, 'utf8')) : null;
}

function estimate(spec, scope) {
  const selected = scannersForTier(spec.tier, spec.scanners);
  const covered = modulesCoveredBy(selected);
  const uncovered = spec.modules.filter((m) => !covered.includes(m));
  return [
    `Scope:    ${spec.target_path}`,
    `Modules:  ${spec.modules.join(',')}    Tier: ${spec.tier}${spec.tier === 'T0' ? ' (static, no traffic)' : ''}`,
    `Scanners: ${selected.map((s) => s.name).join(', ') || 'none'}    Ceiling: ${scope.max_tier}`,
    `Estimate: ${selected.length} scanner run(s), ~${Math.max(1, selected.length * 10)}s.  Subagents: none.`,
    uncovered.length ? `Note:     ${uncovered.length} selected module(s) have no scanner: ${uncovered.join(',')}` : null,
  ].filter(Boolean).join('\n');
}

function printResult(result) {
  const { summary, findings, not_evaluable: ne, run_state: st, rules = [] } = result;
  // The type layer holds the readable name. The issue family is the right key for
  // merging and the wrong label for a report: a route registered before its guard
  // and a query with no tenant predicate are both `missing-authz`, and a reader
  // needs to be told which one is on the line in front of them.
  const nameOf = new Map(rules.map((r) => [r.rule_id, r.name]));
  const lines = [];
  lines.push(`\nRun ${result.run_id} — ${st}`);
  lines.push(`Standards: WSTG ${result.standards.wstg} · ASVS ${result.standards.asvs} · OWASP Top 10 ${result.standards.owasp_top10} · CVSS ${result.standards.cvss}`);

  lines.push('\n            Certain  Firm  Tentative');
  for (const s of [...SEVERITIES].reverse()) {
    const row = summary.by_severity_confidence[s];
    if (!row) continue;
    lines.push(`  ${s.padEnd(9)} ${String(row.Certain).padStart(7)} ${String(row.Firm).padStart(5)} ${String(row.Tentative).padStart(10)}`);
  }
  lines.push(`\n  new ${summary.new} · fixed ${summary.fixed} · unchanged ${summary.unchanged} · suppressed ${summary.suppressed}`);

  const allOpen = findings.filter((f) => f.status === 'open');
  // Scanning Juice Shop put 188 test-suite findings in front of the SQL
  // injection in its login route. They are still reported — a key in a test
  // file is a key — but one list ordered by severity is the wrong shape for
  // them, because severity is a claim about the running system.
  const open = allOpen.filter(isApplicationCode);
  const outside = allOpen.filter((f) => !isApplicationCode(f));
  if (open.length) {
    lines.push('\nFindings');
    for (const f of open) {
      // The issue type is the name every scanner shares. Printing one tool's rule id
      // made two scanners agreeing look like two unrelated problems.
      const name = nameOf.get(f.rule_id) || f.issue_type || f.rule_id;
      const where = `${f.location?.file ?? ''}${f.location?.line ? `:${f.location.line}` : ''}`;
      const tools = (f.tools ?? []).length > 1 ? `  (${f.tools.join(' + ')})` : '';
      // One identity, several places. Printing only the first is how someone
      // fixes one call site and closes the finding.
      const times = f.occurrences ? `  ×${f.occurrences.length}` : '';
      lines.push(`  [${f.severity}/${f.confidence}] ${name}  ${where}${times}${tools}`);
      if (f.occurrences) lines.push(`      also at: ${f.occurrences.filter((o) => o !== where).join(', ')}`);
      if (f.severity_disagreement) {
        const who = f.severity_disagreement.map((s) => `${s.tool} ${s.severity}`).join(', ');
        lines.push(`      scanners disagree on severity: ${who} — taking the highest`);
      }
    }
  }

  if (outside.length) {
    const byRole = {};
    for (const f of outside) {
      const r = f.code_role;
      const name = nameOf.get(f.rule_id) || f.issue_type || f.rule_id;
      byRole[r] ??= {};
      byRole[r][name] = (byRole[r][name] ?? 0) + 1;
    }
    lines.push(`\nIn non-application code (${outside.length}) — reported, not counted against the bar`);
    for (const [role, kinds] of Object.entries(byRole)) {
      const what = Object.entries(kinds)
        .sort((a, b) => b[1] - a[1])
        .map(([name, n]) => `${name} ×${n}`)
        .join(', ');
      lines.push(`  ${role}: ${what}`);
    }
    lines.push('  a credential in a test file is still a credential — judge these, do not assume the path makes them safe');
  }

  if (ne.length) {
    lines.push(`\nCould not evaluate (${ne.length})`);
    for (const n of ne) lines.push(`  - ${n.check}: ${n.reason}`);
  }
  return lines.join('\n');
}

async function main() {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  const args = parseArgs(argv.slice(1));

  if (!cmd || cmd === 'help' || args.help) { process.stdout.write(USAGE); return 0; }
  if (cmd === 'version') { process.stdout.write(`${VERSION}\n`); return 0; }

  const root = resolve(args.root ?? '.');
  const slug = args.slug ?? 'default';

  if (cmd === 'status') {
    const s = projectState(root, slug);
    process.stdout.write(args.json
      ? `${JSON.stringify({ ...s, next: nextStep(s) }, null, 2)}\n`
      : `${formatHelp(s)}\n`);
    return 0;
  }

  if (cmd === 'discover') {
    const target = resolve(args._[0] ?? root);
    const surface = discover(target);
    const dir = join(root, '.sec', slug);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'surface.json'), `${JSON.stringify(surface, null, 2)}\n`, 'utf8');
    process.stdout.write(args.json
      ? `${JSON.stringify(surface, null, 2)}\n`
      : `${formatSurface(surface)}\n\nWritten to ${join(dir, 'surface.json')}\n`);
    return 0;
  }

  if (cmd === 'doctor') {
    const report = await doctor({ root, slug });
    process.stdout.write(`${formatDoctor(report)}\n\n${report.ok ? 'doctor: ok' : `doctor: ${report.failed.length} failing check(s)`}\n`);
    return report.ok ? 0 : 1;
  }

  if (cmd === 'modules') {
    // Measured against the last run in this project, so the numbers describe
    // whatever was actually scanned rather than a claim about the ruleset.
    const s = projectState(root, slug);
    if (!s.last_result) {
      process.stderr.write(`No run in .sec/${slug}. Scan the benchmark first:\n  sec scan mock --slug ${slug}\n`);
      return 3;
    }
    const engines = {};
    for (const a of ALL_SCANNERS) {
      const det = await a.detect();
      engines[a.name] = { modules: a.modules ?? [], installed: Boolean(det.ok) };
    }
    const benchmark = benchmarkFor(s.last_result);
    const rows = scorecard({
      findings: s.last_result.findings ?? [],
      rules: s.last_result.rules ?? [],
      expected: benchmark.expected,
      engines,
      blindSpots: STATIC_BLIND_SPOTS,
      benchmarkTrust: benchmark.trust,
      // What the run could not do, as opposed to what this bundle never covers.
      degraded: s.last_result.degraded ?? [],
    });
    process.stdout.write(`${formatScorecard(rows, { source: benchmark.source })}\n`);
    return 0;
  }

  if (cmd === 'scan') {
    const spec = {
      root,
      slug,
      target: args.target ?? 'repo',
      target_path: resolve(args._[0] ?? args['target-path'] ?? root),
      target_url: args.url,
      tier: args.tier ?? 'T0',
      modules: args.modules ? String(args.modules).split(',') : ALL_MODULES,
      scanners: args.scanners ? String(args.scanners).split(',') : null,
      accuracy: args.accuracy ?? 'balanced',
      depth: args.depth ?? 'normal',
      baseline: args.baseline,
    };

    const scope = loadScope(root, slug);
    if (!args.json) process.stdout.write(`${estimate(spec, scope)}\n`);

    const outcome = await scan(spec);

    if (!outcome.ok && outcome.refused) {
      process.stderr.write(`\nrefused by ${outcome.refused.gate}: ${outcome.refused.reason}\n`);
      return 2;
    }
    if (!outcome.result) {
      process.stderr.write(`\n${outcome.run_state}: ${outcome.reason ?? 'no result'}\n`);
      return outcome.exit_code;
    }
    if (args.json) {
      process.stdout.write(`${JSON.stringify(outcome.result, null, 2)}\n`);
    } else {
      process.stdout.write(`${printResult(outcome.result)}\n`);
      if (outcome.run_state === 'done' && !ledgerIsEmpty({ not_evaluable: outcome.result.not_evaluable })) {
        process.stdout.write('\nNote: this run completed, but the coverage ledger above is not empty.\n');
      }
      process.stdout.write(`\nArtifacts: ${outcome.runDir}\n`);
    }
    return outcome.exit_code;
  }

  if (cmd === 'report') {
    const runDir = resolveRun(root, slug, args.run);
    if (!runDir) { process.stderr.write('no run to report on; run sec scan first\n'); return 1; }
    const result = loadResult(runDir);
    if (!result) { process.stderr.write(`no result.json in ${runDir}\n`); return 1; }

    const scope = loadScope(root, slug);
    const baseline = readBaseline(root, slug, scope.environment);
    const v = verdict(result, { baseline, bootstrap: Boolean(args.bootstrap) });

    process.stdout.write(args.json
      ? `${JSON.stringify(v, null, 2)}\n`
      : `${formatVerdict(v)}\n\nRun: ${runDir}\n`);
    return v.exit_code;
  }

  if (cmd === 'baseline') {
    const sub = args._[0] ?? 'show';
    const scope = loadScope(root, slug);

    if (sub === 'show') {
      const b = readBaseline(root, slug, scope.environment);
      if (!b) { process.stdout.write('no baseline yet\n'); return 0; }
      process.stdout.write(`baseline ${scope.environment}: ${b.findings.length} finding(s), promoted ${b.promoted_at} from run ${b.run_id}\n`);
      for (const f of b.findings) process.stdout.write(`  ${f.fingerprint.slice(0, 12)} [${f.severity}/${f.confidence}] ${f.status.padEnd(16)} ${f.rule_id}\n`);
      return 0;
    }

    if (sub === 'promote') {
      const runDir = resolveRun(root, slug, args.run);
      const result = runDir && loadResult(runDir);
      if (!result) { process.stderr.write('no run to promote; run sec scan first\n'); return 1; }
      const r = promote(root, slug, result, { force: Boolean(args.force) });
      if (!r.ok) { process.stderr.write(`refused: ${r.reason}\n`); return 1; }
      process.stdout.write(`promoted ${r.count} finding(s) to ${r.file}${r.carried ? ` (carried ${r.carried} human verdict(s))` : ''}\n`);
      return 0;
    }

    process.stderr.write(`unknown baseline subcommand: ${sub}\n`);
    return 1;
  }

  if (cmd === 'verify') {
    const [fp, verdict, ...rest] = args._;
    if (!fp || !verdict) {
      process.stderr.write(
        'usage: sec verify <fingerprint> <confirmed|needs_validation|rejected> --by <who> [--via <method>] <reason>\n'
        + `       methods: ${VERIFICATION_METHODS.join(', ')}\n`,
      );
      return 1;
    }
    const scope = loadScope(root, slug);
    const r = verify(root, slug, fp, {
      verdict,
      verifier: args.by ?? args.verifier,
      method: args.via ?? args.method,
      reason: rest.join(' '),
    }, scope.environment);

    if (!r.ok) { process.stderr.write(`${r.reason}\n`); return 1; }
    process.stdout.write(`${fp.slice(0, 12)} -> ${r.verdict}\n`);
    if (r.verdict !== 'confirmed') {
      process.stdout.write('   severity dropped: it is a claim about demonstrated impact\n');
    }
    return 0;
  }

  if (cmd === 'judge') {
    const [fp, status, ...rest] = args._;
    if (!fp || !status) { process.stderr.write('usage: sec judge <fingerprint> <status> <reason>\n'); return 1; }
    const scope = loadScope(root, slug);
    const r = judge(root, slug, fp, status, rest.join(' '), scope.environment);
    if (!r.ok) { process.stderr.write(`${r.reason}\n`); return 1; }
    process.stdout.write(`${fp.slice(0, 12)} -> ${status}\n`);
    return 0;
  }

  if (cmd === 'export') {
    const runDir = resolveRun(root, slug, args.run);
    const result = runDir && loadResult(runDir);
    if (!result) { process.stderr.write('no run to export; run sec scan first\n'); return 1; }

    const sarif = toSarif(result, { toolVersion: VERSION });
    const text = `${JSON.stringify(sarif, null, 2)}\n`;
    if (args.out) {
      writeFileSync(resolve(args.out), text, 'utf8');
      const gaps = sarif.runs[0].properties.not_evaluable.length;
      process.stdout.write(`wrote ${sarif.runs[0].results.length} result(s) to ${resolve(args.out)}\n`);
      if (gaps) process.stdout.write(`note: ${gaps} coverage gap(s) travel in run.properties.not_evaluable, not in results[]\n`);
    } else {
      process.stdout.write(text);
    }
    return 0;
  }

  if (cmd === 'import') {
    const file = args._[0];
    if (!file) { process.stderr.write('usage: sec import <file.sarif>\n'); return 1; }
    const sarif = JSON.parse(read(resolve(file), 'utf8'));
    const { findings, rules } = fromSarif(sarif, { tool: args.tool });
    process.stdout.write(args.json
      ? `${JSON.stringify({ findings, rules }, null, 2)}\n`
      : `imported ${findings.length} finding(s) and ${rules.length} rule(s) from ${file}\n` +
        'every imported finding starts at Tentative: we did not see how it was found.\n');
    return 0;
  }

  if (cmd === 'lessons') {
    if (args._[0] === 'add') {
      const r = appendLesson(root, slug, args._.slice(1).join(' '));
      if (!r.ok) { process.stderr.write(`${r.reason}\n`); return 1; }
      process.stdout.write(`recorded in ${r.file}\n`);
      return 0;
    }
    const text = readLessons(root, slug);
    process.stdout.write(text ?? 'no lessons recorded yet\n');
    return 0;
  }

  process.stderr.write(`unknown command: ${cmd}\n\n${USAGE}`);
  return 1;
}

main().then((code) => process.exit(code)).catch((err) => {
  // A broken config file is the user's problem to fix, not a crash to read.
  if (err instanceof ScopeError) {
    process.stderr.write(`${err.message}\n\nFix the file, or delete it to fall back to the defaults (T0, no hosts).\n`);
    process.exit(1);
  }
  process.stderr.write(`error: ${err.stack ?? err.message}\n`);
  process.exit(1);
});
