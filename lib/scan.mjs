// Orchestration: gates -> scanners -> merge -> coverage -> result.
// The AI is not in this path. CONTRACTS §1-§7.
import { spawn } from 'node:child_process';
import { mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';

import * as redactor from '../controller/redact.mjs';
import { checkGates, evaluateAutoStop, tierRank } from '../controller/rules.mjs';
import { mergeFindings, diffBaseline, summarize } from '../controller/merge.mjs';
import { classify, roleSummary } from '../controller/coderole.mjs';
import { placeFinding } from '../controller/locate.mjs';
import { issueType, mergeClassification } from '../controller/taxonomy.mjs';
import { createState, move, exitCodeFor } from '../controller/state.mjs';
import { emit } from '../controller/events.mjs';
import { buildLedger, resolveRunState } from './coverage.mjs';
import { readBaseline } from './baseline.mjs';
import { TARGETS, scannersForTier, modulesCoveredBy, availableScanners } from '../adapters/index.mjs';

export const STANDARDS = {
  wstg: 'v4.2',
  asvs: '5.0.0',
  owasp_top10: '2025',
  api_top10: '2023',
  cvss: '3.1',
};

export const ALL_MODULES = ['M1','M2','M3','M4','M5','M6','M7','M8','M9','M10','M11','M12','M13','M14'];

export const DEFAULT_SCOPE = {
  schema: 'sec-scope/v1',
  max_tier: 'T0',
  authorization: { basis: 'own-repo', granted_by: 'local', granted_at: null, note: 'implicit for T0' },
  allow_hosts: [],
  deny_paths: ['node_modules/**', 'vendor/**'],
  production: false,
  environment: 'local',
};

export function runId(now = new Date()) {
  const p = (n, w = 2) => String(n).padStart(w, '0');
  const stamp =
    `${now.getFullYear()}${p(now.getMonth() + 1)}${p(now.getDate())}-` +
    `${p(now.getHours())}${p(now.getMinutes())}${p(now.getSeconds())}`;
  return `${stamp}-${randomBytes(2).toString('hex')}`;
}

/** U+FEFF, written as a number so it is visible in the source. */
const BOM = 0xFEFF;

export class ScopeError extends Error {}

export function loadScope(root, slug) {
  const file = join(root, '.sec', slug, 'scope.json');
  if (!existsSync(file)) return { ...DEFAULT_SCOPE };

  // A byte-order mark is what Notepad and Windows PowerShell leave behind, and
  // JSON.parse will not accept it. Strip it rather than failing on a character
  // nobody can see, and report anything else as a readable error, not a stack trace.
  const raw = readFileSync(file, 'utf8');
  const text = raw.charCodeAt(0) === BOM ? raw.slice(1) : raw;
  try {
    return { ...DEFAULT_SCOPE, ...JSON.parse(text) };
  } catch (e) {
    throw new ScopeError(`${file} is not valid JSON: ${e.message}`);
  }
}

export function loadBaseline(root, slug, scope) {
  return readBaseline(root, slug, scope.environment ?? 'local');
}

/** Redact, then write. Never the other way round. */
function writeJson(file, value) {
  writeFileSync(file, `${JSON.stringify(redactor.redactDeep(value), null, 2)}\n`, 'utf8');
}

function writeText(file, text) {
  writeFileSync(file, redactor.redactText(text), 'utf8');
}

function runOne(scanner, { runDir, target, options, depth, accuracy, tier }) {
  const cmd = scanner.scanCommand({ runDir, target, options, depth, accuracy, tier });
  const timeoutMs = (cmd.timeout_s ?? 600) * 1000;

  return new Promise((resolvePromise) => {
    const started = Date.now();
    let stdout = '';
    let stderr = '';
    let timedOut = false;

    const child = spawn(cmd.cmd, cmd.args, {
      env: { ...process.env, ...(cmd.env ?? {}) },
      windowsHide: true,
    });

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, timeoutMs);

    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('error', (err) => {
      clearTimeout(timer);
      resolvePromise({
        name: scanner.name, failed: true, timed_out: false, exit_code: null,
        error: err.message, stdout: '', stderr: '', duration_s: 0,
        timeout_s: cmd.timeout_s,
      });
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolvePromise({
        name: scanner.name,
        failed: timedOut || code !== 0,
        timed_out: timedOut,
        exit_code: code,
        error: timedOut ? `timed out after ${cmd.timeout_s}s` : null,
        stdout, stderr,
        duration_s: (Date.now() - started) / 1000,
        timeout_s: cmd.timeout_s,
      });
    });
  });
}

export async function scan(rawSpec = {}) {
  const root = resolve(rawSpec.root ?? '.');
  const slug = rawSpec.slug ?? 'default';
  const scope = rawSpec.scope ?? loadScope(root, slug);

  const spec = {
    slug,
    target: rawSpec.target ?? 'repo',
    target_path: rawSpec.target_path ?? root,
    target_url: rawSpec.target_url,
    tier: rawSpec.tier ?? 'T0',
    modules: rawSpec.modules ?? ALL_MODULES,
    accuracy: rawSpec.accuracy ?? 'balanced',
    depth: rawSpec.depth ?? 'normal',
    scanners: rawSpec.scanners ?? null,
    scanner_options: rawSpec.scanner_options ?? {},
    timeout_s: rawSpec.timeout_s ?? 600,
    run_id: runId(),
    root,
  };

  // --- gates first. Nothing runs, and nothing is written, before they pass.
  const gates = checkGates({ scope, spec, rawSpec, redactor });
  if (!gates.ok) {
    return {
      ok: false,
      refused: gates.refused,
      run_state: 'aborted',
      exit_code: 2,
      gates: gates.results,
    };
  }

  const runDir = join(root, '.sec', slug, 'runs', spec.run_id);
  mkdirSync(join(runDir, 'raw'), { recursive: true });
  const eventsFile = join(runDir, 'events.ndjson');

  const state = createState(spec.run_id);
  writeJson(join(runDir, 'run.json'), spec);
  emit(eventsFile, 'scan_started', `scan ${spec.run_id} at tier ${spec.tier}`, {
    data: { slug, tier: spec.tier, modules: spec.modules },
  });

  // --- target
  const targetAdapter = TARGETS[spec.target];
  if (!targetAdapter) {
    move(state, 'aborted', `unknown target: ${spec.target}`);
    writeJson(join(runDir, 'state.json'), state);
    return { ok: false, run_state: 'aborted', exit_code: 5, reason: `unknown target: ${spec.target}` };
  }
  const prepared = await targetAdapter.prepare({ spec, scope });
  if (!prepared.ok) {
    move(state, 'not_evaluable', prepared.error);
    writeJson(join(runDir, 'state.json'), state);
    emit(eventsFile, 'run_finished', prepared.error, { severity: 'error' });
    return { ok: false, run_state: 'not_evaluable', exit_code: 3, reason: prepared.error, runDir };
  }

  // --- scanners. One that is not installed is recorded, never silently dropped.
  move(state, 'scanning');
  const requested = scannersForTier(spec.tier, spec.scanners);
  const detected = await availableScanners(requested);
  const selected = detected.filter((d) => d.detected.ok).map((d) => d.scanner);
  const unavailable = detected
    .filter((d) => !d.detected.ok)
    .map((d) => ({ name: d.scanner.name, install: d.detected.install }));

  for (const u of unavailable) {
    emit(eventsFile, 'scanner_failed', `${u.name} is not installed`, {
      severity: 'warn', data: { scanner: u.name },
    });
  }

  const results = [];
  // A scanner that is installed but cannot reach THIS target. `detect` answers a
  // different question, and conflating the two is how a scanner reports zero
  // findings against something it never touched.
  const skipped = [];
  // A scanner that runs with one of its capabilities blind. Not a skip — the rest
  // of it still contributes — and not nothing, because the module that was
  // counting on that capability would otherwise report a confident zero.
  const degraded = [];
  // Above T0 the run sends traffic, so the hard rules are evaluated after every
  // scanner. Stop first, explain after. CONTRACTS §4.
  const active = tierRank(spec.tier) > 0;
  const signals = {
    requests: 0, failures: 0, consecutive_errors: 0,
    out_of_scope_requests: 0, unintended_writes: 0, auth_failure_rate: 0,
  };
  let stopped = null;

  for (const scanner of selected) {
    if (stopped) break;
    const options = spec.scanner_options[scanner.name] ?? {};

    if (typeof scanner.preflight === 'function') {
      const pf = await scanner.preflight({ target: prepared, options, tier: spec.tier, scope });
      if (pf && pf.ok === false) {
        skipped.push({ name: scanner.name, reason: pf.reason, unblock: pf.unblock });
        emit(eventsFile, 'scanner_skipped', `${scanner.name} did not run: ${pf.reason}`, {
          severity: 'warn', data: { scanner: scanner.name },
        });
        continue;
      }
      for (const d of pf?.degraded ?? []) {
        degraded.push({ scanner: scanner.name, ...d });
        emit(eventsFile, 'scanner_degraded', `${scanner.name} cannot check ${d.capability} here: ${d.reason}`, {
          severity: 'warn', data: { scanner: scanner.name, capability: d.capability },
        });
      }
    }

    // One directory per scanner, created before it runs. scanCommand and parse must
    // be given the SAME path: an adapter that writes a report where parse does not
    // look loses every finding it made, silently.
    const scannerDir = join(runDir, 'raw', scanner.name);
    mkdirSync(scannerDir, { recursive: true });

    const raw = await runOne(scanner, {
      runDir: scannerDir, target: prepared, options, depth: spec.depth, accuracy: spec.accuracy, tier: spec.tier,
    });
    writeText(join(scannerDir, 'stdout'), raw.stdout);
    writeText(join(scannerDir, 'stderr'), raw.stderr);
    writeFileSync(join(scannerDir, 'exit'), `${raw.exit_code}\n`, 'utf8');

    const parsed = await scanner.parse({
      stdout: raw.stdout, stderr: raw.stderr, exitCode: raw.exit_code, runDir: scannerDir,
    });
    writeJson(join(scannerDir, 'parsed.json'), parsed);

    results.push({ ...raw, parsed, tool: scanner.tool });

    if (raw.failed) {
      emit(eventsFile, 'scanner_failed', `${scanner.name} failed: ${raw.error ?? raw.exit_code}`, {
        severity: 'warn', data: { scanner: scanner.name },
      });
    } else {
      emit(eventsFile, 'scanner_finished',
        `${scanner.name} finished: ${parsed.findings.length} candidate findings`, {
          data: { scanner: scanner.name, findings: parsed.findings.length },
        });
    }

    if (active) {
      accumulate(signals, parsed.counters);
      const stop = evaluateAutoStop(signals);
      if (stop.stop) {
        stopped = stop;
        emit(eventsFile, 'auto_stopped', stop.reason, {
          severity: 'error', data: { rule: stop.rule, after: scanner.name, signals },
        });
      }
    }
  }

  // --- merge
  move(state, 'merging');
  const baseline = rawSpec.baseline === 'none' ? null : (rawSpec.baseline ?? loadBaseline(root, slug, scope));
  // Normalize and place every finding before merging, so each scanner is judged by
  // the same rules and a fingerprint does not depend on where the repo is checked out.
  const placed = results
    .flatMap((r) => r.parsed?.findings ?? [])
    .map((f) => placeFinding(f, prepared.root));

  // A scanner with its own walker reads our previous runs and reports the findings
  // recorded in them as new ones. Drop those, and say how many, so the number is
  // visible rather than silently absent.
  const partials = placed.filter((f) => f.placement !== 'artifact');
  const artifactCount = placed.length - partials.length;

  // Label before the baseline diff, so a finding's role travels with it and a
  // promoted baseline does not have to be re-classified to be compared.
  const findings = mergeFindings(partials, { baseline }).map(classify);
  const diff = diffBaseline(findings, baseline);

  const rules = collectRules(results);
  // A scanner that was skipped covers nothing. Counting its modules here is how a
  // module ends up reported as covered by a tool that never ran.
  const ran = selected.filter((s) => !skipped.some((k) => k.name === s.name));
  const coveredModules = modulesCoveredBy(ran);
  const ledger = buildLedger({
    results, selectedModules: spec.modules, coveredModules, findings,
    tier: spec.tier, maxTier: scope.max_tier, unavailable, skipped, degraded,
  });

  const runState = resolveRunState(results, stopped ? 'aborted' : null);
  move(state, runState, stopped?.reason ?? null);

  for (const f of findings) {
    if (f.severity === 'Critical' && f.baseline_state === 'new' && f.status === 'open') {
      emit(eventsFile, 'new_critical', `new critical finding: ${f.rule_id}`, {
        severity: 'error', data: { fingerprint: f.fingerprint, rule_id: f.rule_id },
      });
    }
  }

  const result = {
    schema: 'sec-result/v1',
    run_id: spec.run_id,
    run_state: runState,
    started_at: state.started_at,
    finished_at: state.finished_at,
    target: { kind: spec.target, path: prepared.root, git_sha: null },
    scope: {
      tier: spec.tier, max_tier: scope.max_tier,
      authorization_basis: scope.authorization?.basis ?? null,
      environment: scope.environment,
    },
    standards: STANDARDS,
    tools: results.map((r) => ({
      name: r.name, version: null, exit_code: r.exit_code, duration_s: r.duration_s,
    })),
    rules,
    findings,
    coverage: ledger.covered,
    not_evaluable: ledger.not_evaluable,
    // Kept on the result, not only in the ledger text, so `sec modules` can turn
    // it into a blind spot on the exact module it cost.
    degraded,
    summary: { ...summarize(findings), new: diff.new, fixed: diff.fixed, unchanged: diff.unchanged },
    ...(active ? { signals } : {}),
    ...(stopped ? { auto_stop: stopped } : {}),
  };

  if (artifactCount > 0) {
    ledger.covered.push({
      kind: 'files', scanner: 'controller',
      detail: `${artifactCount} finding(s) inside ai-sec's own run artifacts, excluded`,
      count: artifactCount, scanned: false,
    });
  }

  if (stopped) {
    ledger.not_evaluable.push({
      check: 'the rest of this run',
      reason: `auto-stopped: ${stopped.reason}`,
      unblock: 'resolve what tripped the rule, then re-run',
    });
    result.not_evaluable = ledger.not_evaluable;
  }

  writeJson(join(runDir, 'findings.json'), findings);
  writeJson(join(runDir, 'coverage.json'), ledger);
  writeJson(join(runDir, 'result.json'), result);
  writeJson(join(runDir, 'state.json'), state);
  emit(eventsFile, 'run_finished', `run ${spec.run_id} finished: ${runState}`, {
    severity: runState === 'done' ? 'info' : 'warn', data: { run_state: runState },
  });

  return { ok: true, run_state: runState, exit_code: exitCodeFor(runState), result, runDir };
}

/**
 * Fold a scanner's request counters into the run's signals. A scanner that reports
 * none contributes none — it cannot hide traffic by staying quiet, because only a
 * scanner that sends traffic has counters to report in the first place.
 */
function accumulate(signals, counters) {
  if (!counters) return signals;
  signals.requests += counters.requests ?? 0;
  signals.failures += counters.failures ?? 0;
  signals.out_of_scope_requests += counters.out_of_scope_requests ?? 0;
  signals.unintended_writes += counters.unintended_writes ?? 0;
  signals.consecutive_errors = Math.max(signals.consecutive_errors, counters.consecutive_errors ?? 0);
  signals.auth_failure_rate = signals.requests > 0
    ? (signals.auth_failure_rate * 0 + (counters.auth_failures ?? 0)) / signals.requests
    : 0;
  return signals;
}

/**
 * The rules[] catalogue: the type layer. One entry per scanner rule, carrying the
 * background, remediation and classification that must never be repeated on an
 * instance.
 *
 * `issue_type` is what lets a reader see that two scanners' rules name one defect:
 * `open-redirect` and `javascript.express.security.audit.express-open-redirect`
 * both resolve to the family `open-redirect`, which is also the merge key.
 */
function collectRules(results) {
  const byId = new Map();
  for (const r of results) {
    for (const f of r.parsed?.findings ?? []) {
      if (!f.rule_id || byId.has(f.rule_id)) continue;
      const ident = issueType(f);
      byId.set(f.rule_id, {
        rule_id: f.rule_id,
        issue_type: ident.type,
        identity_basis: ident.basis,
        ...(f.rule ?? {}),
        classification: mergeClassification([f.rule?.classification]),
      });
    }
  }
  return [...byId.values()];
}
