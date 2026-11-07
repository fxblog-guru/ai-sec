// The coverage ledger: what the run did NOT look at.
// This is the mechanism behind "never a quiet pass". design.md §7.4.
import { worstOf } from '../controller/state.mjs';
import { roleSummary } from '../controller/coderole.mjs';

export const COVERAGE_KINDS = ['languages', 'files', 'rules', 'packages', 'endpoints'];

/**
 * A scanner that reported neither findings nor coverage produced nothing —
 * it is not evidence of a clean target.
 */
export function scannerProducedNothing(parsed) {
  const findings = parsed?.findings ?? [];
  const coverage = parsed?.coverage ?? [];
  return findings.length === 0 && coverage.length === 0;
}

/**
 * Terminal state from what the scanners actually managed.
 *
 *   done           every selected scanner ran and reported coverage
 *   degraded       at least one reported coverage, but another failed or produced nothing
 *   not_evaluable  nothing reported coverage, or the target could not be read
 */
export function runStateFromScanners(results = []) {
  if (results.length === 0) return 'not_evaluable';

  const withCoverage = results.filter((r) => (r.parsed?.coverage ?? []).length > 0);
  if (withCoverage.length === 0) return 'not_evaluable';

  const failed = results.filter(
    (r) => r.failed || r.timed_out || scannerProducedNothing(r.parsed),
  );
  return failed.length > 0 ? 'degraded' : 'done';
}

/** Merge state derived from scanners with any state the gates or user forced. */
export function resolveRunState(results, forced = null) {
  const derived = runStateFromScanners(results);
  return forced ? worstOf(derived, forced) : derived;
}

/** The ledger written to coverage.json and printed by the report. */
export function buildLedger({
  results = [], selectedModules = [], coveredModules = [], findings = [],
  tier = 'T0', maxTier = 'T0', unavailable = [], skipped = [], degraded = [],
}) {
  const covered = [];
  const notEvaluable = [];

  // A scanner that is not installed covered nothing. Say so rather than quietly
  // narrowing the run to whatever happened to be on the machine.
  for (const u of unavailable) {
    notEvaluable.push({
      check: `scanner ${u.name}`,
      reason: 'not installed, so the checks it contributes did not run',
      unblock: u.install ?? 'install the scanner, then re-run',
    });
  }

  // Installed, selected, and still never ran: it could not reach this target.
  // "Installed" is not "ran", and a ledger that only records the first lets the
  // second pass as a clean result.
  for (const s of skipped) {
    notEvaluable.push({
      check: `scanner ${s.name}`,
      reason: s.reason ?? 'the adapter refused this target',
      unblock: s.unblock ?? 'see the adapter',
    });
  }

  // Ran, and still could not do one of the things it is credited with. This is
  // the half-way state between "not installed" and "clean": trivy with no
  // lockfile reports zero CVEs, and zero is indistinguishable from safe unless
  // the reason is written down beside it.
  for (const d of degraded) {
    notEvaluable.push({
      check: `${d.scanner}: ${d.capability}`,
      reason: d.reason ?? 'the adapter reported this capability as blind against this target',
      unblock: d.unblock ?? 'see the adapter',
      modules: d.modules ?? [],
    });
  }

  for (const r of results) {
    for (const c of r.parsed?.coverage ?? []) {
      covered.push({ scanner: r.name, ...c, scanned: true });
    }
    for (const e of r.parsed?.errors ?? []) {
      notEvaluable.push({
        check: `${r.name}: ${e.kind}`,
        reason: e.detail,
        unblock: e.unblock ?? 'see the scanner output in raw/',
      });
    }
    if (r.timed_out) {
      notEvaluable.push({
        check: `${r.name}: full scan`,
        reason: `timed out after ${r.timeout_s}s`,
        unblock: 'raise timeout_s, or narrow the target',
      });
    }
    if (r.failed && !r.timed_out) {
      notEvaluable.push({
        check: `${r.name}: full scan`,
        reason: r.error ?? `exited ${r.exit_code}`,
        unblock: 'run sec doctor',
      });
    }
    if (!r.failed && !r.timed_out && scannerProducedNothing(r.parsed)) {
      notEvaluable.push({
        check: `${r.name}: coverage`,
        reason: 'reported no findings and no coverage, so it examined nothing we can confirm',
        unblock: 'check the scanner supports this target',
      });
    }
  }

  // A finding whose scanner supplied no CWE has no cross-tool identity, so it can
  // never be recognised as the same defect another scanner already reported. That
  // is a real limit on "merge, never sum", and an unmergeable duplicate looks
  // exactly like a second finding. Counting it is the difference between a known
  // limitation and a quiet one.
  const unmatched = findings.filter((f) => f.identity_basis === 'rule_id');
  if (unmatched.length > 0) {
    const tools = [...new Set(unmatched.flatMap((f) => f.tools ?? []))].sort();
    notEvaluable.push({
      check: 'cross-scanner matching',
      reason:
        `${unmatched.length} finding(s) from ${tools.join(', ') || 'a scanner'} carry no CWE, ` +
        'so they cannot be matched against other scanners and may duplicate findings above',
      unblock: 'map the rule to a CWE in the adapter, or read these alongside the merged set',
    });
  }

  // Findings that are not about anything that runs. They stay in the report and
  // stay out of the verdict, and the count goes here so the difference between
  // "the application is clean" and "the application findings are the short list"
  // is never left to the reader to infer from a path.
  const roles = roleSummary(findings);
  const outside = Object.values(roles).reduce((a, b) => a + b, 0);
  if (outside > 0) {
    notEvaluable.push({
      check: 'non-application code',
      reason:
        `${outside} of ${findings.length} finding(s) are in code that does not run in production (`
        + `${Object.entries(roles).map(([r, n]) => `${n} ${r}`).join(', ')}`
        + '), so they are reported and not counted against the bar',
      unblock:
        'a credential in a test file is still a credential: judge these separately rather than '
        + 'assuming the path makes them safe',
    });
  }

  // One tool reported two of its own rules at one location and the CWE family
  // merged them. Whichever arrived second kept nothing but a line here, and a
  // reader fixing the surviving one has not fixed the other.
  const collapsed = findings.filter((f) => (f.collapsed ?? []).length > 0);
  if (collapsed.length > 0) {
    notEvaluable.push({
      check: 'same-tool merge',
      reason:
        `${collapsed.length} finding(s) absorbed another rule from the same tool at the same location: `
        + `${[...new Set(collapsed.flatMap((f) => f.collapsed))].join(', ')}`,
      unblock: 'give the adapter\'s rules a `subtype` so they keep separate identities',
    });
  }

  const uncoveredModules = selectedModules.filter((m) => !coveredModules.includes(m));
  for (const m of uncoveredModules) {
    notEvaluable.push({
      check: `module ${m}`,
      reason: 'no scanner in this run contributes to it',
      unblock: tier === maxTier
        ? 'add a scanner that covers this module'
        : `run at a higher tier (ceiling is ${maxTier})`,
    });
  }

  return { covered, not_evaluable: notEvaluable };
}

/** A PASS whose ledger is non-empty must say so on its first line. */
export function ledgerIsEmpty(ledger) {
  return (ledger?.not_evaluable ?? []).length === 0;
}
