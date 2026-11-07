// PASS / WARN / FAIL / NOT_EVALUABLE. CONTRACTS §9.
//
// The rule that matters: a run that could not look is not a run that found nothing.
import { severityRank, confidenceRank } from '../controller/merge.mjs';
import { isHardening } from '../controller/taxonomy.mjs';
import { isApplicationCode } from '../controller/coderole.mjs';
import { unverified, verificationSummary } from '../controller/verification.mjs';
import { EXIT_CODES } from '../controller/state.mjs';

export const OUTCOMES = ['PASS', 'WARN', 'FAIL', 'NOT_EVALUABLE'];

/** The CI bar, settled at M0 as decision D4. */
export const BAR = { severity: 'High', confidence: 'Firm' };

export const atOrAbove = (f, bar = BAR) =>
  severityRank(f.severity) >= severityRank(bar.severity) &&
  confidenceRank(f.confidence) >= confidenceRank(bar.confidence);

export function verdict(result, { baseline = null, bootstrap = false, bar = BAR } = {}) {
  const notes = [];
  const allOpen = (result.findings ?? []).filter((f) => f.status === 'open');
  const ledger = result.not_evaluable ?? [];

  // A missing second layer, while the first one holds, is not a way in. Failing a
  // build on an absent `Referrer-Policy` is how a security gate gets switched off,
  // and then the SQL injection goes through too. Hardening notes are reported in
  // full and judged separately.
  // A credential in a test fixture and a credential in a login handler are not
  // the same claim about the running system. Scanning Juice Shop produced 188
  // test-suite findings against 47 application ones, and a bar that counted all
  // of them would be failing builds on fixtures.
  const outside = allOpen.filter((f) => !isApplicationCode(f));
  const open = allOpen.filter((f) => !isHardening(f) && isApplicationCode(f));
  const hardening = allOpen.filter((f) => isHardening(f) && isApplicationCode(f));

  // --- NOT_EVALUABLE first: it outranks anything the findings say.
  if (result.run_state === 'not_evaluable') {
    return done('NOT_EVALUABLE', 'the run could not evaluate the target', {
      notes: [...notes, ...ledger.slice(0, 5).map((n) => `${n.check}: ${n.reason}`)],
    });
  }
  if (result.run_state === 'aborted') {
    return done('NOT_EVALUABLE', 'the run was aborted before it completed', { notes });
  }
  if (!baseline && !bootstrap) {
    return done('NOT_EVALUABLE', 'no baseline to compare against; re-run with --bootstrap to accept this run as the first', { notes });
  }
  if (result.run_state === 'degraded') {
    notes.push('the run is degraded: at least one scanner failed, timed out or examined nothing');
  }

  // Nobody has tried to break these. The coverage ledger's rule, applied to
  // findings instead of checks. It belongs here rather than beside the PASS,
  // where it first sat: a FAIL carrying forty-four findings that nobody has
  // examined is exactly the run where it needs saying.
  const unchecked = unverified(allOpen);
  if (unchecked.length > 0) {
    notes.push(
      `${unchecked.length} of ${allOpen.length} finding(s) have not been verified by anyone; `
      + 'sec verify records a verdict, and the verifier may not be the tool that found it',
    );
  }

  // --- the bar
  const overBar = open.filter((f) => atOrAbove(f, bar));
  const newOverBar = overBar.filter((f) => f.baseline_state === 'new');

  if (newOverBar.length > 0) {
    return done('FAIL', `${newOverBar.length} new finding(s) at or above ${bar.severity}/${bar.confidence}`, {
      notes, findings: newOverBar,
    });
  }
  if (overBar.length > 0) {
    return done('FAIL', `${overBar.length} finding(s) at or above ${bar.severity}/${bar.confidence}`, {
      notes, findings: overBar,
    });
  }

  // --- below the bar: WARN rather than PASS when something real is still open
  const warnable = open.filter(
    (f) => severityRank(f.severity) >= severityRank('Medium') ||
      (severityRank(f.severity) >= severityRank('High') && f.confidence === 'Tentative'),
  );
  if (warnable.length > 0) {
    return done('WARN', `${warnable.length} finding(s) below the ${bar.severity}/${bar.confidence} bar`, {
      notes, findings: warnable,
    });
  }

  // --- PASS, qualified by the ledger
  if (outside.length > 0) {
    notes.push(
      `${outside.length} finding(s) are in test, fixture, example, generated or vendored code: `
      + 'reported, and not counted against the bar',
    );
  }
  if (hardening.length > 0) {
    notes.push(`${hardening.length} hardening note(s): a layer is missing while another still holds`);
  }
  if (ledger.length > 0) {
    notes.unshift(`this PASS is qualified: ${ledger.length} check(s) could not be evaluated`);
  }
  return done('PASS', ledger.length > 0
    ? 'nothing found above the bar, but the coverage ledger is not empty'
    : 'nothing found above the bar, and every selected check was evaluated', { notes });

  function done(outcome, summary, extra = {}) {
    const suppressed = (result.findings ?? []).filter((f) => f.status === 'false_positive');
    return {
      outcome,
      summary,
      exit_code: outcome === 'FAIL' ? 1 : outcome === 'NOT_EVALUABLE' ? EXIT_CODES.not_evaluable : 0,
      bar,
      run_state: result.run_state,
      standards: result.standards,
      coverage_gaps: ledger.length,
      verification: verificationSummary(allOpen),
      hardening: hardening.map((f) => ({
        fingerprint: f.fingerprint, rule_id: f.rule_id, severity: f.severity,
        confidence: f.confidence, location: f.location,
      })),
      suppressed: suppressed.map((f) => ({ fingerprint: f.fingerprint, rule_id: f.rule_id, reason: f.suppressed_reason })),
      notes: extra.notes ?? notes,
      findings: (extra.findings ?? []).map((f) => ({
        fingerprint: f.fingerprint, rule_id: f.rule_id, severity: f.severity,
        confidence: f.confidence, location: f.location, baseline_state: f.baseline_state,
        ...(f.occurrences ? { occurrences: f.occurrences } : {}),
      })),
    };
  }
}

export function formatVerdict(v) {
  const lines = [`VERDICT: ${v.outcome} — ${v.summary}`];
  if (v.findings.length) {
    lines.push('');
    for (const f of v.findings.slice(0, 20)) {
      const where = f.location?.file ? `${f.location.file}${f.location.line ? `:${f.location.line}` : ''}` : '';
      const times = f.occurrences?.length > 1 ? ` ×${f.occurrences.length}` : '';
      lines.push(`  [${f.severity}/${f.confidence}] ${f.rule_id} ${where}${times} (${f.baseline_state})`);
    }
    if (v.findings.length > 20) lines.push(`  ... and ${v.findings.length - 20} more`);
  }
  if (v.hardening?.length) {
    lines.push('', `Hardening notes (${v.hardening.length}) — reported, not counted against the bar:`);
    for (const f of v.hardening.slice(0, 10)) {
      const where = f.location?.file ? `${f.location.file}${f.location.line ? `:${f.location.line}` : ''}` : '';
      lines.push(`  [${f.severity}] ${f.rule_id} ${where}`);
    }
  }
  if (v.suppressed.length) {
    lines.push('', `Suppressed (${v.suppressed.length}):`);
    for (const s of v.suppressed.slice(0, 10)) lines.push(`  ${s.rule_id} — ${s.reason}`);
  }
  if (v.notes.length) {
    lines.push('', 'Notes:');
    for (const n of v.notes) lines.push(`  - ${n}`);
  }
  lines.push('', `Scored against WSTG ${v.standards?.wstg} · ASVS ${v.standards?.asvs} · OWASP Top 10 ${v.standards?.owasp_top10} · CVSS ${v.standards?.cvss}`);
  return lines.join('\n');
}
