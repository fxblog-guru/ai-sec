// A step whose job is to FAIL a finding. docs/verification.md.
//
// Everything before this treats a reported defect as real until somebody types
// `judge <fp> false_positive` — an opt-out that costs effort exactly when the
// finding is wrong, and records nothing when it is right. So a confirmed finding
// and one nobody has looked at are indistinguishable in the report, the baseline
// and CI.
//
// The judgement belongs to the reader. The rules around it are here, in code, so
// they can be mutation-tested — which is the whole reason this project is a
// controller and not a prompt.
import { confidenceFor } from './merge.mjs';

export const VERDICTS = ['confirmed', 'needs_validation', 'rejected'];

/**
 * Only these establish that a boundary is really crossed.
 *
 * The same rule that governs `confidence: Certain`, one layer up: a pattern match
 * cannot confirm anything, however sure the reader feels. `source-trace` is
 * deliberately absent — reading the code is how the candidate was produced.
 */
export const CONFIRMING_METHODS = ['reproduced', 'out-of-band'];

export const VERIFICATION_METHODS = [...CONFIRMING_METHODS, 'source-trace', 'manual-review'];

const MIN_REASON = 12;

/**
 * May this verification be recorded?
 *
 * Returns `{ ok }` or `{ ok: false, error }`. Every refusal names what would fix
 * it: a gate that says no without saying why gets worked around.
 */
export function checkVerification(finding = {}, v = {}) {
  const fail = (error) => ({ ok: false, error });

  if (!VERDICTS.includes(v.verdict)) {
    return fail(`verdict must be one of ${VERDICTS.join(', ')}`);
  }
  if (!v.verifier || String(v.verifier).trim().length === 0) {
    return fail('a verification names who made it; an anonymous one cannot be independent');
  }

  // Independence is the mechanism, not a formality. A scanner agreeing with
  // itself is not corroboration (CONTRACTS §7), and a reader re-reading their own
  // reasoning is not verification.
  const tools = (finding.tools ?? []).map((t) => String(t).toLowerCase());
  if (tools.length === 0) {
    // Not knowing who reported it is not the same as knowing it was someone
    // else. Letting this through is how `builtin` confirmed its own finding:
    // the rule read an absent field and found no conflict.
    return fail(
      'this finding does not record which tool reported it, so independence cannot be '
      + 'checked. Re-run and `sec baseline promote` to record it',
    );
  }
  if (tools.includes(String(v.verifier).toLowerCase())) {
    return fail(
      `${v.verifier} reported this finding, so it cannot verify it — ` +
      'the one who checks is never the one who found it',
    );
  }

  if (!v.reason || String(v.reason).trim().length < MIN_REASON) {
    return fail(`a verdict carries a reason of at least ${MIN_REASON} characters`);
  }
  if (v.method && !VERIFICATION_METHODS.includes(v.method)) {
    return fail(`method must be one of ${VERIFICATION_METHODS.join(', ')}`);
  }
  if (v.verdict === 'confirmed' && !CONFIRMING_METHODS.includes(v.method)) {
    return fail(
      'confirmed needs evidence that can establish it: ' +
      `${CONFIRMING_METHODS.join(' or ')}. Reading the code is how the candidate was produced, ` +
      'so it cannot also be what confirms it — record needs_validation instead',
    );
  }
  return { ok: true };
}

/**
 * Attach a verdict to a finding.
 *
 * `needs_validation` drops the severity. A severity is a claim about demonstrated
 * impact, and a blocked hypothesis has demonstrated nothing — this project has
 * already shipped `Critical / Tentative` twice, once for a dropdown label and
 * once for a PKCE challenge. The potential severity stays, so the finding can
 * still be ordered.
 */
export function applyVerification(finding, v, now = new Date()) {
  const verification = {
    verdict: v.verdict,
    verifier: v.verifier,
    method: v.method ?? 'manual-review',
    reason: v.reason,
    at: now.toISOString(),
  };

  if (v.verdict === 'rejected') {
    return {
      ...finding,
      verification,
      status: 'false_positive',
      suppressed_reason: v.reason,
      severity: null,
      potential_severity: finding.severity,
    };
  }

  if (v.verdict === 'needs_validation') {
    return {
      ...finding,
      verification,
      status: 'open',
      severity: null,
      potential_severity: finding.severity,
      blocked_on: v.blocked_on ?? v.reason,
    };
  }

  // confirmed: reproduction is what Certain has always meant.
  return {
    ...finding,
    verification,
    status: 'open',
    confidence: confidenceFor(verification.method),
  };
}

/** Findings nobody has tried to break. Never a pass on its own, like the ledger. */
export function unverified(findings = []) {
  return findings.filter((f) => f.status === 'open' && !f.verification);
}

export function verificationSummary(findings = []) {
  const out = { confirmed: 0, needs_validation: 0, rejected: 0, unverified: 0 };
  for (const f of findings) {
    const v = f.verification?.verdict;
    if (v && v in out) out[v] += 1;
    else if (f.status === 'open') out.unverified += 1;
  }
  return out;
}
