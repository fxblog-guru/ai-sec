// Baseline and lessons — pillar P2. Without these, every run re-litigates the last one.
import { mkdirSync, writeFileSync, readFileSync, existsSync, appendFileSync } from 'node:fs';
import { join } from 'node:path';

import { redactDeep, redactText, containsSecret } from '../controller/redact.mjs';
import { checkVerification, applyVerification } from '../controller/verification.mjs';

export const baselineDir = (root, slug) => join(root, '.sec', slug, 'baseline');
export const baselineFile = (root, slug, env = 'local') => join(baselineDir(root, slug), `${env}.json`);
export const lessonsFile = (root, slug) => join(root, '.sec', slug, 'lessons.md');

export function readBaseline(root, slug, env = 'local') {
  const file = baselineFile(root, slug, env);
  if (!existsSync(file)) return null;
  try {
    return JSON.parse(readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
}

/**
 * Promote a run to the baseline. Only a `done` run may be promoted: a degraded or
 * not-evaluable run would bake its blind spots in as "known good".
 */
export function promote(root, slug, result, { force = false } = {}) {
  if (result.run_state !== 'done' && !force) {
    return { ok: false, reason: `run is ${result.run_state}; only a done run may become a baseline` };
  }
  const env = result.scope?.environment ?? 'local';
  const prev = readBaseline(root, slug, env);

  // Verdicts a human made are the point of a baseline: carry them forward.
  const judged = new Map(
    (prev?.findings ?? [])
      .filter((f) => f.status === 'false_positive' || f.status === 'accepted_risk')
      .map((f) => [f.fingerprint, f]),
  );

  const baseline = {
    schema: 'sec-baseline/v1',
    promoted_at: new Date().toISOString(),
    run_id: result.run_id,
    environment: env,
    tier: result.scope?.tier ?? 'T0',
    standards: result.standards,
    findings: (result.findings ?? []).map((f) => {
      const was = judged.get(f.fingerprint);
      return {
        fingerprint: f.fingerprint,
        rule_id: f.rule_id,
        location: f.location,
        severity: f.severity,
        confidence: f.confidence,
        status: was?.status ?? f.status,
        // Who reported it. Without this, `verify` cannot tell whether the person
        // or tool recording a verdict is the one that produced the finding, and
        // the independence rule passes vacuously on every entry — which is how
        // `builtin` was allowed to confirm its own SQL injection.
        tools: f.tools ?? [],
        ...(was?.verification ? { verification: was.verification } : {}),
        ...(was?.reason ? { reason: was.reason } : {}),
      };
    }),
    not_evaluable: result.not_evaluable ?? [],
  };

  mkdirSync(baselineDir(root, slug), { recursive: true });
  writeFileSync(baselineFile(root, slug, env), `${JSON.stringify(redactDeep(baseline), null, 2)}\n`, 'utf8');
  return { ok: true, file: baselineFile(root, slug, env), count: baseline.findings.length, carried: judged.size };
}

/**
 * Record a human verdict so the next run does not re-report it.
 *
 * Accepts a prefix, because the report prints a short fingerprint and asking someone
 * to go and find the full 64-character hash is a tax on doing the right thing.
 */
export function judge(root, slug, fingerprint, status, reason, env = 'local') {
  const baseline = readBaseline(root, slug, env);
  if (!baseline) return { ok: false, reason: 'no baseline to record against; promote a run first' };

  const fp = String(fingerprint ?? '').toLowerCase();
  if (fp.length < 8) return { ok: false, reason: 'give at least 8 characters of the fingerprint' };

  const hits = baseline.findings.filter((f) => f.fingerprint.toLowerCase().startsWith(fp));
  if (hits.length > 1) {
    return { ok: false, reason: `"${fp}" matches ${hits.length} findings; use more characters` };
  }
  const entry = hits[0];
  if (!entry) return { ok: false, reason: `no finding starting with ${fp} in the baseline` };
  if (!['open', 'fixed', 'false_positive', 'accepted_risk'].includes(status)) {
    return { ok: false, reason: `unknown status: ${status}` };
  }

  entry.status = status;
  entry.reason = redactText(reason ?? '');
  entry.judged_at = new Date().toISOString();
  writeFileSync(baselineFile(root, slug, env), `${JSON.stringify(baseline, null, 2)}\n`, 'utf8');
  return { ok: true, fingerprint: entry.fingerprint, status };
}

/**
 * Lessons are what changes a FUTURE run — durable facts about this codebase,
 * not a restatement of the findings. Never a secret, never a payload.
 */
export function appendLesson(root, slug, lines) {
  const raw = [].concat(lines).map((l) => String(l)).filter(Boolean);
  if (raw.length === 0) return { ok: false, reason: 'nothing to record' };

  // Check the original, not the redacted copy. A lesson that reaches for a
  // credential is a misunderstanding of what lessons are for, so refuse it
  // rather than quietly sanitizing it and keeping the rest.
  for (const l of raw) {
    if (containsSecret(l)) return { ok: false, reason: 'refusing to write a lesson that carries a credential' };
  }
  const text = raw.map((l) => redactText(l));

  const file = lessonsFile(root, slug);
  mkdirSync(join(root, '.sec', slug), { recursive: true });
  const header = `\n## ${new Date().toISOString().slice(0, 10)}\n`;
  const body = text.map((l) => `- ${l}\n`).join('');

  if (!existsSync(file)) {
    writeFileSync(file, `# Lessons — ${slug}\n\nWhat this codebase taught us. Read at the start of every run.\n${header}${body}`, 'utf8');
  } else {
    appendFileSync(file, `${header}${body}`, 'utf8');
  }
  return { ok: true, file, count: text.length };
}

export function readLessons(root, slug) {
  const file = lessonsFile(root, slug);
  return existsSync(file) ? readFileSync(file, 'utf8') : null;
}

/**
 * Record a verification against a finding in the baseline.
 *
 * Mirrors `judge`, deliberately: the fingerprint prefix handling, the refusal to
 * guess an ambiguous one, and the redaction before anything is written. What it
 * adds is the other direction — `judge` can only record a dismissal, so a
 * finding that was checked and held looked exactly like one nobody had opened.
 */
export function verify(root, slug, fingerprint, v, env = 'local') {
  const baseline = readBaseline(root, slug, env);
  if (!baseline) return { ok: false, reason: 'no baseline to record against; promote a run first' };

  const fp = String(fingerprint ?? '').toLowerCase();
  if (fp.length < 8) return { ok: false, reason: 'give at least 8 characters of the fingerprint' };

  const hits = baseline.findings.filter((f) => f.fingerprint.toLowerCase().startsWith(fp));
  if (hits.length > 1) {
    return { ok: false, reason: `"${fp}" matches ${hits.length} findings; use more characters` };
  }
  const entry = hits[0];
  if (!entry) return { ok: false, reason: `no finding starting with ${fp} in the baseline` };

  const allowed = checkVerification(entry, v);
  if (!allowed.ok) return { ok: false, reason: allowed.error };

  // Redact before storing, and check the ORIGINAL for secrets first — the same
  // order lessons.mjs needed, because redacting first makes the check pass.
  const safe = { ...v, reason: redactText(v.reason ?? '') };
  const verified = applyVerification(entry, safe);
  Object.assign(entry, {
    verification: verified.verification,
    status: verified.status,
    severity: verified.severity,
    potential_severity: verified.potential_severity,
    confidence: verified.confidence ?? entry.confidence,
  });

  writeFileSync(baselineFile(root, slug, env), `${JSON.stringify(baseline, null, 2)}\n`, 'utf8');
  return { ok: true, fingerprint: entry.fingerprint, verdict: v.verdict };
}
