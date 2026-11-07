// Stable identity for a finding, so a re-run does not re-report what an edit moved.
// CONTRACTS §7.
import { createHash } from 'node:crypto';

import { issueType } from './taxonomy.mjs';

const NUL = '\u0000';

/** Repo-relative, forward slashes, no leading ./ */
export function normalizePath(file) {
  if (typeof file !== 'string' || file === '') return '';
  return file
    .replace(/\\/g, '/')
    .replace(/^\.\//, '')
    .replace(/^\/+/, '');
}

/**
 * `file#symbol` when the enclosing symbol resolves, else `file:line`, else `file`.
 * Preferring the symbol is what lets the fingerprint survive edits above it.
 */
export function normalizedLocation(location = {}) {
  const file = normalizePath(location.file);
  if (!file) return '';
  if (location.symbol) return `${file}#${location.symbol}`;
  if (Number.isInteger(location.line)) return `${file}:${location.line}`;
  return file;
}

/** The parameter, header, cookie or field carrying the input — '' when there is none. */
export function normalizedInsertionPoint(ip) {
  if (!ip) return '';
  if (typeof ip === 'string') return ip;
  const kind = ip.kind ?? '';
  const name = ip.name ?? '';
  return kind || name ? `${kind}:${name}` : '';
}

/**
 * The distinction the family cannot make.
 *
 * A CWE family is deliberately broad, and at one location that is usually
 * right. It is wrong when one response is missing two different headers:
 * Referrer-Policy and X-Powered-By are both CWE-200, both at `/`, and the
 * family said they were one defect — so the dynamic benchmark reported three
 * header checks for seven planted, with nothing anywhere saying four had been
 * folded away. Two different fixes are two defects.
 *
 * An adapter sets this when a tool reports several genuinely distinct defects
 * of one family at one place. It must name the defect, not the rule: ZAP's
 * missing Referrer-Policy and ours still merge, because both say
 * `referrer-policy`.
 */
export function normalizedSubtype(subtype) {
  if (typeof subtype !== 'string') return '';
  return subtype.trim().toLowerCase();
}

/**
 * Identity is the issue TYPE, not the scanner's rule id.
 *
 * Keying on rule_id meant two scanners describing one defect produced two
 * fingerprints, so they never merged and corroboration never once fired. The
 * type comes from the CWE family (controller/taxonomy.mjs) and falls back to
 * the rule id only when a scanner supplied no CWE at all.
 */
export function fingerprint(finding = {}) {
  const { location, insertion_point } = finding;
  const parts = [
    issueType(finding).type,
    normalizedLocation(location),
    normalizedInsertionPoint(insertion_point),
  ];
  // Appended, never inserted: a finding without a subtype keeps the fingerprint
  // it had before this existed, so an existing baseline still recognises it.
  const subtype = normalizedSubtype(finding.subtype);
  if (subtype) parts.push(`subtype=${subtype}`);
  return createHash('sha256').update(parts.join(NUL)).digest('hex');
}

/** Short form for reports; collisions are still resolved on the full hash. */
export function shortFingerprint(fp) {
  return typeof fp === 'string' ? fp.slice(0, 12) : '';
}
