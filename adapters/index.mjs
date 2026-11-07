// The adapter registry. Adding a scanner is a row here plus a folder —
// no skill, no flow and no controller change. That is pillar P5.
import builtin from './scanners/builtin/adapter.mjs';
import fake from './scanners/fake/adapter.mjs';
import gitleaks from './scanners/gitleaks/adapter.mjs';
import nuclei from './scanners/nuclei/adapter.mjs';
import probe from './scanners/probe/adapter.mjs';
import semgrep from './scanners/semgrep/adapter.mjs';
import trivy from './scanners/trivy/adapter.mjs';
import zap from './scanners/zap/adapter.mjs';
import repo from './targets/repo.mjs';
import url from './targets/url.mjs';

export const SCANNERS = {
  builtin,
  gitleaks,
  semgrep,
  trivy,
  probe,
  nuclei,
  zap,
  fake,
};

/** `fake` is for tests and the quickstart; it is never selected implicitly. */
export const EXPLICIT_ONLY = new Set(['fake']);

export const TARGETS = {
  repo,
  url,
};

export const ENRICHERS = {};

export function scannersForTier(tier, names = null) {
  return Object.values(SCANNERS).filter((s) => {
    if (!s.tiers.includes(tier)) return false;
    if (names !== null) return names.includes(s.name);
    return !EXPLICIT_ONLY.has(s.name);
  });
}

/** Only scanners that are actually installed can contribute coverage. */
export async function availableScanners(scanners) {
  const out = [];
  for (const s of scanners) {
    let detected;
    try {
      detected = await s.detect();
    } catch (e) {
      detected = { ok: false, version: null, install: `detect() threw: ${e.message}` };
    }
    out.push({ scanner: s, detected });
  }
  return out;
}

export function modulesCoveredBy(scanners) {
  return [...new Set(scanners.flatMap((s) => s.modules ?? []))];
}
