// semgrep — SAST with dataflow. CONTRACTS §3.
// Semgrep carries impact, likelihood and confidence as separate metadata fields;
// we use them rather than its severity enum.
import { spawnSync } from 'node:child_process';

const SEVERITY = { CRITICAL: 'Critical', ERROR: 'High', HIGH: 'High', WARNING: 'Medium', MEDIUM: 'Medium', INFO: 'Low', LOW: 'Low' };
const LEVEL = { HIGH: 'HIGH', MEDIUM: 'MEDIUM', LOW: 'LOW' };

/** impact x likelihood, per references/scoring.md */
function severityFrom(impact, likelihood, fallback) {
  const table = {
    'HIGH|HIGH': 'Critical', 'HIGH|MEDIUM': 'High', 'HIGH|LOW': 'Medium',
    'MEDIUM|HIGH': 'High', 'MEDIUM|MEDIUM': 'Medium', 'MEDIUM|LOW': 'Low',
    'LOW|HIGH': 'Medium', 'LOW|MEDIUM': 'Low', 'LOW|LOW': 'Low',
  };
  return table[`${impact}|${likelihood}`] ?? fallback;
}

const first = (v) => (Array.isArray(v) ? v[0] : v);

export default {
  name: 'semgrep',
  tool: 'semgrep',
  tiers: ['T0'],
  modules: ['M1', 'M4', 'M5', 'M6', 'M9', 'M12'],

  async detect() {
    const r = spawnSync('semgrep', ['--version'], { encoding: 'utf8', shell: false });
    if (r.error || r.status !== 0) {
      return { ok: false, version: null, install: 'pip install semgrep  (or brew install semgrep)' };
    }
    return { ok: true, version: (r.stdout || '').trim(), install: null };
  },

  scanCommand({ target, options = {}, depth }) {
    const config = options.config ?? (depth === 'thorough' ? 'p/security-audit' : 'p/default');
    return {
      cmd: 'semgrep',
      args: ['--config', config, '--json', '--quiet', '--no-git-ignore', '--timeout', '30', target.root],
      env: { SEMGREP_SEND_METRICS: 'off' },
      timeout_s: options.timeout_s ?? (depth === 'thorough' ? 900 : 300),
    };
  },

  async parse({ stdout, stderr, exitCode }) {
    let raw;
    try {
      raw = JSON.parse(stdout || '{}');
    } catch (e) {
      return {
        findings: [],
        coverage: [],
        errors: [{ kind: 'parse-error', detail: `${e.message}; stderr: ${String(stderr).slice(0, 300)}` }],
      };
    }

    const errors = (raw.errors ?? []).map((e) => ({
      kind: 'scanner-error',
      detail: e.long_msg ?? e.message ?? JSON.stringify(e).slice(0, 200),
    }));
    if (exitCode !== 0 && errors.length === 0) {
      errors.push({ kind: 'scanner-error', detail: `semgrep exited ${exitCode}` });
    }

    const findings = (raw.results ?? []).map((r) => {
      const md = r.extra?.metadata ?? {};
      const impact = LEVEL[md.impact] ?? null;
      const likelihood = LEVEL[md.likelihood] ?? null;
      const reported = r.extra?.severity ?? null;
      // `audit` rules are, by Semgrep's own definition, for human review.
      const isAudit = md.subcategory?.includes?.('audit');

      return {
        rule_id: r.check_id,
        rule: {
          name: md.shortDescription ?? String(r.check_id).split('.').pop(),
          background: r.extra?.message ?? '',
          remediation: md.fix ?? r.extra?.fix ?? 'See the rule reference.',
          classification: {
            cwe: [].concat(md.cwe ?? []).map((c) => String(c).match(/CWE-\d+/)?.[0] ?? String(c)),
            owasp: [].concat(md.owasp ?? []),
            wstg: [], asvs: [], api: [],
          },
          typical_severity: SEVERITY[reported] ?? 'Medium',
          references: [].concat(md.references ?? []),
        },
        location: {
          file: String(r.path ?? '').replace(/\\/g, '/'),
          symbol: null,
          line: r.start?.line ?? null,
        },
        insertion_point: null,
        severity: impact && likelihood
          ? severityFrom(impact, likelihood, SEVERITY[reported] ?? 'Medium')
          : (SEVERITY[reported] ?? 'Medium'),
        impact,
        likelihood,
        // A taint-mode result carries a dataflow trace; everything else is a pattern.
        detection_method: r.extra?.dataflow_trace || isAudit === false && md.technology ? 'dataflow' : 'pattern',
        reported_severity: reported,
        source_rule: r.check_id,
        detail: r.extra?.message ?? '',
        evidence: (r.extra?.lines ?? '').trim().slice(0, 200),
        modules: ['M1'],
        tool: 'semgrep',
      };
    });

    const paths = raw.paths ?? {};
    const coverage = [
      { kind: 'files', detail: 'scanned', count: (paths.scanned ?? []).length || null },
      { kind: 'rules', detail: 'semgrep ruleset', count: null },
    ];
    for (const s of paths.skipped ?? []) {
      errors.push({ kind: 'skipped-file', detail: `${s.path}: ${s.reason}` });
    }
    return { findings, coverage, errors };
  },
};
