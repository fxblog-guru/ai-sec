// gitleaks — secrets in the working tree and in history. CONTRACTS §3.
// gitleaks emits no severity of its own, so we assign one from what the secret unlocks.
import { spawnSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const RULE = {
  name: 'Hardcoded credential',
  background:
    'A credential in the repository is available to everyone with read access, to every fork, and in the history for as long as the repository exists. Removing it from the working tree does not revoke it.',
  remediation:
    'Rotate the credential first, then remove it from the code and from history. Move it to a secrets manager and keep it out of the repository.',
  classification: { cwe: ['CWE-798'], owasp: ['A02:2025'], wstg: ['WSTG-v42-CONF-02'], asvs: ['v5.0.0-14.2.1'], api: [] },
  typical_severity: 'Critical',
  references: ['https://cwe.mitre.org/data/definitions/798.html'],
};

/** What the secret unlocks decides the severity; gitleaks does not say. */
function severityFor(ruleId = '') {
  const id = ruleId.toLowerCase();
  if (/aws|gcp|azure|private-key|rsa|ssh|stripe-(?:live|secret)|database|postgres|mysql|mongo/.test(id)) {
    return { severity: 'Critical', impact: 'HIGH', likelihood: 'HIGH' };
  }
  if (/github|gitlab|slack|npm|docker|pypi|jwt|api-key|token/.test(id)) {
    return { severity: 'High', impact: 'HIGH', likelihood: 'MEDIUM' };
  }
  return { severity: 'Medium', impact: 'MEDIUM', likelihood: 'MEDIUM' };
}

export default {
  name: 'gitleaks',
  tool: 'gitleaks',
  tiers: ['T0'],
  modules: ['M3'],

  async detect() {
    const r = spawnSync('gitleaks', ['version'], { encoding: 'utf8', shell: false });
    if (r.error || r.status !== 0) {
      return { ok: false, version: null, install: 'https://github.com/gitleaks/gitleaks#installing' };
    }
    return { ok: true, version: (r.stdout || '').trim(), install: null };
  },

  scanCommand({ runDir, target, options = {} }) {
    const report = join(runDir, 'gitleaks.json');
    const args = [
      'detect',
      '--source', target.root,
      '--report-format', 'json',
      '--report-path', report,
      '--no-banner',
      '--exit-code', '0', // findings are not a tool failure; the controller decides
    ];
    if (options.history) args.push('--log-opts=--all');
    else args.push('--no-git');
    return { cmd: 'gitleaks', args, env: {}, timeout_s: options.timeout_s ?? 300 };
  },

  async parse({ runDir, exitCode, stderr }) {
    const report = join(runDir, 'gitleaks.json');
    const log = String(stderr ?? '');

    // gitleaks writes no report when it finds nothing. That is a clean scan, not a
    // failure — but only when it also tells us it scanned something. Otherwise we
    // have no coverage to claim and the run must not read as clean.
    if (!existsSync(report)) {
      const scanned = /scanned\s+~?([\d.]+)\s*bytes/i.exec(log);
      if (exitCode === 0 && /no leaks found/i.test(log) && scanned) {
        return {
          findings: [],
          coverage: [
            { kind: 'files', detail: `working tree, ${scanned[1]} bytes scanned`, count: null },
            { kind: 'rules', detail: 'gitleaks default ruleset', count: null },
          ],
          errors: [],
        };
      }
      return {
        findings: [],
        coverage: [],
        errors: [{ kind: 'no-report', detail: `gitleaks wrote no report (exit ${exitCode}): ${log.slice(0, 300)}` }],
      };
    }

    let raw;
    try {
      raw = JSON.parse(readFileSync(report, 'utf8') || '[]');
    } catch (e) {
      return { findings: [], coverage: [], errors: [{ kind: 'parse-error', detail: e.message }] };
    }

    const findings = (raw ?? []).map((f) => {
      const sev = severityFor(f.RuleID);
      return {
        rule_id: 'hardcoded-credential',
        rule: RULE,
        location: { file: String(f.File ?? '').replace(/\\/g, '/'), symbol: null, line: f.StartLine ?? null },
        insertion_point: null,
        ...sev,
        detection_method: 'pattern',
        reported_severity: null, // gitleaks has none
        source_rule: f.RuleID,
        // Never carry Secret or Match: the value itself must not travel.
        detail: `${f.Description ?? f.RuleID} (entropy ${typeof f.Entropy === 'number' ? f.Entropy.toFixed(2) : 'n/a'})`,
        evidence: `${f.File}:${f.StartLine}${f.Commit ? ` @ ${String(f.Commit).slice(0, 8)}` : ''}`,
        modules: ['M3'],
        tool: 'gitleaks',
        // gitleaks' own fingerprint is a good dedupe key across runs
        vendor_fingerprint: f.Fingerprint ?? null,
      };
    });

    return {
      findings,
      coverage: [
        { kind: 'rules', detail: 'gitleaks default ruleset', count: null },
        { kind: 'files', detail: 'working tree scanned for secrets', count: null },
      ],
      errors: [],
    };
  },
};
