// OWASP ZAP — baseline (passive) and full (active) scan via the packaged scripts.
// CONTRACTS §3.
//
// ZAP's own docs note that active scanning cannot find logic flaws such as broken
// access control. That is why M5 and M11 stay manual whatever ZAP reports.
import { spawnSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const RISK = { 3: 'High', 2: 'Medium', 1: 'Low', 0: 'Info' };
/** ZAP's confidence is 0..4 with 0 = False Positive and 4 = Confirmed. */
const CONFIDENCE = { 0: 'false_positive', 1: 'Tentative', 2: 'Tentative', 3: 'Firm', 4: 'Certain' };

/**
 * Two installs, and only one of them can do a passive scan.
 *
 * `zap-baseline.py` and `zap-full-scan.py` are wrappers that ship with the
 * container and the Linux packages. A desktop install — what `winget install
 * ZAP.ZAP` gives you — has `zap.bat` and no wrappers at all, and `zap.bat` has
 * no passive-only mode: `-quickurl` spiders and then attacks.
 *
 * Before this the adapter asked "is any zap command present", found `zap.bat`,
 * reported installed, and then every run died on `zap-baseline.py ENOENT`. The
 * question `detect` answers is not the question `preflight` answers.
 */
const PACKAGED = { T1: 'zap-baseline.py', T3: 'zap-full-scan.py' };
const DESKTOP = ['zap.bat', 'zap.sh'];

let memo = null;

export function resetZap() {
  memo = null;
}

export function resolveZap({ spawn = spawnSync } = {}) {
  if (memo) return memo;
  const works = (cmd) => {
    const r = spawn(cmd, ['-h'], { encoding: 'utf8', shell: false });
    return !r.error;
  };
  if (works(PACKAGED.T1)) {
    memo = { kind: 'packaged', command: PACKAGED.T1 };
    return memo;
  }
  const desktop = DESKTOP.find(works);
  memo = desktop ? { kind: 'desktop', command: desktop } : { kind: 'none', command: null };
  return memo;
}

export default {
  name: 'zap',
  tool: 'zap',
  // zap-baseline is passive (T1); zap-full-scan is active (T3).
  tiers: ['T1', 'T3'],
  modules: ['M3', 'M4', 'M6', 'M9', 'M13'],

  async detect() {
    const r = resolveZap();
    if (r.kind === 'none') {
      return {
        ok: false,
        version: null,
        install: 'https://www.zaproxy.org/download/ (or run the ghcr.io/zaproxy/zaproxy image)',
      };
    }
    return { ok: true, version: r.command, runner: r.kind, install: null };
  },

  /**
   * A desktop install has no passive mode. Refusing is the honest answer: the
   * alternative is to run `-quickurl` for a T1 request, which attacks a target
   * the operator authorized us only to read.
   */
  async preflight({ tier = 'T1' } = {}) {
    const r = resolveZap();
    if (r.kind === 'desktop' && tier !== 'T3') {
      return {
        ok: false,
        reason:
          `this is a desktop ZAP install (${r.command}), which has no passive baseline — `
          + '`-quickurl` spiders and then actively attacks, which is T3',
        unblock:
          'run the ghcr.io/zaproxy/zaproxy container, which ships zap-baseline.py, or raise the '
          + 'tier to T3 in scope.json if an active scan is what was authorized',
      };
    }
    return { ok: true };
  },

  scanCommand({ runDir, target, options = {}, tier = 'T1' }) {
    const report = join(runDir, 'zap.json');
    const r = resolveZap();

    if (r.kind === 'desktop') {
      // Headless, one URL, JSON out. `-quickurl` is an active scan whichever
      // tier asked for it, which is why preflight only lets T3 reach here.
      return {
        cmd: r.command,
        args: ['-cmd', '-quickurl', target.root, '-quickout', report, '-quickprogress'],
        env: {},
        timeout_s: options.timeout_s ?? 3600,
      };
    }

    const script = tier === 'T1' ? PACKAGED.T1 : PACKAGED.T3;
    const args = ['-t', target.root, '-J', report, '-I'];
    if (options.minutes) args.push('-m', String(options.minutes));
    if (tier === 'T1') args.push('-l', 'PASS'); // report everything, we do the filtering
    return { cmd: script, args, env: {}, timeout_s: options.timeout_s ?? (tier === 'T1' ? 600 : 3600) };
  },

  async parse({ runDir, exitCode, stderr }) {
    const report = join(runDir, 'zap.json');
    if (!existsSync(report)) {
      return {
        findings: [], coverage: [],
        errors: [{ kind: 'no-report', detail: `zap wrote no report (exit ${exitCode}): ${String(stderr).slice(0, 300)}` }],
      };
    }

    let raw;
    try {
      raw = JSON.parse(readFileSync(report, 'utf8'));
    } catch (e) {
      return { findings: [], coverage: [], errors: [{ kind: 'parse-error', detail: e.message }] };
    }

    const findings = [];
    let siteCount = 0;

    for (const site of raw.site ?? []) {
      siteCount += 1;
      for (const alert of site.alerts ?? []) {
        const confidence = CONFIDENCE[Number(alert.confidence)] ?? 'Tentative';
        // ZAP marks its own false positives; do not import them as findings.
        if (confidence === 'false_positive') continue;

        const first = (alert.instances ?? [])[0] ?? {};
        findings.push({
          rule_id: `zap:${alert.pluginid ?? alert.alertRef ?? alert.alert}`,
          rule: {
            name: alert.alert ?? alert.name,
            background: stripHtml(alert.desc),
            remediation: stripHtml(alert.solution),
            classification: {
              cwe: alert.cweid && alert.cweid !== '-1' ? [`CWE-${alert.cweid}`] : [],
              owasp: [], wstg: [], asvs: [], api: [],
              wasc: alert.wascid && alert.wascid !== '-1' ? [`WASC-${alert.wascid}`] : [],
            },
            typical_severity: RISK[Number(alert.riskcode)] ?? 'Info',
            references: stripHtml(alert.reference).split('\n').filter(Boolean).slice(0, 5),
          },
          location: { file: first.uri ?? site['@name'] ?? 'unknown', symbol: null, line: null },
          insertion_point: first.param ? { kind: 'parameter', name: first.param } : null,
          severity: RISK[Number(alert.riskcode)] ?? 'Info',
          impact: null, likelihood: null,
          // ZAP observed a live response; its own confidence is carried through.
          detection_method: confidence === 'Certain' ? 'reproduced' : 'pattern',
          reported_severity: alert.riskdesc ?? null,
          source_rule: alert.pluginid,
          detail: stripHtml(alert.otherinfo) || stripHtml(alert.desc).slice(0, 200),
          evidence: first.evidence ? String(first.evidence).slice(0, 200) : '',
          modules: ['M3', 'M9'],
          tool: 'zap',
          zap_confidence: confidence,
        });
      }
    }

    return {
      findings,
      coverage: siteCount > 0
        ? [{ kind: 'endpoints', detail: `zap scanned ${siteCount} site(s)`, count: siteCount }]
        : [],
      errors: [],
    };
  },
};

function stripHtml(s) {
  return String(s ?? '').replace(/<[^>]+>/g, '').replace(/\s+\n/g, '\n').trim();
}
