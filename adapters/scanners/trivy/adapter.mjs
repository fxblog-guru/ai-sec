// trivy — dependency CVEs, misconfiguration and secrets. CONTRACTS §3.
import { spawnSync } from 'node:child_process';
import { readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';

/**
 * The files trivy can resolve a package VERSION from.
 *
 * `package.json` is deliberately absent. A range like `^4.17.0` is not a version,
 * trivy will not guess which one is installed, and a repository that ships only
 * `package.json` therefore produces zero dependency findings — which reads
 * exactly like a clean dependency tree. OWASP Juice Shop is that repository, and
 * M2 sat at `unmeasured` for two milestones because nothing said so out loud.
 */
export const DEPENDENCY_MANIFESTS = new Set([
  'package-lock.json', 'npm-shrinkwrap.json', '.package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock',
  'go.mod', 'Gopkg.lock',
  'requirements.txt', 'poetry.lock', 'Pipfile.lock', 'uv.lock',
  'Gemfile.lock', 'Cargo.lock', 'composer.lock', 'mix.lock', 'pubspec.lock',
  'packages.lock.json', 'pom.xml', 'gradle.lockfile', 'conan.lock', 'Podfile.lock',
]);

const SKIP_DIRS = new Set(['.git', 'dist', 'build', 'coverage', '.next', '.nuxt', 'out', '.sec']);

/**
 * Every dependency manifest under `root`, to a bounded depth.
 *
 * `node_modules` is not walked — it is large and trivy reads its
 * `.package-lock.json` rather than its tree — but that one file is looked for,
 * because an installed tree IS something trivy can resolve versions from.
 */
export function dependencyManifests(root, { maxDepth = 4, limit = 40 } = {}) {
  const found = [];
  const walk = (dir, rel, depth) => {
    if (found.length >= limit || depth > maxDepth) return;
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return; // unreadable directory: not a manifest, and not our error to report here
    }
    for (const e of entries) {
      if (found.length >= limit) return;
      const childRel = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) {
        if (e.name === 'node_modules') {
          if (existsSync(join(dir, e.name, '.package-lock.json'))) found.push(`${childRel}/.package-lock.json`);
          continue;
        }
        if (SKIP_DIRS.has(e.name)) continue;
        walk(join(dir, e.name), childRel, depth + 1);
      } else if (DEPENDENCY_MANIFESTS.has(e.name)) {
        found.push(childRel);
      }
    }
  };
  walk(root, '', 0);
  return found;
}


const SEVERITY = { CRITICAL: 'Critical', HIGH: 'High', MEDIUM: 'Medium', LOW: 'Low', UNKNOWN: 'Info' };

const CVE_RULE = (v) => ({
  name: `Vulnerable dependency: ${v.PkgName}`,
  background:
    `${v.Title || v.VulnerabilityID} affects ${v.PkgName} ${v.InstalledVersion}. ` +
    'A known vulnerability in a dependency is exploitable through whatever path of the application reaches it.',
  remediation: v.FixedVersion
    ? `Upgrade ${v.PkgName} to ${v.FixedVersion} or later.`
    : `No fixed version is published yet. Assess reachability and consider removing or replacing ${v.PkgName}.`,
  classification: {
    cwe: [].concat(v.CweIDs ?? []),
    owasp: ['A03:2025'],
    wstg: [], asvs: ['v5.0.0-15.2.1'], api: [],
    cve: [v.VulnerabilityID],
  },
  typical_severity: SEVERITY[v.Severity] ?? 'Medium',
  references: [v.PrimaryURL, ...(v.References ?? []).slice(0, 3)].filter(Boolean),
});

/**
 * Trivy's misconfiguration checks carry no CWE, so with nothing added here they
 * can never merge with another scanner: `misconfig:DS-0002` and our own
 * `container-runs-as-root` were two findings on one line of one Dockerfile.
 *
 * Only the checks where another scanner in this bundle covers the same ground are
 * worth mapping; the rest stay unmatched and are counted as such in the ledger.
 */
export const MISCONF_CWE = {
  'DS-0001': ['CWE-1104'], // ':latest' tag used
  'DS-0002': ['CWE-250'],  // image user should not be root
  'DS-0026': [],           // no HEALTHCHECK — nothing else here reports it
  'DS-0031': ['CWE-798'],  // secrets passed via build-args or env
  'DS-0015': ['CWE-250'],  // runs as root (alternative id)
};

const MISCONF_RULE = (m) => ({
  name: m.Title ?? m.ID,
  background: m.Description ?? '',
  remediation: m.Resolution ?? 'See the reference.',
  classification: {
    cwe: MISCONF_CWE[m.ID] ?? [],
    owasp: ['A02:2025'], wstg: [], asvs: ['v5.0.0-13.1.1'], api: [],
  },
  typical_severity: SEVERITY[m.Severity] ?? 'Medium',
  references: [m.PrimaryURL].filter(Boolean),
});

export default {
  name: 'trivy',
  tool: 'trivy',
  tiers: ['T0'],
  modules: ['M2', 'M3', 'M10'],

  async detect() {
    const r = spawnSync('trivy', ['--version'], { encoding: 'utf8', shell: false });
    if (r.error || r.status !== 0) {
      return { ok: false, version: null, install: 'https://trivy.dev/latest/getting-started/installation/' };
    }
    return { ok: true, version: (r.stdout || '').split('\n')[0].trim(), install: null };
  },

  /**
   * Can this scanner do here what it is credited with doing?
   *
   * `detect` answers "is it installed". A full refusal (`ok: false`) answers "can
   * it reach this target at all", and neither question fits trivy here: without a
   * lockfile its misconfiguration and secret checks still work, and only its
   * dependency check is blind. So this returns a PARTIAL refusal — the scanner
   * runs, and the capability that cannot run is named in the ledger and becomes a
   * blind spot on the module that was counting on it.
   *
   * The failure this prevents is the quietest one in the bundle: zero CVEs
   * reported because zero package versions were readable.
   */
  async preflight({ target }) {
    const root = target?.root;
    if (!root) return { ok: true };
    if (dependencyManifests(root, { limit: 1 }).length > 0) return { ok: true };
    return {
      ok: true,
      degraded: [{
        capability: 'dependency CVEs',
        modules: ['M2'],
        reason:
          'no lockfile or other resolvable manifest was found, so trivy has no package versions to '
          + 'match against its database — zero dependency findings here means nothing was read, not '
          + 'that nothing is vulnerable (package.json alone states ranges, not versions)',
        unblock:
          'commit a lockfile, or install first (`npm ci --ignore-scripts`) and re-scan, or scan the '
          + 'built image instead of the source tree',
      }],
    };
  },

  scanCommand({ target, options = {} }) {
    const scanners = options.scanners ?? 'vuln,misconfig,secret';
    return {
      cmd: 'trivy',
      args: ['fs', '--format', 'json', '--quiet', '--scanners', scanners, '--exit-code', '0', target.root],
      env: { TRIVY_DISABLE_VEX_NOTICE: 'true' },
      timeout_s: options.timeout_s ?? 600,
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

    const errors = [];
    if (exitCode !== 0) errors.push({ kind: 'scanner-error', detail: `trivy exited ${exitCode}` });

    const findings = [];
    const coverage = [];

    for (const res of raw.Results ?? []) {
      const file = String(res.Target ?? '').replace(/\\/g, '/');
      coverage.push({ kind: res.Class === 'config' ? 'files' : 'packages', detail: `${res.Class}: ${file}`, count: (res.Packages ?? []).length || null });

      for (const v of res.Vulnerabilities ?? []) {
        findings.push({
          rule_id: `cve:${v.VulnerabilityID}`,
          rule: CVE_RULE(v),
          location: { file, symbol: v.PkgName, line: null },
          insertion_point: null,
          severity: SEVERITY[v.Severity] ?? 'Medium',
          impact: null, likelihood: null,
          // The version is read from the manifest: a version match, not a pattern guess.
          detection_method: 'version-match',
          reported_severity: v.Severity,
          source_rule: v.VulnerabilityID,
          detail: `${v.PkgName} ${v.InstalledVersion}${v.FixedVersion ? ` (fixed in ${v.FixedVersion})` : ' (no fix published)'}`,
          evidence: v.PrimaryURL ?? v.VulnerabilityID,
          modules: ['M2'],
          tool: 'trivy',
          cvss: pickCvss(v),
        });
      }

      for (const m of res.Misconfigurations ?? []) {
        if (m.Status && m.Status !== 'FAIL') continue;
        findings.push({
          rule_id: `misconfig:${m.ID}`,
          rule: MISCONF_RULE(m),
          location: { file, symbol: m.CauseMetadata?.Resource ?? null, line: m.CauseMetadata?.StartLine ?? null },
          insertion_point: null,
          severity: SEVERITY[m.Severity] ?? 'Medium',
          impact: null, likelihood: null,
          detection_method: 'config',
          reported_severity: m.Severity,
          source_rule: m.ID,
          detail: m.Message ?? m.Title ?? m.ID,
          evidence: `${file}${m.CauseMetadata?.StartLine ? `:${m.CauseMetadata.StartLine}` : ''}`,
          modules: ['M10', 'M3'],
          tool: 'trivy',
        });
      }

      for (const s of res.Secrets ?? []) {
        findings.push({
          rule_id: 'hardcoded-credential',
          rule: {
            name: 'Hardcoded credential',
            background: 'A credential in the repository is available to everyone with read access and to every fork.',
            remediation: 'Rotate it, then move it to a secrets manager.',
            classification: { cwe: ['CWE-798'], owasp: ['A02:2025'], wstg: ['WSTG-v42-CONF-02'], asvs: ['v5.0.0-14.2.1'], api: [] },
            typical_severity: 'Critical',
            references: ['https://cwe.mitre.org/data/definitions/798.html'],
          },
          location: { file, symbol: null, line: s.StartLine ?? null },
          insertion_point: null,
          severity: SEVERITY[s.Severity] ?? 'High',
          impact: 'HIGH', likelihood: 'HIGH',
          detection_method: 'pattern',
          reported_severity: s.Severity,
          source_rule: s.RuleID,
          detail: s.Title ?? s.RuleID,
          evidence: `${file}:${s.StartLine}`, // never s.Match
          modules: ['M3'],
          tool: 'trivy',
        });
      }
    }

    return { findings, coverage, errors };
  },
};

function pickCvss(v) {
  const entry = Object.values(v.CVSS ?? {})[0];
  if (!entry) return null;
  if (entry.V3Vector) return { version: '3.1', vector: entry.V3Vector, score: entry.V3Score ?? null };
  if (entry.V2Vector) return { version: '2.0', vector: entry.V2Vector, score: entry.V2Score ?? null };
  return null;
}
