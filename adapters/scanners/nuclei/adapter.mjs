// nuclei — template-based checks against a live target. CONTRACTS §3.
//
// nuclei's severity enum is 7-valued; we map it and keep the original in
// reported_severity. Its classification block carries CWE and CVSS, which we use.
//
// Two ways to run it: the binary on PATH, or the published container. The
// container exists because nuclei is a Go binary with no winget package, and
// "install it yourself" is how a scanner stays permanently uninstalled. The two
// paths are not equivalent and the adapter does not pretend they are — see
// `preflight`.
import { spawnSync } from 'node:child_process';

const SEVERITY = {
  critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low',
  info: 'Info', unknown: 'Info', undefined: 'Info',
};

/** Templates graded above this are not run below the matching tier. */
const TIER_SEVERITY = {
  T2: 'info,low',
  T3: 'info,low,medium,high,critical',
};

/**
 * Pinned, because `latest` changes what a baseline was taken against without
 * anything in the run saying so. Override with SEC_NUCLEI_IMAGE to move it.
 */
export const IMAGE = process.env.SEC_NUCLEI_IMAGE ?? 'projectdiscovery/nuclei:v3.11.1';

const VERSION_LABEL = '{{index .Config.Labels "org.opencontainers.image.version"}}';

/**
 * A container cannot reach the host's loopback interface: inside it, 127.0.0.1 is
 * the container. The usual workaround is to rewrite the target to
 * host.docker.internal, and that is exactly what this adapter will not do — the
 * host allowlist is checked against the name the user wrote, so rewriting it
 * sends traffic to a host nobody authorized. CONTRACTS §3.
 */
export const LOOPBACK = new Set(['127.0.0.1', 'localhost', '::1', '[::1]', '0.0.0.0']);

export function isLoopback(origin) {
  try {
    return LOOPBACK.has(new URL(origin).hostname.toLowerCase());
  } catch {
    return false;
  }
}

/**
 * How nuclei can be run here, decided once.
 *
 * Memoized because `detect` is called for every scanner on every `sec modules`,
 * and two process spawns per call is a visible pause. `resetRunner` exists for
 * the tests; nothing else should call it.
 */
let memo = null;

export function resetRunner() {
  memo = null;
}

export function resolveRunner({ spawn = spawnSync } = {}) {
  if (memo) return memo;

  const native = spawn('nuclei', ['-version'], { encoding: 'utf8', shell: false });
  if (!native.error && (native.status === 0 || /nuclei/i.test(`${native.stdout}${native.stderr}`))) {
    memo = {
      kind: 'native',
      version: `${native.stdout || native.stderr}`.trim().split('\n').pop(),
    };
    return memo;
  }

  // `image inspect` reads the local image store. It does not pull, and it does
  // not run anything: detection must not execute the thing it is detecting.
  const img = spawn('docker', ['image', 'inspect', IMAGE, '--format', VERSION_LABEL], {
    encoding: 'utf8', shell: false,
  });
  if (!img.error && img.status === 0) {
    // The image's own version label, not the tag we asked for: a tag is a name
    // someone can move, and `nuclei 3.11.1` is what the report should carry.
    const labelled = String(img.stdout ?? '').trim();
    memo = { kind: 'docker', version: `nuclei ${labelled || 'unknown'} (${IMAGE})` };
    return memo;
  }

  memo = { kind: 'none', version: null };
  return memo;
}

export default {
  name: 'nuclei',
  tool: 'nuclei',
  // T1 is impossible for nuclei: every template sends something.
  tiers: ['T2', 'T3'],
  modules: ['M3', 'M7', 'M9', 'M10'],

  async detect() {
    const r = resolveRunner();
    if (r.kind === 'none') {
      return {
        ok: false,
        version: null,
        install:
          'https://docs.projectdiscovery.io/tools/nuclei/install — or, without a package manager, '
          + `docker pull ${IMAGE}`,
      };
    }
    return { ok: true, version: r.version, runner: r.kind, install: null };
  },

  /**
   * Can this scanner run against THIS target?
   *
   * `detect` answers "is it installed", which is a different question, and
   * conflating them is how a scanner reports zero findings against a target it
   * could never have reached. A refusal here reaches the coverage ledger.
   */
  async preflight({ target }) {
    const r = resolveRunner();
    if (r.kind === 'docker' && isLoopback(target?.root ?? '')) {
      return {
        ok: false,
        reason:
          `nuclei is only available here as a container (${IMAGE}), and inside a container `
          + '127.0.0.1 is the container, not this machine',
        unblock:
          'install the nuclei binary on PATH, or point the scan at a host address the container can reach',
      };
    }
    return { ok: true };
  },

  scanCommand({ target, options = {}, tier = 'T2' }) {
    const args = [
      '-target', target.root,
      '-jsonl',
      '-silent',
      '-no-interactsh',           // out-of-band needs its own authorization conversation
      '-disable-update-check',
      '-severity', options.severity ?? TIER_SEVERITY[tier] ?? 'info,low',
      '-rate-limit', String(options.rate_limit ?? 20),
      '-timeout', '10',
    ];
    if (tier === 'T2') args.push('-exclude-tags', 'intrusive,dos,fuzz,sqli,rce,xss');
    else args.push('-exclude-tags', 'dos');
    if (options.templates) args.push('-templates', options.templates);

    const timeout_s = options.timeout_s ?? 900;
    if (resolveRunner().kind !== 'docker') {
      return { cmd: 'nuclei', args, env: {}, timeout_s };
    }

    // --rm so a cancelled run leaves nothing behind; no volume, because the only
    // thing we would mount is a template directory we did not write.
    return {
      cmd: 'docker',
      args: ['run', '--rm', '--network', options.docker_network ?? 'bridge', IMAGE, ...args],
      env: {},
      timeout_s,
    };
  },

  async parse({ stdout, stderr, exitCode }) {
    const errors = [];
    const findings = [];
    let lines = 0;

    for (const line of String(stdout).split('\n')) {
      if (!line.trim()) continue;
      lines += 1;
      let r;
      try {
        r = JSON.parse(line);
      } catch {
        errors.push({ kind: 'parse-error', detail: `unparseable JSONL line: ${line.slice(0, 120)}` });
        continue;
      }

      const info = r.info ?? {};
      const cls = info.classification ?? {};
      findings.push({
        rule_id: `nuclei:${r['template-id'] ?? 'unknown'}`,
        rule: {
          name: info.name ?? r['template-id'],
          background: info.description ?? '',
          remediation: info.remediation ?? 'See the template reference.',
          classification: {
            cwe: [].concat(cls['cwe-id'] ?? []).map((c) => String(c).toUpperCase()),
            owasp: [],
            wstg: [], asvs: [], api: [],
            cve: [].concat(cls['cve-id'] ?? []),
          },
          typical_severity: SEVERITY[info.severity] ?? 'Info',
          references: [].concat(info.reference ?? []),
        },
        location: { file: r['matched-at'] ?? r.host ?? r.url ?? 'unknown', symbol: null, line: null },
        insertion_point: null,
        severity: SEVERITY[info.severity] ?? 'Info',
        impact: null, likelihood: null,
        // nuclei matched a live response: it observed, it did not infer.
        detection_method: 'reproduced',
        reported_severity: info.severity ?? null,
        source_rule: r['template-id'],
        detail: `${info.name ?? r['template-id']} matched at ${r['matched-at'] ?? r.host}`,
        evidence: r['matcher-name'] ? `matcher: ${r['matcher-name']}` : (r['matched-line'] ?? ''),
        modules: ['M3', 'M7'],
        tool: 'nuclei',
        ...(cls['cvss-score'] ? { cvss: { version: '3.1', vector: cls['cvss-metrics'] ?? null, score: cls['cvss-score'] } } : {}),
      });
    }

    if (exitCode !== 0 && findings.length === 0) {
      errors.push({ kind: 'scanner-error', detail: `nuclei exited ${exitCode}: ${String(stderr).slice(0, 300)}` });
    }

    return {
      findings,
      // nuclei is silent about what it tried, so we can only claim what came back.
      coverage: lines > 0 || exitCode === 0
        ? [{ kind: 'endpoints', detail: 'nuclei templates executed', count: null }]
        : [],
      errors,
    };
  },
};
