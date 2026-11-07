// The fake scanner: deterministic, installs nothing, and lets Quick Start and the
// test suite exercise the whole pipeline. The analogue of ai-perf's fake engine.
//
// Behaviour is driven by scanner_options so tests can reproduce every run state:
//   { mode: "findings" | "clean" | "nothing" | "fail" | "timeout", seed?: number }
import { fileURLToPath } from 'node:url';

const HERE = fileURLToPath(new URL('.', import.meta.url));

const CANNED = [
  {
    rule_id: 'sql-injection',
    rule: {
      name: 'SQL injection',
      background:
        'User-controlled input reaches a SQL query without parameterization, letting an attacker change the query.',
      remediation: 'Bind every user value as a parameter. Allowlist identifiers that cannot be bound.',
      classification: { cwe: ['CWE-89'], owasp: ['A05:2025'], wstg: ['WSTG-v42-INPV-05'], asvs: ['v5.0.0-1.2.5'], api: [] },
      typical_severity: 'High',
      references: ['https://cwe.mitre.org/data/definitions/89.html'],
    },
    location: { file: 'src/db/orders.js', symbol: 'getOrder', line: 142 },
    insertion_point: { kind: 'body-parameter', name: 'orderId' },
    severity: 'High',
    impact: 'HIGH',
    likelihood: 'MEDIUM',
    detection_method: 'dataflow',
    reported_severity: 'ERROR',
    detail: 'req.body.orderId flows into db.raw() with no sanitizer on the path.',
    evidence: 'db.raw(`SELECT * FROM orders WHERE id = ${orderId}`)',
    modules: ['M1', 'M6'],
  },
  {
    rule_id: 'hardcoded-credential',
    rule: {
      name: 'Hardcoded credential',
      background: 'A credential committed to the repository is available to everyone with read access, and to anyone who ever had it.',
      remediation: 'Move it to a secrets manager and rotate it. Treat the old value as compromised.',
      classification: { cwe: ['CWE-798'], owasp: ['A02:2025'], wstg: ['WSTG-v42-CONF-02'], asvs: ['v5.0.0-14.1.1'], api: [] },
      typical_severity: 'Critical',
      references: ['https://cwe.mitre.org/data/definitions/798.html'],
    },
    location: { file: 'config/settings.js', symbol: 'default', line: 14 },
    insertion_point: null,
    severity: 'Critical',
    impact: 'HIGH',
    likelihood: 'HIGH',
    detection_method: 'pattern',
    reported_severity: 'CRITICAL',
    detail: 'An AWS access key id is assigned in source.',
    // Deliberately a real-looking key: the redactor must catch it before anything is written.
    evidence: 'const AWS_KEY = "AKIAIOSFODNN7EXAMPLE"',
    modules: ['M3'],
  },
  {
    rule_id: 'missing-authorization',
    rule: {
      name: 'Missing authorization check',
      background: 'A route that changes state is reachable without an authorization check, so any caller can invoke it.',
      remediation: 'Enforce authorization in shared middleware, default-deny, rather than per route.',
      classification: { cwe: ['CWE-862'], owasp: ['A01:2025'], wstg: ['WSTG-v42-ATHZ-02'], asvs: ['v5.0.0-8.1.1'], api: ['API5:2023'] },
      typical_severity: 'High',
      references: ['https://cwe.mitre.org/data/definitions/862.html'],
    },
    location: { file: 'src/routes/admin.js', symbol: 'deleteUser', line: 61 },
    insertion_point: { kind: 'url-path', name: 'userId' },
    severity: 'High',
    impact: 'HIGH',
    likelihood: 'MEDIUM',
    detection_method: 'pattern',
    reported_severity: 'WARNING',
    detail: 'DELETE /admin/users/:userId is registered before the requireAdmin middleware.',
    evidence: "router.delete('/admin/users/:userId', deleteUser)",
    modules: ['M5'],
  },
  {
    rule_id: 'weak-randomness',
    rule: {
      name: 'Insufficiently random value',
      background: 'Math.random is not cryptographically secure; tokens built from it are predictable.',
      remediation: 'Use crypto.randomUUID() or crypto.randomBytes() for anything security-relevant.',
      classification: { cwe: ['CWE-330'], owasp: ['A04:2025'], wstg: ['WSTG-v42-CRYP-04'], asvs: ['v5.0.0-11.3.1'], api: [] },
      typical_severity: 'Medium',
      references: ['https://cwe.mitre.org/data/definitions/330.html'],
    },
    location: { file: 'src/auth/token.js', symbol: 'makeResetToken', line: 23 },
    insertion_point: null,
    severity: 'Medium',
    impact: 'MEDIUM',
    likelihood: 'MEDIUM',
    detection_method: 'pattern',
    reported_severity: 'WARNING',
    detail: 'Password reset tokens are built from Math.random().',
    evidence: 'return Math.random().toString(36).slice(2)',
    modules: ['M4', 'M12'],
  },
];

const COVERAGE = [
  { kind: 'languages', detail: 'javascript', count: 1 },
  { kind: 'files', detail: 'scanned', count: 24 },
  { kind: 'rules', detail: 'fake ruleset', count: CANNED.length },
];

export default {
  name: 'fake',
  tool: 'fake',
  // T2 as well, so the auto-stop path can be exercised without a live target
  tiers: ['T0', 'T2'],
  modules: ['M1', 'M3', 'M4', 'M5', 'M6', 'M12'],

  async detect() {
    return { ok: true, version: '1.0.0', install: null };
  },

  /**
   * `{ blind: "<capability>" }` makes this scanner run with one capability
   * unusable, which is the state a real adapter reports when the target has
   * nothing for one of its checks to read — trivy without a lockfile. It exists
   * so the path from an adapter's partial refusal to the ledger and the
   * scorecard is exercised by something installed on every machine.
   */
  async preflight({ options = {} } = {}) {
    if (!options.blind) return { ok: true };
    return {
      ok: true,
      degraded: [{
        capability: String(options.blind),
        modules: options.blind_modules ?? ['M3'],
        reason: 'the fake scanner was asked to report this capability as blind',
        unblock: 'drop the `blind` option',
      }],
    };
  },

  scanCommand({ options = {} }) {
    const mode = options.mode ?? 'findings';
    const script = `${HERE}run.mjs`;
    return {
      cmd: process.execPath,
      args: [script, mode],
      env: {},
      timeout_s: mode === 'timeout' ? 1 : 60,
    };
  },

  async parse({ stdout, exitCode }) {
    if (exitCode !== 0) {
      return {
        findings: [],
        coverage: [],
        errors: [{ kind: 'scanner-error', detail: `fake scanner exited ${exitCode}` }],
      };
    }
    let payload;
    try {
      payload = JSON.parse(stdout);
    } catch (e) {
      return {
        findings: [],
        coverage: [],
        errors: [{ kind: 'parse-error', detail: `could not parse output: ${e.message}` }],
      };
    }
    return {
      findings: (payload.findings ?? []).map((f) => ({ ...f, tool: 'fake' })),
      coverage: payload.coverage ?? [],
      errors: payload.errors ?? [],
      counters: payload.counters ?? null,
    };
  },

  // exported for the runner and the tests
  _canned: CANNED,
  _coverage: COVERAGE,
};
