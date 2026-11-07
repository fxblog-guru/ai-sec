// The gates. These are code, not prompt, because a prompt cannot be mutation-tested.
// Every gate here has a case in tests/rules.test.mjs that fails when the gate is removed.
// CONTRACTS §1, §1a.

export const TIERS = ['T0', 'T1', 'T2', 'T3', 'T4'];
export const AUTH_BASES = ['own-repo', 'employer-authorized', 'staging', 'ctf', 'practice-app'];
export const AUTH_MAX_AGE_DAYS = 90;

export const REFUSED = 2; // exit code

const refuse = (gate, reason, data = {}) => ({ ok: false, gate, reason, ...data });
const pass = (gate) => ({ ok: true, gate });

export function tierRank(tier) {
  return TIERS.indexOf(tier);
}

/**
 * A hostname label that names production.
 * `prod`, `prod1`, `prd`, `prd-eu`, `production` are production.
 * `product`, `products`, `product-api` are not.
 */
export function isProductionLabel(label) {
  const l = String(label ?? '').toLowerCase();
  if (/^product(?!ion)/.test(l)) return false;
  return /^(prod|prd)/.test(l);
}

export function hostIsProduction(host) {
  if (!host) return false;
  return String(host).toLowerCase().split('.').some(isProductionLabel);
}

export function environmentIsProduction(name) {
  return isProductionLabel(String(name ?? '').trim().replace(/\s+/g, '-'));
}

/** G1 — production is refused outright above T0, and flagged at any tier. */
export function gateProduction(scope = {}, spec = {}) {
  const gate = 'G1-production';
  if (scope.production === true) {
    return refuse(gate, 'scope.json declares this environment as production');
  }
  if (environmentIsProduction(scope.environment)) {
    return refuse(gate, `environment "${scope.environment}" names a production environment`);
  }
  if (spec.target_url) {
    let host;
    try {
      host = new URL(spec.target_url).hostname;
    } catch {
      return refuse(gate, `target_url is not a valid URL: ${spec.target_url}`);
    }
    if (hostIsProduction(host)) {
      return refuse(gate, `host "${host}" names a production host`);
    }
  }
  return pass(gate);
}

/** G2 — the host allowlist is the project's, and credentials never ride in the URL. */
export function gateHostAllowlist(scope = {}, spec = {}) {
  const gate = 'G2-host-allowlist';
  if (!spec.target_url) return pass(gate); // nothing to reach

  let url;
  try {
    url = new URL(spec.target_url);
  } catch {
    return refuse(gate, `target_url is not a valid URL: ${spec.target_url}`);
  }
  if (url.username || url.password) {
    return refuse(gate, 'target_url carries credentials; pass them through the environment instead');
  }
  for (const [k, v] of url.searchParams) {
    if (/token|secret|key|password|auth/i.test(k) && v) {
      return refuse(gate, `target_url carries "${k}" in the query string`);
    }
  }
  const allow = Array.isArray(scope.allow_hosts) ? scope.allow_hosts : [];
  if (!allow.includes(url.hostname)) {
    return refuse(gate, `host "${url.hostname}" is not in scope.allow_hosts`, {
      allow_hosts: allow,
    });
  }
  return pass(gate);
}

/**
 * G3 — the tier ceiling. Anything above T0 needs a current authorization record.
 * Only a human edit to scope.json can raise max_tier; nothing here can.
 */
export function gateTierCeiling(scope = {}, spec = {}, now = new Date()) {
  const gate = 'G3-tier-ceiling';
  const tier = spec.tier ?? 'T0';
  if (!TIERS.includes(tier)) {
    return refuse(gate, `unknown tier "${tier}"`);
  }
  const max = scope.max_tier ?? 'T0';
  if (!TIERS.includes(max)) {
    return refuse(gate, `scope.max_tier is not a known tier: "${max}"`);
  }
  if (tierRank(tier) > tierRank(max)) {
    return refuse(gate, `tier ${tier} is above the project ceiling ${max}; raise max_tier in scope.json by hand`);
  }
  if (tierRank(tier) === 0) return pass(gate); // T0 needs no authorization record

  const auth = scope.authorization;
  if (!auth || typeof auth !== 'object') {
    return refuse(gate, `tier ${tier} requires an authorization record in scope.json`);
  }
  if (!AUTH_BASES.includes(auth.basis)) {
    return refuse(gate, `authorization.basis "${auth.basis}" is not one of ${AUTH_BASES.join(', ')}`);
  }
  const granted = Date.parse(auth.granted_at ?? '');
  if (Number.isNaN(granted)) {
    return refuse(gate, 'authorization.granted_at is missing or not a date');
  }
  const ageDays = (now.getTime() - granted) / 86_400_000;
  if (ageDays > AUTH_MAX_AGE_DAYS) {
    return refuse(gate, `authorization is ${Math.floor(ageDays)} days old; re-confirm (max ${AUTH_MAX_AGE_DAYS})`);
  }
  if (ageDays < -1) {
    return refuse(gate, 'authorization.granted_at is in the future');
  }
  return pass(gate);
}

/**
 * G4 — a run may not widen its own permissions. The allowlist, the ceiling and the
 * authorization belong to the project file, never to the spec on the command line.
 */
export const SCOPE_ONLY_KEYS = ['allow_hosts', 'max_tier', 'authorization', 'production'];

export function gateSpecOverride(rawSpec = {}) {
  const gate = 'G4-spec-override';
  const offending = SCOPE_ONLY_KEYS.filter((k) => Object.hasOwn(rawSpec, k));
  if (offending.length > 0) {
    return refuse(gate, `spec may not carry ${offending.join(', ')}; these live in scope.json`);
  }
  return pass(gate);
}

/** G5 — redaction must be wired in. The check is structural; the behaviour is in redact.mjs. */
export function gateRedaction(redactor) {
  const gate = 'G5-redaction';
  if (typeof redactor?.redactText !== 'function' || typeof redactor?.redactDeep !== 'function') {
    return refuse(gate, 'the redactor is not wired in; refusing to write anything');
  }
  const probe = redactor.redactText('AKIAIOSFODNN7EXAMPLE');
  if (probe.includes('AKIAIOSFODNN7EXAMPLE')) {
    return refuse(gate, 'the redactor did not redact a known secret pattern');
  }
  return pass(gate);
}

/** Every gate, in order. The first refusal stops the run (exit 2). */
export function checkGates({ scope, spec, rawSpec, redactor, now = new Date() }) {
  const results = [
    gateSpecOverride(rawSpec ?? spec),
    gateProduction(scope, spec),
    gateHostAllowlist(scope, spec),
    gateTierCeiling(scope, spec, now),
    gateRedaction(redactor),
  ];
  const refused = results.find((r) => !r.ok);
  return { ok: !refused, refused: refused ?? null, results };
}

/**
 * Auto-stop, evaluated while a T2+ run is in flight. Stop first, explain after.
 * CONTRACTS §4; the design calls these the hard rules.
 */
export const AUTO_STOP_RULES = [
  { id: 'out-of-scope-host', test: (s) => s.out_of_scope_requests > 0,
    reason: 'a request reached a host outside the recorded scope' },
  { id: 'consecutive-errors', test: (s) => s.consecutive_errors >= 5,
    reason: '5 consecutive request errors; the target may be degrading' },
  { id: 'unintended-write', test: (s) => s.unintended_writes > 0,
    reason: 'an unintended write side effect was observed' },
  { id: 'auth-lockout', test: (s) => s.auth_failure_rate >= 0.9 && s.requests >= 20,
    reason: 'auth is failing across the board; a lockout may be in progress' },
  { id: 'tier-exceeded', test: (s) => s.tier_exceeded === true,
    reason: 'continuing would exceed the agreed tier or module list' },
];

export function evaluateAutoStop(signals = {}) {
  const s = {
    out_of_scope_requests: 0, consecutive_errors: 0, unintended_writes: 0,
    auth_failure_rate: 0, requests: 0, tier_exceeded: false, ...signals,
  };
  const hit = AUTO_STOP_RULES.find((r) => r.test(s));
  return hit ? { stop: true, rule: hit.id, reason: hit.reason } : { stop: false };
}
