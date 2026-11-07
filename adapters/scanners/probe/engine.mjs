// The probe engine. Counts every request it makes and reports the counters, so
// the controller's auto-stop has something real to evaluate.
import { createHash } from 'node:crypto';

import {
  passiveChecks, openRedirectFinding, REDIRECT_PARAMS, REDIRECT_CANARY,
  crossAccountFinding, unauthenticatedObjectFinding,
} from './checks.mjs';

/** Paths a T1 pass reads. Nothing is guessed or brute-forced. */
const PASSIVE_PATHS = ['/'];

export async function probe(origin, { tier = 'T1', paths = [], accounts = [], timeoutMs = 8000 } = {}) {
  const findings = [];
  const errors = [];
  const counters = {
    requests: 0, failures: 0, consecutive_errors: 0, out_of_scope_requests: 0,
    unintended_writes: 0, auth_failures: 0,
  };

  const base = new URL(origin);
  const targets = [...new Set([...PASSIVE_PATHS, ...paths])];

  for (const path of targets) {
    const url = new URL(path, base);
    if (url.origin !== base.origin) {
      counters.out_of_scope_requests += 1;
      errors.push({ kind: 'out-of-scope', detail: `${url.origin} is not ${base.origin}` });
      continue;
    }

    const res = await get(url, timeoutMs, counters);
    if (!res.ok) {
      errors.push({ kind: 'request-failed', detail: `${path}: ${res.error}` });
      continue;
    }
    findings.push(...passiveChecks({ url, status: res.status, headers: res.headers, body: res.body }));
  }

  // T2 adds a small number of benign requests.
  if (tier !== 'T1' && counters.out_of_scope_requests === 0) {
    findings.push(...(await redirectProbe(base, timeoutMs, counters, errors)));
    findings.push(...(await crossAccountProbe(base, accounts, timeoutMs, counters, errors)));
  }

  const coverage = [
    { kind: 'endpoints', detail: `${base.origin} paths probed`, count: targets.length },
    { kind: 'rules', detail: `probe ${tier} checks`, count: null },
  ];

  // Authorization between accounts is the one thing here that cannot be read off
  // a single response, and it is also the one thing that needs something the
  // operator has to supply. A run without it did not check it — which is not the
  // same as a run that checked and found nothing.
  if (tier !== 'T1' && usableAccounts(accounts) === null) {
    errors.push({
      kind: 'not-checked',
      detail: 'cross-account object access was not checked: it needs two sessions and an object one of them owns',
      unblock: 'pass scanner_options.probe.accounts: [{ name, cookie, owns: [path] }, { name, cookie }]',
    });
  }

  return { findings: dedupe(findings), coverage, errors, counters };
}

async function redirectProbe(base, timeoutMs, counters, errors) {
  const found = [];
  for (const param of REDIRECT_PARAMS) {
    const url = new URL('/go', base);
    url.searchParams.set(param, REDIRECT_CANARY);

    const res = await get(url, timeoutMs, counters, 'manual');
    if (!res.ok) {
      errors.push({ kind: 'request-failed', detail: `redirect probe ${param}: ${res.error}` });
      continue;
    }
    const location = res.headers.location;
    if (res.status >= 300 && res.status < 400 && location) {
      let off = false;
      try {
        off = new URL(location, base).origin !== base.origin;
      } catch { off = false; }
      if (off) {
        found.push(openRedirectFinding(new URL('/go', base), param, location));
        break; // one confirmed instance is the finding; more requests add nothing
      }
    }
  }
  return found;
}

/**
 * Two accounts, and an object the first one owns. Anything less cannot produce
 * the comparison, so say so rather than running a check that cannot conclude.
 */
export function usableAccounts(accounts = []) {
  const list = [].concat(accounts ?? []);
  const owner = list[0];
  const other = list[1];
  if (!owner?.cookie || !other?.cookie) return null;
  const owns = [].concat(owner.owns ?? []).filter(Boolean);
  if (owns.length === 0) return null;
  if (owner.cookie === other.cookie) return null; // one session wearing two names
  return { owner, other, owns };
}

const digestOf = (body) => createHash('sha256').update(body ?? '').digest('hex').slice(0, 12);

/**
 * Does one account read another's object? See CROSS_ACCOUNT_RULE for the shape
 * of the evidence and why the control request comes before the test.
 */
async function crossAccountProbe(base, accounts, timeoutMs, counters, errors) {
  const use = usableAccounts(accounts);
  if (!use) return [];
  const { owner, other, owns } = use;
  const found = [];

  for (const path of owns) {
    const url = new URL(path, base);
    if (url.origin !== base.origin) {
      counters.out_of_scope_requests += 1;
      errors.push({ kind: 'out-of-scope', detail: `${url.origin} is not ${base.origin}` });
      continue;
    }

    const asOwner = await get(url, timeoutMs, counters, 'follow', { cookie: owner.cookie, body: true });
    if (!asOwner.ok || asOwner.status !== 200 || !asOwner.body) {
      errors.push({
        kind: 'not-checked',
        detail: `${path} did not return a body to its owner (${asOwner.ok ? asOwner.status : asOwner.error}), so there is nothing to compare against`,
        unblock: 'check the cookie is current and the path names an object the first account owns',
      });
      continue;
    }
    const owned = { digest: digestOf(asOwner.body), bytes: asOwner.body.length };

    // The control. A public object answers every session identically, and
    // calling that a cross-account failure names the wrong defect and sends
    // someone to add an ownership check to an endpoint that has no login.
    const anon = await get(url, timeoutMs, counters, 'follow', { body: true });
    if (anon.ok && anon.status === 200 && digestOf(anon.body) === owned.digest) {
      found.push(unauthenticatedObjectFinding(url, { owner: owner.name ?? 'the first account', ...owned }));
      continue;
    }

    const asOther = await get(url, timeoutMs, counters, 'follow', { cookie: other.cookie, body: true });
    if (asOther.ok && asOther.status === 200 && digestOf(asOther.body) === owned.digest) {
      found.push(crossAccountFinding(url, {
        owner: owner.name ?? 'the first account',
        other: other.name ?? 'the second account',
        ...owned,
      }));
    }
  }
  return found;
}

async function get(url, timeoutMs, counters, redirect = 'follow', { cookie = null, body: wantBody = false } = {}) {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), timeoutMs);
  counters.requests += 1;
  try {
    const res = await fetch(url, {
      method: 'GET', redirect, signal: ac.signal,
      headers: {
        'User-Agent': 'ai-sec/probe (authorized security testing)',
        ...(cookie ? { Cookie: cookie } : {}),
      },
    });
    const headers = {};
    for (const [k, v] of res.headers) headers[k.toLowerCase()] = v;
    if (typeof res.headers.getSetCookie === 'function') {
      const sc = res.headers.getSetCookie();
      if (sc.length) headers['set-cookie'] = sc;
    }

    if (res.status >= 500) {
      counters.failures += 1;
      counters.consecutive_errors += 1;
    } else {
      counters.consecutive_errors = 0;
    }
    if (res.status === 401 || res.status === 403) counters.auth_failures += 1;

    const body = (wantBody || res.status >= 400) ? (await res.text()).slice(0, 4000) : '';
    return { ok: true, status: res.status, headers, body };
  } catch (e) {
    counters.failures += 1;
    counters.consecutive_errors += 1;
    return { ok: false, error: e.name === 'AbortError' ? `no response in ${timeoutMs}ms` : e.message };
  } finally {
    clearTimeout(timer);
  }
}

function dedupe(findings) {
  const seen = new Set();
  return findings.filter((f) => {
    const key = `${f.rule_id}|${f.location.file}|${f.insertion_point?.name ?? ''}|${f.detail}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
