// The url target. Everything dangerous about ai-sec goes through here, so it
// re-checks the allowlist itself rather than trusting that a gate already did.
// CONTRACTS §3.
import { hostIsProduction } from '../../controller/rules.mjs';

export default {
  name: 'url',

  async prepare({ spec, scope = {} }) {
    const raw = spec.target_url;
    if (!raw) return { ok: false, root: null, meta: {}, error: 'url target needs target_url' };

    let url;
    try {
      url = new URL(raw);
    } catch {
      return { ok: false, root: null, meta: {}, error: `not a valid URL: ${raw}` };
    }

    if (!['http:', 'https:'].includes(url.protocol)) {
      return { ok: false, root: null, meta: {}, error: `unsupported scheme: ${url.protocol}` };
    }
    if (url.username || url.password) {
      return { ok: false, root: null, meta: {}, error: 'credentials in the URL' };
    }

    // Belt and braces: the gate checked these, and so do we. A target adapter is
    // the last code that runs before traffic leaves the machine.
    if (hostIsProduction(url.hostname)) {
      return { ok: false, root: null, meta: {}, error: `${url.hostname} names a production host` };
    }
    const allow = Array.isArray(scope.allow_hosts) ? scope.allow_hosts : [];
    if (!allow.includes(url.hostname)) {
      return { ok: false, root: null, meta: {}, error: `${url.hostname} is not in scope.allow_hosts` };
    }

    const reachable = await head(url);
    if (!reachable.ok) {
      return { ok: false, root: url.origin, meta: {}, error: `unreachable: ${reachable.error}` };
    }

    return {
      ok: true,
      root: url.origin,
      meta: { kind: 'url', origin: url.origin, host: url.hostname, path: url.pathname, status: reachable.status },
    };
  },

  async cleanup() {},
};

async function head(url, timeoutMs = 5000) {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const res = await fetch(url, { method: 'GET', redirect: 'manual', signal: ac.signal });
    return { ok: true, status: res.status };
  } catch (e) {
    return { ok: false, error: e.name === 'AbortError' ? `no response in ${timeoutMs}ms` : e.message };
  } finally {
    clearTimeout(timer);
  }
}
