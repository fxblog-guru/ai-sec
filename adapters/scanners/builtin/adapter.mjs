// The built-in scanner: real rules, no install. CONTRACTS §3.
import { fileURLToPath } from 'node:url';
import { RULES } from './rules.mjs';

const RUN = fileURLToPath(new URL('./run.mjs', import.meta.url));

export default {
  name: 'builtin',
  tool: 'builtin',
  tiers: ['T0'],
  // rule modules plus the structural checks (M5 authz ordering, M5/M8 tenant predicate)
  modules: [...new Set([...RULES.flatMap((r) => r.modules), 'M5', 'M8'])].sort(),

  async detect() {
    return { ok: true, version: `rules-${RULES.length}`, install: null };
  },

  scanCommand({ target, depth }) {
    return {
      cmd: process.execPath,
      args: [RUN, target.root, depth === 'thorough' ? '20000' : '5000'],
      env: {},
      timeout_s: depth === 'thorough' ? 300 : 120,
    };
  },

  async parse({ stdout, exitCode }) {
    if (exitCode !== 0) {
      return { findings: [], coverage: [], errors: [{ kind: 'scanner-error', detail: `builtin exited ${exitCode}` }] };
    }
    try {
      const p = JSON.parse(stdout);
      return { findings: p.findings ?? [], coverage: p.coverage ?? [], errors: p.errors ?? [] };
    } catch (e) {
      return { findings: [], coverage: [], errors: [{ kind: 'parse-error', detail: e.message }] };
    }
  },
};
