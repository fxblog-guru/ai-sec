// probe — passive and light-active HTTP checks against an authorized live target.
// Pure Node, nothing installed, so T1 and T2 are reachable on a clean machine.
import { fileURLToPath } from 'node:url';

const RUN = fileURLToPath(new URL('./run.mjs', import.meta.url));

export default {
  name: 'probe',
  tool: 'probe',
  // T1 reads what the server already said; T2 adds a handful of benign requests.
  // It never reaches T3: nothing here should read as an attack.
  tiers: ['T1', 'T2'],
  modules: ['M3', 'M4', 'M7', 'M9', 'M13'],

  async detect() {
    return { ok: true, version: 'probe-1', install: null };
  },

  scanCommand({ target, options = {}, tier = 'T1' }) {
    const paths = (options.paths ?? []).join(',');
    // Session cookies go through the environment, never argv. A command line is
    // readable by every process on the machine and is the first thing a crash
    // report copies; the rule against printing a credential does not stop at
    // reports. CONTRACTS §6.
    const accounts = options.accounts ?? [];
    return {
      cmd: process.execPath,
      args: [RUN, target.root, tier, paths],
      env: accounts.length ? { SEC_PROBE_ACCOUNTS: JSON.stringify(accounts) } : {},
      timeout_s: options.timeout_s ?? 120,
    };
  },

  async parse({ stdout, exitCode }) {
    if (exitCode !== 0) {
      return { findings: [], coverage: [], errors: [{ kind: 'scanner-error', detail: `probe exited ${exitCode}` }] };
    }
    try {
      const p = JSON.parse(stdout);
      return {
        findings: p.findings ?? [],
        coverage: p.coverage ?? [],
        errors: p.errors ?? [],
        counters: p.counters ?? null,
      };
    } catch (e) {
      return { findings: [], coverage: [], errors: [{ kind: 'parse-error', detail: e.message }] };
    }
  },
};
