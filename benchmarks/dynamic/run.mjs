// The dynamic benchmark: start a target, scan it, score what came back.
//
// Why this exists. Until now every module was graded against files on disk, so
// "M5 found the IDOR" meant a regular expression recognised the shape of a
// handler. Here the finding is produced by sending a request as one account,
// reading the answer, and comparing it to the same request as another. That is a
// different claim, and it is the one the module is supposed to support.
//
// On authorization. This harness writes its own scope.json, which is exactly the
// thing ai-sec refuses to let a scan do for a user's target. It is allowed here
// for one reason: the target is a server this process started, on an ephemeral
// loopback port, from source in this repository — and the harness checks that
// before it writes anything. Nothing about it generalises. Pointing it at a host
// is not a configuration change, it is a refusal.
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

import { start, HOST } from './app.mjs';
import expected from './expected.json' with { type: 'json' };
import { scan, ALL_MODULES } from '../../lib/scan.mjs';
import { scorecard, formatScorecard } from '../../lib/scorecard.mjs';
import { STATIC_BLIND_SPOTS } from '../../lib/discover.mjs';
import { verdict, formatVerdict } from '../../lib/verdict.mjs';
import { SCANNERS } from '../../adapters/index.mjs';

/** The modules this benchmark can actually speak to. The rest are not graded here. */
export const DYNAMIC_MODULES = [...new Set(expected.defects.flatMap((d) => d.modules))].sort(
  (a, b) => Number(a.slice(1)) - Number(b.slice(1)),
);

/**
 * The harness may target one thing: the server it just started.
 *
 * Written as a check rather than a comment because a comment does not fail.
 */
export function assertOwnLoopbackTarget(origin, port) {
  const url = new URL(origin);
  if (url.hostname !== HOST) {
    throw new Error(`the dynamic benchmark targets ${HOST} and nothing else; got ${url.hostname}`);
  }
  if (Number(url.port) !== Number(port)) {
    throw new Error(`port ${url.port} is not the port this process bound (${port})`);
  }
  return true;
}

function writeScope(root, slug) {
  mkdirSync(join(root, '.sec', slug), { recursive: true });
  writeFileSync(join(root, '.sec', slug, 'scope.json'), `${JSON.stringify({
    schema: 'sec-scope/v1',
    max_tier: 'T2',
    allow_hosts: [HOST],
    deny_paths: [],
    production: false,
    environment: 'local',
    authorization: {
      basis: 'own-repo',
      granted_by: 'benchmarks/dynamic/run.mjs',
      granted_at: new Date().toISOString(),
      note: 'the target is a loopback server this harness started from benchmarks/dynamic/app.mjs',
    },
  }, null, 2)}\n`, 'utf8');
}

export async function runDynamicBenchmark({ keep = false } = {}) {
  const app = await start();
  const root = mkdtempSync(join(tmpdir(), 'ai-sec-dynamic-'));
  const slug = 'dynamic';

  try {
    assertOwnLoopbackTarget(app.origin, app.port);
    writeScope(root, slug);

    const [alice, bob] = app.accounts;
    const outcome = await scan({
      root,
      slug,
      target: 'url',
      target_url: app.origin,
      tier: 'T2',
      modules: ALL_MODULES,
      // Paths the passive pass should read in addition to /. Nothing is guessed:
      // these are routes the benchmark declares it has.
      scanner_options: {
        probe: {
          paths: ['/login', '/boom'],
          accounts: [
            { name: alice.name, cookie: alice.cookie, owns: alice.owns },
            { name: bob.name, cookie: bob.cookie },
          ],
        },
      },
      baseline: 'none',
    });

    if (!outcome.result) {
      return { ok: false, reason: outcome.reason ?? outcome.run_state, rows: [], result: null };
    }
    const result = outcome.result;

    const engines = {};
    for (const a of Object.values(SCANNERS)) {
      const det = await a.detect();
      engines[a.name] = { modules: a.modules ?? [], installed: Boolean(det.ok) };
    }

    const rows = scorecard({
      findings: result.findings ?? [],
      rules: result.rules ?? [],
      expected,
      engines,
      modules: DYNAMIC_MODULES,
      blindSpots: STATIC_BLIND_SPOTS,
      // We wrote the target. `self-measured` is the ceiling and that is correct:
      // what this benchmark adds is the KIND of evidence, not its independence.
      benchmarkTrust: 'self',
    });

    // The deliberately correct endpoint. A score that ignores it rewards a check
    // that reports every handler of that shape.
    const forbidden = (result.findings ?? []).filter((f) =>
      (expected.must_not_report ?? []).some((m) =>
        String(f.location?.file ?? '').startsWith(m.path.replace(/\/:.*$/, '/'))));

    return { ok: true, rows, result, forbidden, root: keep ? root : null };
  } finally {
    await app.close();
    if (!keep) rmSync(root, { recursive: true, force: true });
  }
}

export function formatDynamic({ rows, result, forbidden }) {
  const out = [
    formatScorecard(rows, { source: 'benchmarks/dynamic (ours, but every finding came from a request)' }),
    '',
    formatVerdict(verdict(result, { bootstrap: true })),
  ];
  out.push('', forbidden.length === 0
    ? 'The deliberately correct endpoint was not reported.'
    : `REPORTED THE CORRECT ENDPOINT (${forbidden.length}): ${forbidden.map((f) => `${f.rule_id} ${f.location?.file}`).join(', ')}`);
  return out.join('\n');
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const out = await runDynamicBenchmark();
  if (!out.ok) {
    process.stderr.write(`dynamic benchmark could not run: ${out.reason}\n`);
    process.exit(3);
  }
  process.stdout.write(`${formatDynamic(out)}\n`);
  process.exit(out.forbidden.length === 0 ? 0 : 1);
}
