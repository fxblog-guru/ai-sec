// Per-module measurement. The answer to "is this module any good?"
//
// Until this existed the only available answer was a rule count, and a rule count
// says nothing. M14 shipped five rules of which three produced false positives
// until they were fixed; `screen-spider` produced three findings of which three
// were wrong; a 1005-file Go repository produced none at all and called the run
// `done`. None of that is visible from counting.
//
// What is measured here, per module:
//
//   recall      of the defects the benchmark planted, how many were found
//   accounted   of the findings reported, how many are a planted defect or a
//               recorded true positive. The rest are unverified, NOT false
//               positives — a second engine finds real things we did not plant,
//               and calling those failures would punish the tool for working.
//   engines     which scanners contribute, and which of them are installed
//   blind spots what this module cannot settle at this tier, stated rather than
//               implied by a zero
import { ALL_MODULES } from './scan.mjs';
import { isApplicationCode } from '../controller/coderole.mjs';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

/**
 * The recorded answers for whatever the last run scanned.
 *
 * Without one, every number in the scorecard would be a count of findings
 * rather than a measurement, which is the thing this command exists to replace.
 */
export function benchmarkFor(result) {
  const target = result.target?.path;
  const file = target ? join(target, 'expected.json') : null;
  if (!file || !existsSync(file)) {
    return { expected: {}, source: 'none — nothing planted, so recall is unmeasured' };
  }
  const name = target.split(/[\\/]/).filter(Boolean).pop();

  // `expected.json` is a conventional filename, not a reserved one. A target that
  // ships its own — fixtures, golden files, a test corpus — would otherwise be
  // read as an answer key, and the scorecard would grade this run against
  // somebody else's data without saying a word. A malformed one used to throw and
  // take the whole command with it.
  let expected;
  try {
    expected = JSON.parse(readFileSync(file, 'utf8'));
  } catch (e) {
    return { expected: {}, source: `${name}/expected.json is not valid JSON (${e.message}) — recall is unmeasured` };
  }
  if (!Array.isArray(expected.defects)) {
    return {
      expected: {},
      source: `${name}/expected.json ignored — no \`defects\` array, so it is not an answer key for this tool`,
    };
  }

  // What makes a benchmark strong is who wrote the CODE, not who recorded the
  // answers. We can write the answers for OWASP NodeGoat and still be surprised by
  // it, because we did not choose its defects to suit our rules. A benchmark whose
  // target is third-party declares `corpus`; ours does not, and guessing from the
  // directory name would have made any directory called something else "external".
  const external = typeof expected.corpus === 'string' && expected.corpus.length > 0;
  return {
    expected,
    trust: external ? 'external' : 'self',
    source: external
      ? `${name}/expected.json (${expected.corpus} — code we did not write)`
      : `${name}/expected.json (written by us — a fixture you wrote cannot surprise you)`,
  };
}

/**
 * Has anything reported this defect?
 *
 * A single CWE is the usual key, and it is wrong for a defect that is a CLASS
 * rather than one line. NodeGoat's "vulnerable dependencies" was recorded as
 * CWE-1104, and trivy files each CVE under that CVE's own weakness — CWE-94,
 * CWE-770, CWE-290 — so the benchmark reported a miss while fifty-two findings
 * sat in the file. A defect may therefore be keyed on its CWE, on the issue type,
 * or on the prefix its scanner gives such rules.
 */
/** Every file this finding points at — the one it is anchored to, and every place it also occurs. */
function filesOf(finding) {
  const out = new Set();
  if (finding.location?.file) out.add(finding.location.file);
  for (const o of finding.occurrences ?? []) {
    out.add(String(o).split('\\').join('/').replace(/:\d+$/, ''));
  }
  return out;
}

function matches(finding, defect, cweOf) {
  // `occurrences` has been printed in reports since M15 and was never scored.
  // A finding anchored at the helper that causes a defect, listing the call
  // site the benchmark recorded, was counted as a miss — the scorecard could
  // see the answer and was looking at one field.
  if (defect.file && !filesOf(finding).has(defect.file)) return false;
  if (defect.rule_id_prefix && String(finding.rule_id ?? '').startsWith(defect.rule_id_prefix)) return true;
  if (defect.issue_type && finding.issue_type === defect.issue_type) return true;
  return Boolean(defect.cwe) && cweOf(finding).includes(defect.cwe);
}

/**
 * @param findings  merged findings from a run against the benchmark
 * @param rules     the type catalogue, which carries the classification
 * @param expected  the benchmark's recorded answers
 * @param engines   { name: { modules: [], installed: bool } }
 */
export function scorecard({
  findings = [], rules = [], expected = {}, engines = {},
  modules = ALL_MODULES, blindSpots = {}, benchmarkTrust = 'self', degraded = [],
} = {}) {
  // A capability the run could not use, indexed by the module that was counting
  // on it. Without this a module whose engine was blind is graded `failing`,
  // which blames the rules for a defect they were never shown.
  const blindOn = new Map();
  for (const d of degraded) {
    for (const m of d.modules ?? []) {
      const note = `${d.scanner} could not check ${d.capability} on this target: ${d.reason}`;
      blindOn.set(m, [...(blindOn.get(m) ?? []), note]);
    }
  }

  const cweById = new Map(rules.map((r) => [r.rule_id, r.classification?.cwe ?? []]));
  const cweOf = (f) => cweById.get(f.rule_id) ?? [];

  // A planted defect lives in the application, so a test-suite finding can
  // neither satisfy one nor be an unexplained extra. Counting them made every
  // module on Juice Shop look like it had thirty unaccounted findings.
  findings = findings.filter(isApplicationCode);

  const defects = expected.defects ?? [];
  const accepted = new Set(expected.accepted ?? []);

  const rows = [];
  for (const m of modules) {
    const planted = defects.filter((d) => (d.modules ?? []).includes(m));
    const reported = findings.filter((f) => (f.modules ?? []).includes(m));

    const found = [];
    const missed = [];
    for (const d of planted) {
      (findings.some((f) => matches(f, d, cweOf)) ? found : missed).push(d.id);
    }

    // A reported finding is accounted for when it is one of the planted defects,
    // or the benchmark has recorded it as a real finding we did not plant.
    const unaccounted = reported.filter(
      (f) => !defects.some((d) => matches(f, d, cweOf)) && !accepted.has(f.rule_id),
    );

    const contributing = Object.entries(engines)
      .filter(([, e]) => (e.modules ?? []).includes(m))
      .map(([name, e]) => ({ name, installed: Boolean(e.installed) }));

    rows.push({
      module: m,
      engines: contributing,
      installed_engines: contributing.filter((e) => e.installed).length,
      planted: planted.length,
      found: found.length,
      missed,
      reported: reported.length,
      unaccounted: unaccounted.length,
      unaccounted_rules: [...new Set(unaccounted.map((f) => f.rule_id))].slice(0, 5),
      recall: planted.length ? found.length / planted.length : null,
      // STATIC_BLIND_SPOTS holds one sentence per module, not a list. Iterating a
      // string gives you its characters, which is how M11 reported thirty-one of them.
      blind_spots: [].concat(blindSpots[m] ?? [], blindOn.get(m) ?? []),
      grade: grade({
        planted: planted.length, found: found.length,
        installed: contributing.filter((e) => e.installed).length,
        benchmarkTrust,
        blind: blindOn.has(m),
      }),
    });
  }
  return rows;
}

/**
 * A module's grade, from what is actually known about it.
 *
 * `unmeasured` is deliberately not a passing grade and is the honest state of most
 * modules: an engine is wired up and nothing has ever checked what it finds.
 *
 * Full marks against a benchmark we wrote ourselves is `self-measured`, never
 * `measured`. M6 found nine defects by scanning a repository nobody here wrote,
 * none of which the fixture could ever have exposed, and recorded the reason: a
 * fixture you wrote cannot surprise you. A grade that cannot tell those apart
 * would report the strongest possible result for the weakest possible evidence.
 */
export function grade({ planted, found, installed, benchmarkTrust = 'self', blind = false }) {
  if (installed === 0) return 'no-engine';
  // The engine is here and one of the things it was counted on for could not run
  // against this target. `failing` would blame the rules for a defect they were
  // never shown, and `unmeasured` would not say why. It stops being the answer
  // the moment the module finds everything anyway: a blind capability that cost
  // nothing is not worth a grade of its own.
  if (blind && found < planted) return 'blind';
  if (planted === 0) return blind ? 'blind' : 'unmeasured';
  if (found === 0) return 'failing';
  if (found < planted) return 'partial';
  return benchmarkTrust === 'external' ? 'measured' : 'self-measured';
}

export const GRADES = ['no-engine', 'blind', 'unmeasured', 'failing', 'partial', 'self-measured', 'measured'];

export function formatScorecard(rows, { source = 'unknown' } = {}) {
  const lines = [
    `Module scorecard — benchmark: ${source}`,
    '',
    '                engines  planted  found  reported  unaccounted  grade',
  ];
  for (const r of rows) {
    const eng = `${r.installed_engines}/${r.engines.length}`;
    lines.push(
      `  ${r.module.padEnd(5)}` +
      `${eng.padStart(12)}` +
      `${String(r.planted).padStart(9)}` +
      `${String(r.found).padStart(7)}` +
      `${String(r.reported).padStart(10)}` +
      `${String(r.unaccounted).padStart(13)}` +
      `  ${r.grade}`,
    );
    if (r.missed.length) lines.push(`         missed: ${r.missed.join(', ')}`);
    for (const b of r.blind_spots) lines.push(`         blind spot: ${b}`);
  }

  const tally = {};
  for (const r of rows) tally[r.grade] = (tally[r.grade] ?? 0) + 1;
  lines.push('', Object.entries(tally).map(([k, v]) => `${v} ${k}`).join(' · '));

  // The benchmark is the limit on every number above it.
  lines.push('');
  lines.push('`self-measured` means full marks against a benchmark we wrote. It is the weakest');
  lines.push('evidence there is: run this against a corpus nobody here authored to earn `measured`.'); 
  lines.push('A module is graded only against the defects this benchmark planted.');
  lines.push('`blind` means an engine ran with a capability this module needed unusable against this');
  lines.push('target — the blind spot under the row says which, and a zero there is not a clean result.');
  lines.push('`unaccounted` findings are unverified, not wrong: a second engine reports real');
  lines.push('things the benchmark never planted. Judge them by hand and record the verdict.');
  return lines.join('\n');
}
