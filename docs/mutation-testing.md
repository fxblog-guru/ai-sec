# Mutation testing — the failing check for every gate

Written for: someone who has read that this bundle has 141 safety gates and wants to
know what that number is worth.

A passing test suite proves that the code does something. It does not prove that the
code does the **one thing you are relying on**. A test can pass because the behaviour
is there, or because the test never looks at it, and from the outside those are
identical.

So every safety behaviour here is checked the other way round: **switch it off, and the
suite must go red.** A behaviour that can be removed with the tests still green has no
test, whatever the coverage report says.

```bash
npm run mutate
```

```
baseline: green

  [killed]   G1-production        production is refused
  [killed]   redaction            secrets never reach disk
  [killed]   quiet-pass           a failed or silent scanner never yields done
  …
141/141 mutations killed
every gate has a test that fails when it is removed.
```

It is slow — it runs the whole suite once per mutation — and it is the only number in
this repository that cannot be gamed by writing more tests.

## What a mutation is

One entry in `MUTATIONS` in [`tests/mutate.mjs`](../tests/mutate.mjs): a file, a string
to find, a string to put in its place, and a sentence saying what is being disabled.

```js
{
  id: 'quiet-pass',
  why: 'a failed or silent scanner never yields done',
  path: 'lib/coverage.mjs',
  ...stub('export function runStateFromScanners(results = []) {', "return 'done';"),
}
```

`stub()` makes a function return a constant — the simplest possible way to remove a
behaviour without removing the code that calls it. That matters: a mutation deletes the
*judgement*, not the plumbing, so what goes red is a test that was checking the
judgement rather than a test that was checking the call.

Two sentences are required and both are load-bearing. `id` is how a survivor is
reported; `why` is the claim the gate makes in plain words. If you cannot write `why`
in one line, you do not yet know what the gate is for.

## The anchor problem, and why it is checked first

An anchor is a literal string. The moment someone reformats that line, the mutation
stops applying — and a mutation that never applies guards nothing while looking
exactly like one that does.

Three went stale here in a single afternoon: one line was rewritten by a later fix, and
two were written with the wrong indentation and had **never run at all**. The runner
now checks every anchor before it mutates anything:

```
3 mutation(s) cannot apply:
  - unchecked-module-grades-well: anchor not present in lib/scorecard.mjs
A mutation that never applies guards nothing. Fix the anchors.
```

One line, immediately — instead of a quarter of an hour and a warning buried at the end
of the output. `tests/architecture.test.mjs` runs the same check inside `npm test`, so
renaming a gated function fails the ordinary suite rather than quietly unhooking its
proof.

The runner also refuses to start on a red suite. Mutating a broken build proves
nothing: everything "dies" and every gate looks guarded.

## Crash safety, and why it is on disk

A mutated file is a deliberately broken security tool sitting in your working copy. One
interrupted run left `verdict()` returning a hardcoded `PASS`, and the next full test
run failed in thirteen unrelated places with no clue why.

Signal handlers cannot fix this: `runSuite()` is `spawnSync`, so Node is blocked for the
seconds a mutation is applied and no handler can run — and a hard kill is not catchable
at all. So the restore is written to `.mutate-inflight.json` **before** the file is
touched, and the next run undoes it and **says so**:

```
recovered: an earlier run was killed with lib/verdict.mjs mutated; restored it
```

Recovery deliberately does not happen during `npm test`. The runner's own tests run with
a mutation applied, and repairing there once undid every mutation from inside the suite
meant to detect it — eighty-three survivors at once. A repair that runs where nobody
expects it is indistinguishable from the bug it repairs.

## What the 141 cover

| Area | Gates | A sample of what gets switched off |
|---|---|---|
| `adapters/scanners/builtin/` (structural · engine · rules · crossfile) | 46 | a comment counts as code · a commented-out fix counts as a fix · any field is sensitive · a helper is never resolved |
| `lib/coverage.mjs` · `lib/scan.mjs` | 13 | a scanner that examined nothing reads clean · a degradation never reaches the ledger · a skipped scanner still counts as coverage |
| `controller/merge.mjs` · `fingerprint.mjs` · `taxonomy.mjs` | 14 | confidence inflates to `Certain` · severity disagreement is hidden · hardening fails the build · identity falls back to the rule id |
| `lib/scorecard.mjs` | 8 | our own fixture counts as proof · an unchecked module grades well · a missed defect is not named · any `expected.json` is an answer key |
| `adapters/scanners/probe/` | 8 | the probe escapes its origin · the tier is ignored · evidence quotes the data it found |
| `controller/rules.mjs` · `redact.mjs` · `state.mjs` | 8 | each of the five gates in turn · secrets reach disk · a terminal run state is rewritten |
| `controller/verification.mjs` | 6 | the verifier may be the finder · reading the code counts as confirmation · an anonymous verdict is accepted |
| `lib/baseline.mjs` | 6 | a degraded run becomes a baseline · a human verdict is lost · a lesson leaks a secret |
| `controller/locate.mjs` · `coderole.mjs` | 7 | absolute paths in a report · test code counts as the application |
| `lib/verdict.mjs` · `sarif.mjs` · `discover.mjs` · `help.mjs` | 11 | the verdict turns optimistic · the bar widens · SARIF drops the coverage ledger · imported findings are trusted |
| `adapters/` elsewhere (targets · trivy · zap · nuclei · index) | 11 | a target skips the allowlist · a range is a version · the nuclei container reaches loopback · the fake scanner leaks into a real run |
| `benchmarks/dynamic/` · `bin/sec.mjs` | 3 | the benchmark targets anything · a skill names a dead command |

Read that list as a specification. It is the most precise statement in the repository of
what this tool promises, because each line is a promise something actively tries to
break.

## Adding one

Any change that can fail *quietly* needs a mutation. The test is simple: if the
behaviour disappeared, would anything go red?

1. Write the behaviour and its test.
2. Add the mutation that disables it, with a one-line `why`.
3. `npm run mutate` — your new mutation must be **killed**, and nothing else must have
   started surviving.

If it survives, you have learned something: the test you just wrote does not check what
you thought it checked. Fix the test, not the mutation.

## What this does not prove

- It does not prove the rules **find vulnerabilities**. That is recall, and it is
  measured separately against corpora with recorded answers — `sec modules`,
  [`benchmarks/README.md`](../benchmarks/README.md), and the grades in
  [`docs/user-guide.md`](user-guide.md).
- It does not prove the gates are the **right** gates. Nothing automatic can. That
  argument belongs in [`CONTRACTS.md`](../CONTRACTS.md) and in review.
- A killed mutation means *some* test noticed. It does not promise the test noticed for
  the right reason — only that the behaviour is observable at all, which is the floor,
  not the ceiling.
