# Contributing

Written for: someone about to add a rule, a scanner or a module to this bundle.

One rule governs everything below. **A safety behaviour without a mutation that
breaks it is not a safety behaviour, it is a comment.** If your change can go wrong
quietly, the proof that it cannot is a line in `tests/mutate.mjs`, not a paragraph in
a skill.

## Before you start

```bash
node --version        # 20+
npm test              # 493 tests, no install needed — there are no dependencies
npm run mutate        # 141 mutations, all must be killed (slow: it runs the suite once per mutation)
```

Both green before you change anything, so that red means *you*.

## Where a change goes

| Change | File |
|---|---|
| a new pattern or sink | `adapters/scanners/builtin/rules.mjs` — a rule is **data**; adding one touches nothing else |
| a check that needs structure, not a pattern | `adapters/scanners/builtin/structural.mjs` |
| a check that must read a second file | `adapters/scanners/builtin/crossfile.mjs` — one hop, by name, to a function the target defines |
| a new external scanner | `adapters/scanners/<tool>/adapter.mjs` + a line in `adapters/index.mjs` |
| a new kind of target | `adapters/targets/<kind>.mjs` |
| a refusal | `controller/rules.mjs` (and a mutation, and a row in `SECURITY.md`) |
| finding identity, merge, severity | `controller/fingerprint.mjs`, `controller/merge.mjs`, `controller/taxonomy.mjs` |
| what a run could not examine | `lib/coverage.mjs` |
| how a module is graded | `lib/scorecard.mjs` |
| the verdict and the exit code | `lib/verdict.mjs` |
| what an agent is told to do | `skills/<name>/SKILL.md`, `commands/sec-*.md` |
| the vocabulary everything shares | `CONTRACTS.md` — **the authority**; a doc that disagrees with it has a bug |

## Adding a rule

A rule is an object in `RULES`. Nothing else changes — not the engine, not the
controller, not a skill.

```js
{
  id: 'sql-injection',
  files: js,
  match: /.../,                     // under-claim: a shape you are unsure of belongs in the ledger, not in a regex
  taint: true,                      // only if the rule traces input to the sink; a bare pattern match is Tentative
  severity: 'High', impact: 'HIGH', likelihood: 'MEDIUM',
  modules: ['M1', 'M6', 'M8'],
  rule: {
    name, background, remediation,
    classification: { cwe: ['CWE-89'], owasp: ['A05:2025'], wstg: [...], asvs: [...], api: [] },
    typical_severity, references: [...],
  },
}
```

Rules for the rules:

1. **Under-claim.** `.invoke(` would match LangChain and half the generic code in the
   world with it, so it is deliberately absent. A shape the rules do not recognise
   becomes a coverage-ledger gap. A blind spot named is worth more than a pattern that
   cries wolf — the whole value of this tool is that a zero can be trusted.
2. **Classify it.** CWE is the merge identity; `owasp`, `wstg`, `asvs`, `api` are the
   vocabulary a report is read in. A rule with no CWE cannot merge with another tool's
   finding for the same defect.
3. **Two fixtures**: one the rule must flag, one it must leave alone. The second is
   what stops the next person widening the pattern.
4. **A mutation.** Narrow the rule, or disable the guard it depends on, and the suite
   must fail. See `commented-guard-reads-as-a-guard` and `allowlist-substring-accepted`
   for the shape.
5. If the rule exists because a benchmark answer was missed, record `was_missed_until`
   on that answer. Writing a rule *after* seeing the answer is the most dangerous edit
   available here, and the benchmark test fails if the note is too short to explain
   itself.

## Adding a scanner

The protocol is `CONTRACTS §3` and it is the whole interface: `detect`, optional
`preflight`, `scanCommand`, `parse`. Three questions, and they are not the same
question:

| | |
|---|---|
| `detect()` | **is it installed** — never runs the scan |
| `preflight() → {ok:false}` | **can it reach this target at all** — it does not run, and its modules are not counted as covered |
| `preflight() → {ok:true, degraded:[…]}` | **can it do, here, each thing it is credited with** — it runs, and a capability it cannot use is named, reaches `result.degraded[]`, the ledger, and the grade of every module that was counting on it |

The third is the one people forget, and it is the one that caught the worst bug this
project has had: trivy installed, trivy ran, trivy found zero dependency CVEs because
the target shipped no lockfile, and the module read `unmeasured` with a recorded reason
that was simply wrong ([`docs/evidence/m18-blind.md`](docs/evidence/m18-blind.md)).

Also required:

- `parse()` returns **all three** of `findings`, `coverage`, `errors`. An adapter that
  returns nothing for all three is treated as having examined nothing, and the run goes
  `degraded` — silence is never clean.
- `scanCommand()` is pure. No I/O, no network; the controller spawns it.
- Adapters never write outside `runDir`, never read the baseline, and never see the
  authorization record.
- Anything that needs a binary this machine may not have is still proved everywhere
  through `adapters/scanners/fake/adapter.mjs`, whose options drive the same wiring.

## Adding a module

`ALL_MODULES` in `lib/scan.mjs` is the list; `lib/discover.mjs` holds the blind-spot
sentence for a module nothing can cover. A new module is not finished when a rule
points at it. It is finished when:

1. a benchmark has **recorded answers** for it (`benchmarks/*-expected.json`, or a
   corpus that writes its own, like Juice Shop's `vuln-code-snippet` markers), and
2. `sec modules` gives it a grade you are willing to quote.

`unmeasured` is not a pass, and `no-engine` with a written blind spot is more honest
than a module with a rule and no answer key. M11 (business logic) is permanently
`no-engine` on purpose.

## Tests

| | |
|---|---|
| `npm test` | 493 tests, one file per concern |
| `npm run mutate` | the failing check for every gate — see [`docs/mutation-testing.md`](docs/mutation-testing.md) |
| `npm run bench:dynamic` | starts a vulnerable target locally, scans it at T2, scores what came back |
| `tests/architecture.test.mjs` | every mutation anchor still resolves, so a gate cannot be renamed out from under its own proof |

A new check is not merged without a mutation line that fails without it. If you cannot
write the mutation, either the check has no test or it has no behaviour — find out
which before merging.

## Writing style

Agent-facing files (`skills/`, `commands/`, `CONTRACTS.md`): imperative, one rule per
bullet, state the rule and at most one sentence on the failure it prevents. The long
"because" belongs in `docs/`, not in a file an agent re-reads every run.

Human-facing files (`docs/`, `README.md`): say what it does, then what it does **not**
do. Every number traces to a file; a claim nothing can be read back from is a claim
that will rot. Prose here is English.

Never paste a real secret, a real host, or real customer data into a fixture.

## Releasing

1. `VERSION`, `package.json` `version`, the CHANGELOG entry and the README status row
   move together. Work in progress sits under `## [Unreleased]`; at release it becomes
   `## [X.Y.Z] — YYYY-MM-DD — M<n>, <name>` under a fresh empty `## [Unreleased]`.
2. A milestone that changes a contract adds a `### Changed` note saying what breaks and
   the fix, plus a section in [`UPGRADE.md`](UPGRADE.md).
3. A milestone that changes what the tool can *see* ships an evidence note under
   `docs/evidence/` — what was measured before, what after, and what nobody should
   conclude from it.
4. `npm test` and `npm run mutate` green, then commit. One milestone, one branch, one
   merge request, so each is reviewable on its own.
