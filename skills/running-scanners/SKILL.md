---
name: running-scanners
description: Run the scan and read what came back, including what did not run. Covers the cost estimate, scanner selection, the coverage ledger, and why a degraded or not-evaluable run is never reported as clean. Use when /sec-scan runs, when a scan finishes, or when a run comes back degraded.
version: 1.1.0
---

# Running scanners

Read `sec-protocol` first.

## Estimate, then run

```bash
node <ai-sec>/bin/sec.mjs scan [target] --slug <slug>
```

The command prints a cost estimate before it starts. Let the user see it. If the estimate
is large, say so in one line and let them narrow — but proceed with the default if they
do not reply.

Scanners are selected by tier and by what is installed. `fake` is never selected
implicitly; it exists for tests and the quickstart.

## Read the coverage ledger before the findings

This is the habit that separates a real assessment from a tool dump. **Open the "Could not
evaluate" section first.** It tells you how much the finding list is worth.

| Ledger entry | What it means |
|---|---|
| `scanner X: not installed` | Every check X contributes did not run. Either install it or say the module is uncovered. |
| `scanner X: did not run` | X **is** installed and still could not touch this target — its `preflight` refused and named why. The entry carries the unblock. Treat it exactly as "not installed": X covers no module this run. |
| `module Mn: no scanner contributes` | Nothing examined that area. Not "nothing found". |
| `scanner X: timed out` | Partial coverage. Findings from X are a sample, not a sweep. |
| `scanner X: examined nothing we can confirm` | X produced no findings *and* no coverage. Silence, not cleanliness. |
| `same-tool merge` | One tool's two rules landed on one finding because they share a CWE family and a location. One of the two defects is no longer separately visible. The adapter needs a `subtype`. |
| `unrecognised model SDK` | Files import a model SDK and no M14 rule recognised a call in any of them. Prompt handling, model output and tool authority were **not checked**. Zero findings there means not examined. |
| `non-application code` | N findings are in test, fixture, example, generated or vendored files. They are reported and kept out of the verdict. Read the count: on a real repository it is often most of the list, and "the application is clean" and "the application findings are the short list" are different sentences. |

A run with a long ledger and no findings is **not** a good result. Say that plainly.

## Run states

| State | Exit | Means |
|---|---|---|
| `done` | 0 | every selected scanner ran and reported coverage |
| `degraded` | 4 | one failed, timed out or produced nothing; others covered |
| `not_evaluable` | 3 | nothing reported coverage, or the target could not be read |
| `aborted` | 5 | a gate refused, or auto-stop fired |

**A degraded run may still find real things, and must never be promoted to a baseline** —
it would bake its blind spots in as known-good.

## Ask what a module's silence is worth

The ledger says what did not run. It cannot say whether what *did* run is any good. That
is a separate command, and it is graded against benchmarks with recorded answers:

```bash
node <ai-sec>/bin/sec.mjs modules --slug <slug>
```

| Grade | Means |
|---|---|
| `measured` | Full marks against a corpus **nobody here wrote**. The only grade that can surprise us. |
| `self-measured` | Full marks against a benchmark we wrote. The weakest evidence there is. |
| `partial` | Found some of the planted defects, missed others. The misses are named. |
| `failing` | An engine ran and found none of them. |
| `unmeasured` | Nothing has ever checked this module. **Not a pass.** |
| `blind` | An engine ran with a capability this module needed unusable against this target — trivy with no lockfile cannot read a single package version. The blind spot under the row names it. **A zero here is not a clean result**, and it is deliberately not `failing`: the rules were never shown the defect. |
| `no-engine` | No scanner contributes to it at all, and the blind spot is written out. |

Quote the grade when you quote the module. "M5 found nothing" is worth something if M5 is
`measured` and worth nothing at all if M5 is `unmeasured`, and the difference is invisible
in the finding list.

## What you add

1. **Explain the ledger in one sentence.** "Dependencies were not checked because trivy
   is not installed" is worth more than the whole finding list to someone deciding whether
   to trust it.
2. **Group by cause before reading instance by instance.** Six missing-authorization
   findings across six routes is one finding: authorization is opt-in in this codebase.
   See `diagnostics.md` §4.
3. **Spot the contradictions.** `references/diagnostics.md` catalogues them — parameterized
   queries with cross-tenant reads, a WAF that cannot see a BOLA, a guard registered after
   the route it guards.
4. **Do not re-list what the command printed.** Move to verification.

## Installing a scanner

Suggest, never install.

`sec doctor` lists which scanners are present and which are not, and every absent one
reports its own install hint — that is the adapter's job, not this skill's. The ledger
then names which modules the absence leaves uncovered.

Say what installing it would *add*, in modules, not in tool names:

> Dependencies (M2) and infrastructure config (M10) were not checked this run. Installing
> the scanner the doctor named would cover both. Want me to show the command?

One scanner needs nothing installed and always runs, so a scan is never empty for want of
tooling.

## Done when

- The run reached a terminal state and you have said which.
- The coverage ledger is explained, not just printed.
- Findings are grouped by cause, ready for verification.
