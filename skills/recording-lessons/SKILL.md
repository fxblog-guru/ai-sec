---
name: recording-lessons
description: Write down what this codebase taught us, so the next run starts where this one finished. Covers what counts as a lesson, what never goes in one, and promoting a run to the baseline. Use when /sec-learn runs, at the end of an assessment, or after dismissing a finding as a false positive.
version: 1.0.0
---

# Recording lessons

Read `sec-protocol` first.

Without this, every run re-litigates the last one: the same false positive argued again,
the same dead directory investigated again. This is pillar P2, and it is the cheapest
quality improvement available.

## Two different things

| | Baseline | Lessons |
|---|---|---|
| Holds | fingerprints, severities, human verdicts | durable facts about the codebase |
| Shape | JSON, machine-read | Markdown, read by you at the start of a run |
| Answers | "is this new?" | "what should I already know?" |

```bash
node <ai-sec>/bin/sec.mjs baseline promote --slug <slug>
node <ai-sec>/bin/sec.mjs lessons add "Tenant scoping lives in BaseRepository.scoped()."
```

Only a `done` run may be promoted. A degraded run would record its blind spots as
known-good. Human verdicts (`false_positive`, `accepted_risk`) survive the next promotion.

## What counts as a lesson

A lesson changes a **future** run. Test it: would this have saved time last time?

Good:
- *Tenant scoping lives in `BaseRepository.scoped()`. Any query not going through it is a
  cross-tenant risk — check those first in M5 and M8.*
- *`legacy/` is excluded from the build. Findings there are Tentative at most.*
- *Authorization is enforced in `requireRole` mounted per router, not globally, so route
  ordering decides whether it applies. This bit us once.*
- *The team accepts the `Math.random` in `analytics/` — it is not security-relevant there.
  Do not re-raise it.*
- *`npm audit` flags `lodash` every run; it is dev-only and never shipped.*

Not a lesson:
- *Found SQL injection in `orders.ts`.* — that is a finding; the baseline has it.
- *The app uses Express.* — `surface.json` has it, and re-detects it every run.
- *Security is important.* — advice to nobody.

The distinction: a finding is **state**, a lesson is **knowledge**. State goes in the
baseline and expires when fixed. Knowledge stays true after the fix lands.

## Never in a lesson

- A credential, a token, or any part of one. The command refuses a lesson that carries one
  rather than sanitizing it, because reaching for a secret in a lesson means the lesson was
  the wrong shape.
- An exploit payload.
- Anything about a person rather than the code.

These files live in the repository. Write them as though they are public, because they are.

## Read them first, every run

At the start of an assessment, read `lessons.md` before scanning, and say in the report
which lessons you applied. A lesson nobody reads is a comment.

If a lesson turns out to be wrong — the dead directory came back to life, the accepted
risk stopped being acceptable — delete it. A stale lesson is worse than none, because it
is trusted.

## After dismissing a finding

Two steps, not one:

```bash
node <ai-sec>/bin/sec.mjs judge <fingerprint> false_positive "<why>"
node <ai-sec>/bin/sec.mjs lessons add "<the general rule, if there is one>"
```

The first stops this instance being re-reported. The second stops the *class* being
re-investigated — but only write it when there is a general rule. "This one call is fine"
is a judgement; "migrations never take user input in this repo" is a lesson.

## Done when

- The run is promoted, if it is `done`.
- Every dismissal has a recorded reason.
- Lessons say something a future run can act on, and carry no secret.
- The report names which lessons were applied this run.
