---
name: starting-security-work
description: The entry point for an ai-sec assessment - orchestrates discover, scope, scan, verify and report, and knows what to do next from the project state. Use when /sec-start runs, when asked to run a security assessment or check a repo for vulnerabilities, or when picking up an assessment that was already partly done.
version: 1.1.0
---

# Starting security work

Read `sec-protocol` first. This skill is the conductor; each phase has its own skill.

## If the project has state, resume rather than restart

```bash
node <ai-sec>/bin/sec.mjs status --slug <slug>
```

It prints what is done and **one** next step, with the reason. Follow it. Do not re-run a
phase that is already complete, and do not ask the user to choose between phases — the
state decides.

## If this is a fresh project

Run it, do not plan it. Five steps, each with its own skill:

| Step | Command | Skill |
|---|---|---|
| 1 Discover | `sec discover` | `discovering-attack-surface` |
| 2 Scope | write `scope.json` | `scoping-the-assessment` |
| 3 Scan | `sec scan` | `running-scanners` |
| 4 Triage | read the candidates, try to disprove each | `verifying-findings` |
| 5 Verify | `sec verify` — by someone who did not find it | `verifying-findings` |
| 6 Report | `sec report` | `reporting-findings` |
| — Measure | `sec modules` — what a module's silence is worth | `running-scanners` |
| — Learn | `sec baseline promote`, `sec lessons add` | `recording-lessons` |

Step 5 is the one that gets skipped, and skipping it is allowed — what is not allowed is
reporting as though it happened. An unverified finding stays unverified in the report.

For a repo the user already has open, steps 1–3 need no conversation at all. The defaults
are T0 static, all applicable modules, balanced, normal. Say the defaults in one line,
then run.

## Before anything else

Read `.sec/<slug>/lessons.md` if it exists, and say which lessons you are applying. A
previous run already learned things about this codebase; starting without them wastes the
work that produced them.

Then run `sec doctor` and let the user see it. It names which scanners are present, and
therefore which modules can be covered at all. A missing scanner is a coverage gap you
should state up front, not discover in the ledger at the end.

## The shape of a good first run

```
Lessons:  2 applied (tenant scoping lives in BaseRepository.scoped(); legacy/ is dead code)
Doctor:   builtin ok, gitleaks ok, semgrep not installed, trivy not installed
Scope:    this repo · T0 static, sends nothing · all applicable modules
Estimate: 2 scanner runs, ~20s
```

Then scan, verify, and report. One pass, no interrogation.

## What not to do

- **Do not ask permission to read the user's own code.** T0 sends nothing.
- **Do not ask which modules they want.** `surface.json` decides; mention what was dropped.
- **Do not plan out loud.** Running the scan takes twenty seconds and answers more than a
  plan does.
- **Do not raise the tier because it would find more.** Above T0 is a user decision, asked
  once, concretely, naming the host. See `scoping-the-assessment`.
- **Do not promote a degraded run to the baseline.**

## When the user asks "is my app secure?"

That question has no yes. What you can give them is: what was examined, what was found,
what was not checked, and what to fix first. Say the fourth thing first.

## Done when

- The run reached a terminal state, and you said which.
- Findings are verified, not just listed.
- The report leads with plain language, and a PASS with gaps is qualified.
- The baseline is promoted and lessons recorded, so the next run starts ahead of this one.
