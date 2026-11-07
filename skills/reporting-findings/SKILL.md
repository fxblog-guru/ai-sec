---
name: reporting-findings
description: Turn a verified run into a verdict and a report someone can act on, including the plain-language summary, the severity x confidence matrix, and the coverage ledger. Use when /sec-report runs, when a scan needs writing up, or when asked what the security results mean.
version: 1.1.0
---

# Reporting findings

Read `sec-protocol` first.

```bash
node <ai-sec>/bin/sec.mjs report --slug <slug> [--bootstrap]
```

The command computes the verdict deterministically. **You write the part a person reads.**

## Outcomes

| Outcome | When | Exit |
|---|---|---|
| `PASS` | nothing at or above High/Firm | 0 |
| `WARN` | something real below that bar | 0 |
| `FAIL` | any High or Critical at Firm or Certain | 1 |
| `NOT_EVALUABLE` | the run could not look, or there is no baseline | 3 |

`NOT_EVALUABLE` outranks the findings. A run that could not look has not found nothing.

Two things the bar deliberately ignores:

- **Hardening notes never fail a build on their own.** A missing defence-in-depth layer
  while another still holds is reported, counted and left out of the verdict. Pushing it
  into the bar is how a team learns to ignore the bar.
- **Nobody having checked is not a reason to pass.** A FAIL whose findings are all
  `unverified` says so in its first line, in the same breath as the verdict: this is where
  "nobody has tried to break this" costs the most, because a build is being stopped on it.

## Lead with what it means

Before any table, three to five sentences for someone who does not work in security:

- what was examined, and what was not
- the most serious thing found, and what an attacker could do with it
- what to fix first
- how much of the system could not be checked

No CWE numbers, no tool names, no severity words used as jargon. If a reader cannot act on
it without asking a follow-up question, rewrite it.

> **Example.** We reviewed the application's source code — not the running system. The
> most serious problem is that the route for deleting users runs before the admin check,
> so any signed-in account can delete any user. Fix that first; it is a two-line change to
> the route ordering. Three other issues need attention this week. We could not check the
> dependencies, because the tool that does it is not installed.

## Then the structure

1. **Scope and authorization** — target, basis, tier run, accuracy, depth, modules, and
   which baseline this was compared against.
2. **Summary** — the severity x confidence matrix, plus new / fixed / unchanged / suppressed.
3. **Findings** — ordered by severity, then confidence. Grouped by issue type: the
   background and remediation appear **once** per type, with instances beneath. A finding
   carrying `occurrences` prints `×N` and where the others are; never let a reader fix the
   first one and close it.
4. **Hardening notes** — reported, explicitly not counted against the bar.
5. **In non-application code** — one block with a count per kind, not a line each. The
   one thing to carry out of it into the summary: any credential, because a key in a
   fixture is a key.
6. **Could not evaluate** — check, reason, what would unblock it.
7. **Verification** — how many findings someone independent has checked, and how many
   nobody has. Say the second number even when it is all of them.
8. **Coverage appendix** — what ran, what did not, what a higher tier would add, and the
   module grades from `sec modules` for anything the report leans on.

## The rules that keep it honest

- **A PASS with a non-empty ledger says so in its first line.** "No findings above the bar,
  but dependencies and business logic were not checked" is the honest sentence.
- **Never print a secret.** Type, location, length, four characters at most. Recommend
  rotation and treat it as compromised even if it has been removed from the working tree.
- **Name every assumption** the verdict rests on, and every suppressed finding with its
  reason — a wrong suppression must stay visible.
- **State the standards baseline.** WSTG v4.2 · ASVS 5.0.0 · OWASP Top 10 2025 ·
  API Top 10 2023 · OWASP Top 10 for LLM Applications 2025 · CVSS v3.1.
- **Do not inflate.** A short verified report beats a long speculative one. If three things
  are real and nine were noise, report three and say you dismissed nine.

## What to fix first

Order by what reduces risk fastest, not by the matrix:

1. Anything unauthenticated and remote with high impact.
2. Anything that is a single systemic cause with many instances — one fix, many closures.
3. Anything already exploited elsewhere in the industry (KEV, a live CVE).
4. The rest, by severity.

Say *why* the first item is first. "Fix the route ordering first because it is a two-line
change that closes four findings" is advice; a sorted table is not.

## Sharing it

If the user wants to send this to someone, offer to export it as a document. The audience
for that document is whoever they name, not the user — match its length and vocabulary to
that reader.

For a machine audience — a code-scanning dashboard, a pipeline, another team's tracker —
the run projects to SARIF 2.1.0 instead:

```bash
node <ai-sec>/bin/sec.mjs export --slug <slug> --out findings.sarif
```

Say what the projection loses. SARIF carries the finding and its location; the coverage
ledger, the verification state and the module grades are this tool's, and a dashboard
showing only the findings will read a thin run as a clean one — which is the thing this
whole bundle exists to prevent.

## Done when

- The plain-language summary stands on its own.
- Findings are grouped by type, ordered by severity then confidence.
- The ledger is present, and a PASS is qualified if it is non-empty.
- No secret, no unnamed assumption, no inflated severity.
