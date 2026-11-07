# Verification — the reader who tries to disprove

A finding that nobody has tried to break is a candidate, not a result.

ai-sec can produce findings and score them. What it has never had is a step whose
job is to **fail** a finding: everything from `scan` onwards treats a reported
defect as real until a human types `judge <fp> false_positive`, which is an
opt-out that costs effort exactly when the finding is wrong.

This is the one place `cloudflare/security-audit-skill` is clearly ahead, and its
rule is worth copying verbatim:

> The agent that checks a finding is never the agent that found it.

## The shape

Three verdicts, not two. A finding is `unverified` until somebody says otherwise.

| verdict | means | may carry severity |
|---|---|---|
| `confirmed` | a boundary is crossed, with evidence that stands on its own | yes |
| `needs_validation` | a specific hypothesis, blocked on a fact nobody could settle | no |
| `rejected` | disproved, with the reason recorded | no |

`needs_validation` carrying **no severity** is the part that bites, and it is the
point. `Critical / Tentative` is a priority claim about something nobody has
established — and this project has already shipped two of them: a dropdown label
read as a hardcoded credential, and a PKCE challenge read as a stored password.

## What the controller enforces, and what it does not

The judgement is the reader's. The rules around it are code, so they can be
mutation-tested:

1. **A verification names its verifier**, and the verifier may not be the tool
   that reported the finding. Independence is the whole mechanism; a scanner
   agreeing with itself is not corroboration (CONTRACTS §7, merge rule 4).
2. **`confirmed` requires evidence of a kind that can establish it** — a
   reproduction or an out-of-band interaction. This is the same rule that already
   governs `confidence: Certain`, applied one layer up. A pattern match cannot
   confirm anything, however confident the reader feels.
3. **A verdict carries a reason**, and a `rejected` finding keeps it in the
   baseline, so the next run does not re-ask a question already answered.
4. **Nothing is confirmed by default.** A run with no verification is reported as
   unverified, not as clean — the same rule as the coverage ledger, applied to
   findings instead of checks.

## Why this is not just `judge`

`sec judge` records a dismissal. It is one-directional: it exists to silence
false positives, so the only verdict it can express is "ignore this". Nothing
records that a finding **was** checked and **did** hold, which means a confirmed
finding and an unexamined one are indistinguishable in the report, in the
baseline, and in CI.

That asymmetry is why unverified findings accumulate: dismissing costs a command,
confirming costs nothing and gains nothing.

## Status

Designed, not built. The remaining work is a `verification` field on the
instance, `sec verify`, the independence and evidence rules in `controller/`, and
a skill that briefs the verifier with the finding and **not** with the reasoning
that produced it — an agent handed a hypothesis tends to return it confirmed.
