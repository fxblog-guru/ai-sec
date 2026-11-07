---
name: verifying-findings
description: The adversarial pass that decides report quality - try to disprove each candidate finding, then set its final confidence and severity from what survived. Covers the disproof checklist, the symptom-to-root-cause catalogue, and scoring as impact x likelihood. Use when /sec-verify runs, after a scan produces candidates, or when a finding's severity or confidence needs deciding.
version: 1.1.0
---

# Verifying findings

Read `sec-protocol` first.

This is the phase that decides whether the report is worth reading. False positives are
the main failure mode of every scanner ever built, and the only cure is trying to prove
each candidate wrong.

**A candidate is guilty of being a false positive until you cannot make it one.**

## The disproof checklist

For each candidate, in this order. Stop at the first "yes" — it is not a finding.

1. **Is the sink reachable from untrusted input?** Trace backwards to a source. A sink fed
   only by constants, enums or a hardcoded config is not a finding.
2. **Is there a sanitizer on the path?** Parameterization, context-aware encoding,
   allowlist validation, a safe parser, coercion to a non-string. Framework-level escaping
   counts — and so does the escape hatch around it.
3. **Is it in test, mock, fixture, example, vendored or dead code?** The controller
   answers this one for you now — `code_role` is on every finding, non-application
   findings are capped at `Tentative`, grouped into their own block and kept out of the
   verdict. What is left for you is the part a path cannot settle: **a credential in a
   test file is a credential.** Judge those on whether the value is live, not on where it
   sits. Everything else in that block is usually dropped, and you say so.
4. **Does the installed version actually fall in the CVE's affected range?** Scanners match
   manifest ranges, not resolved versions. This is where most dependency noise dies.
5. **Is the vulnerable code path ever called?** A CVE in a function the app never invokes
   is a maintenance item, not a vulnerability.
6. **Does the path survive the real auth and tenancy checks?** A route reachable only by an
   admin who could already do the thing is not an escalation.

If it survives all six, it is a finding. Record *which* check established it — that is
what sets confidence.

## Setting confidence

From the detection technique alone, never from how bad it would be:

| What you established | Confidence |
|---|---|
| The pattern is there; you did not trace the source | `Tentative` |
| One tool said so and you did not corroborate | `Tentative` |
| You traced source → sink and found no sanitizer | `Firm` |
| You read the config and it says the weak thing | `Firm` |
| Two tools using different techniques agree | `Firm` |
| You reproduced it, or the code path is complete and unambiguous | `Certain` |

**Downgrade honestly.** Static analysis of a dynamic language without runtime confirmation
caps at `Firm`. If you could not establish reachability, it is `Tentative` and you say
which step you could not complete.

## Setting severity

Impact x likelihood, then sanity-check against a CVSS v3.1 vector.

- **Impact** — RCE, full data access or auth bypass is HIGH; limited data or single-record
  tampering is MEDIUM; information disclosure alone is LOW.
- **Likelihood** — unauthenticated and remote is HIGH; needs a valid low-privilege account
  is MEDIUM; needs admin, local access or an unlikely precondition is LOW.

| | Impact HIGH | Impact MEDIUM | Impact LOW |
|---|---|---|---|
| **Likelihood HIGH** | Critical | High | Medium |
| **Likelihood MEDIUM** | High | Medium | Low |
| **Likelihood LOW** | Medium | Low | Low / Info |

Most real findings are Medium. If everything in your report is High, you have not scored
anything — you have ranked by alarm.

## Name the cause, not the symptom

`references/diagnostics.md` in the `security-review` skill is the catalogue. The ones that
come up most:

| What you see | The wrong call | The actual cause |
|---|---|---|
| Parameterized queries, yet one tenant reads another's rows | "SQLi somewhere" | **Missing tenant predicate.** Parameterization binds values; it says nothing about which rows return. |
| A guard exists in the file, yet the route is open | "The role check is wrong" | **Registration order.** The route is mounted above `router.use(guard)`, so the guard never runs for it. |
| A WAF blocks payloads, yet an attacker reads others' records | "WAF covers us" | **Broken object-level authorization.** The request is well-formed; there is nothing to match on. |
| Login is rate-limited, accounts still get taken over | "Brute force is handled" | **An alternative channel** — reset, OTP, a legacy or mobile endpoint. |
| Framework auto-escapes, yet XSS fires | "Templating protects us" | **A raw-render escape hatch**, or a non-HTML context where HTML escaping does not apply. |
| Secrets were rotated out of the code | "The leak is closed" | **History, CI logs and forks still have them.** Removal is not rotation. |

## Collapse systemic findings

When several findings share a shape, report the shape once with the instances beneath it.
Its severity is that of its **worst** instance, not an average.

Six routes missing authorization is not six findings — it is one: *authorization is opt-in
in this codebase; there is no default-deny enforcement point.* The remediation is different
too, and better.

## The checklist above is not verification

Everything up to here is you re-reading the reasoning that produced the candidate. That is
triage, and it is necessary. It is not the same as somebody independent trying to break
the finding, and the report keeps the two apart:

```bash
node <ai-sec>/bin/sec.mjs verify <fingerprint> <confirmed|needs_validation|rejected> \
  --by <who> [--via <method>] "<reason>"
```

**The one who checks is never the one who found it.** The controller refuses a
verification whose verifier is a tool that reported the finding — a scanner agreeing with
itself is not corroboration, and neither is a reader re-reading their own trace. It also
refuses an anonymous verdict: independence that cannot be attributed is not independence.

| Verdict | What it does to the finding |
|---|---|
| `confirmed` | Confidence becomes what the method earns. Needs `reproduced` or `out-of-band` — **`source-trace` cannot confirm**, because reading the code is how the candidate was produced. |
| `needs_validation` | Severity is **dropped** and kept as `potential_severity`. A severity is a claim about demonstrated impact, and a blocked hypothesis has demonstrated nothing. |
| `rejected` | Status becomes `false_positive`, with the reason recorded. |

`--via` names how it was established: `reproduced`, `out-of-band`, `source-trace` or
`manual-review`. The last two record real work and still cannot confirm — they say a
person looked, not that a boundary was crossed. Omitted, it defaults to `manual-review`,
which is why `confirmed` without a `--via` is refused rather than quietly accepted.

If you cannot reproduce it, `needs_validation` with what blocked you is the honest record.
Recording `confirmed` from a careful read is the exact failure this gate exists to stop.

A finding nobody has tried to break stays `unverified`, and that is never a pass on its
own — it is the same silence as an empty coverage ledger, and it matters most on a FAIL.

## Record the dismissal too

A finding you dismissed is worth keeping. Record it so the next run does not re-litigate it:

```bash
node <ai-sec>/bin/sec.mjs judge <fingerprint> false_positive "migrations take no user input"
```

`judge` is your disposition of a finding; `verify` is somebody's independent verdict on
whether it is real. Keep them separate — collapsing them is how "I looked at it" became
"it was confirmed".

Scope the dismissal as narrowly as the evidence allows — this instance, not the whole rule,
unless you verified every instance.

## Done when

- Every candidate has been through the checklist, and you can name which step settled it.
- Confidence matches the technique, with nothing promoted above its evidence.
- Systemic findings are collapsed, with instances grouped beneath — and a finding with
  `occurrences` names every place, because fixing the first does not close it.
- Dismissals are recorded with reasons.
- Anything still `unverified` is counted and said out loud, not left to be assumed real.
