# M15 — the first findings that came from asking the server

2026-10-31. Every module up to here was graded by reading files. This one sends
requests, and the first thing it found was a defect in the merge. Then M14 was
pointed at a real AI application for the first time and reported nothing at all,
which turned out to be the more interesting result.

---

## 1. What was actually being measured

Before this, the strongest claim the scorecard could support was:

> M5 found the IDOR in NodeGoat.

What that sentence meant, unpacked, was that a regular expression recognised the
shape of a handler which takes an identifier from the URL and does not appear to
compare it to anything. That is a reasonable thing to report. It is not the same
as knowing the server hands one customer's order to another, and the difference
is the whole distance between a candidate and a finding.

`benchmarks/dynamic/` closes it for the modules it can reach. It starts a
deliberately vulnerable server on an ephemeral loopback port, scans it at T2,
and scores what comes back. Ten planted defects, nine of them observable in a
single response, one of them only observable by comparing two.

```
                engines  planted  found  reported  unaccounted  grade
  M1            2/3        1      1         1            0  self-measured
  M3            5/7        7      7        19            0  self-measured
  M4            3/5        1      1         1            0  self-measured
  M5            2/3        1      1         1            0  self-measured
  M7            3/3        1      1         3            0  self-measured
  M8            1/1        1      1         1            0  self-measured
  M9            3/5        5      5        13            0  self-measured
  M13           2/3        1      1         1            0  self-measured
```

`self-measured` and not `measured`, because we wrote the target. What this
benchmark adds is the **kind** of evidence, not its independence. NodeGoat is
still the only thing here that can surprise us.

## 2. The IDOR, as a comparison

The cross-account check is the only one in `probe` that needs something the
operator has to supply: two sessions, and an object the first one owns. It sends
three requests, and the order matters.

| request | why it is there |
|---|---|
| as the owner | establishes what the object looks like when the right person asks |
| **with no session** | the control |
| as the other account | the test |

The control is the part that is easy to leave out and expensive to leave out. If
the object comes back to a request carrying no cookie at all, then a second
account reading it proves nothing about authorization *between* accounts — it is
public, which is a different defect with a different fix on a different line.
Without the control, `probe` would have reported "cross-account object read" and
sent someone to add an ownership check to an endpoint that has no login.

The evidence is a digest, not the data:

```
GET /api/orders/1 as "bob" → 200, identical to the owner's response:
sha256:2506f377e7e5 (61 bytes; the body is another account's data and is not
reproduced here)
```

A report is read by people who are not entitled to that body. Quoting it would
make the finding the leak. The session cookies travel in the environment rather
than argv for the same reason, one layer down.

### The benchmark has two endpoints that are correct

`/api/profile/:id` is the orders handler with one more line, and answers 403 to
the wrong account. `/api/inbox` answers **200 to everybody**, and returns that
account's own messages.

The second one is the one that matters. A check that reads the status code and
stops gets `/api/profile` right by accident, and reports `/api/inbox` as a
cross-account failure. Comparing the bodies is what tells them apart, and the
mutation `cross-account-ignores-the-body` fails the suite on that endpoint
alone.

## 3. What it broke: the family was swallowing findings

The first run reported **four** of seven planted header defects and called the
other three missed. Nothing had gone wrong with the checks — `probe` produced all
seven. The merge then threw three away.

```
missing-csp               CWE-1021   at /
missing-frame-protection  CWE-1021   at /     → same family, same location, merged
missing-referrer-policy   CWE-200    at /
technology-banner         CWE-200    at /     → same family, same location, merged
```

Cross-tool identity is built on CWE **families**, deliberately: semgrep calls an
MD5 password hash CWE-327 and we call it CWE-916, and without the family those
never merge. The family is right for that. It is wrong here, because a missing
`Referrer-Policy` and an `X-Powered-By` banner are two defects with two fixes
that happen to share a classification and a URL.

Two changes, because the first one only helps adapters that remember to use it:

- **`subtype`** — an optional discriminator in the fingerprint, naming the
  defect rather than the rule, so our `missing-referrer-policy` and ZAP's
  `10063` still merge while the banner stays separate. Appended to the
  fingerprint only when present, so nothing that existed before this changed
  identity.
- **`collapsed`** — when one tool contributes two of its own rule names to one
  merged finding and neither declared a subtype, the merged finding records both
  and the coverage ledger counts it. The family still wins the merge. What it
  may not do is win it quietly.

This is the same failure as every other one in this project's history: **a rule
read something that was absent and passed.** Here the absent thing was any
notion that two defects could share a family, a location and nothing else.

## 4. nuclei: installed, and still unable to run

nuclei has no winget package, and the environment refuses to execute a binary
downloaded from a release page — correctly. The remaining route is the published
container, which is now pinned in the adapter and detected by reading the local
image store (`docker image inspect`, which does not pull and does not run
anything: detection must not execute the thing it is detecting).

And then it still cannot run here, for a reason worth writing down:

> Inside a container, `127.0.0.1` is the container.

The usual workaround is to rewrite the target to `host.docker.internal`. The
adapter will not do it. The host allowlist is checked against the name the user
wrote; rewriting it sends traffic to a host nobody authorized, and a scanner
choosing its own target is the one thing this tool is built not to do. So
`preflight` refuses, and the refusal is a line in the coverage ledger instead of
a zero in a report.

That required a distinction the controller did not have:

| question | answered by |
|---|---|
| is it installed? | `detect` |
| can it run **against this target**? | `preflight` |

Conflating them is how a scanner reports no findings against something it never
touched. A skipped scanner now also stops counting toward module coverage —
otherwise M3, M7, M9 and M10 were "covered by nuclei" in a run where nuclei did
nothing.

### ZAP had the same disease, with a louder symptom

The distinction was built for nuclei and immediately found a second case. ZAP
has two installs that share a name and almost nothing else:

| install | what is on PATH | has a passive mode |
|---|---|---|
| container, Linux packages | `zap-baseline.py`, `zap-full-scan.py` | yes — baseline is passive |
| desktop (`winget install ZAP.ZAP`) | `zap.bat` | **no** |

`detect` had asked "is any zap command present". On a desktop machine it found
`zap.bat`, reported installed, and then every scan died on `zap-baseline.py
ENOENT` — which degrades a run rather than explaining one.

The fix is not to call `zap.bat` instead. `zap.bat -quickurl` spiders the target
and then actively attacks it, whatever tier asked for it. Answering a **T1**
request that way would attack a host the operator authorised us only to read,
which is the one failure mode this tool exists to prevent. So `preflight`
refuses T1 on a desktop install, names why, and says what would unblock it —
and `scanCommand` only emits the `-quickurl` form for T3, where an active scan
is what was authorised.

Two mutations guard it: `desktop-zap-pretends-to-be-passive` makes `preflight`
return `ok` for a desktop install at T1, and `zap-runner-unknown` makes
`resolveZap` stop recognising the packaged wrappers. Both are killed.

It is worth being plain about what this is **not**: ZAP contributed no finding
to any run here. The winget install needs elevation and failed on this machine,
so the desktop path is proved by unit tests with an injected `spawn` — nothing
was executed — and the packaged path needs the container. ZAP is still an
unmeasured scanner. What changed is that it now says so.

## 5. Then M14 met an application nobody here wrote

The other thing M14 had never been pointed at was real AI code. NodeGoat predates
all of it, and `mock/app/assistant.js` is ours. So: a shallow clone of
`vercel/ai-chatbot`, 169 files, read only at T0, never run.

**Zero findings. A `done` run. An empty ledger.**

The application makes eleven model calls. Every call shape M14 knew was an
OpenAI, Anthropic or Google one — `.chat.completions.create(`,
`.messages.create(`, `generateContent(` — and this application uses the Vercel
AI SDK, where the same thing is written `streamText({...})`. Not one M14 rule
could fire, and nothing anywhere said so.

This is the Go repository again, exactly: 1005 files, zero findings, a ledger
with nothing in it, because the rules were written for a language the target was
not in. The fix is the same shape as that one was:

- `MODEL_CALL` is now one exported pattern covering the SDK vocabularies, used
  by the rules **and** by the engine.
- `unreachedModelSdks` — a file that imports a model SDK is evidence there is
  something to check. Recognising no call in any such file is evidence we did
  not check it, and it becomes a coverage-ledger gap naming what to add.
- `SOURCE_RE` learned the Web `Request` that Next.js, Hono and Remix hand a
  route handler. Nothing in a real Next.js codebase matched the Express shapes,
  so every `taint: true` rule had been silent over a codebase full of request
  data.

With the shapes added, the same scan reports **nine model calls with no output
or time ceiling**, across eight findings. All nine were read by hand: none of
them sets `maxOutputTokens`, a timeout or an `abortSignal`. Nine true positives,
no false ones, at `Low` and classed `hardening`, which is the right weight — it
is a billing and availability concern, not a way in.

### And one more thing the merge was losing

Two of those nine are in the same handler object, forty lines apart. The
fingerprint prefers `file#symbol` over `file:line` so that it survives an edit
above it — so both calls had one fingerprint, and the report showed one. Someone
would have set a ceiling on the first `streamText` and closed the finding.

Merging them is right; losing the line is not. A merged finding now carries
`occurrences`, and the report prints `×2` and where the other one is.

### What it still cannot see

The untrusted text that reaches those prompts arrives as a handler argument from
another module — `document.content`, `title`, `description` — and no regular
expression crosses a call boundary. So indirect prompt injection in this
application is **not** found, and that is now written into
`STATIC_BLIND_SPOTS.M14` rather than implied by a zero.

## 6. Numbers

| | before | after |
|---|---|---|
| benchmarks | 2 (both static) | **3** (one dynamic) |
| corpora nobody here wrote | 1 (NodeGoat) | **2** (+ an AI application) |
| tests | 369 | **416** |
| mutations | 93 | **114** |
| findings produced by sending a request | 1 (open redirect) | **10** |
| modules with dynamic evidence | 0 | **8** |

## 7. What this still does not prove

- The dynamic target is ours. Recall against code we did not write is still
  NodeGoat's job, and NodeGoat is static.
- M11 (business logic) has no engine and will not get one. No scanner can decide
  whether a discount should have applied.
- M14's **precision** on external code is now 9/9 on one application. Its
  **recall** there is unknown and partly known to be zero: the indirect
  injection above is real and unreported.
- Nothing here has been verified by a second party. `sec verify` exists; every
  finding in these runs is `unverified`, and the verdict says so.
