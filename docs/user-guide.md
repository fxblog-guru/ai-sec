# Using ai-sec

Written for: an engineer who has been pointed at this bundle and has to get a
security answer out of it today.

This is the practical guide. [`CONTRACTS.md`](../CONTRACTS.md) is the authority —
where this guide and the contract disagree, the contract is right and this file
has a bug.

To see the whole thing before reading about it, open
[`docs/showcase/pipeline.html`](showcase/pipeline.html) in a browser: ten sections,
one real scan of a real repository, and the findings it came back with.

---

## The one paragraph that explains the whole thing

Every number this tool prints is paired with what it could **not** check. A
scanner that is missing, crashed, timed out, did not understand your language,
or ran with one of its capabilities unusable does not disappear into a clean
result — it turns up in the coverage ledger of that run, and in the grade of the
module that was counting on it. Everything else here — the merge, the two axes,
the baseline, the benchmarks, the mutation suite — exists to keep that one
property true when nobody is watching.

A clean report from this tool means *"these scanners looked at these things and
found nothing"*. It never means *"this is secure"*, and the output is shaped so
you cannot mistake one for the other.

---

## Day one

```bash
node bin/sec.mjs doctor      # what is installed, what is missing, what that costs
node bin/sec.mjs status      # what is done, and the one next step
node bin/sec.mjs scan .      # T0: static, sends not a single packet
node bin/sec.mjs report      # the verdict and the findings
```

Needs Node 20+ and nothing else. Two scanners are built in: `builtin` reads
code, `probe` reads a live target. Semgrep, Trivy, Gitleaks, Nuclei and ZAP are
used **if they are on PATH** and reported as absent if they are not — `doctor`
tells you what each absence costs before you run anything.

`scan` with no tier is **T0**: it reads files and sends nothing. You do not need
authorization to read your own repository, which is why this is the default.

---

## Reading a report

The report has four parts and they are in this order on purpose.

### 1. The verdict

```
FAIL — 3 finding(s) at or above the bar (High)
```

The bar is severity. Two kinds of finding never reach it on their own:

- **hardening** — a defence that is missing rather than a defect that is
  present. Worth doing, never worth failing a build by itself.
- **non-application code** — anything in a test, fixture, example, generated or
  vendored file. It is reported, counted, and kept out of the bar.

That second rule is not cosmetic. Scanning OWASP Juice Shop produced **188
test-suite findings against 47 application ones**; a single list ordered by
severity put seed-data passwords above the SQL injection in the login route.

### 2. The findings

Each one carries **two axes**, and you need both:

| | |
|---|---|
| **severity** | how bad it would be — `Critical` … `Info` |
| **confidence** | how sure we are — `Certain` · `Firm` · `Tentative` |

`High / Tentative` and `High / Certain` are different jobs. The first needs
someone to look; the second needs someone to fix. Severity is **rescored in
context** and never copied from the tool, and when two scanners disagree the
report says so rather than quietly picking one.

Findings from several scanners are merged by **issue type** — the CWE family,
not the scanner's rule id — so `open-redirect` and
`javascript.express.security.audit.express-open-redirect` are one finding with
two sources. Independent corroboration is what raises confidence.

One cause reported in twenty places is **one finding with twenty
`occurrences`**, anchored at the cause. Twenty separate findings would make the
fix look twenty times bigger than it is.

### 3. The non-application block

```
In non-application code (192) — reported, not counted against the bar
  test: Hardcoded credential ×184, …
  a credential in a test file is still a credential — judge these, do not
  assume the path makes them safe
```

Read it. The grouping is there so the report is legible, not so the findings can
be ignored.

### 4. `Could not evaluate`

**This is the part most tools do not have, and the reason to use this one.**

```
Could not evaluate (5)
  - trivy: dependency CVEs: no lockfile or other resolvable manifest was found,
    so trivy has no package versions to match against its database — zero
    dependency findings here means nothing was read, not that nothing is
    vulnerable
  - builtin: unsupported-language: 3 python file(s): only 2 of 31 built-in rules
    apply to this language …
  - module M11: no scanner in this run contributes to it
```

Every entry names a gap and how to close it. A run that passes with a non-empty
ledger says so on its first line. If you read one section of a report, read this
one.

---

## When a finding is wrong, or already known

Nothing is deleted. Judgements are recorded and survive the next run.

```bash
# this is not a real problem here, and here is why
node bin/sec.mjs judge a1b2c3 false_positive "test fixture, never deployed"

# a human confirmed it by reproducing it
node bin/sec.mjs verify a1b2c3 confirmed --by luan --via reproduction "POST /x returns 200 as anon"
```

`judge` takes `open | fixed | false_positive | accepted_risk`. `verify` takes
`confirmed | needs_validation | rejected` — `needs_validation` **drops the
severity** and records what it would have been, which is the honest state of a
finding nobody has tried to break yet.

A reason is required, and a reason containing a credential is refused outright.
No secret is ever written to a report, a baseline, a commit or a tool argument.

---

## The second run

```bash
node bin/sec.mjs baseline promote     # this is the known state
node bin/sec.mjs scan .               # the next run is a diff
```

After a baseline, each run tells you **new**, **fixed**, and **unchanged**, and
does not re-report a false positive you already judged. A `degraded` run may not
become a baseline: you cannot freeze a picture that was taken with the lens
cap half on.

---

## "Is this module any good?"

```bash
node bin/sec.mjs modules
```

This is the command that separates this bundle from a rule count. Every module
is graded against a benchmark with **recorded answers**:

| Grade | Means |
|---|---|
| `measured` | Full marks against a corpus **nobody here wrote**. The only grade that can surprise us. |
| `self-measured` | Full marks against a benchmark we wrote. The weakest evidence there is. |
| `partial` | Found some planted defects, missed others. **The misses are named.** |
| `failing` | An engine ran and found none of them. |
| `blind` | An engine ran with a capability this module needed unusable here — trivy with no lockfile cannot read one package version. **A zero is not a clean result.** |
| `unmeasured` | Nothing has ever checked this module. **Not a pass.** |
| `no-engine` | No scanner contributes to it at all, and the blind spot is written out. |

Quote the grade when you quote the module. "M5 found nothing" means something
different depending on whether M5 is `measured` or `unmeasured`.

---

## CI

```bash
node bin/sec.mjs scan . --baseline .sec/default/baseline.json
echo $?
```

| exit | meaning |
|---|---|
| 0 | done · PASS · WARN |
| 1 | error, or FAIL |
| 2 | **refused** — a gate said no (production, host outside the allowlist, tier above the ceiling) |
| 3 | not evaluable — nothing produced coverage |
| 4 | degraded — something ran and something did not |
| 5 | aborted — an auto-stop fired mid-run |

Treat **4** as a build warning you investigate, not a pass. It is the exit code
that means *you did not get the scan you asked for*.

`sec export --out findings.sarif` projects a run to SARIF 2.1.0 for GitHub Code
Scanning, GitLab, or anything else that reads it. `sec import` brings another
tool's SARIF in, and it merges by the same CWE identity as everything else.

---

## Going above T0

T0 reads files. Everything above it sends traffic, and **the one thing this tool
never guesses is authorization**.

| tier | what it does |
|---|---|
| T0 | static. Sends nothing. The default. |
| T1 | plain reads of known paths, as an ordinary client would — no parameters added, no payloads, no path guessing |
| T2 | a handful of benign requests that vary a parameter: a redirect canary, a header probe. Nothing the application could read as an attack |
| T3 | requests the application may well read as an attack — injection probes, fuzzing |
| T4 | requests that may modify or destroy data |

Raising the ceiling is a **human editing `.sec/<slug>/scope.json`** — not a
flag, not a prompt, not something an agent can talk its way into. A scan above
the ceiling is refused with exit 2 and a named gate, and the refusal tells you
which line of which file would have to change.

Authorized targets only: your own code, employer systems with authorization,
staging, CTF, deliberately vulnerable practice apps. Never a third party, never
production. No exploit development, no denial of service, no data destruction,
no detection evasion. A finding is proved by the smallest safe evidence, never
by damage.

---

## Where everything lands

```
.sec/<slug>/
  scope.json                  tier ceiling, allowed hosts, authorization — human-edited
  baseline.json               the known state, plus every judgement and verification
  lessons.md                  what this project learned, dated
  runs/<run-id>/
    run.json                  the normalised spec: exactly what was asked for
    result.json               the whole result (sec-result/v1)
    findings.json             merged findings
    coverage.json             the ledger — what was and was not examined
    state.json                the terminal state and why
    events.ndjson             one line per event, in order
    raw/<scanner>/            stdout, stderr, exit code, parsed output — untouched
```

`raw/` is kept so any claim in a report can be traced back to the tool that made
it. If a finding and the raw output disagree, the raw output is the fact.

---

## What this does not do

Say this part out loud to whoever asks for the report.

- **It is not a pentest.** It writes no exploits, and the dynamic tiers have
  been exercised against a local benchmark, not against real infrastructure.
- **Business logic is out of reach** (M11, `no-engine`, permanently). Abuse
  cases, pricing flaws, workflow bypasses — the defects that cost real money —
  need a human who understands the intended flow.
- **No mobile, no cloud posture, no container runtime, no SBOM or provenance,
  no fuzzing, no threat modelling, no privacy or PII data-flow analysis, no
  network or TLS review, no compliance evidence.** Each of those is a different
  discipline, and none of them is here.
- **It has one profile.** A mobile banking app and an internal CRUD tool get the
  same fourteen modules. Choosing the approach per project is still yours.
- **Nobody outside this project has reviewed it.** That, not a missing feature,
  is the largest gap in its evidence.

It is a tool for someone who can read the output. It is not a button that tells
a person who cannot whether they are safe.

---

## Where to go next

| | |
|---|---|
| [`CONTRACTS.md`](../CONTRACTS.md) | the authority — every format and every rule above |
| [`docs/security-coverage-map.md`](security-coverage-map.md) | thirty-two security layers, who owns each, and what nothing here covers |
| [`docs/roadmap.md`](roadmap.md) | the three gaps that outrank every missing rule, and what is next |
| [`docs/mutation-testing.md`](mutation-testing.md) | what the 141 gates actually hold, read as a specification |
| [`docs/skill-sources.md`](skill-sources.md) | standards, corpora, tools, licences — nothing third-party is vendored here |
| [`SECURITY.md`](../SECURITY.md) | what this runs on your machine, and how to report a flaw in it |
| [`UPGRADE.md`](../UPGRADE.md) | before you upgrade a project that already has a baseline |
| [`CONTRIBUTING.md`](../CONTRIBUTING.md) | adding a rule, a scanner or a module |
