# ai-sec — design

**M0.** The sibling of [ai-perf](../../ai-perf/docs/design.md): same shape, same five pillars, same
rule that the deterministic part is code and the AI explains and judges.

---

## 1. What it is

AI-driven security assessment for any system, from a single repo to a running API. One flow takes
it from "what is this system, and what may I touch?" to a verdict a pipeline can trust:

`discover → scope → scan → merge → verify → score → report`

The unit of output is a **finding**, not a log line. Findings are deduplicated across scanners,
scored on two independent axes (severity × confidence), compared with a baseline, and reported with
an explicit statement of what could **not** be checked.

### Why it exists

Scanners are good at detection and bad at everything after it. They disagree on severity, repeat
each other, re-report known false positives every run, and present an empty result the same way
whether the code is clean or the parser crashed. The value is the layer above:

| Scanners already do | ai-sec does |
|---|---|
| Pattern and dataflow detection | Merge several scanners into one finding set |
| Per-tool severity | Rescore as impact × likelihood in **this** context |
| Flat result list | Severity × confidence, with confidence from the detection method |
| Re-report everything each run | Baseline: new / fixed / unchanged, with FP verdicts kept |
| Silence on what they skipped | A coverage ledger; `NOT_EVALUABLE` over a quiet pass |
| Raw output | A verdict a non-security reader can act on |

We do **not** write a detection engine. Semgrep, Trivy, Gitleaks, Nuclei and friends plug in as
adapters.

---

## 2. Boundaries

**Authorized targets only.** The user's own code, employer systems with authorization, staging, CTF,
and deliberately vulnerable practice apps. Never a third party, never production.

Test intensity is graded, and the grade is the authorization gate. Burp grades its audit checks
Passive / Light active / Medium active / Intrusive; we use the same idea with explicit tiers:

A tier grades what the traffic could **do**, not whether traffic exists. Burp's crawl makes
plenty of requests and is not an audit check at all; what it never does is send a payload.

| Tier | May send | Needs |
|---|---|---|
| **T0 Static** | nothing at all — reads code, config, manifests, schema | default |
| **T1 Read** | plain reads of known paths, as any client would: no parameters added, no payloads, no path guessing | target ownership confirmed |
| **T2 Light active** | a handful of benign requests that vary a parameter — a redirect canary, a header probe | authorized target in the allowlist |
| **T3 Medium active** | requests the app may well read as an attack: injection probes, fuzzing | explicit authorization, non-production |
| **T4 Intrusive** | requests that may modify or destroy data | explicit authorization, named scope, non-production, re-confirmed each run |

Out of scope, permanently: exploit development, denial of service, data destruction, persistence,
detection evasion, and any host not in the project allowlist. A finding is proved by the smallest
safe evidence — a version string, an out-of-band callback — never by damage.

**Secrets are never printed.** A discovered credential is reported as type, location and length,
with at most four leading characters. It is never written to a report, a baseline, a commit, a log,
or a tool argument, and never sent anywhere to test whether it still works.

### Relationship to the rest of the workspace

| Already exists | Does | ai-sec |
|---|---|---|
| `skills/threat-modeling` | finds threats before code | upstream of us |
| `skills/security-test-strategy` | plans security testing | upstream of us |
| `skills/designing-security-cases` | writes security test cases **inside the STLC pipeline** | parallel; STLC-bound |
| `skills/security-review` | the method, as a single skill | **becomes the skills in §5** |
| `stlc` security tier | a ZAP baseline and authz specs for one feature | enough for one feature; ai-sec is for the whole system, many scanners, and runs over time |

---

## 3. Users

- **The engineer** who wants to know what is wrong with their repo, in one command, without
  learning nine tools.
- **The QA/security engineer** who runs this per release and needs the diff against last time.
- **The pipeline**, which needs an exit code it can gate on.
- **The learner** — the reference material is part of the product, not a side effect.

---

## 4. Entry modes

| Mode | Entry |
|---|---|
| Fresh project | `/sec-start` — discovers, scopes, proposes, runs T0 |
| One command | `node bin/sec.mjs scan .` — defaults to T0, all applicable modules |
| Existing findings | `/sec-import` — bring a SARIF file from CI into the model (M4) |
| CI gate | `sec scan --ci`, exit code = verdict |
| Question | `/sec-help` — answers from project state, asks nothing |

---

## 5. Lifecycle and commands

| Step | Command | Skill | Writes |
|---|---|---|---|
| 1 Discover | `/sec-discover` | `discovering-attack-surface` | `context.json`, `surface.json` |
| 2 Scope | `/sec-scope` | `scoping-the-assessment` | `scope.json` (tier, allowlist, modules) |
| 3 Scan | `/sec-scan` | `running-scanners` | `runs/<id>/raw/<scanner>/…` |
| 4 Merge | (controller) | — | `runs/<id>/findings.json` |
| 5 Verify | `/sec-verify` | `verifying-findings` | updated confidence per finding |
| 6 Score | (controller + skill) | `scoring-findings` | severity, CVSS vector |
| 7 Report | `/sec-report` | `reporting-findings` | `result.json`, `report.md`, `verdict.md` |
| — | `/sec-doctor` | — | what is broken |
| — | `/sec-baseline` | — | promote a run to baseline |
| — | `/sec-learn` | `recording-lessons` | `lessons.md` → Recall |

Support skills: `reading-the-finding-model` (the shared vocabulary) and the five reference files
carried over from `skills/security-review` (`modules`, `taxonomy`, `scoring`, `tooling`,
`diagnostics`).

---

## 6. The adapter axes

Three axes, so a new tool never changes a skill (P5).

| Axis | Folder | Today | Later |
|---|---|---|---|
| **Scanner** | `adapters/scanners/` | `fake`, `semgrep`, `trivy`, `gitleaks` | `nuclei`, `zap`, `codeql`, `checkov`, `osv` |
| **Target** | `adapters/targets/` | `repo` | `image`, `url`, `k8s` |
| **Enricher** | `adapters/enrichers/` | `none` | `epss`, `kev`, `reachability` |

A scanner adapter exports:

```js
name, tool,                                   // tool enum in sec-result/v1
tiers,                                        // the tiers it is allowed to run at, e.g. ["T0"]
detect() → { ok, version, install? },
scanCommand({ runDir, target, options }) → { cmd, args, env?, timeout_s },
parse({ stdout, stderr, runDir }) → { findings[], coverage[], errors[] }
```

`parse` returns **three** things, and the third two are what make honesty mechanical:
`coverage[]` says what the scanner actually looked at (languages, file counts, rules loaded), and
`errors[]` says what it could not. A scanner that returns no findings and no coverage is
`NOT_EVALUABLE`, not clean.

---

## 7. Execute and collect

### 7.1 Why the AI is not in the loop

Same reason as ai-perf. The AI is good at judging a finding and bad at being a reliable gate:
a prompt cannot be mutation-tested. So every safety rule — production refusal, host allowlist,
tier ceiling, secret redaction, auto-stop — lives in `controller/rules.mjs` as code with a test
that breaks when the rule is removed (P4). The AI reads the output and explains it.

For T0 this is a batch pipeline, not a hot loop: spawn scanners, collect, merge. For T2+ the
controller owns the request loop and the auto-stop, and the AI is woken on events only.

### 7.2 Merging — the histogram analogue

ai-perf merges latency histograms and never averages percentiles. The same discipline here:
**findings are merged, never summed.**

```
fingerprint = sha256(type_id + normalized_location + insertion_point)
```

`normalized_location` is `file + enclosing symbol` where it can be resolved, so the fingerprint
survives edits that shift line numbers.

Merge rules, in order:

1. Same fingerprint → one finding. Never two.
2. Severity = the **highest** proposed, after rescoring, not an average.
3. Independent corroboration raises confidence: two scanners agreeing promotes `Tentative` →
   `Firm`. Agreement is only independent when the tools use different techniques; two regex
   scanners matching the same pattern is one piece of evidence, not two.
4. Every contributing tool is recorded in `sources[]`. A merged finding keeps every tool's raw
   location.
5. A tool's own severity is kept in `sources[].reported_severity` and is never the final severity.

### 7.3 Run state

| Terminal | When | Exit |
|---|---|---|
| `done` | every selected scanner ran and reported coverage | 0 |
| `degraded` | a scanner failed or timed out; its coverage is missing but others completed | 4 |
| `not_evaluable` | no scanner produced coverage, or the target could not be read | 3 |
| `aborted` | a gate refused, auto-stop fired, or the user stopped it | 5 |

Precedence: `aborted` > `not_evaluable` > `degraded` > `done`.

### 7.4 The coverage ledger

Every run writes what it did **not** cover, and the report prints it. Sources: scanner `coverage[]`,
languages present in the repo with no scanner that handles them, modules not selected, tiers above
the ceiling, and checks that need a running target when none was given.

This is the mechanism behind "never a quiet pass". `0 findings` with an empty ledger is a result;
`0 findings` with a full ledger is `NOT_EVALUABLE`.

---

## 8. Contracts

See [CONTRACTS.md](../CONTRACTS.md). `sec-result/v1` is SARIF-2.1.0-shaped on purpose: a `rules[]`
catalogue of issue types plus a `findings[]` list referring to them by `rule_id`. That is the same
two-layer model Burp and ZAP arrived at independently, and it means `sec export --sarif` is a
projection, not a translation.

---

## 9. Asking policy

Four tiers; only the last is a question.

| Tier | Source | Examples |
|---|---|---|
| 1. Read | repo, manifests, IaC, CI config, OpenAPI | languages, frameworks, routes, dependencies |
| 2. Detect | run a T0 scanner | what is actually there |
| 3. Safe default | tier T0, all applicable modules, `balanced`/`normal` | the defaults in §4 |
| 4. Ask | what no machine can know | who owns this host, is this environment production, am I authorized |

At most **three questions per step**, each with a proposed answer, multiple choice before free text,
asked at the step that needs it. "Don't know" is valid and becomes a logged assumption.

One exception that is never defaulted: **any tier above T0 requires an explicit answer.** Safety is
not a question we are allowed to guess, and the answer cannot come from a config file or a
subagent — only from the user.

---

## 10. Doctor and help

`/sec-help` answers "what now?" from project state and asks nothing. `/sec-doctor` answers "what is
broken?":

| Group | Checks |
|---|---|
| Machine | scanners installed and pinned, Node, Docker where needed |
| Project | `.sec/` files valid, baseline readable, stale baseline, open assumptions |
| Coverage | a language in the repo with no scanner that handles it |
| Safety | target in the allowlist, no production indicator, tier ceiling set, no secret in the config |
| Target | reachable, auth credentials present for the roles the scope names (T2+) |

Every doctor check has a fault-injection test: point at a production URL, plant a fake token,
uninstall a scanner, corrupt a baseline. The matching check must fail, or the doctor fails.

---

## 11. Operations

| Need | Mechanism |
|---|---|
| CI gate | `sec scan --ci`; exit code = verdict; fails on new Critical/High with Firm or better |
| Baseline | `sec baseline promote <run>`; only a `done` run |
| Diff | every report prints new / fixed / unchanged against the baseline |
| False positives | a verdict is recorded with a reason and scoped as narrowly as the evidence allows |
| Trend | `/sec-trend` across releases (M4) |
| Learning | lessons go to `lessons.md` and Recall; a lesson seen in two projects is proposed to the bundle |

---

## 12. Five pillars

| Pillar | Mechanism | Failing check |
|---|---|---|
| **P1 Intelligence** | the finding model; taint model (source/propagator/sanitizer/sink); merge rules; `references/diagnostics.md` — a symptom → root-cause catalogue (parameterized queries but cross-tenant reads → missing tenant predicate, not SQLi) | an exam of cases with known answers; the analysis must name the cause, not the symptom |
| **P2 Memory & Learning** | baseline per run; `lessons.md` read at the start of every step; FP verdicts carried forward | the second run cites the first run's baseline, reports new/fixed/unchanged, and does not re-report a recorded FP |
| **P3 Judgment & Integrity** | asking policy (§9); `NOT_EVALUABLE` over a guess; coverage ledger; `stlc` for a single feature | mutations: remove the SLO-equivalent (the scope), kill a scanner mid-run, point at an unreadable target, mismatch the environment — each must block or mark, never PASS |
| **P4 Verification & Safety** | gates in `controller/rules.mjs` at every step; production refused; host allowlist; tier ceiling; secret redaction; hard auto-stop | a mutation test per gate; a production URL is refused; a redacted secret never appears in any artifact |
| **P5 Value & Experience** | one-command start; `fake` scanner so Quick Start needs no installs; a verdict a non-security reader can act on; new scanners without flow changes; cost estimated before running | Quick Start on a clean machine; estimated vs actual cost recorded; adding a scanner changes no skill (measured by diff) |

---

## 13. Repository layout

```
ai-sec/
  README.md  CHANGELOG.md  VERSION  CONTRACTS.md
  bin/sec.mjs
  commands/             sec-*.md
  skills/               one folder per skill (§5), references/ inside
  controller/           rules, state, merge, fingerprint, redact, events
  lib/                  scan, verify, score, verdict, baseline, doctor, help, coverage
  adapters/scanners/    fake/  semgrep/  trivy/  gitleaks/
  adapters/targets/     repo.mjs  (image.mjs  url.mjs)
  schemas/              sec-result.v1.json, project file schemas
  tests/                unit, conformance per contract, exam, mutation runner
  mock/                 a deliberately vulnerable app, local only
  examples/quickstart/
  docs/                 design.md, evidence/
```

Node 20+, ES modules, **no runtime dependencies in the controller** — same rule as ai-perf, sdlc
and stlc. Scanners bring their own runtime.

---

## 14. Roadmap

Each milestone ends with its checks green and a local commit.

| Milestone | Delivers | Exit check |
|---|---|---|
| **M0 Design** | this document, CONTRACTS.md | Luan approves; §15 settled |
| **M1 Controller core** | `sec-result/v1`, fingerprint + merge, run state, the five gates, `repo` target, `fake` scanner, `sec doctor`, `sec scan` | conformance + **mutation test per gate**; a run with a killed scanner is `degraded`, never PASS |
| **M2 Real scanners** | semgrep, trivy, gitleaks adapters; normalization; `verdict.mjs`; baseline + lessons | end-to-end on the bundled mock; second run reports new/fixed/unchanged |
| **M3 Lifecycle skills** | the skills in §5, `/sec-start`, `/sec-help`, asking policy | asking-policy checks; adding a scanner produces no skill diff |
| **M4 Intelligence** | `tests/exam.test.mjs` with known-answer cases; `/sec-import` SARIF; `/sec-trend` | the exam passes; a planted defect set is found and named |
| **M5 Dynamic** | nuclei and ZAP adapters, `url` target, T2–T3, auto-stop in the loop | a run against the mock stops on the auto-stop rule in time |
| **M6 Dogfood** | run on a real repo; record what the AI got right and wrong | findings in `docs/evidence/` |

M1 and M2 are the bulk. M4 is where the pillars are proved rather than claimed.

---

## 15. Open decisions

| # | Question | Proposal |
|---|---|---|
| D1 | Project folder name — `.sec/` or `.ai-sec/`? | `.sec/`, matching ai-perf's `.perf/` |
| D2 | Does `sec-result/v1` live here or move to stlc as a shared standard, like `perf-result/v1`? | here for now; propose to stlc at M4 |
| D3 | Should the mock vulnerable app be written here, or should we point at OWASP Juice Shop? | write a tiny one here — pinned, offline, no Docker needed for Quick Start |
| D4 | Does the CI gate fail on new Medium findings, or only High and above? | High and above with confidence ≥ Firm; Medium warns |
| D5 | Where do lessons go — `lessons.md` only, or Recall too? | both, as ai-perf does |
