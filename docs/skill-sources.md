# Provenance — where the knowledge, the corpora and the tools come from

Written for: someone who needs to know what in this bundle is ours, what is
somebody else's, and under what terms.

The short answer: **no third-party code is vendored here.** Not a line. What this
repository contains is its own engine, its own rules, and answer keys it wrote for
code other people maintain. Everything external is either a published standard it
speaks, a tool it detects on `PATH`, or a corpus it clones read-only and never runs.

Licences below are as published by each project at the time of writing
(2026-11-01). Re-check before redistributing anything.

## Standards the vocabulary comes from

Every finding is classified in these, and the exact editions are stated in every
report because standards move. They are vocabulary, not evidence of a control
(row 31 of [`security-coverage-map.md`](security-coverage-map.md)).

| Standard | Edition | Used for | Terms |
|---|---|---|---|
| OWASP **WSTG** | v4.2 | what a test of this kind is called | CC BY-SA 4.0 |
| OWASP **ASVS** | 5.0.0 | the requirement a finding fails | CC BY-SA 4.0 |
| OWASP **Top 10** | 2025 | the category in a report's summary | CC BY-SA 4.0 |
| OWASP **API Security Top 10** | 2023 | API-shaped findings (M7) | CC BY-SA 4.0 |
| OWASP **Top 10 for LLM Applications** | 2025 | M14 — prompt injection, output handling, agent authority | CC BY-SA 4.0 |
| **CWE** | MITRE | **the merge identity** — two tools report one defect when the CWE family agrees | MITRE terms of use |
| **CVSS** | v3.1 | the sanity check on a severity derived as impact × likelihood | FIRST.org |
| **SARIF** | 2.1.0 | `sec export` / `sec import` | OASIS standard |

CWE does more work here than the rest combined: it is not a label, it is the key
findings merge on (`controller/taxonomy.mjs`, `CONTRACTS §7`). A rule with no CWE
cannot corroborate anything.

## The finding model

`Severity × Confidence` with a two-layer record — a reusable **issue type** (name,
background, remediation, classification) and a per-instance finding (location,
evidence, confidence) — is the model Burp Suite and OWASP ZAP both use. The shape is
theirs, and it is a convention rather than anyone's property; no code or content was
taken. We adopted it for one reason: a single severity-ordered list cannot express
"serious if real, and nobody has checked", and that is the most common state a finding
is actually in.

What was changed: severity is **rescored in context** and a tool's own rating is kept
in `sources[].reported_severity` and never used as the answer; `Certain` is reachable
only by reproduction or an out-of-band signal, never by reading code
(`controller/verification.mjs`, and five mutations hold it).

## Corpora — cloned, scanned at T0, never run, never vendored

| Corpus | Who wrote the code | Who wrote the answers | Licence |
|---|---|---|---|
| **OWASP NodeGoat** | OWASP | us, from its own tutorial text | Apache-2.0 |
| **OWASP Juice Shop** | OWASP | **the corpus itself** — `// vuln-code-snippet vuln-line` markers, read back by `benchmarks/juiceshop.mjs` | MIT |

Both are deliberately vulnerable applications. They are cloned on demand into an
ignored directory, read at **T0**, and **never started** — launching one is starting a
vulnerable server on your machine. What is committed here is the answer key
(`benchmarks/*-expected.json`), not their source.

Juice Shop is the strongest evidence this project has, for a reason worth stating:
**we did not write its code and we did not write its answers.** Re-deriving the key
from its own markers is the only arrangement here in which a benchmark can contradict
us ([`benchmarks/README.md`](../benchmarks/README.md)).

`mock/` and `benchmarks/dynamic/` are ours, and are capped at `self-measured` for
exactly that reason. A fixture you wrote cannot surprise you.

## Tools — detected on `PATH`, never bundled, never downloaded

Nothing here installs a scanner for you. `detect()` asks whether it is present;
`sec doctor` prints what each absence costs before a run.

| Tool | Modules it serves | Licence |
|---|---|---|
| **semgrep** | M1, M6 — taint and pattern analysis beyond the built-in rules | LGPL-2.1 (OSS CLI) |
| **trivy** | M2 dependency CVEs, M10 IaC misconfiguration, secrets | Apache-2.0 |
| **gitleaks** | M3 committed credentials | MIT |
| **nuclei** | template-based checks against a live target | MIT |
| **OWASP ZAP** | a passive DAST baseline | Apache-2.0 |

Their output is parsed by our adapters (`adapters/scanners/<tool>/adapter.mjs`) into
`sec-result/v1`. **No tool's severity survives the parse**, and a tool's absence is a
line in the coverage ledger rather than a silent zero.

Two are unproved on this machine and said so in the coverage map: the ZAP installer
needs elevation and has never run here, and this environment refuses to execute
nuclei. Their adapters are covered by unit tests; the **measurement does not exist**,
and no grade claims otherwise (rows 23 and 24).

## Inside this workspace

| From | What came across | Changed how |
|---|---|---|
| `skills/security-review` (and its `references/`: `modules.md`, `taxonomy.md`, `scoring.md`, `diagnostics.md`, `tooling.md`) | the module structure M1–M14, the taxonomy, the scoring anchors, and the symptom → root-cause catalogue | turned from a skill a human follows into a **controller with gates**: the modules became a graded scorecard, the scoring anchors became rescoring code, and the diagnostics became structural checks that can fail |
| `skills/threat-modeling`, `skills/security-test-strategy` | upstream of this bundle — threats and plan before code | not imported; named as the step before a scan |
| `stlc` (`TC-SEC`) | the sibling that attacks what is *deployed* — a ZAP baseline and a Playwright authorization matrix | not imported; the seam is SARIF, and it is one-directional until someone runs `import` |
| `ai-perf` | the bundle this one is modelled on — adapters, run folder, coverage ledger, mutation runner | the same architecture with a different question: ai-perf asks "is it fast enough", this asks "what could not be checked" |

## Read, deliberately not adopted

- **A rule pack copied from another scanner.** Rules here are written against a
  benchmark answer, with a fixture that must flag and a fixture that must not. Importing
  a few hundred unmeasured patterns would raise the rule count and lower the meaning of
  every grade.
- **An LLM as the judge of a finding.** `confidence` is derived from corroboration and
  from reproduction, never from a model's opinion. A verifier that cannot be the finder
  is a gate (`verifier-may-be-the-finder`); an unauditable judge would be neither.
- **Auto-remediation.** Nothing here edits application source. The remediation text is
  advice to a person who can read the diff.
- **Exploit generation, DoS and evasion.** Out of scope by design, not by configuration
  — see [`SECURITY.md`](../SECURITY.md).

## Keeping this current

Standards move and this file rots quietly. Three things to re-check each release:

1. The editions in the table above, against what `skills/sec-protocol/SKILL.md` and
   every report header state — they must agree; the reports say the edition precisely
   so a stale one is visible.
2. The licence of any tool that gained a module.
3. Whether a corpus has changed its planted defects. Juice Shop re-derives its key from
   the corpus, so a change shows up as a benchmark diff; NodeGoat's key is ours and
   will not notice on its own.
