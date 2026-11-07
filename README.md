# ai-sec

**v0.18.0 — M18** ([showcase](docs/showcase/pipeline.html) · [user guide](docs/user-guide.md) · [coverage map](docs/security-coverage-map.md) · [roadmap](docs/roadmap.md) · [changelog](CHANGELOG.md) · [contracts](CONTRACTS.md) · [design](docs/design.md)) · runs in **Claude Code**

Contributing: [CONTRIBUTING.md](CONTRIBUTING.md) · [mutation testing](docs/mutation-testing.md) · [provenance](docs/skill-sources.md) · [SECURITY.md](SECURITY.md) · [UPGRADE.md](UPGRADE.md)

AI-driven security assessment for any system, from a single repo to a running API. One flow takes
it from "what is this, and what may I touch?" to a verdict a pipeline can trust:
discover → scope → scan → merge → verify → score → report.

The sibling of [ai-perf](../ai-perf): same shape, same five pillars, same rule that the
deterministic part is code and the AI explains and judges.

## What it does

- **Works on a clean machine.** Two scanners are built in and need nothing installed: `builtin`
  reads code, `probe` reads a live target. Semgrep, Trivy, Gitleaks, Nuclei and ZAP plug into
  the same adapter protocol (CONTRACTS §3) and are used when present. We do not write a
  detection engine — the value is the layer above one.
- **One finding set**: results from several scanners are merged by **issue type** — the CWE family,
  not the scanner's rule id — so `open-redirect` and
  `javascript.express.security.audit.express-open-redirect` are one finding with two sources, not
  two findings. Severity is rescored in context and never taken from the tool; when scanners
  disagree the report says so instead of quietly picking one. Independent corroboration is what
  raises confidence.
- **Two axes, not one**: every finding carries **severity** (how bad) and **confidence** (how sure,
  derived from the detection method). A `High / Tentative` is a different job from a `High / Certain`.
- **Safe by code**: a deterministic controller owns the gates. It refuses production, hosts outside
  the allowlist, and any tier above the one the project authorised. Secrets are redacted before
  anything reaches disk. The AI explains and judges; it never sits in the hot loop.
- **Honest results**: a scanner that crashed, timed out or does not handle your language makes the
  run `degraded` or `not evaluable` — never a quiet pass. Every run prints what it could **not**
  check.
- **Measured, not claimed**: `sec modules` grades every module against a benchmark with recorded
  answers — three of them, because they answer different questions. `mock/` is ours and can only
  earn `self-measured`. OWASP NodeGoat and OWASP Juice Shop are code we did not write, so they
  can surprise us — and Juice Shop's answers are its own, annotated line by line in its
  source, so even the question was not ours to choose. The
  dynamic benchmark starts a vulnerable server and scans it, so a grade there rests on a request
  and its answer rather than on a pattern that matched. A module nothing has checked reads
  `unmeasured`, which is not a pass; a module whose engine ran with the capability it needed
  unusable reads `blind`, which is not a pass either.
- **Knows what is not the application.** A finding in a test, fixture, example, generated or
  vendored file is reported and counted, and never fails a build on its own. Scanning Juice
  Shop produced 188 test-suite findings against 47 application ones; one list ordered by
  severity put seed-data passwords above the SQL injection in the login route.
- **Remembers**: a baseline per run. The second run tells you what is new, what is fixed, and does
  not re-report a false positive you already judged.
- **Asks little**: it reads the repo and scans first. At most three questions per step, each with a
  proposed answer. The one thing it never guesses is authorization.

## Scope

Authorized targets only: your own code, employer systems with authorization, staging, CTF, and
deliberately vulnerable practice apps. Never a third party, never production.

No exploit development, no denial of service, no data destruction, no detection evasion. A finding
is proved by the smallest safe evidence, never by damage.

## Quick Start

Needs Node 20+ and nothing else.

```bash
node bin/sec.mjs doctor                      # what is present, what is missing
node bin/sec.mjs discover mock --slug demo   # map the attack surface first
node bin/sec.mjs scan mock --slug demo       # static pass, T0, sends nothing
node bin/sec.mjs report --slug demo --bootstrap
```

`mock/` is a read-only app with planted defects. The scan prints a cost estimate, a
severity × confidence matrix, the findings, and the coverage ledger — **what it could not
check**. Artifacts land in `.sec/demo/runs/<id>/`: `result.json` (`sec-result/v1`),
`findings.json`, `coverage.json`, `events.ndjson`, and the scanner output under `raw/`,
redacted before it reached disk.

Against a live target, with a scope file that allows the host:

```bash
node mock/server.mjs 9970 &
node bin/sec.mjs scan --slug live --target url --url http://127.0.0.1:9970/ --tier T1
```

Second run, and the memory shows:

```bash
node bin/sec.mjs baseline promote --slug demo
node bin/sec.mjs scan mock --slug demo        # now reports new / fixed / unchanged
node bin/sec.mjs judge <fingerprint> false_positive "migrations take no user input"
node bin/sec.mjs export --slug demo --out findings.sarif
```

```bash
npm test             # 493 tests
npm run mutate       # disable each safety behaviour in turn; the suite must fail for every one
npm run bench:dynamic  # start a vulnerable target, scan it at T2, score what came back
```

## Status

| Milestone | Delivers | State |
|---|---|---|
| M0 Design | design.md, CONTRACTS.md | done |
| M1 Controller core | `sec-result/v1`, fingerprint + merge, run state, five gates, `repo` target, doctor, mutation runner | done |
| M2 Real scanners | `builtin` (31 rules + 2 structural checks), gitleaks, semgrep, trivy; verdict; baseline + lessons | done |
| M3 Lifecycle skills | seven skills, nine commands, `sec discover`, `sec status` | done |
| M4 Intelligence | the known-answer exam, SARIF export and import | done |
| M5 Dynamic | `url` target, `probe` (T1–T2), nuclei and zap adapters, auto-stop in the run loop | **done — 230 tests** |
| M6 Dogfood | ai-sec and a Go repo; nine defects found and fixed ([evidence](docs/evidence/m6-dogfood.md)) | done — 248 tests, 46/46 mutations killed |
| M7 Merge | cross-tool issue identity, symbol resolution, severity disagreement ([evidence](docs/evidence/m7-merge.md)) | done |
| M8 Hardening | defense-in-depth gaps are reported, never fail a build | done |
| M14 AI/LLM | prompt injection, output handling, agent authority; OWASP LLM Top 10 2025 | done |
| M9 Scorecard | `sec modules` — recall and accountability per module | done |
| M10 Corpus | OWASP NodeGoat; three modules scored zero on code we did not write | done |
| M11-M12 Close | every miss found; six defects in the mutation runner | done |
| M13 Authz | middleware that exists and is applied by nothing; NodeGoat 9 measured, 0 failing | done |
| M14 Verify | `sec verify` — the verifier is never the finder ([design](docs/verification.md)) | done |
| M15 Dynamic benchmark | a vulnerable target started, scanned at T2 and scored; cross-account IDOR proved by comparing two sessions; nuclei via its container; M14 pointed at a real AI application ([evidence](docs/evidence/m15-dynamic.md)) | done — 422 tests, 117/117 mutations killed |
| M16 Juice Shop | a corpus that writes its own answers; 1,468 files; eight rules the misses asked for; the report stops being 76% test suite ([evidence](docs/evidence/m16-juiceshop.md)) | done — 462 tests, 125/125 mutations killed |
| M17 One hop | the first checks that read a second file; `occurrences` finally scored; Juice Shop 9 measured, 0 failing ([evidence](docs/evidence/m17-crossfile.md)) | done — 477 tests, 133/133 mutations killed |
| M18 Ran is not read | a scanner can now report ONE capability as blind; trivy with no lockfile stops reading as a clean dependency tree; `expected.json` is no longer trusted on filename alone ([evidence](docs/evidence/m18-blind.md)) | **done — 493 tests, 141/141 mutations killed** |
| M19-M22 Documentation | a [user guide](docs/user-guide.md), a [coverage map](docs/security-coverage-map.md) of thirty-two layers, a [showcase](docs/showcase/pipeline.html) built on one real scan, and the repository files a security tool has no excuse for missing: [CONTRIBUTING](CONTRIBUTING.md), [SECURITY](SECURITY.md), [UPGRADE](UPGRADE.md), [roadmap](docs/roadmap.md), [provenance](docs/skill-sources.md), [mutation testing](docs/mutation-testing.md) | done — no behaviour changed |

## Related

| | |
|---|---|
| [`skills/security-review`](../skills/security-review/SKILL.md) | the method as a single skill; its `references/` become this bundle's knowledge base |
| [`skills/threat-modeling`](../skills/threat-modeling/SKILL.md) | upstream: threats before code |
| [`skills/security-test-strategy`](../skills/security-test-strategy/SKILL.md) | upstream: planning |
| [`skills/designing-security-cases`](../skills/designing-security-cases/SKILL.md) | parallel: security cases inside the STLC pipeline |
| [`ai-perf`](../ai-perf) | the sibling this is modelled on |

For a single feature and a ZAP baseline, the security tier in `stlc` is enough. ai-sec is for the
whole system, several scanners, and runs that are compared over time.
