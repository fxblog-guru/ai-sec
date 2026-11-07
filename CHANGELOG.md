# Changelog

All notable changes to ai-sec. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
contracts are versioned as described in [CONTRACTS.md](CONTRACTS.md).

## [Unreleased] — M19-M22, the documentation set

No behaviour changed in any of these. The code was ahead of what anyone could read
about it, which for a tool whose whole claim is "it tells you what it could not
check" is the same class of defect as a silent scanner.

### Added
- [`docs/user-guide.md`](docs/user-guide.md) (M19) — the practical guide: day one, the
  four parts of a report, judge and verify, baselines, the grades, CI exit codes, the
  tiers, where files land, and what this does not do.
- [`docs/security-coverage-map.md`](docs/security-coverage-map.md) (M20) — thirty-two
  security layers, who owns each, and the ✗ rows nothing here covers. The inventory is
  the point: a bundle that answers twelve layers well is worth more than one claiming
  thirty and measuring none.
- [`docs/showcase/pipeline.html`](docs/showcase/pipeline.html) (M21) — ten sections, no
  external request of any kind, built around one real scan of a real repository.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) (M22) — where a change goes, how to add a rule,
  a scanner and a module, and the rule that a safety behaviour without a mutation is a
  comment.
- [`SECURITY.md`](SECURITY.md) (M22) — what this bundle runs on your machine, the five
  gates it refuses on, how to report a flaw in it, and what is in and out of scope.
  Closes row 32 of the coverage map, which this bundle had been reporting against
  itself.
- [`UPGRADE.md`](UPGRADE.md) (M22) — per-version notes. The one that matters: after
  0.18, **re-run `sec modules`** if you ever scanned a target shipping its own
  `expected.json`.
- [`docs/roadmap.md`](docs/roadmap.md) (M22) — the three gaps that outrank every missing
  rule, M23-M28 in order, and the five decisions only a human can make.
- [`docs/skill-sources.md`](docs/skill-sources.md) (M22) — provenance: standards and
  their editions, the two corpora and their licences, the five tools detected on PATH,
  and what was read and deliberately not adopted. No third-party code is vendored here.
- [`docs/mutation-testing.md`](docs/mutation-testing.md) (M22) — what the 141 gates
  cover, read as a specification, plus the anchor check and the crash-safety design.

### Fixed
- `package.json` still said `0.0.1` eighteen minor versions in. It now tracks `VERSION`,
  and `CONTRIBUTING.md` states that they move together.


### Changed (installer)
- Commands and skills run `node <ai-sec>/bin/sec.mjs`, defined in `sec-protocol`: `.claude/ai-sec`
  in a project installed with `npx agentic-fx`, `.` in a checkout. They assumed the ai-sec
  checkout was the working folder, which no installed project is.

## [0.18.0] — 2026-10-31 — M18, ran is not read

### Added
- **Partial refusals in `preflight`** — an adapter may now return `{ ok: true, degraded: [...] }`:
  the scanner runs, and a capability it cannot use against *this* target is named. `detect`
  answers "is it installed" and a full `preflight` refusal answers "can it reach this target";
  neither fits a scanner that can do three things here and only two of them. The entries reach
  the run record, the coverage ledger, and the module that was counting on them.
- **trivy preflight** — a target with no lockfile or other resolvable manifest cannot produce a
  single dependency finding, because `package.json` states ranges and a range is not a version.
  OWASP Juice Shop is such a target, and M2 read `unmeasured` for two milestones with nothing
  saying why. Misconfiguration and secret scanning are unaffected and still run.
- **`blind` grade** — an engine ran with a capability this module needed unusable. Deliberately
  not `failing`, which blames the rules for a defect they were never shown, and not
  `unmeasured`, which does not say why. A blind capability that cost the module nothing does
  not downgrade it.
- `scanner_degraded` event, and `degraded[]` on the result.
- `tests/degraded.test.mjs` — 16 tests, including the end-to-end path through `scan()` via a
  `blind` option on the fake scanner, so the wiring is exercised on every machine.
- Eight mutations (133 → **141**).

### Fixed
- **`expected.json` is a conventional filename, not a reserved one.** Any file by that name in
  the scanned target was read as an answer key, so a repository shipping its own fixtures would
  have been graded against somebody else's data with no warning; a malformed one threw and took
  `sec modules` down. It must now look like an answer key (`defects` must be an array) or it is
  ignored with a reason.

### Changed
- `benchmarkFor` moved from `bin/sec.mjs` to `lib/scorecard.mjs` — a function nothing can import
  is a function nothing can test.

## [0.17.0] — 2026-10-31 — M17, one hop

### Added
- **`adapters/scanners/builtin/crossfile.mjs`** — the first checks here that read a second
  file. Every blind spot this project had recorded was the same sentence: no regular
  expression crosses a call boundary. It resolves **one** hop, only to a function the target
  defines, only by name — not a call graph, and deliberately not pretending to be one. A
  helper it cannot resolve becomes a coverage-ledger gap naming the call, so "we did not
  establish how the password is stored" is never printed as silence.
- **`weak-password-hash-via-helper`** (M4, M12) — the password setter names a helper and the
  helper is `crypto.createHash('md5')` in another module. Neither line is wrong; the defect
  is the pair. This is the defect that had M12 at `failing`.
- **`auto-crud-exposes-privileged-field`** (M4, M5, M7) — a model declares a column that
  decides what an account may do, and the generated CRUD resource's exclude list does not
  name it. The defect is the gap between two lists.
- **`caller-identity-fetched-and-unused`** (M5, M8) — a handler binds the authenticated
  account, never reads the binding again, and goes on to read or write stored data. The
  strongest disguise for broken object-level authorization, because the fix looks like it is
  already there.

### Fixed
- **`occurrences` had never been scored.** The scorecard's `matches()` compared
  `location.file` and nothing else, so a finding anchored at the cause and listing the call
  site the benchmark recorded counted as a **miss** — the answer was in a field it did not
  read. Printed in reports since M15, wrong the whole time.
- **Twenty findings for one line.** The cross-file check first reported per call site: 20
  findings from a single `createHash('md5')`. This project's own skill says twenty findings
  with one root cause are one finding with twenty instances. Now one, anchored at the
  helper, carrying every call site.
- **A clearing condition that cleared the case it should catch.**
  `objectReferenceWithoutOwnershipCheck` treats "the caller is consulted" as a reason to
  stay quiet. Fetching the account and then ignoring it is the defect.

### Changed
- Juice Shop scorecard: **9 `measured`, 3 `partial`, 0 `failing`** (was 7 / 4 / 1). M4
  `partial 1/3` → `measured 3/3`; M12 `failing 0/1` → `measured 1/1`.
- Two benchmark answers moved from "out of reach" to "found" **after** the rules were
  written, which is the most dangerous edit available here. Both now carry
  `was_missed_until` saying what changed, `register-as-admin` keeps
  `cwe_originally_recorded`, and the benchmark test fails if such a note is shorter than a
  sentence.

## [0.16.0] - 2026-10-31 - M16, the corpus that grades itself

### Added
- **OWASP Juice Shop as a fourth benchmark**, and the first whose answers we did not
  write. Juice Shop annotates the exact line of each planted defect in its own source
  (`// vuln-code-snippet vuln-line <challengeName>`); `benchmarks/juiceshop.mjs` reads the
  27 markers back out, and `benchmarks/juiceshop-expected.json` groups them into 16
  defects. On NodeGoat we chose which defects to record. Here we chose nothing. It is also
  the first corpus of a realistic size: 1,468 files, a test suite, a frontend and an LLM
  chatbot.
- **Eight built-in rules**, each one a miss this corpus named, each one written to
  generalise past it: `bypass-framework-escaping` (Angular's escape hatch on a non-literal),
  `nosql-operator-injection`, `commented-out-authorization` (the guard is written, commented
  out, one character from live), `rate-limit-keyed-on-client-header`,
  `directory-listing-enabled`, `exposed-operational-endpoint`,
  `allowlist-matched-by-substring`, and `tool-bound-stated-only-in-prose`.
- **`tool-bound-stated-only-in-prose` is the one worth naming.** Juice Shop's chatbot
  declares a coupon tool as `z.number().describe('... maximum 10')` and mints a coupon for
  whatever the model returns. The bound is in a sentence; a sentence is an instruction to
  the model, and a model can be argued out of an instruction by anything it has read. Every
  agent framework invites this, because the schema field is where you tell the model what
  an argument means — and telling the model is not deciding.
- **`controller/coderole.mjs`** — every finding is labelled `application`, `test`,
  `fixture`, `example`, `generated` or `vendored`. Unknown shapes are `application`, which
  is the safe direction.
- **M3, M13 and M14 are now `measured`** — graded on code nobody here wrote. M14's recall
  on an external corpus was previously unknown; it is now 1 of 1, on a defect that matters.

### Fixed
- **The report was 76% test suite.** Scanning Juice Shop produced 246 findings, 188 of them
  hardcoded credentials under `test/`. Because `Critical` sorts above `High`, the first
  three screens were seed data and 2FA fixtures and the SQL injection in the login route
  was below the fold. Nothing was wrong — every finding really is in that file — and nobody
  would have read it, which is worse than a false positive, because a false positive gets
  argued with. A non-application finding is now capped at `Tentative` (with what the scanner
  claimed kept in `reported_confidence`), left out of the verdict bar, grouped into one
  counted block, and named in the coverage ledger. Nothing is dropped: a credential in a
  test file can be a live credential, and the block says so.
- **A rule that named the wrong cause.** `nosql-operator-injection` reported
  `WalletModel.increment({...}, { where: { UserId: req.body.UserId } })` — Sequelize, which
  binds the value. Taking `UserId` from the body to credit a wallet is a real defect, with a
  different fix on a different line. A finding that names the wrong cause is worse than
  silence, because silence gets investigated. Narrowed twice, both narrowings tested.

### Fixed
- **The skills were ten milestones out of date, and nothing said so.** `skills/` had not
  been touched since M5. In between, the controller grew `sec verify`, `sec modules`,
  `sec status`, `sec export`, hardening notes, preflight refusals, `subtype`,
  `occurrences`, `collapsed`, six module grades and the LLM Top 10. A reader following
  the skills would have run an assessment that was correct for M5 and silently missing
  everything after it — the project's own failure mode, in the one place that had no test.
  Six skills updated; the two that were still true were left alone.

### Added
- **`tests/skills.test.mjs`** — the skills are now checked against the code they describe.
  No skill may name a command the CLI does not have; no command may exist that no skill
  mentions; every grade, verdict, finding class, verification method and gate id the tool
  can print at a reader must be explained in a skill; and the standards baseline the
  skills state must be the one the code classifies against. It found four real gaps on its
  first run: `sec export` documented nowhere, `manual-review` and `G5-redaction` never
  explained, and a regex of its own that read the prose "a sec assessment" as a command.
  Three mutations guard it in both directions — rename a command, add a method, rename a
  gate, and the suite fails.

## [0.15.0] — 2026-10-31 — M15, the dynamic benchmark

### Added
- **`benchmarks/dynamic/`** — a deliberately vulnerable application, started on an ephemeral
  loopback port, scanned at T2 and scored. Ten planted defects, and for the first time the
  evidence behind a grade is a request and its answer rather than a pattern that matched a
  file. Eight modules now carry dynamic evidence; `npm run bench:dynamic` runs it, and
  `tests/dynamic-benchmark.test.mjs` fails the suite on a missed defect.
  The app refuses to bind to anything but 127.0.0.1, and the harness checks that its target is
  the server it just started before it writes the scope it is allowed to write.
- **Cross-account object read (`probe`, T2)** — the first check here that needs two sessions.
  Three requests in a fixed order: as the owner, then *with no session at all*, then as the
  other account. The control request is what separates "another account can read this" from
  "anyone can read this" — two different defects with two different fixes. The evidence is a
  digest and a length, never the body: a report is read by people who are not entitled to it.
  Session cookies travel in the environment, never in argv.
- **`subtype`** — an optional discriminator in the fingerprint for two defects that share a CWE
  family and a location. It names the defect, not the rule, so ZAP's missing `Referrer-Policy`
  and ours still merge.
- **`preflight`** on scanner adapters — "is it installed" and "can it run against this target"
  are different questions. A refusal reaches the coverage ledger, and the scanner stops
  counting toward module coverage.
- **nuclei through its published container**, pinned, detected by reading the local image store
  rather than by running anything.
- **ZAP now distinguishes the two installs.** `zap-baseline.py` ships with the container and the
  Linux packages; a desktop install has `zap.bat` and no wrapper at all. The adapter reports
  which one it found, and `preflight` refuses a T1 request on a desktop install — `-quickurl`
  spiders and then actively attacks, so answering a passive request with it would attack a
  target the operator authorised us only to read.
- **`unreachedModelSdks`** — a file that imports a model SDK is evidence there is something to
  check. Recognising no model call in any such file becomes a coverage-ledger gap naming the
  pattern to add, instead of a clean result.
- **`occurrences`** on a merged finding: the fingerprint prefers `file#symbol` so it survives an
  edit above it, which means two call sites in one function share an identity. They still merge;
  the report now prints `×2` and says where the other one is.

### Changed
- A merged finding that absorbed a second rule from the **same tool** now records both names in
  `collapsed`, and the coverage ledger counts it. The CWE family still wins the merge; it may
  no longer win it silently.
- `scanner_skipped` joins the event types. It is not `scanner_failed`: nothing went wrong, and
  nothing ran.

### Fixed
- **The merge was discarding findings.** `missing-csp` and `missing-frame-protection` are both
  CWE-1021; `missing-referrer-policy` and `technology-banner` are both CWE-200. At one URL each
  pair shared a fingerprint, so the second one found was folded into the first and nothing
  anywhere said so. The dynamic benchmark reported four of seven planted header defects on its
  first run — the checks had produced all seven.
- **ZAP reported itself installed and then could not run.** `detect` asked "is any zap command
  present", found `zap.bat`, and every scan after that died on `zap-baseline.py ENOENT` — an
  error, which degrades a run, rather than a stated gap, which explains one.
- nuclei in a container cannot reach this machine's loopback, and the adapter says so instead
  of rewriting the target to `host.docker.internal` — a name that was never checked against
  `scope.allow_hosts`.
- **M14 was blind to the Vercel AI SDK.** Scanning a real AI application — 169 files, eleven
  model calls — produced zero findings, a `done` run and an empty ledger, because every call
  shape the rules knew was an OpenAI, Anthropic or Google one. `MODEL_CALL` now covers
  `streamText`, `generateText`, `streamObject` and `generateObject`, and the same scan reports
  nine model calls with no output or time ceiling. All nine were read by hand; all nine are
  real.
- **Taint sources were Express-only.** Nothing in a Next.js codebase matched
  `req.body`/`req.query`, so every `taint: true` rule sat silent over a codebase full of
  request data. `SOURCE_RE` now also reads the Web `Request`: `request.json()`, `req.text()`,
  `request.formData()`, `searchParams.get()`, `formData.get()`.
- What M14 still cannot settle — indirect prompt injection, where the untrusted text reaches
  the prompt as an argument from another module — is recorded in `STATIC_BLIND_SPOTS` rather
  than implied by a zero.

## [0.5.0] — 2026-10-31 — M5 dynamic

### Added
- **`url` target** — validates scheme, refuses credentials in the URL, re-checks the host
  allowlist and the production rule itself, and confirms reachability before any scanner runs.
  It is the last code before traffic leaves the machine, so it does not assume a gate already
  checked.
- **`probe` scanner** — the dynamic counterpart to `builtin`: pure Node, nothing installed.
  T1 reads security headers, cookie flags, CORS, banners and verbose errors; T2 adds a
  redirect canary. Every request is counted.
- **`nuclei` and `zap` adapters** — honest when absent. nuclei excludes intrusive tags below
  T3; zap maps its 0–4 confidence onto ours and drops what it already marked a false positive.
- **Auto-stop wired into the run loop** for T2 and above: an out-of-scope request, five
  consecutive errors, an unintended write, blanket auth failure or an exceeded tier aborts the
  run, and the ledger records what the stop left unexamined.
- `mock/server.mjs`, a local weak HTTP server bound to 127.0.0.1 for exercising T1–T2.

### Changed
- **Tier definitions corrected.** The table said T1 "sends nothing" while `probe` plainly made
  requests. A tier grades what traffic could *do*, not whether traffic exists — Burp's crawl
  sends plenty and is not an audit check. T1 is now "plain reads of known paths; no parameters
  added, no payloads". Contract, design and `sec-protocol` updated together.
- Dependency detection now requires a manifest key or a real import. A quoted word in source
  is not a dependency: `searchParams.get('next')` was making the mock a Next.js app and
  pulling in a module that did not apply.

### Fixed
- `scope.json` with a byte-order mark — what Notepad and Windows PowerShell leave behind —
  crashed with a stack trace. It is stripped, and malformed JSON now names the file and says
  how to recover.
- The architecture test read a comment containing `require('express')` as an import. It strips
  comments first.

## [0.4.0] — 2026-10-30 — M4 the exam, and SARIF

### Added
- `tests/exam.test.mjs`: known-answer cases from `mock/expected.json`, including the plausible
  wrong answer for each. Misclassifying a cross-tenant read as injection, or citing the 2021
  OWASP edition, now fails the suite.
- `lib/sarif.mjs`: SARIF 2.1.0 export and import. Confidence travels as `properties.precision`;
  the coverage ledger rides in `run.properties` rather than being dropped; a dismissed finding
  is never exported as a live alert; anything imported starts at `Tentative`.

## [0.3.0] — 2026-10-30 — M3 lifecycle skills

### Added
- Seven skills and nine commands. `lib/discover.mjs` maps the attack surface before scanning;
  `lib/help.mjs` answers "what now?" from state and asks nothing.
- `tests/architecture.test.mjs` makes pillar P5 measurable, and caught two real violations on
  the first run.

## [0.2.0] — 2026-10-30 — M2 real scanners

### Added
- `builtin`, `gitleaks`, `semgrep` and `trivy` adapters. `builtin` needs nothing installed:
  17 pattern rules plus two structural checks — a route registered above its guard, and a
  parameterized query with no tenant predicate.
- `lib/verdict.mjs` and `lib/baseline.mjs`: PASS/WARN/FAIL/NOT_EVALUABLE, baseline promotion,
  human verdicts that survive it, and lessons.
- `mock/` with `expected.json` recording the known answer for each planted defect.

## [0.1.0] — 2026-10-30 — M1 controller core

### Added
- **Five gates in code** (`controller/rules.mjs`): production refusal (including host and
  environment naming, where `product` is not `prod`), host allowlist with no credentials in the
  URL, tier ceiling with a dated authorization record above T0, refusal of a spec that tries to
  widen its own permissions, and a redaction gate that blocks the run if the redactor is not live.
  Auto-stop rules for T2+.
- **Redaction before every write** (`controller/redact.mjs`): secrets become
  `<redacted:type:len:first4>` in artifacts, events and logs.
- **Fingerprint and merge** (`controller/fingerprint.mjs`, `merge.mjs`): findings are merged,
  never summed. Severity is the highest proposed, never a tool's own; corroboration promotes
  confidence only when the detection techniques differ; `Certain` requires reproduction or an
  out-of-band interaction. Baseline diff and per-fingerprint false-positive suppression.
- **Coverage ledger** (`lib/coverage.mjs`): a scanner reporting neither findings nor coverage
  examined nothing, so the run is `degraded` or `not_evaluable` — never a quiet pass.
- **Run state machine** (`controller/state.mjs`) with contract exit codes, and events
  (`controller/events.mjs`).
- **Adapters**: the `fake` scanner (deterministic, installs nothing, can simulate clean, silent,
  failing and timing-out runs) and the `repo` target. Registry in `adapters/index.mjs`.
- **CLI** `bin/sec.mjs`: `doctor`, `scan`, `help`, `version`; defaults to T0; prints a cost
  estimate before running.
- **Tests**: 76 across gates, redaction, merge, coverage, state, doctor fault injection, and an
  end-to-end scan. `npm run mutate` disables each safety behaviour in turn and requires the suite
  to fail — 12/12 killed.

## [0.0.1] — 2026-10-30 — M0 design

### Added
- **M0 design.** `docs/design.md` — scope, boundaries and the five pillars; the tier model T0–T4 as
  the authorization gate; the three adapter axes (scanner, target, enricher); the merge rules that
  make findings from several scanners one set; the coverage ledger behind "never a quiet pass".
- **Contracts.** `CONTRACTS.md` — scan spec, scope file, run folder, scanner adapter protocol,
  run state, events, `sec-result/v1` (SARIF-shaped), fingerprint and merge, redaction, verdict.
- Repository skeleton and README.

### Decided
- D1–D5 in `docs/design.md` §15 settled at M0.
