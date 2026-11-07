# ai-sec contracts

Versioned with the bundle. Renaming or removing a key, state, event type or exit code is MAJOR; a
new optional key, event type or adapter is MINOR; wording is PATCH. The design behind these is in
[docs/design.md](docs/design.md).

## §1 Scan spec (`sec scan <spec.json>`, or flags)

| Key | Default | Rule |
|---|---|---|
| `slug` | — | `^[a-z0-9][a-z0-9-]*$` |
| `target` | `repo` | a key of `TARGETS` in `adapters/index.mjs` |
| `target_path` | `.` | for `repo`: an existing directory |
| `target_url` | — | for `url`: host must be in the scope's `allow_hosts` (§1a); no `user:password`, no token in the query; a host label starting `prod` or `prd` (but not `product`) is refused |
| `scanners` | all whose `tiers` fit `tier` and that `detect()` | keys of `SCANNERS` |
| `tier` | `T0` | `T0`…`T4`; above `T0` requires `scope.json` `max_tier` ≥ it **and** `authorization` present |
| `modules` | all applicable | `M1`…`M13` (design §5 of `skills/security-review`) |
| `accuracy` | `balanced` | `minimize-false-negatives` \| `balanced` \| `minimize-false-positives` |
| `depth` | `normal` | `fast` \| `normal` \| `thorough` |
| `baseline` | auto | path to a baseline, or `none` |
| `timeout_s` | `600` | per scanner, integer > 0 |
| `scanner_options` | `{}` | passed to the scanner untouched |

Every number must be a JSON number: `"600"` is refused, never coerced.

A spec that carries its own `allow_hosts`, `max_tier` or `authorization` is **refused**: those are
the project's, not the run's. This is the same rule as ai-perf's allowlist.

`sec scan` adds `run_id` (`YYYYMMDD-HHMMSS-xxxx`), `root`, `git_sha`, `tool_version`, and the
detected version of each scanner (detection runs here, never in the controller), and writes the
normalised spec as `run.json`. The controller reads only that file.

## §1a Scope file (`.sec/<slug>/scope.json`)

```json
{
  "schema": "sec-scope/v1",
  "max_tier": "T0",
  "authorization": { "basis": "own-repo", "granted_by": "...", "granted_at": "2026-10-30", "note": "" },
  "allow_hosts": [],
  "deny_paths": ["node_modules/**", "vendor/**"],
  "production": false,
  "environment": "local"
}
```

`basis` is one of `own-repo`, `employer-authorized`, `staging`, `ctf`, `practice-app`. Anything else
is refused.

**Tiers** grade what the traffic could *do*, not whether traffic exists:

| Tier | What it may send |
|---|---|
| `T0` | nothing at all — reads code, config, manifests, schema |
| `T1` | plain reads of known paths, as an ordinary client would: no parameters added, no payloads, no path guessing |
| `T2` | a handful of benign requests that vary a parameter — a redirect canary, a header probe. Nothing the application could read as an attack |
| `T3` | requests the application may well read as an attack: injection probes, fuzzing |
| `T4` | requests that may modify or destroy data | `sec scan` refuses: a host outside `allow_hosts`; a tier above `max_tier`; a scope with
`production: true`; an environment name starting `prod` or `prd` (except `product…`); and any tier
above `T0` when `authorization` is absent or older than 90 days.

`max_tier` above `T0` may only be raised by a human edit to this file. No command, spec, scanner
adapter or subagent may raise it.

## §2 Run folder (`.sec/<slug>/runs/<run_id>/`)

| File | Writer | Content |
|---|---|---|
| `run.json` | `sec scan` | the normalised spec (§1) |
| `state.json` | controller | §4 |
| `events.ndjson` | controller, doctor | §5 |
| `controller.log` | controller | stdout and stderr; a crash leaves its reason here |
| `raw/<scanner>/stdout`, `stderr`, `exit` | controller | untouched scanner output |
| `raw/<scanner>/parsed.json` | controller | `{ findings[], coverage[], errors[] }` from `parse()` |
| `findings.json` | controller | merged, deduplicated findings (§7) |
| `coverage.json` | controller | the coverage ledger (design §7.4) |
| `result.json` | controller | §6 |
| `report.md`, `verdict.md`, `verdict.json` | `sec report` | §9 |

Raw scanner output is kept **redacted** (§8): the redactor runs before anything is written to disk.

## §3 Scanner adapter protocol

Every adapter, whatever the tool, speaks this protocol. That is what makes the controller
scanner-agnostic, and what lets a new scanner be added without touching a skill (P5).

```js
export default {
  name: "semgrep",
  tool: "semgrep",                 // the sec-result/v1 tool enum
  tiers: ["T0"],                   // tiers this scanner may run at
  modules: ["M1", "M6"],           // modules it contributes to
  detect: async () => ({ ok, version, install }),
  preflight: async ({ target, options, tier, scope }) =>  // optional
    ({ ok, reason?, unblock?, degraded?: [{ capability, modules, reason, unblock }] }),
  scanCommand: ({ runDir, target, options, depth, accuracy }) =>
    ({ cmd, args, env, timeout_s }),
  parse: async ({ stdout, stderr, exitCode, runDir }) =>
    ({ findings, coverage, errors })
}
```

- `detect()` must not run the scan. It is called by `sec scan` and `sec doctor`, never by the
  controller.
- `preflight()` answers a different question: not *is it installed* but *can it do, against
  **this** target, what it is credited with*. Three answers:
  - `{ ok: true }` — nothing to say.
  - `{ ok: false, reason, unblock }` — the scanner does not run at all; the ledger records it and
    its modules are not counted as covered.
  - `{ ok: true, degraded: [...] }` — a **partial** refusal: it runs, and each named capability
    that cannot is carried to `result.degraded[]`, to the coverage ledger, and to the grade of
    every module in its `modules`, which becomes `blind` rather than `failing`. trivy without a
    lockfile is the case this exists for: zero dependency findings because zero package versions
    were readable, which is indistinguishable from clean unless something says so.
- `scanCommand()` is pure: no I/O, no network. The controller spawns it.
- `parse()` returns three arrays and **all three are required**:
  - `findings[]` — partial findings (§6 `findings[]` minus the fields the controller owns:
    `fingerprint`, final `severity`, final `confidence`, `baseline_state`).
  - `coverage[]` — `{ kind, detail, count? }` with `kind` in `languages`, `files`, `rules`,
    `packages`, `endpoints`. What the scanner actually examined.
  - `errors[]` — `{ kind, detail }` for anything it could not examine.
- A scanner that exits non-zero with parseable output is still parsed; the exit code goes to
  `errors[]`.
- **An adapter returning `findings: []` and `coverage: []` is treated as having produced nothing**,
  which makes the run `degraded` (or `not_evaluable` if no scanner produced coverage). Silence is
  never clean.
- A scanner exceeding `timeout_s` is killed; it contributes `errors[]` and whatever coverage it
  reported, and the run is `degraded`.
- Adapters never write outside `runDir`, never read the baseline, and never see the authorization
  record.

A target adapter exports `name`, `prepare({ spec }) → { ok, root, meta }` and
`cleanup({ spec })`. `repo` resolves and validates a directory. `url` checks the host against the
allowlist before anything else.

## §4 Run state (`state.json`, `sec-state/v1`)

States: `preparing`, `scanning`, `merging`, `verifying`, then one terminal state:

| Terminal | When | Exit |
|---|---|---|
| `done` | every selected scanner ran and reported coverage | 0 |
| `degraded` | a scanner failed, timed out, or produced nothing, but at least one reported coverage | 4 |
| `not_evaluable` | no scanner produced coverage, or the target could not be read | 3 |
| `aborted` | a gate refused, auto-stop fired, or the user stopped it | 5 |

Precedence: `aborted` > `not_evaluable` > `degraded` > `done`. Every move is appended to `history`.
A terminal state is written exactly once.

## §5 Events (`events.ndjson`)

One JSON object per line: `{ ts, type, severity, summary, data }`, `severity` in `info`, `warn`,
`error`. Types: `scan_started`, `scanner_finished`, `scanner_failed`, `gate_refused`,
`new_critical`, `auto_stopped`, `run_finished`.

`sec watch` blocks until the AI should look, and wakes on any non-info event, or on
`gate_refused`, `auto_stopped` and `run_finished` at any time.

## §6 Result (`result.json`, `sec-result/v1`)

SARIF-2.1.0-shaped by design: a catalogue of issue types plus instances referring to them.

```json
{
  "schema": "sec-result/v1",
  "run_id": "…", "run_state": "done", "started_at": "…", "finished_at": "…",
  "target": { "kind": "repo", "path": "…", "git_sha": "…" },
  "scope": { "tier": "T0", "max_tier": "T0", "authorization_basis": "own-repo", "environment": "local" },
  "standards": { "wstg": "v4.2", "asvs": "5.0.0", "owasp_top10": "2025", "api_top10": "2023", "cvss": "3.1" },
  "tools": [ { "name": "semgrep", "version": "…", "exit_code": 0, "duration_s": 12.4 } ],
  "rules": [ {
    "rule_id": "sql-injection",
    "name": "SQL injection",
    "background": "…", "remediation": "…",
    "classification": { "cwe": ["CWE-89"], "owasp": ["A05:2025"], "wstg": ["WSTG-v42-INPV-05"], "asvs": ["v5.0.0-1.2.5"], "api": [] },
    "typical_severity": "High",
    "references": ["…"]
  } ],
  "findings": [ {
    "fingerprint": "a1b2c3…",
    "rule_id": "sql-injection",
    "location": { "file": "src/db/orders.ts", "symbol": "getOrder", "line": 142 },
    "insertion_point": { "kind": "body-parameter", "name": "orderId" },
    "severity": "High", "confidence": "Firm", "status": "open",
    "cvss": { "version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", "score": 8.1 },
    "impact": "HIGH", "likelihood": "MEDIUM",
    "detection_method": "dataflow",
    "detail": "…", "evidence": "…",
    "sources": [ { "tool": "semgrep", "rule": "…", "reported_severity": "ERROR" } ],
    "baseline_state": "new",
    "modules": ["M1"]
  } ],
  "coverage": [ { "kind": "languages", "detail": "typescript", "count": 412, "scanned": true } ],
  "not_evaluable": [ { "check": "M7 live API authz", "reason": "no target_url supplied", "unblock": "run at T2 with an authorized staging URL" } ],
  "summary": { "by_severity_confidence": { "High": { "Certain": 0, "Firm": 1, "Tentative": 2 } },
               "new": 1, "fixed": 0, "unchanged": 2, "suppressed": 1 }
}
```

Enums — `severity`: `Critical` `High` `Medium` `Low` `Info`. `confidence`: `Certain` `Firm`
`Tentative`. `status`: `open` `fixed` `false_positive` `accepted_risk`. `baseline_state`: `new`
`unchanged` `updated` `absent`. `detection_method`: `pattern` `dataflow` `config` `version-match`
`reproduced` `out-of-band`. `impact`/`likelihood`: `HIGH` `MEDIUM` `LOW`.

`sec export --sarif` is a projection of this document, not a translation: `rules[]` →
`tool.driver.rules[]`, `findings[]` → `results[]`, `fingerprint` →
`partialFingerprints.primaryLocationLineHash`.

`sec` exit codes: 0 ok, 1 error or doctor failure, 2 refused by a gate, 3 not_evaluable,
4 degraded, 5 aborted.

## §7 Fingerprint and merge

```
fingerprint = sha256(issue_type + "\u0000" + normalized_location + "\u0000" + insertion_point)
```

`issue_type` is the **cross-tool** name of the defect, not the scanner's rule id. Keying on
`rule_id` meant `open-redirect` and
`javascript.express.security.audit.express-open-redirect` were two findings on one line of one
file, so they never merged and corroboration never fired once. It is resolved by
`controller/taxonomy.mjs`:

| basis | when | cross-tool merging |
|---|---|---|
| `family` | a CWE in `ISSUE_FAMILIES` | yes |
| `cwe` | a CWE outside the table | yes, between tools citing that CWE |
| `rule_id` | the scanner supplied no CWE | **no** — and `identity_basis` records it |

A family groups CWEs that describe one defect from different angles — semgrep files an MD5
password hash under CWE-327, our own rule under CWE-916. Merging also requires the same
location, so a broad family costs little and a narrow one costs a duplicate in every report.

`normalized_location` is `file + "#" + symbol` when the enclosing symbol resolves, otherwise
`file + ":" + line`. Paths are repo-relative with forward slashes. This is what lets a finding
survive an edit that shifts line numbers. Most scanners do not report a symbol, so the
controller resolves it for all of them (`controller/locate.mjs`); an adapter must never be the
only place that knows how to do this.

Merge rules, applied in order:

1. One fingerprint, one finding. Never two.
2. `severity` is the **highest** after rescoring in context — never an average, never a tool's own.
3. Independent corroboration promotes confidence one step, capped at `Firm`. Two tools count as
   independent only when their `detection_method` differs; `Certain` is reached only by
   `reproduced` or `out-of-band`.
4. Every contributing tool is appended to `sources[]` with its own location, the severity the
   adapter mapped it onto (`severity`) and the tool's own enum verbatim
   (`reported_severity`: semgrep says `WARNING`, trivy says `MEDIUM`). Only `severity` is ever
   compared — ranking a tool's enum against `Critical…Info` places all of them at the bottom.
4a. When the sources do not propose the same `severity`, the disagreement is recorded in
   `severity_disagreement[]` and printed. Taking the highest is the resolution; saying nothing
   about it would hide a real difference of opinion between scanners.
4b. `tools[]` names every scanner that reported the finding, so a reader can tell one engine's
   guess from two engines agreeing.
5. A finding whose fingerprint is in the baseline with `status: false_positive` is suppressed, and
   counted in `summary.suppressed` with its reason. Suppression is per fingerprint, never per rule.

## §8 Redaction

A single redactor runs before any write to disk, any event, any log line and any chat output.

- A value matching a secret pattern, or reported by a secret scanner, is replaced with
  `<redacted:{type}:{len}:{first4}>`.
- The full value is never persisted, never placed in a tool argument, and never transmitted.
- `evidence` for a secret finding carries the location and the redacted form only.
- Mutation test: removing the redactor must make `tests/redact.test.mjs` fail with a plaintext
  secret found in an artifact.

## §9 Project files and verdict

`.sec/<slug>/`:

| File | Written by | Gate (`sec check <step>`) |
|---|---|---|
| `context.json`, `surface.json` | `/sec-discover` | at most 3 questions, each with a proposed answer |
| `scope.json` | `/sec-scope` | §1a; tier above T0 needs `authorization` |
| `baseline/<env>.json` | `sec baseline promote` | only a `done` run |
| `lessons.md` | `/sec-learn` | no secret, no payload, no raw finding dump |

`sec report` gives one of four outcomes:

| Outcome | When | Exit |
|---|---|---|
| PASS | no `Critical` or `High` with confidence ≥ `Firm`; coverage ledger has no unscanned in-scope area | 0 |
| WARN | only `Medium` and below above the bar, or a `High` at `Tentative` | 0 |
| FAIL | any `Critical` or `High` at `Firm` or `Certain`; or a new one against the baseline | 1 |
| NOT_EVALUABLE | the run is not `done` (except `degraded` with full coverage of the selected modules); no scanner covered a selected module; no baseline without `--bootstrap` | 3 |

A PASS whose coverage ledger is non-empty must say so in its first line. The verdict names every
assumption it rests on, every suppressed finding, and the standards baseline it was scored against.
