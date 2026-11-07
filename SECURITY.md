# Security

Written for: someone deciding whether it is safe to run this bundle, and someone who
has found a flaw in it and needs to know where to send it.

A security tool that cannot say what it does to your machine has no standing to
report on anyone else's.

## What this is, and what it runs

`ai-sec` is Node (ES modules, **zero runtime dependencies**) plus Markdown skills. It
ships no server, no daemon and no telemetry, and it makes **no network call of its
own**. Everything it executes is one of:

| | |
|---|---|
| its own code | `bin/`, `lib/`, `controller/`, `adapters/` — the `builtin` scanner reads files and never leaves the disk |
| scanners **you** installed | `semgrep`, `trivy`, `gitleaks`, `nuclei`, `zap` — used only when `detect()` finds them on `PATH`, never downloaded, never installed for you. `sec doctor` lists exactly what is present |
| requests to the target you named | only the `probe` scanner and only at **T1 and above**, only to hosts in `scope.json`'s allowlist |

Everything it writes goes under `.sec/<slug>/` in the repository you scanned. It does
not edit application source. It has no credentials of its own and asks for none.

## What it refuses to do

These are not policies in prose. Each is a gate in `controller/rules.mjs` with a
mutation in `tests/mutate.mjs` that disables it and requires the suite to go red
([`docs/mutation-testing.md`](docs/mutation-testing.md)).

| Gate | Refusal |
|---|---|
| `G1-production` | a target marked production is refused, whatever the tier |
| `G2-host-allowlist` | a host that is not in `scope.json` is refused |
| `G3-tier-ceiling` | a tier above `max_tier` is refused; raising it is **a human editing `.sec/<slug>/scope.json`** — not a flag, not a prompt, not something an agent can argue for |
| `G4-spec-override` | a scan spec cannot widen its own permissions |
| `G5-redaction-gate` | the run will not start without a working redactor |

Beyond the gates, by design and not by configuration:

- **No exploit development, no denial of service, no data destruction, no persistence,
  no detection evasion.** A finding is proved by the smallest safe evidence — a status
  code, a header, a response that differs — never by damage.
- **Authorized targets only**: your own code, employer systems with written
  authorization, staging, CTF, deliberately vulnerable practice applications. Never a
  third party. Never production.
- **No secret is ever printed.** Not to a report, a baseline, a commit message, a log,
  an event, or a tool argument. Evidence for a credential finding is the location and a
  masked prefix; `judge` refuses a reason that contains one. `tests/redact.test.mjs` and
  the `redaction` mutation hold the line.
- **External corpora are read-only.** OWASP NodeGoat and OWASP Juice Shop are cloned,
  scanned at **T0**, and **never run**. They are deliberately vulnerable applications;
  starting one is starting a vulnerable server on your machine. They are not vendored
  into this repository ([`docs/skill-sources.md`](docs/skill-sources.md)).

## Reporting a vulnerability in ai-sec itself

Open a **confidential issue** on the GitLab project, or contact the maintainer on the
project page. Please do not open a public issue first.

Include:

- `VERSION` (and the commit, if you have it),
- the exact command and the target kind (`repo` or `url`),
- the run folder `.sec/<slug>/runs/<run-id>/` if one was written — `raw/` is the fact,
- what you expected the gate or the ledger to do, and what it did.

Acknowledgement within five working days.

### In scope

- Any path by which a scan **sends traffic the tier did not authorize**, reaches a host
  outside the allowlist, or runs above `max_tier` without a human edit to `scope.json`.
- Any path by which a secret reaches disk, a report, an event or a process argument.
- Any path by which a **gap is reported as a pass** — a scanner that examined nothing,
  failed, timed out, or ran blind, and the run still read clean. That is the one
  property this bundle exists to hold; a break in it is the most serious class of bug
  here, more serious than a missed vulnerability.
- Command injection or path traversal through a scan spec, a scope file, a SARIF import
  or a scanner's output.

### Out of scope

- A missed vulnerability in a scanned target. That is a recall gap: it belongs in
  `sec modules`, a benchmark answer and a rule — not in a disclosure. The grades are
  published precisely so misses are expected rather than hidden.
- A false positive. Use `sec judge <id> false_positive "<reason>"`; it survives the
  next run.
- A vulnerability in `semgrep`, `trivy`, `gitleaks`, `nuclei` or `ZAP`. Report those
  upstream; they are detected, not shipped.

## Supply chain

- **No runtime dependencies.** `package.json` declares none, so `npm ci` installs
  nothing to run a scan. Node 20+ is the whole requirement.
- **No vendored third-party code.** The external scanners are detected on `PATH`; the
  benchmark corpora are cloned on demand into an ignored directory.
- **Provenance** of the ideas and the standards vocabulary is listed, with upstream and
  licence, in [`docs/skill-sources.md`](docs/skill-sources.md).
- **The bundle's own checks** — `npm test` (493 tests) and `npm run mutate`
  (141 mutations, all killed) — run on every change, and `tests/architecture.test.mjs`
  fails when a mutation anchor stops resolving, so a safety gate cannot be renamed out
  from under its own proof.

## The honest limit

**Nobody outside this project has reviewed it.** That is the largest gap in its
evidence — larger than any missing module — and it is recorded as row 32 of
[`docs/security-coverage-map.md`](docs/security-coverage-map.md). This file is where a
reviewer starts; it is not a substitute for one.
