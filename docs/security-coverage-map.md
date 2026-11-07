# Security coverage map — the whole landscape, and who owns each layer

Written for: a lead deciding whether this bundle covers the security work a
product needs, and where the rest of it lives.

Security is not one discipline. It is roughly thirty of them, and a bundle that
answers twelve well is more useful than one that claims thirty and measures
none. This file is the honest inventory: what `ai-sec` owns, what a sibling
bundle owns, what is blocked on this machine, and what nothing here covers at
all.

A layer is **covered** when something here owns it with a check that can fail
and a grade that can be quoted. Everything else is named, not implied.

Legend: ✅ shipped here · ◐ partial · ⛔ built but blocked in this environment ·
↔ owned by a sibling bundle · ✗ not covered anywhere here

## The landscape

| # | Layer | What it proves | Module | Owner | Status |
|---|---|---|---|---|---|
| 1 | **Secret scanning** — committed credentials, keys, tokens | nothing in the repository is a live credential | M3 | ai-sec (`gitleaks`, `trivy`, `builtin`) | ✅ `measured` |
| 2 | **SAST — taint and dataflow** | untrusted input does not reach a dangerous sink | M1 | ai-sec (`builtin` patterns + structural + one-hop cross-file; `semgrep` when present) | ◐ one hop only; `partial` 5/6 on Juice Shop |
| 3 | **Injection rules** — SQL, NoSQL, command, path, template | the specific sink classes are checked by name | M6 | ai-sec | ✅ `measured` |
| 4 | **SCA — dependency CVEs** | no shipped dependency carries a known vulnerability | M2 | ai-sec (`trivy`) | ✅ `measured` on NodeGoat · **`blind` without a lockfile** |
| 5 | **SBOM, provenance, signing** (CycloneDX, SLSA, sigstore) | the artifact is the one that was built, from what it says | — | — | ✗ |
| 6 | **Dependency confusion, typosquatting** | the package you resolved is the package you meant | — | — | ✗ |
| 7 | **Dependency licensing** | nothing shipped has an incompatible licence | — | — | ✗ (`trivy` can; not wired) |
| 8 | **IaC misconfiguration** — Terraform, Dockerfile, k8s manifests | infrastructure as written is not open by default | M10 | ai-sec (`trivy misconfig`) | ✅ `measured` |
| 9 | **CI/CD pipeline security** — workflow permissions, injection into runners | the pipeline cannot be turned against the repository | M10 | ai-sec | ◐ a handful of rules, not a model of the pipeline |
| 10 | **Container image scanning** — built image layers, base image CVEs | what ships in the image is not vulnerable | M2/M10 | ai-sec (`trivy fs` on source only) | ◐ source tree, **not the built image, not a registry** |
| 11 | **Container / Kubernetes runtime posture** | what is running is configured the way the manifest said | — | — | ✗ |
| 12 | **Cloud posture (CSPM)** — a live AWS/Azure/GCP account | the account as it exists today is not open | — | — | ✗ IaC files only; nothing touches an account |
| 13 | **Authentication, session, token handling** | identity is established and cannot be forged or replayed | M4 | ai-sec | ✅ `measured` 3/3 |
| 14 | **Authorization — BOLA, IDOR, multi-tenant isolation** | a caller cannot reach another caller's data | M5 | ai-sec (static) | ◐ `partial` — static only; a live authz matrix is stlc's `TC-SEC` |
| 15 | **API security** — the OWASP API Top 10 shape | the HTTP surface does not leak or over-accept | M7 | ai-sec static · live at T2 | ✅ `measured` 5/5 static |
| 16 | **Client-side** — XSS sinks, CSP, dangerous DOM APIs | the browser is not handed something to execute | M9 | ai-sec | ◐ `partial` 2/3 |
| 17 | **Cryptography** — weak digests, bad modes, weak randomness, KDF misuse | secrets are protected by something that still protects | M12 | ai-sec | ✅ `measured` |
| 18 | **Database access patterns** | queries are parameterised and scoped to a tenant | M8 | ai-sec | ✅ `measured` |
| 19 | **Logging, monitoring, error handling** | failures are recorded without recording secrets | M13 | ai-sec | ✅ `measured` |
| 20 | **AI / LLM / agent** — prompt injection, tool bounds, output handling | a model call cannot be talked into acting outside its bounds | M14 | ai-sec (OWASP LLM Top 10 2025) | ✅ `measured` · indirect injection is a stated blind spot |
| 21 | **Business logic and abuse cases** | the intended flow cannot be walked around for profit | M11 | **nobody** | ✗ `no-engine`, permanently — needs the intended flow modelled |
| 22 | **Threat modelling** | the risks were enumerated before the code was written | — | ↔ sdlc (G2) | ↔ |
| 23 | **DAST baseline** — a passive crawl of a running app | the deployed app does not fail the standard baseline | — | ai-sec adapter (`zap`) · ↔ stlc `TC-SEC` | ⛔ adapter proved by unit tests; **the installer needs elevation and it has never run here** |
| 24 | **Template-based vulnerability scanning** | known CVEs and exposures are not live on this host | — | ai-sec adapter (`nuclei`) | ⛔ **this environment refuses to execute it**; the adapter supports it, the measurement does not exist |
| 25 | **Active probing of a live target** | a finding rests on a request and its answer, not a pattern | M5/M7/M9 | ai-sec (`probe`, T1–T2) | ◐ graded on our own dynamic benchmark only |
| 26 | **Fuzzing** — schema fuzzing, protocol fuzzing | the parser survives what nobody sent on purpose | — | ↔ stlc (`TC-API-FUZZ`) | ↔ |
| 27 | **Penetration testing / red team** | an adversary with time and motive finds nothing worse | — | external humans | ✗ **by design** — no exploit development, no DoS, no evasion |
| 28 | **Mobile application security** — Android/iOS | the app on the device does not leak or trust the wrong thing | — | — | ✗ nothing |
| 29 | **Network and TLS configuration** | the transport is what the policy says | — | — | ✗ |
| 30 | **Privacy / PII data-flow** | personal data goes only where it was declared to go | — | — | ✗ **no module**, and this is the gap most likely to matter legally |
| 31 | **Compliance evidence** (SOC 2, ISO 27001, PCI DSS) | an auditor can trace a control to a result | — | — | ◐ findings map to CWE · ASVS 5.0.0 · WSTG v4.2 · OWASP Top 10 2025 · API Top 10 2023 · CVSS v3.1, and **that is a vocabulary, not evidence of a control** |
| 32 | **Vulnerability disclosure for this bundle itself** | someone who finds a flaw here knows where to send it | — | ai-sec ([`SECURITY.md`](../SECURITY.md)) | ✅ what it runs, what it refuses, where to report, and what is in and out of scope |

## The shape, not only the list

Twelve rows read ✅ for the product being scanned (row 32 is about this bundle
itself), and that number is worth less than it looks until you ask
what each one was measured against. `sec modules` answers that per module, and
the grade is the claim — not the tick:

```
3 partial · 1 blind · 9 measured · 1 no-engine        (OWASP Juice Shop)
```

- `measured` means full marks against a corpus **nobody here wrote**. Nine of
  the fourteen reach it on Juice Shop, whose answers are its own annotations.
- `partial` names its misses. The three that remain are arguments about that
  application, not defects in a rule.
- `blind` means an engine ran with the capability this module needed unusable —
  M2 against a repository with no lockfile. **A zero there is not a clean
  result.**
- `no-engine` is M11, and it is honest rather than aspirational.

Coverage is breadth. The grade is depth. A security report that quotes one
without the other is the thing this bundle exists to stop.

## The gap that is not a missing rule

Every project gets the **same fourteen modules**. A mobile banking app, an
internal CRUD tool, a public marketing site and an LLM agent that can spend
money are handed one identical checklist.

`scope.json` decides *how far a run may go* — the tier ceiling, the allowed
hosts, the recorded authorization. Nothing decides *what this kind of system
should be checked for*. That is the largest architectural gap here, larger than
any row above, because adding rules to a profile nobody chose does not make an
assessment fit the system.

What it would take: a project profile that selects modules, sets the bar per
module, and states which rows of this table are **deliberately out of scope for
this product** — so an unchecked layer is a recorded decision instead of an
absence. Ordered by value for effort, that outranks every ✗ in the table.

After it, in order: **privacy / PII data-flow (row 30) → container image
scanning (row 10) → SBOM and provenance (row 5)**. Rows 27 through 29 belong to
other disciplines and are better bought than built.

## Where this bundle and the others meet

| Direction | Artifact | Read by |
|---|---|---|
| ai-sec → anywhere | `sec export --out findings.sarif` — SARIF 2.1.0 | GitLab / GitHub code scanning, or any hub that reads SARIF |
| anywhere → ai-sec | `sec import <file.sarif> --tool <name>` | merged by the same CWE identity as every other source |
| ↔ sdlc | threat modelling at G2, static scan at G8 | the dev bundle gates the change |
| ↔ stlc | `TC-SEC` — a ZAP baseline and a Playwright authorization matrix against the running app | QA attacks what is deployed |

**Nothing crosses automatically today.** The SARIF projection is the only wired
path, and it is one-directional unless someone runs `import`. Treat the three
bundles as three sets of evidence that a human still has to put beside each
other.
