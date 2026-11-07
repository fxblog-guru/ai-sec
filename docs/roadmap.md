# ai-sec — review and roadmap

Written for: whoever decides what gets built next here, including the version of us
that has forgotten why a thing was left undone.

Current state: **v0.18.0 · 493 tests · 141/141 mutations killed · 31 built-in rules ·
14 modules · 4 benchmarks.**

## 0. The verdict in one screen

This bundle does one thing better than the tools it sits beside: **it will not let a
gap read as a pass.** A scanner that is missing, crashed, timed out, did not understand
the language, or ran with one capability unusable turns up in the coverage ledger and in
the grade of the module that was counting on it. Everything else exists to keep that
property true when nobody is watching.

What it is **not**: a pentest, a complete assessment, or a tool that can tell someone
who cannot read security output whether they are safe.

The three biggest gaps, in the order they should be closed:

| | Gap | Why it outranks the rest |
|---|---|---|
| 1 | **One profile for every project** | A mobile banking app, an internal CRUD tool and an LLM agent that can spend money get the same fourteen modules. Adding rules to a checklist nobody chose does not make an assessment fit the system. |
| 2 | **Nobody outside this project has reviewed it** | Every number here was produced by the people who wrote the thing producing it. Juice Shop is the one piece of evidence that can contradict us. |
| 3 | **Privacy / PII data-flow is not covered by anything** | The gap most likely to matter legally, and no module claims it. |

Nothing below is a defect in what shipped. These are the arguments for what comes next.

## 1. What already works — do not break these

Each of these cost a milestone and has a mutation holding it. Any change that weakens
one needs a reason written down.

- **The coverage ledger.** A run that passes with a non-empty ledger says so on its
  first line. Exit code **4** exists so CI can tell "clean" from "I did not get the scan
  I asked for".
- **`blind` ≠ `failing` ≠ `unmeasured`.** M18 found that M2 had read `unmeasured` for
  two milestones with a recorded reason that was simply wrong. The partial-refusal
  contract is the most valuable thing in the bundle and is three months of credibility
  per line.
- **Two axes.** Severity and confidence are separate, `Certain` is unreachable by
  reading code, and a tool's own severity never survives the parse.
- **Non-application code is reported and kept out of the bar.** Juice Shop produced 188
  test-suite findings against 47 application ones; the verdict would have been noise.
- **One cause, many occurrences.** Twenty call sites of one bad helper is one finding,
  anchored at the cause.
- **Grades are quoted with the module.** `unmeasured` is not a pass; `no-engine` with a
  written blind spot beats a rule with no answer key.
- **Authorization is never guessed.** The tier ceiling moves only when a human edits
  `scope.json`.

## 2. Gaps in what the tool can see

### 2.1 One profile, for every kind of system (**blocks the most value**)

`scope.json` decides *how far a run may go* — tier, hosts, authorization. Nothing
decides *what this kind of system should be checked for*, or which modules are
**deliberately out of scope for this product**.

What it would take: a project profile that selects modules, sets the bar per module, and
records an out-of-scope decision with a reason, so an unchecked layer is a recorded
decision rather than an absence. That changes the meaning of a clean report from
"fourteen modules found nothing" to "the eight modules this product needs found
nothing, and six were declared irrelevant, by a named person, on a date".

This is larger than any missing rule, and it is first.

### 2.2 Taint stops after one hop

`crossfile.mjs` resolves **one** hop, by name, to a function the target defines. It is
not a call graph and does not pretend to be one: an unresolved helper becomes a ledger
gap naming the call. That is honest and it is still a ceiling — a two-hop sanitizer
wrapper reads as unsanitized, and a two-hop sink reads as nothing at all.

Options, cheapest first: lean harder on `semgrep` where it is installed (it has the
engine; we have the ledger); or build a real module graph, which is a milestone of its
own and changes the performance profile of every scan.

### 2.3 Privacy / PII data-flow — covered by nothing

Where personal data enters, where it is stored, where it leaves, and whether that
matches what was declared. No module, no rules, no grade. First concrete step: a
declaration file the project writes (what personal data exists, where it may go) and
checks that compare the code against it — the same shape as the profile in 2.1, which
is why they are adjacent in the order.

### 2.4 The image, not the source tree

`trivy fs` reads the source. Nothing here scans the **built image**, its base layers, or
a registry. M18 makes the related failure visible (no lockfile → `blind`), but a repo
whose dependencies are correct and whose base image is three years old still reads
clean. Adding `trivy image` is a small adapter change and a large increase in honest
coverage.

### 2.5 SBOM, provenance, signing

CycloneDX output, SLSA provenance, sigstore verification. Mostly a projection of what
trivy already knows, plus a verification step nothing here performs today.

### 2.6 Business logic (M11) stays `no-engine` — on purpose

Abuse cases, pricing flaws, workflow bypasses: the defects that cost real money. They
need the intended flow modelled and a human to try it. M11 exists to say so on every
run rather than to leave the subject unmentioned. **Do not ship a rule for it.** An
automated M11 that finds nothing would be worse than an honest `no-engine`.

## 3. Gaps in the evidence, not in the code

These are the ones that make the numbers mean less than they look.

### 3.1 Two adapters have never been measured

ZAP's installer needs elevation and has never run on this machine; this environment
refuses to execute nuclei. Both adapters are covered by unit tests, and **a unit test is
not a measurement**. Rows 23 and 24 of the coverage map say so; no grade claims
otherwise. Closing it needs a machine where both can run, and a dynamic benchmark pass
with each.

### 3.2 The dynamic tiers have faced one target, and we wrote it

`benchmarks/dynamic/` is ours, which caps it at `self-measured` forever. T1–T2 have
never met an application somebody else built. The honest fix is a second dynamic corpus
nobody here wrote — and it must be one that is *meant* to be attacked, under T2 and
loopback-only, or it is not an authorized target.

### 3.3 Nobody outside has reviewed this

The largest gap in the bundle's evidence. [`SECURITY.md`](../SECURITY.md) now says where
a reviewer starts and what classes of bug matter most here; it is not a substitute for
one.

### 3.4 The seam to the sibling bundles is manual

SARIF export is the only wired path and it is one-directional unless someone runs
`import`. Three sets of evidence a human still has to lay beside each other
(`security-coverage-map.md`, last section).

## 4. Ordered roadmap

Ordered by value for effort. The first two change what a clean report **means**; the
rest add coverage.

| | Milestone | Delivers |
|---|---|---|
| **M23** | **Project profile** | modules selected per product, a bar per module, an out-of-scope decision with a reason and a date; the report states the profile it ran under |
| **M24** | **Privacy / PII data-flow** | a declaration of personal data and where it may go, checks against it, a module and a benchmark |
| M25 | **Container image** | `trivy image`, base-image age, secrets in layers; the ledger distinguishes "source clean" from "image unchecked" |
| M26 | **Second dynamic corpus** | T1–T2 measured against a target nobody here wrote |
| M27 | **SBOM and provenance** | CycloneDX out, SLSA/sigstore verification in |
| M28 | **Beyond one hop** | semgrep where present, a module graph where not — each with the ledger entry it replaces |

Deliberately not on this list: mobile security, cloud posture (CSPM), container runtime
posture, network and TLS review, fuzzing, and pentesting. Each is a different discipline
and is better bought than built; naming them in the coverage map is the contribution
this bundle can honestly make.

## 5. Decisions only a human can make

Listed because an agent must not make them, and because they are blocking.

1. **Licence.** There is no `LICENSE` file. Until there is, the default is "all rights
   reserved" and nobody outside can legally reuse it — including the reviewer that 3.3
   asks for.
2. **Visibility.** The GitLab project is private. Public changes the review question and
   the disclosure question at once.
3. **Merging the open merge requests.** `main` deliberately sits behind so each milestone
   is reviewable on its own.
4. **Whether an external review is bought.** Everything in §3 points at it, and it is a
   budget decision, not an engineering one.
5. **The sdlc CI template.** An ai-sec T0 scan of a project that adopted it reported two
   Critical GitHub Actions script-injection findings in `.sdlc/ci/github-workflow.yml`:
   `${{ github.head_ref }}` and `${{ github.base_ref }}` interpolated into a `run:`
   block, where a fork branch name is attacker-controlled. The fix is to pass them
   through `env:`. **The template ships to every project**, so the root fix belongs in
   the sdlc bundle and every copy needs the same edit. Not an ai-sec milestone — but it
   is the most urgent item on this page, and it is the first finding this bundle
   produced that someone has to act on.

## Sources

The standards editions, corpora and tools behind everything above are listed with their
licences in [`skill-sources.md`](skill-sources.md). The layer-by-layer inventory,
including the thirty-two rows this roadmap draws its gaps from, is
[`security-coverage-map.md`](security-coverage-map.md).
