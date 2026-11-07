# M6 — dogfood

Two real repositories, 2026-10-31, ai-sec v0.6.0, tier T0, scanners `builtin` and `gitleaks`.

The point of this milestone is not the findings. It is what running on real code said
about the tool, and nine of those things were defects.

---

## 1. ai-sec scanned by ai-sec

The hardest first target: a security tool's own source is full of strings that look like
credentials, because it needs them to test itself.

### Result

| | |
|---|---|
| Files | 87 |
| Findings, first run | 36 |
| In production code | 6 |
| In `tests/` and `mock/` | 30, all `Info` |
| After human judgement | **PASS**, qualified by a non-empty ledger |

All six production findings were judged false positives, each with a reason recorded in
the baseline:

| Finding | Why it is not real |
|---|---|
| `hardcoded-credential` · `controller/rules.mjs:150` | The G5 gate self-tests the redactor against a published AWS documentation key. The literal is required for the check to mean anything. |
| `hardcoded-credential` · `lib/doctor.mjs:97` | The same probe, in the doctor's safety check. |
| `hardcoded-credential` · `adapters/scanners/fake/adapter.mjs:52` | Canned finding data in a test double. |
| `sql-injection` · `adapters/scanners/fake/adapter.mjs:30` | Evidence text inside a canned finding — data describing a vulnerability, not a query this code runs. |
| `weak-randomness` ×2 · `adapters/scanners/fake/adapter.mjs` | The same fixture. |

No special case was added for ai-sec's own paths. The product's own mechanism handled it:
`baseline promote`, then `judge` with a reason, then the next run reports
`new 0 · unchanged 36 · suppressed 6` and a PASS that states its coverage gap in the first
line. That is pillar P2 working on a real repository rather than in a test.

### What it got right

- **Test placement.** 30 of 36 findings landed in `tests/` and `mock/` and were reported at
  `Info` with the reason stated, not dropped and not alarming.
- **No confidence inflation.** Nothing claimed `Certain`. A static pass cannot reproduce
  anything, and the scoring held that line without being told.
- **The structural checks fired on the planted defects and nowhere else.**

---

## 2. `recall` — a Go repository

Chosen because nothing about it resembles the mock: a different language, no routes our
detector can read, and a real history with worktrees in it.

### Before the fixes

| | |
|---|---|
| Findings | 29 — **2 Critical, 27 High** |
| Genuinely actionable | 0 |

Every one was a test fixture, a worktree duplicate, or a review artifact. A report like
that is worse than no report: it trains the reader to ignore the tool.

### After

| | |
|---|---|
| Findings | 6 — **all `Info`** |
| All in | `_test.go` files |

---

## 3. The nine defects this found

Every one was fixed, and every one now has a test and a mutation that fails when the fix
is removed.

| # | Defect | How it showed up |
|---|---|---|
| 1 | **A scanner's report path was not the path `parse` read.** `scanCommand` was given the run directory, `parse` the per-scanner directory. | gitleaks logged `leaks found: 2` and the run reported none. **Every finding it made was discarded silently** — the worst possible failure for a security tool. |
| 2 | **Absolute paths in findings.** | `C:/Users/luann/.../redact_test.go`. A fingerprint built from that is machine-specific, so the same finding is "new" on a colleague's checkout and in CI, and the baseline never converges. |
| 3 | **Test-code downgrade lived in one scanner.** | `builtin` knew; gitleaks did not. The same file was `Info` from one scanner and `Critical` from another. A judgement about *where a finding lives* belongs to the controller. |
| 4 | **Only JavaScript test conventions were recognised.** | Every `_test.go` in a Go repository reported at full severity. Added `_test.go`, `test_*.py`, `*_spec.rb`, `*Test.java`. |
| 5 | **Git worktrees were scanned as source.** | `.claude/worktrees/` holds two more copies of the repo, so each finding appeared three times. |
| 6 | **ai-sec scanned its own output.** | gitleaks walks the tree itself and read `.sec/.../raw/gitleaks.json`, reporting the secrets recorded there as new findings — a feedback loop that grows every run. |
| 7 | **`judge` demanded the full 64-character fingerprint** while the report printed twelve. | A tax on doing the right thing: the easy path was to leave the false positive unrecorded. Prefixes of 8+ are now accepted, and an ambiguous one is refused rather than guessed. |
| 8 | **A word in prose was treated as a framework.** | A Go repository was reported as "rails", because the word appeared once in a markdown file. Python and Ruby frameworks now need an import or a gem line. |
| 9 | **Zero routes read as "no routes".** | Route detection covers JS, TS and Python. On a Go repository, zero is a blind spot, not a result, and the surface now says so. |

### The shape of them

Seven of the nine are the same mistake in different places: **a judgement that belongs to
everything was implemented in one place.** Path normalization, test placement, artifact
exclusion — each was correct inside `builtin` and absent everywhere else. The fix was the
same each time: move it to `controller/locate.mjs` and let every adapter inherit it.

The other two (#1, #7) are about contracts between halves of the system — a path agreed by
one side and read by the other, and an identifier printed in one form and demanded in
another.

None of these were visible from the mock. The mock is a JavaScript repository with no
worktrees, no `.sec/` history and no Go files, so it exercised none of them. **A fixture
you wrote cannot surprise you.**

---

## 4. What is still open

- **M11 business logic is uncovered by any scanner**, as designed. It appears in every
  coverage ledger, which is correct and also means every run is qualified. Worth a
  convention: a module nobody can cover should perhaps be opt-in rather than always listed.
- **`adapters/scanners/fake/` holds fixture data in a production path.** It is judged as a
  false positive each run rather than excluded, which is the honest handling but costs six
  lines of baseline. Moving canned data to a `fixtures/` directory would resolve it properly.
- **The mutation suite now takes about twelve minutes** (46 mutations × the full suite).
  Worth running only the tests a mutation can affect.
- **gitleaks allowlists `AKIAIOSFODNN7EXAMPLE`** as a published documentation key; `builtin`
  does not. Neither is wrong, and the disagreement is exactly why several scanners are
  merged rather than one trusted — but it means a secret finding's absence from one tool
  says nothing.
