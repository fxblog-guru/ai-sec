# Upgrading ai-sec

Written for: someone who already has `.sec/` folders from an older version and wants
the new one without losing their judgements — or quietly losing their guarantees.

**Pre-1.0.** The contracts in `CONTRACTS.md` are versioned (`sec-result/v1`,
`sec-state/v1`, `sec-scope/v1`) and have not broken yet, but the minor number moves
with the milestone, not with compatibility. Read the section for every version you
are skipping, not only the newest.

## How you hear about an update

`VERSION` holds the bundle version; `CHANGELOG.md` says what moved and why. Each
milestone that changed what the tool can *see* also ships an evidence note under
`docs/evidence/` — that is where a claim is justified, not in the changelog line.

## Every upgrade, whatever the kind

Four steps, in this order. The third is the one people skip and the one that matters.

```bash
npm test                      # the new version's own suite must pass on your machine
node bin/sec.mjs doctor       # what is installed now, and what each absence costs
node bin/sec.mjs scan .       # re-scan with the baseline still in place
node bin/sec.mjs report       # read "Could not evaluate" before you read the verdict
```

1. **Run the suite.** There are no dependencies to install; if it fails here it fails
   for everyone, not only for you.
2. **Re-run `doctor`.** A new version may credit a scanner with a capability it did not
   have before, which changes what its absence costs you.
3. **Re-scan before you promote anything.** A version that can see more will report
   findings your baseline has never seen. They are **new to the baseline and old in the
   code** — that is correct, not a regression, and it is exactly the moment to read them
   rather than promote them away.
4. **Only then** `baseline promote`, if the new state is the state you accept.

Judgements (`false_positive`, `accepted_risk`) and verifications survive upgrades: they
are keyed by fingerprint in `baseline.json` and nothing in an upgrade rewrites them. A
judgement is lost only if the **fingerprint** changes, and a version that changes
fingerprinting says so below.

Nothing here edits `scope.json`. Your tier ceiling, host allowlist and authorization
record are yours; no upgrade raises them.

---

## 0.18.0 (from 0.17)

**No manual steps. One number may move, and it is meant to.**

- A module that depended on a scanner capability unusable against your target now reads
  **`blind`** instead of `unmeasured` or `failing`. Most visibly: **M2 against a
  repository with no lockfile.** Nothing got worse; a row stopped lying. If a dashboard
  of yours matches grade strings, add `blind` to it — `GRADES` is now
  `no-engine · blind · unmeasured · failing · partial · self-measured · measured`.
- `result.json` gains `degraded[]`, and `events.ndjson` gains the `scanner_degraded`
  type. Both are additive; a reader that ignores unknown fields is unaffected.
- **`expected.json` is no longer trusted on filename alone.** If you scanned a target
  that ships its own `expected.json` fixtures, older versions may have graded your
  modules against *that file's* contents with no warning, and a malformed one took
  `sec modules` down. It must now contain a `defects` array or it is ignored with a
  reason. **Re-run `sec modules`** after upgrading: a grade you recorded from an older
  version against such a target was not measuring what it said.
- `benchmarkFor` moved from `bin/sec.mjs` to `lib/scorecard.mjs`. Only matters if you
  imported it.

## 0.17.0 (from 0.16)

**Expect new findings in code you have not touched, and expect twenty to become one.**

- The first checks that read a **second file** (`crossfile.mjs`). A password setter that
  calls a helper, and the helper being MD5 in another module, is now one finding — the
  pair is the defect and neither line is wrong on its own. If your baseline predates
  this, these arrive as new.
- **One cause reported in twenty places is now one finding with twenty `occurrences`**,
  anchored at the cause. The nineteen fingerprints that disappear were never separate
  defects; a judgement attached to one of them does not carry over, so re-judge the
  surviving finding once.
- `occurrences` is now **scored** by the scorecard. Grades may rise without any rule
  changing, because the answer had always been in a field the matcher did not read.

## 0.16.0 (from 0.15)

**The biggest change to what a report looks like.**

- **Non-application code** (test, fixture, example, generated, vendored) is capped at
  `Tentative`, kept out of the verdict bar, grouped into one counted block, and named in
  the ledger. Nothing is dropped — a credential in a test file is still a credential —
  but a build no longer fails on seed data. A pipeline that was failing on test findings
  will start passing: that is the fix, and the block is still there to read.
- Six skills were updated after ten milestones of drift. If you copied a skill into a
  project, **re-copy it**; the old one describes an assessment that was correct for M5.

## 0.15.0 (from 0.5)

**One contract correction, and it changes what you are authorized to do.**

- **Tier definitions were wrong and are now right.** T1 used to be described as "sends
  nothing" while `probe` plainly made requests. A tier grades what the traffic could
  *do*, not whether traffic exists. T1 is now "plain reads of known paths; no parameters
  added, no payloads". **Re-read `scope.json`**: if someone approved `max_tier: T1` on
  the old wording believing nothing would be sent, that approval was given for a
  different thing and should be asked for again.
- `url` targets, the `probe` scanner, nuclei and ZAP adapters, and auto-stop arrive here.
  None of them runs without a host allowlist and a tier ceiling you set by hand.

## 0.5.0 and earlier

Development milestones. Anything created by them is a `.sec/` folder you can delete and
re-create; there is no migration and none is needed.

---

## Rollback

The bundle keeps no global state. To go back, check out the older commit and re-run —
your `.sec/<slug>/` folders are read by both. Two cautions:

- A baseline promoted under a **newer** version may contain fingerprints the older one
  cannot produce. They will read as `fixed` on the old version. They are not fixed.
- A grade recorded by a newer version does not mean the same thing on an older one.
  `blind` did not exist before 0.18; it read as `unmeasured`, which said nothing about
  why.

When in doubt, delete `.sec/<slug>/runs/` (history, safe to lose) and keep
`baseline.json`, `scope.json` and `lessons.md` (judgement, expensive to lose).
