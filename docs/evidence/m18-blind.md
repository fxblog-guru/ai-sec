# M18 — ran is not read

2026-10-31. M17 left one module on Juice Shop reading `unmeasured` and nobody
asked why. The answer turned out to be the quietest failure in the bundle.

---

## 1. Zero, with nothing behind it

`sec modules` on OWASP Juice Shop, after M17:

```
  M2            2/2        0      0         0            0  unmeasured
```

Two engines installed, both credited with M2, and not one dependency finding.
The reading a hurried person takes from that row is *nothing was found*. The
true reading is *nothing was read*.

Juice Shop ships **no lockfile**. `package.json` states `"express": "^4.17.0"`,
and a range is not a version: trivy will not guess which one is installed, so
its vulnerability database has nothing to match against. It exits 0, reports no
dependency results, and every layer above it is correct in saying there were
none.

This is the failure mode the project already had a name for — *never a quiet
pass* — appearing in the one place nothing had been checking: not the findings,
not the rules, but a scanner's **capability**.

## 2. `detect`, `preflight`, and the thing between them

The adapter contract had two questions and needed a third.

| question | answer | what it costs when false |
|---|---|---|
| `detect` | is the scanner installed? | the whole scanner, and the ledger says so |
| `preflight` → `ok: false` | can it reach **this** target? | the whole scanner, and the ledger says so |
| *(missing)* | can it do, here, **each** of the things it is credited with? | — |

Without a lockfile, trivy's misconfiguration and secret checks work perfectly —
they found 94 findings on this corpus. Refusing the whole scanner would have
thrown those away to report one gap. Running it and saying nothing reported the
gap as a clean result.

So `preflight` may now return a **partial** refusal:

```js
return {
  ok: true,
  degraded: [{
    capability: 'dependency CVEs',
    modules: ['M2'],
    reason: '…zero dependency findings here means nothing was read, not that nothing is vulnerable…',
    unblock: 'commit a lockfile, or install first (`npm ci --ignore-scripts`) and re-scan, …',
  }],
};
```

The scanner runs. The capability that cannot run is named, carried on the run
record, written into the coverage ledger, and attached to the module that was
counting on it.

## 3. A grade that does not blame the wrong thing

A degraded capability needed a grade, and neither existing one was honest:

- `failing` means *an engine ran and found none of them* — it blames the rules
  for a defect they were never shown.
- `unmeasured` means *nothing has ever checked this* — true, and it does not say
  why, so it reads as a gap in our effort rather than a gap in the target.

`blind` is the new one, and it is narrow on purpose:

```js
if (installed === 0) return 'no-engine';
if (blind && found < planted) return 'blind';
if (planted === 0) return blind ? 'blind' : 'unmeasured';
```

A blind capability that cost nothing — the module found every planted defect
anyway — does **not** downgrade the module. A grade for a limitation that
changed no outcome would be a grade for nothing.

## 4. On the corpus

```
  M2            2/2        0      0         1            0  blind
         blind spot: trivy could not check dependency CVEs on this target: no lockfile or
         other resolvable manifest was found, so trivy has no package versions to match
         against its database — zero dependency findings here means nothing was read, not
         that nothing is vulnerable (package.json alone states ranges, not versions)
```

Nothing improved. A row that was quietly wrong is now loudly incomplete, which
is the only kind of progress available when the limitation is real.

The same sentence reaches `Could not evaluate` in the report, where a reader
looking for what was skipped will actually find it.

**M2 on Juice Shop cannot reach `measured`, and that is a property of the
corpus**: its answer key is derived from its own `vuln-code-snippet`
annotations, and Juice Shop does not annotate dependency defects. M2 is
`measured` on NodeGoat, where trivy resolves 52 CVEs from a committed lockfile.
Two corpora, two different things provable.

### The unblock is advice, not a measurement

`npm install --package-lock-only --ignore-scripts` would give trivy something to
read without executing any package code. **This environment refused to run it**,
so the advice in the ledger is reasoned, not demonstrated. It is written here
rather than left as an implied claim.

## 5. The second hole, found while wiring the first

`expected.json` is a **conventional** filename, not a reserved one. `benchmarkFor`
read any file by that name in the scanned target and graded the run against it.

A repository with its own `expected.json` — golden files, a test corpus, a
fixture directory — would have produced a scorecard built from somebody else's
data, with the source line confidently naming the file. A malformed one threw
and took the command down.

Now it must look like an answer key (`defects` must be an array) or it is
ignored with a reason, and bad JSON reports itself. Moved out of `bin/sec.mjs`
into `lib/scorecard.mjs` on the way, because a function nothing can import is a
function nothing can test.

## 6. Numbers

| | M17 | M18 |
|---|---|---|
| tests | 477 | **493** |
| mutations | 133 | **141** |
| adapter contract questions | 2 | **3** |
| Juice Shop: `measured` | 9 | 9 |
| Juice Shop: `unmeasured` | 1 | **0** |
| Juice Shop: `blind` | — | **1** |

No score went up. One row stopped lying.

## 7. What this still does not prove

- Only trivy declares a partial refusal. semgrep against a language it has no
  rules for, gitleaks against a repository with no history, nuclei against a
  host that answers nothing — each is the same shape and none of them says so
  yet.
- `dependencyManifests` walks four levels deep and stops at forty hits. A
  monorepo that keeps its lockfiles deeper looks lockfile-less.
- The grade is per module, not per capability. A module with two blind
  capabilities and one working one reads the same as a module with one.
- Still nothing here has been reviewed by a second person.
