# M17 — one hop

2026-10-31. M16 produced a list of named misses. This closes the three that were
reachable, leaves the ones that are not, and the mechanism behind all three is
the same: read the second file.

---

## 1. The sentence every blind spot was

Every gap this project had written down said the same thing in different words.

> no regular expression crosses a call boundary

M14's indirect prompt injection. M12's weak password hash. M4's password
storage. Each is a sink that names a helper, and a helper that does the
dangerous thing somewhere else. Juice Shop is the clean specimen:

```ts
models/user.ts:73     this.setDataValue('password', security.hash(clearTextPassword))
lib/insecurity.ts:41  export const hash = (data) => crypto.createHash('md5').update(data).digest('hex')
```

Nothing on line 73 is wrong. Nothing on line 41 mentions a password. The defect
exists only in the pair, and the first Juice Shop measurement reported neither —
**M12 graded `failing`**, which was the correct grade for a tool that could not
look.

`adapters/scanners/builtin/crossfile.mjs` resolves **one** hop, only to a
function this target defines, only by name. It is not a call graph and does not
pretend to be. The under-claim is the design: a resolver that is wrong in ways
nobody can see is worse than a gap that is written down.

Three outcomes, and only one is a finding:

| | |
|---|---|
| resolved, helper uses a fast digest | a finding |
| resolved, helper uses a KDF | nothing, correctly |
| **unresolved** | a coverage-ledger gap naming the call |

The third row is the one that keeps this honest. A helper imported from a
package, or reached through two hops, produces *"how the password is stored was
not established"* rather than silence.

## 2. Twenty findings, one line

The first version reported per call site: **20 findings**, all from one
`createHash('md5')`.

This project's own skill tells its readers *"name the cause, not the symptom —
twenty findings with one root cause are one systemic finding with twenty
instances"*. The tool was doing the thing it tells people not to. Reporting
twenty makes the fix look twenty times bigger than it is and hides that they are
the same line.

Now: one finding, anchored at the helper, carrying all twenty call sites in
`occurrences`.

### Which exposed something that had been wrong since M15

The scorecard's `matches()` compared `finding.location.file` and nothing else.
`occurrences` has been printed in every report since M15 and was **never
scored**. A finding anchored at the cause, listing the call site the benchmark
recorded, counted as a miss — the scorecard was holding the answer in a field it
did not read.

Fixed, and mutation-guarded. It is a small function and it had been quietly
wrong for a whole milestone, which is the usual shape.

## 3. The gap between two lists

`register-as-admin` was recorded as `judgement`: mass assignment is only a
defect when an assignable field is privileged, and which field that is depends
on the application.

That is still true, and it turned out to be readable:

```ts
models/user.ts:28  declare role: CreationOptional<string>
server.ts:512      { name: 'User', exclude: ['password', 'totpSecret'], model: UserModel }
```

The model declares a column that decides what the account may do. The generated
CRUD resource lists its exclusions and that column is not among them. Neither
line is wrong; the defect is the **gap between two lists**, which is a thing you
can compute once you are willing to read both files.

Remediation says the part that outlives this corpus: prefer an allowlist of
writable fields to a denylist of excluded ones, because a denylist is wrong
again every time a column is added.

## 4. A clearing condition that cleared the case it should catch

`review-update-ignores-owner`: the handler reads the authenticated account and
then filters on `req.body.id`.

`objectReferenceWithoutOwnershipCheck` already existed and stayed silent,
because it treats **"the caller is consulted"** as a clearing condition. Juice
Shop shows why that is wrong: fetching the user and ignoring it is the defect,
and it is the strongest possible disguise for broken object-level authorization
— the fix looks like it is already there.

`callerIdentityFetchedAndUnused` reports a scope that binds the caller, never
reads the binding again, and goes on to read or write stored data.

### And then it did not claim the defect

On the real file, the check **correctly does not fire**. `user` is bound on line
16 and used again on line 24 — inside `challengeUtils.solveIf(...)`, Juice
Shop's own challenge-tracking scaffolding. Deciding that a use inside `solveIf`
is not an authorization use means knowing what `solveIf` is for, which is a
statement about this one application.

So `review-update-ignores-owner` stays a miss, with a better reason than it had.
The check is kept because it fires where the variable is genuinely never read
again — four times on this corpus, zero false positives — and tuning it to pass
one benchmark is the thing benchmarks exist to prevent.

## 5. The scorecard

```
                         M16        M17
  measured                7     →     9
  partial                 4     →     3
  failing                 1     →     0
  unmeasured              1           1
  no-engine               1           1
```

M4 `partial 1/3` → **`measured` 3/3**. M12 `failing 0/1` → **`measured` 1/1**.

Three defects remain unfound on this corpus, and all three are arguments rather
than bugs:

| | why it stays |
|---|---|
| unguarded frontend routes | a route without a guard is the normal case; which ones need one is a statement about the application |
| crypto addresses in the redirect allowlist | whether an entry belongs in an allowlist is a question about the business |
| review update ignores the owner | §4 — the variable *is* used, just not for authorization |

## 6. Answers that changed

Two defects moved from "out of reach" to "found", and the answer key was edited
after the rules were written. That is the single most dangerous move available
here, so both carry a `was_missed_until` field saying what changed, and
`register-as-admin` keeps `cwe_originally_recorded: CWE-269` beside its more
precise `CWE-915`.

`tests/juiceshop-benchmark.test.mjs` fails if such a field is shorter than a
sentence. The grades moved because the tool changed; the record says so in the
file rather than in a commit message nobody re-reads.

## 7. Numbers

| | M16 | M17 |
|---|---|---|
| detection modules in builtin | 2 (patterns, structural) | **3** (+ cross-file) |
| checks that read two files | 0 | **2** |
| tests | 462 | **477** |
| mutations | 125 | **133** |
| modules `measured` on Juice Shop | 7 | **9** |
| modules `failing` | 1 | **0** |

## 8. What this still does not prove

- One hop is one hop. A helper that calls a helper is not followed, and nothing
  reports that it was not — the unresolved ledger entry fires when the *name*
  cannot be found, not when the body defers again.
- `collectModelFields` infers a model's name from its filename. A project that
  names files differently gets no finding and no gap entry.
- The privileged-field list is short on purpose, and short lists miss things.
  `plan`, `tier`, `quota` and every domain-specific authority column are absent.
- Still nothing here has been verified by a second party.
