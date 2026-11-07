# M16 — the corpus that grades itself

2026-10-31. Every module whose grade rested on a benchmark we wrote was asked
the same question again by a corpus we did not write and could not have chosen
to suit us. Seven modules came out `measured`. One came out `failing`, four
`partial`, and the report that produced them was unreadable.

---

## 1. Why this one

The scorecard had three benchmarks and a known weakness: `mock/` and
`benchmarks/dynamic/` are ours, so the best they can award is `self-measured`,
and OWASP NodeGoat — the only external corpus — plants nothing for M3, M4, M13
or M14. Those four modules had the weakest evidence in the project, and three of
them had never been measured on anybody else's code at all.

OWASP Juice Shop closes it, and brings something none of the other three has:

> **It writes down its own answers.**

```ts
models.sequelize.query(`SELECT ... '${req.body.email}' ...`) // vuln-code-snippet vuln-line loginAdminChallenge
```

Twenty-seven lines carry that marker, across nine files. `benchmarks/juiceshop.mjs`
reads them back out. That removes the last place our judgement could flatter us:
on NodeGoat we chose which defects to record, from its tutorials. Here we chose
nothing.

It is also the first corpus of a realistic size — 1,468 files, 648 of them
TypeScript, with a test suite, an Angular frontend and an LLM chatbot.

## 2. The first run, before anything was changed

**2 of 27.** `routes/login.ts:34` and `routes/search.ts:23`, both SQL injection,
both the shape `mock/` already had.

Twenty-five misses is a number, not a finding. The useful part was reading them:

| what was missed | why |
|---|---|
| `bypassSecurityTrustHtml` on a product description | no rule knew Angular's escape hatch existed |
| `url.includes(allowedUrl)` as an allowlist | no rule knew an allowlist could be enforced wrongly |
| `// app.put('/api/Products/:id', security.isAuthorized())` | the guard is written, commented out, and one character from live |
| `keyGenerator` reading `X-Forwarded-For` | the limiter counts per value the attacker sets |
| `serveIndex('ftp')` | a directory made browsable |
| `/metrics` with nothing in front of it | an operational endpoint published |
| `{ _id: req.body.id }` into a NeDB filter | the value *is* the query language |
| a coupon tool whose discount is bounded by a sentence | the headline of §4 |

Eight rules, each of which had to generalise past this corpus to be worth
writing. With them: **16 of 27**.

## 3. What it broke: the report was 76% test suite

246 findings. 188 of them hardcoded credentials in `test/`, 10 in the challenge
exercise fixtures, one in a minified bundle. Forty-seven in the application.

Because `Critical` sorts above `High`, the first three screens were
`data/static/users.yml` seed passwords and `test/api/2fa.test.ts`. The SQL
injection in the login route was below the fold.

Nothing here was wrong. Every one of those findings is a pattern that really is
in that file. The report was accurate and nobody would have read it, which is a
worse failure than a false positive — a false positive gets argued with.

`verifying-findings` had told the reader to handle this by hand since M3: step 3
of the disproof checklist is *"is it in test, mock, fixture, example, vendored
or dead code?"*. Leaving a mechanical judgement to a person on every finding is
how a tool teaches people to skim it. NodeGoat was small enough that nobody
noticed.

`controller/coderole.mjs` now labels every finding `application`, `test`,
`fixture`, `example`, `generated` or `vendored`. A finding outside the
application:

- is **capped at `Tentative`**, with what the scanner claimed kept in
  `reported_confidence` — a pattern matched in a fixture has not been shown to
  be reachable in anything that runs;
- does **not count against the bar**, so a fixture cannot fail a build;
- is **grouped into one block** with a count per kind, instead of competing
  line-by-line with the application findings;
- and appears **in the coverage ledger**, because the difference between "the
  application is clean" and "the application findings are the short list" may
  not be left for a reader to infer from a path.

Nothing is dropped. A credential in a test file can be a live credential, and a
rule that deleted it would be the leak. The block says so in a line of its own.

Unknown shapes classify as `application`, deliberately: calling a handler a test
hides a real finding, while calling a test a handler only costs attention.

```
In non-application code (189) — reported, not counted against the bar
  generated: Regular expression open to catastrophic backtracking ×1
  test: Hardcoded credential ×184, Regular expression open to catastrophic backtracking ×3, Unpinned base image ×1
  a credential in a test file is still a credential — judge these, do not assume the path makes them safe
```

## 4. M14, measured at last, on a defect worth the trip

M14's status before this was: nine hand-verified true positives on one real
application, **recall unknown and partly known to be zero**. Juice Shop ships an
LLM chatbot and annotates its planted defect, so recall there is now a number.

The defect:

```ts
inputSchema: z.object({
  discount: z.number().describe('The discount percentage for the coupon (maximum 10)')
}),
...
const couponCode = security.generateCoupon(discount)
```

The bound is in a sentence. The sentence is an instruction to the model, and
**a model can be argued out of an instruction by anything it has read** — that
is what prompt injection is. The schema enforces nothing, and the handler mints
a coupon for whatever number comes back.

`tool-bound-stated-only-in-prose` fires when a `.describe()` states a limit in
prose and no validator in the same scope encodes one. It is quiet when the
schema carries `.max()`, and quiet when the prose states no bound — a
description is documentation, and most of them are.

This is the most transferable rule in the batch. Every agent framework invites
it: the schema field is where you tell the model what the argument means, and
telling the model is not the same as deciding.

## 5. A rule that named the wrong cause

`nosql-operator-injection` passed its own test and then reported this:

```js
await WalletModel.increment({ balance: totalPoints }, { where: { UserId: req.body.UserId } })
```

Sequelize binds that value. It is **not** operator injection — though taking
`UserId` from the body to credit a wallet is a real authorization defect, with a
different fix on a different line. A finding that names the wrong cause sends
someone to sanitize a value when the bug is whose row it is, and it is worse
than silence, because silence gets investigated.

Narrowed twice: the filter key must be a lookup key, and a Sequelize `where:`
disqualifies it. Both narrowings have a test that fails if they are removed.

## 6. The scorecard, and the five it still cannot answer

```
                engines  planted  found  reported  unaccounted  grade
  M1            2/3        6      5        51           34  partial
  M3            5/7        2      2        54           31  measured
  M4            3/5        3      1        13            3  partial
  M5            2/3        5      2        11            7  partial
  M6            2/4        3      3        20           16  measured
  M7            3/3        4      4        21           14  measured
  M8            1/1        3      3        20           16  measured
  M9            3/5        3      2        21           18  partial
  M10           2/3        1      1        30           28  measured
  M12           2/3        1      0         9            0  failing
  M13           2/3        2      2        34           31  measured
  M14           1/1        1      1         9            7  measured

7 measured · 4 partial · 1 failing · 1 unmeasured · 1 no-engine
```

Five defects are in the denominator and will stay there:

| defect | why it is out of reach |
|---|---|
| unguarded frontend routes | a route without a guard is the normal case. Which routes need one is a statement about the application, not a pattern in it. |
| crypto addresses in the redirect allowlist | whether an entry belongs in an allowlist is a question about the business. |
| weak password hash | the weak primitive is behind `security.hash` in another module. The same call-boundary blind spot as M14's indirect prompt injection. |
| review update ignores the owner | the defect is that a value which **was** fetched is not used. Recognising it means knowing what should have been there. |
| register as admin | mass assignment is only a defect when an assignable field is privileged, and which one that is depends on the roles. |

Deleting the questions you cannot answer turns a benchmark into a decoration.
`tests/juiceshop-benchmark.test.mjs` fails if a defect marked undetectable
carries no reason, if a reason is shorter than a sentence, or if more than half
the benchmark is out of reach — at which point the grade stops being about the
scanner.

M12 `failing` is the honest reading of one planted defect, zero found. It is a
worse-looking grade than `unmeasured` and a better-informed one.

## 7. Numbers

| | before | after |
|---|---|---|
| benchmarks | 3 | **4** |
| corpora nobody here wrote | 2 | 3 |
| answer keys nobody here wrote | 0 | **1** |
| modules `measured` | 9 (NodeGoat) | 9 + **7 on a second corpus**, M3/M13/M14 among them |
| built-in rules | 23 | **31** |
| tests | 422 | **462** |
| mutations | 117 | **125** |
| largest corpus scanned | 1,005 files | **1,468** |

## 8. What this still does not prove

- 16 of 27 is not 27 of 27, and eleven annotated lines go unreported. Five of
  them are argued above; the other six are the four frontend routes and the two
  allowlist entries, which are the same two arguments.
- Juice Shop is a teaching application. Its defects are placed to be found by
  someone learning, which is not the same as the defects a team ships by
  accident.
- `unaccounted` is still 30-ish per module. Those are real findings in a
  deliberately vulnerable application that the answer key never planted — not
  noise, and not verified either.
- Nothing here was verified by a second party. Every finding in these runs is
  `unverified`, and the verdict says so.
