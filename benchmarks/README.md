# Benchmarks

Recorded answers, so `sec modules` reports a measurement instead of a rule count.

## The four of them

| | target written by | answers written by | evidence | best grade reachable |
|---|---|---|---|---|
| `mock/` | us | us | reading files | `self-measured` |
| **OWASP NodeGoat** | someone else | us, from its tutorials | reading files | `measured` |
| **OWASP Juice Shop** | someone else | **the target itself** | reading files | `measured` |
| **`benchmarks/dynamic/`** | us | us | sending requests | `self-measured` |

Different weaknesses, different benchmarks. NodeGoat answers *would we find this
in code we did not write*. The dynamic benchmark answers *is this finding
anything more than a pattern that matched* — its defects are reported because a
request was sent and the answer read, which is a different claim from the same
words produced by a regular expression. Juice Shop answers the question the
other three cannot: *what does this look like on a repository the size of a real
one* — 1,468 files, a test suite, a frontend and an LLM chatbot.

Juice Shop is also the only one whose answers we did not write. It annotates the
exact line of each planted defect in its own source:

```ts
models.sequelize.query(`SELECT ... '${req.body.email}' ...`) // vuln-code-snippet vuln-line loginAdminChallenge
```

`benchmarks/juiceshop.mjs` reads those markers back out, so the answer key can be
re-derived from the corpus instead of trusted.

Neither replaces the other, and `mock/` replaces neither: it is the one that
runs in a second and keeps the exam honest while a rule is being written.

## Why they exist

`mock/` gives every module full marks. An external corpus gave three modules
zero. Nothing about the ruleset changed between those two runs — only the target
did.

| | `mock/` | OWASP NodeGoat | OWASP Juice Shop | `benchmarks/dynamic/` |
|---|---|---|---|---|
| 2026-10-31 | 8 self-measured · 5 unmeasured · 1 no-engine | 9 measured · 4 unmeasured · 1 no-engine | **9 measured · 3 partial · 1 blind · 1 no-engine** | 8 self-measured |

The Juice Shop `unmeasured` in that row became `blind` without anything being
fixed: M2 reported no dependency findings because the corpus ships no lockfile,
so there were no package versions for trivy to read. The grade now says which
capability was missing instead of leaving a zero to be read as clean
([evidence](../docs/evidence/m18-blind.md)). M2 is `measured` on NodeGoat, which
commits one.

The three `partial` rows each name what was missed, and the three misses behind
them are arguments rather than bugs — a route without a guard is the normal
case, an allowlist entry is a business question, and the third is in
`docs/evidence/m17-crossfile.md` §4. The column had a `failing` in it until the
cross-file check landed; a benchmark that never shows one was chosen to be
passed.

NodeGoat's M2 and M10 are `measured` only when `trivy` is on PATH. Without it
they grade `failing`, which is the right answer to a different question — the
rules are fine and the scanner is absent, and the coverage ledger says so on
every run.

A fixture you wrote cannot surprise you. Keeping the numbers side by side is the
cheapest way to stop a green board from meaning nothing.

## Using the static ones

A benchmark is an `expected.json` placed at the root of a checkout of the target.

```bash
git clone --depth 1 https://github.com/OWASP/NodeGoat.git /tmp/nodegoat
cp benchmarks/nodegoat-expected.json /tmp/nodegoat/expected.json

node bin/sec.mjs scan /tmp/nodegoat --slug ng
node bin/sec.mjs modules --slug ng
```

```bash
git clone --depth 1 https://github.com/juice-shop/juice-shop.git /tmp/juice-shop
cp benchmarks/juiceshop-expected.json /tmp/juice-shop/expected.json

node benchmarks/juiceshop.mjs /tmp/juice-shop   # re-derive the answer key first
node bin/sec.mjs scan /tmp/juice-shop --slug js
node bin/sec.mjs modules --slug js
```

Both are deliberately vulnerable practice applications. They are scanned read
only at T0 and are never run. Neither is vendored into this repository — what is
committed here is the answer key, and `tests/juiceshop-benchmark.test.mjs`
checks that the key still describes rules and modules that exist, which is the
part that rots without the corpus present.

## Using the dynamic one

```bash
npm run bench:dynamic
```

It starts `benchmarks/dynamic/app.mjs` on an ephemeral loopback port, scans it at
T2, scores the result and shuts the server down. `tests/dynamic-benchmark.test.mjs`
runs the same thing and fails the suite on a missed defect.

Three things about it are deliberate:

- **The app refuses to bind anywhere but 127.0.0.1.** A benchmark target
  reachable from another machine is an invitation, and "it was only for testing"
  is how these end up on the internet.
- **The harness writes its own `scope.json`** — the one thing ai-sec will not let
  a scan do for a user's target. It is allowed here because the target is a
  server this process started, on a port it bound, from source in this
  repository, and `assertOwnLoopbackTarget` checks that before anything is
  written. Nothing about it generalises; pointing it at a host is not a
  configuration change, it is a refusal.
- **Two endpoints are deliberately correct.** `/api/profile/:id` answers 403 to
  the wrong account, and `/api/inbox` answers 200 to every account with that
  account's own data. The second is the one that matters: a check that reads the
  status code and stops gets the first right by accident and reports the second.

## Writing one

- Take the defects from **the target's own documentation**, not from what the
  scanner happens to find. Choosing them to suit the rules is how a benchmark
  becomes a mirror.
- Record `cause` and `not_the_cause` for each. Naming the shape of a defect is
  not the same as naming its cause, and only `not_the_cause` catches the
  difference — "an IDOR is not injection", "SSRF is not an open redirect".
- Key a defect on `cwe` when it is one weakness at one place. Use `issue_type`
  or `rule_id_prefix` when it is a **class**: NodeGoat's vulnerable dependencies
  were recorded as CWE-1104, and trivy files each CVE under that CVE's own
  weakness, so the card reported a miss with fifty-two findings in the file.
- Include something that is **not** a defect, in `must_not_report`. A benchmark
  made only of defects measures recall and nothing else, and scores full marks
  for a tool that reports everything.
- Set `corpus` to the upstream project. That field, not the directory name, is
  what makes the run count as `measured`: the strength of a benchmark is who
  wrote the **code**, not who recorded the answers.
- List anything real the scan finds that the benchmark did not plant under
  `accepted`, once a human has judged it. Everything else stays `unaccounted`,
  which means unverified — not wrong.
