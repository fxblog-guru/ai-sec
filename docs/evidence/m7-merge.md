# M7 — the merge that was never a merge

2026-10-31. Installed a second real engine and pointed it at `mock/`.

ai-sec's first claim, on the first line of its README, is that results from several
scanners are "merged by fingerprint, never summed". With one engine that claim cannot
be tested. With two it failed immediately.

---

## 1. What one install exposed

`pip install semgrep` took the static pass from 24 built-in checks to something over
two thousand rules. On `mock/`:

| | findings |
|---|---|
| builtin + gitleaks | 13 |
| **+ semgrep** | **19** |
| after the merge was fixed | **14** |

Those 19 were never 19 defects. They were 14, with five counted twice:

```
app/upload.js:10   3 findings   one path traversal
app/routes.js:14   2 findings   one open redirect   builtin Medium, semgrep High
app/auth.js:11     2 findings   one MD5 password hash
Dockerfile:10      2 findings   one root user
```

The open redirect is the worst of them: the same line scored **Medium by one scanner and
High by another**, reported twice, with nothing anywhere saying the two disagreed.

## 2. Two causes, both structural

### Identity was the scanner's own vocabulary

```
fingerprint = sha256(rule_id + location + insertion_point)
```

`rule_id` is whatever the tool calls it. Semgrep says
`javascript.express.security.audit.express-open-redirect`; we say `open-redirect`. Two
strings, two fingerprints, two findings — forever, by construction.

So **corroboration had never once fired.** The rule that independent agreement promotes
confidence had been in `merge.mjs` and in CONTRACTS since M1, with a test proving it
worked on synthetic input, and it could not reach a real finding because no two real
scanners could ever land on one fingerprint.

CWE is the shared vocabulary, and it is not usable raw:

| defect | semgrep | builtin |
|---|---|---|
| MD5 password hash | CWE-327 broken algorithm | CWE-916 no KDF |
| container runs as root | CWE-269 | CWE-250 |

Both are right. Keying on the number alone merged two of the four duplicates and left two.
`controller/taxonomy.mjs` groups CWEs into families, and the family is the identity. The
fallback chain is explicit, and `identity_basis` records which rung was used, so the
coverage of that table is measurable rather than assumed.

### The symbol half of the location

The fingerprint prefers `file#symbol` over `file:line`, because a symbol survives edits
above it. Almost no scanner reports a symbol. So:

```
builtin   app/auth.js#hashPassword
semgrep   app/auth.js:11
```

Same defect, same line, two identities. This is **exactly** the M6 lesson again — a
judgement that belongs to every finding implemented in the one adapter that happened to
need it first. It moved to `controller/locate.mjs`, which already owned path
normalization and test placement, and now resolves the enclosing symbol for every
adapter, in JavaScript, Python, Go, Java, C# and Ruby.

## 3. After

```
[High/Firm] Password stored without a key derivation function  app/auth.js:11  (builtin + semgrep)
[High/Firm] Open redirect  app/routes.js:14  (builtin + semgrep)
    scanners disagree on severity: semgrep High, builtin Medium — taking the highest
[High/Firm] Path traversal  app/upload.js:10  (builtin + semgrep)
[Medium/Firm] Container runs as root  Dockerfile:10  (builtin + semgrep)
```

`Password stored without a key derivation function` was `High/Tentative` from the pattern
rule alone. Semgrep reached it by dataflow, the methods differ, and confidence promoted to
`Firm` — the first time in the project's life that rule has done anything.

Severity disagreement is now a line in the report. The resolution is still the highest
proposed; what changed is that a reader can see there was a choice.

## 4. What this cost, and the rule it suggests

Three of the four fixes were in code written months of milestones ago, fully tested, and
wrong in a way no test could see — because every test fed the merge **synthetic** partial
findings that already shared a `rule_id`.

> A test that builds both sides of an interface proves the two halves agree with each
> other, not that either agrees with the world.

The mock has the same shape of problem as the fixtures did in M6: it is ours. What found
this was not a better test, it was a second real engine. The cheapest remaining source of
truth about ai-sec is **installing the next scanner**.

## 5. Still open

- **nuclei and zap are not installed**, so M7 API and M13 logging have no dynamic engine
  and the claim is untested at T1+.
- **trivy is installed but not on PATH** (winget puts it in `WinGet/Packages/...`).
  `sec doctor` reports it missing, which is literally true and practically unhelpful.
- **`identity_basis: 'rule_id'`** findings cannot merge with anything. Nothing yet reports
  how many findings are in that state, so the taxonomy's coverage is unmeasured.
- The display name comes from the type catalogue. A semgrep rule with no `name` falls back
  to its raw id, which is still unreadable (`direct-response-write`).
