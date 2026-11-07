// The exam — pillar P1's failing check.
//
// mock/expected.json records the known answer for every planted defect, including
// `not_the_cause`: the plausible wrong answer. A scanner that produces output is
// easy; one that names the right cause is the thing worth testing.
//
// These cases are the security equivalent of "p95 rises with load, CPU low -> ?".
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

import { scanRepo } from '../adapters/scanners/builtin/engine.mjs';
import { mergeFindings, summarize } from '../controller/merge.mjs';
import { severityRank } from '../controller/merge.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const MOCK = join(ROOT, 'mock');
const EXPECTED = JSON.parse(readFileSync(join(MOCK, 'expected.json'), 'utf8'));

const findings = mergeFindings(scanRepo(MOCK).findings);
const byCwe = (cwe) => findings.filter((f) => (f.sources, f.rule_id) && cweOf(f).includes(cwe));
const cweOf = (f) => ruleFor(f)?.classification?.cwe ?? [];
const owaspOf = (f) => ruleFor(f)?.classification?.owasp ?? [];

// mergeFindings keeps the rule on the first partial; re-read it from the raw scan
const RAW = scanRepo(MOCK).findings;
function ruleFor(f) {
  return RAW.find((r) => r.rule_id === f.rule_id)?.rule;
}

// --- Case by case, against the recorded answers ----------------------------

for (const d of EXPECTED.defects) {
  test(`exam: ${d.id} — the defect is found at all`, () => {
    const hits = byCwe(d.cwe);
    assert.ok(hits.length > 0, `nothing reported for ${d.cwe} (${d.cause})`);
  });

  if (d.owasp) {
    test(`exam: ${d.id} — it is classified under the right OWASP category`, () => {
      const hits = byCwe(d.cwe);
      const owasp = new Set(hits.flatMap(owaspOf));
      assert.ok(owasp.has(d.owasp),
        `${d.id} should be ${d.owasp}; got ${[...owasp].join(',') || 'none'}`);
    });
  }

  // An AI/LLM defect is scored against the OWASP Top 10 for LLM Applications
  // 2025, which is a separate list from the web Top 10 and not a substitute for it.
  if (d.owasp_llm) {
    test(`exam: ${d.id} — it is classified under the right OWASP LLM category`, () => {
      const hits = byCwe(d.cwe);
      const llm = new Set(hits.flatMap((f) => ruleFor(f)?.classification?.owasp_llm ?? []));
      assert.ok(llm.has(d.owasp_llm),
        `${d.id} should be ${d.owasp_llm}; got ${[...llm].join(',') || 'none'}`);
    });
  }

  if (d.finding_class) {
    test(`exam: ${d.id} — it is a ${d.finding_class}, not the other thing`, () => {
      const hits = byCwe(d.cwe);
      assert.ok(hits.some((f) => (f.finding_class ?? 'vulnerability') === d.finding_class),
        `${d.id} is a ${d.finding_class}: ${d.cause}`);
    });
  }

  test(`exam: ${d.id} — it is scored at least ${d.min_severity}`, () => {
    const hits = byCwe(d.cwe);
    const best = Math.max(...hits.map((f) => severityRank(f.severity)));
    assert.ok(best >= severityRank(d.min_severity),
      `${d.id} scored below ${d.min_severity}`);
  });

  if (d.file) {
    test(`exam: ${d.id} — it points at the right file`, () => {
      const hits = byCwe(d.cwe);
      assert.ok(hits.some((f) => f.location.file === d.file),
        `${d.id} expected in ${d.file}; got ${hits.map((f) => f.location.file).join(', ')}`);
    });
  }
}

// --- The cases that separate naming a cause from naming a symptom ----------

test('exam: cross-tenant read is NOT reported as SQL injection', () => {
  // The query is parameterized. Calling this injection is the classic wrong answer:
  // parameterization binds values, it does not decide which rows come back.
  const f = findings.find((x) => x.rule_id === 'missing-tenant-predicate');
  assert.ok(f, 'the tenant finding is missing entirely');
  assert.deepEqual(cweOf(f), ['CWE-639'], 'must be CWE-639, not CWE-89');
  assert.deepEqual(owaspOf(f), ['A01:2025'], 'it is an access-control failure, not injection');

  const detail = `${f.detail} ${ruleFor(f).background}`;
  assert.match(detail, /not injectable|parameteriz/i,
    'the explanation must say why injection is the wrong answer');
});

test('exam: an unreachable guard is NOT reported as a missing guard', () => {
  // requireAdmin exists in the file. The defect is the ordering, not the absence.
  const f = findings.find((x) => x.rule_id === 'authz-before-guard');
  assert.ok(f, 'the ordering finding is missing entirely');
  assert.match(f.detail, /registered on line \d+, above \w+ on line \d+/,
    'the explanation must name both lines; "add a guard" would be the wrong fix');
  assert.match(f.detail, /never runs/);
  assert.ok(!/missing|absent|no guard/i.test(f.detail),
    'the guard is present; saying it is missing is the wrong diagnosis');
});

test('exam: SSRF is filed under A01, as the 2025 edition has it', () => {
  const f = findings.find((x) => x.rule_id === 'ssrf');
  assert.ok(f);
  assert.deepEqual(owaspOf(f), ['A01:2025'],
    'SSRF was folded into Broken Access Control in 2025; A10:2021 is the stale answer');
});

test('exam: a fast hash on passwords is High, not a style note', () => {
  const f = findings.find((x) => x.rule_id === 'weak-password-hash');
  assert.ok(f);
  assert.ok(severityRank(f.severity) >= severityRank('High'),
    'MD5 on passwords is not merely deprecated');
  assert.match(ruleFor(f).remediation, /argon2|scrypt|bcrypt/i,
    'the fix is a KDF, not "use SHA-256"');
});

test('exam: a credential finding never carries the credential', () => {
  const f = findings.find((x) => x.rule_id === 'hardcoded-credential');
  assert.ok(f);
  assert.ok(!JSON.stringify(f).includes('AKIAIOSFODNN7EXAMPLE'));
  assert.ok(!JSON.stringify(f).includes('sup3rs3cr3t'));
});

// --- Calibration: a report where everything is critical has ranked nothing ---

test('exam: severity is distributed, not uniformly alarming', () => {
  const matrix = summarize(findings).by_severity_confidence;
  const counts = Object.fromEntries(
    Object.entries(matrix).map(([sev, row]) => [sev, row.Certain + row.Firm + row.Tentative]),
  );
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  assert.ok(total >= 8, 'the mock should produce enough findings to calibrate against');

  const high = counts.Critical + counts.High;
  assert.ok(high / total < 0.7, `${high}/${total} at High or above is alarm, not scoring`);
  assert.ok(counts.Medium + counts.Low > 0, 'nothing below High means nothing was ranked');
});

test('exam: confidence is distributed too, and nothing claims Certain', () => {
  const certain = findings.filter((f) => f.confidence === 'Certain');
  assert.equal(certain.length, 0,
    'a static pass cannot reproduce anything, so nothing may claim Certain');

  const firm = findings.filter((f) => f.confidence === 'Firm');
  const tentative = findings.filter((f) => f.confidence === 'Tentative');
  assert.ok(firm.length > 0, 'traced findings should reach Firm');
  assert.ok(tentative.length > 0, 'pattern-only findings should stay Tentative');
});

test('exam: every finding carries a remediation someone can act on', () => {
  for (const f of findings) {
    const r = ruleFor(f)?.remediation ?? '';
    assert.ok(r.length > 20, `${f.rule_id}: remediation too thin to act on`);
    assert.ok(!/^see /i.test(r.trim()), `${f.rule_id}: "see the docs" is not a remediation`);
  }
});

test('exam: every finding is traceable to a standard', () => {
  for (const f of findings) {
    const c = ruleFor(f)?.classification ?? {};
    assert.ok((c.cwe ?? []).length > 0, `${f.rule_id}: no CWE`);
    assert.ok((c.owasp ?? []).length > 0, `${f.rule_id}: no OWASP category`);
    for (const o of c.owasp) {
      assert.match(o, /:2025$/, `${f.rule_id}: ${o} is not the current edition`);
    }
  }
});

test('exam: the scan is deterministic — the same input gives the same fingerprints', () => {
  const a = mergeFindings(scanRepo(MOCK).findings).map((f) => f.fingerprint).sort();
  const b = mergeFindings(scanRepo(MOCK).findings).map((f) => f.fingerprint).sort();
  assert.deepEqual(a, b, 'a non-deterministic scan cannot have a baseline');
});

// --- M14: the AI/LLM cases that separate a cause from a shape

test('exam: untrusted text in a user-role message is NOT prompt injection', () => {
  // mock/app/assistant.js#classifyTicket does the right thing: the ticket stays in
  // a user message, the system prompt is a constant, and the completion is mapped
  // onto a fixed set of actions. An earlier version of this rule fired on every
  // model call that had request data in scope, which reported the correct handler
  // at High — the fastest way to teach someone to ignore a security tool.
  const hits = RAW.filter((f) => f.rule_id === 'prompt-injection');
  assert.ok(hits.length > 0, 'the real injection must still be found');
  assert.ok(!hits.some((f) => f.location.symbol === 'classifyTicket'),
    'the deliberately-correct handler must stay quiet');
  assert.ok(hits.some((f) => f.location.symbol === 'summarizeTicket'),
    'the defect is request data built into the instructions');
});

test('exam: executing a completion is reported as output handling, not command injection from the request', () => {
  const hit = RAW.find((f) => f.rule_id === 'llm-output-to-sink');
  assert.ok(hit, 'a completion reaching execSync is the finding');
  assert.equal(hit.location.symbol, 'runSuggestedFix');
  assert.ok(hit.rule.classification.owasp_llm.includes('LLM05:2025'),
    'improper output handling — the model is the source here, not the request');
  assert.ok(hit.rule.background.includes('untrusted'),
    'the lesson is that a completion is untrusted input');
});

test('exam: a missing token ceiling is a hardening note, not a vulnerability', () => {
  const hit = RAW.find((f) => f.rule_id === 'unbounded-model-consumption');
  assert.ok(hit, 'the uncapped call is still reported');
  assert.equal(hit.finding_class, 'hardening', 'nothing crosses a boundary; it costs money');
  assert.equal(hit.location.symbol, 'draftReply');
});

test('exam: a call that sets a ceiling is not reported as missing one', () => {
  const hits = RAW.filter((f) => f.rule_id === 'unbounded-model-consumption');
  for (const sym of ['summarizeTicket', 'runSuggestedFix', 'classifyTicket']) {
    assert.ok(!hits.some((f) => f.location.symbol === sym), `${sym} sets max_tokens`);
  }
});

test('exam: a word in a comment does not make a function an agent tool handler', () => {
  // The comment above `const tools = [...]` reads "a tool the model may call".
  // Before comments were stripped from the context window, that phrase reported
  // the function above it — which runs no tool at all — as excessive agency.
  const hits = RAW.filter((f) => f.rule_id === 'excessive-agent-authority');
  assert.equal(hits.length, 1, 'exactly one tool handler runs a shell');
  assert.equal(hits[0].location.symbol, 'handleTool');
});

test('exam: a finding inside a guard is attributed to the function, not to `if`', () => {
  for (const f of RAW) {
    assert.ok(!['if', 'for', 'while', 'switch', 'catch'].includes(f.location.symbol),
      `${f.rule_id} resolved its symbol to a keyword, which then goes into its fingerprint`);
  }
});
