#!/usr/bin/env node
// Mutation runner — pillar P4's failing check.
//
// A gate you cannot break is a gate you cannot trust. For each mutation below we
// disable one safety behaviour, run the whole suite, and require it to FAIL.
// A mutation that leaves the suite green means that behaviour has no test, and
// this runner exits non-zero.
//
//   npm run mutate
import { readFileSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { join, resolve } from 'node:path';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const file = (p) => join(ROOT, p);

/** Disable a behaviour by making its function return a constant. */
const stub = (signature, body) => ({ find: signature, replace: `${signature}\n  ${body}` });

const MUTATIONS = [
  {
    id: 'G1-production',
    why: 'production is refused',
    path: 'controller/rules.mjs',
    ...stub('export function gateProduction(scope = {}, spec = {}) {', "return { ok: true, gate: 'G1-production' };"),
  },
  {
    id: 'G2-host-allowlist',
    why: 'a host outside the allowlist is refused',
    path: 'controller/rules.mjs',
    ...stub('export function gateHostAllowlist(scope = {}, spec = {}) {', "return { ok: true, gate: 'G2-host-allowlist' };"),
  },
  {
    id: 'G3-tier-ceiling',
    why: 'a tier above the ceiling is refused',
    path: 'controller/rules.mjs',
    ...stub('export function gateTierCeiling(scope = {}, spec = {}, now = new Date()) {', "return { ok: true, gate: 'G3-tier-ceiling' };"),
  },
  {
    id: 'G4-spec-override',
    why: 'a spec cannot widen its own permissions',
    path: 'controller/rules.mjs',
    ...stub('export function gateSpecOverride(rawSpec = {}) {', "return { ok: true, gate: 'G4-spec-override' };"),
  },
  {
    id: 'G5-redaction-gate',
    why: 'a missing redactor blocks the run',
    path: 'controller/rules.mjs',
    ...stub('export function gateRedaction(redactor) {', "return { ok: true, gate: 'G5-redaction' };"),
  },
  {
    id: 'redaction',
    why: 'secrets never reach disk',
    path: 'controller/redact.mjs',
    ...stub('export function redactText(text) {', 'return text;'),
  },
  {
    id: 'silence-is-not-clean',
    why: 'a scanner that examined nothing is not a clean result',
    path: 'lib/coverage.mjs',
    ...stub('export function scannerProducedNothing(parsed) {', 'return false;'),
  },
  {
    id: 'quiet-pass',
    why: 'a failed or silent scanner never yields done',
    path: 'lib/coverage.mjs',
    ...stub('export function runStateFromScanners(results = []) {', "return 'done';"),
  },
  {
    id: 'confidence-inflation',
    why: 'Certain is reached only by reproduction or out-of-band',
    path: 'controller/merge.mjs',
    ...stub('export function resolveConfidence(sources = []) {', "return 'Certain';"),
  },
  {
    id: 'severity-suppression',
    why: 'severity is the highest proposed',
    path: 'controller/merge.mjs',
    ...stub('export function maxSeverity(list) {', "return 'Info';"),
  },
  {
    id: 'fingerprint-instability',
    why: 'a fingerprint survives a line shift',
    path: 'controller/fingerprint.mjs',
    ...stub('export function normalizedLocation(location = {}) {', "return `${normalizePath(location.file)}:${location.line ?? ''}`;"),
  },
  {
    id: 'state-rewrite',
    why: 'a terminal state is written exactly once',
    path: 'controller/state.mjs',
    ...stub('export function canMove(from, to) {', 'return true;'),
  },
  {
    id: 'verdict-optimism',
    why: 'a run that could not look never passes',
    path: 'lib/verdict.mjs',
    ...stub('export function verdict(result, { baseline = null, bootstrap = false, bar = BAR } = {}) {',
      "return { outcome: 'PASS', summary: 'ok', exit_code: 0, bar, run_state: result.run_state, standards: result.standards, coverage_gaps: 0, suppressed: [], notes: [], findings: [] };"),
  },
  {
    id: 'bar-widening',
    why: 'the bar is severity AND confidence, not either',
    path: 'lib/verdict.mjs',
    ...stub('export const atOrAbove = (f, bar = BAR) =>', 'true ? true :'),
  },
  {
    id: 'baseline-from-bad-run',
    why: 'only a done run may become a baseline',
    path: 'lib/baseline.mjs',
    ...stub('export function promote(root, slug, result, { force = false } = {}) {', 'force = true;'),
  },
  {
    id: 'lost-human-verdict',
    why: 'a human false-positive verdict survives the next promotion',
    path: 'lib/baseline.mjs',
    find: '      .filter((f) => f.status === \'false_positive\' || f.status === \'accepted_risk\')',
    replace: '      .filter(() => false)',
  },
  {
    id: 'lesson-leak',
    why: 'a lesson carrying a credential is refused',
    path: 'lib/baseline.mjs',
    find: '    if (containsSecret(l)) return { ok: false, reason: \'refusing to write a lesson that carries a credential\' };',
    replace: '    if (false) return { ok: false, reason: \'unreachable\' };',
  },
  {
    id: 'secret-evidence',
    why: 'a secret finding never carries the secret itself',
    path: 'adapters/scanners/builtin/engine.mjs',
    find: '          evidence: rule.secret ? `${rel}:${i + 1}` : lines[i].trim().slice(0, 200),',
    replace: '          evidence: lines[i].trim().slice(0, 200),',
  },
  {
    id: 'unverified-dataflow',
    why: 'a rule claims dataflow only when a taint source is in scope',
    path: 'adapters/scanners/builtin/engine.mjs',
    find: '        const tainted = rule.taint ? SOURCE_RE.test(ctx) : false;',
    replace: '        const tainted = rule.taint ? true : false;',
  },
  {
    id: 'tenant-guesswork',
    why: 'the tenant check needs evidence the codebase is multi-tenant',
    path: 'adapters/scanners/builtin/structural.mjs',
    find: '  const multiTenant = SCOPED.test(text) || TENANT_TERM.test(text);',
    replace: '  const multiTenant = true;',
  },
  {
    id: 'missing-scanner-hidden',
    why: 'a scanner that is not installed is recorded, not silently dropped',
    path: 'lib/coverage.mjs',
    find: '  for (const u of unavailable) {',
    replace: '  for (const u of []) {',
  },
  {
    id: 'fake-leaks-into-real-runs',
    why: 'the fake scanner is never selected implicitly',
    path: 'adapters/index.mjs',
    find: "export const EXPLICIT_ONLY = new Set(['fake']);",
    replace: 'export const EXPLICIT_ONLY = new Set([]);',
  },
  {
    id: 'module-optimism',
    why: 'a module with no inputs in the target is not claimed as applicable',
    path: 'lib/discover.mjs',
    ...stub('export function applicableModules(surface) {', 'return ALL_MODULES;'),
  },
  {
    id: 'loose-framework-match',
    why: 'a quoted string in source code is not a dependency',
    path: 'lib/discover.mjs',
    find: '  return isManifest ? m.manifest.test(text) || m.source.test(text) : m.source.test(text);',
    replace: '  return m.manifest.test(text) || m.source.test(text) || m.quoted.test(text);',
  },
  {
    id: 'help-without-reason',
    why: 'every next step carries a reason, not just a command',
    path: 'lib/help.mjs',
    ...stub('export function next(s) {', "return { step: 'scan', command: 'sec scan', why: '' };"),
  },
  // --- the exam must bite: these break a classification, not a mechanism
  {
    id: 'stale-owasp-edition',
    why: 'findings cite the 2025 edition, not 2021',
    path: 'adapters/scanners/builtin/structural.mjs',
    find: "owasp: ['A01:2025'], wstg: ['WSTG-v42-ATHZ-02']",
    replace: "owasp: ['A10:2021'], wstg: ['WSTG-v42-ATHZ-02']",
  },
  {
    id: 'tenant-misdiagnosed-as-injection',
    why: 'a cross-tenant read is not reported as SQL injection',
    path: 'adapters/scanners/builtin/structural.mjs',
    find: "classification: { cwe: ['CWE-639'], owasp: ['A01:2025'], wstg: ['WSTG-v42-ATHZ-04'], asvs: ['v5.0.0-8.2.1'], api: ['API1:2023'] },",
    replace: "classification: { cwe: ['CWE-89'], owasp: ['A05:2025'], wstg: ['WSTG-v42-INPV-05'], asvs: ['v5.0.0-1.2.5'], api: [] },",
  },
  {
    id: 'alarm-scoring',
    why: 'severity is ranked, not uniformly critical',
    path: 'controller/merge.mjs',
    ...stub('export function maxSeverity(list) {', "return 'Critical';"),
  },
  {
    id: 'sarif-drops-coverage',
    why: 'the coverage ledger survives an export',
    path: 'lib/sarif.mjs',
    find: '        not_evaluable: result.not_evaluable ?? [],',
    replace: '        not_evaluable: [],',
  },
  {
    id: 'sarif-exports-suppressed',
    why: 'a dismissed finding is not exported as a live alert',
    path: 'lib/sarif.mjs',
    find: "    .filter((f) => f.status !== 'false_positive')",
    replace: '    .filter(() => true)',
  },
  {
    id: 'imported-findings-trusted',
    why: 'an imported finding starts at Tentative',
    path: 'lib/sarif.mjs',
    find: "        detection_method: 'pattern',\n        reported_severity: res.level ?? null,",
    replace: "        detection_method: 'reproduced',\n        reported_severity: res.level ?? null,",
  },
  // --- dynamic: the target adapter is the last code before traffic leaves
  {
    id: 'target-skips-allowlist',
    why: 'the url target re-checks the allowlist itself',
    path: 'adapters/targets/url.mjs',
    find: '    if (!allow.includes(url.hostname)) {',
    replace: '    if (false) {',
  },
  {
    id: 'target-allows-production',
    why: 'an allowlisted production host is still production',
    path: 'adapters/targets/url.mjs',
    find: '    if (hostIsProduction(url.hostname)) {',
    replace: '    if (false) {',
  },
  {
    id: 'unreachable-reads-as-clean',
    why: 'an unreachable target is an error, not an empty clean scan',
    path: 'adapters/targets/url.mjs',
    find: '    if (!reachable.ok) {',
    replace: '    if (false) {',
  },
  {
    id: 'probe-escapes-origin',
    why: 'a probe never leaves the target origin',
    path: 'adapters/scanners/probe/engine.mjs',
    find: '    if (url.origin !== base.origin) {',
    replace: '    if (false) {',
  },
  {
    id: 'tier-ignored-by-probe',
    why: 'T1 does not probe parameters; that is T2',
    path: 'adapters/scanners/probe/engine.mjs',
    find: "  if (tier !== 'T1' && counters.out_of_scope_requests === 0) {",
    replace: '  if (counters.out_of_scope_requests === 0) {',
  },
  {
    id: 'hsts-over-http',
    why: 'HSTS is only expected over https',
    path: 'adapters/scanners/probe/checks.mjs',
    find: '    if (c.httpsOnly && !https) continue;',
    replace: '    if (false) continue;',
  },
  // --- M6: every one of these was a real defect, found by scanning real repos
  {
    id: 'absolute-paths',
    why: 'a finding location is repo-relative, so the fingerprint is portable',
    path: 'controller/locate.mjs',
    ...stub('export function toRepoRelative(file, root) {', 'return String(file ?? "");'),
  },
  {
    id: 'placement-ignored',
    why: 'a finding in test or vendored code is downgraded',
    path: 'controller/locate.mjs',
    ...stub('export function placeFinding(partial, root) {', "return { ...partial, placement: 'production' };"),
  },
  {
    id: 'artifact-feedback-loop',
    why: "our own run artifacts are not findings about the target",
    path: 'controller/locate.mjs',
    find: '  if (isArtifact(file)) {',
    replace: '  if (false) {',
  },
  {
    id: 'go-tests-at-full-severity',
    why: 'test conventions from every language are recognised',
    path: 'controller/locate.mjs',
    find: "  '_test\\\\.(?:go|py|rb|exs?)$',          // foo_test.go",
    replace: "  'zzzznevermatches$',",
  },
  {
    id: 'scanner-dir-mismatch',
    why: 'scanCommand and parse are given the same directory',
    path: 'lib/scan.mjs',
    find: '      runDir: scannerDir, target: prepared, options, depth: spec.depth, accuracy: spec.accuracy, tier: spec.tier,',
    replace: '      runDir, target: prepared, options, depth: spec.depth, accuracy: spec.accuracy, tier: spec.tier,',
  },
  {
    id: 'fingerprint-prefix-rejected',
    why: 'judge accepts the short fingerprint the report prints',
    path: 'lib/baseline.mjs',
    find: '  const hits = baseline.findings.filter((f) => f.fingerprint.toLowerCase().startsWith(fp));',
    replace: '  const hits = baseline.findings.filter((f) => f.fingerprint.toLowerCase() === fp);',
  },
  {
    id: 'ambiguous-prefix-guessed',
    why: 'an ambiguous fingerprint prefix is refused rather than guessed',
    path: 'lib/baseline.mjs',
    find: '  if (hits.length > 1) {',
    replace: '  if (false) {',
  },
  {
    id: 'prose-is-a-framework',
    why: 'a word in prose is not a framework',
    path: 'lib/discover.mjs',
    find: "  `^\\\\s*(?:from|import|require)\\\\s+['\"]?${name}\\\\b|^\\\\s*gem\\\\s+['\"]${name}['\"]|[\"']${name}[\"']\\\\s*:`,",
    replace: "  `\\\\b${name}\\\\b`,",
  },
  {
    id: 'scope-bom-crash',
    why: 'a byte-order mark in scope.json does not crash the tool',
    path: 'lib/scan.mjs',
    find: '  const text = raw.charCodeAt(0) === BOM ? raw.slice(1) : raw;',
    replace: '  const text = raw;',
  },

  // Four defects found by scanning repositories the tool had never seen.
  {
    id: 'near-window-ignores-functions',
    why: 'a word in a neighbouring function does not satisfy `near`',
    path: 'adapters/scanners/builtin/engine.mjs',
    // Skip the declaration search entirely and every file gets the flat window back.
    find: "  if (!js) return lines.slice(start, end).join('\\n');",
    replace: "  return lines.slice(start, end).join('\\n');",
  },
  {
    id: 'enclosing-body-widens',
    why: 'a declaration boundary narrows the taint window, never widens it',
    path: 'adapters/scanners/builtin/engine.mjs',
    find: '  let start = Math.max(0, index - span);\n  let end = Math.min(lines.length, index + span);',
    replace: '  let start = 0;\n  let end = lines.length;',
  },
  {
    id: 'caption-is-a-credential',
    why: 'a credential value with spaces in it is a label, not a secret',
    path: 'adapters/scanners/builtin/rules.mjs',
    find: "access[_-]?key|token)\\s*[:=]\\s*['\"][^'\"\\n\\s]{8,}['\"]/i,",
    replace: "access[_-]?key|token)\\s*[:=]\\s*['\"][^'\"\\n]{8,}['\"]/i,",
  },
  {
    id: 'unreadable-language-silent',
    why: 'a language the ruleset cannot read reaches the coverage ledger',
    path: 'adapters/scanners/builtin/engine.mjs',
    ...stub('export function unreachedLanguages(reach, total = RULES.length) {', 'return [];'),
  },

  // M7 — cross-tool identity. Without these the merge is a claim, not a mechanism.
  {
    id: 'identity-is-rule-id',
    why: 'two scanners describing one defect merge into one finding',
    path: 'controller/taxonomy.mjs',
    ...stub('export function issueType(finding = {}) {', "return { type: finding.rule_id ?? '', basis: 'rule_id', cwe: null };"),
  },
  {
    id: 'cwe-family-ignored',
    why: 'CWE-916 and CWE-327 are one defect, not two',
    path: 'controller/taxonomy.mjs',
    find: '  for (const c of cwes) {\n    const family = FAMILY_OF.get(c);',
    replace: '  for (const c of cwes) {\n    const family = undefined;',
  },
  {
    id: 'symbol-left-unresolved',
    why: 'a scanner that names no symbol still merges with one that does',
    path: 'controller/locate.mjs',
    ...stub('export function symbolAt(root, file, line) {', 'return null;'),
  },
  {
    id: 'severity-disagreement-hidden',
    why: 'scanners disagreeing on severity is reported, not quietly resolved',
    path: 'controller/merge.mjs',
    find: '    const proposed = toolsDiffer ? [...new Set(f.sources.map((s) => s.severity))] : [];',
    replace: '    const proposed = [];',
  },
  {
    id: 'route-argument-guard-ignored',
    why: 'a guard passed as a route argument counts as a guard',
    path: 'adapters/scanners/builtin/engine.mjs',
    find: "        for (const raw of a[1].split(',')) {",
    replace: '        for (const raw of []) {',
  },
  // M14 — verification. The judgement is the reader's; these rules are not.
  {
    id: 'verifier-may-be-the-finder',
    why: 'the one who checks a finding is never the one who found it',
    path: 'controller/verification.mjs',
    find: '  if (tools.includes(String(v.verifier).toLowerCase())) {',
    replace: '  if (false) {',
  },
  {
    id: 'unknown-reporter-passes',
    why: 'a finding that does not say who reported it cannot be verified',
    path: 'controller/verification.mjs',
    find: '  if (tools.length === 0) {',
    replace: '  if (false) {',
  },
  {
    id: 'reading-code-confirms',
    why: 'confirmed needs evidence that can establish it',
    path: 'controller/verification.mjs',
    find: "export const CONFIRMING_METHODS = ['reproduced', 'out-of-band'];",
    replace: "export const CONFIRMING_METHODS = ['reproduced', 'out-of-band', 'source-trace', 'manual-review'];",
  },
  {
    id: 'anonymous-verdict-accepted',
    why: 'an anonymous verification cannot be independent',
    path: 'controller/verification.mjs',
    find: '  if (!v.verifier || String(v.verifier).trim().length === 0) {',
    replace: '  if (false) {',
  },
  {
    id: 'blocked-lead-keeps-severity',
    why: 'needs_validation drops the severity, because nothing was demonstrated',
    path: 'controller/verification.mjs',
    find: "  if (v.verdict === 'needs_validation') {\n    return {\n      ...finding,\n      verification,\n      status: 'open',\n      severity: null,",
    replace: "  if (v.verdict === 'needs_validation') {\n    return {\n      ...finding,\n      verification,\n      status: 'open',\n      severity: finding.severity,",
  },
  {
    id: 'unverified-findings-unmentioned',
    why: 'a run nobody checked is not reported as a clean run',
    path: 'lib/verdict.mjs',
    find: '  const unchecked = unverified(allOpen);',
    replace: '  const unchecked = [];',
  },
  {
    id: 'baseline-forgets-the-reporter',
    why: 'the baseline records which tool reported a finding, or independence is unenforceable',
    path: 'lib/baseline.mjs',
    find: '        tools: f.tools ?? [],',
    replace: '        ...{},',
  },
  {
    id: 'unused-authz-never-reported',
    why: 'authorization middleware defined and applied by nothing is reported',
    path: 'adapters/scanners/builtin/structural.mjs',
    ...stub('export function authorizationMiddlewareNeverUsed({ authzDefined = new Map(), guardNamesUsed = new Set() }) {', 'return [];'),
  },
  {
    id: 'lookup-table-is-middleware',
    why: 'a name alone does not make something authorization middleware',
    path: 'adapters/scanners/builtin/engine.mjs',
    find: '        if (!looksLikeMiddleware(code.slice(d.index))) continue;',
    replace: '        if (false) continue;',
  },
  {
    id: 'commented-route-counts-as-applied',
    why: 'a guard applied only inside a comment is not applied',
    path: 'adapters/scanners/builtin/engine.mjs',
    find: '      const code = stripComments(text);',
    replace: '      const code = text;',
  },
  {
    id: 'ssrf-knows-one-client',
    why: 'ssrf is found through whichever http client the target chose',
    path: 'adapters/scanners/builtin/rules.mjs',
    find: '    match: /\\b(?:https?|axios|fetch|got|request|needle|superagent|undici|ky|node-fetch|urllib|phin|wreck)\\s*',
    replace: '    match: /\\b(?:https?|axios|fetch|got|request)\\s*',
  },
  {
    id: 'idor-never-reported',
    why: 'an identity from the URL used to read data with no caller check is reported',
    path: 'adapters/scanners/builtin/structural.mjs',
    ...stub('export function objectReferenceWithoutOwnershipCheck(rel, lines, text) {', 'return [];'),
  },
  {
    id: 'idor-ignores-the-caller',
    why: 'taking the identity from the session instead is not reported',
    path: 'adapters/scanners/builtin/structural.mjs',
    find: '    if (CALLER_IDENTITY.test(stripJsComments(body))) continue;',
    replace: '      if (false) continue;',
  },
  {
    id: 'commented-fix-counts-as-a-fix',
    why: 'a fix in a comment is not a fix',
    path: 'adapters/scanners/builtin/structural.mjs',
    find: '    if (CALLER_IDENTITY.test(stripJsComments(body))) continue;',
    replace: '    if (CALLER_IDENTITY.test(body)) continue;',
  },
  {
    id: 'any-request-value-is-an-identity',
    why: 'a threshold or a page number from the request is not an IDOR',
    path: 'adapters/scanners/builtin/structural.mjs',
    find: '      const identity = names.find((n) => IDENTITY_NAME.test(n));',
    replace: '      const identity = names[0];',
  },
  {
    id: 'autoescape-off-ignored',
    why: 'template auto-escaping turned off is the cause of a stored XSS',
    path: 'adapters/scanners/builtin/rules.mjs',
    find: "    match: /\\bautoescap(?:e|ing)\\s*[:=]\\s*(?:false|False|0)\\b|\\{%\\s*autoescape\\s+off\\s*%\\}/,",
    replace: '    match: /__never_matches__/,',
  },
  {
    id: 'redos-nested-quantifier-ignored',
    why: 'a quantified group that is itself quantified is reported',
    path: 'adapters/scanners/builtin/rules.mjs',
    find: "    match: /\\/[^/\\n]*\\([^)\\n]*[+*][^)\\n]*\\)\\s*[+*][^/\\n]*\\//,",
    replace: '    match: /__never_matches__/,',
  },
  {
    id: 'cleartext-field-never-reported',
    why: 'a national id written straight to storage is reported',
    path: 'adapters/scanners/builtin/structural.mjs',
    ...stub('export function sensitiveFieldStoredInCleartext(rel, lines, text) {', 'return [];'),
  },
  {
    id: 'cleartext-ignores-encryption',
    why: 'a field that is encrypted first is not reported',
    path: 'adapters/scanners/builtin/structural.mjs',
    find: '    if (protectedHere) continue;',
    replace: '    if (false) continue;',
  },
  {
    id: 'commented-encryption-counts',
    why: 'an encrypted version sitting in a comment does not count',
    path: 'adapters/scanners/builtin/structural.mjs',
    find: '    const body = stripJsComments(enclosingBody(lines, i));\n    if (!PERSISTENCE.test(body)) continue;',
    replace: '    const body = enclosingBody(lines, i);\n    if (!PERSISTENCE.test(body)) continue;',
  },
  {
    id: 'any-field-is-sensitive',
    why: 'a field nobody could call sensitive is left alone',
    path: 'adapters/scanners/builtin/structural.mjs',
    find: '    if (!SENSITIVE_FIELD.test(field)) continue;',
    replace: '    if (false) continue;',
  },
  {
    id: 'handler-symbol-unresolved',
    why: 'this.handler = () => is named, because the symbol is in the fingerprint',
    path: 'adapters/scanners/builtin/structural.mjs',
    find: "  'this\\\\s*\\\\.\\\\s*([A-Za-z_$][\\\\w$]*)\\\\s*=\\\\s*(?:async\\\\s*)?(?:function|\\\\()',   // this.f = () =>",
    replace: "  'this_never_matches_([A-Za-z_$][\\\\w$]*)',",
  },
  {
    id: 'tool-enum-compared-as-severity',
    why: "a tool's own enum is kept but never ranked against Critical..Info",
    path: 'controller/merge.mjs',
    find: '      reported_severity: p.reported_severity ?? null,\n      severity: p.severity ?? \'Info\',',
    replace: '      reported_severity: p.reported_severity ?? null,\n      severity: p.reported_severity ?? p.severity ?? \'Info\',',
  },

  // M8 — hardening is not a vulnerability, and M14 — AI/LLM.
  {
    id: 'hardening-fails-the-build',
    why: 'a missing second layer, while the first holds, cannot fail a build',
    path: 'controller/taxonomy.mjs',
    ...stub('export function findingClass(finding = {}) {', "return 'vulnerability';"),
  },
  {
    id: 'hardening-swallows-real-findings',
    why: 'the class is declared by the rule, so the gate cannot be dodged',
    path: 'controller/taxonomy.mjs',
    ...stub('export function findingClass(finding = {}) {', "return 'hardening';"),
  },
  {
    id: 'comments-are-code',
    why: 'a word in a comment is not a fact about the code around it',
    path: 'adapters/scanners/builtin/engine.mjs',
    ...stub('export function stripComments(text) {', 'return text;'),
  },
  {
    id: 'keyword-is-a-symbol',
    why: '`if (...) {` is not a declaration, and must not reach a fingerprint',
    path: 'adapters/scanners/builtin/engine.mjs',
    find: '    /^\\s*(?:async\\s+)?(?!(?:if|for|while|switch|catch|return|typeof|await|do)\\b)([A-Za-z_$][\\w$]*)\\s*\\([^)]*\\)\\s*\\{/,',
    replace: '    /^\\s*(?:async\\s+)?([A-Za-z_$][\\w$]*)\\s*\\([^)]*\\)\\s*\\{/,',
  },
  {
    id: 'not-near-ignored',
    why: 'a model call that sets a ceiling is not reported as missing one',
    path: 'adapters/scanners/builtin/engine.mjs',
    find: '        if (rule.not_near && rule.not_near.test(ctx)) continue;',
    replace: '        if (false) continue;',
  },
  {
    id: 'any-model-call-is-injection',
    why: 'untrusted text in a user-role message is not prompt injection',
    path: 'adapters/scanners/builtin/rules.mjs',
    find: "    match: /(?:\\bsystem|\\binstructions?|\\bsystemPrompt|\\bsystem_prompt)\\s*[:=]\\s*(?:`[^`]*\\$\\{|['\"][^'\"]*['\"]\\s*\\+)/i,",
    replace: "    match: /\\.(?:messages|chat\\.completions|completions|responses)\\s*\\.\\s*create\\s*\\(/,",
  },
  {
    id: 'unmatchable-findings-silent',
    why: 'a finding with no cross-tool identity is counted, not silently duplicated',
    path: 'lib/coverage.mjs',
    find: "  const unmatched = findings.filter((f) => f.identity_basis === 'rule_id');",
    replace: '  const unmatched = [];',
  },
  {
    id: 'trivy-misconfig-unmapped',
    why: 'a trivy misconfiguration carries a CWE, or it can never merge',
    path: 'adapters/scanners/trivy/adapter.mjs',
    find: '    cwe: MISCONF_CWE[m.ID] ?? [],',
    replace: '    cwe: [],',
  },

  // M9 — the scorecard. A measurement that flatters the tool is worse than none.
  {
    id: 'own-fixture-counts-as-proof',
    why: 'full marks on a benchmark we wrote is self-measured, never measured',
    path: 'lib/scorecard.mjs',
    find: "  return benchmarkTrust === 'external' ? 'measured' : 'self-measured';",
    replace: "  return 'measured';",
  },
  {
    id: 'unchecked-module-grades-well',
    why: 'a module with nothing planted against it is unmeasured, not a pass',
    path: 'lib/scorecard.mjs',
    find: "  if (planted === 0) return blind ? 'blind' : 'unmeasured';",
    replace: "  if (planted === 0) return 'measured';",
  },
  {
    id: 'missed-defect-not-named',
    why: 'a defect the scan missed is named, not merely counted',
    path: 'lib/scorecard.mjs',
    find: '      (findings.some((f) => matches(f, d, cweOf)) ? found : missed).push(d.id);',
    replace: '      found.push(d.id);',
  },
  {
    id: 'extra-findings-counted-as-correct',
    why: 'a finding the benchmark never planted is flagged for judgement',
    path: 'lib/scorecard.mjs',
    find: '    const unaccounted = reported.filter(',
    replace: '    const unaccounted = [].filter(',
  },

  // M10 — what an external corpus exposed.
  {
    id: 'no-guard-never-reported',
    why: 'routes with no guard anywhere is a finding, not a note on another command',
    path: 'adapters/scanners/builtin/structural.mjs',
    ...stub('export function routesWithoutAnyGuard({ routeFiles = [], guardsSeen = 0, routesSeen = 0 }) {', 'return [];'),
  },
  {
    id: 'no-guard-fires-with-a-guard',
    why: 'one guard anywhere is enough to silence the no-guard finding',
    path: 'adapters/scanners/builtin/structural.mjs',
    find: '  if (routesSeen === 0 || guardsSeen > 0) return [];',
    replace: '  if (routesSeen === 0) return [];',
  },
  {
    id: 'tool-disagrees-with-itself',
    why: 'one scanner reporting several CVEs is not a disagreement',
    path: 'controller/merge.mjs',
    find: '    const proposed = toolsDiffer ? [...new Set(f.sources.map((s) => s.severity))] : [];',
    replace: '    const proposed = [...new Set(f.sources.map((s) => s.severity))];',
  },

  // M15 — the dynamic benchmark, and what it broke on the way in.
  {
    id: 'subtype-dropped-from-identity',
    why: 'two defects of one CWE family at one location stay two findings',
    path: 'controller/fingerprint.mjs',
    ...stub('export function normalizedSubtype(subtype) {', "return '';"),
  },
  {
    id: 'same-tool-collapse-is-silent',
    why: 'a merge that absorbed another rule from the same tool says so',
    path: 'controller/merge.mjs',
    find: "      existing.collapsed = [...new Set([...(existing.collapsed ?? []), existing.rule_id, p.rule_id])].sort();",
    replace: '      existing.collapsed = existing.collapsed ?? undefined;',
  },
  {
    id: 'collapse-not-in-ledger',
    why: 'the findings a merge folded away reach the coverage ledger',
    path: 'lib/coverage.mjs',
    find: '  const collapsed = findings.filter((f) => (f.collapsed ?? []).length > 0);',
    replace: '  const collapsed = [];',
  },
  {
    id: 'skipped-scanner-unrecorded',
    why: 'a scanner that could not reach the target is in the ledger',
    path: 'lib/coverage.mjs',
    find: '  for (const s of skipped) {',
    replace: '  for (const s of []) {',
  },
  {
    id: 'skipped-scanner-still-covers',
    why: 'a scanner that never ran covers no modules',
    path: 'lib/scan.mjs',
    find: '  const ran = selected.filter((s) => !skipped.some((k) => k.name === s.name));',
    replace: '  const ran = selected;',
  },
  {
    id: 'preflight-ignored',
    why: 'an adapter that refuses a target is not run anyway',
    path: 'lib/scan.mjs',
    find: "    if (typeof scanner.preflight === 'function') {",
    replace: '    if (false) {',
  },
  {
    id: 'nuclei-container-reaches-loopback',
    why: 'nuclei in a container cannot reach this machine, and says so',
    path: 'adapters/scanners/nuclei/adapter.mjs',
    ...stub('  async preflight({ target }) {', 'return { ok: true };'),
  },
  {
    id: 'cross-account-without-a-control',
    why: 'a public object is not a cross-account failure',
    path: 'adapters/scanners/probe/engine.mjs',
    find: '    const anon = await get(url, timeoutMs, counters, \'follow\', { body: true });',
    replace: '    const anon = { ok: false };',
  },
  {
    id: 'cross-account-ignores-the-body',
    why: 'identical bytes are the evidence; a 200 on its own is not',
    path: 'adapters/scanners/probe/engine.mjs',
    find: '    if (asOther.ok && asOther.status === 200 && digestOf(asOther.body) === owned.digest) {',
    replace: '    if (asOther.ok && asOther.status === 200) {',
  },
  {
    id: 'one-session-two-names',
    why: 'the same cookie twice is not two accounts',
    path: 'adapters/scanners/probe/engine.mjs',
    find: '  if (owner.cookie === other.cookie) return null; // one session wearing two names',
    replace: '  // mutated',
  },
  {
    id: 'evidence-quotes-the-data',
    why: "another account's data never reaches the report",
    path: 'adapters/scanners/probe/engine.mjs',
    find: "const digestOf = (body) => createHash('sha256').update(body ?? '').digest('hex').slice(0, 12);",
    replace: 'const digestOf = (body) => String(body ?? \'\');',
  },
  {
    id: 'unchecked-authorization-is-quiet',
    why: 'a T2 run with no accounts records that it did not check',
    path: 'adapters/scanners/probe/engine.mjs',
    find: "  if (tier !== 'T1' && usableAccounts(accounts) === null) {",
    replace: '  if (false) {',
  },
  {
    id: 'benchmark-correct-endpoint-broken',
    why: 'the deliberately correct endpoint stays correct, or the benchmark proves nothing',
    path: 'benchmarks/dynamic/app.mjs',
    find: '    if (who !== id) {',
    replace: '    if (false) {',
  },
  // M16 — what an AI application nobody here wrote exposed.
  {
    id: 'model-call-shapes-narrowed',
    why: 'a model call is recognised in more than one SDK vocabulary',
    path: 'adapters/scanners/builtin/rules.mjs',
    find: "  /\\.(?:messages|chat\\.completions|completions|responses)\\s*\\.\\s*create\\s*\\(|\\bgenerateContent\\s*\\(|\\b(?:streamText|generateText|streamObject|generateObject)\\s*\\(/;",
    replace: "  /\\.(?:messages|chat\\.completions|completions|responses)\\s*\\.\\s*create\\s*\\(|\\bgenerateContent\\s*\\(/;",
  },
  {
    id: 'unrecognised-sdk-is-silent',
    why: 'a repository calling a model through an SDK we cannot read is in the ledger',
    path: 'adapters/scanners/builtin/engine.mjs',
    ...stub('export function unreachedModelSdks({ modelSdkFiles = [], modelCallSites = 0 } = {}) {', 'return [];'),
  },
  {
    id: 'taint-sources-express-only',
    why: 'a Web Request is untrusted input too',
    path: 'adapters/scanners/builtin/rules.mjs',
    find: "  /\\b(?:req|request)\\.(?:body|query|params|headers|cookies)\\b|\\b(?:req|request)\\.(?:json|text|formData)\\s*\\(|\\bsearchParams\\s*\\.\\s*get\\s*\\(|\\bformData\\s*\\.\\s*get\\s*\\(|\\bprocess\\.argv\\b|\\bctx\\.request\\b/;",
    replace: "  /\\b(?:req|request)\\.(?:body|query|params|headers|cookies)\\b|\\bprocess\\.argv\\b|\\bctx\\.request\\b/;",
  },
  {
    id: 'second-instance-lost-in-the-merge',
    why: 'a finding that is in two places names both',
    path: 'controller/merge.mjs',
    find: '    if (where.length > 1) f.occurrences = where;',
    replace: '    if (false) f.occurrences = where;',
  },
  {
    id: 'm14-blind-spot-unstated',
    why: 'what M14 cannot settle is written down, not implied by a zero',
    path: 'lib/discover.mjs',
    find: "  M14: 'indirect prompt injection cannot be settled by pattern matching: the untrusted text usually reaches the prompt as an argument from another module, or from a document the model retrieves at run time',",
    replace: '',
  },
  {
    id: 'desktop-zap-pretends-to-be-passive',
    why: 'a desktop ZAP has no passive baseline, and a T1 request is refused rather than attacked',
    path: 'adapters/scanners/zap/adapter.mjs',
    ...stub("  async preflight({ tier = 'T1' } = {}) {", 'return { ok: true };'),
  },
  {
    id: 'zap-runner-unknown',
    why: 'the adapter runs the script the install actually has',
    path: 'adapters/scanners/zap/adapter.mjs',
    find: '  if (works(PACKAGED.T1)) {',
    replace: '  if (false) {',
  },
  {
    // One hop across a call boundary. Every blind spot this project had
    // recorded was the same sentence, and M12 graded `failing` because of it.
    id: 'helper-is-never-resolved',
    why: 'a password hashed through a helper in another file is still found',
    path: 'adapters/scanners/builtin/crossfile.mjs',
    ...stub('export function collectDefinitions(rel, lines, text) {', 'return [];'),
  },
  {
    id: 'kdf-is-not-a-defence',
    why: 'a helper that uses a key derivation function is not reported',
    path: 'adapters/scanners/builtin/crossfile.mjs',
    find: '      if (KDF.test(def.body)) continue;',
    replace: '      if (false) continue;',
  },
  {
    id: 'unresolved-helper-goes-quiet',
    why: 'a hashing call we could not follow is a coverage gap, not a pass',
    path: 'adapters/scanners/builtin/crossfile.mjs',
    find: '  if (unresolved.size > 0) {',
    replace: '  if (false) {',
  },
  {
    id: 'one-cause-reported-as-many',
    why: 'call sites sharing one helper are one finding that names them all',
    path: 'adapters/scanners/builtin/crossfile.mjs',
    find: "      if (!hits.has(key)) hits.set(key, { def, sites: new Set() });",
    replace: "      hits.set(`${key}:${sink.file}:${sink.line}`, { def, sites: new Set() });",
  },
  {
    id: 'generated-crud-exclusions-not-checked',
    why: 'a generated resource that publishes a privileged column is reported',
    path: 'adapters/scanners/builtin/crossfile.mjs',
    ...stub('export function collectAutoCrud(rel, text) {', 'return [];'),
  },
  {
    id: 'privileged-field-list-ignored',
    why: 'excluding the privileged column is what closes the finding',
    path: 'adapters/scanners/builtin/crossfile.mjs',
    find: '    const exposed = fields.filter((f) => !lower.has(f.field.toLowerCase()));',
    replace: '    const exposed = fields;',
  },
  {
    id: 'caller-fetched-and-ignored-accepted',
    why: 'looking up who is asking and not using it is reported, not cleared',
    path: 'adapters/scanners/builtin/structural.mjs',
    find: '    if (uses > 1) continue;',
    replace: '    if (uses >= 1) continue;',
  },
  {
    id: 'occurrences-are-never-scored',
    why: 'a benchmark answer reached through an occurrence counts as found',
    path: 'lib/scorecard.mjs',
    find: '  if (defect.file && !filesOf(finding).has(defect.file)) return false;',
    replace: '  if (defect.file && finding.location?.file !== defect.file) return false;',
  },
  {
    // Juice Shop: 246 findings, 188 of them in its test suite. The gates below
    // are what keeps a report about the running system about the running system.
    id: 'test-code-counts-as-the-application',
    why: 'a finding in a test file does not fail a build about production',
    path: 'controller/coderole.mjs',
    ...stub('export function codeRole(file) {', "return 'application';"),
  },
  {
    id: 'non-application-findings-go-quiet',
    why: 'findings set aside from the bar are still counted where the reader sees them',
    path: 'lib/coverage.mjs',
    find: '  const outside = Object.values(roles).reduce((a, b) => a + b, 0);',
    replace: '  const outside = 0;',
  },
  {
    id: 'fixture-keeps-a-confidence-it-has-not-earned',
    why: 'a pattern matched in a fixture cannot claim it was traced in the application',
    path: 'controller/coderole.mjs',
    find: "    confidence: 'Tentative',",
    replace: '    confidence: finding.confidence,',
  },
  {
    id: 'benchmark-answers-may-name-a-dead-rule',
    why: 'a benchmark whose rules were renamed reports a regression that is a rename',
    path: 'adapters/scanners/builtin/rules.mjs',
    find: "    id: 'tool-bound-stated-only-in-prose',",
    replace: "    id: 'tool-bound-in-prose',",
  },
  {
    id: 'tool-bound-in-prose-accepted',
    why: 'a bound stated in a sentence the model reads is not a control',
    path: 'adapters/scanners/builtin/rules.mjs',
    find: "    match: /\\.\\s*describe\\s*\\(\\s*['\"`][^'\"`]*\\b(?:maximum|minimum|at most|at least|no more than|not exceed|up to)\\b/i,",
    replace: '    match: /\\bthis-pattern-matches-nothing\\b/,',
  },
  {
    id: 'commented-guard-reads-as-a-guard',
    why: 'authorization that is commented out is reported, not read as present',
    path: 'adapters/scanners/builtin/rules.mjs',
    find: "    id: 'commented-out-authorization',",
    replace: "    id: 'commented-out-authorization-disabled',",
  },
  {
    id: 'allowlist-substring-accepted',
    why: 'an allowlist compared by substring enforces nothing',
    path: 'adapters/scanners/builtin/rules.mjs',
    find: '    near: /allow(?:ed|list)?|whitelist|permitted|trusted|safeList/i,',
    replace: '    near: /\\bthis-context-never-occurs\\b/,',
  },
  {
    id: 'nosql-rule-fires-on-sequelize',
    why: 'a rule that names the wrong cause is worse than one that stays quiet',
    path: 'adapters/scanners/builtin/rules.mjs',
    find: '    not_near: /\\bsequelize\\b|\\bwhere\\s*:/i,',
    replace: '    not_near: /\\bnever-in-any-source\\b/,',
  },
  {
    // The skills drifted ten milestones behind the controller with nothing to
    // notice. These three mutations are the doc-code link in both directions.
    id: 'skill-names-a-dead-command',
    why: 'a skill never tells a reader to run a command the CLI has lost',
    path: 'bin/sec.mjs',
    find: "if (cmd === 'verify') {",
    replace: "if (cmd === 'confirm') {",
  },
  {
    id: 'vocabulary-drifts-from-the-code',
    why: 'a word the tool prints at a reader is explained somewhere they will have read',
    path: 'controller/verification.mjs',
    find: "export const VERIFICATION_METHODS = [...CONFIRMING_METHODS, 'source-trace', 'manual-review'];",
    replace: "export const VERIFICATION_METHODS = [...CONFIRMING_METHODS, 'source-trace', 'manual-review', 'spot-check'];",
  },
  {
    id: 'gate-renamed-behind-the-readers-back',
    why: 'every refusal the controller can produce is one the reader has been told how to answer',
    path: 'controller/rules.mjs',
    find: "const gate = 'G2-host-allowlist';",
    replace: "const gate = 'G2-allowed-hosts';",
  },
  {
    id: 'benchmark-targets-anything',
    why: 'the harness may only scan the server it started',
    path: 'benchmarks/dynamic/run.mjs',
    ...stub('export function assertOwnLoopbackTarget(origin, port) {', 'return true;'),
  },

  // M18 — a scanner that ran and still could not do one of its jobs.
  {
    id: 'a-range-is-a-version',
    why: 'package.json states ranges, so it is not something trivy can resolve a version from',
    path: 'adapters/scanners/trivy/adapter.mjs',
    find: "  'package-lock.json', 'npm-shrinkwrap.json',",
    replace: "  'package.json', 'package-lock.json', 'npm-shrinkwrap.json',",
  },
  {
    id: 'missing-lockfile-goes-quiet',
    why: 'zero dependency findings with nothing to read is not a clean dependency tree',
    path: 'adapters/scanners/trivy/adapter.mjs',
    find: "    if (dependencyManifests(root, { limit: 1 }).length > 0) return { ok: true };",
    replace: "    if (true) return { ok: true };",
  },
  {
    id: 'blind-capability-costs-the-whole-scanner',
    why: 'without a lockfile trivy can still check misconfiguration and secrets',
    path: 'adapters/scanners/trivy/adapter.mjs',
    find: "      ok: true,\n      degraded: [{\n        capability: 'dependency CVEs',",
    replace: "      ok: false,\n      degraded: [{\n        capability: 'dependency CVEs',",
  },
  {
    id: 'degradation-never-reaches-the-ledger',
    why: 'the ledger is the one place a reader looks for what was not checked',
    path: 'lib/coverage.mjs',
    find: '  for (const d of degraded) {\n    notEvaluable.push({',
    replace: '  for (const d of []) {\n    notEvaluable.push({',
  },
  {
    id: 'degradation-is-dropped-from-the-run',
    why: 'a partial refusal that does not survive the run exists only in a log line',
    path: 'lib/scan.mjs',
    find: '      for (const d of pf?.degraded ?? []) {',
    replace: '      for (const d of []) {',
  },
  {
    id: 'blind-module-blamed-on-the-rules',
    why: '`failing` says the rules missed it; a blind engine was never shown it',
    path: 'lib/scorecard.mjs',
    find: "  if (blind && found < planted) return 'blind';",
    replace: "  if (false) return 'blind';",
  },
  {
    id: 'blind-grade-hides-which-capability',
    why: 'a grade that does not name the missing capability cannot be acted on',
    path: 'lib/scorecard.mjs',
    find: '      blind_spots: [].concat(blindSpots[m] ?? [], blindOn.get(m) ?? []),',
    replace: '      blind_spots: [].concat(blindSpots[m] ?? []),',
  },
  {
    id: 'any-expected-json-is-an-answer-key',
    why: 'a target that ships its own fixtures must not become the scorecard',
    path: 'lib/scorecard.mjs',
    find: '  if (!Array.isArray(expected.defects)) {',
    replace: '  if (false) {',
  },
];

function runSuite() {
  const r = spawnSync(
    process.execPath,
    ['--test', '--test-concurrency=2', 'tests/*.test.mjs'],
    { cwd: ROOT, encoding: 'utf8', shell: false },
  );
  return r.status ?? 1;
}

/**
 * Every mutation must be able to apply before any of them runs.
 *
 * An anchor goes stale the moment the line it quotes is edited, and a mutation
 * that never applies is reported at the END of a fifteen-minute run — after the
 * behaviour it was supposed to guard has been unguarded for however long. Three
 * went stale in one afternoon: one line was rewritten by a later fix, and two
 * were written with the wrong indentation and never ran at all.
 *
 * Checking first turns a quarter of an hour and a buried warning into one line.
 */
/** Where the pending restore is recorded, so a killed run can be undone. */
const INFLIGHT = file('.mutate-inflight.json');

function beginMutation(path, original) {
  writeFileSync(INFLIGHT, JSON.stringify({ path, original }), 'utf8');
}

function endMutation(path, original) {
  writeFileSync(path, original, 'utf8');
  try { rmSync(INFLIGHT, { force: true }); } catch { /* best effort */ }
}

/**
 * Undo a mutation an earlier run was killed in the middle of.
 *
 * Returns what it restored, so the caller can say so rather than silently
 * repairing the repository — the point is that someone finds out it happened.
 */
export function recoverInterrupted() {
  if (!existsSync(INFLIGHT)) return null;
  let plan;
  try {
    plan = JSON.parse(readFileSync(INFLIGHT, 'utf8'));
  } catch {
    rmSync(INFLIGHT, { force: true });
    return null;
  }
  if (!plan?.path || typeof plan.original !== 'string') {
    rmSync(INFLIGHT, { force: true });
    return null;
  }
  const dirty = readFileSync(plan.path, 'utf8') !== plan.original;
  writeFileSync(plan.path, plan.original, 'utf8');
  rmSync(INFLIGHT, { force: true });
  return { path: plan.path, restored: dirty };
}

/**
 * Check every anchor. Reads files; writes nothing.
 *
 * Recovery deliberately does NOT happen here. `npm test` calls this, and the
 * runner's own suite runs with a mutation applied — so recovering here undid
 * each mutation from inside the suite that was meant to detect it, and all
 * eighty-three survived at once. A repair that runs where it is not expected is
 * indistinguishable from the bug it repairs.
 */
function preflight() {
  const bad = [];
  for (const m of MUTATIONS) {
    let text;
    try {
      text = readFileSync(file(m.path), 'utf8');
    } catch {
      bad.push(`${m.id}: cannot read ${m.path}`);
      continue;
    }
    if (!text.includes(m.find)) bad.push(`${m.id}: anchor not present in ${m.path}`);
    if (m.find === m.replace) bad.push(`${m.id}: find and replace are identical, so it is a no-op`);
  }
  if (bad.length === 0) return 0;

  process.stdout.write(`${bad.length} mutation(s) cannot apply:\n`);
  for (const b of bad) process.stdout.write(`  - ${b}\n`);
  process.stdout.write('\nA mutation that never applies guards nothing. Fix the anchors.\n');
  return 1;
}

function main() {
  const recovered = recoverInterrupted();
  if (recovered?.restored) {
    process.stdout.write(`recovered: an earlier run was killed with ${recovered.path} mutated; restored it\n\n`);
  }
  if (preflight() !== 0) return 1;

  // A green baseline, or the run proves nothing.
  process.stdout.write('baseline: ');
  if (runSuite() !== 0) {
    process.stdout.write('FAIL\n\nThe suite must be green before mutating. Fix it first.\n');
    return 1;
  }
  process.stdout.write('green\n\n');

  const survivors = [];

  // A killed run must not leave the repository mutated.
  //
  // Signal handlers cannot do this: runSuite() is spawnSync, so node is blocked
  // for the twelve seconds a mutation is applied and no handler can run. A hard
  // kill is not catchable at all. So the pending restore is written to disk
  // BEFORE the file is touched, and recovered on the next start.
  //
  // Interrupting one run left verdict() returning a hardcoded PASS, and the next
  // full test run failed in thirteen unrelated places with no clue why. A
  // security tool that silently disables its own verdict is the worst thing in
  // this repository to leave lying around.
  for (const m of MUTATIONS) {
    const path = file(m.path);
    const original = readFileSync(path, 'utf8');

    if (!original.includes(m.find)) {
      process.stdout.write(`  [SKIP] ${m.id.padEnd(24)} anchor not found in ${m.path}\n`);
      survivors.push({ ...m, reason: 'anchor not found — the mutation never applied' });
      continue;
    }

    try {
      beginMutation(path, original);
      writeFileSync(path, original.replace(m.find, m.replace), 'utf8');
      const status = runSuite();
      if (status === 0) {
        process.stdout.write(`  [SURVIVED] ${m.id.padEnd(20)} ${m.why}\n`);
        survivors.push({ ...m, reason: 'the suite stayed green with this behaviour removed' });
      } else {
        process.stdout.write(`  [killed]   ${m.id.padEnd(20)} ${m.why}\n`);
      }
    } finally {
      endMutation(path, original);
    }
  }

  process.stdout.write(`\n${MUTATIONS.length - survivors.length}/${MUTATIONS.length} mutations killed\n`);

  if (survivors.length > 0) {
    process.stdout.write('\nUntested behaviour:\n');
    for (const s of survivors) process.stdout.write(`  - ${s.id}: ${s.why}\n    ${s.reason}\n`);
    return 1;
  }
  process.stdout.write('every gate has a test that fails when it is removed.\n');
  return 0;
}

export { MUTATIONS, preflight };

// Only when run, not when imported. Importing this file used to start a
// fifteen-minute mutation run, which made the mutation list itself the one thing
// in the project no test could look at.
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exit(main());
}
