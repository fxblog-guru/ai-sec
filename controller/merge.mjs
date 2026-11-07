// Findings are merged, never summed. The analogue of ai-perf merging histograms
// instead of averaging percentiles. CONTRACTS §7.
import { fingerprint } from './fingerprint.mjs';
import { issueType, findingClass } from './taxonomy.mjs';

export const SEVERITIES = ['Info', 'Low', 'Medium', 'High', 'Critical'];
export const CONFIDENCES = ['Tentative', 'Firm', 'Certain'];

/** Confidence follows the detection technique, never the severity. CONTRACTS §6. */
export const METHOD_CONFIDENCE = {
  pattern: 'Tentative',
  'version-match': 'Firm',
  config: 'Firm',
  dataflow: 'Firm',
  reproduced: 'Certain',
  'out-of-band': 'Certain',
};

/** Only these establish Certain; corroboration alone never does. */
const CERTAIN_METHODS = new Set(['reproduced', 'out-of-band']);

export const severityRank = (s) => Math.max(0, SEVERITIES.indexOf(s));
export const confidenceRank = (c) => Math.max(0, CONFIDENCES.indexOf(c));

export function maxSeverity(list) {
  return list.reduce((a, b) => (severityRank(b) > severityRank(a) ? b : a), 'Info');
}

export function confidenceFor(method) {
  return METHOD_CONFIDENCE[method] ?? 'Tentative';
}

/**
 * Merge the partial findings every adapter returned into one set.
 *
 * 1. One fingerprint, one finding.
 * 2. Severity is the highest proposed — never an average, never a tool's own enum.
 * 3. Independent corroboration promotes confidence one step, capped at Firm.
 *    Two tools are independent only when their detection_method differs.
 * 4. Every contributing tool is kept in sources[].
 * 5. Baseline false positives are suppressed per fingerprint, never per rule.
 */
export function mergeFindings(partials = [], { baseline = null } = {}) {
  const suppressions = baselineSuppressions(baseline);
  const byFp = new Map();

  for (const p of partials) {
    const fp = p.fingerprint ?? fingerprint(p);
    const ident = issueType(p);
    const source = {
      tool: p.tool ?? p.source?.tool ?? 'unknown',
      rule: p.source_rule ?? p.rule_id ?? null,
      // `reported_severity` is the tool's own enum, kept verbatim for traceability
      // (semgrep says WARNING, trivy says MEDIUM). `severity` is what the adapter
      // mapped it onto, and is the only one of the two that is comparable.
      reported_severity: p.reported_severity ?? null,
      severity: p.severity ?? 'Info',
      detection_method: p.detection_method ?? 'pattern',
      classification: p.rule?.classification ?? p.classification ?? null,
      location: p.location ?? null,
      // A scanner that already knows the other places this defect shows.
      occurrences: p.occurrences ?? null,
    };

    const existing = byFp.get(fp);
    if (!existing) {
      byFp.set(fp, {
        fingerprint: fp,
        // The cross-tool name of the defect. `rule_id` stays as the first
        // scanner's own name for it; every scanner's name is in sources[].
        issue_type: ident.type,
        identity_basis: ident.basis,
        finding_class: findingClass(p),
        rule_id: p.rule_id,
        location: p.location ?? null,
        insertion_point: p.insertion_point ?? null,
        severity: p.severity ?? 'Info',
        confidence: confidenceFor(source.detection_method),
        status: 'open',
        impact: p.impact ?? null,
        likelihood: p.likelihood ?? null,
        cvss: p.cvss ?? null,
        detection_method: source.detection_method,
        detail: p.detail ?? '',
        evidence: p.evidence ?? '',
        modules: [...new Set(p.modules ?? [])],
        sources: [source],
      });
      continue;
    }

    // One tool, one location, two of its own rule names. The tool is saying
    // these are two defects and the family says they are one; the family wins
    // the merge, but the disagreement is not allowed to disappear. An adapter
    // that means them to stay apart gives them a `subtype` (fingerprint.mjs);
    // this is what happens when none did.
    if (existing.rule_id && p.rule_id && existing.rule_id !== p.rule_id
        && existing.sources.some((s) => s.tool === source.tool && s.rule !== source.rule)) {
      existing.collapsed = [...new Set([...(existing.collapsed ?? []), existing.rule_id, p.rule_id])].sort();
    }

    existing.severity = maxSeverity([existing.severity, p.severity ?? 'Info']);
    // If any scanner says this is a real boundary failure, it is not a hardening note.
    if (findingClass(p) === 'vulnerability') existing.finding_class = 'vulnerability';
    existing.sources.push(source);
    existing.modules = [...new Set([...existing.modules, ...(p.modules ?? [])])];
    if (!existing.detail && p.detail) existing.detail = p.detail;
    if (!existing.evidence && p.evidence) existing.evidence = p.evidence;
    if (!existing.cvss && p.cvss) existing.cvss = p.cvss;
    if (!existing.impact && p.impact) existing.impact = p.impact;
    if (!existing.likelihood && p.likelihood) existing.likelihood = p.likelihood;
  }

  const findings = [];
  for (const f of byFp.values()) {
    f.confidence = resolveConfidence(f.sources);
    f.detection_method = strongestMethod(f.sources);
    f.tools = [...new Set(f.sources.map((s) => s.tool))].sort();

    // Where this defect actually is, when it is in more than one place.
    //
    // A fingerprint prefers `file#symbol` over `file:line` so that it survives an
    // edit above it. The cost is that two call sites inside one function are one
    // fingerprint: scanning a real AI application, two `streamText` calls in the
    // same handler object became a single finding, and the second one left no
    // trace at all. Keeping the lines is the lossless answer — the identity stays
    // stable, and nobody fixes one call and closes the finding.
    // A scanner may already know where else its finding shows — the cross-file
    // check reports one defect at the helper that causes it and every password
    // call site that reaches it. Rebuilding this list from the sources alone
    // threw that away, and the finding came back claiming one location.
    const declared = f.sources.flatMap((s) => s.occurrences ?? []);
    const where = [...new Set([
      ...declared,
      ...f.sources
        .map((s) => (s.location?.file
          ? `${s.location.file}${Number.isInteger(s.location.line) ? `:${s.location.line}` : ''}`
          : null))
        .filter(Boolean),
    ])].sort();
    if (where.length > 1) f.occurrences = where;

    // Taking the highest and saying nothing hides a real disagreement: on
    // app/routes.js:14 one scanner said Medium and another High for the same
    // open redirect. The resolution stays conservative; the disagreement is
    // now something a reader can see and a reviewer can settle.
    // Two scanners differing is a disagreement worth reading. One scanner
    // reporting several CVEs for the same package, each with its own severity, is
    // not: `trivy Critical, trivy High, trivy Medium` tells a reader nothing and
    // makes the real disagreements harder to see.
    const byTool = new Map();
    for (const s of f.sources) {
      if (!byTool.has(s.tool)) byTool.set(s.tool, new Set());
      byTool.get(s.tool).add(s.severity);
    }
    const toolsDiffer = new Set(
      [...byTool].map(([, sevs]) => maxSeverity([...sevs])),
    ).size > 1;

    const proposed = toolsDiffer ? [...new Set(f.sources.map((s) => s.severity))] : [];
    f.severity_disagreement = proposed.length > 1
      ? [...byTool]
        .map(([tool, sevs]) => ({
          tool,
          severity: maxSeverity([...sevs]),
          reported: f.sources.find((s) => s.tool === tool)?.reported_severity ?? null,
        }))
        .sort((a, b) => severityRank(b.severity) - severityRank(a.severity))
      : null;

    const sup = suppressions.get(f.fingerprint);
    if (sup) {
      f.status = 'false_positive';
      f.suppressed_reason = sup.reason ?? 'recorded as a false positive in the baseline';
    }
    findings.push(f);
  }

  findings.sort(
    (a, b) =>
      severityRank(b.severity) - severityRank(a.severity) ||
      confidenceRank(b.confidence) - confidenceRank(a.confidence) ||
      a.fingerprint.localeCompare(b.fingerprint),
  );
  return findings;
}

function strongestMethod(sources) {
  return sources
    .map((s) => s.detection_method)
    .reduce((a, b) => (confidenceRank(confidenceFor(b)) > confidenceRank(confidenceFor(a)) ? b : a),
      'pattern');
}

export function resolveConfidence(sources = []) {
  const methods = sources.map((s) => s.detection_method ?? 'pattern');
  const distinct = new Set(methods);

  let conf = methods
    .map(confidenceFor)
    .reduce((a, b) => (confidenceRank(b) > confidenceRank(a) ? b : a), 'Tentative');

  // Certain is only reached by reproduction or an out-of-band interaction.
  if (conf === 'Certain' && !methods.some((m) => CERTAIN_METHODS.has(m))) conf = 'Firm';

  // Independent corroboration promotes one step, capped at Firm.
  if (distinct.size >= 2 && conf === 'Tentative') conf = 'Firm';

  return conf;
}

function baselineSuppressions(baseline) {
  const map = new Map();
  for (const f of baseline?.findings ?? []) {
    if (f.status === 'false_positive') map.set(f.fingerprint, f);
  }
  return map;
}

/** new / unchanged / fixed against the baseline. CONTRACTS §6 baseline_state. */
export function diffBaseline(findings, baseline) {
  if (!baseline) {
    for (const f of findings) f.baseline_state = 'new';
    return { new: findings.length, unchanged: 0, fixed: 0, absent: [] };
  }
  const prev = new Map((baseline.findings ?? []).map((f) => [f.fingerprint, f]));
  let isNew = 0;
  let unchanged = 0;

  for (const f of findings) {
    const was = prev.get(f.fingerprint);
    if (!was) {
      f.baseline_state = 'new';
      isNew += 1;
    } else {
      f.baseline_state =
        was.severity !== f.severity || was.confidence !== f.confidence ? 'updated' : 'unchanged';
      unchanged += 1;
      prev.delete(f.fingerprint);
    }
  }

  const absent = [...prev.values()].filter((f) => f.status === 'open');
  return { new: isNew, unchanged, fixed: absent.length, absent };
}

/** The Severity x Confidence matrix the report opens with. */
export function summarize(findings) {
  const matrix = {};
  for (const s of [...SEVERITIES].reverse()) {
    matrix[s] = { Certain: 0, Firm: 0, Tentative: 0 };
  }
  let suppressed = 0;
  for (const f of findings) {
    if (f.status === 'false_positive') {
      suppressed += 1;
      continue;
    }
    matrix[f.severity][f.confidence] += 1;
  }
  return { by_severity_confidence: matrix, suppressed };
}
