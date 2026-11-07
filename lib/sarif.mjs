// SARIF 2.1.0 — the interchange format every major scanner speaks.
//
// sec-result/v1 was shaped as SARIF is shaped, so this is a projection rather than
// a translation: rules[] -> tool.driver.rules[], findings[] -> results[].
import { SEVERITIES } from '../controller/merge.mjs';

export const SARIF_VERSION = '2.1.0';
export const SARIF_SCHEMA = 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json';

/** SARIF's level enum is severity-agnostic; security-severity carries the number. */
const LEVEL = { Critical: 'error', High: 'error', Medium: 'warning', Low: 'note', Info: 'none' };

/** The CVSS band midpoints GitHub maps back to Critical/High/Medium/Low. */
const SECURITY_SEVERITY = { Critical: 9.5, High: 8.0, Medium: 5.5, Low: 2.0, Info: 0.0 };

/** Confidence has no SARIF field; precision is the nearest convention. */
const PRECISION = { Certain: 'very-high', Firm: 'high', Tentative: 'medium' };

export function toSarif(result, { toolName = 'ai-sec', toolVersion = null } = {}) {
  const rules = (result.rules ?? []).map((r) => ({
    id: r.rule_id,
    name: r.name ?? r.rule_id,
    shortDescription: { text: r.name ?? r.rule_id },
    fullDescription: { text: r.background ?? '' },
    help: {
      text: r.remediation ?? '',
      markdown: [
        r.background ? `**What it is**\n\n${r.background}` : null,
        r.remediation ? `**Fix**\n\n${r.remediation}` : null,
        (r.references ?? []).length ? `**References**\n\n${r.references.map((u) => `- ${u}`).join('\n')}` : null,
      ].filter(Boolean).join('\n\n'),
    },
    helpUri: (r.references ?? [])[0] ?? undefined,
    defaultConfiguration: { level: LEVEL[r.typical_severity] ?? 'warning' },
    properties: {
      tags: classificationTags(r.classification),
      'security-severity': String(SECURITY_SEVERITY[r.typical_severity] ?? 5.5),
    },
  }));

  const ruleIndex = new Map(rules.map((r, i) => [r.id, i]));

  const results = (result.findings ?? [])
    .filter((f) => f.status !== 'false_positive')
    .map((f) => ({
      ruleId: f.rule_id,
      ruleIndex: ruleIndex.get(f.rule_id) ?? undefined,
      level: LEVEL[f.severity] ?? 'warning',
      kind: 'fail',
      message: { text: f.detail || f.rule_id },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: f.location?.file ?? 'unknown' },
          ...(f.location?.line
            ? { region: { startLine: f.location.line, ...(f.evidence ? { snippet: { text: f.evidence } } : {}) } }
            : {}),
        },
        ...(f.location?.symbol ? { logicalLocations: [{ name: f.location.symbol }] } : {}),
      }],
      // GitHub reads only this key, and it is what keeps alerts from duplicating.
      partialFingerprints: { primaryLocationLineHash: f.fingerprint },
      baselineState: f.baseline_state ?? 'new',
      properties: {
        confidence: f.confidence,
        precision: PRECISION[f.confidence] ?? 'medium',
        detection_method: f.detection_method,
        modules: f.modules ?? [],
        tools: (f.sources ?? []).map((s) => s.tool),
        ...(f.insertion_point ? { insertion_point: f.insertion_point } : {}),
      },
    }));

  return {
    $schema: SARIF_SCHEMA,
    version: SARIF_VERSION,
    runs: [{
      tool: {
        driver: {
          name: toolName,
          ...(toolVersion ? { semanticVersion: toolVersion } : {}),
          informationUri: 'https://gitlab.com/agentic-fx/ai-sec',
          rules,
        },
      },
      automationDetails: { id: result.run_id },
      results,
      // Coverage has no home in SARIF, and dropping it would turn a thin run into a
      // clean one on import. Keep it where a reader can still find it.
      properties: {
        run_state: result.run_state,
        standards: result.standards,
        coverage: result.coverage ?? [],
        not_evaluable: result.not_evaluable ?? [],
        suppressed: (result.findings ?? []).filter((f) => f.status === 'false_positive').length,
      },
    }],
  };
}

function classificationTags(c = {}) {
  return [
    ...(c.cwe ?? []),
    ...(c.owasp ?? []),
    ...(c.wstg ?? []),
    ...(c.asvs ?? []).map((a) => `ASVS-${a}`),
    ...(c.api ?? []),
    ...(c.cve ?? []),
    'security',
  ];
}

const FROM_LEVEL = { error: 'High', warning: 'Medium', note: 'Low', none: 'Info' };

/**
 * Import someone else's SARIF into our model — a CI run, another scanner.
 * Everything imported starts at Tentative: we did not see how it was found.
 */
export function fromSarif(sarif, { tool = null } = {}) {
  const findings = [];
  const rules = [];
  const seen = new Set();

  for (const run of sarif.runs ?? []) {
    const driver = run.tool?.driver ?? {};
    const name = tool ?? driver.name ?? 'imported';
    const byIndex = driver.rules ?? [];

    for (const r of byIndex) {
      if (seen.has(r.id)) continue;
      seen.add(r.id);
      const tags = r.properties?.tags ?? [];
      rules.push({
        rule_id: r.id,
        name: r.shortDescription?.text ?? r.name ?? r.id,
        background: r.fullDescription?.text ?? '',
        remediation: r.help?.text ?? '',
        classification: {
          cwe: tags.filter((t) => /^CWE-\d+$/.test(t)),
          owasp: tags.filter((t) => /^A\d+:\d{4}$/.test(t)),
          wstg: tags.filter((t) => /^WSTG-/.test(t)),
          asvs: tags.filter((t) => /^ASVS-/.test(t)).map((t) => t.slice(5)),
          api: tags.filter((t) => /^API\d+:\d{4}$/.test(t)),
        },
        typical_severity: severityFromSarif(r.defaultConfiguration?.level, r.properties),
        references: r.helpUri ? [r.helpUri] : [],
      });
    }

    for (const res of run.results ?? []) {
      if (res.kind && res.kind !== 'fail') continue;
      const rule = byIndex[res.ruleIndex] ?? byIndex.find((x) => x.id === res.ruleId);
      const loc = res.locations?.[0]?.physicalLocation ?? {};
      findings.push({
        rule_id: res.ruleId ?? 'imported',
        rule: rules.find((x) => x.rule_id === res.ruleId),
        location: {
          file: loc.artifactLocation?.uri ?? 'unknown',
          symbol: res.locations?.[0]?.logicalLocations?.[0]?.name ?? null,
          line: loc.region?.startLine ?? null,
        },
        insertion_point: null,
        severity: severityFromSarif(res.level ?? rule?.defaultConfiguration?.level, rule?.properties),
        impact: null,
        likelihood: null,
        // We did not run it and cannot see the technique, so it starts Tentative.
        detection_method: 'pattern',
        reported_severity: res.level ?? null,
        source_rule: res.ruleId,
        detail: res.message?.text ?? '',
        evidence: loc.region?.snippet?.text ?? '',
        modules: res.properties?.modules ?? [],
        tool: name,
      });
    }
  }
  return { findings, rules };
}

function severityFromSarif(level, properties) {
  const score = Number(properties?.['security-severity']);
  if (Number.isFinite(score) && score > 0) {
    if (score > 9.0) return 'Critical';
    if (score >= 7.0) return 'High';
    if (score >= 4.0) return 'Medium';
    return 'Low';
  }
  return FROM_LEVEL[level] ?? 'Medium';
}

export const SARIF_SEVERITY_BANDS = SEVERITIES;
