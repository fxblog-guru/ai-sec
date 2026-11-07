// events.ndjson — the only thing that wakes the AI. CONTRACTS §5.
import { appendFileSync } from 'node:fs';
import { redactDeep, redactText } from './redact.mjs';

export const EVENT_TYPES = [
  'scan_started',
  'scanner_finished',
  'scanner_failed',
  // Installed, selected, and could not reach this target. Distinct from
  // scanner_failed: nothing went wrong, and nothing ran.
  'scanner_skipped',
  // Ran, with one of its capabilities unusable against this target.
  'scanner_degraded',
  'gate_refused',
  'new_critical',
  'auto_stopped',
  'run_finished',
];

export const CRITICAL_TYPES = new Set(['gate_refused', 'auto_stopped', 'run_finished']);
const SEVERITIES = new Set(['info', 'warn', 'error']);

export function makeEvent(type, summary, { severity = 'info', data = {} } = {}) {
  if (!EVENT_TYPES.includes(type)) throw new Error(`unknown event type: ${type}`);
  if (!SEVERITIES.has(severity)) throw new Error(`unknown severity: ${severity}`);
  return {
    ts: new Date().toISOString(),
    type,
    severity,
    summary: redactText(summary),
    data: redactDeep(data),
  };
}

/** Append one event. Redaction happens here, not at the call site. */
export function emit(file, type, summary, opts) {
  const event = makeEvent(type, summary, opts);
  appendFileSync(file, `${JSON.stringify(event)}\n`, 'utf8');
  return event;
}

/** Should the AI be woken? Non-info events, and critical ones regardless of budget. */
export function shouldWake(event, { budgetLeft = Infinity } = {}) {
  if (CRITICAL_TYPES.has(event.type)) return true;
  return event.severity !== 'info' && budgetLeft > 0;
}
