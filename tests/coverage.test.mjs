// "Never a quiet pass": silence from a scanner is not evidence of a clean target.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  scannerProducedNothing, runStateFromScanners, resolveRunState, buildLedger, ledgerIsEmpty,
} from '../lib/coverage.mjs';

const withCoverage = (over = {}) => ({
  name: 'a', failed: false, timed_out: false,
  parsed: { findings: [], coverage: [{ kind: 'files', detail: 'scanned', count: 10 }], errors: [] },
  ...over,
});

test('a scanner with no findings and no coverage produced nothing', () => {
  assert.equal(scannerProducedNothing({ findings: [], coverage: [] }), true);
  assert.equal(scannerProducedNothing({ findings: [], coverage: [{ kind: 'files' }] }), false);
  assert.equal(scannerProducedNothing({ findings: [{}], coverage: [] }), false);
});

test('a clean scan that reported coverage is done', () => {
  assert.equal(runStateFromScanners([withCoverage()]), 'done');
});

test('a scan where nothing reported coverage is not evaluable, never done', () => {
  const silent = withCoverage({ parsed: { findings: [], coverage: [], errors: [] } });
  assert.equal(runStateFromScanners([silent]), 'not_evaluable');
  assert.equal(runStateFromScanners([]), 'not_evaluable');
});

test('one scanner failing while another covered is degraded, never done', () => {
  const failed = withCoverage({ name: 'b', failed: true, exit_code: 3, parsed: { findings: [], coverage: [], errors: [] } });
  assert.equal(runStateFromScanners([withCoverage(), failed]), 'degraded');
});

test('a timeout is degraded', () => {
  const timed = withCoverage({ name: 'b', failed: true, timed_out: true, timeout_s: 1 });
  assert.equal(runStateFromScanners([withCoverage(), timed]), 'degraded');
});

test('a forced terminal state takes precedence over the derived one', () => {
  assert.equal(resolveRunState([withCoverage()], 'aborted'), 'aborted');
  assert.equal(resolveRunState([withCoverage()], null), 'done');
});

test('the ledger names every selected module no scanner covers', () => {
  const ledger = buildLedger({
    results: [withCoverage()],
    selectedModules: ['M1', 'M7', 'M8'],
    coveredModules: ['M1'],
    tier: 'T0', maxTier: 'T0',
  });
  const checks = ledger.not_evaluable.map((n) => n.check);
  assert.ok(checks.includes('module M7'));
  assert.ok(checks.includes('module M8'));
  assert.ok(!checks.includes('module M1'));
});

test('the ledger records a timeout, a failure, and a silent scanner', () => {
  const ledger = buildLedger({
    results: [
      withCoverage({ name: 'slow', failed: true, timed_out: true, timeout_s: 5 }),
      withCoverage({ name: 'broken', failed: true, exit_code: 3, error: 'boom', parsed: { findings: [], coverage: [], errors: [] } }),
      withCoverage({ name: 'silent', parsed: { findings: [], coverage: [], errors: [] } }),
    ],
    selectedModules: [], coveredModules: [], tier: 'T0', maxTier: 'T0',
  });
  const joined = ledger.not_evaluable.map((n) => `${n.check} ${n.reason}`).join(' | ');
  assert.match(joined, /slow.*timed out/);
  assert.match(joined, /broken/);
  assert.match(joined, /silent.*examined nothing/);
});

test('a scanner that is not installed is named in the ledger, not dropped', () => {
  const ledger = buildLedger({
    results: [withCoverage()],
    selectedModules: [], coveredModules: [], tier: 'T0', maxTier: 'T0',
    unavailable: [{ name: 'semgrep', install: 'pip install semgrep' }],
  });
  const entry = ledger.not_evaluable.find((n) => n.check === 'scanner semgrep');
  assert.ok(entry, 'an uninstalled scanner must appear in the coverage ledger');
  assert.match(entry.reason, /not installed/);
  assert.match(entry.unblock, /pip install semgrep/);
});

test('an empty ledger is what lets a PASS stand unqualified', () => {
  assert.equal(ledgerIsEmpty({ not_evaluable: [] }), true);
  assert.equal(ledgerIsEmpty({ not_evaluable: [{ check: 'x' }] }), false);
});

test('a finding with no cross-tool identity is counted, not silently possibly-duplicated', () => {
  const ledger = buildLedger({
    results: [{ name: 'trivy', parsed: { findings: [{}], coverage: [{ kind: 'files', detail: 'read', count: 1 }] } }],
    selectedModules: [], coveredModules: [],
    findings: [
      { identity_basis: 'rule_id', tools: ['trivy'] },
      { identity_basis: 'family', tools: ['builtin', 'semgrep'] },
    ],
  });
  const note = ledger.not_evaluable.find((n) => n.check === 'cross-scanner matching');
  assert.ok(note, 'an unmergeable duplicate looks exactly like a second finding');
  assert.match(note.reason, /1 finding\(s\) from trivy/);
  assert.match(note.reason, /may duplicate/);
});

test('when every finding has a CWE, nothing is said about matching', () => {
  const ledger = buildLedger({
    results: [{ name: 'builtin', parsed: { findings: [{}], coverage: [{ kind: 'files', detail: 'read', count: 1 }] } }],
    selectedModules: [], coveredModules: [],
    findings: [{ identity_basis: 'family', tools: ['builtin'] }],
  });
  assert.ok(!ledger.not_evaluable.some((n) => n.check === 'cross-scanner matching'));
});

// --- installed is not the same as ran

test('a scanner that could not reach the target is in the ledger, not absent from it', () => {
  const l = buildLedger({
    results: [withCoverage()],
    skipped: [{ name: 'nuclei', reason: 'only available as a container, and 127.0.0.1 is the container', unblock: 'install the binary' }],
  });
  const row = l.not_evaluable.find((n) => n.check === 'scanner nuclei');
  assert.ok(row, 'nothing went wrong and nothing ran: both facts have to survive');
  assert.match(row.reason, /container/);
  assert.match(row.unblock, /install/);
});

test('a merge that absorbed another rule from the same tool is counted', () => {
  const l = buildLedger({
    results: [withCoverage()],
    findings: [{ rule_id: 'missing-referrer-policy', collapsed: ['missing-referrer-policy', 'technology-banner'] }],
  });
  const row = l.not_evaluable.find((n) => n.check === 'same-tool merge');
  assert.ok(row);
  assert.match(row.reason, /technology-banner/);
  assert.match(row.unblock, /subtype/);
});

test('findings that merged nothing away add no ledger entry', () => {
  const l = buildLedger({ results: [withCoverage()], findings: [{ rule_id: 'x' }] });
  assert.ok(!l.not_evaluable.some((n) => n.check === 'same-tool merge'));
});
