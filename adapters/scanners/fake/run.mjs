// The fake scanner's "binary". Spawned by the controller like any real tool,
// so the pipeline is exercised end to end with nothing installed.
import adapter from './adapter.mjs';

const mode = process.argv[2] ?? 'findings';

const payloads = {
  // normal: four findings and full coverage
  findings: { findings: adapter._canned, coverage: adapter._coverage, errors: [] },
  // a genuinely clean target: no findings, but it did look
  clean: { findings: [], coverage: adapter._coverage, errors: [] },
  // looked at nothing and says so by saying nothing: must not read as clean
  nothing: { findings: [], coverage: [], errors: [] },
  // reports traffic that left the recorded scope, so auto-stop has something to fire on
  hostile: {
    findings: [], coverage: adapter._coverage, errors: [],
    counters: { requests: 3, failures: 0, consecutive_errors: 0, out_of_scope_requests: 1, unintended_writes: 0, auth_failures: 0 },
  },
};

if (mode === 'fail') {
  process.stderr.write('fake scanner: simulated failure\n');
  process.exit(3);
}

if (mode === 'timeout') {
  setTimeout(() => process.exit(0), 60_000);
} else {
  process.stdout.write(JSON.stringify(payloads[mode] ?? payloads.findings));
  process.exit(0);
}
