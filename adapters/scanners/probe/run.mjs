import { probe } from './engine.mjs';

const [origin, tier = 'T1', paths = ''] = process.argv.slice(2);

// Accounts arrive in the environment because they carry session cookies, and a
// command line is public to the machine. Parsing failure is loud: a silently
// empty account list turns the cross-account check into a quiet no-op.
let accounts = [];
if (process.env.SEC_PROBE_ACCOUNTS) {
  try {
    accounts = JSON.parse(process.env.SEC_PROBE_ACCOUNTS);
  } catch (e) {
    process.stderr.write(`probe: SEC_PROBE_ACCOUNTS is not valid JSON: ${e.message}\n`);
    process.exit(1);
  }
}

try {
  const out = await probe(origin, {
    tier,
    paths: paths ? paths.split(',').filter(Boolean) : [],
    accounts,
  });
  process.stdout.write(JSON.stringify(out));
  process.exit(0);
} catch (e) {
  process.stderr.write(`probe: ${e.stack ?? e.message}\n`);
  process.exit(1);
}
