// "What is broken?" Every check here has a fault-injection test in tests/doctor.test.mjs:
// break the thing, and the matching check must fail — or the doctor itself fails.
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import * as redactor from '../controller/redact.mjs';
import { SCANNERS, TARGETS } from '../adapters/index.mjs';
import {
  TIERS, tierRank, environmentIsProduction, hostIsProduction, AUTH_BASES, AUTH_MAX_AGE_DAYS,
} from '../controller/rules.mjs';
import { loadScope, DEFAULT_SCOPE } from './scan.mjs';

const ok = (group, name, detail = '') => ({ group, name, status: 'ok', detail });
const warn = (group, name, detail) => ({ group, name, status: 'warn', detail });
const fail = (group, name, detail) => ({ group, name, status: 'fail', detail });

export async function doctor({ root = '.', slug = 'default' } = {}) {
  const checks = [];

  // --- Machine
  const major = Number(process.versions.node.split('.')[0]);
  checks.push(major >= 20
    ? ok('Machine', 'node', `v${process.versions.node}`)
    : fail('Machine', 'node', `v${process.versions.node}; ai-sec needs Node 20+`));

  for (const scanner of Object.values(SCANNERS)) {
    try {
      const d = await scanner.detect();
      checks.push(d.ok
        ? ok('Machine', `scanner:${scanner.name}`, d.version ?? 'present')
        : warn('Machine', `scanner:${scanner.name}`, d.install ?? 'not installed'));
    } catch (e) {
      checks.push(fail('Machine', `scanner:${scanner.name}`, `detect() threw: ${e.message}`));
    }
  }

  // --- Safety. These mirror the gates; a doctor that passes where a gate refuses is a bug.
  const scopeFile = join(root, '.sec', slug, 'scope.json');
  let scope;
  let scopeParsed = true;
  try {
    scope = loadScope(root, slug);
  } catch (e) {
    scopeParsed = false;
    scope = { ...DEFAULT_SCOPE };
    checks.push(fail('Project', 'scope.json', `unreadable: ${e.message}`));
  }
  if (scopeParsed) {
    checks.push(existsSync(scopeFile)
      ? ok('Project', 'scope.json', scopeFile)
      : warn('Project', 'scope.json', 'missing; defaults apply (T0, no hosts allowed)'));
  }

  checks.push(scope.production === true
    ? fail('Safety', 'production', 'scope.json declares a production environment')
    : ok('Safety', 'production', 'not production'));

  checks.push(environmentIsProduction(scope.environment)
    ? fail('Safety', 'environment-name', `"${scope.environment}" names production`)
    : ok('Safety', 'environment-name', scope.environment));

  const badHosts = (scope.allow_hosts ?? []).filter(hostIsProduction);
  checks.push(badHosts.length > 0
    ? fail('Safety', 'allow-hosts', `production hosts in the allowlist: ${badHosts.join(', ')}`)
    : ok('Safety', 'allow-hosts', `${(scope.allow_hosts ?? []).length} host(s)`));

  checks.push(TIERS.includes(scope.max_tier)
    ? ok('Safety', 'tier-ceiling', scope.max_tier)
    : fail('Safety', 'tier-ceiling', `unknown tier "${scope.max_tier}"`));

  if (tierRank(scope.max_tier) > 0) {
    const auth = scope.authorization;
    const granted = Date.parse(auth?.granted_at ?? '');
    if (!auth || !AUTH_BASES.includes(auth.basis)) {
      checks.push(fail('Safety', 'authorization', `max_tier is ${scope.max_tier} but no valid authorization.basis`));
    } else if (Number.isNaN(granted)) {
      checks.push(fail('Safety', 'authorization', 'authorization.granted_at is missing or not a date'));
    } else {
      const age = Math.floor((Date.now() - granted) / 86_400_000);
      checks.push(age > AUTH_MAX_AGE_DAYS
        ? fail('Safety', 'authorization', `${age} days old; re-confirm (max ${AUTH_MAX_AGE_DAYS})`)
        : ok('Safety', 'authorization', `${auth.basis}, ${age} days old`));
    }
  } else {
    checks.push(ok('Safety', 'authorization', 'not required at T0'));
  }

  // The scope file itself must not carry a secret.
  if (existsSync(scopeFile)) {
    const raw = readFileSync(scopeFile, 'utf8');
    checks.push(redactor.containsSecret(raw)
      ? fail('Safety', 'scope-secrets', 'scope.json contains something that looks like a credential')
      : ok('Safety', 'scope-secrets', 'no credential in scope.json'));
  }

  // --- Redaction must be live, or nothing may be written.
  const probe = redactor.redactText('AKIAIOSFODNN7EXAMPLE');
  checks.push(probe.includes('AKIAIOSFODNN7EXAMPLE')
    ? fail('Safety', 'redaction', 'the redactor did not redact a known secret pattern')
    : ok('Safety', 'redaction', 'active'));

  // --- Targets
  checks.push(Object.keys(TARGETS).length > 0
    ? ok('Machine', 'targets', Object.keys(TARGETS).join(', '))
    : fail('Machine', 'targets', 'no target adapters registered'));

  const failed = checks.filter((c) => c.status === 'fail');
  return { ok: failed.length === 0, checks, failed };
}

export function formatDoctor({ checks }) {
  const icon = { ok: 'ok  ', warn: 'warn', fail: 'FAIL' };
  const groups = [...new Set(checks.map((c) => c.group))];
  const lines = [];
  for (const g of groups) {
    lines.push(`\n${g}`);
    for (const c of checks.filter((x) => x.group === g)) {
      lines.push(`  [${icon[c.status]}] ${c.name.padEnd(22)} ${c.detail}`);
    }
  }
  return lines.join('\n');
}
