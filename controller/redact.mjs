// Gate G5. Runs before anything reaches disk, an event, a log line or chat output.
// Removing this module must make tests/redact.test.mjs fail. CONTRACTS §8.

/**
 * Patterns are deliberately broad: a false redaction costs a character of context,
 * a missed one leaks a credential.
 */
const PATTERNS = [
  { type: 'aws-access-key', re: /\b(?:AKIA|ASIA|AIDA|AGPA|AROA)[0-9A-Z]{16}\b/g },
  { type: 'github-token', re: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g },
  { type: 'slack-token', re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g },
  { type: 'google-api-key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { type: 'openai-key', re: /\bsk-[A-Za-z0-9_-]{20,}\b/g },
  { type: 'private-key', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g },
  { type: 'jwt', re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  { type: 'bearer', re: /\b[Bb]earer\s+[A-Za-z0-9._~+/-]{16,}=*/g },
  { type: 'basic-auth-url', re: /\b([a-z][a-z0-9+.-]*):\/\/[^/\s:@]+:[^/\s@]+@/gi },
  { type: 'connection-password', re: /\b(?:password|passwd|pwd)\s*=\s*(?:"[^"]{3,}"|'[^']{3,}'|[^\s;,"']{3,})/gi },
  { type: 'generic-secret-assign', re: /\b(?:api[_-]?key|secret|token|access[_-]?key|client[_-]?secret)\s*[:=]\s*(?:"[^"]{8,}"|'[^']{8,}'|[A-Za-z0-9._\-+/]{16,}=*)/gi },
];

export function placeholder(type, value) {
  const s = String(value ?? '');
  const first4 = s.replace(/^\s+/, '').slice(0, 4);
  return `<redacted:${type}:${s.length}:${first4}>`;
}

/** Replace every secret-looking run in a string. Never returns the original value. */
export function redactText(text) {
  if (typeof text !== 'string' || text === '') return text;
  let out = text;
  for (const { type, re } of PATTERNS) {
    out = out.replace(new RegExp(re.source, re.flags), (m) => placeholder(type, m));
  }
  return out;
}

/** A value a secret scanner reported: we know it is a secret, so never echo it. */
export function redactKnownSecret(value, type = 'secret') {
  return placeholder(type, value);
}

const SECRET_KEYS = /^(secret|password|passwd|pwd|token|api_?key|access_?key|client_?secret|authorization|private_?key)$/i;

/** Deep-redact a structure before it is written or logged. */
export function redactDeep(value, seen = new WeakSet()) {
  if (typeof value === 'string') return redactText(value);
  if (value === null || typeof value !== 'object') return value;
  if (seen.has(value)) return value;
  seen.add(value);

  if (Array.isArray(value)) return value.map((v) => redactDeep(v, seen));

  const out = {};
  for (const [k, v] of Object.entries(value)) {
    out[k] = SECRET_KEYS.test(k) && (typeof v === 'string' || typeof v === 'number')
      ? placeholder('secret', v)
      : redactDeep(v, seen);
  }
  return out;
}

/** True when a string still carries something that looks like a live secret. */
export function containsSecret(text) {
  if (typeof text !== 'string') return false;
  return PATTERNS.some(({ re }) => new RegExp(re.source, re.flags).test(text));
}

export const SECRET_PATTERN_TYPES = PATTERNS.map((p) => p.type);
