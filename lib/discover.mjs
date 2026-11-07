// Phase 1 — map the attack surface before testing anything.
// Burp models the app as a graph of locations; ZAP builds a Sites Tree. This is
// the static equivalent: what the code is, where input enters, what guards exist.
import { readFileSync, existsSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

import { walk } from './fswalk.mjs';
import { ALL_MODULES } from './scan.mjs';

const MANIFESTS = {
  'package.json': 'node',
  'requirements.txt': 'python',
  'pyproject.toml': 'python',
  'go.mod': 'go',
  'pom.xml': 'java',
  'build.gradle': 'java',
  'Gemfile': 'ruby',
  'composer.json': 'php',
  'Cargo.toml': 'rust',
  '*.csproj': 'dotnet',
};

/**
 * Match the way a dependency is actually named, and only that.
 *
 * In a manifest, a bare quoted key is a dependency. In source, it is not — a string
 * literal `'next'` is `searchParams.get('next')` far more often than it is Next.js.
 * So source must show an actual import. Getting this wrong made `req.query.next`
 * evidence of a framework, and then pulled in a whole module that did not apply.
 */
const dep = (name) => ({
  name,
  // a manifest key: "express": "^4.18.0"
  manifest: new RegExp(`["']${name}["']\\s*:`, 'i'),
  // source must show a real import, not merely the word in quotes
  source: new RegExp(`\\brequire\\(\\s*["'\`]${name}(?:["'\`/])|\\bfrom\\s+["'\`]${name}(?:["'\`/])|\\bimport\\s+["'\`]${name}(?:["'\`/])`, 'i'),
  // what a quoted word alone would match — kept so the mutation test can loosen it
  quoted: new RegExp(`["']${name}["']`, 'i'),
});

const matches = (m, text, isManifest) => {
  if (m instanceof RegExp) return m.test(text);
  return isManifest ? m.manifest.test(text) || m.source.test(text) : m.source.test(text);
};

/**
 * A Python or Ruby import, for frameworks whose name is not a quoted dependency.
 * A bare word is not enough: scanning a Go repository reported "rails" because the
 * word appeared once in a markdown file.
 */
const imported = (name) => new RegExp(
  `^\\s*(?:from|import|require)\\s+['"]?${name}\\b|^\\s*gem\\s+['"]${name}['"]|["']${name}["']\\s*:`,
  'im',
);

const FRAMEWORKS = [
  [dep('express'), 'express'], [dep('fastify'), 'fastify'], [dep('koa'), 'koa'],
  [dep('@nestjs'), 'nestjs'], [dep('next'), 'nextjs'], [dep('react'), 'react'],
  [dep('vue'), 'vue'], [dep('@angular'), 'angular'],
  [imported('django'), 'django'], [imported('flask'), 'flask'], [imported('fastapi'), 'fastapi'],
  [imported('rails'), 'rails'], [/\bspringframework\b/, 'spring'], [imported('laravel'), 'laravel'],
  [/\bnet\/http\b|\bgin-gonic\b|\bgorilla\/mux\b|\bchi\.NewRouter\b/, 'go-http'],
];

/**
 * An application that calls a model has an attack surface the other twelve modules
 * do not describe: the prompt is an insertion point, the completion is an untrusted
 * source, and a tool handler is a sink with the model's own words in it.
 */
const AI_SDKS = [
  [dep('@anthropic-ai/sdk'), 'anthropic'], [dep('openai'), 'openai'],
  [dep('@google/generative-ai'), 'google-genai'], [dep('@aws-sdk/client-bedrock-runtime'), 'bedrock'],
  [dep('@mistralai/mistralai'), 'mistral'], [dep('cohere-ai'), 'cohere'],
  [dep('@langchain/core'), 'langchain'], [dep('langchain'), 'langchain'],
  [dep('llamaindex'), 'llamaindex'], [dep('ollama'), 'ollama'],
  [dep('@ai-sdk/anthropic'), 'vercel-ai'], [dep('@ai-sdk/openai'), 'vercel-ai'],
  [imported('anthropic'), 'anthropic'], [imported('openai'), 'openai'],
  [imported('litellm'), 'litellm'], [imported('transformers'), 'transformers'],
];

const ORMS = [
  [dep('prisma'), 'prisma'], [dep('sequelize'), 'sequelize'], [dep('typeorm'), 'typeorm'],
  [dep('knex'), 'knex'], [dep('mongoose'), 'mongoose'], [/\bsqlalchemy\b/i, 'sqlalchemy'],
  [/\b(?:db|conn|client|pool)\s*\.\s*(?:raw|query|execute)\s*\(/, 'raw-sql'],
];

const ROUTE_RE = /\b(?:router|app)\s*\.\s*(get|post|put|patch|delete|all)\s*\(\s*['"`]([^'"`]+)['"`]/g;
const PY_ROUTE_RE = /@(?:app|router|bp)\.(get|post|put|patch|delete|route)\s*\(\s*['"]([^'"]+)['"]/g;
const GUARD_RE = /\b(?:use|before_request|middleware)\s*\(\s*([A-Za-z_$][\w$.]*)\s*\)/g;
const GUARD_NAME = /auth|admin|require|ensure|protect|guard|permission|role|verify|authoriz|login|logged|signedin/i;

const INSERTION_KINDS = [
  [/\breq(?:uest)?\.body\b|\brequest\.(?:json|form)\b/, 'body-parameter'],
  [/\breq(?:uest)?\.query\b|\brequest\.args\b/, 'url-parameter'],
  [/\breq(?:uest)?\.params\b/, 'url-path'],
  [/\breq(?:uest)?\.headers\b/, 'header'],
  [/\breq(?:uest)?\.cookies\b/, 'cookie'],
  [/\bmulter\b|\bupload\b|\brequest\.files\b/, 'file-upload'],
];

const TENANT_RE = /tenant|org(?:ani[sz]ation)?_id|workspace|account_id|company_id/i;
const AUTH_HINT = [
  [/\bjsonwebtoken\b|\bjwt\b/i, 'jwt'], [dep('passport'), 'passport'],
  [/\bnext-auth\b|\bauth0\b/i, 'hosted-idp'], [/\b(?:bcrypt|argon2|scrypt)\b/i, 'password-kdf'],
  [/\boauth|openid\b/i, 'oauth'], [/\bexpress-session\b|\breq\.session\b/i, 'session'],
  [/\bhashPassword\b|\bcomparePassword\b|\bcheckPassword\b/i, 'password-local'],
];

export function discover(root, { maxFiles = 5000 } = {}) {
  const files = walk(root, { maxFiles });
  const rel = (f) => relative(root, f).split(sep).join('/');

  const manifests = [];
  for (const [name, eco] of Object.entries(MANIFESTS)) {
    if (name.includes('*')) continue;
    if (existsSync(join(root, name))) manifests.push({ file: name, ecosystem: eco });
  }

  const frameworks = new Set();
  const orms = new Set();
  const aiSdks = new Set();
  const auth = new Set();
  const routes = [];
  const guards = new Set();
  const insertionPoints = new Set();
  let multiTenant = false;
  let bytes = 0;

  for (const file of files) {
    let text;
    try {
      ({ size: bytes } = statSync(file));
      text = readFileSync(file, 'utf8');
    } catch { continue; }
    if (text.includes('\u0000')) continue;

    const r = rel(file);
    const isManifest = /package\.json|requirements\.txt|pyproject\.toml|go\.mod|Gemfile|composer\.json/.test(r);

    for (const [m, name] of FRAMEWORKS) if (matches(m, text, isManifest)) frameworks.add(name);
    for (const [m, name] of ORMS) if (matches(m, text, isManifest)) orms.add(name);
    for (const [m, name] of AI_SDKS) if (matches(m, text, isManifest)) aiSdks.add(name);
    for (const [m, name] of AUTH_HINT) if (matches(m, text, isManifest)) auth.add(name);
    if (TENANT_RE.test(text)) multiTenant = true;

    if (isManifest) continue;

    for (const re of [ROUTE_RE, PY_ROUTE_RE]) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(text)) !== null) {
        routes.push({ method: m[1].toUpperCase(), path: m[2], file: r });
        if (routes.length > 2000) break;
      }
    }
    GUARD_RE.lastIndex = 0;
    let g;
    while ((g = GUARD_RE.exec(text)) !== null) {
      if (GUARD_NAME.test(g[1])) guards.add(g[1]);
    }
    for (const [re, kind] of INSERTION_KINDS) if (re.test(text)) insertionPoints.add(kind);
  }

  const surface = {
    schema: 'sec-surface/v1',
    discovered_at: new Date().toISOString(),
    root,
    files: files.length,
    manifests,
    frameworks: [...frameworks],
    orms: [...orms],
    ai_sdks: [...aiSdks],
    auth: [...auth],
    multi_tenant: multiTenant,
    routes: dedupeRoutes(routes),
    guards: [...guards],
    insertion_points: [...insertionPoints],
  };
  // A hand-written guard is an authentication mechanism too, even when no library
  // names itself. Without this, M4 is skipped on exactly the apps that need it most.
  if (surface.auth.length === 0 && surface.guards.length > 0) {
    surface.auth.push('custom-middleware');
  }
  // Route and guard detection is written for JS/TS and Python. Record whether this
  // target is even a language we can read, so zero is not mistaken for none.
  surface.languages_with_route_support = files.some((f) => /\.(?:js|mjs|cjs|jsx|ts|tsx|py)$/i.test(f));

  surface.applicable_modules = applicableModules(surface);
  return surface;
}

function dedupeRoutes(routes) {
  const seen = new Set();
  const out = [];
  for (const r of routes) {
    const key = `${r.method} ${r.path}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(r);
  }
  return out;
}

/**
 * Which modules this target can actually support. Selecting a module the target
 * has no inputs for only produces a coverage gap nobody can close.
 */
export function applicableModules(surface) {
  const on = new Set(['M1', 'M3', 'M12', 'M13']); // any codebase supports these
  if (surface.manifests.length > 0) on.add('M2');
  if (surface.auth.length > 0) on.add('M4');
  if (surface.routes.length > 0 || surface.guards.length > 0) { on.add('M5'); on.add('M7'); }
  if (surface.insertion_points.length > 0) on.add('M6');
  if (surface.orms.length > 0 || surface.multi_tenant) on.add('M8');
  if (surface.frameworks.some((f) => ['react', 'vue', 'angular', 'nextjs'].includes(f))) on.add('M9');
  if ((surface.ai_sdks ?? []).length > 0) on.add('M14');
  if (surface.manifests.some((m) => m.ecosystem) || surface.files > 0) on.add('M10');
  return ALL_MODULES.filter((m) => on.has(m));
}

/** Modules a static run can never settle: say so rather than claiming them. */
export const STATIC_BLIND_SPOTS = {
  M11: 'business logic and abuse cases cannot be settled statically; they need the intended flow modelled and a target to try it against',
  // Found by scanning an AI application nobody here wrote: the untrusted text
  // reaching its prompts arrives as a handler argument from another module, and
  // no pattern crosses a call boundary. The direct cases are checked; indirect
  // prompt injection through stored or retrieved content is not.
  M14: 'indirect prompt injection cannot be settled by pattern matching: the untrusted text usually reaches the prompt as an argument from another module, or from a document the model retrieves at run time',
};

export function formatSurface(s) {
  const lines = [
    `Files:      ${s.files}`,
    `Stack:      ${[...s.frameworks, ...s.orms].join(', ') || 'not identified'}`,
    `Auth:       ${s.auth.join(', ') || 'none detected'}`,
    `Routes:     ${s.routes.length}`,
    `Guards:     ${s.guards.join(', ') || 'none detected'}`,
    `Input from: ${s.insertion_points.join(', ') || 'none detected'}`,
    `Tenancy:    ${s.multi_tenant ? 'multi-tenant markers present' : 'no tenant markers'}`,
    `Models:     ${(s.ai_sdks ?? []).join(', ') || 'no model SDK detected'}`,
    `Modules:    ${s.applicable_modules.join(',')}`,
  ];
  if (s.routes.length && !s.guards.length) {
    lines.push('', 'Note: routes but no authorization guard was detected. Either authorization');
    lines.push('      lives somewhere this pass did not read, or it is missing. M5 will say which.');
  }
  // Zero routes can mean "none" or "we cannot read this language". Saying which is
  // the difference between a finding and a blind spot.
  if (s.routes.length === 0 && !s.languages_with_route_support) {
    lines.push('', 'Note: route detection covers JavaScript, TypeScript and Python. Zero routes');
    lines.push('      here means this pass could not read them, not that none exist.');
  }
  return lines.join('\n');
}
