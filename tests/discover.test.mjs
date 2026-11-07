// Attack-surface discovery, and the asking policy it exists to serve:
// anything the repo can answer must never become a question.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

import { discover, applicableModules, formatSurface } from '../lib/discover.mjs';
import { state, next } from '../lib/help.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const MOCK = join(ROOT, 'mock');
const surface = discover(MOCK);

test('the stack is identified from how dependencies are named', () => {
  assert.ok(surface.frameworks.includes('express'));
  assert.ok(surface.orms.includes('raw-sql'), 'a raw query path must be visible');
});

test('a bare word in application code is not a framework', () => {
  // mock/ has `req.query.next` and `router.use(next)`; neither makes this Next.js
  assert.ok(!surface.frameworks.includes('nextjs'), 'req.query.next must not imply Next.js');
});

test('routes, guards and insertion points are mapped', () => {
  assert.ok(surface.routes.length >= 3);
  assert.ok(surface.routes.some((r) => r.method === 'DELETE' && r.path.includes('/admin/users')));
  assert.ok(surface.guards.includes('requireAdmin'));
  assert.ok(surface.insertion_points.includes('body-parameter'));
  assert.ok(surface.insertion_points.includes('url-parameter'));
});

test('a hand-written guard counts as authentication', () => {
  assert.ok(surface.auth.length > 0, 'a guard with no auth library must still register');
  assert.ok(surface.applicable_modules.includes('M4'));
});

test('multi-tenancy is detected, which is what makes M8 matter', () => {
  assert.equal(surface.multi_tenant, true);
  assert.ok(surface.applicable_modules.includes('M8'));
});

test('modules with no inputs in this target are not selected', () => {
  // no react/vue/angular in mock, so client-side is out
  assert.ok(!surface.applicable_modules.includes('M9'));
  // business logic cannot be settled statically
  assert.ok(!surface.applicable_modules.includes('M11'));
});

test('applicableModules grows with the surface, not with optimism', () => {
  const bare = { manifests: [], frameworks: [], orms: [], auth: [], routes: [], guards: [], insertion_points: [], multi_tenant: false, files: 1 };
  const m = applicableModules(bare);
  assert.deepEqual(m.filter((x) => ['M4', 'M5', 'M8', 'M9'].includes(x)), [],
    'nothing detected means those modules are not claimed');
  assert.ok(m.includes('M1'), 'any codebase supports code review');
});

test('routes without a guard are called out, because that is the finding', () => {
  const text = formatSurface({
    ...surface, guards: [], routes: [{ method: 'GET', path: '/x', file: 'a.js' }],
  });
  assert.match(text, /no authorization guard was detected/);
});

test('node_modules is never walked', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ai-sec-disc-'));
  try {
    mkdirSync(join(dir, 'node_modules', 'pkg'), { recursive: true });
    writeFileSync(join(dir, 'node_modules', 'pkg', 'index.js'), "app.get('/leak', h)", 'utf8');
    writeFileSync(join(dir, 'app.js'), "const express = require('express')", 'utf8');
    const s = discover(dir);
    assert.equal(s.routes.length, 0, 'a route inside node_modules is not this app');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// --- the next-step machine: /sec-help must never ask anything

function tmpProject(t) {
  const root = mkdtempSync(join(tmpdir(), 'ai-sec-help-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return root;
}

test('a fresh project is told to discover, with a reason', (t) => {
  const n = next(state(tmpProject(t), 'p'));
  assert.equal(n.step, 'discover');
  assert.match(n.why, /guess/);
});

test('every next step carries a command and a reason', (t) => {
  const root = tmpProject(t);
  mkdirSync(join(root, '.sec', 'p'), { recursive: true });
  writeFileSync(join(root, '.sec', 'p', 'surface.json'), '{}', 'utf8');
  const n = next(state(root, 'p'));
  assert.ok(n.command);
  assert.ok(n.why && n.why.length > 10, 'a next step without a reason is a menu item');
});

test('after a successful default run, it does not send you back to write a config', (t) => {
  const root = tmpProject(t);
  const dir = join(root, '.sec', 'p');
  mkdirSync(join(dir, 'runs', '20260101-000000-aaaa'), { recursive: true });
  writeFileSync(join(dir, 'surface.json'), '{}', 'utf8');
  // deliberately no scope.json: the defaults worked
  writeFileSync(join(dir, 'runs', '20260101-000000-aaaa', 'result.json'),
    JSON.stringify({ run_state: 'done', findings: [], not_evaluable: [] }), 'utf8');

  const n = next(state(root, 'p'));
  assert.notEqual(n.step, 'scope', 'scope is worth writing before the first run, not after it');
  assert.equal(n.step, 'baseline');
});

test('a run with no baseline is told to promote, because diffing needs one', (t) => {
  const root = tmpProject(t);
  const dir = join(root, '.sec', 'p');
  mkdirSync(join(dir, 'runs', '20260101-000000-aaaa'), { recursive: true });
  writeFileSync(join(dir, 'surface.json'), '{}', 'utf8');
  writeFileSync(join(dir, 'scope.json'), '{"max_tier":"T0","environment":"local"}', 'utf8');
  writeFileSync(join(dir, 'runs', '20260101-000000-aaaa', 'result.json'),
    JSON.stringify({ run_state: 'done', findings: [], not_evaluable: [] }), 'utf8');

  const n = next(state(root, 'p'));
  assert.equal(n.step, 'baseline');
  assert.match(n.why, /cannot tell you what changed/);
});

test('a word in prose is not a framework', () => {
  // Scanning a Go repository reported "rails", because the word appeared once in a
  // markdown file. A Python or Ruby framework needs an import or a gem line.
  const dir = mkdtempSync(join(tmpdir(), 'ai-sec-fw-'));
  try {
    writeFileSync(join(dir, 'notes.md'), 'we considered rails and django before choosing Go', 'utf8');
    writeFileSync(join(dir, 'main.go'), 'package main\nimport "net/http"\n', 'utf8');
    const s = discover(dir);
    assert.ok(!s.frameworks.includes('rails'), 'prose must not imply a framework');
    assert.ok(!s.frameworks.includes('django'));
    assert.ok(s.frameworks.includes('go-http'), 'but a real import should be seen');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a real python import is still detected', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ai-sec-py-'));
  try {
    writeFileSync(join(dir, 'app.py'), 'from flask import Flask\napp = Flask(__name__)\n', 'utf8');
    assert.ok(discover(dir).frameworks.includes('flask'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('zero routes in a language we cannot read is flagged as a blind spot', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ai-sec-go-'));
  try {
    writeFileSync(join(dir, 'main.go'), 'package main\nimport "net/http"\n', 'utf8');
    const s = discover(dir);
    assert.equal(s.languages_with_route_support, false);
    assert.match(formatSurface(s), /could not read them, not that none exist/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the surface file lands where the next run will look for it', () => {
  assert.ok(readdirSync(MOCK).includes('expected.json'), 'mock keeps its known answers');
});

test('a model SDK is what makes M14 apply', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ai-sec-ai-'));
  try {
    writeFileSync(join(dir, 'package.json'),
      '{"dependencies":{"@anthropic-ai/sdk":"^0.30.0","express":"^4.18.0"}}', 'utf8');
    writeFileSync(join(dir, 'bot.js'),
      "const Anthropic = require('@anthropic-ai/sdk');\napp.post('/ask', h);\n", 'utf8');

    const s = discover(dir);
    assert.deepEqual(s.ai_sdks, ['anthropic']);
    assert.ok(s.applicable_modules.includes('M14'));
    assert.match(formatSurface(s), /Models:\s+anthropic/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('mock/ calls a model, so M14 applies to it', () => {
  assert.ok(surface.ai_sdks.includes('anthropic'));
  assert.ok(surface.applicable_modules.includes('M14'));
});

test('a repository that calls no model does not claim M14', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ai-sec-noai-'));
  try {
    writeFileSync(join(dir, 'package.json'), '{"dependencies":{"express":"^4.18.0"}}', 'utf8');
    writeFileSync(join(dir, 'app.js'), "const express = require('express');\n", 'utf8');

    const s = discover(dir);
    assert.deepEqual(s.ai_sdks, []);
    assert.ok(!s.applicable_modules.includes('M14'),
      'a module with no inputs in this target only produces a coverage gap nobody can close');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
