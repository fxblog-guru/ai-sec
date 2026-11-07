// Where a finding lives changes what it means. Every case here came from scanning
// a real repository and getting the answer wrong first.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  placeFinding, toRepoRelative, isNonProduction, isVendored, isArtifact,
} from '../controller/locate.mjs';

const f = (file) => ({ rule_id: 'hardcoded-credential', severity: 'Critical', likelihood: 'HIGH', location: { file, line: 1 }, detail: 'A credential' });

test('an absolute path becomes repo-relative, so the fingerprint is portable', () => {
  const root = 'C:/Users/luann/agentic-fx/ai-sec';
  assert.equal(toRepoRelative('C:/Users/luann/agentic-fx/ai-sec/lib/scan.mjs', root), 'lib/scan.mjs');
  assert.equal(toRepoRelative('C:\\Users\\luann\\agentic-fx\\ai-sec\\lib\\scan.mjs', root), 'lib/scan.mjs');
  assert.equal(toRepoRelative('./lib/scan.mjs', root), 'lib/scan.mjs');
});

test('path case does not defeat the root match on Windows', () => {
  assert.equal(toRepoRelative('c:/users/luann/repo/a.js', 'C:/Users/luann/repo'), 'a.js');
});

test('test conventions from every language are recognised, not just JavaScript', () => {
  for (const p of [
    'tests/a.js', 'test/a.js', '__tests__/a.js', 'spec/a.rb', 'fixtures/x.json',
    'src/a.test.ts', 'src/a.spec.js',
    'internal/redact/redact_test.go',   // Go
    'app/test_views.py',                 // Python
    'spec/models/user_spec.rb',          // Ruby
    'src/UserTest.java',                 // Java
  ]) {
    assert.equal(isNonProduction(p), true, `${p} should be non-production`);
  }
  for (const p of ['src/app.js', 'internal/store/jobs.go', 'lib/latest.py', 'src/contest.js']) {
    assert.equal(isNonProduction(p), false, `${p} should be production`);
  }
});

test('a finding in test code is reported, downgraded, and explained', () => {
  const out = placeFinding(f('internal/redact/redact_test.go'), null);
  assert.equal(out.placement, 'non-production');
  assert.equal(out.severity, 'Info', 'downgraded, never dropped');
  assert.match(out.detail, /unlikely to be reachable/);
});

test('vendored code is downgraded too, and says whose it is', () => {
  const out = placeFinding(f('node_modules/pkg/index.js'), null);
  assert.equal(out.placement, 'vendored');
  assert.equal(out.severity, 'Info');
  assert.match(out.detail, /does not author/);
  assert.equal(isVendored('vendor/lib.go'), true);
  assert.equal(isVendored('dist/bundle.min.js'), true);
});

test('our own run artifacts are not findings about the target', () => {
  // gitleaks walks the tree itself and will read .sec/.../raw/gitleaks.json,
  // reporting the secrets recorded in it as new ones, growing every run.
  assert.equal(isArtifact('.sec/self/runs/2026/raw/gitleaks/gitleaks.json'), true);
  assert.equal(placeFinding(f('.sec/x/runs/a/raw/y.json'), null).placement, 'artifact');
});

test('a git worktree is a second copy of files already scanned', () => {
  // Scanning a repo with two worktrees reported every finding three times.
  assert.equal(isArtifact('.claude/worktrees/agent-abc/internal/api_test.go'), true);
  assert.equal(isArtifact('worktrees/feature-x/src/app.js'), true);
  assert.equal(isArtifact('src/worktree-manager.js'), false, 'a file merely named for them is not one');
});

test('another tool\'s state directory is not project source', () => {
  assert.equal(isArtifact('.sdlc/reviews/x/code-123.diff'), true);
  assert.equal(isArtifact('.sdlc/scripts/.manifest.json'), true);
  assert.equal(isArtifact('.sdlc/config.json'), false, 'config could hold a real secret');
});

test('production code keeps its severity', () => {
  const out = placeFinding(f('lib/scan.mjs'), null);
  assert.equal(out.placement, 'production');
  assert.equal(out.severity, 'Critical');
});

test('placement never mutates the input', () => {
  const input = f('tests/a.js');
  const before = JSON.stringify(input);
  placeFinding(input, null);
  assert.equal(JSON.stringify(input), before);
});
