// Shared filesystem walk. Lives here, not inside a scanner, so lib/ never has to
// import one — see tests/architecture.test.mjs.
import { readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

export const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'out', 'coverage', '.next', '.nuxt',
  'vendor', '.venv', '__pycache__', '.sec', '.perf',
]);

export const MAX_FILE_BYTES = 1_500_000;

/** Breadth of files a scan or a discovery pass may read. Skips vendored and generated trees. */
export function walk(root, { maxFiles = 5000 } = {}) {
  const files = [];
  const stack = [root];
  while (stack.length && files.length < maxFiles) {
    const dir = stack.pop();
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      const p = join(dir, e.name);
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name) && !e.name.startsWith('.')) stack.push(p);
      } else if (e.isFile()) {
        try {
          if (statSync(p).size <= MAX_FILE_BYTES) files.push(p);
        } catch { /* unreadable: the caller records it */ }
      }
    }
  }
  return files;
}
