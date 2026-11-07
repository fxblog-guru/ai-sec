// The repo target: a directory on disk. CONTRACTS §3.
import { statSync } from 'node:fs';
import { resolve } from 'node:path';

export default {
  name: 'repo',

  async prepare({ spec }) {
    const root = resolve(spec.target_path ?? '.');
    let st;
    try {
      st = statSync(root);
    } catch {
      return { ok: false, root, meta: {}, error: `target_path does not exist: ${root}` };
    }
    if (!st.isDirectory()) {
      return { ok: false, root, meta: {}, error: `target_path is not a directory: ${root}` };
    }
    return { ok: true, root, meta: { kind: 'repo', path: root } };
  },

  async cleanup() {},
};
