// Spawned by the controller like any other scanner binary.
import { scanRepo } from './engine.mjs';

const root = process.argv[2];
const maxFiles = Number(process.argv[3] ?? 5000);

try {
  process.stdout.write(JSON.stringify(scanRepo(root, { maxFiles })));
  process.exit(0);
} catch (e) {
  process.stderr.write(`builtin: ${e.stack ?? e.message}\n`);
  process.exit(1);
}
