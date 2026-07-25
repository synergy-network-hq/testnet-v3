import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '../..');
const isWindows = process.platform === 'win32';

const sourceBinary = path.join(
  repoRoot,
  'control-service',
  'target',
  'release',
  isWindows ? 'control-service.exe' : 'control-service',
);
const targetDir = path.join(repoRoot, 'build', 'electron-runtime', 'control-service');
const targetBinary = path.join(targetDir, isWindows ? 'control-service.exe' : 'control-service');

await fs.mkdir(targetDir, { recursive: true });
await fs.copyFile(sourceBinary, targetBinary);
if (!isWindows) {
  await fs.chmod(targetBinary, 0o755);
}
