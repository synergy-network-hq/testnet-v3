import { access, chmod, stat } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

if (process.platform !== 'darwin') {
  console.log(`node-pty spawn-helper preparation is only required on macOS; skipping on ${process.platform}.`);
  process.exit(0);
}

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(scriptDir, '..', '..');
const candidates = [
  path.join(
    rootDir,
    'node_modules',
    'node-pty',
    'prebuilds',
    `${process.platform}-${process.arch}`,
    'spawn-helper',
  ),
  path.join(rootDir, 'node_modules', 'node-pty', 'build', 'Release', 'spawn-helper'),
];

let prepared = 0;
for (const candidate of candidates) {
  try {
    await access(candidate);
    const metadata = await stat(candidate);
    await chmod(candidate, metadata.mode | 0o111);
    console.log(`Prepared executable node-pty helper: ${candidate}`);
    prepared += 1;
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
}

if (prepared === 0) {
  throw new Error(
    `No node-pty spawn-helper was found for ${process.platform}-${process.arch}.`,
  );
}
