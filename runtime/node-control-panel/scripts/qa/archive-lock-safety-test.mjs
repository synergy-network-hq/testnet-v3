import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const scripts = [
  'scripts/archive/run-snapshot-worker-remote.sh',
  'scripts/archive/revalidate-public-catalog-remote.sh',
  'scripts/archive/upload-public-catalog-local.sh',
];

for (const relativePath of scripts) {
  const source = fs.readFileSync(path.join(root, relativePath), 'utf8');
  const cleanup = source.slice(source.indexOf('cleanup() {'), source.indexOf('\n}', source.indexOf('cleanup() {')) + 2);

  if (!source.includes('FLOCK_FD = 9')) {
    throw new Error(`${relativePath} must use a fixed inherited lock descriptor.`);
  }
  if (!source.includes('os.fstat(FLOCK_FD)') || !source.includes('os.stat(lock_path)') || !source.includes('fcntl.flock(FLOCK_FD, fcntl.LOCK_EX | fcntl.LOCK_NB)')) {
    throw new Error(`${relativePath} must validate and lock the inherited descriptor.`);
  }
  if (!source.includes('fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)')) {
    throw new Error(`${relativePath} must use a nonblocking kernel advisory lock.`);
  }
  if (!source.includes('os.set_inheritable(lock_file.fileno(), True)')) {
    throw new Error(`${relativePath} must preserve the lock descriptor across exec.`);
  }
  if (!source.includes('os.execve("/bin/bash", ["/bin/bash", script, *args], environment)')) {
    throw new Error(`${relativePath} must execute the job while holding the kernel lock.`);
  }
  if (!source.includes('.flock"')) {
    throw new Error(`${relativePath} must not reuse the legacy lock path.`);
  }
  if (!source.includes('SYNERGY_ARCHIVE_FLOCK_HELD')) {
    throw new Error(`${relativePath} must mark the validated inherited descriptor across exec.`);
  }
  if (source.includes('/usr/bin/shlock') || source.includes('${LOCK}.reclaim') || source.includes('SYNERGY_ARCHIVE_FLOCK_PATH')) {
    throw new Error(`${relativePath} must not use PID or reclamation marker locks.`);
  }
  if (cleanup.includes('$LOCK')) {
    throw new Error(`${relativePath} must leave lock-file lifetime to the kernel.`);
  }
}

console.log('Archive lock safety contract QA passed.');
