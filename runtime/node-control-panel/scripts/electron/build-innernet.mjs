import { execFileSync } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const sourceRepository = process.env.INNERNET_SOURCE_REPOSITORY || 'tonarino/innernet';
const sourceRevision = process.env.INNERNET_SOURCE_REV || 'dbdb0097b397fa5b10566ae58d33c699142102f2';
const rustTargets = {
  'darwin-arm64': 'aarch64-apple-darwin',
  'darwin-x64': 'x86_64-apple-darwin',
  'linux-amd64': 'x86_64-unknown-linux-gnu',
  'linux-arm64': 'aarch64-unknown-linux-gnu',
};

function fail(message) {
  throw new Error(`[build-innernet] ${message}`);
}

function parseTargets() {
  const targets = [];
  for (let index = 2; index < process.argv.length; index += 1) {
    if (process.argv[index] !== '--target') fail(`Unknown argument: ${process.argv[index]}`);
    const target = process.argv[++index];
    if (!rustTargets[target]) fail(`Unsupported Innernet target: ${target}`);
    targets.push(target);
  }
  if (!targets.length) fail('Pass at least one --target value.');
  return [...new Set(targets)];
}

function run(command, args, options = {}) {
  execFileSync(command, args, { stdio: 'inherit', ...options });
}

function isNative(target) {
  return (process.platform === 'darwin' && target.startsWith('darwin-') && process.arch === (target.endsWith('arm64') ? 'arm64' : 'x64'))
    || (process.platform === 'linux' && target === (process.arch === 'arm64' ? 'linux-arm64' : 'linux-amd64'));
}

async function main() {
  if (!/^[0-9a-f]{40}$/.test(sourceRevision)) fail('INNERNET_SOURCE_REV must be a full immutable commit SHA.');
  const targets = parseTargets();
  const sourceDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'synergy-innernet-source-'));
  const cargoTargetDirectory = path.join(sourceDirectory, 'target');
  const outputDirectory = path.join(repoRoot, 'binaries', 'innernet');
  try {
    run('git', ['init', '--quiet'], { cwd: sourceDirectory });
    run('git', ['remote', 'add', 'origin', `https://github.com/${sourceRepository}.git`], { cwd: sourceDirectory });
    run('git', ['fetch', '--depth', '1', 'origin', sourceRevision], { cwd: sourceDirectory });
    run('git', ['checkout', '--detach', '--quiet', 'FETCH_HEAD'], { cwd: sourceDirectory });
    const checkedOutRevision = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: sourceDirectory, encoding: 'utf8' }).trim();
    if (checkedOutRevision !== sourceRevision) fail(`Fetched Innernet revision ${checkedOutRevision} does not match ${sourceRevision}.`);

    await fs.mkdir(outputDirectory, { recursive: true });
    const built = {};
    for (const target of targets) {
      const rustTarget = rustTargets[target];
      const args = ['--target', rustTarget, '--locked', '--release', '--package', 'innernet'];
      if (isNative(target)) {
        run('cargo', ['build', ...args], { cwd: sourceDirectory, env: { ...process.env, CARGO_TARGET_DIR: cargoTargetDirectory } });
      } else if (target === 'linux-amd64' && process.platform === 'darwin') {
        run('cargo', ['zigbuild', ...args], { cwd: sourceDirectory, env: { ...process.env, CARGO_TARGET_DIR: cargoTargetDirectory } });
      } else {
        fail(`Cross-building ${target} from ${process.platform}/${process.arch} is not configured.`);
      }
      const sourceBinary = path.join(cargoTargetDirectory, rustTarget, 'release', 'innernet');
      const outputPath = path.join(outputDirectory, `innernet-${target}`);
      await fs.copyFile(sourceBinary, outputPath);
      await fs.chmod(outputPath, 0o755);
      const stat = await fs.stat(outputPath);
      built[target] = { path: path.basename(outputPath), bytes: stat.size };
    }
    await fs.writeFile(path.join(outputDirectory, 'SOURCE.json'), `${JSON.stringify({ repository: sourceRepository, revision: sourceRevision, targets: built }, null, 2)}\n`);
  } finally {
    await fs.rm(sourceDirectory, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
