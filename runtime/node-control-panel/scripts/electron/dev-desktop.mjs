import { spawn, spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { resolveDesktopRendererPort } from './dev-port.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..', '..');
const viteBinary = path.join(
  repoRoot,
  'node_modules',
  '.bin',
  process.platform === 'win32' ? 'vite.cmd' : 'vite',
);
const electronScript = path.join(repoRoot, 'scripts', 'electron', 'dev-electron.mjs');

const rendererPort = await resolveDesktopRendererPort();
const childEnv = {
  ...process.env,
  SYNERGY_RENDERER_PORT: String(rendererPort),
};

console.log('[dev:desktop] Building control-service for the current source tree');
const cargoBuild = spawnSync(
  'cargo',
  ['build', '--manifest-path', 'control-service/Cargo.toml', '--bin', 'control-service', '--release', '--no-default-features'],
  {
    cwd: repoRoot,
    stdio: 'inherit',
  },
);

if (cargoBuild.status !== 0) {
  process.exit(cargoBuild.status ?? 1);
}

console.log(`[dev:desktop] Using renderer port ${rendererPort}`);

const viteProcess = spawn(viteBinary, [], {
  cwd: repoRoot,
  env: childEnv,
  stdio: 'inherit',
});

const electronProcess = spawn(process.execPath, [electronScript], {
  cwd: repoRoot,
  env: childEnv,
  stdio: 'inherit',
});

let shuttingDown = false;

function terminateChildren(signal = 'SIGTERM') {
  if (shuttingDown) {
    return;
  }

  shuttingDown = true;
  if (!viteProcess.killed) {
    viteProcess.kill(signal);
  }
  if (!electronProcess.killed) {
    electronProcess.kill(signal);
  }
}

function handleChildExit(name, otherProcess, code, signal) {
  if (!otherProcess.killed) {
    otherProcess.kill('SIGTERM');
  }

  if (signal) {
    console.error(`[dev:desktop] ${name} exited with signal ${signal}`);
    process.exit(1);
    return;
  }

  process.exit(code ?? 0);
}

process.on('SIGINT', () => {
  terminateChildren('SIGINT');
  process.exit(130);
});
process.on('SIGTERM', () => {
  terminateChildren('SIGTERM');
  process.exit(143);
});

viteProcess.on('exit', (code, signal) => handleChildExit('renderer', electronProcess, code, signal));
electronProcess.on('exit', (code, signal) => handleChildExit('electron', viteProcess, code, signal));
