import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { getRendererPortFromEnv, waitForPort } from './dev-port.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..', '..');
const rendererPort = getRendererPortFromEnv();
const require = createRequire(import.meta.url);
const electronBinary = require('electron');

const childEnv = {
  ...process.env,
  ELECTRON_START_URL: `http://127.0.0.1:${rendererPort}`,
};
delete childEnv.ELECTRON_RUN_AS_NODE;

try {
  await waitForPort(rendererPort);
} catch (error) {
  console.error(`[dev:electron] ${error.message}`);
  process.exit(1);
}

const electronProcess = spawn(electronBinary, ['.'], {
  cwd: repoRoot,
  env: childEnv,
  stdio: 'inherit',
});

const forwardSignal = (signal) => {
  if (!electronProcess.killed) {
    electronProcess.kill(signal);
  }
};

process.on('SIGINT', () => forwardSignal('SIGINT'));
process.on('SIGTERM', () => forwardSignal('SIGTERM'));

electronProcess.on('exit', (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code ?? 0);
});
