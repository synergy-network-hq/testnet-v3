import net from 'node:net';

export const DEFAULT_RENDERER_PORT = 1420;
const DEFAULT_HOST = '127.0.0.1';

export function parseRendererPort(value) {
  if (value == null || value === '') {
    return null;
  }

  const parsed = Number.parseInt(String(value), 10);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) {
    throw new Error(`Invalid SYNERGY_RENDERER_PORT value: ${value}`);
  }

  return parsed;
}

export function getRendererPortFromEnv(env = process.env) {
  return parseRendererPort(env.SYNERGY_RENDERER_PORT) ?? DEFAULT_RENDERER_PORT;
}

export async function isPortAvailable(port, host = DEFAULT_HOST) {
  return new Promise((resolve) => {
    const server = net.createServer();

    server.once('error', () => resolve(false));
    server.once('listening', () => {
      server.close(() => resolve(true));
    });

    server.listen(port, host);
  });
}

export async function resolveDesktopRendererPort({
  env = process.env,
  attempts = 20,
  host = DEFAULT_HOST,
} = {}) {
  const explicitPort = parseRendererPort(env.SYNERGY_RENDERER_PORT);
  if (explicitPort != null) {
    const available = await isPortAvailable(explicitPort, host);
    if (!available) {
      throw new Error(`Renderer port ${explicitPort} is already in use.`);
    }
    return explicitPort;
  }

  for (let offset = 0; offset < attempts; offset += 1) {
    const candidate = DEFAULT_RENDERER_PORT + offset;
    // Electron must know the exact renderer URL, so select the first free port here.
    if (await isPortAvailable(candidate, host)) {
      return candidate;
    }
  }

  throw new Error(
    `No free renderer port found between ${DEFAULT_RENDERER_PORT} and ${DEFAULT_RENDERER_PORT + attempts - 1}.`,
  );
}

export async function waitForPort(
  port,
  {
    host = DEFAULT_HOST,
    timeoutMs = 60_000,
    intervalMs = 250,
  } = {},
) {
  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    const connected = await new Promise((resolve) => {
      const socket = net.connect({ port, host });

      socket.once('connect', () => {
        socket.end();
        resolve(true);
      });

      socket.once('error', () => resolve(false));
    });

    if (connected) {
      return;
    }

    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }

  throw new Error(`Timed out waiting for ${host}:${port}.`);
}
