let cachedServiceConfigPromise = null;
let cachedEventSource = null;
let cachedEventSourceKey = '';
const SERVICE_CONFIG_RETRY_DELAY_MS = 160;
const INVOKE_RETRY_DELAYS_MS = [0, 180, 320, 520, 760];

function getBridge() {
  if (typeof window !== 'undefined' && window.synergyDesktop) {
    return window.synergyDesktop;
  }
  return null;
}

function sleep(ms) {
  return new Promise((resolve) => {
    window.setTimeout(resolve, ms);
  });
}

async function getServiceConfig() {
  if (!cachedServiceConfigPromise) {
    cachedServiceConfigPromise = (async () => {
      for (let attempt = 0; attempt < 20; attempt += 1) {
        const bridge = getBridge();
        if (bridge?.getServiceConfig) {
          const config = await bridge.getServiceConfig();
          if (config?.baseUrl && config?.token) {
            return config;
          }
        }

        await sleep(SERVICE_CONFIG_RETRY_DELAY_MS);
      }

      throw new Error('Electron desktop bridge is required for this action.');
    })();
  }

  try {
    return await cachedServiceConfigPromise;
  } catch (error) {
    cachedServiceConfigPromise = null;
    throw error;
  }
}

export async function invoke(command, args = {}) {
  const bridge = getBridge();
  if (bridge?.invokeService) {
    return bridge.invokeService(command, args);
  }

  const config = await getServiceConfig();
  let lastError = null;

  for (let index = 0; index < INVOKE_RETRY_DELAYS_MS.length; index += 1) {
    const delayMs = INVOKE_RETRY_DELAYS_MS[index];
    if (delayMs > 0) {
      await sleep(delayMs);
    }

    try {
      const response = await fetch(`${config.baseUrl}/v1/invoke`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${config.token}`,
        },
        body: JSON.stringify({
          command,
          args,
        }),
      });

      const payload = await response.json().catch(() => ({}));
      if (!response.ok || payload?.ok === false) {
        throw new Error(String(payload?.error || `Command failed: ${command}`));
      }

      return payload?.data;
    } catch (error) {
      lastError = error;
      const isNetworkError = error instanceof TypeError;
      if (!isNetworkError || index === INVOKE_RETRY_DELAYS_MS.length - 1) {
        break;
      }
    }
  }

  if (lastError instanceof TypeError) {
    throw new Error(`Control service is not reachable yet for "${command}".`);
  }

  throw lastError;
}

export async function invokeOnboarding(action, request = {}) {
  const bridge = getBridge();
  const handler = bridge?.onboarding?.[action];
  if (typeof handler !== 'function') {
    throw new Error('Electron desktop onboarding bridge is required for this action.');
  }

  const response = await handler(request);
  if (response?.ok === false) {
    const error = new Error(String(response.error || 'Onboarding failed.'));
    error.code = response.code || 'ONBOARDING_FAILED';
    error.details = response.details || null;
    throw error;
  }
  if (response?.ok === true) {
    const { ok: _ok, ...payload } = response;
    return payload;
  }
  return response;
}

export function listenOnboardingMeshProgress(handler) {
  const subscribe = getBridge()?.onboarding?.onMeshProgress;
  if (typeof subscribe !== 'function' || typeof handler !== 'function') {
    return () => {};
  }
  return subscribe(handler);
}

export async function desktopFetchJson(url, options = {}) {
  const bridge = getBridge();
  if (!bridge?.fetchJson) {
    return null;
  }
  return bridge.fetchJson(url, options);
}

function getEventSourceKey(config) {
  return `${config.baseUrl}:${config.token}`;
}

async function getEventSource() {
  const config = await getServiceConfig();
  const nextKey = getEventSourceKey(config);
  if (!cachedEventSource || cachedEventSourceKey !== nextKey) {
    if (cachedEventSource) {
      cachedEventSource.close();
    }
    cachedEventSource = new EventSource(
      `${config.baseUrl}/v1/events/stream?token=${encodeURIComponent(config.token)}`,
    );
    cachedEventSourceKey = nextKey;
  }
  return cachedEventSource;
}

export async function listen(eventName, handler) {
  const source = await getEventSource();
  const listener = (event) => {
    let payload = event.data;
    try {
      payload = JSON.parse(event.data);
    } catch {
      // Keep string payloads as-is.
    }
    handler({
      event: eventName,
      payload,
    });
  };

  source.addEventListener(eventName, listener);
  return () => {
    source.removeEventListener(eventName, listener);
  };
}

export async function fetchValidatorLiveStatus(nodeId) {
  const config = await getServiceConfig();
  const url = new URL(`${config.baseUrl}/v1/validator/live-status`);
  if (nodeId) {
    url.searchParams.set('nodeId', nodeId);
  }
  const response = await fetch(url.toString(), {
    headers: {
      Authorization: `Bearer ${config.token}`,
    },
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(String(payload?.error || 'Validator live status is unavailable.'));
  }
  return payload;
}

export async function listenValidatorLiveStatus(nodeId, handler) {
  const config = await getServiceConfig();
  const url = new URL(`${config.baseUrl}/v1/events/validator/live-status`);
  url.searchParams.set('token', config.token);
  if (nodeId) {
    url.searchParams.set('nodeId', nodeId);
  }
  const source = new EventSource(url.toString());
  const emit = (connection, payload = null) => {
    handler({ connection, payload });
  };
  const onStatus = (event) => {
    let payload = null;
    try {
      payload = JSON.parse(event.data);
    } catch {
      payload = { raw: event.data };
    }
    emit('live', payload);
  };
  const onErrorEvent = (event) => {
    let payload = { error: 'Validator live status stream error.' };
    try {
      payload = JSON.parse(event.data);
    } catch {
      // Keep the default error payload.
    }
    emit('error', payload);
  };
  source.addEventListener('validator.status.changed', onStatus);
  source.addEventListener('error', onErrorEvent);
  source.onopen = () => emit('live');
  source.onerror = () => emit('reconnecting');
  return () => {
    source.removeEventListener('validator.status.changed', onStatus);
    source.removeEventListener('error', onErrorEvent);
    source.close();
  };
}

export async function getVersion() {
  const bridge = getBridge();
  if (!bridge?.getVersion) {
    return 'unknown';
  }
  return bridge.getVersion();
}

export async function openHelpWindow() {
  const bridge = getBridge();
  if (bridge?.openHelpWindow) {
    return bridge.openHelpWindow();
  }
  if (typeof window !== 'undefined') {
    window.location.hash = '/help';
  }
  return null;
}

export async function openExternal(url) {
  const bridge = getBridge();
  if (bridge?.openExternal) {
    return bridge.openExternal(url);
  }
  window.open(url, '_blank', 'noreferrer');
  return null;
}

export async function openPath(targetPath) {
  const bridge = getBridge();
  if (bridge?.openPath) {
    return bridge.openPath(targetPath);
  }
  return null;
}

export async function showSaveDialog(options = {}) {
  const bridge = getBridge();
  if (!bridge?.showSaveDialog) {
    return null;
  }
  return bridge.showSaveDialog(options);
}

export async function showOpenDialog(options = {}) {
  const bridge = getBridge();
  if (!bridge?.showOpenDialog) {
    return null;
  }
  return bridge.showOpenDialog(options);
}

export async function fetchSeedPeerTargets(seedServers = []) {
  const bridge = getBridge();
  if (bridge?.fetchSeedPeerTargets) {
    return bridge.fetchSeedPeerTargets(seedServers);
  }

  const targets = new Set();
  const failures = [];
  const inputs = Array.isArray(seedServers) ? seedServers : [];

  await Promise.all(inputs.map(async (seedServer) => {
    const trimmed = String(seedServer || '').trim().replace(/\/+$/, '');
    if (!trimmed) {
      return;
    }

    const url = /^https?:\/\//i.test(trimmed)
      ? (trimmed.includes('/peer-list.json') ? trimmed : `${trimmed}/peer-list.json`)
      : `http://${trimmed}/peer-list.json`;

    try {
      const response = await fetch(url);
      if (!response.ok) {
        failures.push(`${url}: HTTP ${response.status}`);
        return;
      }

      const payload = await response.json();
      const peers = Array.isArray(payload?.peers) ? payload.peers : [];
      peers.forEach((peer) => {
        if (typeof peer === 'string' && peer.trim()) {
          targets.add(peer.trim());
        }
      });
    } catch (error) {
      failures.push(`${url}: ${error?.message || String(error)}`);
    }
  }));

  return {
    targets: Array.from(targets).sort(),
    failures,
  };
}

export async function checkPublicEndpointReachability(endpoint) {
  const bridge = getBridge();
  if (!bridge?.checkPublicEndpointReachability) {
    throw new Error('Public endpoint reachability checks require the desktop runtime.');
  }
  return bridge.checkPublicEndpointReachability(endpoint);
}

async function postSeedPeerRequest(methodName, seedServers = [], payload = {}) {
  const bridge = getBridge();
  const method = bridge?.[methodName];
  if (typeof method === 'function') {
    return method({ seedServers, payload });
  }

  const pathName = methodName === 'heartbeatSeedPeer' ? '/heartbeat' : '/register';
  const results = [];
  await Promise.all((Array.isArray(seedServers) ? seedServers : []).map(async (seedServer) => {
    const trimmed = String(seedServer || '').trim().replace(/\/+$/, '');
    if (!trimmed) return;
    const url = /^https?:\/\//i.test(trimmed) ? `${trimmed}${pathName}` : `http://${trimmed}${pathName}`;
    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      results.push({
        seedServer,
        url,
        ok: response.ok,
        status: response.status,
        payload: await response.json().catch(() => ({})),
      });
    } catch (error) {
      results.push({
        seedServer,
        url,
        ok: false,
        status: 0,
        error: error?.message || String(error),
      });
    }
  }));
  return results.sort((left, right) => String(left.url).localeCompare(String(right.url)));
}

export async function registerSeedPeer(seedServers = [], payload = {}) {
  return postSeedPeerRequest('registerSeedPeer', seedServers, payload);
}

export async function heartbeatSeedPeer(seedServers = [], payload = {}) {
  return postSeedPeerRequest('heartbeatSeedPeer', seedServers, payload);
}

export async function readTextFile(path) {
  const bridge = getBridge();
  if (!bridge?.readTextFile) {
    throw new Error('File reading requires the desktop runtime.');
  }
  return bridge.readTextFile(path);
}

export async function writeTextFile(path, contents) {
  const bridge = getBridge();
  if (!bridge?.writeTextFile) {
    throw new Error('File writing requires the desktop runtime.');
  }
  return bridge.writeTextFile(path, contents);
}

export async function relaunchApp() {
  const bridge = getBridge();
  if (!bridge?.relaunch) {
    return null;
  }
  return bridge.relaunch();
}

export async function openTerminalSession(options = {}) {
  const bridge = getBridge();
  if (!bridge?.openTerminalSession) {
    throw new Error('Terminal sessions require the desktop runtime.');
  }
  return bridge.openTerminalSession(options);
}

export async function writeTerminalInput(sessionId, input) {
  const bridge = getBridge();
  if (!bridge?.writeTerminalInput) {
    throw new Error('Terminal sessions require the desktop runtime.');
  }
  return bridge.writeTerminalInput(sessionId, input);
}

export async function writeAllowlistedOperation(sessionId, actionId) {
  const bridge = getBridge();
  if (!bridge?.writeAllowlistedOperation) {
    throw new Error('Allowlisted Operations PTY bridge requires the desktop runtime.');
  }
  return bridge.writeAllowlistedOperation(sessionId, actionId);
}

export async function appendTerminalOutput(sessionId, output) {
  const bridge = getBridge();
  if (!bridge?.appendTerminalOutput) {
    throw new Error('Terminal sessions require the desktop runtime.');
  }
  return bridge.appendTerminalOutput(sessionId, output);
}

export async function clearTerminalOutput(sessionId) {
  const bridge = getBridge();
  if (!bridge?.clearTerminalOutput) {
    throw new Error('Terminal sessions require the desktop runtime.');
  }
  return bridge.clearTerminalOutput(sessionId);
}

export async function readClipboardText() {
  const bridge = getBridge();
  if (!bridge?.readClipboardText) {
    throw new Error('Clipboard access requires the desktop runtime.');
  }
  return bridge.readClipboardText();
}

export async function resizeTerminal(sessionId, cols, rows) {
  const bridge = getBridge();
  if (!bridge?.resizeTerminal) {
    throw new Error('Terminal sessions require the desktop runtime.');
  }
  return bridge.resizeTerminal(sessionId, cols, rows);
}

export async function interruptTerminalSession(sessionId) {
  const bridge = getBridge();
  if (!bridge?.interruptTerminalSession) {
    throw new Error('Terminal sessions require the desktop runtime.');
  }
  return bridge.interruptTerminalSession(sessionId);
}

export async function closeTerminalSession(sessionId) {
  const bridge = getBridge();
  if (!bridge?.closeTerminalSession) {
    throw new Error('Terminal sessions require the desktop runtime.');
  }
  return bridge.closeTerminalSession(sessionId);
}

export async function getTerminalSession(sessionId) {
  const bridge = getBridge();
  if (!bridge?.getTerminalSession) {
    return null;
  }
  return bridge.getTerminalSession(sessionId);
}

export async function listTerminalSessions() {
  const bridge = getBridge();
  if (!bridge?.listTerminalSessions) {
    return [];
  }
  return bridge.listTerminalSessions();
}

export function onTerminalOutput(callback) {
  const bridge = getBridge();
  if (!bridge?.onTerminalOutput) {
    return () => {};
  }
  return bridge.onTerminalOutput(callback);
}

export function onTerminalExit(callback) {
  const bridge = getBridge();
  if (!bridge?.onTerminalExit) {
    return () => {};
  }
  return bridge.onTerminalExit(callback);
}

export function onTerminalAudit(callback) {
  const bridge = getBridge();
  if (!bridge?.onTerminalAudit) {
    return () => {};
  }
  return bridge.onTerminalAudit(callback);
}

export async function resolvePeerTopology(input = {}) {
  const bridge = getBridge();
  if (!bridge?.resolvePeerTopology) {
    return {
      localNode: null,
      points: [],
      regionSummary: [],
      routes: [],
      resolvedAt: Date.now(),
    };
  }
  return bridge.resolvePeerTopology(input);
}
