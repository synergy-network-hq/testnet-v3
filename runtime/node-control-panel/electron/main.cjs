const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const { existsSync, readFileSync } = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { app, BrowserWindow, Notification, clipboard, dialog, ipcMain, nativeImage, safeStorage, shell } = require('electron');
const { autoUpdater } = require('electron-updater');
const { createPtyManager } = require('./pty-manager.cjs');
const { setupTerminalIpc } = require('./ipc/terminal-ipc.cjs');
const { setupRuntimeInspectorIpc } = require('./ipc/runtime-inspector-ipc.cjs');
const { setupOnboardingIpc } = require('./ipc/onboarding-ipc.cjs');
const { macDmgReleaseUrl, normalizeReleaseVersion, usesNativeInstaller } = require('./updater-policy.cjs');
const repoRoot = path.resolve(__dirname, '..');
const appIconPngPath = path.join(repoRoot, 'control-service', 'icons', 'icon.png');

// Electron GPU-process instability on some macOS hosts can leave a live window
// with no rendered surface. This operator UI does not require GPU acceleration.
if (process.platform === 'darwin') app.disableHardwareAcceleration();

let mainWindow = null;
let helpWindow = null;
let controlServiceProcess = null;
let controlServiceConfig = null;
let availableUpdateVersion = null;
const SERVICE_INVOKE_RETRY_DELAYS_MS = [0, 160, 320, 560];
const DESKTOP_FETCH_ALLOWED_ORIGINS = new Set(['https://relay.synergy-network.io']);
const DESKTOP_FETCH_ALLOWED_PATH_PREFIXES = ['/api/wallet-pairing/'];
const terminalManager = createPtyManager({
  onOutput(payload) {
    sendTerminalEvent('terminal:output', payload);
  },
  onExit(payload) {
    sendTerminalEvent('terminal:exit', payload);
  },
  onAudit(payload) {
    sendTerminalEvent('terminal:audit', payload);
  },
});

function sendTerminalEvent(channel, payload) {
  const ownerId = payload?.ownerId;
  const target = BrowserWindow.getAllWindows().find(
    (window) => ownerId == null || window.webContents.id === ownerId,
  );
  if (!target) return;
  const { ownerId: _ownerId, ...publicPayload } = payload || {};
  target.webContents.send(channel, publicPayload);
}

function getRendererEntry(hash = '/') {
  if (process.env.ELECTRON_START_URL) {
    const url = new URL(process.env.ELECTRON_START_URL);
    url.hash = hash;
    return url.toString();
  }
  return null;
}

function getRendererIndexPath() {
  return path.join(repoRoot, 'dist', 'index.html');
}

async function findAvailablePort(startPort = 47891, attempts = 20) {
  for (let offset = 0; offset < attempts; offset += 1) {
    const port = startPort + offset;
    const available = await new Promise((resolve) => {
      const server = net.createServer();
      server.once('error', () => resolve(false));
      server.once('listening', () => {
        server.close(() => resolve(true));
      });
      server.listen(port, '127.0.0.1');
    });
    if (available) {
      return port;
    }
  }

  throw new Error(`No available control-service port found starting at ${startPort}.`);
}

function getServiceEnv() {
  const resourceRoot = app.isPackaged ? process.resourcesPath : repoRoot;
  const verifierSuffix = process.platform === 'darwin'
    ? 'darwin-arm64'
    : process.platform === 'linux'
      ? 'linux-amd64'
      : null;
  const verifierPath = verifierSuffix
    ? path.join(resourceRoot, 'binaries', `synergy-aegis-${verifierSuffix}${process.platform === 'win32' ? '.exe' : ''}`)
    : null;
  const env = {
    ...process.env,
    SYNERGY_RESOURCE_ROOT: resourceRoot,
    SYNERGY_APP_DATA_DIR: app.getPath('userData'),
  };
  const coordinatorUrl = bundledCoordinatorUrl(resourceRoot);
  if (coordinatorUrl && !env.SYNERGY_COORDINATOR_API_URL) {
    // Electron onboarding uses this value directly while the Rust service
    // reads the same packaged env file through AppContext.
    env.SYNERGY_COORDINATOR_API_URL = coordinatorUrl;
    process.env.SYNERGY_COORDINATOR_API_URL = coordinatorUrl;
  }
  const innernetPublicKey = bundledInnernetPublicKey(resourceRoot);
  if (innernetPublicKey && !env.SYNERGY_INNERNET_COORDINATOR_PUBLIC_KEY) {
    env.SYNERGY_INNERNET_COORDINATOR_PUBLIC_KEY = innernetPublicKey;
    process.env.SYNERGY_INNERNET_COORDINATOR_PUBLIC_KEY = innernetPublicKey;
  }
  if (verifierPath && existsSync(verifierPath)) {
    env.SYNERGY_AEGIS_CLI = verifierPath;
  }
  const archiveSignerSha256 = bundledArchiveSignerSha256(resourceRoot);
  if (archiveSignerSha256 && !env.SYNERGY_AEGIS_ARCHIVE_SIGNER_SHA256) {
    env.SYNERGY_AEGIS_ARCHIVE_SIGNER_SHA256 = archiveSignerSha256;
  }
  return env;
}

function bundledCoordinatorUrl(resourceRoot) {
  const configured = String(
    process.env.SYNERGY_COORDINATOR_API_URL
      || process.env.SYNERGY_INNERNET_COORDINATOR_URL
      || process.env.SYNERGY_VALIDATOR_VPN_COORDINATOR_URL
      || '',
  ).trim();
  if (configured) return configured;
  const envPath = path.join(resourceRoot, 'testnet', 'runtime', 'validator-vpn', 'validator-vpn-coordinator.env');
  try {
    const raw = readFileSync(envPath, 'utf8');
    const match = raw.match(/^SYNERGY_VALIDATOR_VPN_COORDINATOR_URL\s*=\s*(.+)$/m);
    return String(match?.[1] || '').trim().replace(/^['"]|['"]$/g, '') || null;
  } catch {
    return null;
  }
}

function bundledInnernetPublicKey(resourceRoot) {
  const configured = String(process.env.SYNERGY_INNERNET_COORDINATOR_PUBLIC_KEY || '').trim();
  if (configured) return configured;
  const envPath = path.join(resourceRoot, 'testnet', 'runtime', 'validator-vpn', 'validator-vpn-coordinator.env');
  try {
    const raw = readFileSync(envPath, 'utf8');
    const match = raw.match(/^SYNERGY_INNERNET_COORDINATOR_PUBLIC_KEY\s*=\s*(.+)$/m);
    return String(match?.[1] || '').trim().replace(/^['"]|['"]$/g, '') || null;
  } catch {
    return null;
  }
}

function bundledArchiveSignerSha256(resourceRoot) {
  const configured = String(process.env.SYNERGY_AEGIS_ARCHIVE_SIGNER_SHA256 || '').trim().toLowerCase();
  if (/^[0-9a-f]{64}$/.test(configured)) return configured;
  const authorityPath = path.join(
    resourceRoot,
    'testnet',
    'runtime',
    'configs',
    'archive-snapshot-authority.json',
  );
  try {
    const authority = JSON.parse(readFileSync(authorityPath, 'utf8'));
    const fingerprint = String(authority?.signer_public_key_sha256 || '').trim().toLowerCase();
    return /^[0-9a-f]{64}$/.test(fingerprint) ? fingerprint : null;
  } catch {
    return null;
  }
}

function getSettingsPath() {
  return path.join(app.getPath('userData'), 'control-panel-settings.json');
}

function defaultControlPanelSettings() {
  const userData = app.getPath('userData');
  return {
    autoStartNode: false,
    checkUpdatesAutomatically: true,
    desktopNotifications: true,
    darkTheme: true,
    language: 'English',
    alertEmail: '',
    webhookUrl: '',
    criticalAlerts: true,
    dailySummary: false,
    encryptedStorage: safeStorage.isEncryptionAvailable(),
    passwordLock: false,
    sessionTimeout: '15 minutes',
    snapshotLocation: path.join(userData, 'snapshots'),
    logDirectory: '',
    dataDirectory: '',
    logRetention: '30 days',
    lockPasswordHash: '',
    lockPasswordSalt: '',
  };
}

function encryptSettingValue(value) {
  const text = String(value || '');
  if (!text) {
    return '';
  }
  if (!safeStorage.isEncryptionAvailable()) {
    throw new Error('Electron safe storage is not available on this machine.');
  }
  return safeStorage.encryptString(text).toString('base64');
}

function decryptSettingValue(value) {
  const text = String(value || '');
  if (!text) {
    return '';
  }
  if (!safeStorage.isEncryptionAvailable()) {
    return '';
  }
  try {
    return safeStorage.decryptString(Buffer.from(text, 'base64'));
  } catch {
    return '';
  }
}

function normalizeControlPanelSettings(raw = {}) {
  const defaults = defaultControlPanelSettings();
  const merged = { ...defaults, ...(raw || {}) };
  if (raw?.encryptedStorage && raw?.encryptedSecrets) {
    merged.alertEmail = decryptSettingValue(raw.encryptedSecrets.alertEmail);
    merged.webhookUrl = decryptSettingValue(raw.encryptedSecrets.webhookUrl);
  }
  return {
    ...merged,
    autoStartNode: merged.autoStartNode === true,
    checkUpdatesAutomatically: merged.checkUpdatesAutomatically !== false,
    desktopNotifications: merged.desktopNotifications !== false,
    darkTheme: merged.darkTheme !== false,
    language: merged.language === 'English' ? 'English' : 'English',
    criticalAlerts: merged.criticalAlerts !== false,
    dailySummary: merged.dailySummary === true,
    encryptedStorage: merged.encryptedStorage === true,
    passwordLock: merged.passwordLock === true,
    sessionTimeout: ['15 minutes', '30 minutes'].includes(merged.sessionTimeout)
      ? merged.sessionTimeout
      : defaults.sessionTimeout,
    logRetention: ['30 days', '90 days'].includes(merged.logRetention)
      ? merged.logRetention
      : defaults.logRetention,
    snapshotLocation: String(merged.snapshotLocation || defaults.snapshotLocation),
    logDirectory: String(merged.logDirectory || ''),
    dataDirectory: String(merged.dataDirectory || ''),
    alertEmail: String(merged.alertEmail || ''),
    webhookUrl: String(merged.webhookUrl || ''),
    lockPasswordHash: String(merged.lockPasswordHash || ''),
    lockPasswordSalt: String(merged.lockPasswordSalt || ''),
  };
}

function serializeControlPanelSettings(settings) {
  const normalized = normalizeControlPanelSettings(settings);
  const output = { ...normalized };
  if (normalized.encryptedStorage) {
    output.encryptedSecrets = {
      alertEmail: encryptSettingValue(normalized.alertEmail),
      webhookUrl: encryptSettingValue(normalized.webhookUrl),
    };
    output.alertEmail = '';
    output.webhookUrl = '';
  } else {
    delete output.encryptedSecrets;
  }
  return output;
}

async function readControlPanelSettings() {
  try {
    const raw = await fs.readFile(getSettingsPath(), 'utf8');
    return normalizeControlPanelSettings(JSON.parse(raw));
  } catch (error) {
    if (error?.code !== 'ENOENT') {
      console.error(`[settings] failed to read settings: ${error?.message || error}`);
    }
    const defaults = defaultControlPanelSettings();
    await writeControlPanelSettings(defaults);
    return defaults;
  }
}

async function writeControlPanelSettings(nextSettings) {
  const normalized = normalizeControlPanelSettings(nextSettings);
  const pathName = getSettingsPath();
  await fs.mkdir(path.dirname(pathName), { recursive: true });
  await fs.writeFile(pathName, JSON.stringify(serializeControlPanelSettings(normalized), null, 2), 'utf8');
  return normalized;
}

async function updateControlPanelSettings(patch = {}) {
  const current = await readControlPanelSettings();
  return writeControlPanelSettings({ ...current, ...(patch || {}) });
}

function showNativeNotification(options = {}) {
  if (!Notification.isSupported()) {
    throw new Error('Desktop notifications are not supported on this platform.');
  }
  const notification = new Notification({
    title: String(options.title || 'Synergy Node Control Panel'),
    body: String(options.body || 'Notification test completed.'),
    silent: options.silent === true,
  });
  notification.show();
  return { shown: true };
}

function getPackagedServiceBinaryPath() {
  const executable = process.platform === 'win32' ? 'control-service.exe' : 'control-service';
  return path.join(process.resourcesPath, 'control-service', executable);
}

function getDevServiceBinaryPath() {
  const executable = process.platform === 'win32' ? 'control-service.exe' : 'control-service';
  const cargoReleaseBinary = path.join(repoRoot, 'control-service', 'target', 'release', executable);
  if (existsSync(cargoReleaseBinary)) {
    return cargoReleaseBinary;
  }

  const stagedBinary = path.join(repoRoot, 'build', 'electron-runtime', 'control-service', executable);
  if (existsSync(stagedBinary)) {
    return stagedBinary;
  }

  return null;
}

function attachProcessLogging(child) {
  child.stdout?.on('data', (chunk) => {
    process.stdout.write(`[control-service] ${chunk}`);
  });
  child.stderr?.on('data', (chunk) => {
    process.stderr.write(`[control-service] ${chunk}`);
  });
  child.on('exit', (code, signal) => {
    console.error(`control-service exited with code=${code} signal=${signal}`);
  });
}

function sleep(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function normalizeSeedPeerListUrl(seedServer) {
  if (typeof seedServer !== 'string') {
    return null;
  }

  const trimmed = seedServer.trim().replace(/\/+$/, '');
  if (!trimmed) {
    return null;
  }

  if (/^https?:\/\//i.test(trimmed)) {
    const [, remainder = ''] = trimmed.split('://', 2);
    return remainder.includes('/') ? trimmed : `${trimmed}/peer-list.json`;
  }

  return `http://${trimmed}/peer-list.json`;
}

function normalizeSeedApiUrl(seedServer, apiPath) {
  if (typeof seedServer !== 'string') {
    return null;
  }

  const trimmed = seedServer.trim().replace(/\/+$/, '');
  if (!trimmed) {
    return null;
  }

  const pathName = String(apiPath || '').startsWith('/') ? apiPath : `/${apiPath || ''}`;
  if (/^https?:\/\//i.test(trimmed)) {
    const url = new URL(trimmed);
    url.pathname = pathName;
    url.search = '';
    url.hash = '';
    return url.toString();
  }

  return `http://${trimmed}${pathName}`;
}

function parseHostPort(endpoint) {
  const raw = String(endpoint || '').trim().replace(/^"|"$/g, '');
  if (!raw) {
    return null;
  }

  if (/^https?:\/\//i.test(raw)) {
    try {
      const url = new URL(raw);
      if (!url.hostname || !url.port) {
        return null;
      }
      return {
        host: url.hostname,
        port: Number.parseInt(url.port, 10),
        endpoint: `${url.hostname}:${url.port}`,
      };
    } catch {
      return null;
    }
  }

  if (raw.startsWith('[')) {
    const match = raw.match(/^\[([^\]]+)\]:(\d+)$/);
    if (!match) {
      return null;
    }
    return {
      host: match[1],
      port: Number.parseInt(match[2], 10),
      endpoint: `[${match[1]}]:${match[2]}`,
    };
  }

  const separator = raw.lastIndexOf(':');
  if (separator <= 0) {
    return null;
  }

  const host = raw.slice(0, separator).trim();
  const port = Number.parseInt(raw.slice(separator + 1), 10);
  if (!host || !Number.isInteger(port) || port <= 0 || port > 65535) {
    return null;
  }
  return { host, port, endpoint: `${host}:${port}` };
}

async function checkPublicEndpointReachability(endpoint) {
  const parsed = parseHostPort(endpoint);
  if (!parsed) {
    return {
      ok: false,
      reachable: false,
      endpoint: String(endpoint || '').trim(),
      error: 'Invalid public endpoint. Expected host:port.',
    };
  }

  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;
    const finish = (payload) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({
        endpoint: parsed.endpoint,
        host: parsed.host,
        port: parsed.port,
        ...payload,
      });
    };

    socket.setTimeout(5000);
    socket.once('connect', () => finish({ ok: true, reachable: true }));
    socket.once('timeout', () => finish({ ok: false, reachable: false, error: 'Connection timed out.' }));
    socket.once('error', (error) => finish({ ok: false, reachable: false, error: error?.message || String(error) }));
    socket.connect(parsed.port, parsed.host);
  });
}

async function postSeedJsonToServers(seedServers = [], apiPath, payload = {}) {
  const results = [];
  const inputs = Array.isArray(seedServers) ? seedServers : [];
  await Promise.all(inputs.map(async (seedServer) => {
    const url = normalizeSeedApiUrl(seedServer, apiPath);
    if (!url) {
      return;
    }

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(5000),
      });
      const responsePayload = await response.json().catch(() => ({}));
      results.push({
        seedServer,
        url,
        ok: response.ok,
        status: response.status,
        payload: responsePayload,
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

async function fetchSeedPeerTargets(seedServers = []) {
  const targets = new Set();
  const failures = [];
  const inputs = Array.isArray(seedServers) ? seedServers : [];

  await Promise.all(inputs.map(async (seedServer) => {
    const url = normalizeSeedPeerListUrl(seedServer);
    if (!url) {
      return;
    }

    try {
      const response = await fetch(url, {
        signal: AbortSignal.timeout(4000),
      });
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

async function invokeControlService(command, args = {}) {
  if (!controlServiceConfig?.baseUrl || !controlServiceConfig?.token) {
    throw new Error('control-service is not configured.');
  }

  let lastError = null;

  for (const delayMs of SERVICE_INVOKE_RETRY_DELAYS_MS) {
    if (delayMs > 0) {
      await sleep(delayMs);
    }

    try {
      const response = await fetch(`${controlServiceConfig.baseUrl}/v1/invoke`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${controlServiceConfig.token}`,
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
    }
  }

  throw lastError || new Error(`Command failed: ${command}`);
}

function safeDesktopFetchHeaders(headers = {}) {
  const safeHeaders = {};
  Object.entries(headers || {}).forEach(([key, value]) => {
    const normalized = String(key || '').toLowerCase();
    if (normalized === 'content-type' || normalized === 'accept') {
      safeHeaders[key] = String(value);
    }
  });
  return safeHeaders;
}

async function desktopFetchJson({ url, options = {} } = {}) {
  const parsedUrl = new URL(String(url || ''));
  if (!DESKTOP_FETCH_ALLOWED_ORIGINS.has(parsedUrl.origin)) {
    throw new Error('Desktop fetch origin is not allowed.');
  }
  if (!DESKTOP_FETCH_ALLOWED_PATH_PREFIXES.some((prefix) => parsedUrl.pathname.startsWith(prefix))) {
    throw new Error('Desktop fetch path is not allowed.');
  }

  const method = String(options.method || 'GET').toUpperCase();
  if (!['GET', 'POST', 'OPTIONS'].includes(method)) {
    throw new Error(`Desktop fetch method is not allowed: ${method}`);
  }

  const request = {
    method,
    headers: safeDesktopFetchHeaders(options.headers),
    signal: AbortSignal.timeout(15000),
  };
  if (method !== 'GET' && options.body != null) {
    request.body = typeof options.body === 'string' ? options.body : JSON.stringify(options.body);
  }

  const response = await fetch(parsedUrl.toString(), request);
  const text = await response.text();
  let body = null;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = { message: text };
    }
  }

  return {
    ok: response.ok,
    status: response.status,
    statusText: response.statusText,
    body,
  };
}

async function startControlService() {
  const port = await findAvailablePort();
  const token = crypto.randomBytes(24).toString('hex');
  const env = getServiceEnv();

  if (app.isPackaged) {
    console.log(`[control-service] starting packaged binary: ${getPackagedServiceBinaryPath()}`);
    controlServiceProcess = spawn(
      getPackagedServiceBinaryPath(),
      ['--port', String(port), '--token', token],
      {
        cwd: process.resourcesPath,
        env,
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    );
  } else {
    const devBinary = getDevServiceBinaryPath();
    if (devBinary) {
      console.log(`[control-service] starting dev binary: ${devBinary}`);
      controlServiceProcess = spawn(devBinary, ['--port', String(port), '--token', token], {
        cwd: repoRoot,
        env,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } else {
      console.log('[control-service] no dev binary found, falling back to cargo run');
      controlServiceProcess = spawn(
        'cargo',
        [
          'run',
          '--manifest-path',
          path.join(repoRoot, 'control-service', 'Cargo.toml'),
          '--bin',
          'control-service',
          '--',
          '--port',
          String(port),
          '--token',
          token,
        ],
        {
          cwd: repoRoot,
          env,
          stdio: ['ignore', 'pipe', 'pipe'],
        },
      );
    }
  }

  attachProcessLogging(controlServiceProcess);
  controlServiceConfig = {
    baseUrl: `http://127.0.0.1:${port}`,
    token,
  };

  for (let attempt = 0; attempt < 120; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 250));
    try {
      const response = await fetch(`${controlServiceConfig.baseUrl}/health`);
      if (response.ok) {
        return;
      }
    } catch {
      // Retry until health succeeds.
    }
  }

  throw new Error('control-service failed to become healthy.');
}

async function createWindow(hash = '/') {
  let rendererRecoveryAttempted = false;
  const window = new BrowserWindow({
    title: 'Synergy Node Control Panel',
    width: 1280,
    height: 900,
    minWidth: 960,
    minHeight: 680,
    show: false,
    center: true,
    autoHideMenuBar: true,
    frame: true,
    backgroundColor: '#031019',
    icon: appIconPngPath,
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      preload: path.join(__dirname, 'preload.cjs'),
    },
  });

  window.once('ready-to-show', () => {
    window.show();
  });

  window.webContents.on('did-fail-load', (_event, errorCode, errorDescription, validatedURL) => {
    console.error(`renderer failed to load (${errorCode}): ${errorDescription} -> ${validatedURL}`);
  });
  window.webContents.on('did-finish-load', () => {
    rendererRecoveryAttempted = false;
  });
  window.webContents.on('render-process-gone', (_event, details) => {
    console.error(`renderer process ended: ${details?.reason || 'unknown'} (${details?.exitCode ?? 'unknown'})`);
    if (rendererRecoveryAttempted || window.isDestroyed() || details?.reason === 'clean-exit') return;
    rendererRecoveryAttempted = true;
    setTimeout(() => {
      if (!window.isDestroyed()) window.webContents.reload();
    }, 250);
  });
  window.on('unresponsive', () => {
    console.error('renderer became unresponsive');
    if (rendererRecoveryAttempted || window.isDestroyed()) return;
    rendererRecoveryAttempted = true;
    window.webContents.forcefullyCrashRenderer();
    setTimeout(() => {
      if (!window.isDestroyed()) window.webContents.reload();
    }, 250);
  });

  const rendererEntry = getRendererEntry(hash);
  if (rendererEntry) {
    await window.loadURL(rendererEntry);
  } else {
    await window.loadFile(getRendererIndexPath(), { hash });
  }
  return window;
}

async function createMainWindow() {
  mainWindow = await createWindow('/');
}

async function openHelpWindow() {
  if (helpWindow && !helpWindow.isDestroyed()) {
    helpWindow.focus();
    return;
  }

  helpWindow = await createWindow('/help');
  helpWindow.on('closed', () => {
    helpWindow = null;
  });
}

function setupAutoUpdater() {
  const nativeInstallerEnabled = usesNativeInstaller(process.platform);
  autoUpdater.autoDownload = nativeInstallerEnabled;
  autoUpdater.autoInstallOnAppQuit = nativeInstallerEnabled;
  autoUpdater.allowDowngrade = false;

  // Ensure the updater knows where to look for releases
  autoUpdater.setFeedURL({
    provider: 'github',
    owner: 'synergy-network-hq',
    repo: 'synergy-node-control-panel-releases',
  });

  console.log('[auto-updater] configured: github provider -> synergy-network-hq/synergy-node-control-panel-releases');

  autoUpdater.on('update-available', (info) => {
    console.log(`[auto-updater] update available: ${info.version}`);
    availableUpdateVersion = normalizeReleaseVersion(info.version);

    if (mainWindow) {
      mainWindow.webContents.send('updater:update-available', {
        version: info.version,
        releaseDate: info.releaseDate,
      });
    }
  });

  autoUpdater.on('update-not-available', (info) => {
    console.log(`[auto-updater] no update available (current: ${app.getVersion()})`);
    availableUpdateVersion = null;
    if (mainWindow) {
      mainWindow.webContents.send('updater:update-not-available');
    }
  });

  autoUpdater.on('download-progress', (progress) => {
    if (mainWindow) {
      mainWindow.webContents.send('updater:download-progress', {
        percent: progress.percent,
        transferred: progress.transferred,
        total: progress.total,
      });
    }
  });

  autoUpdater.on('update-downloaded', (info) => {
    console.log(`[auto-updater] update downloaded: ${info.version}`);
    if (mainWindow) {
      mainWindow.webContents.send('updater:update-downloaded', {
        version: info.version,
      });
    }
  });

  autoUpdater.on('error', (error) => {
    console.error(`[auto-updater] error: ${error?.message || error}`);
    if (mainWindow) {
      mainWindow.webContents.send('updater:error', {
        message: error?.message || 'Unknown update error',
      });
    }
  });
}

function setupIpc() {
  ipcMain.handle('desktop:get-version', () => app.getVersion());
  ipcMain.handle('desktop:get-service-config', () => controlServiceConfig);
  ipcMain.handle('desktop:invoke-service', async (_event, request = {}) =>
    invokeControlService(request.command, request.args || {}),
  );
  ipcMain.handle('desktop:fetch-json', async (_event, request = {}) =>
    desktopFetchJson(request),
  );
  ipcMain.handle('desktop:open-help-window', () => openHelpWindow());
  ipcMain.handle('desktop:open-external', (_event, url) => shell.openExternal(url));
  ipcMain.handle('desktop:open-path', (_event, targetPath) => shell.openPath(targetPath));
  ipcMain.handle('desktop:get-control-panel-settings', () => readControlPanelSettings());
  ipcMain.handle('desktop:update-control-panel-settings', (_event, patch = {}) =>
    updateControlPanelSettings(patch),
  );
  ipcMain.handle('desktop:show-notification', async (_event, options = {}) => {
    const settings = await readControlPanelSettings();
    if (!settings.desktopNotifications) {
      return { shown: false, reason: 'Desktop notifications are disabled.' };
    }
    return showNativeNotification(options);
  });
  ipcMain.handle('desktop:show-save-dialog', async (_event, options) => {
    const result = await dialog.showSaveDialog(mainWindow, options);
    return result.canceled ? null : result.filePath;
  });
  ipcMain.handle('desktop:show-open-dialog', async (_event, options) => {
    const result = await dialog.showOpenDialog(mainWindow, options);
    if (result.canceled || !Array.isArray(result.filePaths) || result.filePaths.length === 0) {
      return null;
    }
    return result.filePaths[0];
  });
  ipcMain.handle('desktop:fetch-seed-peer-targets', async (_event, seedServers) =>
    fetchSeedPeerTargets(seedServers),
  );
  ipcMain.handle('desktop:check-public-endpoint-reachability', async (_event, endpoint) =>
    checkPublicEndpointReachability(endpoint),
  );
  ipcMain.handle('desktop:register-seed-peer', async (_event, request = {}) =>
    postSeedJsonToServers(request.seedServers || [], '/register', request.payload || {}),
  );
  ipcMain.handle('desktop:heartbeat-seed-peer', async (_event, request = {}) =>
    postSeedJsonToServers(request.seedServers || [], '/heartbeat', request.payload || {}),
  );
  ipcMain.handle('desktop:read-text-file', async (_event, filePath) =>
    fs.readFile(filePath, 'utf8'),
  );
  ipcMain.handle('desktop:write-text-file', async (_event, { path: filePath, contents }) => {
    await fs.writeFile(filePath, contents, 'utf8');
    return true;
  });
  ipcMain.handle('desktop:relaunch', () => {
    app.relaunch();
    app.exit(0);
  });
  ipcMain.handle('desktop:read-clipboard-text', () => clipboard.readText());

  // Auto-update IPC
  ipcMain.handle('desktop:check-for-update', async () => {
    console.log('[auto-updater] check-for-update requested by renderer');
    try {
      return await autoUpdater.checkForUpdates();
    } catch (error) {
      console.error(`[auto-updater] checkForUpdates failed: ${error.message}`);
      throw error;
    }
  });
  ipcMain.handle('desktop:download-update', async (_event, request = {}) => {
    console.log('[auto-updater] download-update requested by renderer');
    try {
      if (!usesNativeInstaller(process.platform)) {
        const version = normalizeReleaseVersion(request.version) || availableUpdateVersion;
        const url = macDmgReleaseUrl(version, process.arch);
        await shell.openExternal(url);
        return { manualInstall: true, version, url };
      }
      return await autoUpdater.downloadUpdate();
    } catch (error) {
      console.error(`[auto-updater] downloadUpdate failed: ${error.message}`);
      throw error;
    }
  });
  ipcMain.handle('desktop:install-update', async (_event, request = {}) => {
    if (!usesNativeInstaller(process.platform)) {
      const version = normalizeReleaseVersion(request.version) || availableUpdateVersion;
      const url = macDmgReleaseUrl(version, process.arch);
      await shell.openExternal(url);
      return { manualInstall: true, version, url };
    }
    console.log('[auto-updater] install-update (quitAndInstall) requested by renderer');
    autoUpdater.quitAndInstall(false, true);
    return { manualInstall: false };
  });

  setupTerminalIpc(ipcMain, terminalManager);
  setupRuntimeInspectorIpc(ipcMain);
  setupOnboardingIpc(ipcMain, { invokeControlService, userDataPath: app.getPath('userData') });
}

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('before-quit', () => {
  terminalManager.closeAllSessions();
  if (controlServiceProcess) {
    controlServiceProcess.kill();
    controlServiceProcess = null;
  }
});

app.whenReady().then(async () => {
  if (process.platform === 'darwin' && existsSync(appIconPngPath)) {
    app.dock.setIcon(nativeImage.createFromPath(appIconPngPath));
  }

  await startControlService();
  setupAutoUpdater();
  setupIpc();
  await createMainWindow();

  // Proactively check for updates ~10 s after launch so the renderer is
  // fully loaded before the network round-trip is made.  Only runs in
  // packaged builds; dev mode has no published release to check against.
  const launchSettings = await readControlPanelSettings();
  if (app.isPackaged && launchSettings.checkUpdatesAutomatically) {
    setTimeout(() => {
      autoUpdater.checkForUpdates().catch((error) => {
        console.error(`[auto-updater] background check failed: ${error?.message || error}`);
      });
    }, 10_000);
  }

  app.on('activate', async () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      await createMainWindow();
    }
  });
}).catch((error) => {
  console.error(error);
  app.exit(1);
});
