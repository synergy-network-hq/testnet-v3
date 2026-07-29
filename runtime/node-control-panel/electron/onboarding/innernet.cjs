const crypto = require('crypto');
const fs = require('fs/promises');
const os = require('os');
const path = require('path');

function meshError(code, message, details = null) {
  const error = new Error(message);
  error.code = code;
  error.details = details;
  return error;
}

function commandFailureParts(error) {
  return [
    error?.message,
    error?.stderr,
    error?.stdout,
    error?.details?.message,
    error?.details?.detail,
    error?.details?.stderr,
    error?.details?.stdout,
    error?.details?.cause?.message,
    error?.details?.cause?.stderr,
    error?.details?.cause?.stdout,
  ].filter(Boolean);
}

function commandFailureMessage(error) {
  return commandFailureParts(error)
    .join(' ')
    .replace(/[\u0000-\u001f\u007f]+/g, ' ')
    .trim()
    .slice(-1_000);
}

function isExistingInterfaceConfigError(error) {
  const failure = commandFailureParts(error)
    .join(' ')
    .replace(/[\u0000-\u001f\u007f]+/g, ' ');
  return /config file for innernet interface\s+[^\s]+\s+already exists/i.test(failure);
}

function isResumableInnernetInstallError(error) {
  if (isExistingInterfaceConfigError(error)) return true;
  const failure = commandFailureParts(error)
    .join(' ')
    .replace(/[\u0000-\u001f\u007f]+/g, ' ');
  return /unique constraint failed:\s*peers\.ip/i.test(failure);
}

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const DEFAULT_HANDSHAKE_TIMEOUT_MS = 120_000;
const HANDSHAKE_PROBE_INTERVAL_MS = 5_000;
const DARWIN_MESH_REPORT_PREFIX = 'SYNERGY_MESH_';

const DARWIN_MESH_INSPECTION_SCRIPT = String.raw`
set -eu
expected_ip="$1"
timeout_seconds="$2"
deadline=$(( $(date +%s) + timeout_seconds ))
last_device=""
last_dump=""
last_addresses=""

encode_report_value() {
  /usr/bin/base64 | /usr/bin/tr -d '\n'
}

print_report() {
  status="$1"
  printf 'SYNERGY_MESH_STATUS=%s\n' "$status"
  printf 'SYNERGY_MESH_DEVICE=%s\n' "$last_device"
  printf 'SYNERGY_MESH_DUMP_B64='
  printf '%s' "$last_dump" | encode_report_value
  printf '\nSYNERGY_MESH_ADDRS_B64='
  printf '%s' "$last_addresses" | encode_report_value
  printf '\n'
}

while :; do
  interfaces="$(wg show interfaces 2>/dev/null || true)"
  for candidate in $interfaces; do
    addresses="$(/sbin/ifconfig "$candidate" 2>/dev/null || true)"
    if ! printf '%s\n' "$addresses" | /usr/bin/awk -v expected="$expected_ip" '
      $1 == "inet" && $2 == expected { found = 1 }
      END { exit found ? 0 : 1 }
    '; then
      continue
    fi

    dump="$(wg show "$candidate" dump 2>/dev/null || true)"
    last_device="$candidate"
    last_dump="$dump"
    last_addresses="$addresses"
    if printf '%s\n' "$dump" | /usr/bin/awk -F '\t' '
      NR > 1 && ($5 + 0) > 0 { found = 1 }
      END { exit found ? 0 : 1 }
    '; then
      print_report ready
      exit 0
    fi

    printf '%s\n' "$dump" | /usr/bin/awk -F '\t' '
      NR > 1 {
        count = split($4, addresses, ",")
        for (index = 1; index <= count; index += 1) {
          split(addresses[index], parts, "/")
          if (parts[1] != "") print parts[1]
        }
      }
    ' | while IFS= read -r target; do
      /sbin/ping -n -c 1 -W 1000 "$target" >/dev/null 2>&1 &
    done
    wait || true
  done

  if [ "$(date +%s)" -ge "$deadline" ]; then
    if [ -n "$last_device" ]; then
      print_report timeout
    else
      print_report missing
    fi
    exit 0
  fi
  /bin/sleep 1
done
`;

function defaultHandshakeTimeoutMs() {
  const configured = Number(process.env.SYNERGY_INNERNET_HANDSHAKE_TIMEOUT_MS);
  return Number.isFinite(configured) && configured > 0
    ? Math.floor(configured)
    : DEFAULT_HANDSHAKE_TIMEOUT_MS;
}

function innernetPlatformKey(platform = process.platform, architecture = process.arch) {
  const osName = String(platform || '').trim().toLowerCase();
  const archName = String(architecture || '').trim().toLowerCase();
  if (osName === 'darwin' && ['arm64', 'x64'].includes(archName)) return `darwin-${archName}`;
  if (osName === 'linux' && ['arm64', 'x64'].includes(archName)) return `linux-${archName === 'x64' ? 'amd64' : 'arm64'}`;
  return null;
}

function isPackagedRuntime() {
  return Boolean(process.resourcesPath && process.defaultApp !== true);
}

async function isRegularFile(filePath) {
  try {
    return (await fs.stat(filePath)).isFile();
  } catch (error) {
    if (error?.code === 'ENOENT') return false;
    throw error;
  }
}

async function resolveInnernetClientBinary({ targetPlatform = innernetPlatformKey(), resourceRoot, packaged } = {}) {
  const platform = String(targetPlatform || '').trim();
  if (!platform) {
    throw meshError('INNERNET_PLATFORM_UNSUPPORTED', 'This control-panel platform cannot run the bundled Innernet client.', { platform: process.platform, architecture: process.arch });
  }
  const isPackaged = packaged ?? isPackagedRuntime();
  if (!isPackaged) {
    const developmentOverride = String(process.env.SYNERGY_INNERNET_CLIENT_BIN || '').trim();
    if (developmentOverride) return developmentOverride;
  }
  const root = resourceRoot || (isPackaged ? process.resourcesPath : REPO_ROOT);
  const candidates = [
    root && path.join(root, 'innernet', `innernet-${platform}`),
    root && path.join(root, 'binaries', 'innernet', `innernet-${platform}`),
  ].filter(Boolean);
  for (const candidate of candidates) {
    if (await isRegularFile(candidate)) return candidate;
  }
  if (isPackaged) {
    throw meshError('INNERNET_CLIENT_NOT_BUNDLED', `This release does not include the official Innernet client for ${platform}.`, { platform });
  }
  if (platform !== innernetPlatformKey()) {
    throw meshError('INNERNET_REMOTE_CLIENT_NOT_BUNDLED', `Development fallback cannot provide the official Innernet client for remote ${platform} targets.`, { platform });
  }
  return 'innernet';
}

async function resolveWireguardQuickBinary(executor) {
  if (executor?.mode === 'remote') return 'wg-quick';
  const root = isPackagedRuntime() ? process.resourcesPath : REPO_ROOT;
  const bundled = root && path.join(root, 'innernet', 'wg-quick');
  if (bundled && await isRegularFile(bundled)) return bundled;
  return 'wg-quick';
}

async function resolveWireguardBinary(executor) {
  if (executor?.mode === 'remote') return 'wg';
  const root = isPackagedRuntime() ? process.resourcesPath : REPO_ROOT;
  const bundled = root && path.join(root, 'innernet', 'wg');
  if (bundled && await isRegularFile(bundled)) return bundled;
  return 'wg';
}

async function resolveRemoteInnernetPlatform(executor) {
  const [operatingSystem, architecture] = await Promise.all([
    executor.run('uname', ['-s']),
    executor.run('uname', ['-m']),
  ]);
  const platform = innernetPlatformKey(
    operatingSystem.stdout.trim().toLowerCase() === 'linux' ? 'linux' : operatingSystem.stdout.trim(),
    architecture.stdout.trim().toLowerCase(),
  );
  if (platform !== 'linux-amd64') {
    throw meshError('INNERNET_REMOTE_PLATFORM_UNSUPPORTED', 'Remote Innernet enrollment requires a Linux amd64 target so the packaged official client can be transferred and executed.', {
      os: operatingSystem.stdout.trim(),
      architecture: architecture.stdout.trim(),
      platform,
    });
  }
  return platform;
}

function shellQuote(value) {
  return `'${String(value).replace(/'/g, "'\\\"'\\\"'")}'`;
}

async function prepareRemoteInnernetClient(executor, sourcePath) {
  const binary = await fs.readFile(sourcePath);
  const digest = crypto.createHash('sha256').update(binary).digest('hex');
  const home = (await executor.run('sh', ['-lc', 'printf %s "$HOME"'])).stdout.trim();
  if (!path.posix.isAbsolute(home)) {
    throw meshError('INNERNET_REMOTE_HOME_INVALID', 'The remote SSH account did not return an absolute home directory for the Innernet client.');
  }
  const remoteDirectory = path.posix.join(home, '.local', 'lib', 'synergy-ncp');
  const remotePath = path.posix.join(remoteDirectory, `innernet-${digest.slice(0, 24)}`);
  await executor.run('mkdir', ['-p', '--', remoteDirectory]);
  const hashCommand = `if test -f ${shellQuote(remotePath)}; then (sha256sum -- ${shellQuote(remotePath)} 2>/dev/null || shasum -a 256 -- ${shellQuote(remotePath)}) | awk '{print $1}'; fi`;
  const remoteHash = (await executor.run('sh', ['-lc', hashCommand])).stdout.trim().toLowerCase();
  if (remoteHash !== digest) await executor.writeFile(remotePath, binary, '0700');
  const verifiedHash = (await executor.run('sh', ['-lc', `(
    sha256sum -- ${shellQuote(remotePath)} 2>/dev/null || shasum -a 256 -- ${shellQuote(remotePath)}
  ) | awk '{print $1}'`])).stdout.trim().toLowerCase();
  if (verifiedHash !== digest) {
    throw meshError('INNERNET_REMOTE_CLIENT_CHECKSUM_FAILED', 'The remote Innernet client checksum did not match the packaged official client.', { expected: digest, actual: verifiedHash });
  }
  return remotePath;
}

async function resolveAndStageRemoteInnernetClient(executor) {
  const platform = await resolveRemoteInnernetPlatform(executor);
  const sourcePath = await resolveInnernetClientBinary({ targetPlatform: platform });
  return prepareRemoteInnernetClient(executor, sourcePath);
}

function normaliseIp(value) {
  return String(value || '').trim().split('/')[0] || null;
}

async function hasExistingInterfaceConfig(executor, interfaceName) {
  if (!/^[A-Za-z0-9_-]+$/.test(String(interfaceName || ''))) {
    throw meshError('INNERNET_INTERFACE_INVALID', 'The coordinator returned an invalid Innernet interface name.');
  }
  const configPath = path.posix.join('/etc/innernet', `${interfaceName}.conf`);
  try {
    await executor.run('test', ['-f', configPath]);
    return true;
  } catch (error) {
    if (error?.code !== 'COMMAND_FAILED') throw error;
  }

  // Innernet protects /etc/innernet with root-only traversal on macOS. A
  // non-elevated `test -f` therefore cannot distinguish an absent config from
  // an existing config hidden behind directory permissions. Confirm with the
  // same administrator path that install/up will use before consuming an
  // invitation a second time.
  if (executor?.mode !== 'local' || typeof executor.runElevated !== 'function') return false;
  // Avoid a standalone macOS authorization dialog for this probe. The
  // coordinator recovery path starts the existing configuration directly.
  if (process.platform === 'darwin' && process.env.NODE_ENV !== 'test') return false;
  try {
    await executor.runElevated('test', ['-f', configPath]);
    return true;
  } catch (error) {
    if (['COMMAND_FAILED', 'ELEVATED_COMMAND_FAILED'].includes(error?.code)) return false;
    throw error;
  }
}

function renderInnernetSystemdUnit(clientCommand, interfaceName) {
  const binary = String(clientCommand || '').trim();
  const iface = String(interfaceName || '').trim();
  if (!path.posix.isAbsolute(binary) || /[\s\u0000\r\n]/.test(binary)) {
    throw meshError('INNERNET_CLIENT_PATH_INVALID', 'The persistent Innernet service requires an absolute client path.');
  }
  if (!/^[A-Za-z0-9_-]+$/.test(iface)) {
    throw meshError('INNERNET_INTERFACE_INVALID', 'The coordinator returned an invalid Innernet interface name.');
  }
  return `[Unit]\nDescription=Synergy Innernet secure transport\nWants=network-online.target\nAfter=network-online.target\nBefore=synergy-validator.service synergy-testnet-relayer.service\n\n[Service]\nType=oneshot\nExecStart=${binary} up ${iface}\nExecStop=${binary} down ${iface}\nRemainAfterExit=yes\n\n[Install]\nWantedBy=multi-user.target\n`;
}

function xmlEscape(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&apos;');
}

function renderInnernetLaunchdPlist(clientCommand, interfaceName) {
  const binary = String(clientCommand || '').trim();
  const iface = String(interfaceName || '').trim();
  if (!path.posix.isAbsolute(binary) || /[\u0000\r\n]/.test(binary)) {
    throw meshError('INNERNET_CLIENT_PATH_INVALID', 'The persistent Innernet service requires an absolute client path.');
  }
  if (!/^[A-Za-z0-9_-]+$/.test(iface)) {
    throw meshError('INNERNET_INTERFACE_INVALID', 'The coordinator returned an invalid Innernet interface name.');
  }
  const searchPath = [path.dirname(binary), '/opt/homebrew/bin', '/usr/local/bin', '/usr/bin', '/bin', '/usr/sbin', '/sbin'].join(':');
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>network.synergy.innernet</string>
  <key>ProgramArguments</key>
  <array>
    <string>${xmlEscape(binary)}</string>
    <string>up</string>
    <string>${xmlEscape(iface)}</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key>
    <string>${xmlEscape(searchPath)}</string>
  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>StartInterval</key>
  <integer>30</integer>
  <key>ProcessType</key>
  <string>Background</string>
  <key>StandardOutPath</key>
  <string>/var/log/synergy-innernet.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/synergy-innernet.err.log</string>
</dict>
</plist>
`;
}

function requiresSystemdPersistence(executor) {
  if (process.env.NODE_ENV === 'test' && process.env.SYNERGY_NCP_TEST_SKIP_SYSTEMD_PERSISTENCE === 'true') return false;
  return executor?.mode === 'remote' || process.platform === 'linux';
}

function requiresLaunchdPersistence(executor) {
  if (process.env.NODE_ENV === 'test' && process.env.SYNERGY_NCP_TEST_SKIP_LAUNCHD_PERSISTENCE === 'true') return false;
  return executor?.mode === 'local' && process.platform === 'darwin';
}

async function writeExecutorFile(executor, filePath, content, mode) {
  if (executor.mode === 'remote') {
    await executor.writeFile(filePath, content, mode);
    return;
  }
  await fs.writeFile(filePath, content, { mode: Number.parseInt(mode, 8) });
}

async function removeExecutorFile(executor, filePath) {
  if (executor.mode === 'remote') {
    await executor.removeFile(filePath).catch(() => undefined);
    return;
  }
  await fs.rm(filePath, { force: true });
}

async function ensurePersistentInnernetService(executor, { clientCommand, interfaceName }) {
  if (requiresLaunchdPersistence(executor)) {
    const label = 'network.synergy.innernet';
    const destination = `/Library/LaunchDaemons/${label}.plist`;
    const plistPath = `/tmp/synergy-ncp-innernet-${crypto.randomUUID()}.plist`;
    const installerPath = `/tmp/synergy-ncp-innernet-${crypto.randomUUID()}.sh`;
    try {
      await writeExecutorFile(executor, plistPath, renderInnernetLaunchdPlist(clientCommand, interfaceName), '0600');
      await writeExecutorFile(executor, installerPath, `#!/bin/sh
set -eu
/usr/bin/install -o root -g wheel -m 0644 '${plistPath}' '${destination}'
/bin/launchctl bootout 'system/${label}' >/dev/null 2>&1 || true
/bin/launchctl bootstrap system '${destination}'
/bin/launchctl enable 'system/${label}'
/bin/launchctl kickstart -k 'system/${label}'
`, '0700');
      await executor.runElevated('/bin/sh', [installerPath], { timeoutMs: 90_000 });
    } catch (error) {
      if (error?.code === 'ELEVATION_REQUIRED') throw error;
      throw meshError('INNERNET_PERSISTENCE_FAILED', 'The secure-network interface is up but macOS could not install its persistence watchdog.', {
        sourceCode: error?.code || 'COMMAND_FAILED',
      });
    } finally {
      await removeExecutorFile(executor, plistPath);
      await removeExecutorFile(executor, installerPath);
    }
    return;
  }

  if (!requiresSystemdPersistence(executor)) return;
  const unitPath = `/tmp/synergy-ncp-innernet-${crypto.randomUUID()}.service`;
  try {
    await writeExecutorFile(executor, unitPath, renderInnernetSystemdUnit(clientCommand, interfaceName), '0644');
    await executor.runElevated('install', ['-m', '0644', unitPath, '/etc/systemd/system/synergy-innernet.service']);
    await executor.runElevated('systemctl', ['daemon-reload']);
    await executor.runElevated('systemctl', ['enable', '--now', 'synergy-innernet.service'], { timeoutMs: 90_000 });
  } catch (error) {
    if (error?.code === 'ELEVATION_REQUIRED' || error?.code === 'REMOTE_SUDO_REQUIRED') throw error;
    throw meshError('INNERNET_PERSISTENCE_FAILED', 'The secure-network interface is up but could not be persisted for reboot.', {
      sourceCode: error?.code || 'COMMAND_FAILED',
    });
  } finally {
    await removeExecutorFile(executor, unitPath);
  }
}

function renderWireguardLaunchdPlist(wgQuickCommand) {
  const binary = String(wgQuickCommand || '').trim();
  if (!path.posix.isAbsolute(binary) || /[\u0000\r\n]/.test(binary)) {
    throw meshError('WIREGUARD_QUICK_PATH_INVALID', 'The persistent WireGuard service requires an absolute wg-quick path.');
  }
  const searchPath = [path.dirname(binary), '/opt/homebrew/bin', '/usr/local/bin', '/usr/bin', '/bin', '/usr/sbin', '/sbin'].join(':');
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>network.synergy.wireguard</string>
  <key>ProgramArguments</key>
  <array>
    <string>${xmlEscape(binary)}</string>
    <string>up</string>
    <string>sy-vpn</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict><key>PATH</key><string>${xmlEscape(searchPath)}</string></dict>
  <key>RunAtLoad</key><true/>
  <key>StandardOutPath</key><string>/var/log/synergy-wireguard.log</string>
  <key>StandardErrorPath</key><string>/var/log/synergy-wireguard.err.log</string>
</dict>
</plist>
`;
}

async function ensurePersistentPackagedWireguard(executor, wgQuickCommand) {
  if (requiresLaunchdPersistence(executor)) {
    const label = 'network.synergy.wireguard';
    const plistPath = `/tmp/synergy-ncp-wireguard-${crypto.randomUUID()}.plist`;
    const installerPath = `/tmp/synergy-ncp-wireguard-${crypto.randomUUID()}.sh`;
    try {
      await writeExecutorFile(executor, plistPath, renderWireguardLaunchdPlist(wgQuickCommand), '0600');
      await writeExecutorFile(executor, installerPath, `#!/bin/sh
set -eu
/usr/bin/install -o root -g wheel -m 0644 '${plistPath}' '/Library/LaunchDaemons/${label}.plist'
/bin/launchctl bootout 'system/${label}' >/dev/null 2>&1 || true
/bin/launchctl bootstrap system '/Library/LaunchDaemons/${label}.plist'
/bin/launchctl enable 'system/${label}'
`, '0700');
      await executor.runElevated('/bin/sh', [installerPath], { timeoutMs: 90_000 });
    } finally {
      await removeExecutorFile(executor, plistPath);
      await removeExecutorFile(executor, installerPath);
    }
    return;
  }
  if (requiresSystemdPersistence(executor)) {
    await executor.runElevated('systemctl', ['enable', 'wg-quick@sy-vpn.service'], { timeoutMs: 90_000 });
  }
}

function canonicalPackagedWireguardPeers(assignedIp) {
  const local = normaliseIp(assignedIp);
  const participants = [
    '10.70.0.1',
    ...Array.from({ length: 21 }, (_, index) => `10.70.10.${index + 1}`),
    ...Array.from({ length: 3 }, (_, index) => `10.70.20.${index + 1}`),
  ];
  return participants.filter((address) => address !== local).sort();
}

function packagedWireguardPeerIps(config) {
  return String(config).split(/^\[Peer\]\s*$/m).slice(1).flatMap((peer) => {
    const allowed = peer.match(/^AllowedIPs\s*=\s*([^\r\n]+)/m)?.[1] || '';
    return allowed.split(',').map((value) => normaliseIp(value)).filter(Boolean);
  });
}

function validatePackagedWireguardConfig(packageData) {
  if (!packageData?.available || !packageData?.wireguardConfig || !packageData?.wireguardPrivateKey) {
    throw meshError('PACKAGED_WIREGUARD_REQUIRED', 'This installer does not contain its assigned WireGuard configuration.');
  }
  const config = String(packageData.wireguardConfig);
  const address = config.match(/^Address\s*=\s*([^\s,]+)/m)?.[1]?.split('/')[0];
  const privateKey = config.match(/^PrivateKey\s*=\s*(\S+)/m)?.[1];
  const peerCount = (config.match(/^\[Peer\]$/gm) || []).length;
  const expectedPeers = canonicalPackagedWireguardPeers(address);
  const actualPeers = packagedWireguardPeerIps(config).sort();
  const topologyMatches = actualPeers.length === expectedPeers.length
    && actualPeers.every((peer, index) => peer === expectedPeers[index]);
  if (
    address !== normaliseIp(packageData.vpnIp)
    || privateKey !== packageData.wireguardPrivateKey
    || peerCount !== expectedPeers.length
    || !topologyMatches
    || !/^\[Interface\]$/m.test(config)
  ) {
    throw meshError('PACKAGED_WIREGUARD_INVALID', 'The packaged WireGuard configuration does not contain the complete canonical Testnet-v3 mesh.');
  }
}

async function retireInnernetForPackagedWireguard(executor) {
  if (requiresLaunchdPersistence(executor)) {
    await executor.runElevated('/bin/sh', ['-ceu', `
/bin/launchctl bootout system/network.synergy.innernet >/dev/null 2>&1 || true
/bin/rm -f /Library/LaunchDaemons/network.synergy.innernet.plist
`], { timeoutMs: 90_000 });
    return;
  }
  if (!requiresSystemdPersistence(executor)) return;
  await executor.runElevated('/bin/sh', ['-ceu', `
systemctl disable --now synergy-innernet-refresh.timer >/dev/null 2>&1 || true
systemctl stop synergy-innernet-refresh.service >/dev/null 2>&1 || true
systemctl disable --now synergy-innernet.service >/dev/null 2>&1 || true
systemctl reset-failed synergy-innernet-refresh.service >/dev/null 2>&1 || true
systemctl daemon-reload
`], { timeoutMs: 90_000 });
}

async function activatePackagedWireguardConfig(executor, packageData, emitProgress) {
  validatePackagedWireguardConfig(packageData);
  const interfaceName = 'sy-vpn';
  const assignedIp = normaliseIp(packageData.vpnIp);
  const wgQuickCommand = await resolveWireguardQuickBinary(executor);
  const wgCommand = await resolveWireguardBinary(executor);
  const temporaryPath = `/tmp/synergy-ncp-${interfaceName}-${crypto.randomUUID()}.conf`;
  try {
    emitProgress?.({ step: 'requesting_elevation' });
    await writeExecutorFile(executor, temporaryPath, packageData.wireguardConfig, '0600');
    const derivedPublicKey = String((await executor.run(wgCommand, ['pubkey'], {
      input: `${packageData.wireguardPrivateKey}\n`,
    })).stdout || '').trim();
    if (derivedPublicKey !== packageData.wireguardPublicKey) {
      throw meshError('PACKAGED_WIREGUARD_KEY_MISMATCH', 'The packaged WireGuard private and public keys do not match.');
    }
    emitProgress?.({ step: 'retiring_innernet_client' });
    await retireInnernetForPackagedWireguard(executor);
    await executor.runElevated('mkdir', ['-p', '/etc/wireguard']);
    await executor.runElevated('install', ['-m', '0600', temporaryPath, `/etc/wireguard/${interfaceName}.conf`]);
    await executor.runElevated(wgQuickCommand, ['down', interfaceName], { timeoutMs: 90_000 }).catch((error) => {
      if (error?.code === 'ELEVATION_REQUIRED' || error?.code === 'REMOTE_SUDO_REQUIRED') throw error;
    });
    emitProgress?.({ step: 'activating_packaged_wireguard' });
    await executor.runElevated(wgQuickCommand, ['up', interfaceName], { timeoutMs: 90_000 });
  } finally {
    await removeExecutorFile(executor, temporaryPath);
  }
  let health = await getMeshHealth(executor, { interfaceName, assignedIp }).catch((error) => {
    if (!isRetryableMeshHealthError(error)) throw error;
    return null;
  });
  if (!health?.handshakeConfirmed) {
    health = await waitForMeshHandshake(executor, {
      interfaceName,
      assignedIp,
      initialHealth: health,
      emitProgress,
    });
  }
  if (!health.handshakeConfirmed) {
    throw meshError('NO_HANDSHAKE', 'The packaged secure-network configuration started, but no validator peer completed a handshake.');
  }
  await ensurePersistentPackagedWireguard(executor, wgQuickCommand);
  emitProgress?.({ step: 'packaged_wireguard_active' });
  return health;
}

function parseWireGuardDump(interfaceName, stdout) {
  const lines = String(stdout || '').trim().split('\n').filter(Boolean);
  const peers = lines.slice(1).map((line, index) => {
    const fields = line.split('\t');
    const handshakeAt = Number(fields[4] || 0);
    return {
      name: `Peer ${index + 1}`,
      endpoint: fields[2] || null,
      allowedIps: String(fields[3] || '').split(',').map((value) => value.trim()).filter(Boolean),
      lastHandshakeSecondsAgo: handshakeAt > 0 ? Math.max(0, Math.floor(Date.now() / 1000) - handshakeAt) : null,
    };
  });
  return { interfaceName, peers };
}

function validIpv4(value) {
  const candidate = normaliseIp(value);
  const octets = String(candidate || '').split('.');
  if (octets.length !== 4) return null;
  if (!octets.every((octet) => /^\d{1,3}$/.test(octet) && Number(octet) <= 255)) return null;
  return octets.map(Number).join('.');
}

function handshakeProbeTargets(health) {
  const assignedIp = validIpv4(health?.assignedIp);
  return [...new Set((health?.peers || [])
    .flatMap((peer) => peer.allowedIps || [])
    .map(validIpv4)
    .filter((candidate) => candidate && candidate !== assignedIp))];
}

async function stimulateMeshHandshake(executor, health) {
  const targets = handshakeProbeTargets(health);
  await Promise.allSettled(targets.map((target) => executor.run(
    'ping',
    ['-n', '-c', '1', target],
    { timeoutMs: 2_500 },
  )));
  return targets;
}

function isRetryableMeshHealthError(error) {
  return ['INTERFACE_FAILED', 'INTERFACE_EVIDENCE_FAILED', 'INTERFACE_ADDRESS_MISSING'].includes(error?.code);
}

async function waitForMeshHandshake(
  executor,
  {
    interfaceName,
    assignedIp,
    initialHealth,
    emitProgress,
    timeoutMs = defaultHandshakeTimeoutMs(),
    pollIntervalMs = 1_000,
    probeIntervalMs = HANDSHAKE_PROBE_INTERVAL_MS,
  },
) {
  const deadline = Date.now() + timeoutMs;
  let health = initialHealth || null;
  let lastKnownHealth = health;
  let lastHealthError = null;
  let nextProbeAt = 0;
  let lastProgressAt = 0;
  while (Date.now() < deadline) {
    if (!health) {
      try {
        health = await getMeshHealth(executor, { interfaceName, assignedIp });
        lastKnownHealth = health;
        lastHealthError = null;
      } catch (error) {
        if (error?.code === 'ELEVATION_REQUIRED' || error?.code === 'REMOTE_SUDO_REQUIRED') throw error;
        if (!isRetryableMeshHealthError(error)) throw error;
        lastHealthError = error;
      }
    }
    if (health?.handshakeConfirmed || health?.probeExhausted) return health;

    const now = Date.now();
    if (health && now >= nextProbeAt) {
      const probeTargets = await stimulateMeshHandshake(executor, health);
      emitProgress?.({ step: 'handshake_probe_started', peers: probeTargets.length });
      nextProbeAt = now + probeIntervalMs;
    }
    if (health && now - lastProgressAt >= probeIntervalMs) {
      emitProgress?.({
        step: 'handshake_waiting',
        peersConfigured: health.peers?.length || 0,
        peersConnected: health.peersConnected || 0,
        peersWithEndpoint: (health.peers || [])
          .filter((peer) => peer.endpoint && peer.endpoint !== '(none)').length,
        remainingSeconds: Math.max(0, Math.ceil((deadline - now) / 1_000)),
      });
      lastProgressAt = now;
    }

    const remainingMs = deadline - Date.now();
    if (remainingMs <= 0) break;
    await new Promise((resolve) => setTimeout(resolve, Math.min(pollIntervalMs, remainingMs)));
    if (Date.now() >= deadline) break;

    try {
      health = await getMeshHealth(executor, { interfaceName, assignedIp });
      lastKnownHealth = health;
      lastHealthError = null;
    } catch (error) {
      if (error?.code === 'ELEVATION_REQUIRED' || error?.code === 'REMOTE_SUDO_REQUIRED') throw error;
      if (!isRetryableMeshHealthError(error)) throw error;
      lastHealthError = error;
      health = null;
    }
  }
  if (lastKnownHealth) return lastKnownHealth;
  throw lastHealthError || meshError('INTERFACE_FAILED', 'The expected Innernet interface is not available.');
}

function parseInterfaceAddresses(stdout) {
  const addresses = [];
  for (const match of String(stdout || '').matchAll(/\binet\s+(\d{1,3}(?:\.\d{1,3}){3})(?:\/(\d{1,2}))?/g)) {
    addresses.push({ ip: match[1], cidr: match[2] ? `${match[1]}/${match[2]}` : match[1] });
  }
  return addresses;
}

function parseDarwinMeshInspection(stdout, interfaceName, assignedIp) {
  const values = new Map();
  for (const line of String(stdout || '').split('\n')) {
    if (!line.startsWith(DARWIN_MESH_REPORT_PREFIX)) continue;
    const separator = line.indexOf('=');
    if (separator <= 0) continue;
    values.set(line.slice(DARWIN_MESH_REPORT_PREFIX.length, separator), line.slice(separator + 1));
  }
  const status = values.get('STATUS') || 'missing';
  const deviceInterfaceName = String(values.get('DEVICE') || '').trim();
  const decode = (key) => {
    const value = values.get(key);
    if (!value) return '';
    return Buffer.from(value, 'base64').toString('utf8');
  };
  const addresses = parseInterfaceAddresses(decode('ADDRS_B64'));
  const report = parseWireGuardDump(deviceInterfaceName || interfaceName, decode('DUMP_B64'));
  const expectedIp = normaliseIp(assignedIp);
  const actualAddress = addresses.find((address) => address.ip === expectedIp);
  if (!deviceInterfaceName || !actualAddress) {
    throw meshError('INTERFACE_FAILED', 'The expected Innernet interface is not available.', {
      interfaceName,
      expectedIp,
      status,
    });
  }
  const peersConnected = report.peers.filter((peer) => peer.lastHandshakeSecondsAgo !== null).length;
  return {
    ...report,
    interfaceName,
    deviceInterfaceName,
    assignedIp: actualAddress.ip,
    addresses,
    interfaceUp: true,
    peersConnected,
    handshakeConfirmed: status === 'ready' && peersConnected > 0,
    probeExhausted: status === 'timeout',
  };
}

async function getDarwinExpectedMeshHealth(executor, interfaceName, assignedIp) {
  const timeoutMs = defaultHandshakeTimeoutMs();
  const result = await executor.runElevated(
    '/bin/sh',
    [
      '-c',
      DARWIN_MESH_INSPECTION_SCRIPT,
      'synergy-innernet-health',
      normaliseIp(assignedIp),
      String(Math.max(1, Math.ceil(timeoutMs / 1_000))),
    ],
    { timeoutMs: timeoutMs + 10_000 },
  );
  return parseDarwinMeshInspection(result.stdout, interfaceName, assignedIp);
}

async function readInterfaceAddresses(executor, interfaceName) {
  let stdout;
  try {
    stdout = (await executor.run('ip', ['-o', '-4', 'addr', 'show', 'dev', interfaceName])).stdout;
  } catch {
    try {
      stdout = (await executor.run('ifconfig', [interfaceName])).stdout;
    } catch (error) {
      throw meshError('INTERFACE_EVIDENCE_FAILED', 'The redeemed Innernet interface address could not be inspected.', {
        sourceCode: error?.code || 'COMMAND_FAILED',
      });
    }
  }
  const addresses = parseInterfaceAddresses(stdout);
  if (!addresses.length) {
    throw meshError('INTERFACE_ADDRESS_MISSING', 'The redeemed Innernet interface has no IPv4 address.');
  }
  return addresses;
}

async function getExpectedMeshHealth(executor, interfaceName, assignedIp) {
  if (executor?.mode === 'local' && process.platform === 'darwin' && process.env.NODE_ENV !== 'test') {
    return getDarwinExpectedMeshHealth(executor, interfaceName, assignedIp);
  }
  const expectedIp = normaliseIp(assignedIp);
  const candidates = [interfaceName];
  try {
    const interfaces = String((await executor.runElevated('wg', ['show', 'interfaces'])).stdout || '')
      .trim().split(/\s+/).filter(Boolean);
    interfaces.forEach((candidate) => {
      if (!candidates.includes(candidate)) candidates.push(candidate);
    });
  } catch (error) {
    if (error?.code === 'ELEVATION_REQUIRED' || error?.code === 'REMOTE_SUDO_REQUIRED') throw error;
  }

  const actualIps = [];
  let lastError = null;
  for (const candidate of candidates) {
    try {
      const [dump, addresses] = await Promise.all([
        executor.runElevated('wg', ['show', candidate, 'dump']),
        readInterfaceAddresses(executor, candidate),
      ]);
      addresses.forEach((address) => actualIps.push(address.ip));
      const actualAddress = addresses.find((address) => address.ip === expectedIp);
      if (!actualAddress) continue;
      const report = parseWireGuardDump(candidate, dump.stdout);
      const peersConnected = report.peers.filter((peer) => peer.lastHandshakeSecondsAgo !== null).length;
      return {
        ...report,
        interfaceName,
        deviceInterfaceName: candidate,
        assignedIp: actualAddress.ip,
        addresses,
        interfaceUp: true,
        peersConnected,
        handshakeConfirmed: peersConnected > 0,
      };
    } catch (error) {
      if (error?.code === 'ELEVATION_REQUIRED' || error?.code === 'REMOTE_SUDO_REQUIRED') throw error;
      lastError = error;
    }
  }

  if (actualIps.length) {
    throw meshError('ASSIGNED_IP_MISMATCH', 'The redeemed Innernet interface does not have the coordinator-assigned IP.', {
      interfaceName,
      expectedIp,
      actualIps: [...new Set(actualIps)],
    });
  }
  throw meshError('INTERFACE_FAILED', 'The expected Innernet interface is not available.', {
    interfaceName,
    sourceCode: lastError?.code || 'COMMAND_FAILED',
  });
}

async function getMeshHealth(executor, { interfaceName, assignedIp } = {}) {
  if (interfaceName || assignedIp) {
    if (!String(interfaceName || '').trim()) {
      throw meshError('INTERFACE_REQUIRED', 'The coordinator did not identify the expected Innernet interface.');
    }
    if (!normaliseIp(assignedIp)) {
      throw meshError('ASSIGNED_IP_REQUIRED', 'The coordinator did not identify the assigned Innernet IP.');
    }
    return getExpectedMeshHealth(executor, String(interfaceName).trim(), assignedIp);
  }
  const interfaces = String((await executor.runElevated('wg', ['show', 'interfaces'])).stdout || '').trim()
    .split(/\s+/).filter(Boolean);
  const reports = [];
  for (const interfaceName of interfaces) {
    const dump = await executor.runElevated('wg', ['show', interfaceName, 'dump']);
    reports.push(parseWireGuardDump(interfaceName, dump.stdout));
  }
  const peers = reports.flatMap((report) => report.peers);
  return {
    interfaceUp: reports.length > 0,
    interfaceName: reports[0]?.interfaceName || null,
    peers,
    peersConnected: peers.filter((peer) => peer.lastHandshakeSecondsAgo !== null).length,
    handshakeConfirmed: peers.some((peer) => peer.lastHandshakeSecondsAgo !== null),
  };
}

function redeemOptions(inviteOrPayload, optionsOrEmit, maybeEmit) {
  const payload = inviteOrPayload && typeof inviteOrPayload === 'object' ? inviteOrPayload : {};
  const options = typeof optionsOrEmit === 'function' ? {} : (optionsOrEmit || {});
  return {
    token: String(payload.invite || inviteOrPayload || '').trim(),
    resumeExisting: payload.resumeExisting === true || payload.resume_existing === true,
    assignedIp: options.assignedIp || payload.assignedIp || payload.assigned_ip,
    interfaceName: options.interfaceName
      || payload.interfaceName
      || payload.interface_name
      || payload.innernetInterface
      || payload.innernet_interface
      || payload.interface
      || process.env.SYNERGY_INNERNET_INTERFACE
      || 'innernet0',
    emitProgress: typeof optionsOrEmit === 'function' ? optionsOrEmit : maybeEmit,
  };
}

async function redeemInvite(executor, inviteOrPayload, optionsOrEmit, maybeEmit) {
  const {
    token, resumeExisting, assignedIp, interfaceName, emitProgress,
  } = redeemOptions(inviteOrPayload, optionsOrEmit, maybeEmit);
  if (!token && !resumeExisting) throw meshError('INVITE_REQUIRED', 'Request a secure-network invite before connecting.');
  if (!normaliseIp(assignedIp)) throw meshError('ASSIGNED_IP_REQUIRED', 'The coordinator did not return an assigned Innernet IP.');
  const clientCommand = executor.mode === 'remote'
    ? await resolveAndStageRemoteInnernetClient(executor)
    : await resolveInnernetClientBinary();
  const inviteName = `synergy-innernet-${crypto.randomUUID()}.invite`;
  let localDirectory = null;
  let invitePath;
  let clientInstallError = null;
  let existingConfigResumed = false;
  let clientInstallRecovered = false;
  try {
    emitProgress?.({ step: 'requesting_elevation' });
    if (await hasExistingInterfaceConfig(executor, interfaceName)) {
      emitProgress?.({ step: 'existing_innernet_config_detected' });
      await executor.runElevated(clientCommand, ['up', interfaceName], { timeoutMs: 90_000 });
      emitProgress?.({ step: 'existing_innernet_config_started' });
      existingConfigResumed = true;
    }

    if (resumeExisting && !existingConfigResumed) {
      emitProgress?.({ step: 'existing_innernet_config_detected' });
      try {
        await executor.runElevated(clientCommand, ['up', interfaceName], { timeoutMs: 90_000 });
        emitProgress?.({ step: 'existing_innernet_config_started' });
        existingConfigResumed = true;
      } catch (error) {
        if (error?.code === 'ELEVATION_REQUIRED' || error?.code === 'REMOTE_SUDO_REQUIRED') throw error;
        throw meshError(
          'INNERNET_EXISTING_CONFIG_REQUIRED',
          'The coordinator recovered an existing secure-network membership, but this machine could not start its Innernet interface configuration.',
          { sourceCode: error?.code || 'COMMAND_FAILED', detail: commandFailureMessage(error) || null },
        );
      }
    }

    if (!existingConfigResumed) {
      if (executor.mode === 'remote') {
        invitePath = `/tmp/${inviteName}`;
        await executor.writeFile(invitePath, token, '0600');
      } else {
        localDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'synergy-ncp-invite-'));
        invitePath = path.join(localDirectory, inviteName);
        await fs.writeFile(invitePath, token, { mode: 0o600 });
      }
      emitProgress?.({ step: 'innernet_client_ready' });
      emitProgress?.({ step: 'redeeming_invite' });
      try {
        await executor.runElevated(clientCommand, ['install', '--default-name', '--delete-invite', invitePath], { timeoutMs: 90_000 });
      } catch (error) {
        if (error?.code === 'ELEVATION_REQUIRED' || error?.code === 'REMOTE_SUDO_REQUIRED') throw error;
        // Innernet can report a nonzero exit after it has registered a peer. The
        // coordinator confirmation still independently proves that membership.
        clientInstallError = error;
        if (isResumableInnernetInstallError(error)) {
          emitProgress?.({ step: 'existing_innernet_config_detected' });
          try {
            await executor.runElevated(clientCommand, ['up', interfaceName], { timeoutMs: 90_000 });
            emitProgress?.({ step: 'existing_innernet_config_started' });
            existingConfigResumed = true;
            clientInstallRecovered = true;
            clientInstallError = null;
          } catch (resumeError) {
            if (resumeError?.code === 'ELEVATION_REQUIRED' || resumeError?.code === 'REMOTE_SUDO_REQUIRED') throw resumeError;
            clientInstallError = resumeError;
          }
        }
      }
    }
  } catch (error) {
    if (error?.code === 'ELEVATION_REQUIRED' || error?.code === 'REMOTE_SUDO_REQUIRED') throw error;
    throw meshError('INVITE_REDEMPTION_FAILED', 'The secure-network invite could not be redeemed.', { sourceCode: error?.code || 'COMMAND_FAILED' });
  } finally {
    if (executor.mode === 'remote' && invitePath) await executor.removeFile(invitePath).catch(() => undefined);
    if (localDirectory) await fs.rm(localDirectory, { recursive: true, force: true });
  }

  let health;
  try {
    health = await getMeshHealth(executor, { interfaceName, assignedIp });
  } catch (error) {
    if (clientInstallError) {
      const detail = commandFailureMessage(clientInstallError);
      throw meshError('INVITE_REDEMPTION_FAILED', `The secure-network invite could not be redeemed${detail ? `: ${detail}` : '.'}`, {
        sourceCode: clientInstallError?.code || 'COMMAND_FAILED',
        detail: detail || null,
      });
    }
    if (!isRetryableMeshHealthError(error)) throw error;
    health = null;
  }
  if (!health || !health.interfaceUp || !health.handshakeConfirmed) {
    health = await waitForMeshHandshake(executor, {
      interfaceName,
      assignedIp,
      initialHealth: health,
      emitProgress,
    });
  }
  if (!health.handshakeConfirmed) {
    throw meshError(
      'NO_HANDSHAKE',
      'The secure-network interface started but no peer completed a handshake before the convergence timeout.',
      {
        timeoutSeconds: Math.round(defaultHandshakeTimeoutMs() / 1_000),
        peersConfigured: health.peers?.length || 0,
        peersConnected: health.peersConnected || 0,
        peersWithEndpoint: (health.peers || [])
          .filter((peer) => peer.endpoint && peer.endpoint !== '(none)').length,
      },
    );
  }
  if (clientInstallRecovered || clientInstallError) {
    emitProgress?.({ step: 'innernet_client_recovered' });
  }
  emitProgress?.({ step: 'interface_up' });
  await ensurePersistentInnernetService(executor, { clientCommand, interfaceName });
  emitProgress?.({ step: 'persistence_ready' });
  health.peers.filter((peer) => peer.lastHandshakeSecondsAgo !== null)
    .forEach((peer) => emitProgress?.({ step: 'handshake_confirmed', peer: peer.name }));
  return health;
}

module.exports = {
  activatePackagedWireguardConfig,
  canonicalPackagedWireguardPeers,
  getMeshHealth,
  hasExistingInterfaceConfig,
  innernetPlatformKey,
  isExistingInterfaceConfigError,
  isResumableInnernetInstallError,
  parseDarwinMeshInspection,
  parseInterfaceAddresses,
  parseWireGuardDump,
  prepareRemoteInnernetClient,
  redeemInvite,
  renderInnernetLaunchdPlist,
  renderInnernetSystemdUnit,
  resolveInnernetClientBinary,
  resolveRemoteInnernetPlatform,
  stimulateMeshHandshake,
  validatePackagedWireguardConfig,
  waitForMeshHandshake,
};
