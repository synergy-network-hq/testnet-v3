import {
  checkPublicEndpointReachability,
  fetchSeedPeerTargets,
  heartbeatSeedPeer,
  readTextFile,
  registerSeedPeer,
  writeTextFile,
} from './desktopClient';

const PORT_SETTINGS_STORAGE_KEY = 'synergy:testnet:port-settings:v1';
const TESTNET_CHAIN_ID = 'synergy-testnet';
const DEFAULT_VALIDATOR_PUBLIC_P2P_PORT = 5622;
const TESTNET_ENDPOINTS = {
  coreRpc: 'https://testnet-rpc.synergy-network.io',
  coreWs: 'wss://testnet-core-ws.synergy-network.io',
  walletApi: 'https://testnet-wallet-api.synergy-network.io',
  sxcpApi: 'https://testnet-sxcp-api.synergy-network.io',
};
const TESTNET_BOOTSTRAP_DNS_RECORDS = Object.freeze(['_dnsaddr.bootstrap.synergynode.xyz']);
const CANONICAL_VALIDATOR_PEERS = Object.freeze([]);
const SENTRY_UPSTREAMS = Object.freeze({
  rpc_gateway: [
    'relay1.synergynode.xyz:5622',
    'relay2.synergynode.xyz:5622',
    'archive.synergynode.xyz:5615',
  ],
  indexer: [
    'relay1.synergynode.xyz:5622',
    'relay2.synergynode.xyz:5622',
    'rpc.synergynode.xyz:5623',
    'archive.synergynode.xyz:5615',
  ],
  observer: [
    'relay1.synergynode.xyz:5622',
    'relay2.synergynode.xyz:5622',
    'rpc.synergynode.xyz:5623',
    'archive.synergynode.xyz:5615',
  ],
});
// New validators must start from bootnodes + seed registration. They should not
// force every existing validator config to add them as persistent peers.
const PUBLIC_VALIDATOR_UPSTREAMS = Object.freeze([]);

const TESTNET_DEFAULT_PORT_SETTINGS = Object.freeze({
  p2p: 5622,
  rpc: 5640,
  ws: 5660,
  discovery: 5680,
  metrics: 6030,
});

const TESTNET_PORT_FIELDS = Object.freeze([
  {
    key: 'p2p',
    label: 'P2P',
    detail: 'Peer listener and advertised external peer port.',
  },
  {
    key: 'rpc',
    label: 'RPC',
    detail: 'HTTP and gRPC port used by the local node.',
  },
  {
    key: 'ws',
    label: 'WebSocket',
    detail: 'WebSocket port used by the local node.',
  },
  {
    key: 'discovery',
    label: 'Discovery',
    detail: 'Peer discovery service port used by the local node.',
  },
  {
    key: 'metrics',
    label: 'Metrics',
    detail: 'Local telemetry metrics port used by the local node.',
  },
]);
const VALIDATOR_NAT_MODE_OPTIONS = Object.freeze([
  {
    value: 'router_port_forward',
    label: 'Router port-forward',
    detail: 'Use this when your router forwards public TCP traffic to this machine.',
  },
  {
    value: 'direct_public_ip',
    label: 'Direct public IP',
    detail: 'Use this when this machine owns the public IP directly.',
  },
  {
    value: 'custom_public_port',
    label: 'Custom public port',
    detail: 'Use this when NAT forwards a non-default public port to local 5622.',
  },
]);

function getLocalStorage() {
  if (typeof window === 'undefined') {
    return null;
  }

  try {
    return window.localStorage;
  } catch {
    return null;
  }
}

function cloneDefaultPortSettings() {
  return { ...TESTNET_DEFAULT_PORT_SETTINGS };
}

function usesFixedValidatorPorts(node) {
  const roleId = String(node?.role_id ?? node?.roleId ?? '').trim().toLowerCase();
  return roleId === 'validator';
}

function usesStaticValidatorMesh(node) {
  const roleId = String(node?.role_id ?? node?.roleId ?? '').trim().toLowerCase();
  if (roleId !== 'validator') {
    return false;
  }
  return false;
}

function normalizeStoredPortSettings(value) {
  const normalized = cloneDefaultPortSettings();
  const source = value && typeof value === 'object' ? value : {};

  TESTNET_PORT_FIELDS.forEach(({ key }) => {
    const parsed = Number.parseInt(String(source[key] ?? '').trim(), 10);
    if (Number.isInteger(parsed) && parsed > 0 && parsed <= 65535) {
      normalized[key] = parsed;
    }
  });

  return normalized;
}

function resolveNodePortSlot(node) {
  const raw = node?.port_slot ?? node?.portSlot ?? 0;
  const parsed = Number.parseInt(String(raw).trim(), 10);
  if (!Number.isInteger(parsed) || parsed < 0) {
    return 0;
  }
  return parsed;
}

function offsetPort(port, offset) {
  const nextPort = Number(port) + Number(offset);
  if (!Number.isInteger(nextPort) || nextPort <= 0 || nextPort > 65535) {
    return port;
  }
  return nextPort;
}

function resolveNodePortSettings(settings, node) {
  const baseSettings = normalizeStoredPortSettings(settings);
  if (usesFixedValidatorPorts(node)) {
    return baseSettings;
  }
  const portSlot = resolveNodePortSlot(node);
  return normalizeStoredPortSettings({
    p2p: offsetPort(baseSettings.p2p, portSlot),
    rpc: offsetPort(baseSettings.rpc, portSlot),
    ws: offsetPort(baseSettings.ws, portSlot),
    discovery: offsetPort(baseSettings.discovery, portSlot),
    metrics: offsetPort(baseSettings.metrics, portSlot),
  });
}

function parsePortValue(value) {
  const parsed = Number.parseInt(String(value ?? '').trim(), 10);
  if (!Number.isInteger(parsed) || parsed <= 0 || parsed > 65535) {
    return null;
  }
  return parsed;
}

export function normalizePublicP2pPort(value) {
  return parsePortValue(value) ?? DEFAULT_VALIDATOR_PUBLIC_P2P_PORT;
}

function isIpv4Address(host) {
  const segments = String(host || '').split('.');
  if (segments.length !== 4) {
    return false;
  }

  return segments.every((segment) => {
    if (!/^\d+$/.test(segment)) {
      return false;
    }
    const value = Number.parseInt(segment, 10);
    return value >= 0 && value <= 255;
  });
}

function isIpv6Address(host) {
  const normalized = String(host || '').trim();
  return normalized.includes(':') && /^[0-9a-fA-F:]+$/.test(normalized);
}

function isPrivateAdvertiseHost(host) {
  const normalized = String(host || '').trim().toLowerCase().replace(/^\[/, '').replace(/\]$/, '');
  if (!normalized || normalized === 'localhost' || normalized === '0.0.0.0' || normalized === '::1') {
    return true;
  }

  if (isIpv4Address(normalized)) {
    const [first, second] = normalized.split('.').map((part) => Number.parseInt(part, 10));
    return first === 10
      || first === 127
      || first === 0
      || (first === 172 && second >= 16 && second <= 31)
      || (first === 192 && second === 168)
      || (first === 169 && second === 254);
  }

  if (isIpv6Address(normalized)) {
    return normalized === '::'
      || normalized.startsWith('fc')
      || normalized.startsWith('fd')
      || normalized.startsWith('fe80:');
  }

  return normalized.endsWith('.local');
}

function isPlausibleDialHost(host) {
  const normalized = String(host || '').trim();
  if (!normalized) {
    return false;
  }

  if (normalized.toLowerCase() === 'localhost') {
    return true;
  }

  if (isIpv4Address(normalized) || isIpv6Address(normalized)) {
    return true;
  }

  return normalized.includes('.') && /^[a-zA-Z0-9.-]+$/.test(normalized);
}

function normalizeHostPort(host, port) {
  const normalizedHost = String(host || '')
    .trim()
    .replace(/^\[/, '')
    .replace(/\]$/, '')
    .replace(/\.+$/, '');
  const normalizedPort = Number.parseInt(String(port || '').trim(), 10);

  if (!Number.isInteger(normalizedPort) || normalizedPort <= 0 || normalizedPort > 65535) {
    return null;
  }

  if (!isPlausibleDialHost(normalizedHost)) {
    return null;
  }

  if (isIpv6Address(normalizedHost)) {
    return `[${normalizedHost}]:${normalizedPort}`;
  }

  return `${normalizedHost}:${normalizedPort}`;
}

function normalizeDialTarget(value) {
  const dial = String(value || '').trim();
  if (!dial) {
    return null;
  }

  if (dial.startsWith('[')) {
    const stripped = dial.slice(1);
    const parts = stripped.split(']:');
    if (parts.length === 2) {
      return normalizeHostPort(parts[0], parts[1]);
    }
  }

  const separatorIndex = dial.lastIndexOf(':');
  if (separatorIndex <= 0) {
    return null;
  }

  return normalizeHostPort(dial.slice(0, separatorIndex), dial.slice(separatorIndex + 1));
}

function splitHostPort(value) {
  const normalized = String(value || '').trim().replace(/^"|"$/g, '');
  if (!normalized) {
    return null;
  }

  if (normalized.startsWith('[')) {
    const stripped = normalized.slice(1);
    const parts = stripped.split(']:');
    if (parts.length !== 2) {
      return null;
    }

    const parsedPort = parsePortValue(parts[1]);
    if (parsedPort == null) {
      return null;
    }

    return {
      host: parts[0],
      port: parsedPort,
    };
  }

  const separatorIndex = normalized.lastIndexOf(':');
  if (separatorIndex <= 0) {
    return null;
  }

  const parsedPort = parsePortValue(normalized.slice(separatorIndex + 1));
  if (parsedPort == null) {
    return null;
  }

  return {
    host: normalized.slice(0, separatorIndex),
    port: parsedPort,
  };
}

function formatHostPort(host, port) {
  const normalized = String(host || '').trim().replace(/^\[/, '').replace(/\]$/, '');
  if (isIpv6Address(normalized)) {
    return `[${normalized}]:${port}`;
  }
  return `${normalized}:${port}`;
}

export function buildPublicP2pEndpoint(host, port = DEFAULT_VALIDATOR_PUBLIC_P2P_PORT) {
  const normalizedHost = String(host || '').trim().replace(/^\[/, '').replace(/\]$/, '').replace(/\.+$/, '');
  const normalizedPort = normalizePublicP2pPort(port);
  if (!normalizedHost || isPrivateAdvertiseHost(normalizedHost)) {
    throw new Error('Validator public P2P endpoint must be a public IP address or DNS name.');
  }
  return formatHostPort(normalizedHost, normalizedPort);
}

function updateAddressPort(value, fallbackHost, port) {
  const current = splitHostPort(value);
  const host = current?.host || fallbackHost;
  return formatHostPort(host, port);
}

function tomlString(value) {
  return JSON.stringify(String(value));
}

function tomlArray(values) {
  return `[${values.map((value) => tomlString(value)).join(', ')}]`;
}

function escapeRegExp(value) {
  return String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function sectionPattern(sectionName) {
  return new RegExp(`(^\\[${escapeRegExp(sectionName)}\\]\\n)([\\s\\S]*?)(?=^\\[|\\Z)`, 'm');
}

function readSectionValue(contents, sectionName, key) {
  const match = String(contents || '').match(sectionPattern(sectionName));
  if (!match) {
    return null;
  }

  const body = match[2];
  const keyMatch = body.match(new RegExp(`^${escapeRegExp(key)}\\s*=\\s*(.+)$`, 'm'));
  return keyMatch ? keyMatch[1].trim() : null;
}

function replaceSectionValue(contents, sectionName, key, rawValue) {
  const pattern = sectionPattern(sectionName);
  const keyPattern = new RegExp(`^${escapeRegExp(key)}\\s*=\\s*.+$`, 'm');

  if (!pattern.test(contents)) {
    return contents;
  }

  return contents.replace(pattern, (fullMatch, header, body) => {
    const normalizedBody = keyPattern.test(body)
      ? body.replace(keyPattern, `${key} = ${rawValue}`)
      : `${body.trimEnd()}\n${key} = ${rawValue}\n`;

    return `${header}${normalizedBody}`;
  });
}

function resolveConfigPath(node, fileName) {
  const configPaths = Array.isArray(node?.config_paths) ? node.config_paths : [];
  return configPaths.find((entry) => {
    const normalized = String(entry || '').replace(/\\/g, '/');
    return normalized.endsWith(`/${fileName}`);
  }) || null;
}

function replaceNginxUpstreamPort(contents, upstreamName, port) {
  const pattern = new RegExp(
    `(upstream\\s+${escapeRegExp(upstreamName)}\\s*\\{[\\s\\S]*?server\\s+127\\.0\\.0\\.1:)(\\d+)(;)`,
    'm',
  );
  return String(contents || '').replace(pattern, `$1${port}$3`);
}

function normalizeBootstrapHost(value) {
  const normalized = String(value || '')
    .trim()
    .replace(/^\[/, '')
    .replace(/\]$/, '')
    .replace(/\.+$/, '');
  return normalized || null;
}

function bootstrapEndpointHost(endpoint, options = {}) {
  if (typeof endpoint === 'string') {
    return normalizeBootstrapHost(endpoint);
  }

  const preferIpAddress = Boolean(options?.preferIpAddress);
  const candidates = preferIpAddress
    ? [endpoint?.ip_address, endpoint?.host]
    : [endpoint?.host, endpoint?.ip_address];

  for (const candidate of candidates) {
    const normalized = normalizeBootstrapHost(candidate);
    if (normalized) {
      return normalized;
    }
  }

  return null;
}

function bootnodeDialTargets(networkProfile) {
  const bootnodes = Array.isArray(networkProfile?.bootnodes) ? networkProfile.bootnodes : [];
  return bootnodes
    .map((entry) => {
      if (typeof entry === 'string') {
        return entry;
      }
      const host = bootstrapEndpointHost(entry, { preferIpAddress: false });
      const port = parsePortValue(entry?.port);
      if (!host || port == null) {
        return null;
      }
      return `${host}:${port}`;
    })
    .filter(Boolean);
}

function seedServerUrls(networkProfile) {
  const seeds = Array.isArray(networkProfile?.seed_servers) ? networkProfile.seed_servers : [];
  return seeds
    .map((seed) => {
      if (typeof seed === 'string') {
        return seed;
      }

      if (seed?.url) {
        return seed.url;
      }

      const host = bootstrapEndpointHost(seed, { preferIpAddress: false });
      const port = parsePortValue(seed?.port);
      if (host && port != null) {
        return `http://${host}:${port}`;
      }

      return null;
    })
    .filter(Boolean);
}

export function getTestnetDefaultPortSettings() {
  return cloneDefaultPortSettings();
}

export function getTestnetPortFields() {
  return TESTNET_PORT_FIELDS.map((field) => ({ ...field }));
}

export function getValidatorNatModeOptions() {
  return VALIDATOR_NAT_MODE_OPTIONS.map((option) => ({ ...option }));
}

export function formatPortSettingsForForm(settings) {
  const normalized = normalizeStoredPortSettings(settings);
  return Object.fromEntries(
    TESTNET_PORT_FIELDS.map(({ key }) => [key, String(normalized[key])]),
  );
}

export function formatPortSettingsSummary(settings) {
  const normalized = normalizeStoredPortSettings(settings);
  return `P2P ${normalized.p2p} | RPC ${normalized.rpc} | WS ${normalized.ws} | Discovery ${normalized.discovery} | Metrics ${normalized.metrics}`;
}

export function readStoredTestnetPortSettings() {
  const storage = getLocalStorage();
  if (!storage) {
    return cloneDefaultPortSettings();
  }

  try {
    const raw = storage.getItem(PORT_SETTINGS_STORAGE_KEY);
    return normalizeStoredPortSettings(raw ? JSON.parse(raw) : null);
  } catch {
    return cloneDefaultPortSettings();
  }
}

export function saveStoredTestnetPortSettings(settings) {
  const normalized = normalizeStoredPortSettings(settings);
  const storage = getLocalStorage();
  if (storage) {
    storage.setItem(PORT_SETTINGS_STORAGE_KEY, JSON.stringify(normalized));
  }
  return normalized;
}

export function resetStoredTestnetPortSettings() {
  const defaults = cloneDefaultPortSettings();
  const storage = getLocalStorage();
  if (storage) {
    storage.removeItem(PORT_SETTINGS_STORAGE_KEY);
  }
  return defaults;
}

export function validateTestnetPortSettingsForm(formState) {
  const nextValue = {};
  const errors = {};
  const seenPorts = new Map();

  TESTNET_PORT_FIELDS.forEach(({ key, label }) => {
    const parsed = parsePortValue(formState?.[key]);
    if (parsed == null) {
      errors[key] = `${label} port must be between 1 and 65535.`;
      return;
    }

    nextValue[key] = parsed;
    const previousKey = seenPorts.get(parsed);
    if (previousKey) {
      errors[key] = `${label} port duplicates ${previousKey}.`;
      if (!errors[previousKey]) {
        errors[previousKey] = `${previousKey} duplicates ${label}.`;
      }
      return;
    }

    seenPorts.set(parsed, label);
  });

  return {
    ok: Object.keys(errors).length === 0,
    errors,
    value: Object.keys(errors).length === 0 ? nextValue : null,
  };
}

export function parseDialAddress(value) {
  let raw = String(value || '').trim();
  if (!raw) {
    return null;
  }

  raw = raw.replace(/^(snr|enode):\/\//i, '');
  if (raw.includes('@')) {
    raw = raw.split('@').pop() || '';
  }

  raw = raw.split('/')[0] || '';
  raw = raw.split('?')[0] || '';
  raw = raw.split('#')[0] || '';

  return normalizeDialTarget(raw.trim());
}

export function normalizeDialTargets(values = []) {
  const deduped = new Set();
  (Array.isArray(values) ? values : []).forEach((value) => {
    const normalized = parseDialAddress(value);
    if (normalized) {
      deduped.add(normalized);
    }
  });
  return Array.from(deduped).sort();
}

export function resolveNodeTomlPath(node) {
  return resolveConfigPath(node, 'node.toml');
}

export function resolvePeersTomlPath(node) {
  return resolveConfigPath(node, 'peers.toml');
}

export function resolveNginxConfPath(node) {
  return resolveConfigPath(node, 'nginx.conf');
}

function resolveEffectiveNodePortSettings(node, settings) {
  return {
    portSettings: resolveNodePortSettings(settings, node),
    source: 'stored-profile',
  };
}

export function buildPeersToml(networkProfile, additionalDialTargets = [], options = {}) {
  const explicitOnly = Boolean(options?.explicitOnly);
  const bootnodes = explicitOnly ? [] : bootnodeDialTargets(networkProfile);
  const seeds = (explicitOnly ? [] : seedServerUrls(networkProfile)).map((entry) => {
    const trimmed = String(entry).trim().replace(/\/+$/, '');
    return /^https?:\/\//i.test(trimmed) ? trimmed : `http://${trimmed}`;
  });
  const dialTargets = normalizeDialTargets(additionalDialTargets);
  const bootstrapDnsRecords = explicitOnly ? [] : Array.from(TESTNET_BOOTSTRAP_DNS_RECORDS);

  return `# Testnet multi-source bootstrap inputs.
# Nodes consume DNS bootnodes, DNS seed services, and bootstrap DNS records for peer discovery.
[global]
bootnodes = ${tomlArray(bootnodes)}
seed_servers = ${tomlArray(seeds)}
bootstrap_dns_records = ${tomlArray(bootstrapDnsRecords)}
additional_dial_targets = ${tomlArray(dialTargets)}
persistent_peers = ${tomlArray(dialTargets)}

[testnet]
core_rpc = ${tomlString(TESTNET_ENDPOINTS.coreRpc)}
core_ws = ${tomlString(TESTNET_ENDPOINTS.coreWs)}
wallet_api = ${tomlString(TESTNET_ENDPOINTS.walletApi)}
sxcp_api = ${tomlString(TESTNET_ENDPOINTS.sxcpApi)}

[security]
strict_tls = true
allow_unpinned_dev_endpoints = false
bootstrap_connectivity_required = false
`;
}

export function parseNodePortSettingsFromToml(contents) {
  const p2pPort = parsePortValue(readSectionValue(contents, 'network', 'p2p_port'))
    ?? splitHostPort(readSectionValue(contents, 'p2p', 'listen_address'))?.port
    ?? TESTNET_DEFAULT_PORT_SETTINGS.p2p;
  const rpcPort = parsePortValue(readSectionValue(contents, 'network', 'rpc_port'))
    ?? parsePortValue(readSectionValue(contents, 'rpc', 'http_port'))
    ?? splitHostPort(readSectionValue(contents, 'rpc', 'bind_address'))?.port
    ?? TESTNET_DEFAULT_PORT_SETTINGS.rpc;
  const wsPort = parsePortValue(readSectionValue(contents, 'network', 'ws_port'))
    ?? parsePortValue(readSectionValue(contents, 'rpc', 'ws_port'))
    ?? TESTNET_DEFAULT_PORT_SETTINGS.ws;
  const discoveryPort = parsePortValue(readSectionValue(contents, 'p2p', 'discovery_port'))
    ?? TESTNET_DEFAULT_PORT_SETTINGS.discovery;
  const metricsPort = splitHostPort(readSectionValue(contents, 'telemetry', 'metrics_bind'))?.port
    ?? TESTNET_DEFAULT_PORT_SETTINGS.metrics;

  return normalizeStoredPortSettings({
    p2p: p2pPort,
    rpc: rpcPort,
    ws: wsPort,
    discovery: discoveryPort,
    metrics: metricsPort,
  });
}

export async function readTestnetNodePortSettings(node) {
  const nodeTomlPath = resolveNodeTomlPath(node);
  if (!nodeTomlPath) {
    throw new Error('Generated node is missing a node.toml config path.');
  }

  const contents = await readTextFile(nodeTomlPath);
  return {
    nodeTomlPath,
    portSettings: parseNodePortSettingsFromToml(contents),
  };
}

export async function applyTestnetPortSettings(node, settings, options = {}) {
  const nodeTomlPath = resolveNodeTomlPath(node);
  if (!nodeTomlPath) {
    throw new Error('Generated node is missing a node.toml config path.');
  }

  let contents = await readTextFile(nodeTomlPath);
  const roleId = String(node?.role_id ?? node?.roleId ?? '').trim().toLowerCase();
  const generatedPortSettings = parseNodePortSettingsFromToml(contents);
  const { portSettings, source } = roleId === 'validator' && !usesStaticValidatorMesh(node)
    ? { portSettings: generatedPortSettings, source: 'generated-validator-config' }
    : resolveEffectiveNodePortSettings(node, settings);

  const rpcBindAddress = updateAddressPort(
    readSectionValue(contents, 'rpc', 'bind_address'),
    '127.0.0.1',
    portSettings.rpc,
  );
  const networkP2PListen = updateAddressPort(
    readSectionValue(contents, 'network', 'p2p_listen'),
    '0.0.0.0',
    portSettings.p2p,
  );
  const p2pListenAddress = updateAddressPort(
    readSectionValue(contents, 'p2p', 'listen_address'),
    '0.0.0.0',
    portSettings.p2p,
  );
  const currentPublicAddress = splitHostPort(readSectionValue(contents, 'p2p', 'public_p2p_address'))
    || splitHostPort(readSectionValue(contents, 'p2p', 'public_address'));
  const publicHost = String(options?.publicHost || '').trim()
    || currentPublicAddress?.host
    || String(node?.public_host || '').trim()
    || '127.0.0.1';
  if (roleId === 'validator' && isPrivateAdvertiseHost(publicHost)) {
    throw new Error('Validator public P2P address must be a public IP or DNS name, not localhost, LAN, VPN, or 0.0.0.0.');
  }
  const configuredPublicPort = parsePortValue(options?.publicP2pPort)
    ?? parsePortValue(portSettings.publicP2p)
    ?? parsePortValue(currentPublicAddress?.port);
  const publicP2pPort = usesFixedValidatorPorts(node)
    ? (configuredPublicPort ?? portSettings.p2p)
    : (portSettings.publicP2p ?? portSettings.p2p);
  const publicAddress = formatHostPort(publicHost, publicP2pPort);
  const discoveryPublicAddress = formatHostPort(publicHost, portSettings.discovery);
  const metricsBind = updateAddressPort(
    readSectionValue(contents, 'telemetry', 'metrics_bind'),
    '0.0.0.0',
    portSettings.metrics,
  );

  contents = replaceSectionValue(contents, 'network', 'p2p_port', String(portSettings.p2p));
  contents = replaceSectionValue(contents, 'network', 'rpc_port', String(portSettings.rpc));
  contents = replaceSectionValue(contents, 'network', 'ws_port', String(portSettings.ws));
  contents = replaceSectionValue(contents, 'network', 'p2p_listen', tomlString(networkP2PListen));
  contents = replaceSectionValue(contents, 'network', 'listen_addr', tomlString(networkP2PListen));
  contents = replaceSectionValue(contents, 'network', 'public_p2p_address', tomlString(publicAddress));
  contents = replaceSectionValue(contents, 'rpc', 'bind_address', tomlString(rpcBindAddress));
  contents = replaceSectionValue(contents, 'rpc', 'http_port', String(portSettings.rpc));
  contents = replaceSectionValue(contents, 'rpc', 'ws_port', String(portSettings.ws));
  contents = replaceSectionValue(contents, 'rpc', 'grpc_port', String(portSettings.rpc));
  contents = replaceSectionValue(contents, 'p2p', 'listen_address', tomlString(p2pListenAddress));
  contents = replaceSectionValue(contents, 'p2p', 'public_address', tomlString(publicAddress));
  contents = replaceSectionValue(contents, 'p2p', 'public_p2p_address', tomlString(publicAddress));
  contents = replaceSectionValue(contents, 'p2p', 'discovery_port', String(portSettings.discovery));
  contents = replaceSectionValue(contents, 'p2p', 'discovery_listen_address', tomlString(`0.0.0.0:${portSettings.discovery}`));
  contents = replaceSectionValue(contents, 'p2p', 'discovery_public_address', tomlString(discoveryPublicAddress));
  contents = replaceSectionValue(contents, 'p2p', 'enable_seed_registration', roleId === 'validator' ? 'true' : 'false');
  contents = replaceSectionValue(contents, 'p2p', 'enable_peer_exchange', 'true');
  contents = replaceSectionValue(contents, 'p2p', 'reject_private_advertise_addrs', 'true');
  contents = replaceSectionValue(contents, 'telemetry', 'metrics_bind', tomlString(metricsBind));

  await writeTextFile(nodeTomlPath, contents);

  const updatedFiles = [nodeTomlPath];
  const nginxConfPath = resolveNginxConfPath(node);
  if (nginxConfPath) {
    const nginxContents = await readTextFile(nginxConfPath);
    const nextNginxContents = replaceNginxUpstreamPort(
      replaceNginxUpstreamPort(nginxContents, `${node?.id}_rpc`, portSettings.rpc),
      `${node?.id}_ws`,
      portSettings.ws,
    );

    if (nextNginxContents !== nginxContents) {
      await writeTextFile(nginxConfPath, nextNginxContents);
      updatedFiles.push(nginxConfPath);
    }
  }

  return {
    nodeTomlPath,
    nginxConfPath,
    updatedFiles,
    portSlot: resolveNodePortSlot(node),
    portSettings,
    source,
  };
}

export async function applyStoredTestnetPortSettings(node, options = {}) {
  return applyTestnetPortSettings(node, readStoredTestnetPortSettings(), options);
}

export async function resolveValidatorPublicEndpoint(node, options = {}) {
  const explicitEndpoint = String(options?.publicEndpoint || '').trim();
  if (explicitEndpoint) {
    const normalized = parseDialAddress(explicitEndpoint);
    if (!normalized) {
      throw new Error('Validator public P2P endpoint must be formatted as host:port.');
    }
    const parsed = splitHostPort(normalized);
    if (!parsed || isPrivateAdvertiseHost(parsed.host)) {
      throw new Error('Validator public P2P endpoint must be public, not localhost, LAN, VPN, or 0.0.0.0.');
    }
    return normalized;
  }

  if (options?.publicHost) {
    return buildPublicP2pEndpoint(options.publicHost, options.publicP2pPort);
  }

  const nodeTomlPath = resolveNodeTomlPath(node);
  if (nodeTomlPath) {
    try {
      const contents = await readTextFile(nodeTomlPath);
      const configured = readSectionValue(contents, 'p2p', 'public_p2p_address')
        || readSectionValue(contents, 'p2p', 'public_address')
        || readSectionValue(contents, 'network', 'public_p2p_address');
      const normalized = parseDialAddress(String(configured || '').replace(/^"|"$/g, ''));
      const parsed = normalized ? splitHostPort(normalized) : null;
      if (normalized && parsed && !isPrivateAdvertiseHost(parsed.host)) {
        return normalized;
      }
    } catch {
      // Fall back to the node record below.
    }
  }

  return buildPublicP2pEndpoint(node?.public_host || node?.publicHost, options.publicP2pPort);
}

function firstText(...values) {
  const value = values.find((candidate) => String(candidate ?? '').trim().length > 0);
  return String(value ?? '').trim();
}

function finiteIntOrZero(value) {
  const number = Number(value);
  return Number.isFinite(number) && number >= 0 ? Math.trunc(number) : 0;
}

function seedServerUrlsForRegistration(networkProfile) {
  return seedServerUrls(networkProfile).map((entry) => String(entry).trim().replace(/\/+$/, ''));
}

function summarizeSeedResponses(action, responses = []) {
  const results = Array.isArray(responses) ? responses : [];
  const accepted = results.filter((result) => result?.payload?.accepted === true);
  const dialbackSuccess = accepted.filter((result) => String(result?.payload?.dialback_status || '').toLowerCase() === 'success');
  const failures = results
    .filter((result) => !result?.ok || result?.payload?.accepted === false || result?.error)
    .map((result) => {
      const seedId = result?.payload?.seed_id || result?.seedServer || result?.url || 'seed';
      const reason = result?.payload?.reason || result?.payload?.error || result?.error || `HTTP ${result?.status || 0}`;
      return `${seedId}: ${reason}`;
    });
  const recommendedPeers = Array.from(new Set(results.flatMap((result) => (
    Array.isArray(result?.payload?.recommended_peers) ? result.payload.recommended_peers : []
  )))).sort();

  return {
    action,
    ok: dialbackSuccess.length > 0,
    total: results.length,
    acceptedCount: accepted.length,
    dialbackSuccessCount: dialbackSuccess.length,
    failures,
    recommendedPeers,
    responses: results,
  };
}

export function buildValidatorSeedPayload(node, options = {}) {
  const validatorAddress = firstText(node?.node_address, node?.nodeAddress, options.validatorAddress);
  const publicEndpoint = firstText(options.publicEndpoint);
  if (!validatorAddress) {
    throw new Error('Validator seed registration requires a validator address.');
  }
  if (!publicEndpoint) {
    throw new Error('Validator seed registration requires a public endpoint.');
  }
  const parsedEndpoint = splitHostPort(publicEndpoint);
  const peerId = firstText(
    node?.peer_id,
    node?.peerId,
    node?.node_public_key,
    node?.nodePublicKey,
    node?.public_key,
    node?.publicKey,
    node?.id,
    validatorAddress,
  );
  const currentHeight = finiteIntOrZero(
    options.currentHeight
      ?? options.current_height
      ?? options.localChainHeight
      ?? options.local_chain_height,
  );
  const highestKnownHeight = finiteIntOrZero(
    options.highestKnownHeight
      ?? options.highest_known_height
      ?? options.targetHeight
      ?? options.target_height
      ?? currentHeight,
  );

  return {
    chain_id: TESTNET_CHAIN_ID,
    role: 'validator',
    node_name: firstText(node?.display_label, node?.displayLabel, node?.id, 'validator'),
    validator_address: validatorAddress,
    peer_id: peerId,
    node_public_key: firstText(node?.node_public_key, node?.nodePublicKey, node?.public_key, node?.publicKey, peerId),
    public_endpoint: publicEndpoint,
    listen_port: parsedEndpoint?.port || normalizePublicP2pPort(options.publicP2pPort),
    protocol_version: firstText(options.protocolVersion, options.protocol_version, 'synergy-p2p/1'),
    app_version: firstText(options.appVersion, options.app_version, 'node-control-panel'),
    current_height: currentHeight,
    highest_known_height: highestKnownHeight,
    sync_gap: Math.max(0, highestKnownHeight - currentHeight),
    health_status: firstText(options.healthStatus, options.health_status, 'pending'),
    timestamp: new Date().toISOString(),
    signature: firstText(options.signature),
  };
}

export async function checkValidatorPublicEndpoint(node, options = {}) {
  const publicEndpoint = await resolveValidatorPublicEndpoint(node, options);
  return checkPublicEndpointReachability(publicEndpoint);
}

export async function registerValidatorWithSeedServers(networkProfile, node, options = {}) {
  const publicEndpoint = await resolveValidatorPublicEndpoint(node, options);
  const payload = buildValidatorSeedPayload(node, {
    ...options,
    publicEndpoint,
    healthStatus: options.healthStatus || 'pending',
  });
  const seedServers = seedServerUrlsForRegistration(networkProfile);
  const responses = await registerSeedPeer(seedServers, payload);
  return {
    publicEndpoint,
    payload,
    seedServers,
    ...summarizeSeedResponses('register', responses),
  };
}

export async function heartbeatValidatorToSeedServers(networkProfile, node, options = {}) {
  const publicEndpoint = await resolveValidatorPublicEndpoint(node, options);
  const payload = buildValidatorSeedPayload(node, {
    ...options,
    publicEndpoint,
    healthStatus: options.healthStatus || 'healthy',
  });
  payload.sync_status = firstText(options.syncStatus, options.sync_status, 'starting');
  payload.peer_count = finiteIntOrZero(options.peerCount ?? options.peer_count);
  const seedServers = seedServerUrlsForRegistration(networkProfile);
  const responses = await heartbeatSeedPeer(seedServers, payload);
  return {
    publicEndpoint,
    payload,
    seedServers,
    ...summarizeSeedResponses('heartbeat', responses),
  };
}

export async function refreshTestnetBootstrapConfig(node, networkProfile) {
  const peersTomlPath = resolvePeersTomlPath(node);
  if (!peersTomlPath) {
    throw new Error('Generated node is missing a peers.toml config path.');
  }
  const roleId = String(node?.role_id ?? node?.roleId ?? '').trim().toLowerCase();
  const isValidator = roleId === 'validator';
  const validatorMeshOnly = usesStaticValidatorMesh(node);
  const sentryTargets = Array.isArray(SENTRY_UPSTREAMS[roleId]) ? SENTRY_UPSTREAMS[roleId] : [];
  const publicValidatorTargets = isValidator && !validatorMeshOnly ? PUBLIC_VALIDATOR_UPSTREAMS : [];
  const useExplicitOnly = validatorMeshOnly || sentryTargets.length > 0;

  const activePorts = await readTestnetNodePortSettings(node)
    .then((result) => result.portSettings)
    .catch(() => readStoredTestnetPortSettings());

  const { targets = [], failures = [] } = useExplicitOnly
    ? { targets: [], failures: [] }
    : await fetchSeedPeerTargets(seedServerUrls(networkProfile));
  const bootnodeTargets = new Set(
    normalizeDialTargets(bootnodeDialTargets(networkProfile)),
  );

  // Build the set of self-addresses to exclude from dial targets.  We need to
  // cover both the internal listen address (public_host:p2p) and the announced
  // public_address from node.toml (which may use a different external port for
  // validators behind NAT with unique external ports, e.g. validator 3 → 5622).
  const selfAddressCandidates = [];
  if (node?.public_host) {
    selfAddressCandidates.push(`${node.public_host}:${activePorts.p2p}`);
  }
  const nodeTomlPath = resolveNodeTomlPath(node);
  if (nodeTomlPath) {
    try {
      const nodeTomlContents = await readTextFile(nodeTomlPath);
      const announcedPublicAddress = readSectionValue(nodeTomlContents, 'p2p', 'public_address');
      if (announcedPublicAddress) {
        selfAddressCandidates.push(announcedPublicAddress.replace(/^"|"$/g, ''));
      }
    } catch {
      // Best-effort: if the toml cannot be read, rely on the host:p2p fallback.
    }
  }
  const selfTargets = new Set(normalizeDialTargets(selfAddressCandidates));

  const validatorTargets = CANONICAL_VALIDATOR_PEERS
    .filter((entry) => entry.address !== String(node?.node_address ?? node?.nodeAddress ?? '').trim())
    .map((entry) => `${entry.host}:${entry.port}`);
  const additionalDialTargets = validatorMeshOnly
    ? normalizeDialTargets(validatorTargets).filter((target) => !selfTargets.has(target))
    : sentryTargets.length > 0
      ? normalizeDialTargets(sentryTargets).filter((target) => !selfTargets.has(target))
      : normalizeDialTargets([...publicValidatorTargets, ...targets]).filter(
        (target) => !bootnodeTargets.has(target) && !selfTargets.has(target),
      );

  await writeTextFile(
    peersTomlPath,
    buildPeersToml(networkProfile, additionalDialTargets, { explicitOnly: useExplicitOnly }),
  );

  return {
    peersTomlPath,
    additionalDialTargets,
    failures,
  };
}
