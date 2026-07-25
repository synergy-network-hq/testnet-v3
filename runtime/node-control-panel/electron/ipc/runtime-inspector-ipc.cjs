const dns = require('node:dns/promises');
const net = require('node:net');
const geoip = require('geoip-lite');

const geoCache = new Map();

function parseEndpoint(value) {
  const raw = String(value || '').trim();
  if (!raw) {
    return null;
  }

  if (raw.startsWith('[')) {
    const closing = raw.indexOf(']');
    if (closing === -1) {
      return null;
    }
    const host = raw.slice(1, closing).trim();
    return host ? { host, port: raw.slice(closing + 2) } : null;
  }

  const lastSeparator = raw.lastIndexOf(':');
  if (lastSeparator <= 0) {
    return { host: raw, port: null };
  }

  return {
    host: raw.slice(0, lastSeparator),
    port: raw.slice(lastSeparator + 1),
  };
}

function classifyRegion(latitude, longitude) {
  if (!Number.isFinite(latitude) || !Number.isFinite(longitude)) {
    return 'Unknown';
  }
  if (longitude < -30) {
    return latitude >= 0 ? 'North America' : 'South America';
  }
  if (longitude >= -30 && longitude < 30) {
    return latitude >= 20 ? 'Europe' : 'Africa';
  }
  if (longitude >= 30 && longitude < 60 && latitude < 36) {
    return 'Middle East';
  }
  return 'Asia Pacific';
}

function healthTone(health) {
  if (health === 'healthy') return 'good';
  if (health === 'degraded' || health === 'stale') return 'warn';
  if (health === 'offline') return 'bad';
  return 'purple';
}

function resolveHealth(peer) {
  const lastSeen = Number(peer?.lastSeen || 0);
  const now = Date.now();
  const timestampMs = lastSeen > 0 && lastSeen < 1e12 ? lastSeen * 1000 : lastSeen;
  const ageSeconds = timestampMs > 0 ? Math.max(0, Math.round((now - timestampMs) / 1000)) : null;

  if (ageSeconds == null) {
    return {
      health: 'pending',
      sessionAgeSec: null,
    };
  }
  if (ageSeconds <= 25) {
    return {
      health: 'healthy',
      sessionAgeSec: ageSeconds,
    };
  }
  if (ageSeconds <= 55) {
    return {
      health: 'degraded',
      sessionAgeSec: ageSeconds,
    };
  }
  return {
    health: 'stale',
    sessionAgeSec: ageSeconds,
  };
}

function classifyRole(peer, context = {}) {
  const label = `${peer?.label || ''} ${peer?.publicAddress || ''} ${peer?.address || ''}`.toLowerCase();
  const bootnodeHosts = new Set(
    (Array.isArray(context?.bootnodes) ? context.bootnodes : [])
      .map((entry) => String(entry?.host || '').toLowerCase())
      .filter(Boolean),
  );
  const host = String(parseEndpoint(peer?.publicAddress || peer?.address)?.host || '').toLowerCase();

  if (bootnodeHosts.has(host) || /bootnode/.test(label)) return 'bootnode';
  if (/seed/.test(label)) return 'seed';
  if (/rpc/.test(label)) return 'rpc';
  if (/observer/.test(label)) return 'observer';
  if (peer?.validatorAddress) return 'validator';
  return 'unknown';
}

async function resolveGeoForHost(host) {
  const normalizedHost = String(host || '').trim().toLowerCase();
  if (!normalizedHost) {
    return null;
  }
  if (geoCache.has(normalizedHost)) {
    return geoCache.get(normalizedHost);
  }

  let ip = normalizedHost;
  try {
    if (!net.isIP(normalizedHost)) {
      const lookup = await dns.lookup(normalizedHost);
      ip = lookup.address;
    }
  } catch {
    // Keep host as-is and return no geographic point if it cannot be resolved.
  }

  const geo = net.isIP(ip) ? geoip.lookup(ip) : null;

  const result = geo
    ? { ip, ...geo }
    : { ip, ll: null, country: '', region: 'Unmapped', city: '' };

  geoCache.set(normalizedHost, result);
  return result;
}

function buildRegionSummary(points) {
  const summary = new Map();
  points.forEach((point) => {
    const current = summary.get(point.region) || {
      region: point.region,
      peerCount: 0,
      healthyCount: 0,
      degradedCount: 0,
      pendingCount: 0,
      healthTone: 'neutral',
    };
    current.peerCount += 1;
    if (point.health === 'healthy') current.healthyCount += 1;
    if (point.health === 'degraded' || point.health === 'stale') current.degradedCount += 1;
    if (point.health === 'pending') current.pendingCount += 1;
    current.healthTone = current.degradedCount > 0
      ? 'warn'
      : current.pendingCount > 0
        ? 'purple'
        : 'good';
    summary.set(point.region, current);
  });
  return Array.from(summary.values()).sort((left, right) => right.peerCount - left.peerCount);
}

async function resolvePeerTopology(input = {}) {
  const peers = Array.isArray(input?.peers) ? input.peers : [];
  const localNodeLabel = input?.localNode?.display_label || input?.localNode?.label || 'Local node';
  const localNodeHost = parseEndpoint(input?.localNode?.public_host || input?.localNode?.publicAddress)?.host || '';
  const localGeo = await resolveGeoForHost(localNodeHost);
  const localHasCoordinates = Array.isArray(localGeo?.ll);
  const localNode = {
    label: localNodeLabel,
    latitude: localHasCoordinates ? Number(localGeo.ll[0]) : null,
    longitude: localHasCoordinates ? Number(localGeo.ll[1]) : null,
  };

  const points = await Promise.all(peers.map(async (peer, index) => {
    const endpoint = parseEndpoint(peer?.publicAddress || peer?.address);
    const geo = await resolveGeoForHost(endpoint?.host || '');
    const hasCoordinates = Array.isArray(geo?.ll);
    const latitude = hasCoordinates ? Number(geo.ll[0]) : null;
    const longitude = hasCoordinates ? Number(geo.ll[1]) : null;
    const healthState = resolveHealth(peer);
    const region = hasCoordinates ? classifyRegion(latitude, longitude) : 'Unmapped';
    const role = classifyRole(peer, input);
    const label = peer?.validatorAddress
      || peer?.publicAddress
      || peer?.address
      || `Peer ${index + 1}`;

    return {
      id: peer?.id || label,
      peerId: peer?.id || label,
      label,
      shortLabel: String(label).length > 16 ? `${String(label).slice(0, 10)}…` : label,
      role,
      region,
      countryCode: geo?.country || '',
      city: geo?.city || '',
      latitude,
      longitude,
      latencyMs: peer?.latencyMs != null ? Number(peer.latencyMs) : null,
      health: healthState.health,
      healthTone: healthTone(healthState.health),
      direction: peer?.direction || 'both',
      sessionAgeSec: healthState.sessionAgeSec,
      lastSeenAt: healthState.sessionAgeSec == null
        ? 'Unknown'
        : new Date(Date.now() - (healthState.sessionAgeSec * 1000)).toLocaleString(),
      transport: peer?.transport || 'p2p',
      protocolVersion: peer?.version || '',
      peerVersion: peer?.version || '',
      raw: peer,
    };
  })).then((items) => items.filter((point) => (
    Number.isFinite(point.latitude) && Number.isFinite(point.longitude)
  )));

  const regionSummary = buildRegionSummary(points);
  const routes = Number.isFinite(localNode.latitude) && Number.isFinite(localNode.longitude)
    ? points.map((point) => ({
      fromNodeId: input?.localNode?.id || 'local-node',
      toPeerId: point.id,
      from: [localNode.longitude, localNode.latitude],
      to: [point.longitude, point.latitude],
      latencyMs: point.latencyMs,
      health: point.health,
      healthTone: point.healthTone,
    }))
    : [];

  return {
    localNode,
    points,
    regionSummary,
    routes,
    resolvedAt: Date.now(),
  };
}

function setupRuntimeInspectorIpc(ipcMain) {
  ipcMain.handle('desktop:resolve-peer-topology', (_event, input = {}) =>
    resolvePeerTopology(input),
  );
}

module.exports = {
  setupRuntimeInspectorIpc,
};
