function toFiniteNumber(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function parsePeerEndpoint(value) {
  const raw = String(value || '').trim();
  if (!raw) return null;

  if (raw.startsWith('[')) {
    const closing = raw.indexOf(']');
    if (closing === -1) return null;
    const host = raw.slice(1, closing).trim().toLowerCase();
    const port = toFiniteNumber(raw.slice(closing + 2));
    return host ? { host, port } : null;
  }

  const separator = raw.lastIndexOf(':');
  if (separator <= 0) {
    return { host: raw.toLowerCase(), port: null };
  }

  const host = raw.slice(0, separator).trim().toLowerCase();
  const port = toFiniteNumber(raw.slice(separator + 1));
  return host ? { host, port } : null;
}

function hasAssignedSynergyEndpoint(value) {
  const host = parsePeerEndpoint(value)?.host || '';
  return CANONICAL_VALIDATOR_HOSTS.has(host);
}

const CANONICAL_VALIDATOR_HOSTS = new Map([
  ['62.146.182.207', 'synv11qen9x0g9p0f2pqznpqzfrwkrgnsussdwmvs'],
  ['62.146.182.208', 'synv11s4wc6l4kg4jr0k5meg42cyzxa03cf863srt'],
  ['62.146.182.209', 'synv11e3ephsarcw6mey0fx5xtnygg2ewegnum4re'],
  ['73.79.66.255', 'synv11mka64uz049aekwhdvfrq6dvh75d0k7kmdp5'],
  ['194.163.183.166', 'synv11kguave5fpdpm9hru4acfvw0hcp4fcc7zv9f'],
  ['157.173.192.45', 'synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx'],
]);
const PEER_READY_GRACE_SECONDS = 25;
const PEER_STALE_SECONDS = 45;

function buildKnownValidatorAddressMap(nodes) {
  // Keys by publicHost → validatorAddress.
  // Each preassigned validator has a public IP. Private VPN hosts are metadata
  // only and are not treated as preferred connection or identity targets here.
  const byHost = new Map();
  (Array.isArray(nodes) ? nodes : []).forEach((node) => {
    const roleId = String(node?.role_id || '').trim().toLowerCase();
    const validatorAddress = String(node?.node_address || '').trim();
    const publicHost = String(node?.public_host || '').trim().toLowerCase();
    if (roleId !== 'validator' || !validatorAddress || !publicHost) {
      return;
    }
    if (!byHost.has(publicHost)) {
      byHost.set(publicHost, validatorAddress);
    }
  });
  CANONICAL_VALIDATOR_HOSTS.forEach((validatorAddress, host) => {
    if (!byHost.has(host)) {
      byHost.set(host, validatorAddress);
    }
  });
  return byHost;
}

function buildValidatorNodeMap(nodes) {
  const byAddress = new Map();
  (Array.isArray(nodes) ? nodes : []).forEach((node) => {
    const roleId = String(node?.role_id || '').trim().toLowerCase();
    const validatorAddress = String(node?.node_address || '').trim();
    if (roleId !== 'validator' || !validatorAddress) {
      return;
    }
    byAddress.set(validatorAddress, node);
  });
  return byAddress;
}

function formatPeerLastSeen(value) {
  const numeric = toFiniteNumber(value);
  if (numeric == null || numeric <= 0) {
    return 'Unknown';
  }

  const milliseconds = numeric < 1e12 ? numeric * 1000 : numeric;
  const timestamp = new Date(milliseconds);
  if (Number.isNaN(timestamp.getTime())) {
    return 'Unknown';
  }

  return timestamp.toLocaleString();
}

function inferValidatorAddress(peer, knownValidatorsByHost) {
  const explicit = String(peer?.validator_address || '').trim();
  if (explicit) {
    return explicit;
  }

  if (!(knownValidatorsByHost instanceof Map) || knownValidatorsByHost.size === 0) {
    return '';
  }

  // Check public_address first because it carries the node's announced public
  // endpoint. address is checked second as a fallback from peer telemetry.
  for (const entry of [peer?.public_address, peer?.address]) {
    const host = parsePeerEndpoint(entry)?.host;
    if (!host) continue;
    const match = knownValidatorsByHost.get(host);
    if (match) return match;
  }

  return '';
}

function choosePreferredPeerAddress(currentAddress, nextAddress, publicAddress) {
  const current = String(currentAddress || '').trim();
  const next = String(nextAddress || '').trim();
  const announced = String(publicAddress || '').trim();

  if (hasAssignedSynergyEndpoint(announced)) {
    return announced;
  }

  if (announced) {
    if (next === announced) return next;
    if (current === announced) return current;
  }

  return current || next;
}

function mergePeerEntries(current, next) {
  const publicAddress = current.publicAddress || next.publicAddress;
  return {
    id: current.id,
    address: choosePreferredPeerAddress(current.address, next.address, publicAddress),
    nodeId: current.nodeId || next.nodeId,
    publicAddress,
    validatorAddress: current.validatorAddress || next.validatorAddress,
    version: current.version || next.version,
    capabilities: Array.from(new Set([...current.capabilities, ...next.capabilities])),
    genesisHash: current.genesisHash || next.genesisHash,
    bestBlockHash: current.bestBlockHash || next.bestBlockHash,
    lastKnownHeight: Math.max(current.lastKnownHeight ?? 0, next.lastKnownHeight ?? 0) || null,
    lastSeen: Math.max(current.lastSeen ?? 0, next.lastSeen ?? 0) || null,
    blocksSent: Math.max(current.blocksSent, next.blocksSent),
    blocksReceived: Math.max(current.blocksReceived, next.blocksReceived),
    txsSent: Math.max(current.txsSent, next.txsSent),
    txsReceived: Math.max(current.txsReceived, next.txsReceived),
  };
}

function hasStrongPeerIdentity(peer) {
  return Boolean(
    peer.validatorAddress
      || peer.nodeId
      || peer.publicAddress
      || peer.version
      || peer.capabilities.length,
  );
}

function isLikelyEphemeralSocket(peer) {
  const endpoint = parsePeerEndpoint(peer.address);
  return !hasStrongPeerIdentity(peer) && endpoint?.port != null && endpoint.port >= 49152;
}

function peerHosts(peer) {
  const hosts = new Set();
  [peer.publicAddress, peer.address].forEach((entry) => {
    const endpoint = parsePeerEndpoint(entry);
    if (endpoint?.host) {
      hosts.add(endpoint.host);
    }
  });
  return hosts;
}

function shouldMergeEphemeralPeer(current, next) {
  const currentEphemeral = isLikelyEphemeralSocket(current);
  const nextEphemeral = isLikelyEphemeralSocket(next);

  if (currentEphemeral === nextEphemeral) {
    return false;
  }

  const weakPeer = currentEphemeral ? current : next;
  const strongPeer = currentEphemeral ? next : current;
  const weakHost = parsePeerEndpoint(weakPeer.address)?.host;
  if (!weakHost || !hasStrongPeerIdentity(strongPeer)) {
    return false;
  }

  return peerHosts(strongPeer).has(weakHost);
}

function findMergeTargetKey(dedupedPeers, normalized) {
  if (dedupedPeers.has(normalized.id)) {
    return normalized.id;
  }

  for (const [key, existing] of dedupedPeers.entries()) {
    if (shouldMergeEphemeralPeer(existing, normalized)) {
      return key;
    }
  }

  return normalized.id;
}

function normalizePeerInfoPayload(raw, knownValidatorsByHost) {
  const peers = Array.isArray(raw?.peers) ? raw.peers : [];
  const dedupedPeers = new Map();

  peers.forEach((peer, index) => {
    const inferredValidatorAddress = inferValidatorAddress(peer, knownValidatorsByHost);
    const normalized = {
      id: String(
        inferredValidatorAddress
          || peer?.node_id
          || peer?.public_address
          || peer?.address
          || `peer-${index}`,
      ).trim(),
      address: String(peer?.address || '').trim(),
      nodeId: String(peer?.node_id || '').trim(),
      publicAddress: String(peer?.public_address || '').trim(),
      validatorAddress: inferredValidatorAddress,
      version: String(peer?.version || '').trim(),
      capabilities: Array.isArray(peer?.capabilities)
        ? peer.capabilities.map((entry) => String(entry || '').trim()).filter(Boolean)
        : [],
      genesisHash: String(peer?.genesis_hash || '').trim(),
      bestBlockHash: String(peer?.best_block_hash || '').trim(),
      lastKnownHeight: toFiniteNumber(peer?.last_known_height),
      lastSeen: toFiniteNumber(peer?.last_seen),
      blocksSent: toFiniteNumber(peer?.blocks_sent) ?? 0,
      blocksReceived: toFiniteNumber(peer?.blocks_received) ?? 0,
      txsSent: toFiniteNumber(peer?.txs_sent) ?? 0,
      txsReceived: toFiniteNumber(peer?.txs_received) ?? 0,
    };

    const mergeKey = findMergeTargetKey(dedupedPeers, normalized);
    const existing = dedupedPeers.get(mergeKey);
    dedupedPeers.set(
      mergeKey,
      existing ? mergePeerEntries(existing, normalized) : { ...normalized, id: mergeKey },
    );
  });

  const normalizedPeers = Array.from(dedupedPeers.values())
    .filter((peer) => peer.validatorAddress && (
      hasAssignedSynergyEndpoint(peer.publicAddress)
      || hasAssignedSynergyEndpoint(peer.address)
    ))
    .sort((left, right) => {
      const leftSeen = left.lastSeen ?? 0;
      const rightSeen = right.lastSeen ?? 0;
      if (rightSeen !== leftSeen) {
        return rightSeen - leftSeen;
      }
      return left.id.localeCompare(right.id);
    });

  return {
    peerCount: normalizedPeers.length,
    peers: normalizedPeers,
  };
}

function peerMeshStatus(peer) {
  const ageSeconds = peerSeenAgeSeconds(peer);
  const hasStatusSync = Boolean(String(peer?.genesisHash || '').trim());

  if (ageSeconds != null && ageSeconds > PEER_STALE_SECONDS) {
    return {
      status: 'stale',
      label: 'Stale',
      tone: 'warn',
      detail: 'No recent heartbeat or status exchange.',
    };
  }

  if (hasStatusSync && (ageSeconds == null || ageSeconds <= PEER_READY_GRACE_SECONDS)) {
    return {
      status: 'ready',
      label: 'Status Synced',
      tone: 'good',
      detail: 'Recent status exchange completed and consensus metadata is present.',
    };
  }

  if (hasStatusSync) {
    return {
      status: 'connected',
      label: 'Aging',
      tone: 'warn',
      detail: 'Status sync exists, but the heartbeat is getting old.',
    };
  }

  return {
    status: 'handshake',
    label: 'Handshake Only',
    tone: 'warn',
    detail: 'Socket is connected, but this peer has not completed status sync yet.',
  };
}

function peerValidatorRuntimeStatus(peer, validatorNodesByAddress, nodeLiveById) {
  const validatorAddress = String(peer?.validatorAddress || '').trim();
  if (!validatorAddress) {
    return null;
  }

  const meshStatus = peerMeshStatus(peer);
  const node = validatorNodesByAddress instanceof Map
    ? validatorNodesByAddress.get(validatorAddress)
    : null;
  const live = node ? (nodeLiveById?.[node.id] || null) : null;
  if (live) {
    if (!live.is_running) {
      return { label: 'Offline', tone: 'bad' };
    }
    if (live.local_rpc_ready === false) {
      return { label: 'Starting', tone: 'warn' };
    }
    if ((Number(live.sync_gap) || 0) > 0) {
      return { label: 'Syncing', tone: 'warn' };
    }
    if (meshStatus.status === 'ready') {
      return { label: 'Ready', tone: 'good' };
    }
    if (meshStatus.status === 'connected') {
      return { label: 'Connected', tone: 'warn' };
    }
    return { label: meshStatus.label, tone: meshStatus.tone };
  }

  if (meshStatus.status === 'ready') {
    return { label: 'Ready', tone: 'good' };
  }
  if (meshStatus.status === 'connected') {
    return { label: 'Connected', tone: 'warn' };
  }
  return { label: meshStatus.label, tone: meshStatus.tone };
}

function peerSeenAgeSeconds(peer) {
  const lastSeen = toFiniteNumber(peer?.lastSeen);
  if (lastSeen == null || lastSeen <= 0) {
    return null;
  }

  const timestampMs = lastSeen < 1e12 ? lastSeen * 1000 : lastSeen;
  const ageSeconds = (Date.now() - timestampMs) / 1000;
  return Number.isFinite(ageSeconds) ? ageSeconds : null;
}

export {
  buildKnownValidatorAddressMap,
  buildValidatorNodeMap,
  formatPeerLastSeen,
  normalizePeerInfoPayload,
  peerMeshStatus,
  peerValidatorRuntimeStatus,
};
