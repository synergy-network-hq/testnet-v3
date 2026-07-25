import {
  formatPeerLastSeen,
  peerMeshStatus,
  peerValidatorRuntimeStatus,
} from '../../lib/testnetPeerInfo';

export function safeArray(value) {
  return Array.isArray(value) ? value : [];
}

export function truncateMiddle(value, start = 8, end = 5) {
  const text = String(value || '').trim();
  if (!text) {
    return 'Not reported';
  }
  if (text.length <= start + end + 3) {
    return text;
  }
  return `${text.slice(0, start)}...${text.slice(-end)}`;
}

export function formatNumber(value, options = {}) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return '—';
  }
  return new Intl.NumberFormat(undefined, options).format(numeric);
}

export function formatPercent(value, maximumFractionDigits = 1) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return '—';
  }
  return `${numeric.toFixed(maximumFractionDigits)}%`;
}

export function formatTimestamp(value) {
  if (!value) {
    return 'Unknown';
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return String(value);
  }

  return date.toLocaleString();
}

export function formatRuntimeDuration(secondsValue) {
  const totalSeconds = Number(secondsValue);
  if (!Number.isFinite(totalSeconds) || totalSeconds <= 0) {
    return 'Not running';
  }

  const days = Math.floor(totalSeconds / 86400);
  const hours = Math.floor((totalSeconds % 86400) / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);

  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m`;
  return '<1m';
}

export function formatScore(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return '—';
  }
  return `${numeric.toFixed(1)}/100`;
}

export function roleTypeLabel(roleDisplayName) {
  const value = String(roleDisplayName || '').trim();
  if (!value) {
    return 'Node';
  }
  return value.replace(/\s+node$/i, '').trim();
}

export function classTierLabel(role) {
  const classId = Number(role?.class_id || 0);
  if (!Number.isFinite(classId) || classId < 1 || classId > 5) {
    return 'Class Unknown';
  }

  const roman = ['I', 'II', 'III', 'IV', 'V'];
  return `Class ${roman[classId - 1]}`;
}

export function statusTone(value) {
  const text = String(value || '').toLowerCase();
  if (text.includes('online') || text.includes('healthy') || text.includes('ready') || text.includes('connected') || text.includes('optimal')) {
    return 'good';
  }
  if (text.includes('sync') || text.includes('starting') || text.includes('catch') || text.includes('progress') || text.includes('aging')) {
    return 'warn';
  }
  if (text.includes('offline') || text.includes('stale') || text.includes('error') || text.includes('attention') || text.includes('fail')) {
    return 'bad';
  }
  return 'neutral';
}

export function nodeRuntimeLabel(nodeLive) {
  if (!nodeLive?.is_running) {
    return 'Offline';
  }
  if (nodeLive.local_rpc_ready === false) {
    return 'Starting';
  }
  if ((Number(nodeLive.sync_gap) || 0) > 0) {
    return 'Syncing';
  }
  return 'Healthy';
}

export function nodeRuntimeTone(nodeLive) {
  return statusTone(nodeRuntimeLabel(nodeLive));
}

export function effectiveLocalChainHeight(nodeLive) {
  if (nodeLive?.local_chain_height_verified === false) {
    return null;
  }
  return nodeLive?.local_chain_height ?? null;
}

export function nodeBlockHeightValue(nodeLive, liveStatus) {
  if (nodeLive?.is_running) {
    return effectiveLocalChainHeight(nodeLive);
  }
  return effectiveLocalChainHeight(nodeLive) ?? liveStatus?.public_chain_height ?? null;
}

export function nodeBlockHeightDetail(nodeLive, liveStatus) {
  if (!nodeLive?.is_running) {
    return `Network tip ${formatNumber(liveStatus?.public_chain_height)}`;
  }

  if (nodeLive.local_rpc_ready === false) {
    return nodeLive?.local_rpc_status || 'Local RPC is waking up.';
  }

  const gap = Number(nodeLive?.sync_gap || 0);
  if (gap > 0) {
    return `${formatNumber(gap)} blocks behind`;
  }

  return 'At the live chain head';
}

export function nodeSyncPercent(nodeLive, liveStatus) {
  if (!nodeLive?.is_running) {
    return 0;
  }

  const networkHeight = Number(nodeLive?.sync_target_height ?? liveStatus?.public_chain_height);
  const localHeight = Number(effectiveLocalChainHeight(nodeLive));

  if (Number.isFinite(networkHeight) && networkHeight > 0 && Number.isFinite(localHeight) && localHeight >= 0) {
    return Math.max(0, Math.min(100, (localHeight / networkHeight) * 100));
  }

  if ((Number(nodeLive?.sync_gap) || 0) <= 0 && nodeLive?.local_rpc_ready !== false) {
    return 100;
  }

  return 0;
}

export function localRpcEndpointForNode(node, nodeLive) {
  if (nodeLive?.rpc_endpoint) {
    return nodeLive.rpc_endpoint;
  }

  const usesFixedValidatorPort = String(node?.role_id || '').trim().toLowerCase() === 'validator';
  const slot = Number(node?.port_slot || 0);
  return `http://127.0.0.1:${usesFixedValidatorPort ? 5640 : (5640 + slot)}`;
}

export async function queryLocalRpc(endpoint, method, params = []) {
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method,
      params,
    }),
  });

  if (!response.ok) {
    throw new Error(`${method} returned HTTP ${response.status}`);
  }

  const payload = await response.json();
  if (payload?.error) {
    throw new Error(payload.error?.message || JSON.stringify(payload.error));
  }
  return payload?.result;
}

export function buildMetricBars(items) {
  const numericItems = safeArray(items).map((item) => ({
    ...item,
    numericValue: Number(item?.numericValue),
  }));
  const max = Math.max(
    1,
    ...numericItems.map((item) => (Number.isFinite(item.numericValue) ? item.numericValue : 0)),
  );

  return numericItems.map((item) => ({
    ...item,
    width: Number.isFinite(item.numericValue) ? Math.max(8, (item.numericValue / max) * 100) : 8,
  }));
}

export function logLevelTone(level) {
  const normalized = String(level || '').trim().toUpperCase();
  if (normalized === 'ERROR') return 'bad';
  if (normalized === 'WARN') return 'warn';
  if (normalized === 'DEBUG' || normalized === 'TRACE') return 'neutral';
  return 'good';
}

export function simplifyLogEntry(entry, mode = 'basic') {
  const level = String(entry?.level || 'INFO').toUpperCase();
  const rawMessage = String(entry?.message || entry?.raw || 'System event').trim();
  const lower = rawMessage.toLowerCase();

  let title = rawMessage;
  let detail = rawMessage;

  if (/connected to peer|paired with|registered with seed/i.test(rawMessage)) {
    title = mode === 'basic' ? 'Connected to the network' : 'Peer link updated';
    detail = rawMessage;
  } else if (/block reward|new block|block synchronized|block proposed/i.test(rawMessage)) {
    title = mode === 'basic' ? 'Block activity detected' : 'Chain activity';
    detail = rawMessage;
  } else if (/starting|initialized|workspace created|runtime is active/i.test(rawMessage)) {
    title = mode === 'basic' ? 'Node is starting up' : 'Runtime initialization';
    detail = rawMessage;
  } else if (level === 'ERROR') {
    title = mode === 'basic' ? 'Jarvis flagged an issue' : 'Runtime error';
    detail = rawMessage;
  } else if (level === 'WARN') {
    title = mode === 'basic' ? 'Something needs attention' : 'Runtime warning';
    detail = rawMessage;
  } else if (lower.includes('sync')) {
    title = mode === 'basic' ? 'Sync progress updated' : 'Sync telemetry updated';
    detail = rawMessage;
  }

  return {
    id: `${entry?.source_id || 'log'}-${entry?.timestamp_utc || rawMessage}`,
    title,
    detail,
    time: formatTimestamp(entry?.timestamp_utc),
    tone: logLevelTone(level),
    level,
    module: entry?.module || 'runtime',
    sourceLabel: entry?.source_label || 'Node',
    metadata: entry?.metadata || null,
    raw: rawMessage,
  };
}

export function buildLogLevelCounts(entries = []) {
  return safeArray(entries).reduce((counts, entry) => {
    const key = String(entry?.level || 'INFO').toUpperCase();
    counts[key] = (counts[key] || 0) + 1;
    return counts;
  }, {});
}

export function buildTopologyModel({
  selectedNode,
  selectedNodeLive,
  localPeerInfo,
  liveStatus,
  validatorNodesByAddress,
  nodeLiveById,
  viewMode = 'basic',
}) {
  const peerLimit = viewMode === 'developer' ? 10 : viewMode === 'advanced' ? 8 : 6;
  const rawPeers = [];

  safeArray(localPeerInfo?.peers).forEach((peer) => {
    const runtimeStatus = peerValidatorRuntimeStatus(peer, validatorNodesByAddress, nodeLiveById)
      || peerMeshStatus(peer);
    rawPeers.push({
      id: peer.id,
      label: truncateMiddle(peer.validatorAddress || peer.publicAddress || peer.address, 8, 5),
      title: peer.publicAddress || peer.address || peer.validatorAddress,
      metric: peer.lastKnownHeight != null ? `Block ${formatNumber(peer.lastKnownHeight)}` : formatPeerLastSeen(peer.lastSeen),
      tone: runtimeStatus?.tone || 'neutral',
      status: runtimeStatus?.label || 'Connected',
    });
  });

  if (!rawPeers.length) {
    safeArray(liveStatus?.bootnodes).forEach((entry, index) => {
      rawPeers.push({
        id: entry?.host || `bootnode-${index}`,
        label: entry?.host || `Bootnode ${index + 1}`,
        title: entry?.detail || entry?.host || 'Bootstrap relay',
        metric: entry?.latency_ms != null ? `${entry.latency_ms} ms` : 'Waiting for probe',
        tone: entry?.reachable ? 'good' : 'warn',
        status: entry?.reachable ? 'Reachable' : 'Pending',
      });
    });
  }

  const visiblePeers = rawPeers.slice(0, peerLimit).map((peer, index, list) => {
    const angle = (Math.PI * 2 * index) / Math.max(list.length, 1);
    return {
      ...peer,
      x: 50 + (36 * Math.cos(angle)),
      y: 50 + (30 * Math.sin(angle)),
    };
  });

  return {
    center: {
      label: selectedNode?.display_label || roleTypeLabel(selectedNode?.role_display_name) || 'Your node',
      detail: nodeRuntimeLabel(selectedNodeLive),
      metric: nodeBlockHeightValue(selectedNodeLive, liveStatus) != null
        ? `Block ${formatNumber(nodeBlockHeightValue(selectedNodeLive, liveStatus))}`
        : 'Waiting for chain data',
    },
    peers: visiblePeers,
    overflowCount: Math.max(rawPeers.length - visiblePeers.length, 0),
  };
}

export function buildLatencyBars({ localPeerInfo, liveStatus }) {
  const peerLatency = safeArray(localPeerInfo?.peers)
    .map((peer, index) => {
      const status = peerMeshStatus(peer);
      const lastSeen = Number(peer?.lastSeen);
      const metricValue = Number.isFinite(lastSeen) ? Math.max(1, 100 - Math.min(95, Math.round((Date.now() - (lastSeen < 1e12 ? lastSeen * 1000 : lastSeen)) / 1000))) : 10;
      return {
        id: peer.id || `peer-${index}`,
        label: truncateMiddle(peer.validatorAddress || peer.publicAddress || peer.address, 6, 4),
        value: status.label,
        detail: status.detail,
        numericValue: metricValue,
        tone: status.tone,
      };
    });

  if (peerLatency.length) {
    return buildMetricBars(peerLatency);
  }

  return buildMetricBars(
    safeArray(liveStatus?.bootnodes).map((entry, index) => ({
      id: entry?.host || `bootnode-${index}`,
      label: entry?.host || `Bootnode ${index + 1}`,
      value: entry?.latency_ms != null ? `${entry.latency_ms} ms` : 'Waiting',
      detail: entry?.detail || 'Bootstrap probe',
      numericValue: entry?.latency_ms != null ? Math.max(1, 1000 - entry.latency_ms) : 1,
      tone: entry?.reachable ? 'good' : 'warn',
    })),
  );
}

export function networkHealthSummary(liveStatus) {
  const publicRpcOnline = liveStatus?.public_rpc_online === true;
  const healthyBootnodes = safeArray(liveStatus?.bootnodes).filter((entry) => entry?.reachable).length;
  const totalBootnodes = safeArray(liveStatus?.bootnodes).length;

  if (publicRpcOnline && totalBootnodes > 0 && healthyBootnodes === totalBootnodes) {
    return {
      title: 'Network looks healthy',
      detail: 'Public RPC is online and every bootstrap relay answered the latest probe.',
      tone: 'good',
    };
  }

  if (publicRpcOnline || healthyBootnodes > 0) {
    return {
      title: 'Network is reachable',
      detail: 'Some bootstrap services are online, but there may still be sync or peer gaps to clear.',
      tone: 'warn',
    };
  }

  return {
    title: 'Network needs attention',
    detail: 'Bootstrap reachability and public RPC probes are both failing right now.',
    tone: 'bad',
  };
}
