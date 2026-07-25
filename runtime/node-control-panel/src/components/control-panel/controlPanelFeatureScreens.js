export const FEATURE_SCREEN_GROUPS = [
  {
    id: 'monitor',
    label: 'Monitor',
    items: ['alerts'],
  },
  {
    id: 'validator',
    label: 'Validator',
    items: ['validator', 'security', 'identity'],
  },
  {
    id: 'protocol',
    label: 'Protocol',
    items: ['consensus', 'dag', 'transactions'],
  },
  {
    id: 'system',
    label: 'System',
    items: ['storage', 'api', 'maintenance', 'diagnostics', 'config'],
  },
];

export const FEATURE_SCREENS = {
  alerts: {
    key: 'alerts',
    path: '/alerts',
    icon: 'notification_important',
    label: 'Alerts',
    title: 'Incident Response & Alerts',
    eyebrow: 'Live incidents',
    description: 'Operator incidents generated from runtime logs, readiness checks, and RPC health.',
    jarvis: 'This screen uses current runtime evidence only: log severity, failed readiness checks, and local RPC probes.',
    tone: 'warn',
    modeTitles: {
      advanced: 'Alerts',
      developer: 'Alerts + Incidents',
    },
    modeCopy: {
      basic: 'Plain-language alerts and the safest next action.',
      advanced: 'Incident severity, source evidence, and runbook actions.',
      developer: 'Incident payloads, probe responses, and raw event evidence.',
    },
  },
  validator: {
    key: 'validator',
    path: '/validator',
    icon: 'verified_user',
    label: 'Validator',
    title: 'Validator Lifecycle Management',
    eyebrow: 'Validator state',
    description: 'Lifecycle state, activation readiness, duty evidence, and validator RPC payloads.',
    jarvis: 'This screen reads validator readiness and validator RPC state before enabling lifecycle actions.',
    tone: 'purple',
    modeTitles: {
      advanced: 'Validator Lifecycle',
      developer: 'Validator Lifecycle',
    },
    modeCopy: {
      basic: 'Validator status and safe next steps.',
      advanced: 'Activation readiness, validator performance, and queue state.',
      developer: 'Raw validator RPC responses and activation guard data.',
    },
  },
  security: {
    key: 'security',
    path: '/security',
    icon: 'shield',
    label: 'Security',
    title: 'Identity + Security',
    eyebrow: 'Signing safety',
    description: 'Identity files, key presence, slashing RPC data, and runtime guardrails.',
    jarvis: 'This screen checks the actual workspace identity files and validator slashing state.',
    tone: 'good',
    modeTitles: {
      advanced: 'Identity + Security',
      developer: 'Security + Slashing',
    },
    modeCopy: {
      basic: 'Identity and safety status for this node.',
      advanced: 'Identity, keys, slashing, and readiness evidence.',
      developer: 'Security payloads, key-file inventory, and slashing inspector.',
    },
  },
  identity: {
    key: 'identity',
    path: '/identity',
    icon: 'key',
    label: 'Identity',
    title: 'Identity + Keys',
    eyebrow: 'Developer identity',
    description: 'Raw identity metadata, key file inventory, and validator address proofs.',
    jarvis: 'Identity is developer-only because it exposes raw key-path and validator metadata.',
    developerOnly: true,
    tone: 'purple',
    modeCopy: {
      developer: 'Raw identity, key-path, validator address, and RPC proof data.',
    },
  },
  consensus: {
    key: 'consensus',
    path: '/consensus',
    icon: 'account_tree',
    label: 'Consensus',
    title: 'Consensus Inspector',
    eyebrow: 'Finality evidence',
    description: 'Consensus state from block-validation RPC, validator activity, latest block, and sync status.',
    jarvis: 'Consensus status is derived from local chain, validator activity, and validation RPC data.',
    tone: 'cyan',
    modeTitles: {
      advanced: 'Consensus',
      developer: 'Consensus Inspector',
    },
    modeCopy: {
      basic: 'Whether the node is close enough to participate.',
      advanced: 'Block validation, validator activity, and sync status.',
      developer: 'Raw finality, validator, and latest-block RPC payloads.',
    },
  },
  dag: {
    key: 'dag',
    path: '/dag',
    icon: 'schema',
    label: 'DAG',
    title: 'DAG Graph',
    eyebrow: 'Block graph',
    description: 'Graph built from recent local block parent links returned by the node RPC.',
    jarvis: 'This graph is generated from actual block hashes and parent hashes returned by the runtime.',
    tone: 'cyan',
    modeTitles: {
      advanced: 'DAG Explorer',
      developer: 'DAG Graph',
    },
    modeCopy: {
      basic: 'Recent block graph and convergence signals.',
      advanced: 'Local block parent graph, producer, and transaction counts.',
      developer: 'Raw graph nodes, parent links, and block payloads.',
    },
  },
  transactions: {
    key: 'transactions',
    path: '/transactions',
    icon: 'swap_horiz',
    label: 'Transactions',
    title: 'Transaction Pool',
    eyebrow: 'Transaction flow',
    description: 'Pending pool, latest block transactions, gas price, and transaction RPC probes.',
    jarvis: 'This screen reads the local transaction pool and recent block transaction payloads.',
    tone: 'cyan',
    modeTitles: {
      advanced: 'Transactions',
      developer: 'Transaction Pool',
    },
    modeCopy: {
      basic: 'Pending transactions and recent block activity.',
      advanced: 'Pool pressure, latest block transactions, and fee probes.',
      developer: 'Raw pool, block transaction, gas, and receipt RPC payloads.',
    },
  },
  storage: {
    key: 'storage',
    path: '/storage',
    icon: 'storage',
    label: 'Storage',
    title: 'Storage + Snapshots',
    eyebrow: 'Workspace storage',
    description: 'Actual workspace folder sizes, file counts, disk capacity, and chain data footprint.',
    jarvis: 'Storage data is read from the local workspace and host disk.',
    tone: 'blue',
    modeTitles: {
      advanced: 'Storage + Snapshots',
      developer: 'Storage Internals',
    },
    modeCopy: {
      basic: 'Local data size and disk headroom.',
      advanced: 'Workspace sections, chain data, logs, and disk capacity.',
      developer: 'Per-folder bytes, file counts, and raw storage snapshot.',
    },
  },
  api: {
    key: 'api',
    path: '/api',
    icon: 'terminal',
    label: 'API/RPC',
    title: 'API/RPC Lab',
    eyebrow: 'RPC probes',
    description: 'Live JSON-RPC method probes against the selected node endpoint.',
    jarvis: 'This lab proves which RPC methods are responding on the selected node.',
    tone: 'purple',
    modeTitles: {
      advanced: 'API/RPC',
      developer: 'API/RPC Lab',
    },
    modeCopy: {
      basic: 'RPC status in plain language.',
      advanced: 'Method probes, latency, and endpoint state.',
      developer: 'Raw request results for supported JSON-RPC methods.',
    },
  },
  maintenance: {
    key: 'maintenance',
    path: '/maintenance',
    icon: 'build_circle',
    label: 'Maintenance',
    title: 'Maintenance',
    eyebrow: 'Controlled actions',
    description: 'Restart, rejoin, sync, readiness, and maintenance actions tied to live runtime state.',
    jarvis: 'Maintenance actions are wired to the normal control-service action path and audit trail.',
    tone: 'warn',
    modeCopy: {
      basic: 'Safe repair actions for this node.',
      advanced: 'Restart, rejoin, sync, readiness, and action receipts.',
      developer: 'Action receipts plus raw maintenance probes.',
    },
  },
  diagnostics: {
    key: 'diagnostics',
    path: '/diagnostics',
    icon: 'troubleshoot',
    label: 'Diagnostics',
    title: 'Diagnostics',
    eyebrow: 'Machine checks',
    description: 'Process, port, disk, RPC, bootstrap, log, and support diagnostics from this machine.',
    jarvis: 'Diagnostics runs real machine checks and keeps the raw output visible in Developer view.',
    developerOnly: true,
    tone: 'warn',
    modeCopy: {
      developer: 'Port listeners, processes, disk usage, local RPC probes, logs, and config evidence.',
    },
  },
  config: {
    key: 'config',
    path: '/config',
    icon: 'tune',
    label: 'Configuration',
    title: 'Configuration',
    eyebrow: 'Raw config',
    description: 'Actual node.toml, peers.toml, node.env, genesis, and runtime manifest data.',
    jarvis: 'Configuration shows the files this node is actually using.',
    developerOnly: true,
    tone: 'purple',
    modeCopy: {
      developer: 'Raw config files, endpoint values, bootstrap lists, and validation probes.',
    },
  },
};

export const FEATURE_ROUTES = FEATURE_SCREEN_GROUPS
  .flatMap((group) => group.items)
  .map((key) => FEATURE_SCREENS[key])
  .filter(Boolean);

export function getFeatureScreenByKey(key) {
  return FEATURE_SCREENS[key] || null;
}

export function getFeatureScreenByPathname(pathname) {
  const normalizedPath = String(pathname || '').replace(/\/+$/, '') || '/';
  return FEATURE_ROUTES.find((screen) => normalizedPath === screen.path || normalizedPath.startsWith(`${screen.path}/`)) || null;
}

export function featureNavItemsForGroup(groupId) {
  const group = FEATURE_SCREEN_GROUPS.find((entry) => entry.id === groupId);
  if (!group) {
    return [];
  }
  return group.items.map((key) => FEATURE_SCREENS[key]).filter(Boolean);
}
