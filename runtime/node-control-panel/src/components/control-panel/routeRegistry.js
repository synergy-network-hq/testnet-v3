export const VIEW_IDS = ['basic', 'advanced', 'developer'];

export const DEVELOPER_ONLY_PATHS = ['/identity', '/diagnostics', '/config'];

export const BASIC_NAV_GROUPS = [
  {
    id: 'basic-primary',
    label: 'Navigation',
    layout: 'single',
    items: [
      { to: '/', key: 'dashboard', label: 'Dashboard', icon: 'space_dashboard', end: true },
      { to: '/node', key: 'details', label: 'My Node', icon: 'dns' },
      { to: '/rewards', key: 'rewards', label: 'Rewards', icon: 'savings' },
      { to: '/activity', key: 'activity', label: 'Activity', icon: 'receipt_long' },
    ],
  },
  {
    id: 'basic-utility',
    label: 'Utility',
    layout: 'single',
    items: [
      { to: '/settings', key: 'settings', label: 'Settings', icon: 'settings' },
      { to: '/help', key: 'help', label: 'Help', icon: 'help' },
    ],
  },
];

export const ADVANCED_NAV_GROUPS = [
  {
    id: 'monitor',
    label: 'Monitor',
    layout: 'two-column',
    items: [
      { to: '/', key: 'dashboard', label: 'Dashboard', icon: 'space_dashboard', end: true },
      { to: '/node', key: 'details', label: 'Node Details', icon: 'dns' },
      { to: '/connectivity', key: 'connectivity', label: 'Connections', icon: 'hub' },
      { to: '/logs', key: 'logs', label: 'Logs', icon: 'receipt_long' },
      { to: '/incidents', key: 'incidents', label: 'Incidents', icon: 'notification_important' },
    ],
  },
  {
    id: 'validator',
    label: 'Validator',
    layout: 'two-column',
    items: [
      { to: '/validator', key: 'validator', label: 'Validator Lifecycle', icon: 'verified_user' },
      { to: '/rewards', key: 'rewards', label: 'Rewards + Stake', icon: 'savings' },
      { to: '/security', key: 'security', label: 'Identity + Security', icon: 'shield' },
    ],
  },
  {
    id: 'protocol',
    label: 'Protocol',
    layout: 'two-column',
    items: [
      { to: '/consensus', key: 'consensus', label: 'Consensus', icon: 'account_tree' },
      { to: '/dag', key: 'dag', label: 'DAG Explorer', icon: 'schema' },
      { to: '/transactions', key: 'transactions', label: 'Transactions', icon: 'swap_horiz' },
    ],
  },
  {
    id: 'system',
    label: 'System',
    layout: 'two-column',
    items: [
      { to: '/archive', key: 'archive', label: 'Archive Manager', icon: 'inventory_2' },
      { to: '/storage', key: 'storage', label: 'Storage + Snapshots', icon: 'storage' },
      { to: '/api', key: 'api', label: 'API/RPC', icon: 'terminal' },
      { to: '/maintenance', key: 'maintenance', label: 'Maintenance', icon: 'build_circle' },
    ],
  },
  {
    id: 'utility',
    label: 'Utility',
    layout: 'two-column',
    items: [
      { to: '/settings', key: 'settings', label: 'Settings', icon: 'settings' },
      { to: '/help', key: 'help', label: 'Help', icon: 'help' },
    ],
  },
];

export const DEVELOPER_NAV_GROUPS = [
  {
    id: 'runtime',
    label: 'Runtime',
    layout: 'two-column',
    items: [
      { to: '/', key: 'dashboard', label: 'Runtime', icon: 'space_dashboard', end: true },
      { to: '/node', key: 'details', label: 'Validator Detail', icon: 'dns' },
      { to: '/connectivity', key: 'connectivity', label: 'P2P', icon: 'hub' },
      { to: '/logs', key: 'logs', label: 'Runtime Logs', icon: 'receipt_long' },
      { to: '/incidents', key: 'incidents', label: 'Incidents + Evidence', icon: 'notification_important' },
    ],
  },
  {
    id: 'validator',
    label: 'Validator',
    layout: 'two-column',
    items: [
      { to: '/validator', key: 'validator', label: 'Validator Lifecycle', icon: 'verified_user' },
      { to: '/rewards', key: 'rewards', label: 'Rewards + Ledger', icon: 'savings' },
      { to: '/identity', key: 'identity', label: 'Identity + Keys', icon: 'key', developerOnly: true },
      { to: '/security', key: 'security', label: 'Security + Slashing', icon: 'shield' },
    ],
  },
  {
    id: 'protocol',
    label: 'Protocol',
    layout: 'two-column',
    items: [
      { to: '/consensus', key: 'consensus', label: 'Consensus Inspector', icon: 'account_tree' },
      { to: '/dag', key: 'dag', label: 'DAG Graph', icon: 'schema' },
      { to: '/transactions', key: 'transactions', label: 'Transaction Pool', icon: 'swap_horiz' },
    ],
  },
  {
    id: 'system',
    label: 'System',
    layout: 'two-column',
    items: [
      { to: '/archive', key: 'archive', label: 'Archive Manager', icon: 'inventory_2' },
      { to: '/storage', key: 'storage', label: 'Storage Internals', icon: 'storage' },
      { to: '/api', key: 'api', label: 'API/RPC Lab', icon: 'terminal' },
      { to: '/maintenance', key: 'maintenance', label: 'Maintenance', icon: 'build_circle' },
      { to: '/diagnostics', key: 'diagnostics', label: 'Diagnostics', icon: 'troubleshoot', developerOnly: true },
      { to: '/config', key: 'config', label: 'Configuration', icon: 'tune', developerOnly: true },
    ],
  },
  {
    id: 'utility',
    label: 'Utility',
    layout: 'two-column',
    items: [
      { to: '/settings', key: 'settings', label: 'Settings', icon: 'settings' },
      { to: '/help', key: 'help', label: 'Developer Help', icon: 'help' },
    ],
  },
];

export function visibleControlPanelViews(developerModeEnabled) {
  return developerModeEnabled ? VIEW_IDS : VIEW_IDS.filter((view) => view !== 'developer');
}

export function navGroupsForView(viewMode, developerModeEnabled) {
  if (viewMode === 'developer' && developerModeEnabled) {
    return DEVELOPER_NAV_GROUPS;
  }
  if (viewMode === 'advanced') {
    return ADVANCED_NAV_GROUPS;
  }
  return BASIC_NAV_GROUPS;
}

export function isDeveloperOnlyPathname(pathname) {
  const normalized = String(pathname || '').replace(/\/+$/, '') || '/';
  return DEVELOPER_ONLY_PATHS.some((path) => normalized === path || normalized.startsWith(`${path}/`));
}

export function isActivityPathname(pathname) {
  const normalized = String(pathname || '').replace(/\/+$/, '') || '/';
  return normalized === '/activity' || normalized.startsWith('/activity/') || normalized === '/logs' || normalized.startsWith('/logs/');
}

export function isNodePathname(pathname) {
  const normalized = String(pathname || '').replace(/\/+$/, '') || '/';
  return normalized === '/node' || normalized.startsWith('/node/');
}
