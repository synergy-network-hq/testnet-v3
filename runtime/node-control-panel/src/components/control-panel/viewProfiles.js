export const PANEL_VIEW_MODES = ['basic', 'advanced', 'developer'];

export const BASIC_PROFILE = {
  id: 'basic',
  label: 'Basic',
  navLabels: {
    dashboard: 'Dashboard',
    details: 'My Node',
    connectivity: 'Connections',
    logs: 'Activity',
    rewards: 'Rewards',
  },
  showPlainLanguageHelp: true,
  showDerivedHealthNarrative: true,
  showRawPaths: false,
  showRawIds: false,
  showRawJson: false,
  showDangerZone: false,
  showActionConsole: false,
  showEmbeddedTerminal: false,
  showAdvancedCharts: false,
  showDeveloperCharts: false,
  showLogSourceList: false,
  showLiveLogTail: false,
  showGeoPeerMap: true,
  showPeerGraph: false,
  showCommandPalette: false,
  defaultLogPreset: 'simple',
  defaultChartDensity: 'light',
  maxPrimaryActionsPerSection: 3,
  languageStyle: 'plain',
  icon: 'person',
};

export const ADVANCED_PROFILE = {
  id: 'advanced',
  label: 'Advanced',
  navLabels: {
    dashboard: 'Dashboard',
    details: 'Node Details',
    connectivity: 'Connections',
    logs: 'Logs',
    rewards: 'Rewards + Stake',
  },
  showPlainLanguageHelp: false,
  showDerivedHealthNarrative: true,
  showRawPaths: true,
  showRawIds: false,
  showRawJson: false,
  showDangerZone: false,
  showActionConsole: true,
  showEmbeddedTerminal: false,
  showAdvancedCharts: true,
  showDeveloperCharts: false,
  showLogSourceList: true,
  showLiveLogTail: false,
  showGeoPeerMap: true,
  showPeerGraph: true,
  showCommandPalette: true,
  defaultLogPreset: 'ops',
  defaultChartDensity: 'medium',
  maxPrimaryActionsPerSection: 6,
  languageStyle: 'technical',
  icon: 'psychology',
};

export const DEVELOPER_PROFILE = {
  id: 'developer',
  label: 'Developer',
  navLabels: {
    dashboard: 'Runtime',
    details: 'Validator Detail',
    connectivity: 'P2P',
    logs: 'Runtime Logs',
    rewards: 'Rewards + Ledger',
  },
  showPlainLanguageHelp: false,
  showDerivedHealthNarrative: false,
  showRawPaths: true,
  showRawIds: true,
  showRawJson: true,
  showDangerZone: true,
  showActionConsole: true,
  showEmbeddedTerminal: true,
  showAdvancedCharts: true,
  showDeveloperCharts: true,
  showLogSourceList: true,
  showLiveLogTail: true,
  showGeoPeerMap: true,
  showPeerGraph: true,
  showCommandPalette: true,
  defaultLogPreset: 'raw',
  defaultChartDensity: 'heavy',
  maxPrimaryActionsPerSection: 10,
  languageStyle: 'protocol',
  icon: 'terminal',
};

export const VIEW_PROFILES = {
  basic: BASIC_PROFILE,
  advanced: ADVANCED_PROFILE,
  developer: DEVELOPER_PROFILE,
};

export const MODE_SWITCH_ITEMS = PANEL_VIEW_MODES.map((mode) => ({
  id: mode,
  label: VIEW_PROFILES[mode].label,
  icon: VIEW_PROFILES[mode].icon,
}));

const MODE_ORDER = {
  basic: 0,
  advanced: 1,
  developer: 2,
};

export function normalizePanelViewMode(value) {
  const normalized = String(value || '').trim().toLowerCase();
  if (normalized === 'expert') {
    return 'advanced';
  }
  return PANEL_VIEW_MODES.includes(normalized) ? normalized : 'basic';
}

export function getViewProfile(mode) {
  return VIEW_PROFILES[normalizePanelViewMode(mode)] || BASIC_PROFILE;
}

export function isModeAtLeast(mode, minimumMode) {
  return MODE_ORDER[normalizePanelViewMode(mode)] >= MODE_ORDER[normalizePanelViewMode(minimumMode)];
}

export function modeLabel(mode) {
  return getViewProfile(mode).label;
}
