const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('synergyDesktop', {
  mode: 'electron',
  getVersion: () => ipcRenderer.invoke('desktop:get-version'),
  getServiceConfig: () => ipcRenderer.invoke('desktop:get-service-config'),
  invokeService: (command, args) => ipcRenderer.invoke('desktop:invoke-service', { command, args }),
  fetchJson: (url, options) => ipcRenderer.invoke('desktop:fetch-json', { url, options }),
  openHelpWindow: () => ipcRenderer.invoke('desktop:open-help-window'),
  openExternal: (url) => ipcRenderer.invoke('desktop:open-external', url),
  openPath: (targetPath) => ipcRenderer.invoke('desktop:open-path', targetPath),
  getControlPanelSettings: () => ipcRenderer.invoke('desktop:get-control-panel-settings'),
  updateControlPanelSettings: (patch) =>
    ipcRenderer.invoke('desktop:update-control-panel-settings', patch),
  showNotification: (options) => ipcRenderer.invoke('desktop:show-notification', options),
  showSaveDialog: (options) => ipcRenderer.invoke('desktop:show-save-dialog', options),
  showOpenDialog: (options) => ipcRenderer.invoke('desktop:show-open-dialog', options),
  fetchSeedPeerTargets: (seedServers) =>
    ipcRenderer.invoke('desktop:fetch-seed-peer-targets', seedServers),
  checkPublicEndpointReachability: (endpoint) =>
    ipcRenderer.invoke('desktop:check-public-endpoint-reachability', endpoint),
  registerSeedPeer: (request) =>
    ipcRenderer.invoke('desktop:register-seed-peer', request),
  heartbeatSeedPeer: (request) =>
    ipcRenderer.invoke('desktop:heartbeat-seed-peer', request),
  readTextFile: (path) => ipcRenderer.invoke('desktop:read-text-file', path),
  writeTextFile: (path, contents) =>
    ipcRenderer.invoke('desktop:write-text-file', { path, contents }),
  relaunch: () => ipcRenderer.invoke('desktop:relaunch'),
  readClipboardText: () => ipcRenderer.invoke('desktop:read-clipboard-text'),
  openTerminalSession: (options) => ipcRenderer.invoke('desktop:open-terminal-session', options),
  writeTerminalInput: (sessionId, input) =>
    ipcRenderer.invoke('desktop:write-terminal-input', { sessionId, input }),
  writeAllowlistedOperation: (sessionId, actionId) =>
    ipcRenderer.invoke('desktop:write-allowlisted-operation', { sessionId, actionId }),
  appendTerminalOutput: (sessionId, output) =>
    ipcRenderer.invoke('desktop:append-terminal-output', { sessionId, output }),
  clearTerminalOutput: (sessionId) =>
    ipcRenderer.invoke('desktop:clear-terminal-output', sessionId),
  resizeTerminal: (sessionId, cols, rows) =>
    ipcRenderer.invoke('desktop:resize-terminal', { sessionId, cols, rows }),
  interruptTerminalSession: (sessionId) =>
    ipcRenderer.invoke('desktop:interrupt-terminal-session', sessionId),
  closeTerminalSession: (sessionId) =>
    ipcRenderer.invoke('desktop:close-terminal-session', sessionId),
  getTerminalSession: (sessionId) =>
    ipcRenderer.invoke('desktop:get-terminal-session', sessionId),
  listTerminalSessions: () =>
    ipcRenderer.invoke('desktop:list-terminal-sessions'),
  resolvePeerTopology: (input) =>
    ipcRenderer.invoke('desktop:resolve-peer-topology', input),
  onboarding: {
    listTargets: () => ipcRenderer.invoke('onboarding:list-targets'),
    addTarget: (request) => ipcRenderer.invoke('onboarding:add-target', request),
    testConnection: (request) => ipcRenderer.invoke('onboarding:test-connection', request),
    deviceCheck: (request) => ipcRenderer.invoke('onboarding:device-check', request),
    runDeviceCheck: (request) => ipcRenderer.invoke('onboarding:run-device-check', request),
    connectWallet: (request) => ipcRenderer.invoke('onboarding:connect-wallet', request),
    getWalletStatus: (request) => ipcRenderer.invoke('onboarding:get-wallet-status', request),
    bondStake: (request) => ipcRenderer.invoke('onboarding:bond-stake', request),
    recordValidatorFunding: (request) => ipcRenderer.invoke('onboarding:record-validator-funding', request),
    finalizeValidatorBond: (request) => ipcRenderer.invoke('onboarding:finalize-validator-bond', request),
    verifyBond: (request) => ipcRenderer.invoke('onboarding:verify-bond', request),
    setValidatorOwner: (request) => ipcRenderer.invoke('onboarding:set-validator-owner', request),
    verifyValidatorEligibility: (request) =>
      ipcRenderer.invoke('onboarding:verify-validator-eligibility', request),
    generateKeys: (request) => ipcRenderer.invoke('onboarding:generate-keys', request),
    getValidatorPackage: () => ipcRenderer.invoke('onboarding:get-validator-package'),
    installPackagedValidatorIdentity: (request) =>
      ipcRenderer.invoke('onboarding:install-packaged-validator-identity', request),
    createValidatorIdentity: (request) =>
      ipcRenderer.invoke('onboarding:create-validator-identity', request),
    exportEncryptedBackup: (request) =>
      ipcRenderer.invoke('onboarding:export-encrypted-backup', request),
    requestInvite: (request) => ipcRenderer.invoke('onboarding:request-invite', request),
    connectMesh: (request) => ipcRenderer.invoke('onboarding:connect-mesh', request),
    connectSecureNetwork: (request) =>
      ipcRenderer.invoke('onboarding:connect-secure-network', request),
    configureNode: (request) => ipcRenderer.invoke('onboarding:configure-node', request),
    applyValidatorSnapshot: (request) =>
      ipcRenderer.invoke('onboarding:apply-validator-snapshot', request),
    discoverSnapshots: (request) => ipcRenderer.invoke('onboarding:discover-snapshots', request),
    downloadSnapshot: (request) => ipcRenderer.invoke('onboarding:download-snapshot', request),
    verifySnapshot: (request) => ipcRenderer.invoke('onboarding:verify-snapshot', request),
    applyVerifiedSnapshot: (request) => ipcRenderer.invoke('onboarding:apply-verified-snapshot', request),
    syncAfterSnapshot: (request) => ipcRenderer.invoke('onboarding:sync-after-snapshot', request),
    applySnapshot: (request) => ipcRenderer.invoke('onboarding:apply-snapshot', request),
    startNormalSync: (request) => ipcRenderer.invoke('onboarding:start-normal-sync', request),
    launchNode: (request) => ipcRenderer.invoke('onboarding:launch-node', request),
    getStatus: (request) => ipcRenderer.invoke('onboarding:get-status', request),
    getOnboardingStatus: (request) => ipcRenderer.invoke('onboarding:get-onboarding-status', request),
    getDashboardStatus: (request) => ipcRenderer.invoke('onboarding:get-dashboard-status', request),
    recoverLocalFork: (request) => ipcRenderer.invoke('onboarding:recover-local-fork', request),
    getAllDashboardStatus: () => ipcRenderer.invoke('dashboard:get-all-status'),
    getMeshHealth: (request) => ipcRenderer.invoke('onboarding:get-mesh-health', request),
    onMeshProgress: (handler) => {
      const listener = (_event, payload) => handler(payload);
      ipcRenderer.on('onboarding:mesh-progress', listener);
      return () => ipcRenderer.removeListener('onboarding:mesh-progress', listener);
    },
  },

  // Auto-update
  checkForUpdate: () => ipcRenderer.invoke('desktop:check-for-update'),
  downloadUpdate: (request) => ipcRenderer.invoke('desktop:download-update', request),
  installUpdate: (request) => ipcRenderer.invoke('desktop:install-update', request),
  onUpdaterEvent: (channel, callback) => {
    const listener = (_event, data) => callback(data);
    ipcRenderer.on(channel, listener);
    return () => ipcRenderer.removeListener(channel, listener);
  },
  onTerminalOutput: (callback) => {
    const listener = (_event, data) => callback(data);
    ipcRenderer.on('terminal:output', listener);
    return () => ipcRenderer.removeListener('terminal:output', listener);
  },
  onTerminalExit: (callback) => {
    const listener = (_event, data) => callback(data);
    ipcRenderer.on('terminal:exit', listener);
    return () => ipcRenderer.removeListener('terminal:exit', listener);
  },
  onTerminalAudit: (callback) => {
    const listener = (_event, data) => callback(data);
    ipcRenderer.on('terminal:audit', listener);
    return () => ipcRenderer.removeListener('terminal:audit', listener);
  },
});
