import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  OPERATION_ACTIONS,
  OPERATION_AVAILABILITY,
  OPERATION_CATEGORIES,
  OPERATION_ROLES,
} from '../../src/features/operations/operationCatalog.js';
import {
  OPERATION_HANDLER_BY_ACTION_ID,
  createOperationHandlers,
} from '../../src/features/operations/operationBindings.js';
import {
  OPERATION_ACTION_BINDINGS,
  getOperationActionBinding,
} from '../../src/features/operations/operationActionMap.js';
import { nodeService } from '../../src/services/nodeService.js';

const expectedCategories = [
  'Lifecycle',
  'Network & VPN',
  'Sync & Chain State',
  'Snapshots & Recovery',
  'Wallet & Keys',
  'Consensus',
  'Logs & Diagnostics',
  'Staking & Rewards',
  'Updates & Maintenance',
];

assert.deepEqual(OPERATION_CATEGORIES.map((category) => category.label), expectedCategories);
assert.equal(new Set(OPERATION_CATEGORIES.map((category) => category.id)).size, 9);
assert.equal(new Set(OPERATION_ACTIONS.map((action) => action.actionId)).size, OPERATION_ACTIONS.length);

for (const [index, category] of OPERATION_CATEGORIES.entries()) {
  assert.equal(category.order, index + 1);
  assert.ok(category.actions.length > 0, `${category.label} must contain actions`);
  assert.ok(category.tooltip?.trim(), `${category.label} must have plain-language hover help`);
  assert.doesNotMatch(category.tooltip, /planned/i, `${category.label} must not advertise a planned control`);

  for (const action of category.actions) {
    assert.match(action.actionId, /^operations\.[a-z0-9-]+\.[a-z0-9-]+$/);
    assert.equal(action.categoryId, category.id);
    assert.equal(action.status, OPERATION_AVAILABILITY.AVAILABLE);
    assert.equal(action.availability, OPERATION_AVAILABILITY.AVAILABLE);
    assert.equal(action.executionMode, 'allowlisted-backend');
    assert.ok(action.tooltip?.trim(), `${action.label} must have plain-language hover help`);
    assert.doesNotMatch(action.tooltip, /planned/i, `${action.label} must not advertise a planned control`);
    assert.ok(Array.isArray(action.allowedRoles) && action.allowedRoles.length > 0);
    assert.ok(action.allowedRoles.every((role) => OPERATION_ROLES.includes(role)));
    assert.equal('handler' in action, false);
    assert.equal(typeof action.handler, 'undefined');
  }
}

const actionById = new Map(OPERATION_ACTIONS.map((action) => [action.actionId, action]));
const mappedEntries = Object.entries(OPERATION_HANDLER_BY_ACTION_ID);
assert.ok(mappedEntries.length >= 55, `Operations must expose at least 55 executable actions, got ${mappedEntries.length}`);
assert.equal(Object.keys(OPERATION_ACTION_BINDINGS).length, mappedEntries.length);
assert.deepEqual(
  new Set(OPERATION_ACTIONS.map((action) => action.actionId)),
  new Set(mappedEntries.map(([actionId]) => actionId)),
  'The exported catalog must contain exactly the allowlisted actions shown as command buttons',
);
for (const [actionId, handler] of mappedEntries) {
  const binding = getOperationActionBinding(actionId);
  assert.equal(binding?.handler, handler, `${actionId} must preserve its executable handler`);
  assert.ok(binding?.serviceCommand, `${actionId} must identify its real service command`);
}

const operationPtyAllowlist = JSON.parse(
  readFileSync(new URL('../../electron/operation-pty-allowlist.json', import.meta.url), 'utf8'),
);
for (const action of OPERATION_ACTIONS) {
  assert.equal(
    operationPtyAllowlist[action.actionId],
    action.displayCommand,
    `${action.actionId} must have the catalog command in the Electron PTY allowlist`,
  );
}

const deliberatelyUnavailableActions = [
  'operations.network-vpn.check-firewall',
  'operations.wallet-keys.wallet-status',
];
for (const actionId of deliberatelyUnavailableActions) {
  assert.equal(
    OPERATION_HANDLER_BY_ACTION_ID[actionId],
    undefined,
    `${actionId} must remain hidden until a matching backend operation exists`,
  );
}

for (const [actionId] of mappedEntries) {
  const action = actionById.get(actionId);
  assert.ok(action, `Mapped operation ${actionId} must exist in the catalog`);
  if (action.riskLevel === 'high' || action.riskLevel === 'critical') {
    assert.equal(action.requiresConfirmation, true, `${action.label} must require confirmation`);
  }
}

const fakeNode = {
  id: 'validator-7',
  owner_wallet_address: 'syn1owner',
  node_address: 'synv1validator7',
};

const statusPayload = {
  node_id: fakeNode.id,
  current_status: 'ACTIVE',
  status_headline: 'VALIDATOR ACTIVE',
  status_severity: 'healthy',
  local_rpc_ready: true,
  is_consensus_active: true,
  is_voting: true,
  is_proposing: false,
  is_syncing: false,
  is_shadowing: false,
  is_quarantined: false,
  is_failed_closed: false,
  latest_finalized_height: 1200,
  latest_finalized_block_hash: 'block-1200',
  latest_state_root: 'state-1200',
  latest_qc_hash: 'qc-1200',
  sync_target_height: 1200,
  sync_target_source: 'public-rpc',
  sync_target_verified: true,
  height_sources: [{ source: 'public-rpc', height: 1200, verification_status: 'verified' }],
  current_epoch: 12,
  current_round: 2,
  current_cluster_id: 1,
  stake_status: 'LOCKED',
  next_expected_action: 'Continue participating in consensus.',
  consensus_activity: {
    current_leader: 'validator-2',
    current_height: 1201,
    current_epoch: 12,
    current_round: 2,
    proposal_phase: 'WAITING_FOR_PROPOSAL',
    vote_phase: 'VOTING',
    vote_decision: 'YES',
    qc_status: 'FORMING_QC',
    signed_weight: 3,
    required_threshold_weight: 3,
  },
  lifecycle: {
    current_state: 'ACTIVE',
    pending_activation_epoch: 13,
    expected_activation_height: 1300,
    shadow_observation: {
      status: 'complete',
      latest_height: 1200,
      observed_blocks: 1000,
      required_blocks: 1000,
      remaining_blocks: 0,
      completed: true,
    },
  },
  aegis_pqvm: {
    status: 'READY',
    version: 'aegis-pqvm-required',
    validator_consensus_key_status: 'loaded',
    validator_peer_identity_key_status: 'loaded',
    validator_operator_key_status: 'loaded',
    key_active_for_current_epoch: true,
    latest_signature_verification_result: 'valid',
    latest_qc_verification_result: 'valid',
  },
};

const preflightPayload = {
  node_id: fakeNode.id,
  generated_at_utc: '2026-07-14T00:00:00Z',
  can_activate: true,
  checks: [
    { id: 'local-signing-key', label: 'Local signing key', status: 'pass' },
    { id: 'canonical-workspace-genesis', label: 'Canonical genesis', status: 'pass' },
  ],
  onboarding_policy: { validator_set_snapshot: { active_validators: [] } },
};

const dispatchCalls = [];
const onboardingCalls = [];
const dispatcherResponses = {
  testnet_get_validator_live_status: statusPayload,
  testnet_get_validator_activation_preflight: preflightPayload,
  testnet_get_feature_snapshot: { screenKey: 'consensus', live: { local_chain_height: 1200 } },
  testnet_get_rewards_data: {
    node_id: fakeNode.id,
    token_symbol: 'SNRG',
    live: {
      staked_balance_snrg: '50000',
      current_total_position_snrg: '50100',
      validator_status: 'Active',
      staking_entry_count: 1,
      historical_earned_snrg: '120',
      pending_rewards_snrg: '4',
      reward_history: [{ epoch: 12, amount_snrg: '4' }],
      synergy_multiplier: 1.2,
    },
    telemetry: { telemetry_gaps: [] },
  },
  testnet_get_node_logs: {
    node_id: fakeNode.id,
    workspace_directory: '/tmp/syn1-node',
    sources: [],
    entries: [{ message: 'live log', source_label: 'runtime', level: 'info', raw: 'live log' }],
    summary: {
      total_entries: 1,
      error_count: 0,
      warn_count: 0,
      info_count: 1,
      debug_count: 0,
      trace_count: 0,
      active_source_count: 1,
    },
    combined_text: 'live log',
  },
};
const previousWindow = globalThis.window;
globalThis.window = {
  setTimeout,
  clearTimeout,
  dispatchEvent() {},
  synergyDesktop: {
    async invokeService(command, args) {
      dispatchCalls.push({ command, args });
      if (Object.prototype.hasOwnProperty.call(dispatcherResponses, command)) {
        return dispatcherResponses[command];
      }
      return { command, args, message: `${command} dispatched` };
    },
    async getVersion() {
      return '19.0.17';
    },
    async checkForUpdate() {
      return {};
    },
    async downloadUpdate() {
      return {};
    },
    async installUpdate() {},
    async showSaveDialog() {
      return '/tmp/operation-test.tar.gz';
    },
    async showOpenDialog() {
      return '/tmp/operation-test.tar.gz';
    },
    onboarding: {
      async getMeshHealth(request) {
        onboardingCalls.push({ action: 'getMeshHealth', request });
        return {
          interfaceUp: true,
          handshakeConfirmed: true,
          peersConnected: 3,
          coordinator: { status: 'ok', reachable: true, version: '19.0.53' },
        };
      },
      async discoverSnapshots() {
        return { snapshots: [] };
      },
      async applyValidatorSnapshot() {
        return { message: 'snapshot applied' };
      },
      async createValidatorIdentity() {
        return { message: 'identity created' };
      },
      async exportEncryptedBackup() {
        return { message: 'backup exported' };
      },
    },
  },
};

const executableHandlers = createOperationHandlers({
  service: nodeService,
  node: fakeNode,
  nodeAddress: fakeNode.node_address,
  openLogs: () => {
    dispatchCalls.push({ command: 'open-logs', args: undefined });
  },
});

const adapterCalls = [];
const serviceAdapter = new Proxy({}, {
  get(_target, method) {
    return async (...args) => {
      adapterCalls.push({ method, args });
      return { method, args };
    };
  },
});
const adapterHandlers = createOperationHandlers({
  service: serviceAdapter,
  node: fakeNode,
  nodeAddress: fakeNode.node_address,
  openLogs: () => adapterCalls.push({ method: 'openLogs', args: [] }),
});

for (const handlerName of new Set(Object.values(OPERATION_HANDLER_BY_ACTION_ID))) {
  adapterCalls.length = 0;
  await adapterHandlers[handlerName]();
  const serviceCalls = adapterCalls.filter((call) => call.method !== 'openLogs');
  assert.ok(serviceCalls.length > 0, `${handlerName} must call a real service adapter`);
  for (const call of serviceCalls) {
    assert.equal(
      typeof nodeService[call.method],
      'function',
      `${handlerName} requires nodeService.${String(call.method)} to exist`,
    );
  }
}

for (const handlerName of new Set(Object.values(OPERATION_HANDLER_BY_ACTION_ID))) {
  assert.equal(typeof executableHandlers[handlerName], 'function', `${handlerName} must resolve to an executable handler`);
}

async function dispatchAction(handlerName, expectedCommand, expectedArgs) {
  dispatchCalls.length = 0;
  const result = await executableHandlers[handlerName]();
  assert.deepEqual(dispatchCalls[0], { command: expectedCommand, args: expectedArgs }, `${handlerName} must use the real IPC adapter`);
  return result;
}

async function dispatchOnboardingAction(handlerName, expectedAction, expectedRequest) {
  dispatchCalls.length = 0;
  onboardingCalls.length = 0;
  const result = await executableHandlers[handlerName]();
  assert.equal(dispatchCalls.length, 0, `${handlerName} must not use the retired static-VPN control-service command`);
  assert.deepEqual(
    onboardingCalls,
    [{ action: expectedAction, request: expectedRequest }],
    `${handlerName} must use the live Innernet onboarding bridge`,
  );
  return result;
}

const syncStatus = await dispatchAction('syncStatus', 'testnet_get_validator_live_status', { nodeId: fakeNode.id });
assert.equal(syncStatus.action, 'sync-status');
assert.equal(syncStatus.syncGap, 0);

const headComparison = await dispatchAction('compareNetworkHead', 'testnet_get_validator_live_status', { nodeId: fakeNode.id });
assert.equal(headComparison.action, 'compare-network-head');
assert.equal(headComparison.matched, true);
assert.equal(headComparison.networkHeadHeight, 1200);

const finality = await dispatchAction('finalityStatus', 'testnet_get_validator_live_status', { nodeId: fakeNode.id });
assert.equal(finality.action, 'finality-status');
assert.equal(finality.healthy, true);
assert.equal(finality.finalizedHeight, 1200);

const epoch = await dispatchAction('epochStatus', 'testnet_get_validator_live_status', { nodeId: fakeNode.id });
assert.equal(epoch.action, 'epoch-status');
assert.equal(epoch.currentEpoch, 12);
assert.equal(epoch.currentHeight, 1201);

const participation = await dispatchAction('participationReport', 'testnet_get_validator_live_status', { nodeId: fakeNode.id });
assert.equal(participation.action, 'participation-report');
assert.equal(participation.isVoting, true);
assert.equal(participation.qcStatus, 'FORMING_QC');

const stake = await dispatchAction('stakeReport', 'testnet_get_rewards_data', { nodeId: fakeNode.id });
assert.equal(stake.action, 'view-stake');
assert.equal(stake.stakedBalance, '50000');

const rewards = await dispatchAction('rewardsReport', 'testnet_get_rewards_data', { nodeId: fakeNode.id });
assert.equal(rewards.action, 'view-rewards');
assert.equal(rewards.pendingRewards, '4');

const innernet = await dispatchOnboardingAction('innernetStatus', 'getMeshHealth', { targetId: 'local' });
assert.equal(innernet.action, 'innernet-status');
assert.equal(innernet.connected, true);

await dispatchAction('resetInnernetClient', 'testnet_reset_innernet_client_state', {
  targetOs: 'macos',
});

const coordinator = await dispatchOnboardingAction('coordinatorStatus', 'getMeshHealth', { targetId: 'local' });
assert.equal(coordinator.action, 'coordinator-status');
assert.equal(coordinator.reachable, true);

await dispatchAction('safeShutdown', 'testnet_node_control', {
  input: { nodeId: fakeNode.id, action: 'safe-shutdown' },
});

await dispatchAction('verifyPorts', 'testnet_get_node_readiness', { nodeId: fakeNode.id });

await dispatchAction('speedSync', 'testnet_sync_catch_up_rejoin', {
  input: { nodeId: fakeNode.id, autoActivate: false },
});

await dispatchAction('recoverLocalFork', 'testnet_recover_local_fork', {
  node_id: fakeNode.id,
});

await dispatchAction('restoreSnapshot', 'testnet_restore_validator_snapshot', {
  input: { nodeId: fakeNode.id },
});

dispatchCalls.length = 0;
const liveLogsResult = await executableHandlers.liveLogs();
assert.deepEqual(
  dispatchCalls[0],
  { command: 'testnet_get_node_logs', args: { nodeId: fakeNode.id, lines: 700 } },
  'Live logs must dispatch the real logs IPC request',
);
assert.deepEqual(
  dispatchCalls[1],
  { command: 'open-logs', args: undefined },
  'Live logs must navigate to /logs after fetching logs',
);
assert.equal(dispatchCalls.length, 2, 'Live logs should dispatch one IPC command plus one navigation event');
assert.equal(liveLogsResult.node_id, fakeNode.id);
assert.equal(liveLogsResult.summary.total_entries, 1);

globalThis.window = previousWindow;

const operationsSource = readFileSync(new URL('../../src/components/control-panel-v18/ControlPanelV18.jsx', import.meta.url), 'utf8');
const terminalSource = readFileSync(new URL('../../src/components/control-panel-v18/DeveloperTerminalDock.jsx', import.meta.url), 'utf8');
const terminalManagerSource = readFileSync(new URL('../../electron/pty-manager.cjs', import.meta.url), 'utf8');
const nodeServiceSource = readFileSync(new URL('../../src/services/nodeService.js', import.meta.url), 'utf8');
const controlServiceSource = readFileSync(new URL('../../control-service/src/testnet.rs', import.meta.url), 'utf8');
const controlServiceDispatcherSource = readFileSync(new URL('../../control-service/src/control_service.rs', import.meta.url), 'utf8');
const appUpdaterSource = readFileSync(new URL('../../src/lib/appUpdater.js', import.meta.url), 'utf8');
const preloadSource = readFileSync(new URL('../../electron/preload.cjs', import.meta.url), 'utf8');
const electronMainSource = readFileSync(new URL('../../electron/main.cjs', import.meta.url), 'utf8');

for (const binding of Object.values(OPERATION_ACTION_BINDINGS)) {
  if (/^(?:testnet|monitor)_/.test(binding.serviceCommand)) {
    assert.ok(
      controlServiceDispatcherSource.includes(`"${binding.serviceCommand}"`),
      `${binding.serviceCommand} must exist in the Rust control-service dispatcher`,
    );
  }
}

assert.match(operationsSource, /<DeveloperTerminalDock node=\{node\} title="Node shell" \/>/);
assert.match(operationsSource, /const OPERATION_ACTION_ICONS = Object\.freeze\(\{/);
assert.match(operationsSource, /icon: OPERATION_ACTION_ICONS\[action\.icon\] \|\| OPERATION_CATEGORY_ICONS\[category\.id\] \|\| TerminalSquare/);
assert.match(operationsSource, /const Icon = operation\.icon \|\| activeCategory\.icon;/);
const lucideImportEnd = operationsSource.indexOf("} from 'lucide-react';");
const lucideImportStart = operationsSource.lastIndexOf('import {', lucideImportEnd);
assert.notEqual(lucideImportEnd, -1, 'ControlPanelV18.jsx must import lucide-react icons');
assert.notEqual(lucideImportStart, -1, 'ControlPanelV18.jsx must use a named lucide-react import');
const lucideImportBody = operationsSource.slice(lucideImportStart + 'import {'.length, lucideImportEnd);
const lucideImports = new Set(lucideImportBody
  .split(',')
  .map((item) => item.trim())
  .filter(Boolean)
  .map((item) => item.includes(' as ') ? item.split(/\s+as\s+/).pop().trim() : item));
const operationIconBody = operationsSource.match(/const OPERATION_ACTION_ICONS = Object\.freeze\(\{([\s\S]*?)\}\);/)?.[1] || '';
const operationIconReferences = operationIconBody
  .split('\n')
  .map((line) => line.trim().replace(/,$/, ''))
  .filter(Boolean)
  .map((line) => line.includes(':') ? line.split(':').pop().trim() : line);
for (const iconReference of operationIconReferences) {
  assert.ok(lucideImports.has(iconReference), `${iconReference} must be imported from lucide-react`);
}
assert.doesNotMatch(operationsSource, /title=\{operation\.tooltip \|\| operation\.detail\}/);
assert.match(operationsSource, /dangerous: Boolean\(action\.requiresConfirmation\)/);
assert.doesNotMatch(operationsSource, /Manual terminal execution is not connected yet/);
assert.match(nodeServiceSource, /async emergencyStop[\s\S]*action: 'emergency-stop'/);
assert.doesNotMatch(
  nodeServiceSource,
  /async getValidatorVpnStatus\(nodeId\) \{\s*return invoke\('testnet_validator_vpn_agent_status'/,
  'VPN Operations must inspect the live Innernet interface through onboarding IPC, not the retired static-VPN command',
);
for (const actionId of [
  'operations.network-vpn.vpn-status',
  'operations.network-vpn.innernet-status',
  'operations.network-vpn.check-coordinator',
  'operations.network-vpn.check-routes',
]) {
  assert.equal(
    OPERATION_ACTION_BINDINGS[actionId].serviceCommand,
    'onboarding:getMeshHealth',
    `${actionId} must report the current Innernet bridge rather than a retired static-VPN command`,
  );
}
assert.match(controlServiceSource, /"emergency-stop" => \{/);
assert.match(controlServiceSource, /testnet_recover_local_fork/);
assert.match(terminalSource, /openTerminalSession/);
assert.match(terminalSource, /writeTerminalInput/);
assert.match(terminalSource, /resizeTerminal/);
assert.match(terminalManagerSource, /ownerId/);
assert.match(terminalManagerSource, /interruptSession/);
assert.match(terminalManagerSource, /pendingInput|Terminal command/);
const desktopMappings = Object.entries(OPERATION_ACTION_BINDINGS)
  .filter(([, binding]) => binding.serviceCommand.startsWith('desktop:'));
assert.deepEqual(
  desktopMappings.map(([actionId, binding]) => [actionId, binding.serviceCommand]),
  [
    ['operations.updates-maintenance.check-updates', 'desktop:check-for-update'],
    ['operations.updates-maintenance.update-control-panel', 'desktop:download-update'],
  ],
  'desktop operation mappings must stay explicit and allowlisted',
);
assert.match(appUpdaterSource, /bridge\.checkForUpdate\(\)/);
assert.match(appUpdaterSource, /bridge\.downloadUpdate\(\{ version: targetVersion \}\)/);
assert.match(preloadSource, /checkForUpdate: \(\) => ipcRenderer\.invoke\('desktop:check-for-update'\)/);
assert.match(preloadSource, /downloadUpdate: \(request\) => ipcRenderer\.invoke\('desktop:download-update', request\)/);
assert.match(electronMainSource, /ipcMain\.handle\('desktop:check-for-update'/);
assert.match(electronMainSource, /ipcMain\.handle\('desktop:download-update'/);

console.log(`Operation catalog QA passed: ${OPERATION_CATEGORIES.length} categories, ${OPERATION_ACTIONS.length} documented actions, ${mappedEntries.length} executable actions.`);
