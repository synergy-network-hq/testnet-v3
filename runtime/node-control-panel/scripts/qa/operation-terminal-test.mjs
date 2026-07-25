import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import {
  createOperationTerminalEvent,
  extractOperationOutput,
  formatOperationTerminalEvent,
} from '../../src/features/operations/operationTerminal.js';

const operation = {
  id: 'operations.network-vpn.view-connected-peers',
  label: 'Check Peers',
  displayCommand: 'synergy node peers connected',
};

test('operation transcript renders command, both streams, and informational success', () => {
  assert.match(
    formatOperationTerminalEvent(createOperationTerminalEvent({ operation, phase: 'start' })),
    /\[operation\] Starting Check Peers\r\n\[operation\] Command: synergy node peers connected/,
  );
  assert.match(
    formatOperationTerminalEvent(createOperationTerminalEvent({
      operation: { ...operation, serviceCommand: 'testnet_get_feature_snapshot' },
      phase: 'start',
    })),
    /Local service: testnet_get_feature_snapshot[\s\S]*installed Control Panel service on this machine/,
  );
  assert.match(
    formatOperationTerminalEvent(createOperationTerminalEvent({ operation, phase: 'output', stream: 'stdout', text: 'peer-1\npeer-2' })),
    /\[stdout\][\s\S]*peer-1\r\npeer-2/,
  );
  assert.match(
    formatOperationTerminalEvent(createOperationTerminalEvent({ operation, phase: 'output', stream: 'stderr', text: 'warning' })),
    /\[stderr\][\s\S]*warning/,
  );
  assert.match(
    formatOperationTerminalEvent(createOperationTerminalEvent({
      operation,
      phase: 'complete',
      status: 'success',
      detail: 'No local peers.',
    })),
    /OK Check Peers: No local peers\./,
  );
});

test('service output is normalized before it is appended to the Operations PTY transcript', () => {
  assert.deepEqual(
    extractOperationOutput({
      stdout: 'primary output',
      stderr: 'primary warning',
      result: { data: { stdout: 'nested output' } },
    }),
    [
      { stream: 'stdout', text: 'primary output' },
      { stream: 'stderr', text: 'primary warning' },
      { stream: 'stdout', text: 'nested output' },
    ],
  );
});

test('action transcript output stays visible across a terminal reconnect', () => {
  const transcript = [
    createOperationTerminalEvent({ operation, phase: 'start' }),
    createOperationTerminalEvent({ operation, phase: 'output', stream: 'stdout', text: 'peer-1' }),
    createOperationTerminalEvent({ operation, phase: 'output', stream: 'stderr', text: 'warning' }),
    createOperationTerminalEvent({ operation, phase: 'complete', status: 'success', detail: 'Done.' }),
  ].map(formatOperationTerminalEvent).join('');

  assert.match(transcript, /\[operation\] Starting Check Peers/);
  assert.match(transcript, /\[operation\] Command: synergy node peers connected/);
  assert.match(transcript, /peer-1/);
  assert.match(transcript, /warning/);
  assert.match(transcript, /OK Check Peers: Done\./);
});

test('Operations and the v18 terminal dock are wired to the transcript bridge', () => {
  const operationsSource = readFileSync(new URL('../../src/components/control-panel-v18/ControlPanelV18.jsx', import.meta.url), 'utf8');
  const terminalSource = readFileSync(new URL('../../src/components/control-panel-v18/DeveloperTerminalDock.jsx', import.meta.url), 'utf8');
  const executionSource = readFileSync(new URL('../../src/features/operations/operationExecution.js', import.meta.url), 'utf8');

  assert.match(executionSource, /phase: 'output'/);
  assert.match(operationsSource, /executeOperationThroughPty/);
  assert.match(executionSource, /extractOperationOutput\(result\)/);
  assert.match(executionSource, /formatOperationTerminalEvent/);
  assert.match(executionSource, /phase: 'start'/);
  assert.match(executionSource, /appendTerminalOutput\(sessionId, transcript\)/);
  assert.match(terminalSource, /pendingPtyOutputRef\.current\.delete\(outputSessionId\)/);
  assert.match(terminalSource, /MAX_PENDING_PTY_EVENTS_PER_SESSION/);
  assert.match(terminalSource, /MAX_PENDING_PTY_SESSIONS/);
  assert.match(terminalSource, /reuseExisting:\s*true/);
  assert.match(terminalSource, /sessionName/);
  assert.match(operationsSource, /appendTerminalOutput/);
  assert.doesNotMatch(operationsSource, /emitOperationTerminalEvent|window\.dispatchEvent/);
  assert.doesNotMatch(terminalSource, /OPERATION_TERMINAL_EVENT|appendTerminalOutput/);

  const unmountCleanupStart = terminalSource.indexOf('mountedRef.current = false;');
  const unmountCleanupEnd = terminalSource.indexOf('terminal.dispose();', unmountCleanupStart);
  assert.ok(unmountCleanupStart >= 0 && unmountCleanupEnd > unmountCleanupStart);
  assert.doesNotMatch(
    terminalSource.slice(unmountCleanupStart, unmountCleanupEnd),
    /closeSession|closeTerminalSession|\.kill\(/,
    'route unmount must release the dock without killing a reusable named PTY session',
  );

  const staleConnectStart = terminalSource.indexOf('if (!mountedRef.current || attempt !== connectAttemptRef.current) {');
  const staleConnectEnd = terminalSource.indexOf('const nextSessionId', staleConnectStart);
  assert.ok(staleConnectStart >= 0 && staleConnectEnd > staleConnectStart);
  assert.doesNotMatch(
    terminalSource.slice(staleConnectStart, staleConnectEnd),
    /closeSession|closeTerminalSession|\.kill\(/,
    'a stale terminal connect must not close a reusable session adopted by a newer dock mount',
  );
});

test('operation actions use a single synchronous lock and release it after confirmation cancellation', () => {
  const operationsSource = readFileSync(new URL('../../src/components/control-panel-v18/ControlPanelV18.jsx', import.meta.url), 'utf8');
  assert.match(operationsSource, /operationLockRef\.current/);
  assert.match(operationsSource, /if \(operationLockRef\.current\) return/);
  assert.match(operationsSource, /disabled=\{!availability\.available \|\| Boolean\(runningOperationId\)\}/);
  assert.match(operationsSource, /disabled=\{Boolean\(runningOperationId\)\}/);
  assert.match(operationsSource, /finally \{/);
  assert.match(operationsSource, /onCancel=\{\(\) => \{/);
  assert.match(operationsSource, /confirmRequest\?\.onCancel\?\.\(\)/);
});

test('terminal dock bounds the xterm viewport and gates resize feedback', () => {
  const terminalSource = readFileSync(new URL('../../src/components/control-panel-v18/DeveloperTerminalDock.jsx', import.meta.url), 'utf8');
  const terminalStyles = readFileSync(new URL('../../src/components/control-panel-v18/DeveloperTerminalDock.css', import.meta.url), 'utf8');

  assert.match(terminalSource, /requestAnimationFrame/);
  assert.match(terminalSource, /fitFrameRef\.current !== null/);
  assert.match(terminalSource, /lastTerminalSizeRef\.current/);
  assert.match(terminalSource, /nextSize\.cols === previousSize\.cols && nextSize\.rows === previousSize\.rows/);
  assert.match(terminalSource, /copySelection/);
  assert.match(terminalSource, /pasteClipboard/);
  assert.match(terminalSource, /readClipboardText/);
  assert.match(terminalSource, /resizeTerminal/);
  assert.match(terminalStyles, /height: min\(548px, max\(280px, calc\(100dvh - var\(--terminal-viewport-inset\)\)\)\);/);
  assert.match(terminalStyles, /grid-template-rows: auto auto minmax\(0, 1fr\) auto;/);
  assert.match(terminalStyles, /\.v18-terminal-dock__root \{[\s\S]*?min-height: 0;/);
  assert.match(terminalStyles, /overflow-y: auto !important;/);
});

test('staking operations expose the local validator self-bond action with owner-wallet gating', () => {
  const catalogSource = readFileSync(new URL('../../src/features/operations/operationCatalog.js', import.meta.url), 'utf8');
  const bindingsSource = readFileSync(new URL('../../src/features/operations/operationBindings.js', import.meta.url), 'utf8');
  const actionMapSource = readFileSync(new URL('../../src/features/operations/operationActionMap.js', import.meta.url), 'utf8');
  const allowlistSource = readFileSync(new URL('../../electron/operation-pty-allowlist.json', import.meta.url), 'utf8');
  const nodeServiceSource = readFileSync(new URL('../../src/services/nodeService.js', import.meta.url), 'utf8');
  const operationsSource = readFileSync(new URL('../../src/components/control-panel-v18/ControlPanelV18.jsx', import.meta.url), 'utf8');

  assert.match(catalogSource, /operations\.staking-rewards\.complete-validator-self-bond/);
  assert.match(catalogSource, /Complete Validator Self-Bond/);
  assert.match(catalogSource, /requiresOwnerWallet:\s*true/);
  assert.match(catalogSource, /does not ask the owner wallet to send another funding transfer/);
  assert.match(bindingsSource, /completeValidatorSelfBond/);
  assert.match(actionMapSource, /'operations\.staking-rewards\.complete-validator-self-bond': 'testnet_stake_validator'/);
  assert.match(allowlistSource, /"operations\.staking-rewards\.complete-validator-self-bond": "synergy staking self-bond --amount 50000"/);
  assert.match(nodeServiceSource, /async completeValidatorSelfBond\(nodeId, ownerWalletAddress\)/);
  assert.match(nodeServiceSource, /amountSnrg:\s*50000/);
  assert.match(operationsSource, /Boolean\(action\.requiresOwnerWallet\)/);
});

test('sync operations expose guarded local fork recovery in the operations terminal', () => {
  const catalogSource = readFileSync(new URL('../../src/features/operations/operationCatalog.js', import.meta.url), 'utf8');
  const bindingsSource = readFileSync(new URL('../../src/features/operations/operationBindings.js', import.meta.url), 'utf8');
  const actionMapSource = readFileSync(new URL('../../src/features/operations/operationActionMap.js', import.meta.url), 'utf8');
  const allowlistSource = readFileSync(new URL('../../electron/operation-pty-allowlist.json', import.meta.url), 'utf8');
  const nodeServiceSource = readFileSync(new URL('../../src/services/nodeService.js', import.meta.url), 'utf8');

  assert.match(catalogSource, /operations\.sync-chain-state\.recover-local-fork/);
  assert.match(catalogSource, /Recover Local Fork/);
  assert.match(catalogSource, /preserving validator identity, wallet, stake, and VPN enrollment/);
  assert.match(catalogSource, /keeps your validator keys, wallet, stake, and secure-network setup/);
  assert.match(bindingsSource, /recoverLocalFork/);
  assert.match(actionMapSource, /'operations\.sync-chain-state\.recover-local-fork': 'testnet_recover_local_fork'/);
  assert.match(allowlistSource, /"operations\.sync-chain-state\.recover-local-fork": "synergy node sync recover-local-fork"/);
  assert.match(nodeServiceSource, /async recoverLocalFork\(nodeId\)/);
  assert.match(nodeServiceSource, /testnet_recover_local_fork/);
});

test('network operations expose a narrow secure-network reset without deleting validator state', () => {
  const catalogSource = readFileSync(new URL('../../src/features/operations/operationCatalog.js', import.meta.url), 'utf8');
  const bindingsSource = readFileSync(new URL('../../src/features/operations/operationBindings.js', import.meta.url), 'utf8');
  const actionMapSource = readFileSync(new URL('../../src/features/operations/operationActionMap.js', import.meta.url), 'utf8');
  const allowlistSource = readFileSync(new URL('../../electron/operation-pty-allowlist.json', import.meta.url), 'utf8');
  const nodeServiceSource = readFileSync(new URL('../../src/services/nodeService.js', import.meta.url), 'utf8');
  const controlServiceSource = readFileSync(new URL('../../control-service/src/testnet.rs', import.meta.url), 'utf8');
  const controlDispatcherSource = readFileSync(new URL('../../control-service/src/control_service.rs', import.meta.url), 'utf8');

  assert.match(catalogSource, /operations\.network-vpn\.reset-innernet-client/);
  assert.match(catalogSource, /Reset Secure Network/);
  assert.match(catalogSource, /stale sy-vpn client config, service, interface, and Innernet logs/);
  assert.match(catalogSource, /does not delete your validator keys, wallet, stake, or synced chain data/);
  assert.match(bindingsSource, /resetInnernetClient/);
  assert.match(actionMapSource, /'operations\.network-vpn\.reset-innernet-client': 'testnet_reset_innernet_client_state'/);
  assert.match(allowlistSource, /"operations\.network-vpn\.reset-innernet-client": "synergy node vpn reset-innernet-client"/);
  assert.match(nodeServiceSource, /async resetInnernetClientState\(\)/);
  assert.match(controlServiceSource, /pub async fn testnet_reset_innernet_client_state/);
  assert.match(controlServiceSource, /without deleting validator keys, wallet, stake, or chain data/);
  assert.match(controlDispatcherSource, /"testnet_reset_innernet_client_state"/);
});

test('live Operations status keeps activation preflight on a bounded evidence budget', () => {
  const controlServiceSource = readFileSync(new URL('../../control-service/src/testnet.rs', import.meta.url), 'utf8');

  assert.match(controlServiceSource, /TESTNET_LIVE_STATUS_PREFLIGHT_TIMEOUT_SECS: u64 = 4/);
  assert.match(
    controlServiceSource,
    /timeout\(\s*Duration::from_secs\(TESTNET_LIVE_STATUS_PREFLIGHT_TIMEOUT_SECS\),\s*build_validator_activation_preflight\(&state, &node\),/s,
  );
  assert.match(
    controlServiceSource,
    /Run the dedicated Activation Preflight action for full eligibility evidence\./,
  );
  assert.match(
    controlServiceSource,
    /build_node_live_status_for_dashboard\(&client, &node, public_chain_height\)/,
  );
  assert.match(
    controlServiceSource,
    /query_public_chain_height_for_live_status/,
  );
});
