import { OPERATION_HANDLER_BY_ACTION_ID } from './operationBindings.js';

// This is execution metadata for the typed service handlers. The privileged
// service command is never supplied by the renderer or passed to a shell; the
// separate Electron PTY allowlist owns the safe visible command echo.
const SERVICE_COMMAND_BY_ACTION_ID = Object.freeze({
  'operations.lifecycle.view-status': 'testnet_get_validator_live_status',
  'operations.lifecycle.start-node': 'testnet_node_control',
  'operations.lifecycle.stop-node': 'testnet_node_control',
  'operations.lifecycle.restart-node': 'testnet_node_control',
  'operations.lifecycle.safe-shutdown': 'testnet_node_control',
  'operations.lifecycle.emergency-stop': 'testnet_node_control',
  'operations.network-vpn.vpn-status': 'onboarding:getMeshHealth',
  'operations.network-vpn.innernet-status': 'onboarding:getMeshHealth',
  'operations.network-vpn.reset-innernet-client': 'testnet_reset_innernet_client_state',
  'operations.network-vpn.check-coordinator': 'onboarding:getMeshHealth',
  'operations.network-vpn.view-connected-peers': 'testnet_get_feature_snapshot',
  'operations.network-vpn.view-known-peers': 'testnet_get_feature_snapshot',
  'operations.network-vpn.refresh-seed-registration': 'testnet_run_register_with_seeds',
  'operations.network-vpn.check-routes': 'onboarding:getMeshHealth',
  'operations.network-vpn.test-port-reachability': 'testnet_get_node_readiness',
  'operations.sync-chain-state.sync-status': 'testnet_get_validator_live_status',
  'operations.sync-chain-state.verify-chain-state': 'testnet_get_feature_snapshot',
  'operations.sync-chain-state.compare-network-head': 'testnet_get_validator_live_status',
  'operations.sync-chain-state.compare-archive-node': 'testnet_diagnose_onboarding_sync',
  'operations.sync-chain-state.finality-status': 'testnet_get_validator_live_status',
  'operations.sync-chain-state.epoch-status': 'testnet_get_validator_live_status',
  'operations.sync-chain-state.inspect-recent-blocks': 'testnet_get_chain_blocks',
  'operations.sync-chain-state.force-resync': 'testnet_boost_sync',
  'operations.sync-chain-state.start-normal-sync': 'testnet_start_validator_normal_sync',
  'operations.sync-chain-state.recover-local-fork': 'testnet_recover_local_fork',
  'operations.snapshots-recovery.download-snapshot': 'testnet_download_validator_snapshot',
  'operations.snapshots-recovery.view-snapshots': 'onboarding:discoverSnapshots',
  'operations.snapshots-recovery.apply-snapshot': 'onboarding:applyValidatorSnapshot',
  'operations.snapshots-recovery.restore-snapshot': 'testnet_restore_validator_snapshot',
  'operations.snapshots-recovery.create-local-snapshot': 'testnet_create_snapshot',
  'operations.snapshots-recovery.verify-snapshot': 'testnet_verify_validator_snapshot',
  'operations.snapshots-recovery.speed-sync': 'testnet_sync_catch_up_rejoin',
  'operations.snapshots-recovery.backup-config': 'testnet_export_config',
  'operations.snapshots-recovery.backup-keys': 'onboarding:exportEncryptedBackup',
  'operations.snapshots-recovery.restore-backup': 'testnet_restore_backup',
  'operations.snapshots-recovery.verify-backup': 'testnet_verify_backup',
  'operations.snapshots-recovery.import-config': 'testnet_import_config',
  'operations.wallet-keys.key-status': 'testnet_get_validator_live_status',
  'operations.wallet-keys.verify-owner-wallet': 'testnet_verify_validator_eligibility',
  'operations.wallet-keys.backup-keys': 'onboarding:exportEncryptedBackup',
  'operations.wallet-keys.restore-keys': 'testnet_restore_backup',
  'operations.wallet-keys.security-audit': 'testnet_get_feature_snapshot',
  'operations.consensus.validator-status': 'testnet_get_validator_live_status',
  'operations.consensus.eligibility-check': 'testnet_verify_validator_eligibility',
  'operations.consensus.shadowing-status': 'testnet_get_validator_live_status',
  'operations.consensus.activation-schedule': 'testnet_get_validator_activation_preflight',
  'operations.consensus.request-validator-rejoin': 'testnet_request_validator_rejoin',
  'operations.consensus.view-validator-set': 'testnet_get_validator_activation_preflight',
  'operations.consensus.participation-report': 'testnet_get_validator_live_status',
  'operations.consensus.signing-key-status': 'testnet_get_validator_activation_preflight',
  'operations.consensus.slashing-risk': 'testnet_get_feature_snapshot',
  'operations.logs-diagnostics.live-logs': 'testnet_get_node_logs',
  'operations.logs-diagnostics.run-diagnostics': 'testnet_get_node_readiness',
  'operations.logs-diagnostics.network-diagnostics': 'testnet_get_feature_snapshot',
  'operations.logs-diagnostics.config-diagnostics': 'testnet_get_feature_snapshot',
  'operations.logs-diagnostics.security-diagnostics': 'testnet_get_feature_snapshot',
  'operations.logs-diagnostics.rpc-diagnostics': 'testnet_get_feature_snapshot',
  'operations.logs-diagnostics.dag-status': 'testnet_get_feature_snapshot',
  'operations.logs-diagnostics.mempool-status': 'testnet_get_feature_snapshot',
  'operations.logs-diagnostics.export-support-bundle': 'monitor_export_node_data',
  'operations.staking-rewards.view-stake': 'testnet_get_rewards_data',
  'operations.staking-rewards.check-account-parity': 'testnet_get_validator_activation_preflight',
  'operations.staking-rewards.complete-validator-self-bond': 'testnet_stake_validator',
  'operations.staking-rewards.view-rewards': 'testnet_get_rewards_data',
  'operations.updates-maintenance.check-updates': 'desktop:check-for-update',
  'operations.updates-maintenance.update-control-panel': 'desktop:download-update',
  'operations.updates-maintenance.run-update-preflight': 'testnet_get_node_readiness',
  'operations.updates-maintenance.backup-before-update': 'testnet_create_snapshot',
  'operations.updates-maintenance.disk-analysis': 'testnet_get_feature_snapshot',
  'operations.updates-maintenance.clean-temporary-files': 'testnet_clear_cache',
});

export const OPERATION_ACTION_BINDINGS = Object.freeze(
  Object.fromEntries(
    Object.entries(SERVICE_COMMAND_BY_ACTION_ID)
      .filter(([actionId]) => OPERATION_HANDLER_BY_ACTION_ID[actionId])
      .map(([actionId, serviceCommand]) => [
        actionId,
        Object.freeze({
          handler: OPERATION_HANDLER_BY_ACTION_ID[actionId],
          serviceCommand,
        }),
      ]),
  ),
);

export function getOperationActionBinding(actionId) {
  return OPERATION_ACTION_BINDINGS[actionId] || null;
}
