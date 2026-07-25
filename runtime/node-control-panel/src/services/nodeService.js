import { invoke, invokeOnboarding, showOpenDialog, showSaveDialog } from '../lib/desktopClient.js';

function selectedNodeId(nodeId) {
  if (!nodeId) {
    throw new Error('No validator node is selected.');
  }
  return nodeId;
}

function currentTargetOs() {
  const platform = String(typeof navigator === 'undefined' ? '' : navigator.platform || '').toLowerCase();
  if (platform.includes('win')) return 'windows';
  if (platform.includes('mac')) return 'macos';
  if (platform.includes('linux')) return 'linux';
  return 'macos';
}

function selectedSnapshotId(snapshotId, action) {
  const id = String(snapshotId || '').trim();
  if (!id) {
    throw new Error(`Snapshot ${action} requires a selected snapshot ID.`);
  }
  return id;
}

function finiteValue(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function objectValue(value) {
  return value && typeof value === 'object' ? value : {};
}

function textValue(...values) {
  const value = values.find((candidate) => typeof candidate === 'string' && candidate.trim());
  return value ? value.trim() : '';
}

function actionMessage(action, message) {
  return {
    action,
    message,
  };
}

function liveStatusReport(status, action, report, message) {
  return {
    ...actionMessage(action, message),
    nodeId: status?.node_id || status?.validator_id || null,
    ...report,
  };
}

function statusHeight(status, ...keys) {
  const source = objectValue(status);
  for (const key of keys) {
    const value = finiteValue(source[key]);
    if (value !== null) return value;
  }
  return null;
}

function rewardValue(rewards, ...keys) {
  const live = objectValue(rewards?.live);
  for (const key of keys) {
    if (live[key] !== undefined && live[key] !== null) return live[key];
  }
  return null;
}

export const nodeService = {
  async getStatus(nodeId) {
    if (nodeId) {
      return invoke('testnet_get_validator_live_status', { nodeId });
    }
    return invoke('testnet_get_live_status');
  },

  async getSyncStatus(nodeId) {
    const status = await this.getStatus(selectedNodeId(nodeId));
    const localHeight = statusHeight(status, 'latest_finalized_height');
    const targetHeight = statusHeight(status, 'sync_target_height');
    const syncGap = targetHeight === null || localHeight === null
      ? null
      : Math.max(targetHeight - localHeight, 0);
    return liveStatusReport(
      status,
      'sync-status',
      {
        localHeadHeight: localHeight,
        syncTargetHeight: targetHeight,
        syncGap,
        syncTargetSource: status?.sync_target_source || null,
        syncTargetVerified: status?.sync_target_verified === true,
        syncTargetError: status?.sync_target_error || null,
      },
      syncGap === null
        ? 'Synchronization height is unavailable.'
        : status?.sync_target_verified === true
          ? `Local head is ${syncGap} block(s) behind the verified sync target.`
          : `Local head is ${syncGap} block(s) from an unverified sync target.`,
    );
  },

  async compareNetworkHead(nodeId) {
    const status = await this.getStatus(selectedNodeId(nodeId));
    const localHeight = statusHeight(status, 'latest_finalized_height');
    const networkHeight = statusHeight(status, 'sync_target_height');
    const heightDelta = localHeight === null || networkHeight === null
      ? null
      : networkHeight - localHeight;
    const matched = heightDelta === 0 && status?.sync_target_verified === true;
    return liveStatusReport(
      status,
      'compare-network-head',
      {
        localHeadHeight: localHeight,
        networkHeadHeight: networkHeight,
        heightDelta,
        matched,
        networkHeadSource: status?.sync_target_source || null,
        networkHeadVerified: status?.sync_target_verified === true,
        heightSources: Array.isArray(status?.height_sources) ? status.height_sources : [],
      },
      heightDelta === null
        ? 'Network head comparison is unavailable.'
        : matched
          ? `Local head matches the verified network head at block ${localHeight}.`
          : status?.sync_target_verified !== true && heightDelta === 0
            ? 'Local and reported network heads are at the same height, but the network head is not verified.'
            : `Local head differs from the network head by ${Math.abs(heightDelta)} block(s).`,
    );
  },

  async getFinalityStatus(nodeId) {
    const status = await this.getStatus(selectedNodeId(nodeId));
    const finalizedHeight = statusHeight(status, 'latest_finalized_height');
    const available = finalizedHeight !== null && Boolean(status?.latest_finalized_block_hash);
    const healthy = available && status?.local_rpc_ready === true && status?.is_quarantined !== true;
    return liveStatusReport(
      status,
      'finality-status',
      {
        available,
        healthy,
        finalizedHeight,
        finalizedBlockHash: status?.latest_finalized_block_hash || null,
        finalizedStateRoot: status?.latest_state_root || null,
        latestQcHash: status?.latest_qc_hash || null,
        source: status?.sync_target_source || null,
      },
      !available
        ? 'Finality data is unavailable.'
        : healthy
          ? `Finality is healthy at finalized block ${finalizedHeight}.`
          : `Finalized block ${finalizedHeight} is reported, but finality health is not confirmed.`,
    );
  },

  async getEpochStatus(nodeId) {
    const status = await this.getStatus(selectedNodeId(nodeId));
    const activity = objectValue(status?.consensus_activity);
    const lifecycle = objectValue(status?.lifecycle);
    const epoch = statusHeight(status, 'current_epoch') ?? statusHeight(activity, 'current_epoch');
    const currentHeight = statusHeight(activity, 'current_height')
      ?? statusHeight(status, 'latest_finalized_height');
    return liveStatusReport(
      status,
      'epoch-status',
      {
        available: epoch !== null,
        currentEpoch: epoch,
        currentHeight,
        currentRound: statusHeight(status, 'current_round') ?? statusHeight(activity, 'current_round'),
        currentClusterId: statusHeight(status, 'current_cluster_id') ?? statusHeight(activity, 'current_cluster_id'),
        lifecycleState: lifecycle.current_state || null,
        pendingActivationEpoch: finiteValue(lifecycle.pending_activation_epoch),
        expectedActivationHeight: finiteValue(lifecycle.expected_activation_height),
      },
      epoch === null
        ? 'Epoch data is unavailable.'
        : `Current epoch is ${epoch} at block ${currentHeight ?? 'unknown'}.`,
    );
  },

  async getKeyStatus(nodeId) {
    const status = await this.getStatus(selectedNodeId(nodeId));
    const keyStatus = objectValue(status?.aegis_pqvm);
    return liveStatusReport(
      status,
      'key-status',
      {
        available: Object.keys(keyStatus).length > 0,
        status: keyStatus.status || null,
        version: keyStatus.version || null,
        consensusKeyStatus: keyStatus.validator_consensus_key_status || null,
        peerIdentityKeyStatus: keyStatus.validator_peer_identity_key_status || null,
        operatorKeyStatus: keyStatus.validator_operator_key_status || null,
        keyActiveForCurrentEpoch: keyStatus.key_active_for_current_epoch === true,
        latestSignatureVerificationResult: keyStatus.latest_signature_verification_result || null,
        latestQcVerificationResult: keyStatus.latest_qc_verification_result || null,
      },
      keyStatus.status
        ? `Validator key status is ${keyStatus.status}.`
        : 'Validator key status is unavailable.',
    );
  },

  async getValidatorStatus(nodeId) {
    const status = await this.getStatus(selectedNodeId(nodeId));
    return liveStatusReport(
      status,
      'validator-status',
      {
        status: status?.current_status || null,
        headline: status?.status_headline || null,
        severity: status?.status_severity || null,
        isRunning: status?.is_offline === false,
        isConsensusActive: status?.is_consensus_active === true,
        isSyncing: status?.is_syncing === true,
        isShadowing: status?.is_shadowing === true,
        isQuarantined: status?.is_quarantined === true,
        isFailedClosed: status?.is_failed_closed === true,
        nextExpectedAction: status?.next_expected_action || null,
      },
      status?.status_headline || 'Validator status is unavailable.',
    );
  },

  async getShadowingStatus(nodeId) {
    const status = await this.getStatus(selectedNodeId(nodeId));
    const lifecycle = objectValue(status?.lifecycle);
    const observation = objectValue(lifecycle.shadow_observation);
    return liveStatusReport(
      status,
      'shadowing-status',
      {
        isShadowing: status?.is_shadowing === true,
        lifecycleState: lifecycle.current_state || null,
        observationStatus: observation.status || null,
        latestHeight: finiteValue(observation.latest_height),
        observedBlocks: finiteValue(observation.observed_blocks),
        requiredBlocks: finiteValue(observation.required_blocks),
        remainingBlocks: finiteValue(observation.remaining_blocks),
        completed: observation.completed === true,
      },
      status?.is_shadowing === true
        ? `Validator shadowing state is ${lifecycle.current_state || 'active'}.`
        : 'Validator is not currently reporting shadowing.',
    );
  },

  async getActivationSchedule(nodeId) {
    const preflight = await this.getActivationPreflight(selectedNodeId(nodeId));
    return {
      ...actionMessage(
        'activation-schedule',
        preflight?.can_activate === true
          ? 'Validator activation is currently allowed.'
          : 'Validator activation remains blocked by preflight checks.',
      ),
      nodeId: preflight?.node_id || selectedNodeId(nodeId),
      canActivate: preflight?.can_activate === true,
      generatedAtUtc: preflight?.generated_at_utc || null,
      checks: Array.isArray(preflight?.checks) ? preflight.checks : [],
      onboardingPolicy: preflight?.onboarding_policy || null,
    };
  },

  async getParticipationReport(nodeId) {
    const status = await this.getStatus(selectedNodeId(nodeId));
    const activity = objectValue(status?.consensus_activity);
    const report = {
      isConsensusActive: status?.is_consensus_active === true,
      isVoting: status?.is_voting === true,
      isProposing: status?.is_proposing === true,
      currentEpoch: statusHeight(status, 'current_epoch') ?? statusHeight(activity, 'current_epoch'),
      currentHeight: statusHeight(activity, 'current_height'),
      currentLeader: activity.current_leader || null,
      proposalPhase: activity.proposal_phase || null,
      votePhase: activity.vote_phase || null,
      voteDecision: activity.vote_decision || null,
      qcStatus: activity.qc_status || null,
      signedWeight: finiteValue(activity.signed_weight),
      requiredThresholdWeight: finiteValue(activity.required_threshold_weight),
      stakeStatus: status?.stake_status || null,
      isSyncing: status?.is_syncing === true,
      isQuarantined: status?.is_quarantined === true,
    };
    return liveStatusReport(
      status,
      'participation-report',
      report,
      report.isConsensusActive
        ? `Consensus participation is active: ${report.isVoting ? 'voting' : 'not voting'}${report.isProposing ? ', proposing' : ''}.`
        : 'Consensus participation is not active.',
    );
  },

  async getStakeReport(nodeId) {
    const rewards = await this.getRewardsData(selectedNodeId(nodeId));
    const stakedBalance = rewardValue(rewards, 'staked_balance_snrg', 'staked_balance_raw');
    const totalPosition = rewardValue(rewards, 'current_total_position_snrg', 'current_total_position_raw');
    return {
      ...actionMessage(
        'view-stake',
        stakedBalance === null
          ? 'Validator stake data is unavailable.'
          : `Validator stake is ${stakedBalance} ${rewards?.token_symbol || 'SNRG'}.`,
      ),
      nodeId: rewards?.node_id || selectedNodeId(nodeId),
      stakedBalance,
      currentTotalPosition: totalPosition,
      validatorStatus: rewardValue(rewards, 'validator_status'),
      stakingEntryCount: rewardValue(rewards, 'staking_entry_count'),
      telemetry: rewards?.telemetry || null,
    };
  },

  async getAccountStateParityReport(nodeId) {
    const preflight = await this.getActivationPreflight(selectedNodeId(nodeId));
    const checks = Array.isArray(preflight?.checks) ? preflight.checks : [];
    const parityCheck = checks.find((check) => String(check?.id || '') === 'normal-sync-account-state-parity')
      || checks.find((check) => /account-state parity/i.test(`${check?.label || ''} ${check?.detail || ''}`));
    const status = String(parityCheck?.status || '').toLowerCase();
    const passed = ['pass', 'passed', 'ok', 'success'].includes(status);
    return {
      ...actionMessage(
        'account-state-parity',
        parityCheck?.detail
          || 'Validator account-state parity is unavailable from activation preflight.',
      ),
      nodeId: preflight?.node_id || selectedNodeId(nodeId),
      canActivate: preflight?.can_activate === true,
      generatedAtUtc: preflight?.generated_at_utc || null,
      passed,
      check: parityCheck || null,
      suggestion: parityCheck?.suggestion || null,
    };
  },

  async getRewardsReport(nodeId) {
    const rewards = await this.getRewardsData(selectedNodeId(nodeId));
    const historicalEarned = rewardValue(rewards, 'historical_earned_snrg', 'historical_earned_raw');
    const pendingRewards = rewardValue(rewards, 'pending_rewards_snrg', 'pending_rewards_raw');
    return {
      ...actionMessage(
        'view-rewards',
        historicalEarned === null && pendingRewards === null
          ? 'Validator rewards data is unavailable.'
          : `Historical rewards: ${historicalEarned ?? 'unavailable'}; pending rewards: ${pendingRewards ?? 'unavailable'}.`,
      ),
      nodeId: rewards?.node_id || selectedNodeId(nodeId),
      historicalEarned,
      pendingRewards,
      rewardHistory: Array.isArray(rewards?.live?.reward_history) ? rewards.live.reward_history : [],
      synergyMultiplier: rewardValue(rewards, 'synergy_multiplier'),
      telemetry: rewards?.telemetry || null,
    };
  },

  async getSigningKeyStatus(nodeId) {
    const preflight = await this.getActivationPreflight(selectedNodeId(nodeId));
    const checks = Array.isArray(preflight?.checks) ? preflight.checks : [];
    const keyChecks = checks.filter((check) => /key|identity|aegis|sign/i.test(`${check?.id || ''} ${check?.label || ''}`));
    return {
      ...actionMessage(
        'signing-key-status',
        keyChecks.length
          ? `Signing-key preflight returned ${keyChecks.length} key-related check(s).`
          : 'Signing-key status is unavailable.',
      ),
      nodeId: preflight?.node_id || selectedNodeId(nodeId),
      canActivate: preflight?.can_activate === true,
      checks: keyChecks,
      available: keyChecks.length > 0,
    };
  },

  async getFeatureSnapshot(nodeId, screenKey) {
    const key = String(screenKey || '').trim();
    if (!key) {
      throw new Error('A feature screen is required for this inspection.');
    }
    return invoke('testnet_get_feature_snapshot', {
      input: {
        nodeId: selectedNodeId(nodeId),
        screenKey: key,
      },
    });
  },

  async getRecentBlocks(nodeId, count = 40) {
    const normalizedCount = Math.max(1, Math.min(100, Math.trunc(Number(count) || 40)));
    return invoke('testnet_get_chain_blocks', {
      nodeId: selectedNodeId(nodeId),
      count: normalizedCount,
    });
  },

  async getActivationPreflight(nodeId) {
    return invoke('testnet_get_validator_activation_preflight', {
      nodeId: selectedNodeId(nodeId),
    });
  },

  async diagnoseOnboardingSync(nodeId) {
    return invoke('testnet_diagnose_onboarding_sync', {
      nodeId: selectedNodeId(nodeId),
    });
  },

  async getRewardsData(nodeId) {
    return invoke('testnet_get_rewards_data', { nodeId: selectedNodeId(nodeId) });
  },

  async getValidatorVpnStatus(nodeId) {
    selectedNodeId(nodeId);
    const report = await invokeOnboarding('getMeshHealth', { targetId: 'local' });
    const coordinator = objectValue(report?.coordinator);
    const connected = report?.connected === true
      || report?.handshake_confirmed === true
      || report?.handshakeConfirmed === true
      || Number(report?.peersConnected) > 0
      || Number(report?.peers_connected) > 0;
    const coordinatorReachable = coordinator.reachable === true || coordinator.status === 'ok';
    return {
      ...objectValue(report),
      connected,
      handshake_confirmed: connected,
      handshakeConfirmed: connected,
      coordinator_reachable: coordinatorReachable,
      coordinatorReachable,
      coordinator,
    };
  },

  async getInnernetStatus(nodeId) {
    const report = await this.getValidatorVpnStatus(selectedNodeId(nodeId));
    const connected = report?.connected === true
      || report?.handshake_confirmed === true
      || report?.handshakeConfirmed === true;
    return {
      ...objectValue(report),
      action: 'innernet-status',
      connected,
      message: connected
        ? 'The private validator network is connected and a peer handshake is confirmed.'
        : textValue(report?.message, report?.detail)
          || 'The private validator network has not confirmed a peer handshake.',
    };
  },

  async getCoordinatorStatus(nodeId) {
    const report = await this.getValidatorVpnStatus(selectedNodeId(nodeId));
    const reachable = report?.coordinator_reachable === true
      || report?.coordinatorReachable === true
      || report?.server_confirmed === true
      || report?.serverConfirmed === true;
    return {
      ...objectValue(report),
      action: 'coordinator-status',
      reachable,
      message: reachable
        ? 'The secure-network coordinator is reachable.'
        : textValue(report?.message, report?.detail)
          || 'Coordinator reachability has not been confirmed.',
    };
  },

  async discoverValidatorSnapshot(nodeId) {
    return invokeOnboarding('discoverSnapshots', {
      targetId: 'local',
      nodeId: selectedNodeId(nodeId),
    });
  },

  async downloadValidatorSnapshot(nodeId, snapshotId) {
    const input = { nodeId: selectedNodeId(nodeId) };
    const id = String(snapshotId || '').trim();
    if (id) input.snapshotId = id;
    return invoke('testnet_download_validator_snapshot', { input });
  },

  async verifyValidatorSnapshot(nodeId, snapshotId) {
    return invoke('testnet_verify_validator_snapshot', {
      input: {
        nodeId: selectedNodeId(nodeId),
        snapshotId: selectedSnapshotId(snapshotId, 'verification'),
      },
    });
  },

  async applyValidatorSnapshot(nodeId, snapshotId) {
    return invoke('testnet_apply_validator_snapshot', {
      input: {
        nodeId: selectedNodeId(nodeId),
        snapshotId: selectedSnapshotId(snapshotId, 'apply'),
      },
    });
  },

  async verifyValidatorEligibility(nodeId, walletAddress, validatorAddress) {
    const wallet = String(walletAddress || '').trim();
    if (!wallet) {
      throw new Error('A wallet address is required to verify validator eligibility.');
    }
    const input = {
      nodeId: selectedNodeId(nodeId),
      walletAddress: wallet,
    };
    const validator = String(validatorAddress || '').trim();
    if (validator) input.validatorAddress = validator;
    return invoke('testnet_verify_validator_eligibility', input);
  },

  async boostSync(nodeId) {
    return invoke('testnet_boost_sync', { nodeId: selectedNodeId(nodeId) });
  },

  async transferValidatorTokens(nodeId, destinationAddress, amountSnrg) {
    const amount = Number(amountSnrg);
    if (!Number.isSafeInteger(amount) || amount <= 0) {
      throw new Error('Enter a positive whole-number SNRG amount.');
    }
    return invoke('testnet_transfer_validator_tokens', {
      input: {
        nodeId: selectedNodeId(nodeId),
        destinationAddress,
        amountSnrg: amount,
      },
    });
  },

  async completeValidatorSelfBond(nodeId, ownerWalletAddress) {
    const wallet = String(ownerWalletAddress || '').trim();
    if (!wallet) {
      throw new Error('Connect and assign the validator owner wallet before completing the self-bond.');
    }
    return invoke('testnet_stake_validator', {
      input: {
        nodeId: selectedNodeId(nodeId),
        ownerWalletAddress: wallet,
        amountSnrg: 50000,
      },
    });
  },

  async start(nodeId) {
    return invoke('testnet_node_control', { input: { nodeId: selectedNodeId(nodeId), action: 'start' } });
  },

  async stop(nodeId) {
    return invoke('testnet_node_control', { input: { nodeId: selectedNodeId(nodeId), action: 'stop' } });
  },

  async restart(nodeId) {
    const id = selectedNodeId(nodeId);
    await invoke('testnet_node_control', { input: { nodeId: id, action: 'stop' } });
    return invoke('testnet_node_control', { input: { nodeId: id, action: 'start' } });
  },

  async safeShutdown(nodeId) {
    return invoke('testnet_node_control', { input: { nodeId: selectedNodeId(nodeId), action: 'safe-shutdown' } });
  },

  async emergencyStop(nodeId) {
    return invoke('testnet_node_control', { input: { nodeId: selectedNodeId(nodeId), action: 'emergency-stop' } });
  },

  async checkForUpdates() {
    const { checkForUpdate } = await import('../lib/appUpdater.js');
    return checkForUpdate();
  },

  async update() {
    const { downloadAndInstallUpdate } = await import('../lib/appUpdater.js');
    return downloadAndInstallUpdate();
  },

  async setupValidatorNode(input = {}) {
    return invokeOnboarding('createValidatorIdentity', {
      targetId: input.targetId || 'local',
      target: input.target,
      displayLabel: input.displayLabel || 'Validator Node',
      intendedDirectory: input.intendedDirectory || undefined,
      publicHost: input.publicHost || undefined,
      publicP2pPort: input.publicP2pPort || undefined,
      natMode: input.natMode || undefined,
      identityPassphrase: input.identityPassphrase,
    });
  },

  async createSnapshot(nodeId) {
    const id = selectedNodeId(nodeId);
    const target = await showSaveDialog({
      title: 'Create validator workspace snapshot',
      defaultPath: `${id}-control-panel-snapshot.tar.gz`,
    });
    if (!target) throw new Error('Snapshot creation was cancelled.');
    return invoke('testnet_create_snapshot', { nodeId: id, target });
  },

  async verifySnapshot(nodeId, snapshotId) {
    let selectedId = String(snapshotId || '').trim();
    if (!selectedId) {
      const downloaded = await this.downloadValidatorSnapshot(nodeId);
      selectedId = String(downloaded?.snapshotId || downloaded?.snapshot_id || '').trim();
    }
    return this.verifyValidatorSnapshot(nodeId, selectedId);
  },

  async speedSync(nodeId) {
    return invoke('testnet_sync_catch_up_rejoin', {
      input: { nodeId: selectedNodeId(nodeId), autoActivate: false },
    });
  },

  async startNormalSync(nodeId) {
    return invoke('testnet_start_validator_normal_sync', {
      input: { nodeId: selectedNodeId(nodeId), autoActivate: false },
    });
  },

  async recoverLocalFork(nodeId) {
    return invoke('testnet_recover_local_fork', {
      node_id: selectedNodeId(nodeId),
    });
  },

  async requestValidatorRejoin(nodeId) {
    return invoke('testnet_request_validator_rejoin', {
      input: { nodeId: selectedNodeId(nodeId) },
    });
  },

  async restoreValidatorSnapshot(nodeId) {
    return invoke('testnet_restore_validator_snapshot', {
      input: { nodeId: selectedNodeId(nodeId) },
    });
  },

  async downloadApplyValidatorSnapshot(nodeId) {
    const id = selectedNodeId(nodeId);
    return invokeOnboarding('applyValidatorSnapshot', { targetId: 'local', nodeId: id });
  },

  async resyncFromSnapshot(nodeId) {
    return this.downloadApplyValidatorSnapshot(nodeId);
  },

  async getLogs(nodeId, lines = 700) {
    return invoke('testnet_get_node_logs', { nodeId, lines });
  },

  streamLogs(nodeId, onBundle, { lines = 700, intervalMs = 3000 } = {}) {
    const id = selectedNodeId(nodeId);
    if (typeof onBundle !== 'function') {
      throw new Error('A log stream callback is required.');
    }
    let cancelled = false;
    let timer = null;
    const poll = async () => {
      if (cancelled) return;
      try {
        onBundle(await this.getLogs(id, lines));
      } catch (error) {
        onBundle({ error: String(error?.message || error), entries: [], summary: {} });
      }
      if (!cancelled) {
        timer = window.setTimeout(poll, intervalMs);
      }
    };
    void poll();
    return () => {
      cancelled = true;
      if (timer) window.clearTimeout(timer);
    };
  },

  async runHealthCheck(nodeId) {
    return invoke('testnet_get_node_readiness', { nodeId: selectedNodeId(nodeId) });
  },

  async exportSupportBundle(nodeId) {
    return invoke('monitor_export_node_data', { nodeSlotId: selectedNodeId(nodeId) });
  },

  async clearCache() {
    throw new Error('A validator node must be selected before clearing cache.');
  },

  async clearNodeCache(nodeId) {
    return invoke('testnet_clear_cache', { nodeId: selectedNodeId(nodeId) });
  },

  async verifyPorts(nodeId) {
    return invoke('testnet_get_node_readiness', { nodeId: selectedNodeId(nodeId) });
  },

  async refreshPeerRegistration(nodeId) {
    return invoke('testnet_run_register_with_seeds', { nodeId: selectedNodeId(nodeId) });
  },

  async backupKeys(nodeId) {
    const id = selectedNodeId(nodeId);
    const target = await showSaveDialog({
      title: 'Export encrypted validator key backup',
      defaultPath: `${id}-validator-keys.tar.gz`,
    });
    if (!target) throw new Error('Key backup was cancelled.');
    return invokeOnboarding('exportEncryptedBackup', { targetId: 'local', nodeId: id, target });
  },

  async encryptKeys(nodeId, passphrase) {
    const id = selectedNodeId(nodeId);
    const normalizedPassphrase = String(passphrase || '');
    if (normalizedPassphrase.length < 8) {
      throw new Error('Validator key encryption passphrase must be at least 8 characters.');
    }
    return invoke('testnet_encrypt_validator_keys', { nodeId: id, passphrase: normalizedPassphrase });
  },

  async exportConfig(nodeId) {
    const id = selectedNodeId(nodeId);
    const target = await showSaveDialog({
      title: 'Export validator configuration',
      defaultPath: `${id}-config.tar.gz`,
    });
    if (!target) throw new Error('Configuration export was cancelled.');
    return invoke('testnet_export_config', { nodeId: id, target });
  },

  async importConfig() {
    const source = await showOpenDialog({ title: 'Import validator configuration', properties: ['openFile'] });
    if (!source) throw new Error('Configuration import was cancelled.');
    return source;
  },

  async importConfigForNode(nodeId) {
    const source = await this.importConfig();
    return invoke('testnet_import_config', { nodeId: selectedNodeId(nodeId), source });
  },

  async verifyBackup(nodeId) {
    const source = await showOpenDialog({ title: 'Verify validator backup', properties: ['openFile'] });
    if (!source) throw new Error('Backup verification was cancelled.');
    return invoke('testnet_verify_backup', { nodeId: selectedNodeId(nodeId), source });
  },

  async restoreBackup(nodeId) {
    const source = await showOpenDialog({ title: 'Restore validator backup', properties: ['openFile'] });
    if (!source) throw new Error('Backup restore was cancelled.');
    return invoke('testnet_restore_backup', { nodeId: selectedNodeId(nodeId), source });
  },

  async applyLogRetention(nodeId, retentionDays) {
    return invoke('testnet_apply_log_retention', {
      nodeId: selectedNodeId(nodeId),
      retentionDays,
    });
  },

  async validatePath(path) {
    return invoke('testnet_validate_path', { path });
  },

  async eraseAllNodeFiles() {
    return invoke('testnet_erase_local_machine_data', { targetOs: currentTargetOs() });
  },

  async resetInnernetClientState() {
    return invoke('testnet_reset_innernet_client_state', { targetOs: currentTargetOs() });
  },
};
