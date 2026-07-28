const {
  confirmRedemption,
  getCoordinatorHealth,
  getMeshTransportSnapshot,
  getMeshStatus,
  requestInvite,
  waitForMeshPropagation,
} = require('../onboarding/coordinator-client.cjs');
const {
  activatePackagedWireguardConfig,
  getMeshHealth,
  redeemInvite,
} = require('../onboarding/innernet.cjs');
const {
  PendingInviteStore,
  isPendingInviteRecoverable,
} = require('../onboarding/pending-invites.cjs');
const { TargetRegistry } = require('../onboarding/targets.cjs');
const {
  decryptValidatorPackage,
  loadValidatorPackage,
} = require('../onboarding/validator-package.cjs');

const REQUIRED_VALIDATOR_STAKE_SNRG = 50_000;
const VALIDATOR_FEE_RESERVE_SNRG = 1;
const VALIDATOR_FUNDING_TARGET_SNRG = REQUIRED_VALIDATOR_STAKE_SNRG + VALIDATOR_FEE_RESERVE_SNRG;
const VALIDATOR_FUNDING_TARGET_NWEI = String(VALIDATOR_FUNDING_TARGET_SNRG * 1_000_000_000);
const VALIDATOR_FUNDING_GAS_LIMIT = '100000';

function ok(payload = {}) {
  if (payload && typeof payload === 'object' && !Array.isArray(payload)) {
    return { ok: true, ...payload };
  }
  return { ok: true, value: payload };
}

function codedError(code, message, details = null) {
  const error = new Error(message);
  error.code = code;
  if (details) {
    error.details = details;
  }
  return error;
}

function fail(error) {
  return {
    ok: false,
    code: error?.code || 'ONBOARDING_FAILED',
    error: error?.message || 'Onboarding failed.',
    details: error?.details || null,
  };
}

function targetId(input = {}) {
  return String(input?.targetId || input?.target?.id || 'local').trim() || 'local';
}

function requireString(input, key, code, message) {
  const value = String(input?.[key] || '').trim();
  if (!value) {
    throw codedError(code, message);
  }
  return value;
}

function setupOnboardingIpc(ipcMain, {
  invokeControlService,
  userDataPath,
  redeemInviteFn = redeemInvite,
  getMeshHealthFn = getMeshHealth,
  pendingInviteStore = new PendingInviteStore(userDataPath || process.cwd()),
}) {
  if (typeof invokeControlService !== 'function') {
    throw new Error('setupOnboardingIpc requires invokeControlService.');
  }

  const pendingInvitesByTarget = new Map();
  const pendingInvitesReady = pendingInviteStore.load().then((stored) => {
    for (const [id, invite] of stored) pendingInvitesByTarget.set(id, invite);
  });
  const configuredNodesByTarget = new Map();
  const targets = new TargetRegistry(userDataPath || process.cwd());

  const emitProgress = (event, payload) => {
    const scoped = { targetId: targetId(payload), ...payload };
    event?.sender?.send('onboarding:mesh-progress', scoped);
  };

  async function runOnTarget(input, { localCommand, localArgs, remoteCommand, remotePayload, timeoutMs } = {}) {
    if (targetId(input) === 'local') {
      return invokeControlService(localCommand, localArgs || {});
    }
    return targets.runRemoteControl(input, remoteCommand, remotePayload, { timeoutMs });
  }

  async function requestInviteForTarget(input = {}) {
    await pendingInvitesReady;
    const id = targetId(input);
    await targets.find(id);
    let validatorFields = {
      validatorAddress: input.validatorAddress,
      validatorPublicKey: input.validatorPublicKey,
      identityProof: input.identityProof,
      assignmentId: input.assignmentId,
      preconfiguredVpnIp: input.preconfiguredVpnIp,
      preconfiguredWireguardPublicKey: input.preconfiguredWireguardPublicKey,
      preconfiguredConfigVersion: input.preconfiguredConfigVersion,
    };
    if (String(input.peerType || '').trim() === 'validator') {
      const packaged = await loadValidatorPackage();
      if (packaged.available) {
        const nodeId = requireString(
          input,
          'nodeId',
          'NODE_REQUIRED',
          'Install the packaged validator identity before activating its secure network.',
        );
        const peerName = requireString(
          input,
          'peerName',
          'PEER_NAME_REQUIRED',
          'A validator nickname is required before activating the secure network.',
        );
        const proof = await runOnTarget(input, {
          localCommand: 'testnet_sign_packaged_validator_enrollment_proof',
          localArgs: {
            nodeId,
            assignmentId: packaged.assignmentId,
            peerName,
          },
          remoteCommand: 'sign-packaged-validator-enrollment-proof',
          remotePayload: {
            nodeId,
            assignmentId: packaged.assignmentId,
            peerName,
          },
        });
        validatorFields = {
          validatorAddress: proof.validatorAddress || proof.validator_address,
          validatorPublicKey: proof.validatorPublicKey || proof.validator_public_key,
          identityProof: proof.identityProof || proof.identity_proof,
          assignmentId: packaged.assignmentId,
          preconfiguredVpnIp: packaged.vpnIp,
          preconfiguredWireguardPublicKey: packaged.wireguardPublicKey,
          preconfiguredConfigVersion: packaged.vpnConfigVersion,
        };
      }
    }
    const invite = await requestInvite({
      onboardingToken: requireString(input, 'onboardingToken', 'ONBOARDING_TOKEN_REQUIRED', 'Enter the secure-network onboarding token.'),
      peerType: requireString(input, 'peerType', 'PEER_TYPE_REQUIRED', 'A peer type is required before requesting a secure-network invite.'),
      peerName: requireString(input, 'peerName', 'PEER_NAME_REQUIRED', 'A validator nickname is required before requesting a secure-network invite.'),
      nodeId: input.nodeId,
      validatorAddress: validatorFields.validatorAddress,
      operatorAddress: input.operatorAddress,
      ownerWalletAddress: input.ownerWalletAddress,
      walletAddress: input.walletAddress,
      stakeTxHash: input.stakeTxHash,
      identityPublicKey: input.identityPublicKey,
      identityFingerprint: input.identityFingerprint,
      validatorPublicKey: validatorFields.validatorPublicKey,
      identityProof: validatorFields.identityProof,
      eligibility: input.eligibility,
      validatorIdentity: input.validatorIdentity,
      assignmentId: validatorFields.assignmentId,
      preconfiguredVpnIp: validatorFields.preconfiguredVpnIp,
      preconfiguredWireguardPublicKey: validatorFields.preconfiguredWireguardPublicKey,
      preconfiguredConfigVersion: validatorFields.preconfiguredConfigVersion,
    });
    pendingInvitesByTarget.set(id, invite);
    await pendingInviteStore.save(pendingInvitesByTarget);
    return {
      enrollmentId: invite.enrollmentId,
      assignedIp: invite.assignedIp,
      expiresAt: invite.expiresAt,
      configurationVersion: invite.configurationVersion,
      interfaceName: invite.interfaceName,
      propagation: invite.propagation,
      preconfigured: invite.preconfigured,
    };
  }

  async function connectMeshForTarget(input = {}, event) {
    const id = targetId(input);
    const invite = pendingInvitesByTarget.get(id);
    if (!invite) {
      throw codedError('INVITE_REQUIRED', 'Request a secure-network invite before connecting the mesh.');
    }
    const nodeId = requireString(input, 'nodeId', 'NODE_REQUIRED', 'A validator node is required before connecting the secure network.');
    let completed = false;
    try {
      const result = await targets.withExecutor(input, async (executor) => {
        const mesh = invite.preconfigured
          ? await activatePackagedWireguardConfig(
            executor,
            await loadValidatorPackage({ includeSecrets: true }),
            (progress) => emitProgress(event, { targetId: id, ...progress }),
          )
          : await redeemInviteFn(
            executor,
            invite,
            {
              assignedIp: invite.assignedIp,
              interfaceName: invite.interfaceName,
            },
            (progress) => emitProgress(event, { targetId: id, ...progress }),
          );
        emitProgress(event, { targetId: id, step: 'confirming_redemption' });
        const redemption = await confirmRedemption({
          enrollmentId: invite.enrollmentId,
          confirmationToken: invite.confirmationToken,
          interfaceName: mesh.interfaceName,
          assignedIp: mesh.assignedIp,
        });
        emitProgress(event, { targetId: id, step: 'confirming_propagation' });
        const coordinator = await waitForMeshPropagation({
          enrollmentId: invite.enrollmentId,
          configurationVersion: invite.configurationVersion,
          confirmationToken: invite.confirmationToken,
          preconfigured: invite.preconfigured,
        });
        const innernetTransportSnapshot = await getMeshTransportSnapshot({
          enrollmentId: invite.enrollmentId,
          confirmationToken: invite.confirmationToken,
        });
        const coordinatorReceipt = redemption?.receipt
          || redemption?.coordinator_receipt
          || redemption?.coordinatorReceipt
          || null;
        if (!coordinatorReceipt) {
          throw codedError('COORDINATOR_RECEIPT_MISSING', 'The coordinator did not return a redemption receipt.');
        }
        const localInterfaceEvidence = {
          interfaceName: mesh.interfaceName,
          assignedIp: mesh.assignedIp,
          addresses: mesh.addresses,
          handshakeConfirmed: mesh.handshakeConfirmed,
          peersConnected: mesh.peersConnected,
          peers: mesh.peers,
        };
        const enrollmentRecord = {
          nodeId,
          enrollmentId: invite.enrollmentId,
          configurationVersion: invite.configurationVersion,
          coordinatorReceipt,
          innernetTransportSnapshot,
          localInterfaceEvidence,
        };
        const localRecord = await runOnTarget(input, {
          localCommand: 'testnet_record_innernet_enrollment',
          localArgs: { input: enrollmentRecord },
          remoteCommand: 'record-innernet-enrollment',
          remotePayload: enrollmentRecord,
        });
        return {
          enrollmentId: invite.enrollmentId,
          interfaceName: mesh.interfaceName,
          assignedIp: mesh.assignedIp,
          peers: mesh.peers,
          peersConnected: mesh.peersConnected,
          handshakeConfirmed: mesh.handshakeConfirmed,
          coordinator: { ...coordinator, redemption, receipt: coordinatorReceipt, status: 'confirmed' },
          coordinatorConfirmed: true,
          configurationVersion: invite.configurationVersion,
          propagation: { complete: true, generation: coordinator.generation },
          localRecord,
        };
      });
      completed = true;
      return result;
    } finally {
      if (completed) {
        pendingInvitesByTarget.delete(id);
        await pendingInviteStore.save(pendingInvitesByTarget);
      }
    }
  }

  async function reuseExistingMeshForTarget(input = {}) {
    const nodeId = requireString(input, 'nodeId', 'NODE_REQUIRED', 'A validator node is required before connecting the secure network.');
    const reused = await runOnTarget(input, {
      localCommand: 'testnet_reuse_innernet_enrollment',
      localArgs: { input: { nodeId, autoApply: true } },
      remoteCommand: 'reuse-innernet-enrollment',
      remotePayload: { nodeId },
    });
    if (reused?.status !== 'vpn_ready_reused') return null;

    const mesh = await targets.withExecutor(input, (executor) => getMeshHealthFn(executor));
    if (mesh?.handshakeConfirmed !== true && !(Number(mesh?.peersConnected) > 0)) {
      throw codedError(
        'EXISTING_MESH_HANDSHAKE_UNCONFIRMED',
        'The existing signed secure-network enrollment was restored, but no validator peer handshake is currently active.',
      );
    }
    const id = targetId(input);
    pendingInvitesByTarget.delete(id);
    await pendingInviteStore.save(pendingInvitesByTarget);
    return {
      reused: true,
      enrollmentId: reused.vpnNodeId || reused.vpn_node_id || null,
      interfaceName: mesh.interfaceName,
      assignedIp: mesh.assignedIp || reused.vpnIp || reused.vpn_ip || null,
      peers: mesh.peers || [],
      peersConnected: Number(mesh.peersConnected) || 0,
      handshakeConfirmed: true,
      coordinator: { status: 'confirmed', reused: true },
      coordinatorConfirmed: true,
      configurationVersion: reused.peerSnapshotGeneration || reused.peer_snapshot_generation || null,
      propagation: {
        complete: true,
        generation: reused.peerSnapshotGeneration || reused.peer_snapshot_generation || null,
      },
      localRecord: reused,
      message: reused.message,
    };
  }

  function handle(channel, handler) {
    ipcMain.handle(channel, async (event, input = {}) => {
      try {
        return ok(await handler(input || {}, event));
      } catch (error) {
        return fail(error);
      }
    });
  }

  async function deviceCheck(input = {}) {
    return runOnTarget(input, {
      localCommand: 'testnet_get_device_profile',
      remoteCommand: 'device-check',
    });
  }

  async function verifyEligibility(input = {}) {
    const eligibilityInput = {
      walletAddress: requireString(input, 'walletAddress', 'WALLET_REQUIRED', 'Connect the validator owner wallet before verifying stake.'),
      nodeId: input.nodeId || undefined,
      validatorAddress: input.validatorAddress || undefined,
      requiredStake: input.requiredStake || undefined,
      stakeTxHash: input.stakeTxHash || undefined,
    };
    return runOnTarget(input, {
      localCommand: 'testnet_verify_validator_eligibility',
      localArgs: eligibilityInput,
      remoteCommand: 'verify-validator-eligibility',
      remotePayload: eligibilityInput,
    });
  }

  async function prepareBondStake(input = {}) {
    const nodeId = requireString(input, 'nodeId', 'NODE_REQUIRED', 'A validator node is required before preparing the bonded stake transaction.');
    const ownerWalletAddress = requireString(input, 'walletAddress', 'WALLET_REQUIRED', 'Connect the validator owner wallet before preparing bonded stake.');
    const validatorAddress = requireString(input, 'validatorAddress', 'VALIDATOR_ADDRESS_REQUIRED', 'The validator must report a synv1 address before bonding stake.');
    const amountNwei = VALIDATOR_FUNDING_TARGET_NWEI;
    if (input.amountNwei != null && String(input.amountNwei) !== amountNwei) {
      throw codedError('STAKE_AMOUNT_INVALID', 'Validator funding must be exactly 50,001 SNRG: 50,000 SNRG bonded stake plus a 1 SNRG fee reserve.');
    }
    await runOnTarget({ ...input, nodeId, ownerWalletAddress }, {
      localCommand: 'testnet_set_validator_owner',
      localArgs: { input: { nodeId, ownerWalletAddress } },
      remoteCommand: 'set-validator-owner',
      remotePayload: { nodeId, ownerWalletAddress },
    });
    const tokenAmount = Number(amountNwei);
    if (!Number.isSafeInteger(tokenAmount)) {
      throw codedError('STAKE_AMOUNT_INVALID', 'The validator funding amount exceeds the mobile wallet safe integer limit.');
    }
    const envelope = {
      from: ownerWalletAddress,
      sender: ownerWalletAddress,
      // The external operator wallet funds the validator. The validator then
      // creates its own protocol-locked bond with its local signing key.
      to: ownerWalletAddress,
      receiver: ownerWalletAddress,
      value: '1',
      amountNwei: '1',
      tokenAmountNwei: amountNwei,
      gasLimit: VALIDATOR_FUNDING_GAS_LIMIT,
      maxFee: '1000',
      chainId: 1266,
      chain_id: 1266,
      chainIdHex: '0x4f2',
      networkId: 'synergy-testnet-v3',
      network_id: 'synergy-testnet-v3',
      data: `token_transfer:${JSON.stringify({
        to: validatorAddress,
        token: 'SNRG',
        amount: tokenAmount,
        memo: 'validator self-bond funding',
      })}`,
      signatureAlgorithm: 'fndsa',
      signature_algorithm: 'fndsa',
      metadata: {
        action: 'validator_bond_funding',
        ownerWalletAddress,
        validatorAddress,
        token: 'SNRG',
        amountSnrg: VALIDATOR_FUNDING_TARGET_SNRG,
        amountNwei,
        bondAmountSnrg: REQUIRED_VALIDATOR_STAKE_SNRG,
        feeReserveSnrg: VALIDATOR_FEE_RESERVE_SNRG,
        custody: 'validator_funding_then_local_self_bond',
      },
    };
    return {
      nodeId,
      ownerWalletAddress,
      walletRequest: {
        method: 'synergy_sendTransaction',
        params: [envelope],
        label: 'Fund validator self-bond',
        envelope,
      },
      message: 'Owner assignment is recorded. Approve the 50,001 SNRG funding transfer in Synergy Wallet: 50,000 SNRG for the bond plus a 1 SNRG fee reserve. After confirmation, the validator will create its own protocol-locked self-bond.',
    };
  }

  function summarizeNodeState(state, target, mesh = null, lastError = null) {
    const nodes = Array.isArray(state?.nodes) ? state.nodes : [];
    const node = nodes[0] || {};
    const lifecycle = String(node.lifecycleStatus || node.lifecycle_status || node.status || '').toLowerCase();
    const nodeRunning = ['running', 'active', 'ready', 'syncing', 'catching_up'].includes(lifecycle);
    const peers = Array.isArray(mesh?.peers) ? mesh.peers : [];
    const handshaked = peers.filter((peer) => peer?.lastHandshakeSecondsAgo !== null && peer?.lastHandshakeSecondsAgo !== undefined).length;
    return {
      targetId: target.id,
      label: target.label,
      reachable: !lastError,
      nodeRunning,
      meshConnected: Boolean(mesh?.interfaceUp || mesh?.interface_up),
      peersHandshaked: handshaked,
      peersTotal: peers.length,
      blockHeight: Number(node.blockHeight || node.block_height || node.localChainHeight || node.local_chain_height) || null,
      lastError: lastError ? String(lastError.message || lastError) : null,
    };
  }

  async function getAllDashboardStatus() {
    const configuredTargets = await targets.list();
    const statuses = await Promise.all(configuredTargets.map(async (target) => {
      try {
        const [state, mesh] = await Promise.all([
          runOnTarget({ targetId: target.id }, {
            localCommand: 'testnet_get_state',
            remoteCommand: 'testnet-state',
          }),
          targets.withExecutor({ targetId: target.id }, (executor) => getMeshHealth(executor)).catch(() => null),
        ]);
        return summarizeNodeState(state, target, mesh);
      } catch (error) {
        return summarizeNodeState(null, target, null, error);
      }
    }));
    return { targets: statuses };
  }

  handle('onboarding:list-targets', async () => ({ targets: await targets.list() }));

  handle('onboarding:add-target', async (input = {}) => {
    if (String(input?.mode || input?.target?.mode || '').trim().toLowerCase() === 'local') {
      return { targetId: 'local', pubkeyToInstall: null, installInstructions: null };
    }
    const result = await targets.add(input);
    return {
      targetId: result.target.id,
      pubkeyToInstall: result.publicKeyToInstall,
      installInstructions: result.publicKeyToInstall
        ? 'Install this public key in the target account authorized_keys file, then test the SSH connection.'
        : null,
    };
  });

  handle('onboarding:test-connection', async (input = {}) => {
    return targets.withExecutor(input, async (executor) => executor.testConnection ? executor.testConnection() : { connected: true });
  });

  handle('onboarding:device-check', deviceCheck);
  handle('onboarding:run-device-check', deviceCheck);

  handle('onboarding:set-validator-owner', async (input = {}) => {
    const ownerInput = {
      nodeId: requireString(input, 'nodeId', 'NODE_REQUIRED', 'A validator node is required before assigning its owner.'),
      ownerWalletAddress: requireString(input, 'ownerWalletAddress', 'WALLET_REQUIRED', 'Connect the validator owner wallet before assigning it.'),
    };
    return runOnTarget(input, {
      localCommand: 'testnet_set_validator_owner',
      localArgs: { input: ownerInput },
      remoteCommand: 'set-validator-owner',
      remotePayload: ownerInput,
    });
  });

  handle('onboarding:verify-validator-eligibility', verifyEligibility);
  handle('onboarding:verify-bond', verifyEligibility);

  handle('onboarding:connect-wallet', async (input = {}) => {
    const walletAddress = requireString(input, 'walletAddress', 'WALLET_REQUIRED', 'Approve wallet connection before continuing.');
    const eligibility = await verifyEligibility({ ...input, walletAddress });
    return { walletAddress, eligibility, signerManagedExternally: true };
  });

  handle('onboarding:get-wallet-status', async (input = {}) => {
    const walletAddress = requireString(input, 'walletAddress', 'WALLET_REQUIRED', 'Connect the validator owner wallet before checking its status.');
    return { walletAddress, ...(await verifyEligibility({ ...input, walletAddress })) };
  });

  handle('onboarding:bond-stake', prepareBondStake);

  handle('onboarding:record-validator-funding', async (input = {}) => {
    const amountSnrg = Number(input.amountSnrg ?? VALIDATOR_FUNDING_TARGET_SNRG);
    if (amountSnrg !== VALIDATOR_FUNDING_TARGET_SNRG) {
      throw codedError('STAKE_AMOUNT_INVALID', 'Validator funding must be exactly 50,001 SNRG: 50,000 SNRG bonded stake plus a 1 SNRG fee reserve.');
    }
    const fundingInput = {
      nodeId: requireString(input, 'nodeId', 'NODE_REQUIRED', 'A validator node is required before recording its funding transaction.'),
      txHash: requireString(input, 'txHash', 'TRANSACTION_REQUIRED', 'A funding transaction hash is required.'),
      amountSnrg,
    };
    return runOnTarget(input, {
      localCommand: 'testnet_record_validator_funding',
      localArgs: { input: fundingInput },
      remoteCommand: 'record-validator-funding',
      remotePayload: fundingInput,
    });
  });

  handle('onboarding:finalize-validator-bond', async (input = {}) => {
    const nodeId = requireString(input, 'nodeId', 'NODE_REQUIRED', 'A validator node is required before completing its self-bond.');
    const ownerWalletAddress = requireString(input, 'ownerWalletAddress', 'WALLET_REQUIRED', 'Connect the validator owner wallet before completing the self-bond.');
    const stakeInput = {
      nodeId,
      ownerWalletAddress,
      amountSnrg: Number(input.amountSnrg || 50000),
    };
    return runOnTarget(input, {
      localCommand: 'testnet_stake_validator',
      localArgs: { input: stakeInput },
      remoteCommand: 'stake-validator',
      remotePayload: stakeInput,
      timeoutMs: 60_000,
    });
  });

  handle('onboarding:generate-keys', async () => {
    throw codedError(
      'IDENTITY_CREATION_REQUIRED',
      'Create Validator Identity generates and encrypts all validator key material on the selected target as one atomic operation.',
    );
  });

  handle('onboarding:get-validator-package', async () => loadValidatorPackage());

  handle('onboarding:install-packaged-validator-identity', async (input = {}) => {
    const { packageData, packagedValidatorIdentity } = await decryptValidatorPackage(
      requireString(
        input,
        'identityPassphrase',
        'VALIDATOR_PASSPHRASE_REQUIRED',
        'Enter the validator identity passphrase.',
      ),
    );
    const setupInput = {
      roleId: 'validator',
      displayLabel: input.displayLabel || input.validatorMoniker || packageData.validatorLabel || `Validator ${packageData.validator}`,
      intendedDirectory: input.intendedDirectory || undefined,
      publicHost: input.publicHost || undefined,
      publicP2pPort: input.publicP2pPort || undefined,
      natMode: input.natMode || undefined,
      nodeAddressOverride: packageData.validatorAddress,
      packagedValidatorIdentity,
    };
    const result = await runOnTarget(input, {
      localCommand: 'testnet_setup_node',
      localArgs: { input: setupInput },
      remoteCommand: 'setup-node',
      remotePayload: setupInput,
    });
    const node = result?.node || {};
    const configPaths = Array.isArray(node.configPaths) ? node.configPaths : [];
    const configPath = configPaths.find((candidate) => /(?:^|\/)node\.toml$/i.test(String(candidate))) || configPaths[0] || null;
    configuredNodesByTarget.set(targetId(input), {
      nodeId: node.id || input.nodeId || null,
      configPath,
      workspaceDirectory: node.workspaceDirectory || node.workspace_directory || null,
    });
    return {
      ...result,
      validatorPackage: {
        assignmentId: packageData.assignmentId,
        validator: packageData.validator,
        validatorAddress: packageData.validatorAddress,
        vpnIp: packageData.vpnIp,
        activationStatus: packageData.activationStatus,
      },
      message: `Installed the encrypted ${packageData.assignmentId} identity and its assigned Testnet-v3 key roles.`,
    };
  });

  handle('onboarding:create-validator-identity', async (input = {}) => {
    const setupInput = {
        roleId: 'validator',
        displayLabel: input.displayLabel || input.validatorMoniker || 'Validator Node',
        intendedDirectory: input.intendedDirectory || undefined,
        publicHost: input.publicHost || undefined,
        publicP2pPort: input.publicP2pPort || undefined,
        natMode: input.natMode || undefined,
        identityPassphrase: input.identityPassphrase,
    };
    const result = await runOnTarget(input, {
      localCommand: 'testnet_setup_node',
      localArgs: { input: setupInput },
      remoteCommand: 'setup-node',
      remotePayload: setupInput,
    });
    const node = result?.node || {};
    const configPaths = Array.isArray(node.configPaths) ? node.configPaths : [];
    const configPath = configPaths.find((candidate) => /(?:^|\/)node\.toml$/i.test(String(candidate))) || configPaths[0] || null;
    const id = targetId(input);
    configuredNodesByTarget.set(id, {
      nodeId: node.id || input.nodeId || null,
      configPath,
      workspaceDirectory: node.workspaceDirectory || node.workspace_directory || null,
    });
    return result;
  });

  handle('onboarding:export-encrypted-backup', async (input = {}) => {
    const backupInput = {
      nodeId: requireString(input, 'nodeId', 'NODE_REQUIRED', 'A validator node is required before exporting a backup.'),
      target: input.target || undefined,
    };
    return runOnTarget(input, {
      localCommand: 'testnet_backup_keys',
      localArgs: backupInput,
      remoteCommand: 'backup-keys',
      remotePayload: backupInput,
    });
  });

  handle('onboarding:request-invite', async (input = {}) => {
    return requestInviteForTarget(input);
  });

  handle('onboarding:connect-mesh', async (input = {}, event) => connectMeshForTarget(input, event));

  handle('onboarding:connect-secure-network', async (input = {}, event) => {
    await pendingInvitesReady;
    const reused = await reuseExistingMeshForTarget(input);
    if (reused) return reused;
    const id = targetId(input);
    if (pendingInvitesByTarget.has(id)
      && !isPendingInviteRecoverable(pendingInvitesByTarget.get(id))) {
      pendingInvitesByTarget.delete(id);
      await pendingInviteStore.save(pendingInvitesByTarget);
    }
    if (!pendingInvitesByTarget.has(id)) await requestInviteForTarget(input);
    return connectMeshForTarget(input, event);
  });

  handle('onboarding:configure-node', async (input = {}) => {
    const configured = configuredNodesByTarget.get(targetId(input));
    if (!configured?.configPath) {
      throw codedError('NODE_CONFIGURATION_REQUIRED', 'Create the validator identity on this target before configuring the node.');
    }
    return {
      configured: true,
      nodeId: configured.nodeId,
      configPath: configured.configPath,
      workspaceDirectory: configured.workspaceDirectory,
      message: 'Validator configuration was generated with the encrypted identity and aligned with the applied secure-network peer configuration.',
    };
  });

  handle('onboarding:download-snapshot', async (input = {}) => {
    const nodeId = requireString(input, 'nodeId', 'NODE_REQUIRED', 'A validator node is required before downloading a snapshot.');
    return runOnTarget(input, {
      localCommand: 'testnet_download_validator_snapshot',
      localArgs: { input: { nodeId, snapshotId: input.snapshotId || undefined } },
      remoteCommand: 'download-validator-snapshot',
      remotePayload: { nodeId, snapshotId: input.snapshotId || undefined },
      timeoutMs: 2 * 60 * 60_000,
    });
  });

  handle('onboarding:verify-snapshot', async (input = {}) => {
    const nodeId = requireString(input, 'nodeId', 'NODE_REQUIRED', 'A validator node is required before verifying a snapshot.');
    const snapshotId = requireString(input, 'snapshotId', 'SNAPSHOT_REQUIRED', 'Select and download a snapshot before verifying it.');
    return runOnTarget(input, {
      localCommand: 'testnet_verify_validator_snapshot',
      localArgs: { input: { nodeId, snapshotId } },
      remoteCommand: 'verify-validator-snapshot',
      remotePayload: { nodeId, snapshotId },
      timeoutMs: 20 * 60_000,
    });
  });

  handle('onboarding:apply-verified-snapshot', async (input = {}) => {
    const nodeId = requireString(input, 'nodeId', 'NODE_REQUIRED', 'A validator node is required before applying a snapshot.');
    const snapshotId = requireString(input, 'snapshotId', 'SNAPSHOT_REQUIRED', 'Verify a selected snapshot before applying it.');
    return runOnTarget(input, {
      localCommand: 'testnet_apply_validator_snapshot',
      localArgs: { input: { nodeId, snapshotId } },
      remoteCommand: 'apply-validator-snapshot',
      remotePayload: { nodeId, snapshotId },
      timeoutMs: 20 * 60_000,
    });
  });

  handle('onboarding:apply-validator-snapshot', async (input = {}) => {
    const nodeId = requireString(input, 'nodeId', 'NODE_REQUIRED', 'A validator node is required before applying a snapshot.');
    const downloaded = await runOnTarget(input, {
      localCommand: 'testnet_download_validator_snapshot',
      localArgs: { input: { nodeId, snapshotId: input.snapshotId || undefined } },
      remoteCommand: 'download-validator-snapshot',
      remotePayload: { nodeId, snapshotId: input.snapshotId || undefined },
      timeoutMs: 2 * 60 * 60_000,
    });
    const snapshotId = requireString(downloaded, 'snapshotId', 'SNAPSHOT_REQUIRED', 'The archive catalog did not return a selected snapshot ID.');
    const verified = await runOnTarget(input, {
      localCommand: 'testnet_verify_validator_snapshot',
      localArgs: { input: { nodeId, snapshotId } },
      remoteCommand: 'verify-validator-snapshot',
      remotePayload: { nodeId, snapshotId },
      timeoutMs: 20 * 60_000,
    });
    const restore = await runOnTarget(input, {
      localCommand: 'testnet_apply_validator_snapshot',
      localArgs: { input: { nodeId, snapshotId } },
      remoteCommand: 'apply-validator-snapshot',
      remotePayload: { nodeId, snapshotId },
      timeoutMs: 20 * 60_000,
    });
    const sync = await runOnTarget(input, {
      localCommand: 'testnet_sync_catch_up_rejoin',
      localArgs: { input: { nodeId, autoActivate: false } },
      remoteCommand: 'validator-sync-catch-up',
      remotePayload: { nodeId, autoActivate: false },
      timeoutMs: 2 * 60 * 60_000,
    });
    return {
      nodeId,
      status: sync?.status || restore?.status || 'ok',
      downloaded,
      verified,
      restore,
      sync,
      message: `${restore?.detail || restore?.message || 'Validator snapshot applied.'} ${sync?.message || 'Live speed sync requested.'}`,
    };
  });

  handle('onboarding:discover-snapshots', async (input = {}) => runOnTarget(input, {
    localCommand: 'testnet_discover_validator_snapshot',
    remoteCommand: 'discover-validator-snapshot',
  }));

  handle('onboarding:apply-snapshot', async (input = {}) => {
    const nodeId = requireString(input, 'nodeId', 'NODE_REQUIRED', 'A validator node is required before applying a snapshot.');
    const restore = await runOnTarget(input, {
      localCommand: 'testnet_restore_validator_snapshot',
      localArgs: { input: { nodeId } },
      remoteCommand: 'restore-validator-snapshot',
      remotePayload: { nodeId },
    });
    return { nodeId, restore, status: restore?.status || 'ok', message: restore?.detail || 'Validator snapshot was restored after archive verification.' };
  });

  handle('onboarding:sync-after-snapshot', async (input = {}) => {
    const nodeId = requireString(input, 'nodeId', 'NODE_REQUIRED', 'A validator node is required before starting snapshot catch-up.');
    return runOnTarget(input, {
      localCommand: 'testnet_sync_catch_up_rejoin',
      localArgs: { input: { nodeId, autoActivate: false } },
      remoteCommand: 'validator-sync-catch-up',
      remotePayload: { nodeId, autoActivate: false },
      timeoutMs: 2 * 60 * 60_000,
    });
  });

  handle('onboarding:launch-node', async (input = {}) => {
    const launchInput = {
        nodeId: requireString(input, 'nodeId', 'NODE_REQUIRED', 'A validator node is required before launch.'),
        dryRun: false,
        autoStart: true,
        autoResyncTime: true,
        autoStake: false,
        autoActivate: false,
        syncMode: input.syncMode || undefined,
    };
    return runOnTarget(input, {
      localCommand: 'testnet_run_validator_onboarding',
      localArgs: { input: launchInput },
      remoteCommand: 'validator-onboarding',
      remotePayload: launchInput,
      timeoutMs: 2 * 60 * 60_000,
    });
  });

  handle('onboarding:start-normal-sync', async (input = {}) => {
    const nodeId = requireString(input, 'nodeId', 'NODE_REQUIRED', 'A validator node is required before normal sync.');
    return runOnTarget(input, {
      localCommand: 'testnet_start_validator_normal_sync',
      localArgs: { input: { nodeId, autoActivate: false } },
      remoteCommand: 'validator-normal-sync',
      remotePayload: { nodeId, autoActivate: false },
      timeoutMs: 5 * 60_000,
    });
  });

  handle('onboarding:get-status', async (input = {}) => {
    return runOnTarget(input, {
      localCommand: 'testnet_get_state',
      remoteCommand: 'testnet-state',
    });
  });

  handle('onboarding:get-onboarding-status', async (input = {}) => runOnTarget(input, {
    localCommand: 'testnet_get_state',
    remoteCommand: 'testnet-state',
  }));

  handle('onboarding:get-dashboard-status', async (input = {}) => {
    return runOnTarget(input, {
      localCommand: 'testnet_get_state',
      remoteCommand: 'testnet-state',
    });
  });

  handle('onboarding:recover-local-fork', async (input = {}) => {
    const nodeId = requireString(input, 'nodeId', 'NODE_REQUIRED', 'A validator node is required before local fork recovery.');
    return runOnTarget(input, {
      localCommand: 'testnet_recover_local_fork',
      localArgs: { nodeId },
      remoteCommand: 'recover-local-fork',
      remotePayload: { nodeId },
      timeoutMs: 2 * 60 * 60_000,
    });
  });

  handle('dashboard:get-all-status', getAllDashboardStatus);

  handle('onboarding:get-mesh-health', async (input = {}) => {
    return targets.withExecutor(input, async (executor) => {
      const mesh = await getMeshHealthFn(executor);
      let coordinator;
      try {
        coordinator = await getCoordinatorHealth();
      } catch (error) {
        coordinator = {
          reachable: false,
          error: error?.code || 'COORDINATOR_UNREACHABLE',
          detail: error?.message || 'Could not reach the secure-network coordinator.',
        };
      }
      return { ...mesh, coordinator };
    });
  });
}

module.exports = { setupOnboardingIpc };
