import { invokeOnboarding } from '../lib/desktopClient';

export const REQUIRED_VALIDATOR_STAKE_SNRG = 50000;
export const VALIDATOR_FEE_RESERVE_SNRG = 1;
export const VALIDATOR_FUNDING_TARGET_SNRG = REQUIRED_VALIDATOR_STAKE_SNRG + VALIDATOR_FEE_RESERVE_SNRG;
const TOKEN_SCALE = 1_000_000_000;
const TOKEN_SCALE_BIGINT = 1_000_000_000n;
const VALIDATOR_FUNDING_FALLBACK_GAS_LIMIT = 100_000n;
const VALIDATOR_FUNDING_MAX_FEE_PER_GAS_NWEI = 1_000n;
const VALIDATOR_FUNDING_TOKEN_FEE_BPS = 3n;
const BASIS_POINTS_DENOMINATOR = 10_000n;
const VALIDATOR_FUNDING_TARGET_NWEI_BIGINT = BigInt(VALIDATOR_FUNDING_TARGET_SNRG) * TOKEN_SCALE_BIGINT;
const VALIDATOR_FUNDING_FALLBACK_NETWORK_FEE_NWEI = (
  (VALIDATOR_FUNDING_TARGET_NWEI_BIGINT * VALIDATOR_FUNDING_TOKEN_FEE_BPS) / BASIS_POINTS_DENOMINATOR
  + VALIDATOR_FUNDING_FALLBACK_GAS_LIMIT * VALIDATOR_FUNDING_MAX_FEE_PER_GAS_NWEI
);
const VALIDATOR_FUNDING_FALLBACK_SENDER_NWEI = (
  VALIDATOR_FUNDING_TARGET_NWEI_BIGINT + VALIDATOR_FUNDING_FALLBACK_NETWORK_FEE_NWEI
);
export const VALIDATOR_FUNDING_SENDER_MINIMUM_SNRG = (
  Number(VALIDATOR_FUNDING_FALLBACK_SENDER_NWEI) / TOKEN_SCALE
);
const SYNERGY_TESTNET_RPC_URLS = Object.freeze([
  'https://testnet-rpc.synergy-network.io',
  'https://testnet-core-rpc.synergy-network.io',
]);
const SYNERGY_TESTNET_CHAIN_ID = 1264;
const SYNERGY_TESTNET_CHAIN_ID_HEX = '0x4f0';
const SYNERGY_TESTNET_NETWORK_ID = 'synergy-testnet-v3';
const STAKE_CONFIRMATION_ATTEMPTS = 15;
const STAKE_CONFIRMATION_INTERVAL_MS = 4000;
const FUNDING_OUTBOX_PREFIX = 'synergy:ncp:validator-funding:v1';

export const ELIGIBILITY_STATUSES = Object.freeze({
  walletNotConnected: 'wallet_not_connected',
  checking: 'checking',
  notEnoughBalance: 'not_enough_balance',
  notStaked: 'not_staked',
  stakePending: 'stake_pending',
  stakeInsufficient: 'stake_insufficient',
  stakeInvalid: 'stake_invalid',
  stakeReadyToBond: 'stake_ready_to_bond',
  eligible: 'eligible',
  error: 'error',
});

function numberOrZero(value) {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : 0;
}

export function emptyEligibility(walletAddress = '') {
  return {
    walletAddress,
    snrgBalance: 0,
    requiredStake: REQUIRED_VALIDATOR_STAKE_SNRG,
    activeStakeAmount: 0,
    pendingStakeAmount: 0,
    missingStakeAmount: REQUIRED_VALIDATOR_STAKE_SNRG,
    eligibilityStatus: walletAddress ? ELIGIBILITY_STATUSES.notStaked : ELIGIBILITY_STATUSES.walletNotConnected,
    eligible: false,
    stakeTxHash: '',
    stakeTxStatus: 'not_provided',
    bondTxHash: '',
    bondTxStatus: 'not_provided',
    validatorFundingAmount: 0,
    fundingReadyToBond: false,
    fundingSenderRequiredSnrg: VALIDATOR_FUNDING_SENDER_MINIMUM_SNRG,
    fundingNetworkFeeSnrg: Number(VALIDATOR_FUNDING_FALLBACK_NETWORK_FEE_NWEI) / TOKEN_SCALE,
    fundingGasLimit: Number(VALIDATOR_FUNDING_FALLBACK_GAS_LIMIT),
    validatorSlotId: '',
    lastVerifiedAt: null,
    errorMessage: '',
  };
}

function normalizeEligibility(payload, walletAddress) {
  const activeStakeAmount = numberOrZero(payload?.activeStakeAmount ?? payload?.active_stake_amount ?? payload?.activeStake);
  const pendingStakeAmount = numberOrZero(payload?.pendingStakeAmount ?? payload?.pending_stake_amount ?? payload?.pendingStake);
  const snrgBalance = numberOrZero(payload?.snrgBalance ?? payload?.snrg_balance ?? payload?.balance);
  const requiredStake = REQUIRED_VALIDATOR_STAKE_SNRG;
  const missingStakeAmount = Math.max(0, requiredStake - activeStakeAmount);
  const rawStatus = String(payload?.eligibilityStatus ?? payload?.eligibility_status ?? '').trim();
  const bondedStakeConfirmed = activeStakeAmount >= requiredStake;
  const validatorFundingAmount = numberOrZero(payload?.validatorFundingAmount ?? payload?.validator_funding_amount);
  const fundingReadyToBond = !bondedStakeConfirmed && validatorFundingAmount >= VALIDATOR_FUNDING_TARGET_SNRG;
  const derivedStatus = bondedStakeConfirmed
    ? ELIGIBILITY_STATUSES.eligible
    : activeStakeAmount > 0
      ? ELIGIBILITY_STATUSES.stakeInsufficient
      : fundingReadyToBond
        ? ELIGIBILITY_STATUSES.stakeReadyToBond
      : snrgBalance >= VALIDATOR_FUNDING_TARGET_SNRG
        ? ELIGIBILITY_STATUSES.notStaked
        : ELIGIBILITY_STATUSES.notEnoughBalance;
  const eligibilityStatus = (
    (rawStatus === ELIGIBILITY_STATUSES.eligible && !bondedStakeConfirmed)
      || (rawStatus === ELIGIBILITY_STATUSES.stakeReadyToBond && !fundingReadyToBond)
  )
    ? derivedStatus
    : rawStatus || derivedStatus;

  return {
    walletAddress,
    snrgBalance,
    requiredStake,
    activeStakeAmount,
    pendingStakeAmount,
    missingStakeAmount,
    eligibilityStatus,
    eligible: bondedStakeConfirmed && (payload?.eligible === true || eligibilityStatus === ELIGIBILITY_STATUSES.eligible),
    stakeTxHash: payload?.stakeTxHash ?? payload?.stake_tx_hash ?? '',
    stakeTxStatus: payload?.stakeTxStatus ?? payload?.stake_tx_status ?? 'not_provided',
    bondTxHash: payload?.bondTxHash ?? payload?.bond_tx_hash ?? '',
    bondTxStatus: payload?.bondTxStatus ?? payload?.bond_tx_status ?? 'not_provided',
    validatorFundingAmount,
    fundingReadyToBond,
    fundingSenderRequiredSnrg: numberOrZero(
      payload?.fundingSenderRequiredSnrg ?? payload?.funding_sender_required_snrg,
    ) || VALIDATOR_FUNDING_SENDER_MINIMUM_SNRG,
    fundingNetworkFeeSnrg: numberOrZero(
      payload?.fundingNetworkFeeSnrg ?? payload?.funding_network_fee_snrg,
    ) || Number(VALIDATOR_FUNDING_FALLBACK_NETWORK_FEE_NWEI) / TOKEN_SCALE,
    fundingGasLimit: numberOrZero(payload?.fundingGasLimit ?? payload?.funding_gas_limit)
      || Number(VALIDATOR_FUNDING_FALLBACK_GAS_LIMIT),
    validatorSlotId: payload?.validatorSlotId ?? payload?.validator_slot_id ?? '',
    lastVerifiedAt: payload?.lastVerifiedAt ?? payload?.last_verified_at ?? new Date().toISOString(),
    errorMessage: payload?.errorMessage ?? payload?.error_message ?? '',
  };
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function fundingOutboxKey(nodeId, targetId = 'local') {
  return `${FUNDING_OUTBOX_PREFIX}:${String(targetId || 'local')}:${String(nodeId || '')}`;
}

function readFundingOutbox(nodeId, targetId) {
  if (typeof window === 'undefined' || !nodeId) return null;
  try {
    const value = JSON.parse(window.localStorage.getItem(fundingOutboxKey(nodeId, targetId)) || 'null');
    return value && typeof value.txHash === 'string' ? value : null;
  } catch {
    return null;
  }
}

function writeFundingOutbox(record) {
  if (typeof window === 'undefined' || !record?.nodeId || !record?.txHash) return;
  try {
    window.localStorage.setItem(
      fundingOutboxKey(record.nodeId, record.targetId),
      JSON.stringify({ ...record, recordedAt: new Date().toISOString() }),
    );
  } catch {
    // The backend recording call immediately below remains the primary durable record.
  }
}

function clearFundingOutbox(nodeId, targetId) {
  if (typeof window === 'undefined' || !nodeId) return;
  try {
    window.localStorage.removeItem(fundingOutboxKey(nodeId, targetId));
  } catch {
    // Canonical verification remains authoritative if browser storage is unavailable.
  }
}

function eligibilityHasConfirmedBondedStake(eligibility) {
  const requiredStake = numberOrZero(eligibility?.requiredStake) || REQUIRED_VALIDATOR_STAKE_SNRG;
  return eligibility?.eligible === true
    && eligibility?.eligibilityStatus === ELIGIBILITY_STATUSES.eligible
    && numberOrZero(eligibility?.activeStakeAmount) >= requiredStake;
}

async function queryPublicRpc(method, params = []) {
  let lastError = null;
  for (const rpcUrl of SYNERGY_TESTNET_RPC_URLS) {
    try {
      const response = await fetch(rpcUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: Date.now(),
          method,
          params,
        }),
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok || payload.error) {
        throw new Error(payload.error?.message || payload.error || `Synergy RPC ${method} failed.`);
      }
      return payload.result;
    } catch (error) {
      lastError = error;
    }
  }
  throw new Error(lastError?.message || `Synergy RPC ${method} failed on every public endpoint.`);
}

function validatorFundingTargetNwei() {
  return String(VALIDATOR_FUNDING_TARGET_NWEI_BIGINT);
}

function buildStakeEnvelope({ ownerWalletAddress, validatorAddress }) {
  const amountNwei = validatorFundingTargetNwei();
  return {
    from: ownerWalletAddress,
    sender: ownerWalletAddress,
    to: ownerWalletAddress,
    receiver: ownerWalletAddress,
    value: '1',
    amountNwei: '1',
    tokenAmountNwei: amountNwei,
    gasLimit: String(VALIDATOR_FUNDING_FALLBACK_GAS_LIMIT),
    maxFee: '1000',
    chainId: SYNERGY_TESTNET_CHAIN_ID,
    chain_id: SYNERGY_TESTNET_CHAIN_ID,
    chainIdHex: SYNERGY_TESTNET_CHAIN_ID_HEX,
    networkId: SYNERGY_TESTNET_NETWORK_ID,
    network_id: SYNERGY_TESTNET_NETWORK_ID,
    data: `token_transfer:${JSON.stringify({
      to: validatorAddress,
      token: 'SNRG',
      amount: Number(amountNwei),
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
      bondAmountSnrg: REQUIRED_VALIDATOR_STAKE_SNRG,
      feeReserveSnrg: VALIDATOR_FEE_RESERVE_SNRG,
      custody: 'validator_funding_then_local_self_bond',
    },
  };
}

function bigintFromRpc(value, fallback) {
  try {
    if (value == null || String(value).trim() === '') return fallback;
    const parsed = BigInt(String(value));
    return parsed >= 0n ? parsed : fallback;
  } catch {
    return fallback;
  }
}

async function estimateValidatorFundingEnvelope({ ownerWalletAddress, validatorAddress, envelope }) {
  const baseEnvelope = envelope || buildStakeEnvelope({ ownerWalletAddress, validatorAddress });
  let gasLimit = Number(VALIDATOR_FUNDING_FALLBACK_GAS_LIMIT);
  let maxNetworkFeeNwei = VALIDATOR_FUNDING_FALLBACK_NETWORK_FEE_NWEI;

  try {
    const nonce = await queryPublicRpc('synergy_getAccountNonce', [ownerWalletAddress]);
    const estimate = await queryPublicRpc('synergy_estimateGas', [{
      ...baseEnvelope,
      nonce: numberOrZero(nonce),
    }]);
    const estimatedGas = Number(estimate?.gas);
    if (Number.isSafeInteger(estimatedGas) && estimatedGas > 0) {
      gasLimit = estimatedGas;
    }
    maxNetworkFeeNwei = bigintFromRpc(
      estimate?.maxFee ?? estimate?.maxFeeBreakdown?.totalNetworkFeeNwei,
      maxNetworkFeeNwei,
    );
  } catch {
    // The conservative fallback covers the protocol fee and the 100,000-gas envelope.
  }

  const senderRequiredNwei = VALIDATOR_FUNDING_TARGET_NWEI_BIGINT + maxNetworkFeeNwei;
  return {
    envelope: {
      ...baseEnvelope,
      gasLimit: String(gasLimit),
      metadata: {
        ...baseEnvelope.metadata,
        estimatedNetworkFeeNwei: String(maxNetworkFeeNwei),
        senderRequiredNwei: String(senderRequiredNwei),
      },
    },
    gasLimit,
    maxNetworkFeeNwei,
    networkFeeSnrg: Number(maxNetworkFeeNwei) / TOKEN_SCALE,
    senderRequiredNwei,
    senderRequiredSnrg: Number(senderRequiredNwei) / TOKEN_SCALE,
  };
}

function extractWalletTransactionHash(result) {
  const candidates = [
    result?.txHash,
    result?.tx_hash,
    result?.transactionHash,
    result?.transaction_hash,
    result?.hash,
    result?.result?.txHash,
    result?.result?.tx_hash,
    result?.result?.transactionHash,
    result?.result?.transaction_hash,
    result?.result?.hash,
    result?.response?.txHash,
    result?.response?.tx_hash,
  ];
  return candidates.find((candidate) => typeof candidate === 'string' && candidate.trim())?.trim() || '';
}

export const validatorEligibilityService = {
  async connectWallet() {
    return null;
  },

  async disconnectWallet() {
    return null;
  },

  async getConnectedWallet(wallet) {
    return wallet || null;
  },

  async getSnrgBalance(walletAddress) {
    if (!walletAddress) return 0;
    const result = await queryPublicRpc('synergy_getTokenBalance', [walletAddress, 'SNRG']);
    return numberOrZero((result?.balance ?? result) / TOKEN_SCALE);
  },

  async getValidatorStake(walletAddress, validatorAddress = '') {
    if (!walletAddress) return emptyEligibility();
    return this.verifyValidatorEligibility(walletAddress, { validatorAddress });
  },

  async verifyValidatorEligibility(walletAddress, options = {}) {
    if (!walletAddress) {
      return emptyEligibility();
    }

    try {
      const targetId = options.targetId || 'local';
      const outbox = readFundingOutbox(options.nodeId, targetId);
      const matchingOutbox = outbox
        && outbox.walletAddress === walletAddress
        && (!options.validatorAddress || outbox.validatorAddress === options.validatorAddress)
        ? outbox
        : null;
      if (matchingOutbox) {
        try {
          await invokeOnboarding('recordValidatorFunding', {
            nodeId: options.nodeId,
            txHash: matchingOutbox.txHash,
            amountSnrg: VALIDATOR_FUNDING_TARGET_SNRG,
            targetId,
          });
          clearFundingOutbox(options.nodeId, targetId);
        } catch {
          // Keep the durable outbox and still verify the canonical transaction directly.
        }
      }
      const result = await invokeOnboarding('verifyValidatorEligibility', {
        walletAddress,
        nodeId: options.nodeId,
        validatorAddress: options.validatorAddress,
        requiredStake: REQUIRED_VALIDATOR_STAKE_SNRG,
        stakeTxHash: options.stakeTxHash || matchingOutbox?.txHash || undefined,
        targetId,
      });
      const normalized = normalizeEligibility(result, walletAddress);
      if (
        normalized.eligible
        || normalized.fundingReadyToBond
        || normalized.eligibilityStatus === ELIGIBILITY_STATUSES.stakeInvalid
      ) {
        clearFundingOutbox(options.nodeId, targetId);
      }
      return normalized;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error || 'Unknown validator eligibility error.');
      return {
        ...emptyEligibility(walletAddress),
        eligibilityStatus: ELIGIBILITY_STATUSES.error,
        errorMessage: `Validator stake verification failed: ${message}`,
        lastVerifiedAt: new Date().toISOString(),
      };
    }
  },

  async setValidatorOwner(nodeId, ownerWalletAddress, options = {}) {
    if (!nodeId || !ownerWalletAddress) return null;
    return invokeOnboarding('setValidatorOwner', {
      nodeId,
      ownerWalletAddress,
      targetId: options.targetId || 'local',
    });
  },

  async finalizeValidatorBond(input = {}) {
    if (!input.nodeId || !input.walletAddress) {
      throw new Error('A validator node and owner wallet are required to complete the self-bond.');
    }
    const result = await invokeOnboarding('finalizeValidatorBond', {
      nodeId: input.nodeId,
      ownerWalletAddress: input.walletAddress,
      targetId: input.targetId || 'local',
      amountSnrg: REQUIRED_VALIDATOR_STAKE_SNRG,
    });
    let latestEligibility = null;
    for (let attempt = 1; attempt <= STAKE_CONFIRMATION_ATTEMPTS; attempt += 1) {
      if (attempt > 1) await sleep(STAKE_CONFIRMATION_INTERVAL_MS);
      latestEligibility = await this.verifyValidatorEligibility(input.walletAddress, {
        nodeId: input.nodeId,
        validatorAddress: input.validatorAddress,
        targetId: input.targetId,
        stakeTxHash: input.stakeTxHash,
      });
      if (eligibilityHasConfirmedBondedStake(latestEligibility)) {
        return {
          ...result,
          eligibility: latestEligibility,
          bondConfirmed: true,
        };
      }
    }
    return {
      ...result,
      eligibility: latestEligibility,
      bondConfirmed: false,
      message: result?.message || 'Validator self-bond was submitted and is awaiting canonical confirmation. The control panel will resume without submitting a duplicate bond.',
    };
  },

  async stakeRequiredAmount(inputOrWalletAddress, legacyNodeId) {
    const input = typeof inputOrWalletAddress === 'object'
      ? inputOrWalletAddress
      : { walletAddress: inputOrWalletAddress, nodeId: legacyNodeId };
    const walletAddress = input.walletAddress;
    const nodeId = input.nodeId;
    const validatorAddress = input.validatorAddress;
    if (!walletAddress) {
      throw new Error('Connect a Synergy wallet before staking.');
    }
    if (!nodeId) {
      throw new Error('Provision or select a validator node before staking.');
    }
    if (!validatorAddress) {
      throw new Error('The selected validator node has not reported a synv1 validator address.');
    }
    if (typeof input.requestWalletAction !== 'function') {
      throw new Error('Mobile Synergy Wallet approval is required before staking.');
    }
    const preparedStake = await invokeOnboarding('bondStake', {
      nodeId,
      walletAddress,
      validatorAddress,
      targetId: input.targetId || 'local',
      amountNwei: validatorFundingTargetNwei(),
    });
    const preparedEnvelope = preparedStake?.walletRequest?.envelope || buildStakeEnvelope({
      ownerWalletAddress: walletAddress,
      validatorAddress,
    });
    const fundingEstimate = await estimateValidatorFundingEnvelope({
      ownerWalletAddress: walletAddress,
      validatorAddress,
      envelope: preparedEnvelope,
    });
    const availableSnrg = await this.getSnrgBalance(walletAddress);
    if (availableSnrg < fundingEstimate.senderRequiredSnrg) {
      throw new Error(
        `The owner wallet needs at least ${fundingEstimate.senderRequiredSnrg.toLocaleString(undefined, { maximumFractionDigits: 9 })} SNRG: ${VALIDATOR_FUNDING_TARGET_SNRG.toLocaleString()} SNRG for the validator plus up to ${fundingEstimate.networkFeeSnrg.toLocaleString(undefined, { maximumFractionDigits: 9 })} SNRG for the funding transaction fee.`,
      );
    }
    const envelope = fundingEstimate.envelope;
    const walletActionResult = await input.requestWalletAction({
      method: 'synergy_sendTransaction',
      params: [envelope],
      label: 'Fund validator self-bond',
      summary: `Send ${VALIDATOR_FUNDING_TARGET_SNRG.toLocaleString()} SNRG from ${walletAddress} to validator ${validatorAddress}: ${REQUIRED_VALIDATOR_STAKE_SNRG.toLocaleString()} SNRG for the bond plus ${VALIDATOR_FEE_RESERVE_SNRG} SNRG retained by the validator. The owner wallet may also pay up to ${fundingEstimate.networkFeeSnrg.toLocaleString(undefined, { maximumFractionDigits: 9 })} SNRG in network fees.`,
      metadata: envelope.metadata,
    });
    const stakeTxHash = extractWalletTransactionHash(walletActionResult);
    if (stakeTxHash) {
      writeFundingOutbox({
        nodeId,
        targetId: input.targetId || 'local',
        walletAddress,
        validatorAddress,
        txHash: stakeTxHash,
      });
    }
    if (stakeTxHash && typeof input.onTransactionSubmitted === 'function') {
      input.onTransactionSubmitted({
        stakeTxHash,
        submittedAt: new Date().toISOString(),
      });
    }
    if (stakeTxHash) {
      await invokeOnboarding('recordValidatorFunding', {
        nodeId,
        txHash: stakeTxHash,
        amountSnrg: VALIDATOR_FUNDING_TARGET_SNRG,
        targetId: input.targetId || 'local',
      });
      clearFundingOutbox(nodeId, input.targetId || 'local');
    }
    let latestEligibility = null;
    for (let attempt = 1; attempt <= STAKE_CONFIRMATION_ATTEMPTS; attempt += 1) {
      await sleep(attempt === 1 ? 1500 : STAKE_CONFIRMATION_INTERVAL_MS);
      latestEligibility = await this.verifyValidatorEligibility(walletAddress, {
        nodeId,
        validatorAddress,
        targetId: input.targetId,
        stakeTxHash,
      });
      if (eligibilityHasConfirmedBondedStake(latestEligibility)) {
        return {
          ...walletActionResult,
          eligibility: latestEligibility,
          stakeConfirmed: true,
          stakePending: false,
        };
      }
      if (latestEligibility?.fundingReadyToBond) {
        return {
          ...walletActionResult,
          stakeTxHash,
          eligibility: latestEligibility,
          stakeConfirmed: false,
          stakePending: false,
          fundingReadyToBond: true,
          message: 'Funding is confirmed in the validator balance. Complete Validator Self-Bond to create the protocol-locked stake without sending another transfer.',
        };
      }
    }

    return {
      ...walletActionResult,
      stakeTxHash,
      eligibility: latestEligibility,
      stakeConfirmed: false,
      stakePending: true,
      message: 'Funding approval was submitted, but the validator balance is not visible yet. Use Verify Bond after the transaction is included.',
    };
  },

  async refreshEligibility(walletAddress) {
    return this.verifyValidatorEligibility(walletAddress);
  },
};
