import { invoke, invokeOnboarding } from '../lib/desktopClient';
import { validatorVpnPeerName } from './validatorVpnPeerName';

function requireEligibility(eligibility) {
  if (eligibility?.eligible !== true || eligibility?.eligibilityStatus !== 'eligible') {
    throw new Error('Validator eligibility is not verified. Launch is blocked until 50,000 SNRG active stake is confirmed on-chain.');
  }
}

function requireBootstrapEligibility(eligibility) {
  const bonded = eligibility?.eligible === true && eligibility?.eligibilityStatus === 'eligible';
  const funded = eligibility?.fundingReadyToBond === true && eligibility?.eligibilityStatus === 'stake_ready_to_bond';
  if (!bonded && !funded) {
    throw new Error('Validator bootstrap is blocked until the validator has 50,000 SNRG confirmed funding or active bonded stake.');
  }
}

export const validatorProvisioningService = {
  async registerValidator(input) {
    requireEligibility(input?.eligibility);
    return invoke('testnet_run_validator_onboarding', { input: { ...input, phase: 'register-validator', autoActivate: false } });
  },

  async requestValidatorCertificate(input) {
    requireEligibility(input?.eligibility);
    return invokeOnboarding('getMeshHealth', { targetId: input?.targetId || 'local' });
  },

  async issueValidatorCertificate(input) {
    requireEligibility(input?.eligibility);
    return invokeOnboarding('getMeshHealth', { targetId: input?.targetId || 'local' });
  },

  async importValidatorVpnBootstrapNodes() {
    throw new Error('Secure-network peer topology is managed only by the coordinator. Manual bootstrap imports are not supported.');
  },

  async enrollValidatorVpn(input) {
    requireBootstrapEligibility(input?.eligibility);
    return invokeOnboarding('connectSecureNetwork', {
      targetId: input?.targetId || 'local',
      nodeId: input?.nodeId,
      onboardingToken: input?.onboardingToken,
      assignmentId: input?.assignmentId,
      validatorPublicKey: input?.validatorPublicKey,
      identityProof: input?.identityProof,
      peerName: validatorVpnPeerName(input),
      peerType: 'validator',
      walletAddress: input?.walletAddress,
      ownerWalletAddress: input?.ownerWalletAddress,
      operatorAddress: input?.operatorAddress,
      validatorAddress: input?.validatorAddress,
      stakeTxHash: input?.stakeTxHash,
      eligibility: input?.eligibility,
      target: input?.target,
    });
  },

  async installVpnConfig(input) {
    requireBootstrapEligibility(input?.eligibility);
    return this.enrollValidatorVpn(input);
  },

  async verifyVpnConnection(input) {
    requireBootstrapEligibility(input?.eligibility);
    return invokeOnboarding('getMeshHealth', { targetId: input?.targetId || 'local' });
  },

  async registerValidatorIdentity(input) {
    requireEligibility(input?.eligibility);
    return invoke('testnet_run_validator_onboarding', { input: { ...input, phase: 'register-identity', autoActivate: false } });
  },

  async fetchPeerConfiguration(input) {
    requireEligibility(input?.eligibility);
    return invokeOnboarding('getMeshHealth', { targetId: input?.targetId || 'local' });
  },

  async installPeerConfiguration() {
    throw new Error('Secure-network peer configuration is installed by innernet from the coordinator-issued invite.');
  },

  async downloadSnapshot(input) {
    requireEligibility(input?.eligibility);
    return invoke('testnet_restore_validator_snapshot', { input });
  },

  async verifySnapshot(input) {
    requireEligibility(input?.eligibility);
    return invoke('testnet_get_node_readiness', { nodeId: input?.nodeId });
  },

  async restoreSnapshot(input) {
    requireEligibility(input?.eligibility);
    return invoke('testnet_restore_validator_snapshot', { input });
  },

  async installValidatorService(input) {
    requireEligibility(input?.eligibility);
    return invoke('testnet_run_validator_onboarding', { input: { ...input, autoStart: false, autoActivate: false } });
  },

  async runAutonomousOnboarding(input) {
    requireBootstrapEligibility(input?.eligibility);
    return invokeOnboarding('launchNode', {
      targetId: input?.targetId || 'local',
      nodeId: input?.nodeId,
      syncMode: input?.syncMode,
    });
  },

  async getActivationPreflight(input) {
    requireEligibility(input?.eligibility);
    return invoke('testnet_get_validator_activation_preflight', {
      nodeId: input?.nodeId,
    });
  },

  async startValidatorService(input) {
    requireEligibility(input?.eligibility);
    return invoke('testnet_node_control', { input: { nodeId: input?.nodeId, action: 'start' } });
  },

  async waitForSync(input) {
    requireEligibility(input?.eligibility);
    return invoke('testnet_sync_catch_up_rejoin', { input: { nodeId: input?.nodeId, autoActivate: false } });
  },

  async activateValidator(input) {
    requireEligibility(input?.eligibility);
    return invoke('testnet_activate_validator', { input });
  },
};
