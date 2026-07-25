import { ethers } from 'ethers';

const HEARTBEAT_INTERVAL_SECONDS = 60;

export class SynergyReporter {
  constructor(synergyRpcUrl, relayerAddress, config = {}) {
    this.synergyRpcUrl = synergyRpcUrl;
    this.relayerAddress = relayerAddress;
    this.config = {
      heartbeatInterval: config.heartbeatInterval || HEARTBEAT_INTERVAL_SECONDS,
      ...config,
    };

    this.provider = null;
    this.heartbeatTimer = null;
    this.lastHeartbeat = null;

    this.logger = console;
  }

  async initialize() {
    this.provider = new ethers.JsonRpcProvider(this.synergyRpcUrl);

    // Test connection
    try {
      const version = await this.provider.send('web3_clientVersion', []);
      this.logger.info(`[Reporter] Connected to Synergy Testnet: ${version}`);
    } catch (error) {
      this.logger.error(`[Reporter] Failed to connect to Synergy Testnet: ${error.message}`);
      throw error;
    }

    // Start heartbeat
    this.startHeartbeat();
  }

  /**
   * Submit an attestation result to Synergy Testnet
   */
  async submitAttestation(attestation) {
    try {
      const attestationData = {
        bundleId: attestation.bundleId,
        bundleHash: attestation.bundleHash,
        intentId: attestation.intentId,
        sourceChainId: attestation.sourceChainId,
        destChainId: attestation.destChainId,
        pqcCommitment: attestation.pqcCommitment,
        signatures: attestation.signatures.map(sig => ({
          relayer: sig.relayer,
          pqcSignature: sig.signature,
          pqcPublicKey: sig.publicKey,
          algorithm: sig.algorithm,
        })),
        signatureCount: attestation.signatureCount,
        threshold: attestation.threshold,
        timestamp: new Date().toISOString(),
      };

      const result = await this.provider.send('synergy_submitAttestation', [
        this.relayerAddress,
        attestationData,
      ]);

      this.logger.info(`[Reporter] Submitted attestation for bundle ${attestation.bundleId}`);

      return result;
    } catch (error) {
      this.logger.error(`[Reporter] Failed to submit attestation: ${error.message}`);
      throw error;
    }
  }

  /**
   * Send heartbeat to Synergy Testnet
   */
  async sendHeartbeat() {
    try {
      const heartbeat = {
        relayerAddress: this.relayerAddress,
        timestamp: new Date().toISOString(),
        status: 'active',
        version: '0.1.0',
      };

      const result = await this.provider.send('synergy_relayerHeartbeat', [heartbeat]);

      this.lastHeartbeat = new Date();
      this.logger.debug(`[Reporter] Heartbeat sent`);

      return result;
    } catch (error) {
      this.logger.warn(`[Reporter] Heartbeat failed: ${error.message}`);
      // Don't throw - heartbeat failures shouldn't stop the relayer
    }
  }

  /**
   * Start periodic heartbeat
   */
  startHeartbeat() {
    if (this.heartbeatTimer) return;

    const heartbeat = async () => {
      await this.sendHeartbeat();
      this.heartbeatTimer = setTimeout(heartbeat, this.config.heartbeatInterval * 1000);
    };

    // First heartbeat immediately
    heartbeat();
    this.logger.info('[Reporter] Heartbeat started');
  }

  /**
   * Stop periodic heartbeat
   */
  stopHeartbeat() {
    if (this.heartbeatTimer) {
      clearTimeout(this.heartbeatTimer);
      this.heartbeatTimer = null;
      this.logger.info('[Reporter] Heartbeat stopped');
    }
  }

  /**
   * Report an error condition to Synergy
   */
  async reportError(bundleId, error) {
    try {
      const errorReport = {
        relayerAddress: this.relayerAddress,
        bundleId,
        error: error.message,
        stack: error.stack,
        timestamp: new Date().toISOString(),
      };

      await this.provider.send('synergy_reportError', [errorReport]);
      this.logger.info(`[Reporter] Error reported for bundle ${bundleId}`);
    } catch (reportError) {
      this.logger.warn(`[Reporter] Failed to report error: ${reportError.message}`);
    }
  }

  /**
   * Get relayer status from Synergy
   */
  async getRelayerStatus() {
    try {
      const status = await this.provider.send('synergy_getRelayerStatus', [this.relayerAddress]);
      return status;
    } catch (error) {
      this.logger.warn(`[Reporter] Failed to get relayer status: ${error.message}`);
      return null;
    }
  }

  async close() {
    this.stopHeartbeat();
    this.logger.info('[Reporter] Closed');
  }
}
