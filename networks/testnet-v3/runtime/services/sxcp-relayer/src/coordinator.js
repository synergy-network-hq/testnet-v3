import { ethers } from 'ethers';
import { Buffer } from 'buffer';
import crypto from 'crypto';

const BFT_THRESHOLD_FRACTION = 2 / 3; // 2/3 BFT threshold

export class QuorumCoordinator {
  constructor(relayerAddress, synergyRpcUrl, store, config = {}) {
    this.relayerAddress = relayerAddress;
    this.synergyRpcUrl = synergyRpcUrl;
    this.store = store;
    this.config = config;

    this.synergyProvider = null;
    this.pqcAlgorithm = config.pqcAlgorithm || 'fndsa';
    this.publicKeyB64 = config.pqcPublicKeyB64 || '';
    this.bundleSignatures = new Map(); // bundleId -> [{ relayer, signature, algorithm, publicKey }]
    this.pendingBundles = new Map(); // bundleId -> bundle metadata

    this.logger = console;
  }

  async initialize() {
    this.synergyProvider = new ethers.JsonRpcProvider(this.synergyRpcUrl);
    this.logger.info('[Coordinator] Initialized with Synergy Testnet');
  }

  /**
   * Register a new attestation bundle for quorum coordination
   */
  async registerBundle(bundleId, sourceChainId, destChainId, intentId, bundleHash, threshold) {
    this.bundleSignatures.set(bundleId, []);
    this.pendingBundles.set(bundleId, {
      bundleId,
      sourceChainId,
      destChainId,
      intentId,
      bundleHash,
      threshold,
      signers: new Set(),
      readyAt: null,
    });

    this.store.createBundle(bundleId, sourceChainId, destChainId, intentId, bundleHash, this.pqcAlgorithm, threshold);

    this.logger.info(`[Coordinator] Registered bundle ${bundleId} with threshold ${threshold}`);
  }

  /**
   * Submit a PQC signature for a bundle (from another relayer or self)
   */
  async submitSignature(bundleId, relayerAddress, pqcSignature, pqcPublicKey, algorithm) {
    const bundle = this.pendingBundles.get(bundleId);
    if (!bundle) {
      this.logger.warn(`[Coordinator] Unknown bundle: ${bundleId}`);
      return false;
    }

    // Prevent duplicate signatures from same relayer
    if (bundle.signers.has(relayerAddress)) {
      this.logger.warn(`[Coordinator] Duplicate signature from ${relayerAddress}`);
      return false;
    }

    const signatures = this.bundleSignatures.get(bundleId) || [];
    signatures.push({
      relayer: relayerAddress,
      signature: pqcSignature,
      publicKey: pqcPublicKey,
      algorithm: algorithm || this.pqcAlgorithm,
    });

    this.bundleSignatures.set(bundleId, signatures);
    bundle.signers.add(relayerAddress);

    this.store.incrementBundleSignatures(bundleId);

    this.logger.info(
      `[Coordinator] Bundle ${bundleId}: signature ${bundle.signers.size}/${bundle.threshold} collected`
    );

    // Check if quorum is reached
    if (this.isQuorumReached(bundleId)) {
      bundle.readyAt = new Date();
      this.logger.info(`[Coordinator] Bundle ${bundleId} reached quorum!`);
      return true;
    }

    return false;
  }

  /**
   * Check if a bundle has reached the BFT threshold
   */
  isQuorumReached(bundleId) {
    const bundle = this.pendingBundles.get(bundleId);
    if (!bundle) return false;

    // 2/3 BFT threshold
    const required = Math.ceil(bundle.threshold * BFT_THRESHOLD_FRACTION);
    return bundle.signers.size >= required;
  }

  /**
   * Get aggregate attestation for a bundle once quorum is reached
   */
  async getAggregateAttestation(bundleId) {
    const bundle = this.pendingBundles.get(bundleId);
    if (!bundle) {
      throw new Error(`Unknown bundle: ${bundleId}`);
    }

    if (!this.isQuorumReached(bundleId)) {
      throw new Error(`Bundle ${bundleId} has not reached quorum`);
    }

    const signatures = this.bundleSignatures.get(bundleId) || [];

    // Create PQC commitment hash
    const pqcCommitment = this.computePQCCommitment(
      bundle.bundleHash,
      signatures[0].algorithm,
      signatures[0].publicKey,
      signatures[0].signature
    );

    return {
      bundleId,
      bundleHash: bundle.bundleHash,
      intentId: bundle.intentId,
      sourceChainId: bundle.sourceChainId,
      destChainId: bundle.destChainId,
      signatures: signatures.map(s => ({
        relayer: s.relayer,
        signature: s.signature,
        publicKey: s.publicKey,
        algorithm: s.algorithm,
      })),
      pqcCommitment,
      signatureCount: signatures.length,
      threshold: bundle.threshold,
      collectedAt: bundle.readyAt,
    };
  }

  /**
   * Compute PQC commitment hash
   * keccak256(abi.encodePacked(algorithmId, pqcPublicKey, pqcSignature, digest))
   */
  computePQCCommitment(digest, algorithmId, pqcPublicKey, pqcSignature) {
    // Normalize algorithm ID to bytes (4 bytes)
    const algoBytes = Buffer.alloc(4);
    algoBytes.writeUInt32BE(this.algorithmToId(algorithmId), 0);

    // Combine: algorithmId + publicKey + signature + digest
    const packed = Buffer.concat([
      algoBytes,
      Buffer.from(pqcPublicKey, 'base64'),
      Buffer.from(pqcSignature, 'base64'),
      Buffer.from(digest.slice(2), 'hex'),
    ]);

    // Keccak256 hash
    const hash = ethers.keccak256(packed);
    return hash;
  }

  /**
   * Convert algorithm name to numeric ID
   */
  algorithmToId(algorithm) {
    const ids = {
      'ML-DSA-65': 1,
      'FN-DSA-1024': 2,
      'SLH-DSA': 3,
      'fndsa': 2, // Lowercase alias
      'mldsa': 1,
      'slhdsa': 3,
    };
    return ids[algorithm] || 2; // Default to FN-DSA
  }

  /**
   * Sign a bundle locally using Aegis-PQVM
   * This calls the Synergy node RPC for PQC operations
   */
  async signBundleLocally(bundleHash) {
    try {
      // Call Synergy node's aegis_signPQC RPC method
      const signature = await this.synergyProvider.send('aegis_signPQC', [
        bundleHash,
        this.pqcAlgorithm,
        this.relayerAddress,
      ]);

      this.logger.info(`[Coordinator] Signed bundle locally with ${this.pqcAlgorithm}`);

      return {
        signature,
        publicKey: this.publicKeyB64,
        algorithm: this.pqcAlgorithm,
      };
    } catch (error) {
      this.logger.error(`[Coordinator] PQC signing failed: ${error.message}`);
      throw error;
    }
  }

  /**
   * Verify a PQC signature (via Synergy node)
   */
  async verifySignature(bundleHash, signature, publicKey, algorithm) {
    try {
      const isValid = await this.synergyProvider.send('aegis_verifyPQC', [
        bundleHash,
        signature,
        publicKey,
        algorithm,
      ]);

      return isValid === true;
    } catch (error) {
      this.logger.error(`[Coordinator] Signature verification failed: ${error.message}`);
      return false;
    }
  }

  /**
   * Cleanup completed bundle from memory
   */
  finalizeBundle(bundleId) {
    this.bundleSignatures.delete(bundleId);
    this.pendingBundles.delete(bundleId);
    this.logger.info(`[Coordinator] Finalized bundle ${bundleId}`);
  }

  /**
   * Get pending bundles awaiting signatures
   */
  getPendingBundles() {
    const pending = [];
    for (const [bundleId, bundle] of this.pendingBundles) {
      pending.push({
        bundleId,
        signatureCount: bundle.signers.size,
        threshold: bundle.threshold,
        isReady: this.isQuorumReached(bundleId),
      });
    }
    return pending;
  }

  async close() {
    this.logger.info('[Coordinator] Closed');
  }
}
