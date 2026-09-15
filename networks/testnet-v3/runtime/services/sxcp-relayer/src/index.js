import dotenv from 'dotenv';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { ethers } from 'ethers';

import { RelayerStore } from './store.js';
import { SourceChainWatcher } from './watcher.js';
import { QuorumCoordinator } from './coordinator.js';
import { DestinationChainSubmitter } from './submitter.js';
import { SynergyReporter } from './reporter.js';

// Load environment variables
dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const logger = console;

/**
 * SXCP Relayer Daemon
 *
 * Implements the watch→finalize→sign→submit→report loop for cross-chain intent execution.
 *
 * Flow:
 * 1. Watch source chains (Sepolia, Amoy) for IntentCommitted events
 * 2. Collect signatures from peer relayers via quorum coordinator
 * 3. Sign locally using PQC (ML-DSA/FN-DSA via Aegis-PQVM)
 * 4. Submit attestation bundle to destination chain once quorum reached
 * 5. Report result to Synergy Testnet
 */

class SXCPRelayer {
  constructor() {
    this.config = this.loadConfig();
    this.store = null;
    this.watchers = new Map();
    this.coordinator = null;
    this.submitter = null;
    this.reporter = null;
    this.mainLoop = null;
  }

  loadConfig() {
    const configPath = process.env.SXCP_RELAYER_CONFIG_PATH;

    let config = {
      // Default configuration
      sepoliaChainId: 11155111,
      amoyChainId: 80002,
      destinationChainId: 1264, // Synergy Testnet
      relayerAddress: process.env.RELAYER_ADDRESS || '',
      pqcAlgorithm: process.env.PQC_ALGORITHM || 'fndsa',
      pqcPublicKeyB64: process.env.PQC_PUBLIC_KEY_B64 || '',
      pqcPrivateKeyPath: process.env.PQC_PRIVATE_KEY_PATH || './keys/relayer.pqc.enc',
      sxcpIntentHubAddress: '',
      sxcpVaultAddress: '',
      maxRetries: 5,
      pollInterval: 12000, // 12 seconds
      confirmationBlocks: 12,
    };

    // Load from config file if available
    if (configPath && fs.existsSync(configPath)) {
      try {
        const fileConfig = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
        config = { ...config, ...fileConfig };
        logger.info(`[Relayer] Loaded config from ${configPath}`);
      } catch (error) {
        logger.warn(`[Relayer] Failed to load config file: ${error.message}`);
      }
    }

    // Override with env vars
    if (process.env.SEPOLIA_CHAIN_ID) config.sepoliaChainId = Number(process.env.SEPOLIA_CHAIN_ID);
    if (process.env.AMOY_CHAIN_ID) config.amoyChainId = Number(process.env.AMOY_CHAIN_ID);
    if (process.env.DESTINATION_CHAIN_ID) config.destinationChainId = Number(process.env.DESTINATION_CHAIN_ID);

    return config;
  }

  async initialize() {
    logger.info('[Relayer] Starting SXCP Relayer daemon...');

    // Validate config
    if (!process.env.SEPOLIA_RPC_URL || !process.env.AMOY_RPC_URL) {
      throw new Error('Missing required RPC URLs in environment');
    }

    if (!this.config.relayerAddress) {
      throw new Error('Missing RELAYER_ADDRESS in config');
    }

    // Initialize store
    const dbPath = process.env.SQLITE_DB_PATH || './data/relayer.db';
    this.store = new RelayerStore(dbPath);
    this.store.initialize();

    // Initialize coordinator (quorum manager)
    this.coordinator = new QuorumCoordinator(
      this.config.relayerAddress,
      process.env.SYNERGY_RPC_URL || 'http://127.0.0.1:5640',
      this.store,
      {
        pqcAlgorithm: this.config.pqcAlgorithm,
        pqcPublicKeyB64: this.config.pqcPublicKeyB64,
      }
    );
    await this.coordinator.initialize();

    // Initialize submitter (destination chain)
    this.submitter = new DestinationChainSubmitter({
      gasLimitMultiplier: 1.2,
      initialBackoff: 5,
      maxBackoff: 300,
      maxRetries: this.config.maxRetries,
    });

    // Initialize reporter (Synergy Testnet)
    this.reporter = new SynergyReporter(
      process.env.SYNERGY_RPC_URL || 'http://127.0.0.1:5640',
      this.config.relayerAddress,
      {
        heartbeatInterval: 60,
      }
    );
    await this.reporter.initialize();

    // Initialize source chain watchers
    await this.initializeWatchers();

    logger.info('[Relayer] Initialization complete');
  }

  async initializeWatchers() {
    // Sepolia watcher
    const sepoliaWatcher = new SourceChainWatcher(
      this.config.sepoliaChainId,
      process.env.SEPOLIA_WS_URL || process.env.SEPOLIA_RPC_URL,
      process.env.SEPOLIA_RPC_URL,
      this.store,
      {
        pollIntervalMs: this.config.pollInterval,
        confirmationBlocks: this.config.confirmationBlocks,
      }
    );

    // Amoy watcher
    const amoyWatcher = new SourceChainWatcher(
      this.config.amoyChainId,
      process.env.AMOY_WS_URL || process.env.AMOY_RPC_URL,
      process.env.AMOY_RPC_URL,
      this.store,
      {
        pollIntervalMs: this.config.pollInterval,
        confirmationBlocks: this.config.confirmationBlocks,
      }
    );

    // Load contract addresses from config
    const sxcpIntentHubAddress = this.config.sxcpIntentHubAddress || '';
    const sxcpVaultAddress = this.config.sxcpVaultAddress || '';

    if (!sxcpIntentHubAddress || !sxcpVaultAddress) {
      logger.warn('[Relayer] SXCPIntentHub or SXCPVault address not configured');
    }

    // Initialize watchers
    await sepoliaWatcher.initialize(sxcpIntentHubAddress);
    await amoyWatcher.initialize(sxcpIntentHubAddress);

    // Register watchers
    this.watchers.set(this.config.sepoliaChainId, sepoliaWatcher);
    this.watchers.set(this.config.amoyChainId, amoyWatcher);

    // Setup event listeners
    sepoliaWatcher.on('IntentCommitted', (event) => this.handleIntentCommitted(event));
    amoyWatcher.on('IntentCommitted', (event) => this.handleIntentCommitted(event));

    logger.info('[Relayer] Source chain watchers initialized');
  }

  /**
   * Handle IntentCommitted event from source chain
   */
  async handleIntentCommitted(event) {
    logger.info(`[Relayer] IntentCommitted on chain ${event.chainId}: ${event.intentId}`);

    try {
      // Create bundle hash (simplified - in practice would include more data)
      const bundleData = ethers.solidityPacked(
        ['bytes32', 'address', 'uint256', 'bytes32'],
        [event.intentId, event.sender, event.nonce, event.intentHash]
      );
      const bundleHash = ethers.keccak256(bundleData);
      const bundleId = ethers.keccak256(ethers.solidityPacked(['bytes32', 'uint256'], [bundleHash, event.blockNumber]));

      // Register bundle with coordinator
      const threshold = this.config.threshold || 2; // 2/3 BFT
      await this.coordinator.registerBundle(
        bundleId,
        event.chainId,
        this.config.destinationChainId,
        event.intentId,
        bundleHash,
        threshold
      );

      // Sign locally
      try {
        const localSignature = await this.coordinator.signBundleLocally(bundleHash);
        await this.coordinator.submitSignature(
          bundleId,
          this.config.relayerAddress,
          localSignature.signature,
          localSignature.publicKey,
          localSignature.algorithm
        );
        logger.info(`[Relayer] Self-signed bundle ${bundleId}`);
      } catch (error) {
        logger.error(`[Relayer] Failed to sign bundle: ${error.message}`);
      }

      // Check if quorum reached (would normally wait for peer signatures)
      // For testing, proceed if we have local signature
      if (this.coordinator.isQuorumReached(bundleId)) {
        await this.processPendingBundle(bundleId);
      }
    } catch (error) {
      logger.error(`[Relayer] Error handling IntentCommitted: ${error.message}`);
      await this.reporter.reportError(event.intentId, error);
    }
  }

  /**
   * Process a bundle that has reached quorum
   */
  async processPendingBundle(bundleId) {
    try {
      logger.info(`[Relayer] Processing bundle ${bundleId}...`);

      // Get aggregate attestation
      const attestation = await this.coordinator.getAggregateAttestation(bundleId);

      // Submit to destination chain
      try {
        const result = await this.submitter.submitAttestationBundle(
          attestation.destChainId,
          attestation
        );

        this.store.updateBundleStatus(bundleId, 'submitted', true);
        logger.info(`[Relayer] Bundle ${bundleId} submitted: ${result.txHash}`);

        // Report to Synergy
        await this.reporter.submitAttestation(attestation);

        // Mark as finalized
        this.store.updateBundleStatus(bundleId, 'finalized', false, true);
        this.coordinator.finalizeBundle(bundleId);
      } catch (submitError) {
        logger.error(`[Relayer] Submission failed: ${submitError.message}`);

        // Implement exponential backoff retry
        const retryState = this.store.getRetryState(bundleId);
        const backoff = this.submitter.getRetryBackoff(retryState.retry_count);

        if (retryState.retry_count < this.config.maxRetries) {
          this.store.recordRetry(bundleId, submitError.message, backoff);
          logger.info(`[Relayer] Scheduled retry in ${backoff}s`);
        } else {
          logger.error(`[Relayer] Max retries exceeded for bundle ${bundleId}`);
          this.store.updateBundleStatus(bundleId, 'failed');
          await this.reporter.reportError(bundleId, submitError);
        }
      }
    } catch (error) {
      logger.error(`[Relayer] Error processing bundle ${bundleId}: ${error.message}`);
      await this.reporter.reportError(bundleId, error);
    }
  }

  /**
   * Main relay loop - process pending bundles
   */
  async runMainLoop() {
    const loopInterval = 5000; // 5 seconds

    const loop = async () => {
      try {
        // Process pending bundles waiting for submission
        const pending = this.store.getPendingBundles(10);

        for (const bundle of pending) {
          // Check if ready to submit
          if (this.coordinator.isQuorumReached(bundle.bundleId)) {
            await this.processPendingBundle(bundle.bundleId);
          }
        }

        // Process retries
        const retries = this.store.getPendingBundles(5); // In practice, would query retry_state
        // ... handle retries ...

      } catch (error) {
        logger.error(`[Relayer] Main loop error: ${error.message}`);
      }

      this.mainLoop = setTimeout(loop, loopInterval);
    };

    this.mainLoop = setTimeout(loop, loopInterval);
    logger.info('[Relayer] Main loop started');
  }

  async shutdown() {
    logger.info('[Relayer] Shutting down gracefully...');

    if (this.mainLoop) {
      clearTimeout(this.mainLoop);
    }

    // Close watchers
    for (const watcher of this.watchers.values()) {
      await watcher.close();
    }

    // Close coordinator
    if (this.coordinator) {
      await this.coordinator.close();
    }

    // Close submitter
    if (this.submitter) {
      await this.submitter.close();
    }

    // Close reporter
    if (this.reporter) {
      await this.reporter.close();
    }

    // Close store
    if (this.store) {
      this.store.close();
    }

    logger.info('[Relayer] Shutdown complete');
    process.exit(0);
  }

  async run() {
    try {
      await this.initialize();
      await this.runMainLoop();

      // Handle graceful shutdown
      process.on('SIGTERM', () => this.shutdown());
      process.on('SIGINT', () => this.shutdown());

      logger.info('[Relayer] Running...');
    } catch (error) {
      logger.error(`[Relayer] Fatal error: ${error.message}`);
      logger.error(error.stack);
      process.exit(1);
    }
  }
}

// Main entry point
const relayer = new SXCPRelayer();
relayer.run().catch((error) => {
  logger.error(`[Relayer] Startup failed: ${error.message}`);
  process.exit(1);
});
