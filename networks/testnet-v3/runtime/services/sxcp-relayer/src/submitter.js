import { ethers } from 'ethers';

const DEFAULT_GAS_LIMIT_MULTIPLIER = 1.2;
const INITIAL_BACKOFF_SECONDS = 5;
const MAX_BACKOFF_SECONDS = 300;
const MAX_RETRIES = 5;

export class DestinationChainSubmitter {
  constructor(config = {}) {
    this.config = {
      gasLimitMultiplier: config.gasLimitMultiplier || DEFAULT_GAS_LIMIT_MULTIPLIER,
      initialBackoff: config.initialBackoff || INITIAL_BACKOFF_SECONDS,
      maxBackoff: config.maxBackoff || MAX_BACKOFF_SECONDS,
      maxRetries: config.maxRetries || MAX_RETRIES,
      ...config,
    };

    this.providers = new Map();
    this.signers = new Map();
    this.nonces = new Map();
    this.contracts = new Map();

    this.logger = console;
  }

  async registerChain(chainId, rpcUrl, privateKeyOrSigner) {
    const provider = new ethers.JsonRpcProvider(rpcUrl);

    let signer;
    if (typeof privateKeyOrSigner === 'string') {
      signer = new ethers.Wallet(privateKeyOrSigner, provider);
    } else {
      signer = privateKeyOrSigner.connect(provider);
    }

    this.providers.set(chainId, provider);
    this.signers.set(chainId, signer);

    // Initialize nonce
    const nonce = await provider.getTransactionCount(signer.address);
    this.nonces.set(chainId, nonce);

    this.logger.info(`[Submitter] Registered chain ${chainId}, signer: ${signer.address}`);
  }

  async registerSXCPIntentHub(chainId, contractAddress, abi) {
    const provider = this.providers.get(chainId);
    const signer = this.signers.get(chainId);

    if (!provider || !signer) {
      throw new Error(`Chain ${chainId} not registered`);
    }

    const contract = new ethers.Contract(contractAddress, abi, signer);
    this.contracts.set(chainId, contract);

    this.logger.info(`[Submitter] Registered SXCPIntentHub on chain ${chainId}: ${contractAddress}`);
  }

  /**
   * Submit an attestation bundle to the destination chain
   */
  async submitAttestationBundle(destChainId, attestation) {
    const contract = this.contracts.get(destChainId);
    if (!contract) {
      throw new Error(`SXCPIntentHub not registered for chain ${destChainId}`);
    }

    const signer = this.signers.get(destChainId);
    const bundleId = attestation.bundleId;

    // Format signatures for contract
    const formattedSignatures = attestation.signatures.map(sig => ({
      relayer: sig.relayer,
      pqcSignature: sig.signature,
      pqcPublicKey: sig.publicKey,
      algorithm: sig.algorithm,
    }));

    this.logger.info(`[Submitter] Submitting bundle ${bundleId} to chain ${destChainId}...`);

    try {
      // Get gas estimate
      let gasEstimate;
      try {
        gasEstimate = await contract.verifyAttestationBundle.estimateGas(
          attestation.bundleHash,
          formattedSignatures,
          attestation.pqcCommitment,
          {
            from: signer.address,
          }
        );
      } catch (error) {
        this.logger.warn(`[Submitter] Gas estimation failed, using fallback: ${error.message}`);
        gasEstimate = BigInt(500000); // Fallback
      }

      // Apply gas limit multiplier
      const gasLimit = (gasEstimate * BigInt(Math.floor(this.config.gasLimitMultiplier * 100))) / BigInt(100);

      // Get current gas price
      const feeData = await this.providers.get(destChainId).getFeeData();
      const gasPrice = feeData.gasPrice || BigInt('20000000000');

      // Get nonce
      const nonce = this.nonces.get(destChainId);

      // Submit transaction
      const tx = await contract.verifyAttestationBundle(
        attestation.bundleHash,
        formattedSignatures,
        attestation.pqcCommitment,
        {
          nonce,
          gasPrice,
          gasLimit,
        }
      );

      // Increment nonce
      this.nonces.set(destChainId, nonce + 1);

      this.logger.info(
        `[Submitter] Bundle ${bundleId} submitted to chain ${destChainId}: ${tx.hash}`
      );

      // Wait for confirmation
      const receipt = await tx.wait(1);
      if (receipt && receipt.status === 1) {
        this.logger.info(`[Submitter] Bundle ${bundleId} confirmed on chain ${destChainId}`);
        return {
          success: true,
          txHash: tx.hash,
          blockNumber: receipt.blockNumber,
        };
      } else {
        throw new Error('Transaction failed or reverted');
      }
    } catch (error) {
      this.logger.error(`[Submitter] Submission failed for bundle ${bundleId}: ${error.message}`);
      throw error;
    }
  }

  /**
   * Get submission retry information
   */
  getRetryBackoff(retryCount) {
    const backoff = Math.min(
      this.config.initialBackoff * Math.pow(2, retryCount),
      this.config.maxBackoff
    );
    return Math.floor(backoff);
  }

  async close() {
    this.logger.info('[Submitter] Closed');
  }
}
