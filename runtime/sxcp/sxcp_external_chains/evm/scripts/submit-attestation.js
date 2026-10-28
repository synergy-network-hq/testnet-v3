import fs from "node:fs";
import { network } from "hardhat";
import {
  loadDeployment,
  loadRuntime,
  parseArgs,
  rpcUrlForNetwork,
  saveRuntime,
} from "./lib/common.js";

const args = parseArgs(process.argv.slice(2));
const connection = await network.create(args.network);
const { ethers, networkName } = connection;

async function main() {
  const source = args.source;
  const destination = args.destination || networkName;
  if (!source) throw new Error("Missing --source <network>");
  if (destination !== networkName) {
    throw new Error(`Run this script on --network ${destination}. Current network: ${networkName}`);
  }

  const bundlePath = process.env.PQC_ATTESTATION_BUNDLE_PATH;
  if (!bundlePath) {
    throw new Error("PQC_ATTESTATION_BUNDLE_PATH must identify a bundle verified by the off-chain PQC relayer");
  }
  const bundle = JSON.parse(fs.readFileSync(bundlePath, "utf8"));
  const pqcAlgorithmId = Number(bundle.pqcAlgorithmId);
  const epochId = Number(bundle.epochId);
  if (![1, 2, 3].includes(pqcAlgorithmId) || !Number.isSafeInteger(epochId) || epochId < 1) {
    throw new Error("Invalid PQC algorithm or epoch in attestation bundle");
  }
  const { stateProofRoot, digest: suppliedDigest, pqcCommitments } = bundle;
  if (!ethers.isHexString(stateProofRoot, 32) || !ethers.isHexString(suppliedDigest, 32)) {
    throw new Error("Bundle requires a 32-byte stateProofRoot and digest");
  }
  if (!Array.isArray(bundle.signers) || !Array.isArray(pqcCommitments) ||
      bundle.signers.length !== pqcCommitments.length || bundle.signers.length === 0) {
    throw new Error("Bundle requires matching nonempty signers and pqcCommitments arrays");
  }
  const signers = bundle.signers.map((address) => ethers.getAddress(address));
  let previous = 0n;
  for (let i = 0; i < signers.length; i++) {
    const current = BigInt(signers[i]);
    if (current <= previous) throw new Error("Bundle signers must be sorted and unique");
    if (!ethers.isHexString(pqcCommitments[i], 32) || BigInt(pqcCommitments[i]) === 0n) {
      throw new Error("PQC commitments must be nonzero 32-byte values");
    }
    previous = current;
  }

  const sourceDeployment = loadDeployment(source);
  const destinationDeployment = loadDeployment(destination);
  const intent = loadRuntime(`latest-intent-${source}-to-${destination}.json`);
  const destinationHub = await ethers.getContractAt("SXCPIntentHub", destinationDeployment.contracts.sxcpIntentHub);
  const witnessRegistry = await ethers.getContractAt("WitnessRegistry", destinationDeployment.contracts.witnessRegistry);
  const sourceRpcUrl = rpcUrlForNetwork(source);
  if (!sourceRpcUrl) throw new Error(`Missing RPC URL for source network ${source}`);
  const sourceProvider = new ethers.JsonRpcProvider(sourceRpcUrl);
  let observedSourceHead;
  try {
    observedSourceHead = await sourceProvider.getBlockNumber();
  } finally {
    sourceProvider.destroy();
  }
  const sourceChainId = Number(sourceDeployment.chainId);
  const destinationChainId = Number((await ethers.provider.getNetwork()).chainId);
  if (destinationChainId !== Number(destinationDeployment.chainId)) {
    throw new Error("Destination deployment chain does not match the selected network");
  }
  const sourceCommitmentRef = intent.txHash;
  const digest = await destinationHub.computeAttestationDigest(
    sourceChainId, destinationChainId, intent.intentId, intent.scopeDigest,
    sourceCommitmentRef, intent.sourceBlockNumber, intent.sourceLogIndex,
    intent.expiry, epochId, stateProofRoot, pqcAlgorithmId
  );
  if (digest.toLowerCase() !== suppliedDigest.toLowerCase()) {
    throw new Error("PQC bundle digest does not match the current intent and chain context");
  }
  const threshold = Number(await witnessRegistry.getThreshold(epochId));
  if (signers.length < threshold) throw new Error(`Need at least ${threshold} PQC commitments`);
  for (const signer of signers) {
    if (!(await witnessRegistry.isActiveRelayer(signer, epochId))) {
      throw new Error(`Relayer ${signer} is not active in epoch ${epochId}`);
    }
  }

  const tx = await destinationHub.verifyAttestationBundle(
    sourceChainId, intent.intentId, intent.scopeDigest, sourceCommitmentRef,
    intent.sourceBlockNumber, intent.sourceLogIndex, observedSourceHead,
    intent.expiry, epochId, stateProofRoot, pqcAlgorithmId, signers, pqcCommitments
  );
  const receipt = await tx.wait();
  const topic = destinationHub.interface.getEvent("PQCAttestationVerified").topicHash;
  const eventLog = receipt.logs.find((log) =>
    log.address.toLowerCase() === destinationDeployment.contracts.sxcpIntentHub.toLowerCase() &&
    log.topics[0] === topic);
  const attestationId = eventLog ? destinationHub.interface.parseLog(eventLog).args.attestationId : null;
  const payload = {
    generatedAt: new Date().toISOString(), sourceNetwork: source, destinationNetwork: destination,
    sourceChainId, destinationChainId, intentId: intent.intentId, txHash: receipt.hash,
    stateProofRoot, epochId, pqcAlgorithmId, observedSourceHead, signers, attestationId,
  };
  saveRuntime(`latest-attestation-${source}-to-${destination}.json`, payload);
  console.log(JSON.stringify(payload, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
}).finally(() => connection.close());
