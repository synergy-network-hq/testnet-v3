const hre = require("hardhat");
const {
  loadDeployment,
  loadRuntime,
  parseArgs,
  rpcUrlForNetwork,
  saveRuntime,
} = require("./lib/common");

function parsePrivateKeys(raw) {
  if (!raw) return [];
  return raw
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const source = args.source;
  const destination = args.destination || hre.network.name;

  if (!source) {
    throw new Error("Missing --source <network>");
  }

  if (destination !== hre.network.name) {
    throw new Error(
      `Run this script on --network ${destination}. Current network: ${hre.network.name}`
    );
  }

  const sourceDeployment = loadDeployment(source);
  const destinationDeployment = loadDeployment(destination);
  const intent = loadRuntime(`latest-intent-${source}-to-${destination}.json`);

  const destinationHub = await hre.ethers.getContractAt(
    "SXCPIntentHub",
    destinationDeployment.contracts.sxcpIntentHub
  );
  const witnessRegistry = await hre.ethers.getContractAt(
    "WitnessRegistry",
    destinationDeployment.contracts.witnessRegistry
  );

  const sourceRpcUrl = rpcUrlForNetwork(source);
  if (!sourceRpcUrl) {
    throw new Error(`Missing RPC URL env var for source network ${source}`);
  }

  const sourceProvider = new hre.ethers.JsonRpcProvider(sourceRpcUrl);
  const observedSourceHead = await sourceProvider.getBlockNumber();

  const sourceChainId = Number(sourceDeployment.chainId);
  const destinationChainId = Number(destinationDeployment.chainId);
  const epochId = Number(process.env.ATTESTATION_EPOCH_ID || 1);
  const sourceCommitmentRef = intent.txHash;

  const stateProofRoot =
    process.env.STATE_PROOF_ROOT ||
    hre.ethers.keccak256(
      hre.ethers.solidityPacked(
        ["bytes32", "bytes32", "uint256", "uint64", "uint64", "uint256", "uint256"],
        [
          intent.intentId,
          sourceCommitmentRef,
          sourceChainId,
          intent.sourceBlockNumber,
          intent.sourceLogIndex,
          intent.expiry,
          observedSourceHead,
        ]
      )
    );

  const digest = await destinationHub.computeAttestationDigest(
    sourceChainId,
    destinationChainId,
    intent.intentId,
    intent.scopeDigest,
    sourceCommitmentRef,
    intent.sourceBlockNumber,
    intent.sourceLogIndex,
    intent.expiry,
    epochId,
    stateProofRoot
  );

  const relayerKeys = parsePrivateKeys(process.env.RELAYER_PRIVATE_KEYS);
  if (relayerKeys.length === 0) {
    throw new Error("RELAYER_PRIVATE_KEYS is required for demo attestation");
  }

  const wallets = relayerKeys
    .map((key) => new hre.ethers.Wallet(key))
    .sort((a, b) => a.address.toLowerCase().localeCompare(b.address.toLowerCase()));

  const signers = wallets.map((wallet) => wallet.address);
  const threshold = Number(await witnessRegistry.getThreshold(epochId));
  if (signers.length < threshold) {
    throw new Error(`Need at least ${threshold} relayer signatures, got ${signers.length}`);
  }

  for (const signer of signers) {
    const isActive = await witnessRegistry.isActiveRelayer(signer, epochId);
    if (!isActive) {
      throw new Error(`Relayer ${signer} is not active in epoch ${epochId}`);
    }
  }

  const signatures = [];
  for (const wallet of wallets) {
    signatures.push(await wallet.signMessage(hre.ethers.getBytes(digest)));
  }

  const tx = await destinationHub.verifyAttestationBundle(
    sourceChainId,
    intent.intentId,
    intent.scopeDigest,
    sourceCommitmentRef,
    intent.sourceBlockNumber,
    intent.sourceLogIndex,
    observedSourceHead,
    intent.expiry,
    epochId,
    stateProofRoot,
    signers,
    signatures
  );
  const receipt = await tx.wait();

  const eventTopic = destinationHub.interface.getEvent("AttestationVerified").topicHash;
  const eventLog = receipt.logs.find(
    (log) =>
      log.address.toLowerCase() === destinationDeployment.contracts.sxcpIntentHub.toLowerCase() &&
      log.topics[0] === eventTopic
  );

  const parsed = eventLog ? destinationHub.interface.parseLog(eventLog) : null;
  const attestationId = parsed ? parsed.args.attestationId : null;

  const runtimePayload = {
    generatedAt: new Date().toISOString(),
    sourceNetwork: source,
    destinationNetwork: destination,
    sourceChainId,
    destinationChainId,
    intentId: intent.intentId,
    txHash: receipt.hash,
    stateProofRoot,
    epochId,
    observedSourceHead,
    signers,
    attestationId,
  };

  saveRuntime(`latest-attestation-${source}-to-${destination}.json`, runtimePayload);

  console.log("Attestation submitted:");
  console.log(JSON.stringify(runtimePayload, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
