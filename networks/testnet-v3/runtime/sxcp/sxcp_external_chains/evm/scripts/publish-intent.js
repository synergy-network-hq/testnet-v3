const hre = require("hardhat");
const { loadDeployment, parseArgs, saveRuntime } = require("./lib/common");

function buildIntentId(sender, sourceChainId, destinationChainId, scopeDigest, salt) {
  return hre.ethers.keccak256(
    hre.ethers.solidityPacked(
      ["address", "uint256", "uint256", "bytes32", "string"],
      [sender, sourceChainId, destinationChainId, scopeDigest, salt]
    )
  );
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const source = args.source || hre.network.name;
  const destination = args.destination;

  if (!destination) {
    throw new Error("Missing --destination <network>");
  }

  if (source !== hre.network.name) {
    throw new Error(`Run this script on --network ${source}. Current network: ${hre.network.name}`);
  }

  const sourceDeployment = loadDeployment(source);
  const destinationDeployment = loadDeployment(destination);
  const destinationChainId = Number(destinationDeployment.chainId);

  const [sender] = await hre.ethers.getSigners();
  const sourceNetwork = await hre.ethers.provider.getNetwork();
  const sourceChainId = Number(sourceNetwork.chainId);

  const scopeText = process.env.INTENT_SCOPE_TEXT || "SXCP_TESTNET_SCOPE:SEPOLIA_AMOY";
  const scopeDigest = hre.ethers.keccak256(hre.ethers.toUtf8Bytes(scopeText));
  const expirySeconds = Number(process.env.INTENT_EXPIRY_SECONDS || 3600);
  const expiry = Math.floor(Date.now() / 1000) + expirySeconds;
  const nonce = BigInt(process.env.INTENT_NONCE || Date.now());
  const salt = process.env.INTENT_SALT || `${Date.now()}`;
  const intentId = buildIntentId(sender.address, sourceChainId, destinationChainId, scopeDigest, salt);

  const intentHub = await hre.ethers.getContractAt(
    "SXCPIntentHub",
    sourceDeployment.contracts.sxcpIntentHub
  );

  const tx = await intentHub.publishIntent(intentId, destinationChainId, scopeDigest, expiry, nonce);
  const receipt = await tx.wait();

  const eventTopic = intentHub.interface.getEvent("IntentCommitted").topicHash;
  const intentLog = receipt.logs.find(
    (log) =>
      log.address.toLowerCase() === sourceDeployment.contracts.sxcpIntentHub.toLowerCase() &&
      log.topics[0] === eventTopic
  );

  const runtimePayload = {
    generatedAt: new Date().toISOString(),
    sourceNetwork: source,
    sourceChainId,
    destinationNetwork: destination,
    destinationChainId,
    intentId,
    scopeDigest,
    expiry,
    nonce: nonce.toString(),
    txHash: receipt.hash,
    sourceBlockNumber: receipt.blockNumber,
    sourceLogIndex: intentLog ? Number(intentLog.index) : 0,
    scopeText,
  };

  saveRuntime(`latest-intent-${source}-to-${destination}.json`, runtimePayload);

  console.log("Intent published:");
  console.log(JSON.stringify(runtimePayload, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
