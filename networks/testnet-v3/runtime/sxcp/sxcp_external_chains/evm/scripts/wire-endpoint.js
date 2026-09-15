const hre = require("hardhat");
const { chainIdForNetwork, loadDeployment, parseArgs } = require("./lib/common");

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const source = args.source || hre.network.name;
  const remote = args.remote;

  if (!remote) {
    throw new Error("Missing --remote <network>");
  }

  if (source !== hre.network.name) {
    throw new Error(`Run this script on --network ${source}. Current network: ${hre.network.name}`);
  }

  const sourceDeployment = loadDeployment(source);
  const remoteDeployment = loadDeployment(remote);
  const remoteChainId = Number(remoteDeployment.chainId || chainIdForNetwork(remote));

  const intentHub = await hre.ethers.getContractAt(
    "SXCPIntentHub",
    sourceDeployment.contracts.sxcpIntentHub
  );

  const tx = await intentHub.setRemoteEndpoint(
    remoteChainId,
    remoteDeployment.contracts.sxcpIntentHub,
    remoteDeployment.contracts.witnessRegistry,
    true
  );
  const receipt = await tx.wait();

  console.log(
    `Wired ${source} -> ${remote} (chainId ${remoteChainId}) in tx ${receipt.hash}`
  );
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
