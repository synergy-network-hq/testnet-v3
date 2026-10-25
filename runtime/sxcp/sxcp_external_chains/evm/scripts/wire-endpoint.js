import { network } from "hardhat";
import { chainIdForNetwork, loadDeployment, parseArgs } from "./lib/common.js";

const { ethers, networkName } = await network.create(parseArgs(process.argv.slice(2)).network);

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const source = args.source || networkName;
  const remote = args.remote;

  if (!remote) {
    throw new Error("Missing --remote <network>");
  }

  if (source !== networkName) {
    throw new Error(`Run this script on --network ${source}. Current network: ${networkName}`);
  }

  const sourceDeployment = loadDeployment(source);
  const remoteDeployment = loadDeployment(remote);
  const remoteChainId = Number(remoteDeployment.chainId || chainIdForNetwork(remote));

  const intentHub = await ethers.getContractAt(
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
