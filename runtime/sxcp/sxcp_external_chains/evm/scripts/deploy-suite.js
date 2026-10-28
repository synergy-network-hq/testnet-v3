import { network } from "hardhat";
import { parseArgs, saveDeployment } from "./lib/common.js";

const { ethers, networkName } = await network.create(parseArgs(process.argv.slice(2)).network);

function parseAddressList(value) {
  if (!value) return [];
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

async function deployContract(name, args) {
  const factory = await ethers.getContractFactory(name);
  const contract = await factory.deploy(...args);
  await contract.waitForDeployment();
  return contract;
}

async function main() {
  const networkName = networkName;
  const [deployer] = await ethers.getSigners();
  const network = await ethers.provider.getNetwork();
  const chainId = Number(network.chainId);

  const relayerAddresses = parseAddressList(process.env.INITIAL_RELAYER_ADDRESSES);
  if (relayerAddresses.length === 0) {
    relayerAddresses.push(deployer.address);
  }

  const configuredThreshold = Number(process.env.INITIAL_THRESHOLD || 2);
  const threshold = Math.max(1, Math.min(configuredThreshold, relayerAddresses.length));

  const sepoliaFinality = Number(process.env.SEPOLIA_FINALITY_CONFIRMATIONS || 12);
  const amoyFinality = Number(process.env.AMOY_FINALITY_CONFIRMATIONS || 64);

  const governance = await deployContract("GovernanceModule", [deployer.address]);
  const witnessRegistry = await deployContract("WitnessRegistry", [
    deployer.address,
    threshold,
    relayerAddresses,
  ]);
  const signatureVerifier = await deployContract("SignatureVerifier", [await witnessRegistry.getAddress()]);
  const finalityChecker = await deployContract("FinalityChecker", [
    deployer.address,
    [11155111, 80002],
    [sepoliaFinality, amoyFinality],
  ]);
  const stateProofValidator = await deployContract("StateProofValidator", [deployer.address, false]);
  const auditLogger = await deployContract("AuditLogger", []);
  const sxcpIntentHub = await deployContract("SXCPIntentHub", [
    deployer.address,
    await signatureVerifier.getAddress(),
    await finalityChecker.getAddress(),
    await stateProofValidator.getAddress(),
    await auditLogger.getAddress(),
  ]);
  console.log("  [8/8] SXCPVault (PQC attestation-gated)...");
  const sxcpVault = await deployContract("SXCPVault", [
    await signatureVerifier.getAddress(),
    await witnessRegistry.getAddress(),
  ]);

  const deployment = {
    generatedAt: new Date().toISOString(),
    network: networkName,
    chainId,
    deployer: deployer.address,
    pqcEnabled: true,
    pqcAlgorithms: ["ML-DSA-65", "FN-DSA-1024", "SLH-DSA"],
    config: {
      initialThreshold: threshold,
      initialRelayers: relayerAddresses,
      finalityConfirmations: {
        sepolia: sepoliaFinality,
        amoy: amoyFinality,
      },
    },
    contracts: {
      governanceModule: await governance.getAddress(),
      witnessRegistry: await witnessRegistry.getAddress(),
      signatureVerifier: await signatureVerifier.getAddress(),
      finalityChecker: await finalityChecker.getAddress(),
      stateProofValidator: await stateProofValidator.getAddress(),
      auditLogger: await auditLogger.getAddress(),
      sxcpIntentHub: await sxcpIntentHub.getAddress(),
      sxcpVault: await sxcpVault.getAddress(),
    },
  };

  saveDeployment(networkName, deployment);

  console.log(`Deployed SXCP suite with PQC attestation on ${networkName} (${chainId}).`);
  console.log(JSON.stringify(deployment, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
