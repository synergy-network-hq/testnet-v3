const { loadDeployment, parseArgs, saveRuntime } = require("./lib/common");

function ensureDeployment(name) {
  const deployment = loadDeployment(name);
  if (!deployment.contracts || !deployment.contracts.sxcpIntentHub) {
    throw new Error(`Deployment ${name} is missing required SXCP contracts`);
  }
  return deployment;
}

function buildChainConfig(deployment, rpcEnvKey) {
  return {
    network: deployment.network,
    chainId: Number(deployment.chainId),
    rpcUrlEnv: rpcEnvKey,
    contracts: {
      governanceModule: deployment.contracts.governanceModule,
      witnessRegistry: deployment.contracts.witnessRegistry,
      signatureVerifier: deployment.contracts.signatureVerifier,
      finalityChecker: deployment.contracts.finalityChecker,
      stateProofValidator: deployment.contracts.stateProofValidator,
      auditLogger: deployment.contracts.auditLogger,
      sxcpIntentHub: deployment.contracts.sxcpIntentHub,
    },
    finalityConfirmations: deployment.config?.finalityConfirmations || {},
  };
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const source = args.source || "sepolia";
  const destination = args.destination || "amoy";
  const output = args.output || "testnet-sxcp-relayer-config.json";

  const sourceDeployment = ensureDeployment(source);
  const destinationDeployment = ensureDeployment(destination);

  const config = {
    generatedAt: new Date().toISOString(),
    profile: "sxcp-testnet-phase1",
    flow: {
      source,
      destination,
    },
    chains: {
      [source]: buildChainConfig(sourceDeployment, source === "sepolia" ? "SEPOLIA_RPC_URL" : "AMOY_RPC_URL"),
      [destination]: buildChainConfig(
        destinationDeployment,
        destination === "sepolia" ? "SEPOLIA_RPC_URL" : "AMOY_RPC_URL"
      ),
    },
    relayer: {
      epochId: 1,
      quorumThreshold: sourceDeployment.config?.initialThreshold ?? 2,
      signerKeysEnv: "RELAYER_PRIVATE_KEYS",
      testnetRpcGateway: "https://testnet-core-rpc.synergy-network.io",
      recommendedNodes: ["machine-06", "machine-07", "machine-08", "machine-09"],
    },
    rpcMethodsRequiredOnTestnet: [
      "synergy_registerRelayer",
      "synergy_relayerHeartbeat",
      "synergy_getRelayerSet",
      "synergy_submitAttestation",
      "synergy_getEventAttestation",
      "synergy_getAttestations",
      "synergy_getSxcpStatus",
    ],
  };

  saveRuntime(output, config);
  console.log(`Wrote runtime/${output}`);
  console.log(JSON.stringify(config, null, 2));
}

try {
  main();
} catch (error) {
  console.error(error);
  process.exitCode = 1;
}
