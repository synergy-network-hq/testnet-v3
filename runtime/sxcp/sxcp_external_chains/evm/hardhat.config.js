import "dotenv/config";
import hardhatEthers from "@nomicfoundation/hardhat-ethers";
import hardhatMocha from "@nomicfoundation/hardhat-mocha";

const { AMOY_RPC_URL, DEPLOYER_PRIVATE_KEY, SEPOLIA_RPC_URL } = process.env;

const networks = {
  hardhat: { type: "edr-simulated", chainType: "l1" },
};

if (SEPOLIA_RPC_URL && DEPLOYER_PRIVATE_KEY) {
  networks.sepolia = {
    type: "http",
    chainType: "l1",
    url: SEPOLIA_RPC_URL,
    chainId: 11155111,
    accounts: [DEPLOYER_PRIVATE_KEY],
  };
}

if (AMOY_RPC_URL && DEPLOYER_PRIVATE_KEY) {
  networks.amoy = {
    type: "http",
    chainType: "l1",
    url: AMOY_RPC_URL,
    chainId: 80002,
    accounts: [DEPLOYER_PRIVATE_KEY],
  };
}

export default {
  plugins: [hardhatEthers, hardhatMocha],
  solidity: {
    version: "0.8.28",
    settings: {
      evmVersion: "cancun",
      viaIR: true,
      optimizer: {
        enabled: true,
        runs: 200,
      },
    },
  },
  paths: {
    sources: "./contracts",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts",
  },
  networks,
};
