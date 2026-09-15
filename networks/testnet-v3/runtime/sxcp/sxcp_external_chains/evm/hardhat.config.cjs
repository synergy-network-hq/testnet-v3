require("dotenv").config();
require("@nomicfoundation/hardhat-ethers");

const { AMOY_RPC_URL, DEPLOYER_PRIVATE_KEY, SEPOLIA_RPC_URL } = process.env;

const networks = {
  hardhat: {},
};

if (SEPOLIA_RPC_URL && DEPLOYER_PRIVATE_KEY) {
  networks.sepolia = {
    url: SEPOLIA_RPC_URL,
    chainId: 11155111,
    accounts: [DEPLOYER_PRIVATE_KEY],
  };
}

if (AMOY_RPC_URL && DEPLOYER_PRIVATE_KEY) {
  networks.amoy = {
    url: AMOY_RPC_URL,
    chainId: 80002,
    accounts: [DEPLOYER_PRIVATE_KEY],
  };
}

module.exports = {
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
