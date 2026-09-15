const fs = require("fs");
const path = require("path");

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (!token.startsWith("--")) continue;
    const key = token.slice(2);
    const next = argv[i + 1];
    if (!next || next.startsWith("--")) {
      args[key] = true;
    } else {
      args[key] = next;
      i += 1;
    }
  }
  return args;
}

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function chainIdForNetwork(networkName) {
  if (networkName === "sepolia") return 11155111;
  if (networkName === "amoy") return 80002;
  throw new Error(`Unsupported network: ${networkName}`);
}

function rpcUrlForNetwork(networkName) {
  if (networkName === "sepolia") return process.env.SEPOLIA_RPC_URL;
  if (networkName === "amoy") return process.env.AMOY_RPC_URL;
  throw new Error(`Unsupported network: ${networkName}`);
}

function deploymentPath(networkName) {
  return path.join(__dirname, "..", "..", "deployments", `${networkName}.json`);
}

function loadDeployment(networkName) {
  const filePath = deploymentPath(networkName);
  if (!fs.existsSync(filePath)) {
    throw new Error(`Deployment file not found: ${filePath}`);
  }
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function saveDeployment(networkName, payload) {
  const dir = path.join(__dirname, "..", "..", "deployments");
  ensureDir(dir);
  fs.writeFileSync(deploymentPath(networkName), JSON.stringify(payload, null, 2));
}

function runtimePath(fileName) {
  return path.join(__dirname, "..", "..", "runtime", fileName);
}

function saveRuntime(fileName, payload) {
  const dir = path.join(__dirname, "..", "..", "runtime");
  ensureDir(dir);
  fs.writeFileSync(runtimePath(fileName), JSON.stringify(payload, null, 2));
}

function loadRuntime(fileName) {
  const filePath = runtimePath(fileName);
  if (!fs.existsSync(filePath)) {
    throw new Error(`Runtime file not found: ${filePath}`);
  }
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

module.exports = {
  chainIdForNetwork,
  ensureDir,
  loadDeployment,
  loadRuntime,
  parseArgs,
  rpcUrlForNetwork,
  saveDeployment,
  saveRuntime,
};
