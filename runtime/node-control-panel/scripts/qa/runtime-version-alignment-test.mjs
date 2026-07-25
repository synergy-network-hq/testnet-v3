import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function readJson(relativePath) {
  const absolutePath = path.resolve(repoRoot, relativePath);
  return JSON.parse(fs.readFileSync(absolutePath, 'utf8'));
}

function requireEqual(label, actual, expected) {
  if (actual !== expected) {
    throw new Error(`${label} (${actual ?? 'missing'}) does not match ${expected}`);
  }
}

function sha256(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

const packageJson = readJson('package.json');
const packageLock = readJson('package-lock.json');
const expectedVersion = packageJson.version;
if (!/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(expectedVersion ?? '')) {
  throw new Error(`package.json contains an invalid version: ${expectedVersion ?? 'missing'}`);
}

requireEqual('package-lock.json version', packageLock.version, expectedVersion);
requireEqual('package-lock.json root package version', packageLock.packages?.['']?.version, expectedVersion);

const cargoToml = fs.readFileSync(path.join(repoRoot, 'control-service/Cargo.toml'), 'utf8');
const cargoVersion = cargoToml.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
requireEqual('control-service version', cargoVersion, expectedVersion);

const platform = {
  darwin: {
    binary: 'binaries/synergy-testnet-darwin-arm64',
    manifestPlatform: 'macos-arm64',
  },
  linux: {
    binary: 'binaries/synergy-testnet-linux-amd64',
    manifestPlatform: 'linux-amd64',
  },
  win32: {
    binary: 'binaries/synergy-testnet-windows-amd64.exe',
    manifestPlatform: 'windows-amd64',
  },
}[process.platform];

if (!platform) {
  throw new Error(`Unsupported runtime version-check platform: ${process.platform}`);
}

const runtimeBinary = path.resolve(
  repoRoot,
  process.env.SYNERGY_RUNTIME_BINARY_PATH || platform.binary,
);
if (!fs.existsSync(runtimeBinary)) {
  throw new Error(`Bundled runtime binary is missing: ${runtimeBinary}`);
}

const versionResult = spawnSync(runtimeBinary, ['--version'], {
  encoding: 'utf8',
  timeout: 15_000,
});
if (versionResult.error) {
  throw new Error(`Could not execute bundled runtime: ${versionResult.error.message}`);
}
if (versionResult.status !== 0) {
  throw new Error(
    `Bundled runtime --version failed with exit code ${versionResult.status}: ${(versionResult.stderr || versionResult.stdout).trim()}`,
  );
}

const reportedVersion = `${versionResult.stdout}\n${versionResult.stderr}`
  .split(/\r?\n/)
  .map((line) => line.trim())
  .find(Boolean);
const expectedOutput = `Synergy Testnet Node v${expectedVersion}`;
requireEqual('bundled runtime version', reportedVersion, expectedOutput);

const manifestSetting = process.env.SYNERGY_RUNTIME_RELEASE_MANIFEST_PATH;
const defaultManifest = path.join(repoRoot, 'testnet-latest.json');
const manifestPath = manifestSetting
  ? path.resolve(repoRoot, manifestSetting)
  : defaultManifest;

if (manifestSetting || fs.existsSync(manifestPath)) {
  if (!fs.existsSync(manifestPath)) {
    throw new Error(`Runtime release manifest is missing: ${manifestPath}`);
  }
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  requireEqual('runtime release manifest version', manifest.version, `v${expectedVersion}`);

  const expectedHash = manifest.binaries?.[platform.manifestPlatform]?.['synergy-testnet']?.sha256;
  if (!/^[0-9a-f]{64}$/i.test(expectedHash ?? '')) {
    throw new Error(
      `Runtime release manifest is missing ${platform.manifestPlatform}/synergy-testnet/sha256`,
    );
  }
  requireEqual('bundled runtime checksum', sha256(runtimeBinary), expectedHash.toLowerCase());
}

if (process.env.SYNERGY_SKIP_WORKSPACE_MANIFEST_CHECK !== '1') {
  const workspaceManifestPath = path.resolve(
    repoRoot,
    process.env.SYNERGY_WORKSPACE_MANIFEST_PATH || 'testnet/runtime/workspace-manifest.json',
  );
  if (!fs.existsSync(workspaceManifestPath)) {
    throw new Error(`Workspace manifest is missing: ${workspaceManifestPath}`);
  }
  const workspaceManifest = JSON.parse(fs.readFileSync(workspaceManifestPath, 'utf8'));
  requireEqual('workspace manifest app_version', workspaceManifest.app_version, expectedVersion);
  if (!`${workspaceManifest.workspace_resource_version ?? ''}`.startsWith(`${expectedVersion}+`)) {
    throw new Error(
      `workspace_resource_version (${workspaceManifest.workspace_resource_version ?? 'missing'}) must start with ${expectedVersion}+`,
    );
  }
  const workspaceHash = workspaceManifest.checksums?.[platform.binary];
  if (!/^[0-9a-f]{64}$/i.test(workspaceHash ?? '')) {
    throw new Error(`Workspace manifest is missing the checksum for ${platform.binary}`);
  }
  requireEqual('workspace manifest runtime checksum', sha256(runtimeBinary), workspaceHash.toLowerCase());
}

console.log(
  `Version alignment verified: Control Panel ${expectedVersion}, control service ${cargoVersion}, runtime ${reportedVersion}`,
);
