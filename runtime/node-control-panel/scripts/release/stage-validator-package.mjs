#!/usr/bin/env node
import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import {
  chmod,
  copyFile,
  mkdir,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { basename, join, resolve } from "node:path";

const APP_ROOT = resolve(import.meta.dirname, "../..");
const DEFAULT_STAGING = join(APP_ROOT, "build", "validator-package");
const INITIAL_VALIDATORS = new Set([1, 2, 3, 4, 5, 6]);

function option(name, fallback = null) {
  const index = process.argv.indexOf(name);
  return index === -1 ? fallback : process.argv[index + 1] || fallback;
}

function usage() {
  return "Usage: node scripts/release/stage-validator-package.mjs --identity-root <testnet-v3-identity-files> --validator <1-21> [--staging <directory>]";
}

async function sha256(filePath) {
  return createHash("sha256").update(await readFile(filePath)).digest("hex");
}

async function json(filePath) {
  return JSON.parse(await readFile(filePath, "utf8"));
}

async function findValidatorSource(identityRoot, validator) {
  const directories = await readdir(identityRoot, { withFileTypes: true });
  const candidates = [];
  for (const directory of directories) {
    if (!directory.isDirectory()) continue;
    const source = join(identityRoot, directory.name);
    try {
      const binding = await json(join(source, "wireguard", "vpn-binding.json"));
      if (
        binding.role === "validator"
        && Number(binding.index) === validator
        && Number(binding.chain_id) === 1266
        && binding.network_id === "synergy-testnet-v3"
      ) {
        candidates.push({ source, binding });
      }
    } catch {
      // Non-validator identity directories are intentionally skipped.
    }
  }
  if (candidates.length !== 1) {
    throw new Error(`Expected exactly one Testnet-v3 identity directory for Validator ${validator}; found ${candidates.length}.`);
  }
  return candidates[0];
}

const identityRootOption = option("--identity-root");
const validator = Number(option("--validator"));
const staging = resolve(option("--staging", DEFAULT_STAGING));
if (!identityRootOption || !Number.isInteger(validator) || validator < 1 || validator > 21) {
  console.error(usage());
  process.exitCode = 2;
} else {
  const identityRoot = resolve(identityRootOption);
  const { source, binding } = await findValidatorSource(identityRoot, validator);
  const [identityPublic, identityManifest] = await Promise.all([
    json(join(source, "identity.pub.json")),
    json(join(source, "manifest.json")),
  ]);
  if (
    identityPublic.address !== binding.node_identity?.synv_address
    || identityManifest.address !== identityPublic.address
    || identityManifest.identity_kind !== "validator-node"
    || identityManifest.key_bundle !== "full-node-key-set"
  ) {
    throw new Error(`Validator ${validator} identity, manifest, and VPN binding do not match.`);
  }
  const expectedActivationStatus = INITIAL_VALIDATORS.has(validator)
    ? "active"
    : "provisioned-inactive";
  if (binding.activation_status !== expectedActivationStatus) {
    throw new Error(`Validator ${validator} has activation status ${binding.activation_status}; expected ${expectedActivationStatus}.`);
  }
  const [wireguardConfigTemplate, wireguardPrivateKey, wireguardPublicKey] = await Promise.all([
    readFile(join(source, "wireguard", "sy-vpn.conf"), "utf8"),
    readFile(join(source, "wireguard", "wireguard-private.key"), "utf8"),
    readFile(join(source, "wireguard", "wireguard-public.key"), "utf8"),
  ]);
  const configAddress = wireguardConfigTemplate.match(/^Address\s*=\s*([^\s,]+)/m)?.[1]?.split("/")[0];
  const peerCount = (wireguardConfigTemplate.match(/^\[Peer\]$/gm) || []).length;
  const privateKeyBytes = Buffer.from(wireguardPrivateKey.trim(), "base64");
  const privateKeyDer = Buffer.concat([
    Buffer.from("302e020100300506032b656e04220420", "hex"),
    privateKeyBytes,
  ]);
  const derivedPublicKey = createPublicKey(
    createPrivateKey({ key: privateKeyDer, format: "der", type: "pkcs8" }),
  ).export({ format: "der", type: "spki" }).subarray(-32).toString("base64");
  if (
    configAddress !== binding.route?.vpn_ip
    || peerCount !== 24
    || privateKeyBytes.length !== 32
    || derivedPublicKey !== wireguardPublicKey.trim()
    || derivedPublicKey !== binding.wireguard_identity?.public_key
  ) {
    throw new Error(`Validator ${validator} does not contain its exact complete 24-peer Testnet-v3 VPN topology.`);
  }
  const wireguardConfig = wireguardConfigTemplate.replace(
    /^PrivateKey\s*=.*$/m,
    `PrivateKey = ${wireguardPrivateKey.trim()}`,
  );

  const files = new Map([
    ["identity.enc.json", join(source, "identity.enc.json")],
    ["identity.pub.json", join(source, "identity.pub.json")],
    ["manifest.json", join(source, "manifest.json")],
    ["wireguard-private.key", join(source, "wireguard", "wireguard-private.key")],
    ["wireguard-public.key", join(source, "wireguard", "wireguard-public.key")],
    ["sy-vpn.conf", join(source, "wireguard", "sy-vpn.conf")],
    ["vpn-binding.json", join(source, "wireguard", "vpn-binding.json")],
  ]);

  await rm(staging, { recursive: true, force: true });
  await mkdir(staging, { recursive: true, mode: 0o700 });
  const checksums = {};
  for (const [fileName, sourcePath] of files) {
    const targetPath = join(staging, fileName);
    if (fileName === "sy-vpn.conf") {
      await writeFile(targetPath, wireguardConfig, { mode: 0o600 });
    } else {
      await copyFile(sourcePath, targetPath);
    }
    await chmod(
      targetPath,
      ["wireguard-private.key", "identity.enc.json", "sy-vpn.conf"].includes(fileName)
        ? 0o600
        : 0o644,
    );
    checksums[fileName] = await sha256(targetPath);
  }

  const assignmentId = `validator-${String(validator).padStart(2, "0")}`;
  const assignment = {
    schemaVersion: 1,
    assignmentId,
    validator,
    validatorLabel: binding.workbook_node || basename(source),
    validatorAddress: identityPublic.address,
    chainId: 1266,
    networkId: "synergy-testnet-v3",
    cohort: INITIAL_VALIDATORS.has(validator) ? "initial-six" : "gradual-activation",
    activationStatus: binding.activation_status,
    vpnConfigVersion: binding.config_version,
    checksums,
    security: {
      encryptedIdentity: true,
      containsIdentityPassphrase: false,
      containsWireguardPrivateKey: true,
      installerBoundToSingleValidator: true,
    },
  };
  await writeFile(join(staging, "assignment.json"), `${JSON.stringify(assignment, null, 2)}\n`, { mode: 0o644 });
  console.log(`Staged ${assignmentId} at ${staging}`);
}
