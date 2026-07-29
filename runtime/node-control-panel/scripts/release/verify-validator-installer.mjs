#!/usr/bin/env node
import { createPrivateKey, createPublicKey } from "node:crypto";
import { spawn } from "node:child_process";
import {
  mkdtemp,
  readFile,
  readdir,
  rm,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const { loadValidatorPackage } = require("../../electron/onboarding/validator-package.cjs");
const PACKAGE_FILES = new Set([
  "assignment.json",
  "identity.enc.json",
  "identity.pub.json",
  "manifest.json",
  "wireguard-public.key",
  "wireguard-config.envelope.json",
  "vpn-binding.json",
]);

function option(name, fallback = null) {
  const index = process.argv.indexOf(name);
  return index === -1 ? fallback : process.argv[index + 1] || fallback;
}

function usage() {
  return "Usage: node scripts/release/verify-validator-installer.mjs --installer <file> --platform <mac|linux> --validator <1-21> --vpn-onboarding-token-file <protected file>";
}

function run(command, args) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, { stdio: "inherit" });
    child.once("error", reject);
    child.once("close", (code) => {
      if (code === 0) resolvePromise();
      else reject(new Error(`${command} exited with status ${code}.`));
    });
  });
}

async function findNamedDirectories(root, name, matches = []) {
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const entryPath = join(root, entry.name);
    if (!entry.isDirectory()) continue;
    if (!name || entry.name === name) matches.push(entryPath);
    await findNamedDirectories(entryPath, name, matches);
  }
  return matches;
}

async function findMacApp(root) {
  const apps = (await readdir(root, { withFileTypes: true }))
    .filter((entry) => entry.isDirectory() && entry.name.endsWith(".app"))
    .map((entry) => join(root, entry.name));
  if (apps.length !== 1) {
    throw new Error(`Expected exactly one app bundle in ${root}; found ${apps.length}.`);
  }
  return apps[0];
}

async function readOnboardingToken(filePath) {
  let token;
  try {
    token = (await readFile(filePath, "utf8")).trim();
  } catch {
    throw new Error("The protected validator VPN onboarding-token file could not be read.");
  }
  if (!/^[A-Za-z0-9_-]{32,}$/.test(token)) {
    throw new Error("The protected validator VPN onboarding-token file does not contain a valid one-time token.");
  }
  return token;
}

function wireguardPublicKey(privateKey) {
  const privateKeyBytes = Buffer.from(String(privateKey).trim(), "base64");
  if (privateKeyBytes.length !== 32) return null;
  const privateKeyDer = Buffer.concat([
    Buffer.from("302e020100300506032b656e04220420", "hex"),
    privateKeyBytes,
  ]);
  return createPublicKey(
    createPrivateKey({ key: privateKeyDer, format: "der", type: "pkcs8" }),
  ).export({ format: "der", type: "spki" }).subarray(-32).toString("base64");
}

export async function verifyPackageRoot(packageRoot, validator, onboardingToken) {
  const entries = (await readdir(packageRoot))
    .filter((entry) => entry !== ".DS_Store");
  const unexpected = entries.filter((entry) => !PACKAGE_FILES.has(entry));
  const missing = [...PACKAGE_FILES].filter((entry) => !entries.includes(entry));
  if (unexpected.length || missing.length || entries.length !== PACKAGE_FILES.size) {
    throw new Error(
      `Validator package file set is invalid. missing=${missing.join(",") || "none"} unexpected=${unexpected.join(",") || "none"}`,
    );
  }

  const previousRoot = process.env.SYNERGY_VALIDATOR_PACKAGE_DIR;
  process.env.SYNERGY_VALIDATOR_PACKAGE_DIR = packageRoot;
  let packageData;
  try {
    packageData = await loadValidatorPackage({ includeSecrets: true, activationToken: onboardingToken });
  } finally {
    if (previousRoot === undefined) delete process.env.SYNERGY_VALIDATOR_PACKAGE_DIR;
    else process.env.SYNERGY_VALIDATOR_PACKAGE_DIR = previousRoot;
  }

  const assignmentId = `validator-${String(validator).padStart(2, "0")}`;
  if (
    !packageData.available
    || Number(packageData.validator) !== validator
    || packageData.assignmentId !== assignmentId
    || Number(packageData.chainId) !== 1266
    || packageData.networkId !== "synergy-testnet-v3"
  ) {
    throw new Error(`Packaged assignment does not match ${assignmentId}.`);
  }

  const assignment = JSON.parse(await readFile(join(packageRoot, "assignment.json"), "utf8"));
  const expectedCohort = validator <= 6 ? "initial-six" : "gradual-activation";
  if (
    assignment.cohort !== expectedCohort
    || assignment?.security?.encryptedIdentity !== true
    || assignment?.security?.containsIdentityPassphrase !== false
    || assignment?.security?.containsWireguardPrivateKey !== false
    || assignment?.security?.encryptedWireguardConfigWithOnboardingToken !== true
    || assignment?.security?.onboardingTokenEmbedded !== false
    || assignment?.security?.installerBoundToSingleValidator !== true
  ) {
    throw new Error(`${assignmentId} has invalid cohort or custody metadata.`);
  }

  const wireguardConfig = packageData.wireguardConfig;
  const configuredPrivateKey = wireguardConfig.match(/^PrivateKey\s*=\s*(\S+)\s*$/m)?.[1];
  if (
    (wireguardConfig.match(/^\[Peer\]$/gm) || []).length !== 24
    || configuredPrivateKey !== packageData.wireguardPrivateKey
    || wireguardPublicKey(packageData.wireguardPrivateKey) !== packageData.wireguardPublicKey
  ) {
    throw new Error(`${assignmentId} does not contain its complete protected WireGuard configuration.`);
  }
}

async function verifyExtractedInstaller(root, validator, onboardingToken) {
  const resolvedRoots = [];
  for (const path of await findNamedDirectories(root, "validator-package")) {
    if ((await readdir(path)).includes("assignment.json")) resolvedRoots.push(path);
  }
  if (resolvedRoots.length !== 1) {
    throw new Error(`Expected exactly one embedded validator package; found ${resolvedRoots.length}.`);
  }
  await verifyPackageRoot(resolvedRoots[0], validator, onboardingToken);
}

async function verifyMac(installer, validator, onboardingToken) {
  const mount = await mkdtemp(join(tmpdir(), "synergy-validator-dmg-"));
  try {
    await run("hdiutil", ["attach", installer, "-nobrowse", "-readonly", "-mountpoint", mount]);
    const app = await findMacApp(mount);
    await run("codesign", ["--verify", "--deep", "--strict", "--verbose=2", app]);
    await run("xcrun", ["stapler", "validate", app]);
    await run("xcrun", ["stapler", "validate", installer]);
    await run("spctl", ["--assess", "--type", "execute", "--verbose=4", app]);
    await verifyExtractedInstaller(app, validator, onboardingToken);
  } finally {
    await run("hdiutil", ["detach", mount, "-quiet"]).catch(() => {});
    await rm(mount, { recursive: true, force: true });
  }
}

async function verifyLinux(installer, validator, onboardingToken) {
  const extract = await mkdtemp(join(tmpdir(), "synergy-validator-deb-"));
  try {
    await run("dpkg-deb", ["--info", installer]);
    await run("dpkg-deb", ["--extract", installer, extract]);
    await verifyExtractedInstaller(extract, validator, onboardingToken);
  } finally {
    await rm(extract, { recursive: true, force: true });
  }
}

async function main() {
  const installer = option("--installer");
  const platform = option("--platform");
  const validator = Number(option("--validator"));
  const onboardingTokenFile = option("--vpn-onboarding-token-file");
  if (
    !installer
    || !onboardingTokenFile
    || !["mac", "linux"].includes(platform)
    || !Number.isInteger(validator)
    || validator < 1
    || validator > 21
  ) {
    console.error(usage());
    process.exitCode = 2;
    return;
  }
  const resolvedInstaller = resolve(installer);
  const onboardingToken = await readOnboardingToken(resolve(onboardingTokenFile));
  if (platform === "mac" && !basename(resolvedInstaller).endsWith(".dmg")) {
    throw new Error("The macOS validator installer must be a DMG.");
  }
  if (platform === "linux" && !basename(resolvedInstaller).endsWith(".deb")) {
    throw new Error("The Linux validator installer must be a DEB.");
  }
  if (platform === "mac") await verifyMac(resolvedInstaller, validator, onboardingToken);
  else await verifyLinux(resolvedInstaller, validator, onboardingToken);
  console.log(`Verified Validator ${String(validator).padStart(2, "0")} ${platform} installer.`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
