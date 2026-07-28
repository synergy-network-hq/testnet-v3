#!/usr/bin/env node
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
  "wireguard-private.key",
  "wireguard-public.key",
  "sy-vpn.conf",
  "vpn-binding.json",
]);

function option(name, fallback = null) {
  const index = process.argv.indexOf(name);
  return index === -1 ? fallback : process.argv[index + 1] || fallback;
}

function usage() {
  return "Usage: node scripts/release/verify-validator-installer.mjs --installer <file> --platform <mac|linux> --validator <1-21>";
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

export async function verifyPackageRoot(packageRoot, validator) {
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
    packageData = await loadValidatorPackage();
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
    || assignment?.security?.containsWireguardPrivateKey !== true
    || assignment?.security?.installerBoundToSingleValidator !== true
  ) {
    throw new Error(`${assignmentId} has invalid cohort or custody metadata.`);
  }

  const wireguardConfig = await readFile(join(packageRoot, "sy-vpn.conf"), "utf8");
  if (
    (wireguardConfig.match(/^\[Peer\]$/gm) || []).length !== 24
    || !/^PrivateKey\s*=\s*[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/m.test(wireguardConfig)
  ) {
    throw new Error(`${assignmentId} does not contain its complete, activated WireGuard configuration.`);
  }
}

async function verifyExtractedInstaller(root, validator) {
  const resolvedRoots = [];
  for (const path of await findNamedDirectories(root, "validator-package")) {
    if ((await readdir(path)).includes("assignment.json")) resolvedRoots.push(path);
  }
  if (resolvedRoots.length !== 1) {
    throw new Error(`Expected exactly one embedded validator package; found ${resolvedRoots.length}.`);
  }
  await verifyPackageRoot(resolvedRoots[0], validator);
}

async function verifyMac(installer, validator) {
  const mount = await mkdtemp(join(tmpdir(), "synergy-validator-dmg-"));
  try {
    await run("hdiutil", ["attach", installer, "-nobrowse", "-readonly", "-mountpoint", mount]);
    const app = await findMacApp(mount);
    await run("codesign", ["--verify", "--deep", "--strict", "--verbose=2", app]);
    await run("xcrun", ["stapler", "validate", app]);
    await run("xcrun", ["stapler", "validate", installer]);
    await run("spctl", ["--assess", "--type", "execute", "--verbose=4", app]);
    await verifyExtractedInstaller(app, validator);
  } finally {
    await run("hdiutil", ["detach", mount, "-quiet"]).catch(() => {});
    await rm(mount, { recursive: true, force: true });
  }
}

async function verifyLinux(installer, validator) {
  const extract = await mkdtemp(join(tmpdir(), "synergy-validator-deb-"));
  try {
    await run("dpkg-deb", ["--info", installer]);
    await run("dpkg-deb", ["--extract", installer, extract]);
    await verifyExtractedInstaller(extract, validator);
  } finally {
    await rm(extract, { recursive: true, force: true });
  }
}

async function main() {
  const installer = option("--installer");
  const platform = option("--platform");
  const validator = Number(option("--validator"));
  if (
    !installer
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
  if (platform === "mac" && !basename(resolvedInstaller).endsWith(".dmg")) {
    throw new Error("The macOS validator installer must be a DMG.");
  }
  if (platform === "linux" && !basename(resolvedInstaller).endsWith(".deb")) {
    throw new Error("The Linux validator installer must be a DEB.");
  }
  if (platform === "mac") await verifyMac(resolvedInstaller, validator);
  else await verifyLinux(resolvedInstaller, validator);
  console.log(`Verified Validator ${String(validator).padStart(2, "0")} ${platform} installer.`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
