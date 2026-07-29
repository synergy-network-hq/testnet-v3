#!/usr/bin/env node
import { spawn } from "node:child_process";
import {
  copyFile,
  mkdir,
  readFile,
  readdir,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { createHash } from "node:crypto";
import { join, resolve } from "node:path";

const APP_ROOT = resolve(import.meta.dirname, "../..");
const STAGING = join(APP_ROOT, "build", "validator-package");
const ELECTRON_DIST = join(APP_ROOT, "electron-dist");
const APP_VERSION = JSON.parse(await readFile(join(APP_ROOT, "package.json"), "utf8")).version;

function option(name, fallback = null) {
  const index = process.argv.indexOf(name);
  return index === -1 ? fallback : process.argv[index + 1] || fallback;
}

function usage() {
  return "Usage: node scripts/release/build-validator-installers.mjs --identity-root <directory> --vpn-onboarding-token-directory <protected directory> --platform <mac|linux> [--output <directory>] [--from 1] [--to 21] [--skip-build-electron]";
}

function run(command, args, env = process.env) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, {
      cwd: APP_ROOT,
      env,
      stdio: "inherit",
    });
    child.once("error", reject);
    child.once("close", (code) => {
      if (code === 0) resolvePromise();
      else reject(new Error(`${command} exited with status ${code}.`));
    });
  });
}

function requiredEnvironment(name) {
  const value = String(process.env[name] || "").trim();
  if (!value) throw new Error(`${name} is required for signed and notarized macOS validator installers.`);
  return value;
}

async function notarizeMacDmg(filePath) {
  await run("xcrun", [
    "notarytool",
    "submit",
    filePath,
    "--apple-id",
    requiredEnvironment("APPLE_ID"),
    "--password",
    requiredEnvironment("APPLE_APP_SPECIFIC_PASSWORD"),
    "--team-id",
    requiredEnvironment("APPLE_TEAM_ID"),
    "--wait",
  ]);
  await run("xcrun", ["stapler", "staple", filePath]);
}

async function sha256(filePath) {
  return createHash("sha256").update(await readFile(filePath)).digest("hex");
}

async function newestMatchingFile(extension) {
  const entries = await readdir(ELECTRON_DIST);
  const candidates = [];
  for (const entry of entries) {
    if (!entry.endsWith(extension)) continue;
    const filePath = join(ELECTRON_DIST, entry);
    candidates.push({ filePath, modified: (await stat(filePath)).mtimeMs });
  }
  candidates.sort((left, right) => right.modified - left.modified);
  if (!candidates.length) throw new Error(`electron-builder did not produce a ${extension} installer.`);
  return candidates[0].filePath;
}

const identityRoot = option("--identity-root");
const vpnOnboardingTokenDirectory = option("--vpn-onboarding-token-directory");
const platform = option("--platform");
const from = Number(option("--from", "1"));
const to = Number(option("--to", "21"));
const output = resolve(option("--output", join(APP_ROOT, "validator-installers", platform || "unknown")));
const skipBuildElectron = process.argv.includes("--skip-build-electron");
if (
  !identityRoot
  || !vpnOnboardingTokenDirectory
  || !["mac", "linux"].includes(platform)
  || !Number.isInteger(from)
  || !Number.isInteger(to)
  || from < 1
  || to > 21
  || from > to
) {
  console.error(usage());
  process.exitCode = 2;
} else {
  if (platform === "mac" && process.platform !== "darwin") {
    throw new Error("macOS DMG installers must be built and signed on macOS.");
  }
  if (platform === "linux" && process.platform !== "linux") {
    throw new Error("Linux DEB installers must be built on Linux.");
  }
  if (platform === "mac") {
    for (const name of ["APPLE_ID", "APPLE_APP_SPECIFIC_PASSWORD", "APPLE_TEAM_ID"]) {
      requiredEnvironment(name);
    }
  }
  await mkdir(output, { recursive: true });
  if (!skipBuildElectron) await run("npm", ["run", "build:electron"]);

  const manifest = [];
  try {
    for (let validator = from; validator <= to; validator += 1) {
      const id = String(validator).padStart(2, "0");
      const onboardingTokenFile = join(
        resolve(vpnOnboardingTokenDirectory),
        `validator-${id}.token`,
      );
      await run(process.execPath, [
        "scripts/release/stage-validator-package.mjs",
        "--identity-root",
        resolve(identityRoot),
        "--validator",
        String(validator),
        "--vpn-onboarding-token-file",
        onboardingTokenFile,
        "--staging",
        STAGING,
      ]);
      await rm(ELECTRON_DIST, { recursive: true, force: true });
      const targetArguments = platform === "mac"
        ? ["electron-builder", "--config", "electron-builder.yml", "--mac", "dmg", "--arm64"]
        : ["electron-builder", "--config", "electron-builder.yml", "--linux", "deb", "--x64"];
      await run("npx", targetArguments, {
        ...process.env,
        SYNERGY_VALIDATOR_ASSIGNMENT: `validator-${String(validator).padStart(2, "0")}`,
      });
      const extension = platform === "mac" ? ".dmg" : ".deb";
      const built = await newestMatchingFile(extension);
      const fileName = platform === "mac"
        ? `Synergy.Node.Control.Panel-${APP_VERSION}-Validator-${id}-arm64.dmg`
        : `synergy-node-control-panel_${APP_VERSION}_validator-${id}_amd64.deb`;
      const destination = join(output, fileName);
      await copyFile(built, destination);
      if (platform === "mac") await notarizeMacDmg(destination);
      await run(process.execPath, [
        "scripts/release/verify-validator-installer.mjs",
        "--installer",
        destination,
        "--platform",
        platform,
        "--validator",
        String(validator),
        "--vpn-onboarding-token-file",
        onboardingTokenFile,
      ]);
      manifest.push({
        validator,
        assignmentId: `validator-${id}`,
        file: fileName,
        sha256: await sha256(destination),
      });
    }
  } finally {
    await rm(STAGING, { recursive: true, force: true });
    await mkdir(STAGING, { recursive: true });
    await writeFile(join(STAGING, ".gitkeep"), "");
  }
  await writeFile(
    join(output, "SHA256SUMS"),
    `${manifest.map((entry) => `${entry.sha256}  ${entry.file}`).join("\n")}\n`,
  );
  await writeFile(join(output, "manifest.json"), `${JSON.stringify({ version: APP_VERSION, platform, installers: manifest }, null, 2)}\n`);
  console.log(`Built ${manifest.length} unique ${platform} validator installers in ${output}`);
}
