#!/usr/bin/env node
/**
 * Create the key-free Validator 1–21 distribution matrix from the verified,
 * signed generic Electron installers. This deliberately does not generate,
 * copy, or inspect validator private identities: those are released only by
 * the coordinator after one-time enrollment.
 */
import { createHash } from "node:crypto";
import { copyFile, mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { basename, join, resolve } from "node:path";

const ROOT = resolve(import.meta.dirname, "../..");
const DEFAULT_OUTPUT = join(ROOT, "validator-distribution");
const VALIDATOR_IDS = Array.from({ length: 21 }, (_, index) => index + 1);
const INITIAL_VALIDATORS = new Set([1, 2, 3, 4, 5, 6]);

function readOption(name) {
  const position = process.argv.indexOf(name);
  return position === -1 ? null : process.argv[position + 1] || null;
}

function usage() {
  return [
    "Usage: npm run release:validator-distribution -- --macos <signed.dmg> --linux <signed.deb> --assignments <validator-identities.json> [--output <directory>]",
    "",
    "The input artifacts must be the signed, release-verified generic Node Control Panel installers.",
    "This command creates Validator-01 through Validator-21 folders and SHA-256 checksums.",
  ].join("\n");
}

async function sha256(path) {
  const bytes = await readFile(path);
  return createHash("sha256").update(bytes).digest("hex");
}

async function requiredFile(path, label) {
  try {
    const details = await stat(path);
    if (!details.isFile() || details.size === 0) throw new Error("not a non-empty file");
  } catch (error) {
    throw new Error(`${label} is required and must be a non-empty file: ${path} (${error.message})`);
  }
}

async function loadAssignments(path) {
  const parsed = JSON.parse(await readFile(path, "utf8"));
  if (!Array.isArray(parsed) || parsed.length !== 21) throw new Error("Assignment map must contain exactly Validator 1–21.");
  const byValidator = new Map();
  for (const entry of parsed) {
    const validator = Number(entry?.validator);
    const identity = String(entry?.identity || "").trim();
    const publicKey = String(entry?.publicKey || entry?.public_key || "").trim();
    if (!Number.isInteger(validator) || validator < 1 || validator > 21 || !/^synv[0-9a-z]+$/i.test(identity) || !/^[A-Za-z0-9+/]+={0,2}$/.test(publicKey) || byValidator.has(validator)) {
      throw new Error("Every assignment must contain one unique Validator 1–21, a valid synv identity, and its nonsecret public key.");
    }
    byValidator.set(validator, { identity, publicKey });
  }
  if (new Set([...byValidator.values()].map((entry) => entry.identity)).size !== 21) throw new Error("Each validator must be assigned a unique synv identity.");
  if (new Set([...byValidator.values()].map((entry) => entry.publicKey)).size !== 21) throw new Error("Each validator must be assigned a unique public key.");
  return byValidator;
}

function assignmentManifest(validatorId, assignment) {
  const sequence = String(validatorId).padStart(2, "0");
  return {
    assignmentId: `validator-${sequence}`,
    assignedSynergyIdentity: assignment.identity,
    assignedValidatorPublicKey: assignment.publicKey,
    releaseCohort: INITIAL_VALIDATORS.has(validatorId) ? "internal-launch" : "operator-distribution",
    enrollment: {
      mode: "request-token-during-installation",
      note: "The VPN coordinator validates the single-use token, WireGuard key proof, and detached proof from the assigned Synergy identity before it releases encrypted validator-specific configuration.",
    },
    security: {
      containsReusablePrivateIdentityKey: false,
      containsCustodyPassphrase: false,
      containsUnencryptedConsensusPrivateKey: false,
      consensusActivation: "separate",
    },
  };
}

const macos = readOption("--macos");
const linux = readOption("--linux");
const assignmentsFile = readOption("--assignments");
const output = resolve(readOption("--output") || DEFAULT_OUTPUT);
if (!macos || !linux || !assignmentsFile) {
  console.error(usage());
  process.exitCode = 2;
} else {
  const macosPath = resolve(macos);
  const linuxPath = resolve(linux);
  const assignments = await loadAssignments(resolve(assignmentsFile));
  await requiredFile(macosPath, "macOS installer");
  await requiredFile(linuxPath, "Linux installer");
  if (!macosPath.endsWith(".dmg") || !linuxPath.endsWith(".deb")) throw new Error("Expected a macOS .dmg and a Linux .deb installer.");

  const macosName = basename(macosPath);
  const linuxName = basename(linuxPath);
  const macosChecksum = await sha256(macosPath);
  const linuxChecksum = await sha256(linuxPath);
  const matrixChecksums = [];
  for (const validatorId of VALIDATOR_IDS) {
    const id = String(validatorId).padStart(2, "0");
    const directory = join(output, `Validator-${id}`);
    await mkdir(directory, { recursive: true });
    await Promise.all([
      copyFile(macosPath, join(directory, macosName)),
      copyFile(linuxPath, join(directory, linuxName)),
      writeFile(join(directory, "assignment.json"), `${JSON.stringify(assignmentManifest(validatorId, assignments.get(validatorId)), null, 2)}\n`, "utf8"),
      writeFile(join(directory, "INSTALLATION.txt"), [
        "Synergy Node Control Panel standard installer package", "", "1. Install the appropriate signed package.",
        "2. Open Node Control Panel and begin secure validator enrollment.",
        "3. Enter the single-use VPN coordinator token supplied to you.",
        "4. Receive the encrypted assigned bundle through the approved custody channel and use its local key to create the displayed detached enrollment proof.",
        "5. The coordinator verifies the assigned identity proof, WireGuard key proof, and endpoint before it completes enrollment.",
        "6. Confirm VPN connectivity. Consensus activation remains a separate approval step.", "",
        "This package contains no reusable validator private identity key, custody passphrase, or unencrypted consensus private key.",
      ].join("\n") + "\n", "utf8"),
    ]);
    const checksums = [
      `${macosChecksum}  ${macosName}`, `${linuxChecksum}  ${linuxName}`,
      `${await sha256(join(directory, "assignment.json"))}  assignment.json`,
      `${await sha256(join(directory, "INSTALLATION.txt"))}  INSTALLATION.txt`,
    ];
    await writeFile(join(directory, "SHA256SUMS"), `${checksums.join("\n")}\n`, "utf8");
    matrixChecksums.push(...checksums.map((line) => line.replace(/  /, `  Validator-${id}/`)));
  }
  await writeFile(join(output, "SHA256SUMS"), `${matrixChecksums.join("\n")}\n`, "utf8");
  await writeFile(join(output, "README.txt"), [
    "Validator 1–21 distribution matrix", "",
    "Validators 1–6 are internal-launch assignments. Validators 7–21 are operator-distribution assignments.",
    "All installers are generic signed Node Control Panel artifacts. Per-validator encrypted configuration is retrieved from the VPN coordinator after successful one-time enrollment; no private identity material is in this distribution.",
  ].join("\n") + "\n", "utf8");
  console.log(`Created key-free validator distribution matrix at ${output}`);
}
