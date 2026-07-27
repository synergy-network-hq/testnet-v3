#!/usr/bin/env node
/**
 * Export the nonsecret Validator 1-21 public assignment map from the
 * authoritative Testnet allocation manifest and public identity registry.
 *
 * This intentionally reads only identity.pub.json files. It rejects any
 * source that cannot be verified by the supplied synergy-control binary, and
 * never reads encrypted custody bundles or private keys.
 */
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";

const VALIDATOR_IDS = Array.from({ length: 21 }, (_, index) => index + 1);

function option(name) {
  const position = process.argv.indexOf(name);
  return position < 0 ? null : process.argv[position + 1] || null;
}

function fail(message) {
  throw new Error(message);
}

function usage() {
  return "Usage: node scripts/release/extract-validator-assignment-map.mjs --allocation-manifest <testnet-allocation-manifest.json> --identity-registry <identity-registry.public.json> --verifier <synergy-control> --output <validator-identities.json>";
}

const allocationManifestPath = option("--allocation-manifest");
const identityRegistryPath = option("--identity-registry");
const verifier = option("--verifier");
const outputPath = option("--output");
if (!allocationManifestPath || !identityRegistryPath || !verifier || !outputPath) {
  console.error(usage());
  process.exitCode = 2;
} else {
  const allocationManifest = JSON.parse(await readFile(resolve(allocationManifestPath), "utf8"));
  const identityRegistry = JSON.parse(await readFile(resolve(identityRegistryPath), "utf8"));
  const allocations = new Map();
  for (const record of allocationManifest.allocations || []) {
    const match = /^Validator (\d+) Bonded Stake$/.exec(String(record.name || ""));
    if (match) allocations.set(Number(match[1]), String(record.address || "").trim());
  }
  if (allocations.size !== VALIDATOR_IDS.length || VALIDATOR_IDS.some((id) => !/^synv[0-9a-z]+$/i.test(allocations.get(id) || ""))) {
    fail("Allocation manifest must contain exactly Validator 1-21 bonded-stake synv identities.");
  }
  const identities = new Map((identityRegistry.identities || []).map((record) => [String(record.address || "").trim(), record]));
  const assignments = [];
  for (const validator of VALIDATOR_IDS) {
    const identity = allocations.get(validator);
    const registryRecord = identities.get(identity);
    const publicFile = registryRecord && typeof registryRecord.public_file === "string" ? registryRecord.public_file : "";
    if (!publicFile) fail(`Validator ${validator} has no public identity file in the registry.`);
    const publicIdentity = JSON.parse(await readFile(resolve(publicFile), "utf8"));
    const publicKey = typeof publicIdentity.public_key === "string" ? publicIdentity.public_key.trim() : "";
    if (publicIdentity.address !== identity || !/^[A-Za-z0-9+/]+={0,2}$/.test(publicKey)) {
      fail(`Validator ${validator} public identity file is malformed or does not match the allocation manifest.`);
    }
    const verification = spawnSync(resolve(verifier), ["verify-validator-identity", "--address", identity, "--public-key-file", resolve(publicFile)], { encoding: "utf8" });
    if (verification.status !== 0) fail(`Validator ${validator} public key failed address-derivation verification.`);
    assignments.push({ validator, identity, publicKey });
  }
  if (new Set(assignments.map((entry) => entry.identity)).size !== VALIDATOR_IDS.length || new Set(assignments.map((entry) => entry.publicKey)).size !== VALIDATOR_IDS.length) {
    fail("Validator identities and public keys must each be unique.");
  }
  await writeFile(resolve(outputPath), `${JSON.stringify(assignments, null, 2)}\n`, "utf8");
  console.log(`Verified and wrote ${assignments.length} nonsecret validator assignments to ${resolve(outputPath)}.`);
}
