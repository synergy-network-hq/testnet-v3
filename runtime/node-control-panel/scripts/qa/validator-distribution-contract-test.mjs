import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const source = await readFile(new URL("../release/prepare-validator-distribution.mjs", import.meta.url), "utf8");
const extractor = await readFile(new URL("../release/extract-validator-assignment-map.mjs", import.meta.url), "utf8");
const artifactAudit = await readFile(new URL("../release/audit-installer-secret-surface.mjs", import.meta.url), "utf8");
const releaseWorkflow = await readFile(new URL("../../.github/workflows/release.yml", import.meta.url), "utf8");
const electronBuilder = await readFile(new URL("../../electron-builder.yml", import.meta.url), "utf8");

test("validator distribution produces the complete 1–21 matrix without private provisioning material", () => {
  assert.match(source, /length: 21/);
  assert.match(source, /INITIAL_VALIDATORS.*1, 2, 3, 4, 5, 6/s);
  assert.match(source, /validator-\$\{sequence\}/);
  assert.match(source, /assignedSynergyIdentity/);
  assert.match(source, /assignedValidatorPublicKey/);
  assert.match(source, /Each validator must be assigned a unique public key/);
  assert.match(source, /--assignments/);
  assert.match(source, /Each validator must be assigned a unique synv identity/);
  assert.match(source, /containsReusablePrivateIdentityKey: false/);
  assert.match(source, /containsCustodyPassphrase: false/);
  assert.match(source, /containsUnencryptedConsensusPrivateKey: false/);
  assert.match(source, /request-token-during-installation/);
  assert.match(source, /SHA256SUMS/);
  assert.match(source, /\.dmg/);
  assert.match(source, /\.deb/);
});

test("assignment-map extraction verifies public identity derivation without opening custody material", () => {
  assert.match(extractor, /length: 21/);
  assert.match(extractor, /identity\.pub\.json/);
  assert.match(extractor, /verify-validator-identity/);
  assert.match(extractor, /encrypted custody bundles or private keys/);
  assert.match(extractor, /Validator 1-21 bonded-stake synv identities/);
});

test("native packaging audits the final DMG and DEB payloads before validator distribution", () => {
  assert.match(artifactAudit, /endsWith\("\.asar"\)/);
  assert.match(artifactAudit, /PRIVATE_KEY_FILENAMES/);
  assert.match(artifactAudit, /PRIVATE_KEY_CONTENT/);
  assert.match(artifactAudit, /never prints file contents/);
  assert.match(releaseWorkflow, /Audit packaged installer for prohibited validator material/);
  assert.match(releaseWorkflow, /dpkg-deb --fsys-tarfile/);
  assert.match(releaseWorkflow, /hdiutil attach/);
  assert.match(releaseWorkflow, /audit-installer-secret-surface\.mjs/);
  assert.match(electronBuilder, /!\*\*\/keys\/\*\*/);
  assert.match(electronBuilder, /!\*\*\/setup-package\.json/);
});
