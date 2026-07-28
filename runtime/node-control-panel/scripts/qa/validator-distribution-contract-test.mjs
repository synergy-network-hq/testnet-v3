import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const source = (path) => readFile(new URL(path, import.meta.url), "utf8");
const [staging, builder, packageLoader, workflow, electronBuilder] = await Promise.all([
  source("../release/stage-validator-package.mjs"),
  source("../release/build-validator-installers.mjs"),
  source("../../electron/onboarding/validator-package.cjs"),
  source("../../../../.github/workflows/node-control-panel-release.yml"),
  source("../../electron-builder.yml"),
]);

test("validator installers bind exactly one complete Testnet-v3 assignment", () => {
  for (const fileName of [
    "identity.enc.json",
    "identity.pub.json",
    "manifest.json",
    "wireguard-private.key",
    "wireguard-public.key",
    "sy-vpn.conf",
    "vpn-binding.json",
  ]) {
    assert.match(staging, new RegExp(fileName.replaceAll(".", "\\.")));
    assert.match(packageLoader, new RegExp(fileName.replaceAll(".", "\\.")));
  }
  assert.match(staging, /validator <1-21>/);
  assert.match(staging, /chain_id\) === 1266/);
  assert.match(staging, /synergy-testnet-v3/);
  assert.match(staging, /initial-six/);
  assert.match(staging, /gradual-activation/);
  assert.match(staging, /containsIdentityPassphrase: false/);
  assert.match(staging, /installerBoundToSingleValidator: true/);
  assert.match(packageLoader, /VALIDATOR_PACKAGE_CHECKSUM_FAILED/);
  assert.match(packageLoader, /VALIDATOR_PACKAGE_BINDING_FAILED/);
});

test("native release build produces 21 uniquely named DMGs or DEBs and clears staging", () => {
  assert.match(builder, /from < 1/);
  assert.match(builder, /to > 21/);
  assert.match(builder, /macOS DMG installers must be built and signed on macOS/);
  assert.match(builder, /Linux DEB installers must be built on Linux/);
  assert.match(builder, /APP_VERSION.*Validator-\$\{id\}-arm64\.dmg/s);
  assert.match(builder, /APP_VERSION.*validator-\$\{id\}_amd64\.deb/s);
  assert.match(builder, /SHA256SUMS/);
  assert.match(builder, /manifest\.json/);
  assert.match(builder, /finally/);
  assert.match(builder, /\.gitkeep/);
  assert.match(electronBuilder, /from: build\/validator-package/);
  assert.match(electronBuilder, /to: validator-package/);
});

test("generic release remains separate and audits out validator custody material", () => {
  assert.match(workflow, /Audit packaged installer for prohibited validator material/);
  assert.match(workflow, /audit-installer-secret-surface\.mjs/);
  assert.match(workflow, /dpkg-deb --fsys-tarfile/);
  assert.match(workflow, /hdiutil attach/);
});
