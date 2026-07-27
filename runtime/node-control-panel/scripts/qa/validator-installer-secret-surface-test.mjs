import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { auditInstallerSecretSurface } from "../release/audit-installer-secret-surface.mjs";

async function fixture() {
  return mkdtemp(join(tmpdir(), "synergy-installer-audit-"));
}

test("accepts a generic installer payload without validator provisioning material", async (t) => {
  const root = await fixture();
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, "resources"), { recursive: true });
  await writeFile(join(root, "resources", "configuration.json"), '{"enrollment":"request-token-during-installation"}\n');
  await auditInstallerSecretSurface(root);
});

test("rejects a packaged private validator key by its filename", async (t) => {
  const root = await fixture();
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, "resources", "keys"), { recursive: true });
  await writeFile(join(root, "resources", "keys", "validator-key.json"), '{}\n');
  await assert.rejects(() => auditInstallerSecretSurface(root), /Unsafe validator provisioning material/);
});

test("rejects a private key value in structured installer configuration", async (t) => {
  const root = await fixture();
  t.after(() => rm(root, { recursive: true, force: true }));
  await writeFile(join(root, "identity.json"), '{"private_key":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}\n');
  await assert.rejects(() => auditInstallerSecretSurface(root), /private-key content/);
});
