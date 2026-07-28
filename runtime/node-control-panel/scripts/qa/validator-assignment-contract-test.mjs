import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../../", import.meta.url);
const source = (path) => readFile(new URL(path, root), "utf8");

test("coordinator binds the one-time token to the installer assignment and a locally generated synv proof", async () => {
  const [vpn, service, client, ipc, innernet, packaged, ui] = await Promise.all([
    source("control-service/src/validator_vpn.rs"),
    source("control-service/src/control_service.rs"),
    source("electron/onboarding/coordinator-client.cjs"),
    source("electron/ipc/onboarding-ipc.cjs"),
    source("electron/onboarding/innernet.cjs"),
    source("electron/onboarding/validator-package.cjs"),
    source("src/components/control-panel-v18/ControlPanelV18.jsx"),
  ]);
  assert.match(vpn, /assigned_validator_identity/);
  assert.match(vpn, /assigned_validator_public_key/);
  assert.match(vpn, /verify_validator_identity_enrollment_proof/);
  assert.match(vpn, /verify_identity_proof/);
  assert.match(vpn, /identity_proof_verified_at/);
  assert.match(vpn, /assignment_id/);
  assert.match(vpn, /fn onboarding_token_assignment_matches/);
  assert.match(vpn, /token_record\.assignment_id\.as_deref\(\) == assignment_id/);
  assert.match(vpn, /token_record\.assigned_validator_identity\.as_deref\(\)/);
  assert.match(vpn, /validator_onboarding_token_requires_its_exact_assignment_and_identity/);
  assert.match(vpn, /record\.used_at = Some/);
  assert.match(service, /assignment_id: Option<String>/);
  assert.match(service, /identity_proof: Option<String>/);
  assert.match(client, /assignment_id:/);
  assert.match(client, /identity_proof:/);
  assert.match(client, /preconfigured_vpn_ip:/);
  assert.match(client, /preconfigured_wireguard_public_key:/);
  assert.match(packaged, /VALIDATOR_PACKAGE_CHECKSUM_FAILED/);
  assert.match(packaged, /decryptValidatorPackage/);
  assert.match(ipc, /testnet_sign_packaged_validator_enrollment_proof/);
  assert.match(ipc, /packaged\.assignmentId/);
  assert.match(ipc, /install-packaged-validator-identity/);
  assert.match(ipc, /activatePackagedWireguardConfig/);
  assert.match(innernet, /install.*\/etc\/wireguard\/\$\{interfaceName\}\.conf/s);
  assert.match(innernet, /wg-quick@sy-vpn\.service/);
  assert.match(innernet, /PACKAGED_WIREGUARD_KEY_MISMATCH/);
  assert.match(service, /create_preconfigured_enrollment/);
  assert.match(ui, /Validator package assignment ID/);
  assert.match(ui, /Validator enrollment proof/);
  assert.match(ui, /validatorEnrollmentProofMessage/);
  assert.match(ui, /validatorPackage\.assignmentId \|\| validatorAssignmentId\.trim\(\)/);
  assert.match(ui, /One-time onboarding token/);
  assert.match(ui, /full .* VPN topology is already included/);
});
