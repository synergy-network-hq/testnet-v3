import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../../", import.meta.url);
const source = (path) => readFile(new URL(path, root), "utf8");

test("coordinator binds a validator token to its package assignment and cryptographic synv proof", async () => {
  const [vpn, service, client, ui] = await Promise.all([
    source("control-service/src/validator_vpn.rs"),
    source("control-service/src/control_service.rs"),
    source("electron/onboarding/coordinator-client.cjs"),
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
  assert.match(ui, /Validator package assignment ID/);
  assert.match(ui, /Validator enrollment proof/);
  assert.match(ui, /validatorEnrollmentProofMessage/);
  assert.match(ui, /assignmentId: validatorAssignmentId\.trim\(\)/);
});
