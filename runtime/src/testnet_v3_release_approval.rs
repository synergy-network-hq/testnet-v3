//! Offline release-approval evidence for the Testnet-v3 genesis candidate.
//!
//! The candidate is not made final by an English-language status field.  The
//! designated governance authority must produce an ML-DSA-87 signature over a
//! canonical request that binds the exact staged candidate and its release
//! inputs.  This module only creates unsigned requests and verifies detached
//! signatures; it deliberately has no access to custody material and cannot
//! sign or apply a release.

use aegis_pqvm::pqc::signatures::mldsa::mldsa87;
use pqrust_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::address::derive_standard_account_address;

/// The exact ML-DSA context used for Testnet-v3 genesis release approval.
pub const TESTNET_V3_GENESIS_RELEASE_APPROVAL_DOMAIN: &str =
    "SYNERGY_TESTNET_V3_GENESIS_RELEASE_APPROVAL_V4";
/// The only frozen role permitted to approve the Testnet-v3 genesis release.
pub const TESTNET_V3_GOVERNANCE_AUTHORITY_ROLE: &str = "SNRG-TESTNET-V3-GOVERNANCE-AUTHORITY";
/// The artifact type accepted by the final Genesis release gate.
pub const TESTNET_V3_GENESIS_RELEASE_APPROVAL_ARTIFACT_TYPE: &str =
    "testnet-v3-genesis-release-approval";
/// The exact action that the designated governance authority approves.
pub const TESTNET_V3_GENESIS_RELEASE_ACTION: &str = "APPROVE_FINAL_TESTNET_V3_GENESIS_CANDIDATE";

const SCHEMA_VERSION: u32 = 4;
const EXPECTED_CHAIN_ID: u64 = 1266;
/// SNTS-09's canonical *technical* environment identifier.  It is deliberately
/// distinct from the human release identifier below.
const EXPECTED_NETWORK_ID: &str = "testnet";
const EXPECTED_RELEASE_ID: &str = "testnet-v3";
const EXPECTED_SYNQ_NETWORK_ID: &str = "synergy-testnet";
const EXPECTED_ALGORITHM: &str = "ML-DSA-87";
const EXPECTED_AUTHORITIES_ARTIFACT: &str = "TESTNET_V3_PRODUCTION_AUTHORITIES";
const ETDAG_MEMBERSHIP_ANCHOR_SCHEMA: &str = "synergy-etdag-governed-membership-proof-v1";

/// The immutable facts a governance signature authorizes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TestnetV3GenesisReleaseApprovalRequest {
    pub schema_version: u32,
    pub artifact_type: String,
    pub action: String,
    pub signature_algorithm: String,
    pub signature_domain: String,
    pub governance_authority_role: String,
    pub governance_standard_account_address: String,
    pub governance_public_key_fingerprint: String,
    pub governance_identity_authorization_binding_sha3_256: String,
    pub candidate_sha256: String,
    pub genesis_hash: String,
    pub chain_id: u64,
    pub network_id: String,
    pub release_id: String,
    pub synq_network_id: String,
    pub candidate_input_id: String,
    pub post_deployment_execution_state_root: String,
    pub post_deployment_aivm_state_root: String,
    pub deployment_receipt_root: String,
    pub consensus_parameter_manifest_sha256: String,
    pub consensus_parameter_root_sha3_512: String,
    pub consensus_parameter_decision_id: String,
    /// Root of the exact governed ETDAG parameter artifact committed by this
    /// authorization.  It must never be a placeholder or an all-zero digest.
    pub etdag_parameter_root_sha3_512: String,
    /// Root of the fee schedule chained to `etdag_parameter_root_sha3_512`.
    pub etdag_fee_schedule_root_sha3_512: String,
    /// Digest of the public, strictly canonical validator membership anchor.
    /// The anchor is post-Genesis because it contains the finalized Genesis
    /// hash, but this approval commits the anchor digest before activation.
    pub etdag_membership_anchor_digest_sha3_512: String,
    pub frozen_authority_record_sha256: String,
    /// Exact P3 desired-state bytes that every initial validator must install.
    /// The V4 approval is the only production authorization for this binding.
    pub desired_state_sha256: String,
    pub desired_state_testnet_v3_revision: String,
    pub desired_state_synq_revision: String,
    pub desired_state_aegis_revision: String,
    pub desired_state_role_binary_sha256: BTreeMap<String, String>,
    pub desired_state_role_configuration_sha256: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreshP3DesiredStateBinding {
    pub desired_state_sha256: String,
    pub testnet_v3_revision: String,
    pub synq_revision: String,
    pub aegis_revision: String,
    pub role_binary_sha256: BTreeMap<String, String>,
    pub role_configuration_sha256: BTreeMap<String, String>,
}

impl TestnetV3GenesisReleaseApprovalRequest {
    /// Serializes the only payload that an approver is allowed to sign.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        validate_request_shape(self)?;
        serde_json::to_vec(self)
            .map_err(|error| format!("serialize canonical release-approval request: {error}"))
    }
}

/// A detached ML-DSA-87 signature over a canonical release-approval request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedTestnetV3GenesisReleaseApproval {
    pub schema_version: u32,
    pub artifact_type: String,
    pub request: TestnetV3GenesisReleaseApprovalRequest,
    pub signature_hex: String,
}

/// The authority facts pinned from the candidate-bound frozen authority file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrozenGovernanceAuthority {
    pub role: String,
    pub standard_account_address: String,
    pub public_key_fingerprint: String,
    pub governance_identity_authorization_binding_sha3_256: String,
    pub public_key: Vec<u8>,
    pub frozen_authority_record_sha256: String,
}

/// Builds the unsigned, canonical request for a staged Testnet-v3 candidate.
///
/// The request includes the SHA-256 of the candidate bytes as staged, rather
/// than a re-serialized copy, so a signature cannot be replayed against a
/// whitespace- or content-different release file.
pub fn build_release_approval_request(
    repo_root: &Path,
    candidate_path: &Path,
    authorities_path: &Path,
    desired_state_path: &Path,
) -> Result<TestnetV3GenesisReleaseApprovalRequest, String> {
    build_release_approval_request_inner(
        repo_root,
        candidate_path,
        authorities_path,
        desired_state_path,
        true,
    )
}

fn build_release_approval_request_inner(
    repo_root: &Path,
    candidate_path: &Path,
    authorities_path: &Path,
    desired_state_path: &Path,
    require_custody_hashes: bool,
) -> Result<TestnetV3GenesisReleaseApprovalRequest, String> {
    let candidate_bytes = read_file(candidate_path, "release candidate")?;
    let candidate = parse_json(&candidate_bytes, "release candidate")?;
    let authority = load_frozen_governance_authority_inner(
        repo_root,
        authorities_path,
        require_custody_hashes,
    )?;

    let candidate_authority_sha = json_string(
        &candidate,
        "/genesis_deployment/authority_record_sha256",
        "candidate genesis_deployment.authority_record_sha256",
    )?;
    if candidate_authority_sha != authority.frozen_authority_record_sha256 {
        return Err(
            "candidate authority_record_sha256 does not match the frozen authority record"
                .to_string(),
        );
    }
    validate_candidate_release_state(&candidate)?;
    let desired_state = load_fresh_p3_desired_state_binding(
        desired_state_path,
        &json_string(
            &candidate,
            "/integrity/genesis_hash",
            "candidate genesis hash",
        )?,
    )?;
    let etdag_binding = load_candidate_etdag_governance(&candidate)?;
    let etdag_membership_anchor = load_candidate_etdag_membership_anchor(&candidate)?;

    let request = TestnetV3GenesisReleaseApprovalRequest {
        schema_version: SCHEMA_VERSION,
        artifact_type: TESTNET_V3_GENESIS_RELEASE_APPROVAL_ARTIFACT_TYPE.to_string(),
        action: TESTNET_V3_GENESIS_RELEASE_ACTION.to_string(),
        signature_algorithm: EXPECTED_ALGORITHM.to_string(),
        signature_domain: TESTNET_V3_GENESIS_RELEASE_APPROVAL_DOMAIN.to_string(),
        governance_authority_role: authority.role,
        governance_standard_account_address: authority.standard_account_address,
        governance_public_key_fingerprint: authority.public_key_fingerprint,
        governance_identity_authorization_binding_sha3_256: authority
            .governance_identity_authorization_binding_sha3_256,
        candidate_sha256: sha256_hex(&candidate_bytes),
        genesis_hash: json_string(
            &candidate,
            "/integrity/genesis_hash",
            "candidate genesis hash",
        )?,
        chain_id: json_u64(&candidate, "/network/chain_id", "candidate chain id")?,
        network_id: json_string(
            &candidate,
            "/genesis_deployment/network_id",
            "candidate canonical network id",
        )?,
        release_id: json_string(
            &candidate,
            "/genesis_deployment/release_id",
            "candidate release id",
        )?,
        synq_network_id: json_string(
            &candidate,
            "/genesis_deployment/synq_network_id",
            "candidate SynQ network id",
        )?,
        candidate_input_id: json_string(
            &candidate,
            "/genesis_deployment/candidate_input_id",
            "candidate input id",
        )?,
        post_deployment_execution_state_root: json_string(
            &candidate,
            "/genesis_deployment/post_deployment_execution_state_root",
            "candidate post-deployment execution root",
        )?,
        post_deployment_aivm_state_root: json_string(
            &candidate,
            "/genesis_deployment/post_deployment_aivm_state_root",
            "candidate post-deployment AIVM root",
        )?,
        deployment_receipt_root: json_string(
            &candidate,
            "/genesis_deployment/receipt_root",
            "candidate deployment receipt root",
        )?,
        consensus_parameter_manifest_sha256: json_string(
            &candidate,
            "/consensus_parameters/canonical_manifest_sha256",
            "candidate consensus parameter manifest SHA-256",
        )?,
        consensus_parameter_root_sha3_512: json_string(
            &candidate,
            "/consensus_parameters/parameter_root_sha3_512",
            "candidate consensus parameter SHA3-512 root",
        )?,
        consensus_parameter_decision_id: json_string(
            &candidate,
            "/consensus_parameters/decision_id",
            "candidate consensus parameter decision id",
        )?,
        etdag_parameter_root_sha3_512: etdag_binding
            .parameter_artifact
            .etdag_parameter_root_sha3_512
            .to_hex(),
        etdag_fee_schedule_root_sha3_512: etdag_binding
            .fee_schedule_artifact
            .etdag_fee_schedule_root_sha3_512
            .to_hex(),
        etdag_membership_anchor_digest_sha3_512: etdag_membership_anchor.anchor_digest.to_hex(),
        frozen_authority_record_sha256: candidate_authority_sha,
        desired_state_sha256: desired_state.desired_state_sha256,
        desired_state_testnet_v3_revision: desired_state.testnet_v3_revision,
        desired_state_synq_revision: desired_state.synq_revision,
        desired_state_aegis_revision: desired_state.aegis_revision,
        desired_state_role_binary_sha256: desired_state.role_binary_sha256,
        desired_state_role_configuration_sha256: desired_state.role_configuration_sha256,
    };
    request.canonical_bytes()?;
    Ok(request)
}

/// Loads the canonical Testnet-v3 governance public key only after anchoring it
/// to the frozen authority record bound by the candidate.
pub fn load_frozen_governance_authority(
    repo_root: &Path,
    authorities_path: &Path,
) -> Result<FrozenGovernanceAuthority, String> {
    load_frozen_governance_authority_inner(repo_root, authorities_path, true)
}

/// Node-side trust loading validates only public identity material.  The V4
/// signature binds the authority-record bytes, so nodes must never receive an
/// encrypted governance custody envelope merely to verify a release.
pub fn load_frozen_governance_authority_public(
    repo_root: &Path,
    authorities_path: &Path,
) -> Result<FrozenGovernanceAuthority, String> {
    load_frozen_governance_authority_inner(repo_root, authorities_path, false)
}

fn load_frozen_governance_authority_inner(
    repo_root: &Path,
    authorities_path: &Path,
    require_custody_hashes: bool,
) -> Result<FrozenGovernanceAuthority, String> {
    let authority_bytes = read_file(authorities_path, "frozen authority record")?;
    let authorities = parse_json(&authority_bytes, "frozen authority record")?;
    if authorities.pointer("/artifact").and_then(Value::as_str)
        != Some(EXPECTED_AUTHORITIES_ARTIFACT)
        || authorities.pointer("/status").and_then(Value::as_str) != Some("FROZEN")
        || authorities
            .pointer("/test_fixture")
            .and_then(Value::as_bool)
            != Some(false)
        || authorities
            .pointer("/current_release_authority")
            .and_then(Value::as_bool)
            != Some(false)
        || authorities.pointer("/chain_id").and_then(Value::as_u64) != Some(EXPECTED_CHAIN_ID)
        || authorities.pointer("/network_id").and_then(Value::as_str) != Some(EXPECTED_NETWORK_ID)
        || authorities.pointer("/release_id").and_then(Value::as_str) != Some(EXPECTED_RELEASE_ID)
        || [
            "technical_network_id",
            "runtime_network_id",
            "network_slug",
            "network_native_id",
        ]
        .iter()
        .any(|retired_alias| authorities.get(retired_alias).is_some())
    {
        return Err(
            "authority record is not the canonical frozen Testnet-v3 V4 record".to_string(),
        );
    }

    let entries = authorities
        .pointer("/authorities")
        .and_then(Value::as_array)
        .ok_or_else(|| "frozen authority record has no authorities array".to_string())?;
    let entry = entries
        .iter()
        .find(|entry| {
            entry.get("role_id").and_then(Value::as_str)
                == Some(TESTNET_V3_GOVERNANCE_AUTHORITY_ROLE)
        })
        .ok_or_else(|| "frozen authority record has no governance authority entry".to_string())?;

    let role = value_string(entry, "role_id", "governance authority role")?;
    let standard_account_address = value_string(
        entry,
        "standard_account_address",
        "governance standard-account address",
    )?;
    let public_key_fingerprint = value_string(
        entry,
        "public_key_fingerprint",
        "governance public-key fingerprint",
    )?;
    let governance_identity_authorization_binding_sha3_256 = value_string(
        entry,
        "release_authorization_binding_payload_sha3_256",
        "governance release authorization binding payload SHA3-256",
    )?;
    let authorization_encrypted_sha256 = value_string(
        entry,
        "authorization_encrypted_sha256",
        "governance encrypted custody SHA-256",
    )?;
    let release_authorization_binding_sha256 = value_string(
        entry,
        "release_authorization_binding_sha256",
        "governance release authorization binding SHA-256",
    )?;
    if entry.get("authorization_algorithm").and_then(Value::as_str) != Some(EXPECTED_ALGORITHM)
        || !is_lower_hex(&governance_identity_authorization_binding_sha3_256, 32)
        || !is_lower_hex(&authorization_encrypted_sha256, 32)
        || !is_lower_hex(&release_authorization_binding_sha256, 32)
    {
        return Err(
            "governance authority entry has an invalid V4 algorithm, custody, or authorization binding"
                .to_string(),
        );
    }
    let bundle_dir = value_string(entry, "bundle_dir", "governance bundle directory")?;
    let bundle_dir = safe_relative_path(&bundle_dir, "governance bundle directory")?;
    let bundle = repo_root.join(bundle_dir);
    let identity_root_encrypted_sha256 = value_string(
        entry,
        "identity_root_encrypted_sha256",
        "governance encrypted identity-root custody SHA-256",
    )?;
    if !is_lower_hex(&identity_root_encrypted_sha256, 32) {
        return Err(
            "governance encrypted identity-root custody does not match the frozen authority entry"
                .to_string(),
        );
    }
    if require_custody_hashes
        && (sha256_hex(&read_file(
            &bundle.join("identity-root.enc.json"),
            "governance encrypted identity-root custody",
        )?) != identity_root_encrypted_sha256
            || sha256_hex(&read_file(
                &bundle.join("identity.enc.json"),
                "governance encrypted authorization custody",
            )?) != authorization_encrypted_sha256)
    {
        return Err(
            "governance encrypted custody does not match the frozen authority entry".to_string(),
        );
    }
    let identity_root_bytes = read_file(
        &bundle.join("identity-root.pub.json"),
        "governance identity-root public identity",
    )?;
    let identity_root = parse_json(
        &identity_root_bytes,
        "governance identity-root public identity",
    )?;
    if identity_root.get("schema_version").and_then(Value::as_str)
        != Some("synergy-native-public-identity-v3")
        || identity_root.get("binary_encoding").and_then(Value::as_str) != Some("lowercase-hex")
        || identity_root.get("identity_id").and_then(Value::as_str) != Some(role.as_str())
        || identity_root.get("address_type").and_then(Value::as_str) != Some("WalletAccount")
        || identity_root.get("algorithm").and_then(Value::as_str) != Some("FN-DSA-1024")
        || identity_root.get("address").and_then(Value::as_str)
            != Some(standard_account_address.as_str())
    {
        return Err(
            "governance FN-DSA identity root does not match the frozen authority entry".to_string(),
        );
    }
    let identity_root_public_sha256 = value_string(
        entry,
        "identity_root_public_sha256",
        "governance identity-root public identity SHA-256",
    )?;
    if !is_lower_hex(&identity_root_public_sha256, 32)
        || identity_root_public_sha256 != sha256_hex(&identity_root_bytes)
    {
        return Err(
            "governance identity-root public identity does not match the frozen authority entry"
                .to_string(),
        );
    }
    let identity_root_public_key_hex = value_string(
        &identity_root,
        "public_key",
        "governance FN-DSA identity-root public key",
    )?;
    let identity_root_public_key = decode_lower_hex(
        &identity_root_public_key_hex,
        "governance FN-DSA identity-root public key",
    )?;
    if identity_root_public_key.len() != 1_793 {
        return Err(format!(
            "governance FN-DSA identity-root public key is {} bytes; expected 1793",
            identity_root_public_key.len()
        ));
    }
    if derive_standard_account_address(&identity_root_public_key)? != standard_account_address {
        return Err(
            "governance standard-account address is not rooted in its frozen FN-DSA identity"
                .to_string(),
        );
    }
    let public_bytes = read_file(
        &bundle.join("identity.pub.json"),
        "governance authorization public key",
    )?;
    let public_document = parse_json(&public_bytes, "governance authorization public key")?;
    if public_document
        .get("binary_encoding")
        .and_then(Value::as_str)
        != Some("lowercase-hex")
        || public_document.get("role_id").and_then(Value::as_str) != Some(role.as_str())
        || public_document.get("algorithm").and_then(Value::as_str) != Some(EXPECTED_ALGORITHM)
    {
        return Err(
            "governance public bundle does not match the frozen authority entry".to_string(),
        );
    }
    if public_document
        .get("schema_version")
        .and_then(Value::as_str)
        != Some("synergy-governance-authorization-public-key-v1")
    {
        return Err(
            "governance authorization public key is not the canonical SNTS-v1.3 rotation schema"
                .to_string(),
        );
    }
    let public_key_hex = value_string(&public_document, "public_key", "governance public key")?;
    let public_key = decode_lower_hex(&public_key_hex, "governance public key")?;
    let expected_public_sha256 = value_string(
        entry,
        "authorization_public_sha256",
        "governance authorization public identity SHA-256",
    )?;
    if !is_lower_hex(&expected_public_sha256, 32)
        || expected_public_sha256 != sha256_hex(&public_bytes)
    {
        return Err(
            "governance authorization public identity does not match the frozen authority entry"
                .to_string(),
        );
    }
    if public_key.len() != 2_592 {
        return Err(format!(
            "governance public key is {} bytes; expected ML-DSA-87 length 2592",
            public_key.len()
        ));
    }
    let actual_fingerprint = format!("sha256:{}", sha256_hex(&public_key));
    if actual_fingerprint != public_key_fingerprint {
        return Err(
            "governance public-key fingerprint does not match frozen authority entry".to_string(),
        );
    }
    let release_binding_bytes = read_file(
        &bundle.join("release-authorization-binding.json"),
        "governance release authorization binding",
    )?;
    if sha256_hex(&release_binding_bytes) != release_authorization_binding_sha256 {
        return Err(
            "governance release authorization binding does not match the frozen authority entry"
                .to_string(),
        );
    }
    let release_binding = parse_json(
        &release_binding_bytes,
        "governance release authorization binding",
    )?;
    if release_binding
        .get("schema_version")
        .and_then(Value::as_str)
        != Some("synergy-identity-authorization-binding-v1")
        || release_binding
            .get("binary_encoding")
            .and_then(Value::as_str)
            != Some("lowercase-hex")
        || release_binding.get("identity_id").and_then(Value::as_str) != Some(role.as_str())
        || release_binding
            .get("identity_address")
            .and_then(Value::as_str)
            != Some(standard_account_address.as_str())
        || release_binding
            .pointer("/identity_root/algorithm")
            .and_then(Value::as_str)
            != Some("FN-DSA-1024")
        || release_binding
            .pointer("/identity_root/public_key")
            .and_then(Value::as_str)
            != Some(identity_root_public_key_hex.as_str())
        || release_binding
            .pointer("/authorization_policy/policy_type")
            .and_then(Value::as_str)
            != Some("single-key")
        || release_binding
            .pointer("/authorization_policy/threshold")
            .and_then(Value::as_u64)
            != Some(1)
        || release_binding
            .pointer("/authorization_policy/principals/0/algorithm")
            .and_then(Value::as_str)
            != Some(EXPECTED_ALGORITHM)
        || release_binding
            .pointer("/authorization_policy/principals/0/public_key")
            .and_then(Value::as_str)
            != Some(public_key_hex.as_str())
        || release_binding
            .pointer("/authorization_policy/principals/0/status")
            .and_then(Value::as_str)
            != Some("active")
        || release_binding
            .pointer("/authorization_scopes/0/signature_domain")
            .and_then(Value::as_str)
            != Some(TESTNET_V3_GENESIS_RELEASE_APPROVAL_DOMAIN)
        || release_binding
            .pointer("/authorization_scopes/0/chain_id")
            .and_then(Value::as_u64)
            != Some(EXPECTED_CHAIN_ID)
        || release_binding
            .pointer("/authorization_scopes/0/network_id")
            .and_then(Value::as_str)
            != Some(EXPECTED_NETWORK_ID)
        || release_binding
            .pointer("/authorization_scopes/0/purpose")
            .and_then(Value::as_str)
            != Some("testnet-v3-genesis-release-approval")
        || release_binding
            .get("authorization_scopes")
            .and_then(Value::as_array)
            .map(Vec::len)
            != Some(1)
        || release_binding
            .get("binding_payload_sha3_256")
            .and_then(Value::as_str)
            != Some(governance_identity_authorization_binding_sha3_256.as_str())
    {
        return Err(
            "governance release authorization binding does not bind the exact v1.3 identity, key, and V4 scope"
                .to_string(),
        );
    }

    Ok(FrozenGovernanceAuthority {
        role,
        standard_account_address,
        public_key_fingerprint,
        governance_identity_authorization_binding_sha3_256,
        public_key,
        frozen_authority_record_sha256: sha256_hex(&authority_bytes),
    })
}

/// Verifies a supplied governance approval against the exact staged candidate.
///
/// This function never reads a private key and does not accept a public key
/// from the approval artifact.  The only verification key is the frozen
/// governance public key that is already bound into the candidate.
pub fn verify_release_approval_file(
    repo_root: &Path,
    candidate_path: &Path,
    authorities_path: &Path,
    desired_state_path: &Path,
    approval_path: &Path,
) -> Result<TestnetV3GenesisReleaseApprovalRequest, String> {
    let expected = build_release_approval_request(
        repo_root,
        candidate_path,
        authorities_path,
        desired_state_path,
    )?;
    let authority = load_frozen_governance_authority(repo_root, authorities_path)?;
    let approval: SignedTestnetV3GenesisReleaseApproval = serde_json::from_slice(&read_file(
        approval_path,
        "signed release-approval artifact",
    )?)
    .map_err(|error| format!("parse signed release-approval artifact: {error}"))?;
    if approval.schema_version != SCHEMA_VERSION
        || approval.artifact_type != TESTNET_V3_GENESIS_RELEASE_APPROVAL_ARTIFACT_TYPE
    {
        return Err(
            "signed release-approval artifact has an unsupported schema or type".to_string(),
        );
    }
    if approval.request != expected {
        return Err(
            "signed release-approval request does not exactly match the staged candidate"
                .to_string(),
        );
    }
    let signature = decode_lower_hex(&approval.signature_hex, "release-approval signature")?;
    if signature.is_empty() {
        return Err("release-approval signature is empty".to_string());
    }
    let payload = approval.request.canonical_bytes()?;
    let public_key = mldsa87::PublicKey::from_bytes(&authority.public_key)
        .map_err(|_| "frozen governance ML-DSA-87 public key is malformed".to_string())?;
    let signature = mldsa87::DetachedSignature::from_bytes(&signature)
        .map_err(|_| "release-approval ML-DSA-87 signature is malformed".to_string())?;
    mldsa87::verify_detached_signature_ctx(
        &signature,
        &payload,
        TESTNET_V3_GENESIS_RELEASE_APPROVAL_DOMAIN.as_bytes(),
        &public_key,
    )
    .map_err(|_| "ML-DSA-87 release-approval signature verification failed".to_string())?;
    Ok(approval.request)
}

/// Verifies a deployed V4 approval using only the explicit frozen authority
/// record and its public bundle.  This is the production P3 node path: it is
/// intentionally unable to read encrypted governance custody material.
pub fn verify_release_approval_file_public(
    trust_root: &Path,
    candidate_path: &Path,
    authorities_path: &Path,
    desired_state_path: &Path,
    approval_path: &Path,
) -> Result<TestnetV3GenesisReleaseApprovalRequest, String> {
    let expected = build_release_approval_request_inner(
        trust_root,
        candidate_path,
        authorities_path,
        desired_state_path,
        false,
    )?;
    let authority = load_frozen_governance_authority_public(trust_root, authorities_path)?;
    let approval: SignedTestnetV3GenesisReleaseApproval = serde_json::from_slice(&read_file(
        approval_path,
        "signed release-approval artifact",
    )?)
    .map_err(|error| format!("parse signed release-approval artifact: {error}"))?;
    if approval.schema_version != SCHEMA_VERSION
        || approval.artifact_type != TESTNET_V3_GENESIS_RELEASE_APPROVAL_ARTIFACT_TYPE
    {
        return Err(
            "signed release-approval artifact has an unsupported schema or type".to_string(),
        );
    }
    if approval.request != expected {
        return Err(
            "signed release-approval request does not exactly match the staged candidate"
                .to_string(),
        );
    }
    let signature = decode_lower_hex(&approval.signature_hex, "release-approval signature")?;
    if signature.is_empty() {
        return Err("release-approval signature is empty".to_string());
    }
    let payload = approval.request.canonical_bytes()?;
    let public_key = mldsa87::PublicKey::from_bytes(&authority.public_key)
        .map_err(|_| "frozen governance ML-DSA-87 public key is malformed".to_string())?;
    let signature = mldsa87::DetachedSignature::from_bytes(&signature)
        .map_err(|_| "release-approval ML-DSA-87 signature is malformed".to_string())?;
    mldsa87::verify_detached_signature_ctx(
        &signature,
        &payload,
        TESTNET_V3_GENESIS_RELEASE_APPROVAL_DOMAIN.as_bytes(),
        &public_key,
    )
    .map_err(|_| "ML-DSA-87 release-approval signature verification failed".to_string())?;
    Ok(approval.request)
}

fn validate_candidate_release_state(candidate: &Value) -> Result<(), String> {
    if candidate
        .pointer("/integrity/status")
        .and_then(Value::as_str)
        != Some("candidate_deployment_bound_pending_release_approval")
        || candidate
            .pointer("/genesis_deployment/status")
            .and_then(Value::as_str)
            != Some("EXECUTED_AND_BOUND")
        || candidate
            .pointer("/network/network_slug")
            .and_then(Value::as_str)
            != Some(EXPECTED_NETWORK_ID)
        || candidate
            .pointer("/genesis_deployment/network_id")
            .and_then(Value::as_str)
            != Some(EXPECTED_NETWORK_ID)
        || candidate
            .pointer("/genesis_deployment/release_id")
            .and_then(Value::as_str)
            != Some(EXPECTED_RELEASE_ID)
    {
        return Err("candidate is not the executed Testnet-v3 release-approval stage".to_string());
    }
    Ok(())
}

fn load_candidate_etdag_governance(
    candidate: &Value,
) -> Result<crate::etdag_governance::EtdagGovernedGenesisBinding, String> {
    let binding: crate::etdag_governance::EtdagGovernedGenesisBinding = serde_json::from_value(
        candidate
            .pointer("/etdag_governance")
            .cloned()
            .ok_or_else(|| "candidate ETDAG governed binding is missing".to_string())?,
    )
    .map_err(|error| format!("parse candidate ETDAG governed binding: {error}"))?;
    binding.validate()?;
    let parameter_root = binding
        .parameter_artifact
        .etdag_parameter_root_sha3_512
        .to_hex();
    let fee_root = binding
        .fee_schedule_artifact
        .etdag_fee_schedule_root_sha3_512
        .to_hex();
    if json_string(
        candidate,
        "/integrity/etdag_parameter_root_sha3_512",
        "candidate ETDAG parameter root",
    )? != parameter_root
        || json_string(
            candidate,
            "/integrity/etdag_fee_schedule_root_sha3_512",
            "candidate ETDAG fee schedule root",
        )? != fee_root
    {
        return Err("candidate ETDAG integrity roots disagree with governed artifacts".to_string());
    }
    Ok(binding)
}

fn load_candidate_etdag_membership_anchor(
    candidate: &Value,
) -> Result<crate::etdag_governance::EtdagGovernedMembershipAnchor, String> {
    const ANCHOR_PATH: &str = "/etdag_membership_anchor";
    let anchor: crate::etdag_governance::EtdagGovernedMembershipAnchor = serde_json::from_value(
        candidate
            .pointer(ANCHOR_PATH)
            .cloned()
            .ok_or_else(|| "candidate ETDAG membership anchor is missing".to_string())?,
    )
    .map_err(|error| format!("parse candidate ETDAG membership anchor: {error}"))?;
    anchor.validate()?;
    if anchor.schema != ETDAG_MEMBERSHIP_ANCHOR_SCHEMA
        || anchor.genesis_hash
            != json_string(
                candidate,
                "/integrity/genesis_hash",
                "candidate genesis hash",
            )?
        || anchor.deployed_execution_state_root
            != json_string(
                candidate,
                "/genesis_deployment/post_deployment_execution_state_root",
                "candidate post-deployment execution root",
            )?
        || anchor.initial_consensus_parameter_root.to_hex()
            != json_string(
                candidate,
                "/consensus_parameters/parameter_root_sha3_512",
                "candidate consensus parameter SHA3-512 root",
            )?
    {
        return Err(
            "candidate ETDAG membership anchor is not bound to the staged Genesis inputs"
                .to_string(),
        );
    }
    let genesis_hash_inputs = candidate
        .pointer("/canonicalization/genesis_hash_inputs")
        .and_then(Value::as_array)
        .ok_or_else(|| "candidate canonical Genesis hash inputs are missing".to_string())?;
    if genesis_hash_inputs
        .iter()
        .any(|entry| entry.as_str() == Some("etdag_membership_anchor"))
    {
        return Err(
            "post-Genesis ETDAG membership anchor must not be included in the Genesis hash"
                .to_string(),
        );
    }
    if !candidate
        .pointer("/canonicalization/excluded_from_genesis_hash")
        .and_then(Value::as_array)
        .is_some_and(|excluded| {
            excluded
                .iter()
                .any(|entry| entry.as_str() == Some("etdag_membership_anchor"))
        })
    {
        return Err(
            "post-Genesis ETDAG membership anchor must be explicitly excluded from the Genesis hash"
                .to_string(),
        );
    }
    let binding = load_candidate_etdag_governance(candidate)?;
    if anchor.governance_decision_id != binding.parameter_artifact.manifest.governance_decision_id {
        return Err(
            "ETDAG membership anchor governance decision does not match the parameter and fee artifacts"
                .to_string(),
        );
    }
    Ok(anchor)
}

/// Reads the P3 desired-state document that is itself covered by the V4
/// approval.  This deliberately accepts no P1 coordinator or detached
/// start-authority fields: a fresh P3 node must derive release authority from
/// the verified V4 approval, not from a second legacy signing domain.
pub fn load_fresh_p3_desired_state_binding(
    desired_state_path: &Path,
    expected_genesis_hash: &str,
) -> Result<FreshP3DesiredStateBinding, String> {
    let bytes = read_file(desired_state_path, "fresh P3 desired state")?;
    let value = parse_json(&bytes, "fresh P3 desired state")?;
    if value.pointer("/schema_version").and_then(Value::as_u64) != Some(1)
        || value.pointer("/chain/chain_id").and_then(Value::as_u64) != Some(EXPECTED_CHAIN_ID)
        || value.pointer("/chain/incarnation").and_then(Value::as_u64) != Some(5)
        || value.pointer("/chain/genesis_hash").and_then(Value::as_str)
            != Some(expected_genesis_hash)
        || value
            .pointer("/state/consensus_schema_version")
            .and_then(Value::as_u64)
            != Some(5)
        || value
            .pointer("/state/directory_namespace")
            .and_then(Value::as_str)
            != Some("chain-1266/incarnation-5")
        || value.pointer("/state/mode").and_then(Value::as_str) != Some("posy_simplified_v3")
        || value
            .pointer("/state/coordinator_id")
            .and_then(Value::as_str)
            != Some("")
        || value
            .pointer("/state/producer_ids")
            .and_then(Value::as_array)
            .is_none_or(|ids| !ids.is_empty())
        || value
            .pointer("/state/producer_turn_timeout_ms")
            .and_then(Value::as_u64)
            != Some(0)
        || value.get("start_authority").is_some()
    {
        return Err("desired state is not the canonical fresh P3 release profile".to_string());
    }
    let source = value
        .get("source")
        .and_then(Value::as_object)
        .ok_or_else(|| "fresh P3 desired state omits source revisions".to_string())?;
    let source_revision = |name: &str| -> Result<String, String> {
        let value = source
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("fresh P3 desired state omits source.{name}"))?;
        if !is_lower_hex(value, 20) {
            return Err(format!(
                "fresh P3 desired state source.{name} is not a Git revision"
            ));
        }
        Ok(value.to_string())
    };
    let role_binary_sha256 =
        required_sha256_map(value.get("artifacts"), "fresh P3 desired-state role binary")?;
    if role_binary_sha256.len() != 1 || !role_binary_sha256.contains_key("validator_node") {
        return Err(
            "fresh P3 desired state must bind exactly the validator_node binary".to_string(),
        );
    }
    let role_configuration_sha256 = required_sha256_map(
        value.get("configuration"),
        "fresh P3 desired-state role configuration",
    )?;
    let expected_roles = [
        "validator-02",
        "validator-03",
        "validator-04",
        "validator-05",
        "validator-06",
    ];
    if role_configuration_sha256
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>()
        != expected_roles
    {
        return Err(
            "fresh P3 desired state must bind exactly validator-02 through validator-06"
                .to_string(),
        );
    }
    Ok(FreshP3DesiredStateBinding {
        desired_state_sha256: sha256_hex(&bytes),
        testnet_v3_revision: source_revision("testnet_v3_revision")?,
        synq_revision: source_revision("synq_revision")?,
        aegis_revision: source_revision("aegis_revision")?,
        role_binary_sha256,
        role_configuration_sha256,
    })
}

fn required_sha256_map(
    value: Option<&Value>,
    label: &str,
) -> Result<BTreeMap<String, String>, String> {
    let object = value
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{label} must be an object"))?;
    if object.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    let mut output = BTreeMap::new();
    for (name, digest) in object {
        let digest = digest
            .as_str()
            .filter(|digest| is_lower_hex(digest, 32))
            .ok_or_else(|| format!("{label} {name} is not a SHA-256 digest"))?;
        if name.trim().is_empty() {
            return Err(format!("{label} has an empty role"));
        }
        output.insert(name.clone(), digest.to_string());
    }
    Ok(output)
}

fn validate_request_shape(request: &TestnetV3GenesisReleaseApprovalRequest) -> Result<(), String> {
    if request.schema_version != SCHEMA_VERSION
        || request.artifact_type != TESTNET_V3_GENESIS_RELEASE_APPROVAL_ARTIFACT_TYPE
        || request.action != TESTNET_V3_GENESIS_RELEASE_ACTION
        || request.signature_algorithm != EXPECTED_ALGORITHM
        || request.signature_domain != TESTNET_V3_GENESIS_RELEASE_APPROVAL_DOMAIN
        || request.governance_authority_role != TESTNET_V3_GOVERNANCE_AUTHORITY_ROLE
        || request.chain_id != EXPECTED_CHAIN_ID
        || request.network_id != EXPECTED_NETWORK_ID
        || request.release_id != EXPECTED_RELEASE_ID
        || request.synq_network_id != EXPECTED_SYNQ_NETWORK_ID
    {
        return Err(
            "release-approval request has an invalid immutable Testnet-v3 binding".to_string(),
        );
    }
    for (label, value, bytes) in [
        ("candidate_sha256", &request.candidate_sha256, 32),
        ("genesis_hash", &request.genesis_hash, 32),
        ("candidate_input_id", &request.candidate_input_id, 32),
        (
            "post_deployment_execution_state_root",
            &request.post_deployment_execution_state_root,
            32,
        ),
        (
            "post_deployment_aivm_state_root",
            &request.post_deployment_aivm_state_root,
            32,
        ),
        (
            "deployment_receipt_root",
            &request.deployment_receipt_root,
            32,
        ),
        (
            "consensus_parameter_manifest_sha256",
            &request.consensus_parameter_manifest_sha256,
            32,
        ),
        (
            "consensus_parameter_root_sha3_512",
            &request.consensus_parameter_root_sha3_512,
            64,
        ),
        (
            "etdag_parameter_root_sha3_512",
            &request.etdag_parameter_root_sha3_512,
            64,
        ),
        (
            "etdag_fee_schedule_root_sha3_512",
            &request.etdag_fee_schedule_root_sha3_512,
            64,
        ),
        (
            "etdag_membership_anchor_digest_sha3_512",
            &request.etdag_membership_anchor_digest_sha3_512,
            64,
        ),
        (
            "frozen_authority_record_sha256",
            &request.frozen_authority_record_sha256,
            32,
        ),
        ("desired_state_sha256", &request.desired_state_sha256, 32),
        (
            "desired_state_testnet_v3_revision",
            &request.desired_state_testnet_v3_revision,
            20,
        ),
        (
            "desired_state_synq_revision",
            &request.desired_state_synq_revision,
            20,
        ),
        (
            "desired_state_aegis_revision",
            &request.desired_state_aegis_revision,
            20,
        ),
    ] {
        if !is_lower_hex(value, bytes) {
            return Err(format!(
                "release-approval request {label} is not lowercase hex"
            ));
        }
    }
    if !request
        .governance_public_key_fingerprint
        .starts_with("sha256:")
        || !is_lower_hex(&request.governance_public_key_fingerprint[7..], 32)
        || !is_lower_hex(
            &request.governance_identity_authorization_binding_sha3_256,
            32,
        )
        || request.governance_standard_account_address.is_empty()
        || request.consensus_parameter_decision_id.is_empty()
    {
        return Err(
            "release-approval request has invalid governance or consensus bindings".to_string(),
        );
    }
    if request.desired_state_role_binary_sha256.len() != 1
        || !request
            .desired_state_role_binary_sha256
            .contains_key("validator_node")
    {
        return Err(
            "release-approval request must bind exactly the fresh P3 validator binary".to_string(),
        );
    }
    let expected_roles = [
        "validator-02",
        "validator-03",
        "validator-04",
        "validator-05",
        "validator-06",
    ];
    if request
        .desired_state_role_configuration_sha256
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>()
        != expected_roles
    {
        return Err(
            "release-approval request must bind exactly validator-02 through validator-06 configurations"
                .to_string(),
        );
    }
    for (label, bindings) in [
        (
            "desired_state_role_binary_sha256",
            &request.desired_state_role_binary_sha256,
        ),
        (
            "desired_state_role_configuration_sha256",
            &request.desired_state_role_configuration_sha256,
        ),
    ] {
        for (role, digest) in bindings {
            if role.trim().is_empty() || !is_lower_hex(digest, 32) {
                return Err(format!(
                    "release-approval request {label} has an invalid role binding"
                ));
            }
        }
    }
    for (label, root) in [
        (
            "etdag_parameter_root_sha3_512",
            &request.etdag_parameter_root_sha3_512,
        ),
        (
            "etdag_fee_schedule_root_sha3_512",
            &request.etdag_fee_schedule_root_sha3_512,
        ),
        (
            "etdag_membership_anchor_digest_sha3_512",
            &request.etdag_membership_anchor_digest_sha3_512,
        ),
    ] {
        if root.bytes().all(|byte| byte == b'0') {
            return Err(format!(
                "release-approval request {label} must not be all zero"
            ));
        }
    }
    Ok(())
}

fn read_file(path: &Path, label: &str) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|error| format!("read {label} {}: {error}", path.display()))
}

fn parse_json(bytes: &[u8], label: &str) -> Result<Value, String> {
    serde_json::from_slice(bytes).map_err(|error| format!("parse {label} JSON: {error}"))
}

fn json_string(value: &Value, pointer: &str, label: &str) -> Result<String, String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("{label} is missing or not a string"))
}

fn json_u64(value: &Value, pointer: &str, label: &str) -> Result<u64, String> {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{label} is missing or not an unsigned integer"))
}

fn value_string(value: &Value, key: &str, label: &str) -> Result<String, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("{label} is missing or not a string"))
}

fn safe_relative_path(raw: &str, label: &str) -> Result<PathBuf, String> {
    let path = Path::new(raw);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(format!("{label} must be a repository-relative path"));
    }
    Ok(path.to_path_buf())
}

fn is_lower_hex(value: &str, expected_bytes: usize) -> bool {
    value.len() == expected_bytes.saturating_mul(2)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn decode_lower_hex(value: &str, label: &str) -> Result<Vec<u8>, String> {
    if value.is_empty()
        || value.len() % 2 != 0
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "{label} must be non-empty lowercase hexadecimal without a 0x prefix"
        ));
    }
    hex::decode(value).map_err(|error| format!("decode {label}: {error}"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqrust_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
    use serde_json::json;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestRepository {
        root: PathBuf,
        candidate: PathBuf,
        authorities: PathBuf,
        desired_state: PathBuf,
    }

    fn test_authority_keypair() -> (Vec<u8>, Vec<u8>) {
        let (public_key, signing_key) = mldsa87::keypair();
        (
            public_key.as_bytes().to_vec(),
            signing_key.as_bytes().to_vec(),
        )
    }

    impl Drop for TestRepository {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn test_repository_with_governance_schema(
        public_key: &[u8],
        preserved_v3: bool,
    ) -> TestRepository {
        let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "synergy-testnet-v3-release-approval-{}-{sequence}",
            std::process::id()
        ));
        let bundle = root.join("test-fixture/governance");
        fs::create_dir_all(&bundle).expect("create test governance bundle");
        let identity_root_public_key = vec![0x42; 1_793];
        let standard_account_address = derive_standard_account_address(&identity_root_public_key)
            .expect("test FN-DSA root derives a canonical account address");
        let identity_root = serde_json::to_vec(&json!({
            "schema_version": "synergy-native-public-identity-v3",
            "binary_encoding": "lowercase-hex",
            "identity_id": TESTNET_V3_GOVERNANCE_AUTHORITY_ROLE,
            "address": standard_account_address,
            "address_type": "WalletAccount",
            "algorithm": "FN-DSA-1024",
            "public_key": hex::encode(&identity_root_public_key),
        }))
        .expect("encode identity root");
        fs::write(bundle.join("identity-root.pub.json"), &identity_root)
            .expect("write identity root");
        let identity_root_encrypted = b"test encrypted FN custody";
        fs::write(
            bundle.join("identity-root.enc.json"),
            identity_root_encrypted,
        )
        .expect("write encrypted identity root");
        let public_key_fingerprint = format!("sha256:{}", sha256_hex(public_key));
        let public_identity = serde_json::to_vec(&if preserved_v3 {
            json!({
                "schema_version": "synergy-authority-public-identity-v3",
                "binary_encoding": "lowercase-hex",
                "address": standard_account_address,
                "address_type": "WalletAccount",
                "algorithm": EXPECTED_ALGORITHM,
                "created_at": "2026-08-23T00:00:00Z",
                "public_key": hex::encode(public_key),
                "role_id": TESTNET_V3_GOVERNANCE_AUTHORITY_ROLE,
            })
        } else {
            json!({
                "schema_version": "synergy-governance-authorization-public-key-v1",
                "binary_encoding": "lowercase-hex",
                "role_id": TESTNET_V3_GOVERNANCE_AUTHORITY_ROLE,
                "algorithm": EXPECTED_ALGORITHM,
                "public_key": hex::encode(public_key),
            })
        })
        .expect("encode public identity");
        fs::write(bundle.join("identity.pub.json"), &public_identity)
            .expect("write public identity");
        let authorization_encrypted = b"test encrypted ML custody";
        fs::write(bundle.join("identity.enc.json"), authorization_encrypted)
            .expect("write encrypted authorization key");
        let release_binding = serde_json::to_vec(&json!({
            "schema_version": "synergy-identity-authorization-binding-v1",
            "binary_encoding": "lowercase-hex",
            "identity_id": TESTNET_V3_GOVERNANCE_AUTHORITY_ROLE,
            "identity_address": standard_account_address,
            "identity_root": {
                "algorithm": "FN-DSA-1024",
                "public_key": hex::encode(&identity_root_public_key),
            },
            "authorization_policy": {
                "policy_type": "single-key",
                "threshold": 1,
                "principals": [{
                    "principal_id": TESTNET_V3_GOVERNANCE_AUTHORITY_ROLE,
                    "principal_type": "public-key",
                    "algorithm": EXPECTED_ALGORITHM,
                    "public_key": hex::encode(public_key),
                    "status": "active",
                    "purposes": ["testnet-v3-genesis-release-approval"],
                }],
            },
            "authorization_scopes": [{
                "signature_domain": TESTNET_V3_GENESIS_RELEASE_APPROVAL_DOMAIN,
                "chain_id": EXPECTED_CHAIN_ID,
                "network_id": EXPECTED_NETWORK_ID,
                "purpose": "testnet-v3-genesis-release-approval",
            }],
            "binding_payload_sha3_256": "aa".repeat(32),
        }))
        .expect("encode release binding");
        fs::write(
            bundle.join("release-authorization-binding.json"),
            &release_binding,
        )
        .expect("write release binding");
        let authorities = root.join("authorities.json");
        let authority_value = json!({
            "artifact": EXPECTED_AUTHORITIES_ARTIFACT,
            "status": "FROZEN",
            "test_fixture": false,
            "current_release_authority": false,
            "chain_id": EXPECTED_CHAIN_ID,
            "network_id": EXPECTED_NETWORK_ID,
            "release_id": EXPECTED_RELEASE_ID,
            "authorities": [{
                "role_id": TESTNET_V3_GOVERNANCE_AUTHORITY_ROLE,
                "authorization_algorithm": EXPECTED_ALGORITHM,
                "standard_account_address": standard_account_address,
                "public_key_fingerprint": public_key_fingerprint,
                "identity_root_public_sha256": sha256_hex(&identity_root),
                "identity_root_encrypted_sha256": sha256_hex(identity_root_encrypted),
                "authorization_public_sha256": sha256_hex(&public_identity),
                "authorization_encrypted_sha256": sha256_hex(authorization_encrypted),
                "release_authorization_binding_sha256": sha256_hex(&release_binding),
                "release_authorization_binding_payload_sha3_256": "aa".repeat(32),
                "bundle_dir": "test-fixture/governance",
            }]
        });
        let authority_bytes = serde_json::to_vec(&authority_value).expect("encode authorities");
        fs::write(&authorities, &authority_bytes).expect("write authorities");
        let etdag_binding = test_etdag_binding();
        let etdag_membership_anchor = test_etdag_membership_anchor();
        let candidate = root.join("candidate.json");
        let candidate_value = json!({
            "network": {"chain_id": EXPECTED_CHAIN_ID, "network_slug": EXPECTED_NETWORK_ID},
            "integrity": {
                "status": "candidate_deployment_bound_pending_release_approval",
                "genesis_hash": "11".repeat(32),
                "etdag_parameter_root_sha3_512":
                    etdag_binding.parameter_artifact.etdag_parameter_root_sha3_512.to_hex(),
                "etdag_fee_schedule_root_sha3_512":
                    etdag_binding.fee_schedule_artifact.etdag_fee_schedule_root_sha3_512.to_hex(),
            },
            "genesis_deployment": {
                "status": "EXECUTED_AND_BOUND",
                "network_id": EXPECTED_NETWORK_ID,
                "release_id": EXPECTED_RELEASE_ID,
                "synq_network_id": EXPECTED_SYNQ_NETWORK_ID,
                "candidate_input_id": "22".repeat(32),
                "authority_record_sha256": sha256_hex(&authority_bytes),
                "post_deployment_execution_state_root": "33".repeat(32),
                "post_deployment_aivm_state_root": "44".repeat(32),
                "receipt_root": "55".repeat(32),
            },
            "consensus_parameters": {
                "canonical_manifest_sha256": "66".repeat(32),
                "parameter_root_sha3_512": "77".repeat(64),
                "decision_id": "TV3-POSY-PARAMS-UNIT-TEST",
            },
            "canonicalization": {
                "genesis_hash_inputs": ["etdag_governance"],
                "excluded_from_genesis_hash": ["etdag_membership_anchor"],
            },
            "etdag_governance": etdag_binding,
            "etdag_membership_anchor": etdag_membership_anchor,
        });
        fs::write(
            &candidate,
            serde_json::to_vec(&candidate_value).expect("encode candidate"),
        )
        .expect("write candidate");
        let desired_state = root.join("desired-state.json");
        fs::write(
            &desired_state,
            serde_json::to_vec(&json!({
                "schema_version": 1,
                "release_id": "chain1266-incarnation-5-rc1",
                "release_tag": "chain1266-v20.0.0-rc.1",
                "chain": {
                    "chain_id": 1266,
                    "incarnation": 5,
                    "genesis_hash": "11".repeat(32),
                    "validator_set_root": "22".repeat(32),
                },
                "source": {
                    "testnet_v3_revision": "33".repeat(20),
                    "synq_revision": "44".repeat(20),
                    "aegis_revision": "55".repeat(20),
                },
                "state": {
                    "consensus_schema_version": 5,
                    "directory_namespace": "chain-1266/incarnation-5",
                    "mode": "posy_simplified_v3",
                    "coordinator_id": "",
                    "producer_ids": [],
                    "producer_turn_timeout_ms": 0,
                },
                "artifacts": {"validator_node": "66".repeat(32)},
                "configuration": {
                    "validator-02": "67".repeat(32),
                    "validator-03": "68".repeat(32),
                    "validator-04": "69".repeat(32),
                    "validator-05": "6a".repeat(32),
                    "validator-06": "6b".repeat(32),
                },
            }))
            .expect("encode desired state"),
        )
        .expect("write desired state");
        TestRepository {
            root,
            candidate,
            authorities,
            desired_state,
        }
    }

    fn test_repository(public_key: &[u8]) -> TestRepository {
        test_repository_with_governance_schema(public_key, false)
    }

    fn test_etdag_binding() -> crate::etdag_governance::EtdagGovernedGenesisBinding {
        use crate::etdag::EtdagParameters;
        use crate::etdag_governance::{
            EtdagFeeScheduleArtifact, EtdagFeeScheduleManifest, EtdagGovernedGenesisBinding,
            EtdagParameterArtifact, EtdagParameterManifest, ETDAG_FEE_SCHEDULE_MANIFEST_SCHEMA,
            ETDAG_GOVERNED_GENESIS_BINDING_SCHEMA_VERSION, ETDAG_GOVERNED_GENESIS_BINDING_STATUS,
            ETDAG_PARAMETER_MANIFEST_SCHEMA,
        };
        use crate::gas::{fee_market::FeeMarketParams, FeeSchedule};
        use crate::synergy_types::{ChainId, NetworkId};

        let parameter_artifact = EtdagParameterArtifact::from_manifest(EtdagParameterManifest {
            schema: ETDAG_PARAMETER_MANIFEST_SCHEMA.to_string(),
            governance_decision_id: "GOV-ETDAG-20260823-UNIT".to_string(),
            chain_id: ChainId::synergy_testnet_v3(),
            network_id: NetworkId::fresh_posy_testnet_v3(),
            consensus_protocol_version:
                crate::consensus::simplified_posy::POSY_SIMPLIFIED_PROTOCOL_VERSION.to_string(),
            parameters: EtdagParameters::default(),
        })
        .expect("construct ETDAG parameter artifact");
        let fee_schedule_artifact =
            EtdagFeeScheduleArtifact::from_manifest(EtdagFeeScheduleManifest {
                schema: ETDAG_FEE_SCHEDULE_MANIFEST_SCHEMA.to_string(),
                governance_decision_id: "GOV-ETDAG-20260823-UNIT".to_string(),
                chain_id: ChainId::synergy_testnet_v3(),
                network_id: NetworkId::fresh_posy_testnet_v3(),
                consensus_protocol_version:
                    crate::consensus::simplified_posy::POSY_SIMPLIFIED_PROTOCOL_VERSION.to_string(),
                etdag_parameter_root_sha3_512: parameter_artifact
                    .etdag_parameter_root_sha3_512
                    .clone(),
                fee_schedule: FeeSchedule::default(),
                fee_market_params: FeeMarketParams::testnet_v3_defaults(),
            })
            .expect("construct ETDAG fee artifact");
        EtdagGovernedGenesisBinding {
            schema_version: ETDAG_GOVERNED_GENESIS_BINDING_SCHEMA_VERSION,
            status: ETDAG_GOVERNED_GENESIS_BINDING_STATUS.to_string(),
            parameter_artifact,
            fee_schedule_artifact,
        }
    }

    fn test_etdag_membership_anchor() -> crate::etdag_governance::EtdagGovernedMembershipAnchor {
        use crate::etdag_governance::{
            EtdagGovernedMembershipAnchor, EtdagGovernedRoot, EtdagInitialValidatorSet,
            EtdagMembershipConsensusPublicKey, EtdagMembershipValidator,
            ETDAG_GOVERNED_MEMBERSHIP_PROOF_SCHEMA,
        };
        use crate::synergy_types::{
            TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM, TESTNET_V3_MLDSA65_PUBLIC_KEY_BYTES,
        };

        let mut anchor = EtdagGovernedMembershipAnchor {
            schema: ETDAG_GOVERNED_MEMBERSHIP_PROOF_SCHEMA.to_string(),
            governance_decision_id: "GOV-ETDAG-20260823-UNIT".to_string(),
            genesis_hash: "11".repeat(32),
            deployed_execution_state_root: "33".repeat(32),
            genesis_activation_binding_digest: EtdagGovernedRoot::from_hex(&"88".repeat(64))
                .expect("fixed activation digest"),
            initial_epoch: 0,
            initial_consensus_parameter_root: EtdagGovernedRoot::from_hex(&"77".repeat(64))
                .expect("fixed parameter digest"),
            initial_validator_set: EtdagInitialValidatorSet {
                validators: (2..=6)
                    .map(|index| EtdagMembershipValidator {
                        validator_id: format!("validator-{index:02}"),
                        consensus_public_key: EtdagMembershipConsensusPublicKey {
                            key_id: format!("validator-{index:02}-consensus"),
                            algorithm: TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM.to_string(),
                            key_bytes: vec![index as u8; TESTNET_V3_MLDSA65_PUBLIC_KEY_BYTES],
                        },
                        voting_weight: 1,
                    })
                    .collect(),
            },
            anchor_digest: EtdagGovernedRoot::from_hex(&"99".repeat(64))
                .expect("fixed placeholder digest"),
        };
        anchor.anchor_digest = anchor
            .expected_anchor_digest()
            .expect("derive anchor digest");
        anchor
    }

    fn signed_approval(
        repository: &TestRepository,
        signing_key: &[u8],
    ) -> SignedTestnetV3GenesisReleaseApproval {
        let request = build_release_approval_request(
            &repository.root,
            &repository.candidate,
            &repository.authorities,
            &repository.desired_state,
        )
        .expect("build request");
        let signing_key =
            mldsa87::SecretKey::from_bytes(signing_key).expect("parse ML-DSA-87 test signing key");
        let signature = mldsa87::detached_sign_ctx(
            &request.canonical_bytes().expect("canonical request"),
            TESTNET_V3_GENESIS_RELEASE_APPROVAL_DOMAIN.as_bytes(),
            &signing_key,
        );
        SignedTestnetV3GenesisReleaseApproval {
            schema_version: SCHEMA_VERSION,
            artifact_type: TESTNET_V3_GENESIS_RELEASE_APPROVAL_ARTIFACT_TYPE.to_string(),
            request,
            signature_hex: hex::encode(signature.as_bytes()),
        }
    }

    #[test]
    fn signed_approval_verifies_only_against_the_frozen_governance_key() {
        let (public_key, signing_key) = test_authority_keypair();
        let repository = test_repository(&public_key);
        let approval = signed_approval(&repository, &signing_key);
        let approval_path = repository.root.join("approval.json");
        fs::write(
            &approval_path,
            serde_json::to_vec(&approval).expect("encode approval"),
        )
        .expect("write approval");

        let verified = verify_release_approval_file(
            &repository.root,
            &repository.candidate,
            &repository.authorities,
            &repository.desired_state,
            &approval_path,
        )
        .expect("verify signed approval");

        assert_eq!(verified, approval.request);
    }

    #[test]
    fn public_verifier_accepts_only_the_staged_public_authority_bundle() {
        let (public_key, signing_key) = test_authority_keypair();
        let repository = test_repository(&public_key);
        let approval = signed_approval(&repository, &signing_key);
        let approval_path = repository.root.join("approval.json");
        fs::write(
            &approval_path,
            serde_json::to_vec(&approval).expect("encode approval"),
        )
        .expect("write approval");

        // Deployment packages must not carry governance custody material. The
        // public verifier still has to validate every V4 binding and signature.
        fs::remove_file(
            repository
                .root
                .join("test-fixture/governance/identity-root.enc.json"),
        )
        .expect("remove encrypted FN custody");
        fs::remove_file(
            repository
                .root
                .join("test-fixture/governance/identity.enc.json"),
        )
        .expect("remove encrypted ML custody");

        let verified = verify_release_approval_file_public(
            &repository.root,
            &repository.candidate,
            &repository.authorities,
            &repository.desired_state,
            &approval_path,
        )
        .expect("verify public-only release approval");

        assert_eq!(verified, approval.request);
    }

    #[test]
    fn approval_rejects_a_signature_from_an_unfrozen_key() {
        let (frozen_public_key, _) = test_authority_keypair();
        let (_, attacker_key) = test_authority_keypair();
        let repository = test_repository(&frozen_public_key);
        let approval = signed_approval(&repository, &attacker_key);
        let approval_path = repository.root.join("approval.json");
        fs::write(
            &approval_path,
            serde_json::to_vec(&approval).expect("encode approval"),
        )
        .expect("write approval");

        let error = verify_release_approval_file(
            &repository.root,
            &repository.candidate,
            &repository.authorities,
            &repository.desired_state,
            &approval_path,
        )
        .expect_err("unfrozen signer must be rejected");

        assert!(error.contains("signature verification failed"));
    }

    #[test]
    fn authority_loader_accepts_the_canonical_v1_rotation_public_shape() {
        let (public_key, _) = test_authority_keypair();
        let repository = test_repository(&public_key);

        assert!(
            load_frozen_governance_authority(&repository.root, &repository.authorities).is_ok()
        );
    }

    #[test]
    fn authority_loader_rejects_the_superseded_key_derived_v3_public_shape() {
        let (public_key, _) = test_authority_keypair();
        let repository = test_repository_with_governance_schema(&public_key, true);

        let error = load_frozen_governance_authority(&repository.root, &repository.authorities)
            .expect_err("superseded key-derived authority schema must be rejected");
        assert!(error.contains("canonical SNTS-v1.3 rotation schema"));
    }

    #[test]
    fn approval_rejects_a_changed_candidate_before_signature_verification() {
        let (public_key, signing_key) = test_authority_keypair();
        let repository = test_repository(&public_key);
        let approval = signed_approval(&repository, &signing_key);
        let approval_path = repository.root.join("approval.json");
        fs::write(
            &approval_path,
            serde_json::to_vec(&approval).expect("encode approval"),
        )
        .expect("write approval");
        let mut candidate: Value =
            serde_json::from_slice(&fs::read(&repository.candidate).expect("read candidate"))
                .expect("parse candidate");
        candidate["genesis_deployment"]["candidate_input_id"] = Value::String("88".repeat(32));
        fs::write(
            &repository.candidate,
            serde_json::to_vec(&candidate).expect("encode changed candidate"),
        )
        .expect("write changed candidate");

        let error = verify_release_approval_file(
            &repository.root,
            &repository.candidate,
            &repository.authorities,
            &repository.desired_state,
            &approval_path,
        )
        .expect_err("changed candidate must be rejected");

        assert!(error.contains("does not exactly match the staged candidate"));
    }

    #[test]
    fn request_commits_nonzero_governed_etdag_roots_and_membership_anchor() {
        let (public_key, _) = test_authority_keypair();
        let repository = test_repository(&public_key);

        let request = build_release_approval_request(
            &repository.root,
            &repository.candidate,
            &repository.authorities,
            &repository.desired_state,
        )
        .expect("build governed V4 request");

        assert_eq!(request.schema_version, 4);
        assert_eq!(request.network_id, EXPECTED_NETWORK_ID);
        assert_eq!(request.release_id, EXPECTED_RELEASE_ID);
        assert!(is_lower_hex(&request.etdag_parameter_root_sha3_512, 64));
        assert!(is_lower_hex(&request.etdag_fee_schedule_root_sha3_512, 64));
        assert!(is_lower_hex(
            &request.etdag_membership_anchor_digest_sha3_512,
            64
        ));
        assert_ne!(request.etdag_parameter_root_sha3_512, "0".repeat(128));
        assert_ne!(request.etdag_fee_schedule_root_sha3_512, "0".repeat(128));
        assert_ne!(
            request.etdag_membership_anchor_digest_sha3_512,
            "0".repeat(128)
        );
    }

    #[test]
    fn request_rejects_etdag_roots_that_do_not_match_the_governed_artifacts() {
        let (public_key, _) = test_authority_keypair();
        let repository = test_repository(&public_key);
        let mut candidate: Value =
            serde_json::from_slice(&fs::read(&repository.candidate).expect("read candidate"))
                .expect("parse candidate");
        candidate["integrity"]["etdag_fee_schedule_root_sha3_512"] = Value::String("00".repeat(64));
        fs::write(
            &repository.candidate,
            serde_json::to_vec(&candidate).expect("encode changed candidate"),
        )
        .expect("write changed candidate");

        let error = build_release_approval_request(
            &repository.root,
            &repository.candidate,
            &repository.authorities,
            &repository.desired_state,
        )
        .expect_err("tampered ETDAG root must be rejected");

        assert!(error.contains("ETDAG integrity roots disagree"));
    }
}
