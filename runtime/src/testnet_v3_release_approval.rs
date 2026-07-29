//! Offline release-approval evidence for the Testnet-v3 genesis candidate.
//!
//! The candidate is not made final by an English-language status field.  The
//! designated governance authority must produce an ML-DSA-87 signature over a
//! canonical request that binds the exact staged candidate and its release
//! inputs.  This module only creates unsigned requests and verifies detached
//! signatures; it deliberately has no access to custody material and cannot
//! sign or apply a release.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::address::derive_standard_account_address;

/// The exact ML-DSA context used for Testnet-v3 genesis release approval.
pub const TESTNET_V3_GENESIS_RELEASE_APPROVAL_DOMAIN: &str =
    "SYNERGY_TESTNET_V3_GENESIS_RELEASE_APPROVAL_V1";
/// The only frozen role permitted to approve the Testnet-v3 genesis release.
pub const TESTNET_V3_GOVERNANCE_AUTHORITY_ROLE: &str = "SNRG-TESTNET-V3-GOVERNANCE-AUTHORITY";
/// The artifact type accepted by the final Genesis release gate.
pub const TESTNET_V3_GENESIS_RELEASE_APPROVAL_ARTIFACT_TYPE: &str =
    "testnet-v3-genesis-release-approval";
/// The exact action that the designated governance authority approves.
pub const TESTNET_V3_GENESIS_RELEASE_ACTION: &str = "APPROVE_FINAL_TESTNET_V3_GENESIS_CANDIDATE";

const SCHEMA_VERSION: u32 = 1;
const EXPECTED_CHAIN_ID: u64 = 1266;
const EXPECTED_RUNTIME_NETWORK_ID: &str = "synergy-testnet-v3";
const EXPECTED_SYNQ_NETWORK_ID: &str = "synergy-testnet";
const EXPECTED_ALGORITHM: &str = "ML-DSA-87";

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
    pub candidate_sha256: String,
    pub genesis_hash: String,
    pub chain_id: u64,
    pub runtime_network_id: String,
    pub synq_network_id: String,
    pub candidate_input_id: String,
    pub post_deployment_execution_state_root: String,
    pub post_deployment_aivm_state_root: String,
    pub deployment_receipt_root: String,
    pub consensus_parameter_manifest_sha256: String,
    pub consensus_parameter_root_sha3_512: String,
    pub consensus_parameter_decision_id: String,
    pub frozen_authority_record_sha256: String,
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
    pub signature_base64: String,
}

/// The authority facts pinned from the candidate-bound frozen authority file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrozenGovernanceAuthority {
    pub role: String,
    pub standard_account_address: String,
    pub public_key_fingerprint: String,
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
) -> Result<TestnetV3GenesisReleaseApprovalRequest, String> {
    let candidate_bytes = read_file(candidate_path, "release candidate")?;
    let candidate = parse_json(&candidate_bytes, "release candidate")?;
    let authority = load_frozen_governance_authority(repo_root, authorities_path)?;

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

    let request = TestnetV3GenesisReleaseApprovalRequest {
        schema_version: SCHEMA_VERSION,
        artifact_type: TESTNET_V3_GENESIS_RELEASE_APPROVAL_ARTIFACT_TYPE.to_string(),
        action: TESTNET_V3_GENESIS_RELEASE_ACTION.to_string(),
        signature_algorithm: EXPECTED_ALGORITHM.to_string(),
        signature_domain: TESTNET_V3_GENESIS_RELEASE_APPROVAL_DOMAIN.to_string(),
        governance_authority_role: authority.role,
        governance_standard_account_address: authority.standard_account_address,
        governance_public_key_fingerprint: authority.public_key_fingerprint,
        candidate_sha256: sha256_hex(&candidate_bytes),
        genesis_hash: json_string(
            &candidate,
            "/integrity/genesis_hash",
            "candidate genesis hash",
        )?,
        chain_id: json_u64(&candidate, "/network/chain_id", "candidate chain id")?,
        runtime_network_id: json_string(
            &candidate,
            "/genesis_deployment/runtime_network_id",
            "candidate runtime network id",
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
        frozen_authority_record_sha256: candidate_authority_sha,
    };
    validate_candidate_release_state(&candidate)?;
    request.canonical_bytes()?;
    Ok(request)
}

/// Loads the canonical Testnet-v3 governance public key only after anchoring it
/// to the frozen authority record bound by the candidate.
pub fn load_frozen_governance_authority(
    repo_root: &Path,
    authorities_path: &Path,
) -> Result<FrozenGovernanceAuthority, String> {
    let authority_bytes = read_file(authorities_path, "frozen authority record")?;
    let authorities = parse_json(&authority_bytes, "frozen authority record")?;
    if authorities.pointer("/status").and_then(Value::as_str) != Some("FROZEN")
        || authorities
            .pointer("/test_fixture")
            .and_then(Value::as_bool)
            != Some(false)
        || authorities.pointer("/algorithm").and_then(Value::as_str) != Some(EXPECTED_ALGORITHM)
        || authorities.pointer("/chain_id").and_then(Value::as_u64) != Some(EXPECTED_CHAIN_ID)
        || authorities.pointer("/network_id").and_then(Value::as_str)
            != Some(EXPECTED_RUNTIME_NETWORK_ID)
    {
        return Err("authority record is not the frozen Testnet-v3 ML-DSA-87 record".to_string());
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
    let bundle_dir = value_string(entry, "bundle_dir", "governance bundle directory")?;
    let bundle_dir = safe_relative_path(&bundle_dir, "governance bundle directory")?;
    let bundle = repo_root.join(bundle_dir);
    let public_document = parse_json(
        &read_file(
            &bundle.join("identity.pub.json"),
            "governance public identity",
        )?,
        "governance public identity",
    )?;
    let bundle_manifest = parse_json(
        &read_file(&bundle.join("manifest.json"), "governance bundle manifest")?,
        "governance bundle manifest",
    )?;
    if bundle_manifest.get("role_id").and_then(Value::as_str) != Some(role.as_str())
        || bundle_manifest.get("algorithm").and_then(Value::as_str) != Some(EXPECTED_ALGORITHM)
        || bundle_manifest.get("chain_id").and_then(Value::as_u64) != Some(EXPECTED_CHAIN_ID)
        || bundle_manifest.get("network_id").and_then(Value::as_str)
            != Some(EXPECTED_RUNTIME_NETWORK_ID)
        || bundle_manifest.get("test_fixture").and_then(Value::as_bool) != Some(false)
        || bundle_manifest
            .get("public_key_fingerprint")
            .and_then(Value::as_str)
            != Some(public_key_fingerprint.as_str())
        || public_document.get("algorithm").and_then(Value::as_str) != Some(EXPECTED_ALGORITHM)
        || public_document.get("address").and_then(Value::as_str)
            != Some(standard_account_address.as_str())
    {
        return Err(
            "governance public bundle does not match the frozen authority entry".to_string(),
        );
    }
    let public_key_base64 = value_string(&public_document, "public_key", "governance public key")?;
    let public_key = BASE64
        .decode(public_key_base64)
        .map_err(|error| format!("decode governance public key: {error}"))?;
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
    if derive_standard_account_address(&public_key) != standard_account_address {
        return Err(
            "governance public key does not derive the frozen standard-account address".to_string(),
        );
    }

    Ok(FrozenGovernanceAuthority {
        role,
        standard_account_address,
        public_key_fingerprint,
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
    approval_path: &Path,
) -> Result<TestnetV3GenesisReleaseApprovalRequest, String> {
    let expected = build_release_approval_request(repo_root, candidate_path, authorities_path)?;
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
    let signature = BASE64
        .decode(&approval.signature_base64)
        .map_err(|error| format!("decode release-approval signature: {error}"))?;
    if signature.is_empty() {
        return Err("release-approval signature is empty".to_string());
    }
    let payload = approval.request.canonical_bytes()?;
    let verified = pqsynq::Sign::mldsa87()
        .verify_ctx(
            &payload,
            &signature,
            &authority.public_key,
            TESTNET_V3_GENESIS_RELEASE_APPROVAL_DOMAIN.as_bytes(),
        )
        .map_err(|error| format!("verify ML-DSA-87 release-approval signature: {error}"))?;
    if !verified {
        return Err("ML-DSA-87 release-approval signature verification failed".to_string());
    }
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
            != Some(EXPECTED_RUNTIME_NETWORK_ID)
    {
        return Err("candidate is not the executed Testnet-v3 release-approval stage".to_string());
    }
    Ok(())
}

fn validate_request_shape(request: &TestnetV3GenesisReleaseApprovalRequest) -> Result<(), String> {
    if request.schema_version != SCHEMA_VERSION
        || request.artifact_type != TESTNET_V3_GENESIS_RELEASE_APPROVAL_ARTIFACT_TYPE
        || request.action != TESTNET_V3_GENESIS_RELEASE_ACTION
        || request.signature_algorithm != EXPECTED_ALGORITHM
        || request.signature_domain != TESTNET_V3_GENESIS_RELEASE_APPROVAL_DOMAIN
        || request.governance_authority_role != TESTNET_V3_GOVERNANCE_AUTHORITY_ROLE
        || request.chain_id != EXPECTED_CHAIN_ID
        || request.runtime_network_id != EXPECTED_RUNTIME_NETWORK_ID
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
            "frozen_authority_record_sha256",
            &request.frozen_authority_record_sha256,
            32,
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
        || request.governance_standard_account_address.is_empty()
        || request.consensus_parameter_decision_id.is_empty()
    {
        return Err(
            "release-approval request has invalid governance or consensus bindings".to_string(),
        );
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

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqsynq::traits::DigitalSignature as _;
    use serde_json::json;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestRepository {
        root: PathBuf,
        candidate: PathBuf,
        authorities: PathBuf,
    }

    impl Drop for TestRepository {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn test_repository(public_key: &[u8]) -> TestRepository {
        let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "synergy-testnet-v3-release-approval-{}-{sequence}",
            std::process::id()
        ));
        let bundle = root.join("test-fixture/governance");
        fs::create_dir_all(&bundle).expect("create test governance bundle");
        let public_key_fingerprint = format!("sha256:{}", sha256_hex(public_key));
        let standard_account_address = derive_standard_account_address(public_key);
        fs::write(
            bundle.join("identity.pub.json"),
            serde_json::to_vec(&json!({
                "algorithm": EXPECTED_ALGORITHM,
                "address": standard_account_address,
                "public_key": BASE64.encode(public_key),
            }))
            .expect("encode public identity"),
        )
        .expect("write public identity");
        fs::write(
            bundle.join("manifest.json"),
            serde_json::to_vec(&json!({
                "role_id": TESTNET_V3_GOVERNANCE_AUTHORITY_ROLE,
                "algorithm": EXPECTED_ALGORITHM,
                "chain_id": EXPECTED_CHAIN_ID,
                "network_id": EXPECTED_RUNTIME_NETWORK_ID,
                "test_fixture": false,
                "public_key_fingerprint": public_key_fingerprint,
            }))
            .expect("encode governance manifest"),
        )
        .expect("write governance manifest");
        let authorities = root.join("authorities.json");
        let authority_value = json!({
            "status": "FROZEN",
            "test_fixture": false,
            "algorithm": EXPECTED_ALGORITHM,
            "chain_id": EXPECTED_CHAIN_ID,
            "network_id": EXPECTED_RUNTIME_NETWORK_ID,
            "authorities": [{
                "role_id": TESTNET_V3_GOVERNANCE_AUTHORITY_ROLE,
                "standard_account_address": standard_account_address,
                "public_key_fingerprint": public_key_fingerprint,
                "bundle_dir": "test-fixture/governance",
            }]
        });
        let authority_bytes = serde_json::to_vec(&authority_value).expect("encode authorities");
        fs::write(&authorities, &authority_bytes).expect("write authorities");
        let candidate = root.join("candidate.json");
        let candidate_value = json!({
            "network": {"chain_id": EXPECTED_CHAIN_ID, "network_slug": EXPECTED_RUNTIME_NETWORK_ID},
            "integrity": {
                "status": "candidate_deployment_bound_pending_release_approval",
                "genesis_hash": "11".repeat(32),
            },
            "genesis_deployment": {
                "status": "EXECUTED_AND_BOUND",
                "runtime_network_id": EXPECTED_RUNTIME_NETWORK_ID,
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
            }
        });
        fs::write(
            &candidate,
            serde_json::to_vec(&candidate_value).expect("encode candidate"),
        )
        .expect("write candidate");
        TestRepository {
            root,
            candidate,
            authorities,
        }
    }

    fn signed_approval(
        repository: &TestRepository,
        signing_key: &[u8],
    ) -> SignedTestnetV3GenesisReleaseApproval {
        let request = build_release_approval_request(
            &repository.root,
            &repository.candidate,
            &repository.authorities,
        )
        .expect("build request");
        let signature = pqsynq::Sign::mldsa87()
            .sign_ctx(
                &request.canonical_bytes().expect("canonical request"),
                signing_key,
                TESTNET_V3_GENESIS_RELEASE_APPROVAL_DOMAIN.as_bytes(),
            )
            .expect("sign test request");
        SignedTestnetV3GenesisReleaseApproval {
            schema_version: SCHEMA_VERSION,
            artifact_type: TESTNET_V3_GENESIS_RELEASE_APPROVAL_ARTIFACT_TYPE.to_string(),
            request,
            signature_base64: BASE64.encode(signature),
        }
    }

    #[test]
    fn signed_approval_verifies_only_against_the_frozen_governance_key() {
        let (public_key, signing_key) = pqsynq::Sign::mldsa87()
            .keygen()
            .expect("generate ML-DSA-87 test authority");
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
            &approval_path,
        )
        .expect("verify signed approval");

        assert_eq!(verified, approval.request);
    }

    #[test]
    fn approval_rejects_a_signature_from_an_unfrozen_key() {
        let (frozen_public_key, _) = pqsynq::Sign::mldsa87()
            .keygen()
            .expect("generate frozen ML-DSA-87 authority");
        let (_, attacker_key) = pqsynq::Sign::mldsa87()
            .keygen()
            .expect("generate untrusted ML-DSA-87 authority");
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
            &approval_path,
        )
        .expect_err("unfrozen signer must be rejected");

        assert!(error.contains("signature verification failed"));
    }

    #[test]
    fn approval_rejects_a_changed_candidate_before_signature_verification() {
        let (public_key, signing_key) = pqsynq::Sign::mldsa87()
            .keygen()
            .expect("generate ML-DSA-87 test authority");
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
            &approval_path,
        )
        .expect_err("changed candidate must be rejected");

        assert!(error.contains("does not exactly match the staged candidate"));
    }
}
