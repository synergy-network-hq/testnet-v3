//! Signed, immutable-Genesis consensus activation for Chain 1266 P1.
//!
//! The applied Genesis remains the canonical block-zero commitment.  This
//! module therefore does not reinterpret or rewrite Genesis.  Instead, the
//! existing Governance Authority signs a versioned activation record that is
//! bound to the already-authorized desired state, exact Genesis hash, release
//! artifacts, role configuration, validator set, and the height-one P1
//! coordinator/producer schedule.

use crate::consensus_parameters::ConsensusParameterRoot;
use crate::desired_state::{
    validate_chain1266_p1_consensus_binding, verify_signed_desired_state_file,
};
use crate::genesis::GenesisDocument;
use crate::synergy_types::{SYNERGY_TESTNET_V3_CHAIN_ID, TESTNET_V3_CHAIN_INCARNATION};
use base64::{engine::general_purpose, Engine as _};
use pqsynq::Sign;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

pub const CHAIN1266_CONSENSUS_ACTIVATION_SIGNATURE_DOMAIN: &str =
    "SYNERGY_CHAIN1266_CONSENSUS_ACTIVATION_V1";
pub const CONSENSUS_ACTIVATION_MANIFEST_ENV: &str = "SYNERGY_CONSENSUS_ACTIVATION_MANIFEST";
pub const CHAIN1266_P1_ACTIVATION_HEIGHT: u64 = 1;
const ACTIVATION_SCHEMA_VERSION: u32 = 1;
const ACTIVATION_ACTION: &str = "ACTIVATE_COORDINATED_ROUND_ROBIN";
const RELEASE_ARTIFACT_ROOT_DOMAIN: &str = "SYNERGY_CHAIN1266_RELEASE_ARTIFACT_ROOT_V1";
const CONFIGURATION_ROOT_DOMAIN: &str = "SYNERGY_CHAIN1266_CONFIGURATION_ROOT_V1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConsensusActivationManifest {
    pub schema_version: u32,
    pub action: String,
    pub release_id: String,
    pub chain_id: u64,
    pub chain_incarnation: u64,
    pub network_id: String,
    pub network_numeric_id: u64,
    pub genesis_hash: String,
    pub activation_height: u64,
    pub consensus_mode: String,
    pub coordinator_id: String,
    pub producer_ids: Vec<String>,
    pub producer_turn_timeout_ms: u64,
    pub validator_set_root: String,
    pub release_artifacts_sha256: String,
    pub configuration_sha256: String,
    pub desired_state_sha256: String,
    pub authority_public_key_fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConsensusActivationSignatureRequest {
    pub schema_version: u32,
    pub action: String,
    pub activation: ConsensusActivationManifest,
    pub signature_algorithm: String,
    pub signature_domain: String,
    pub authority_public_key_fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedConsensusActivationManifest {
    pub request: ConsensusActivationSignatureRequest,
    pub signature_base64: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedConsensusActivation {
    pub manifest: ConsensusActivationManifest,
    /// The exact SHA3-512 root carried in each P1 committed-block context.
    /// It covers all activation bindings but never changes Genesis.
    pub root: ConsensusParameterRoot,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DesiredStateActivationView {
    schema_version: u32,
    release_id: String,
    release_tag: String,
    chain: DesiredChainView,
    source: DesiredSourceView,
    state: DesiredConsensusStateView,
    start_authority: DesiredStartAuthorityView,
    artifacts: BTreeMap<String, String>,
    configuration: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DesiredChainView {
    chain_id: u64,
    incarnation: u64,
    genesis_hash: String,
    validator_set_root: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DesiredSourceView {
    testnet_v3_revision: String,
    synq_revision: String,
    aegis_revision: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DesiredConsensusStateView {
    consensus_schema_version: u32,
    directory_namespace: String,
    mode: String,
    coordinator_id: String,
    producer_ids: Vec<String>,
    producer_turn_timeout_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DesiredStartAuthorityView {
    signature_algorithm: String,
    signature_domain: String,
    public_key_fingerprint: String,
    public_key_base64: String,
}

#[derive(Debug, Clone)]
struct DesiredStateActivationBinding {
    release_id: String,
    chain_id: u64,
    chain_incarnation: u64,
    genesis_hash: String,
    validator_set_root: String,
    consensus_mode: String,
    coordinator_id: String,
    producer_ids: Vec<String>,
    producer_turn_timeout_ms: u64,
    release_artifacts_sha256: String,
    configuration_sha256: String,
    desired_state_sha256: String,
    authority_public_key_fingerprint: String,
    authority_public_key: Vec<u8>,
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn require_lower_hex(name: &str, value: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{name} is not canonical lowercase 32-byte hex"));
    }
    Ok(())
}

fn map_root(
    domain: &str,
    values: &BTreeMap<String, String>,
    label: &str,
) -> Result<String, String> {
    if values.is_empty() {
        return Err(format!("desired state omits {label} bindings"));
    }
    for (name, hash) in values {
        if name.trim().is_empty() {
            return Err(format!("desired state has an empty {label} binding name"));
        }
        require_lower_hex(&format!("{label} {name} SHA-256"), hash)?;
    }
    let encoded = serde_json::to_vec(values)
        .map_err(|error| format!("encode canonical {label} bindings: {error}"))?;
    let mut material = Vec::with_capacity(domain.len() + 1 + encoded.len());
    material.extend_from_slice(domain.as_bytes());
    material.push(0);
    material.extend_from_slice(&encoded);
    Ok(sha256_hex(&material))
}

fn network_id_from_genesis(genesis: &GenesisDocument) -> Result<String, String> {
    genesis
        .value()
        .get("network")
        .and_then(|network| network.get("network_slug"))
        .and_then(serde_json::Value::as_str)
        .filter(|network_id| !network_id.trim().is_empty())
        .map(ToString::to_string)
        .ok_or_else(|| "canonical Genesis omits network.network_slug".to_string())
}

fn parse_desired_state(bytes: &[u8]) -> Result<DesiredStateActivationView, String> {
    serde_json::from_slice(bytes)
        .map_err(|error| format!("parse strict desired state for consensus activation: {error}"))
}

fn binding_from_desired_state(
    desired: DesiredStateActivationView,
    desired_state_sha256: String,
) -> Result<DesiredStateActivationBinding, String> {
    // Fields that are not activation inputs remain present in the strict view
    // so a future desired-state schema cannot be silently accepted here.
    let _ = (
        desired.schema_version,
        desired.release_tag.as_str(),
        desired.source.testnet_v3_revision.as_str(),
        desired.source.synq_revision.as_str(),
        desired.source.aegis_revision.as_str(),
        desired.state.consensus_schema_version,
        desired.state.directory_namespace.as_str(),
    );
    validate_chain1266_p1_consensus_binding(
        &desired.state.mode,
        &desired.state.coordinator_id,
        &desired.state.producer_ids,
        desired.state.producer_turn_timeout_ms,
    )?;
    if desired.chain.chain_id != SYNERGY_TESTNET_V3_CHAIN_ID
        || desired.chain.incarnation != TESTNET_V3_CHAIN_INCARNATION
    {
        return Err("desired state is outside the Chain 1266 incarnation-4 domain".to_string());
    }
    require_lower_hex("desired-state genesis hash", &desired.chain.genesis_hash)?;
    require_lower_hex(
        "desired-state validator-set root",
        &desired.chain.validator_set_root,
    )?;
    let authority_public_key = general_purpose::STANDARD
        .decode(&desired.start_authority.public_key_base64)
        .map_err(|error| format!("decode desired-state Governance Authority key: {error}"))?;
    if desired.start_authority.signature_algorithm != "ML-DSA-87"
        || desired.start_authority.signature_domain
            != crate::consensus_start::CHAIN1266_START_SIGNATURE_DOMAIN
        || authority_public_key.len() != 2_592
        || format!("sha256:{}", sha256_hex(&authority_public_key))
            != desired.start_authority.public_key_fingerprint
    {
        return Err("desired state has an invalid Governance Authority binding".to_string());
    }
    Ok(DesiredStateActivationBinding {
        release_id: desired.release_id,
        chain_id: desired.chain.chain_id,
        chain_incarnation: desired.chain.incarnation,
        genesis_hash: desired.chain.genesis_hash,
        validator_set_root: desired.chain.validator_set_root,
        consensus_mode: desired.state.mode,
        coordinator_id: desired.state.coordinator_id,
        producer_ids: desired.state.producer_ids,
        producer_turn_timeout_ms: desired.state.producer_turn_timeout_ms,
        release_artifacts_sha256: map_root(
            RELEASE_ARTIFACT_ROOT_DOMAIN,
            &desired.artifacts,
            "release artifact",
        )?,
        configuration_sha256: map_root(
            CONFIGURATION_ROOT_DOMAIN,
            &desired.configuration,
            "configuration",
        )?,
        desired_state_sha256,
        authority_public_key_fingerprint: desired.start_authority.public_key_fingerprint,
        authority_public_key,
    })
}

fn expected_request(manifest: ConsensusActivationManifest) -> ConsensusActivationSignatureRequest {
    ConsensusActivationSignatureRequest {
        schema_version: ACTIVATION_SCHEMA_VERSION,
        action: ACTIVATION_ACTION.to_string(),
        authority_public_key_fingerprint: manifest.authority_public_key_fingerprint.clone(),
        activation: manifest,
        signature_algorithm: "ML-DSA-87".to_string(),
        signature_domain: CHAIN1266_CONSENSUS_ACTIVATION_SIGNATURE_DOMAIN.to_string(),
    }
}

fn validate_manifest(
    manifest: &ConsensusActivationManifest,
    desired: &DesiredStateActivationBinding,
    genesis: &GenesisDocument,
) -> Result<(), String> {
    if manifest.schema_version != ACTIVATION_SCHEMA_VERSION
        || manifest.action != ACTIVATION_ACTION
        || manifest.release_id != desired.release_id
        || manifest.chain_id != desired.chain_id
        || manifest.chain_incarnation != desired.chain_incarnation
        || manifest.network_id != network_id_from_genesis(genesis)?
        || manifest.network_numeric_id != genesis.network_id()
        || manifest.genesis_hash != desired.genesis_hash
        || manifest.genesis_hash != genesis.hash()
        || manifest.activation_height != CHAIN1266_P1_ACTIVATION_HEIGHT
        || manifest.validator_set_root != desired.validator_set_root
        || manifest.release_artifacts_sha256 != desired.release_artifacts_sha256
        || manifest.configuration_sha256 != desired.configuration_sha256
        || manifest.desired_state_sha256 != desired.desired_state_sha256
        || manifest.authority_public_key_fingerprint != desired.authority_public_key_fingerprint
    {
        return Err(
            "signed consensus activation disagrees with the immutable Genesis or signed desired state"
                .to_string(),
        );
    }
    require_lower_hex("consensus activation genesis hash", &manifest.genesis_hash)?;
    require_lower_hex(
        "consensus activation validator-set root",
        &manifest.validator_set_root,
    )?;
    require_lower_hex(
        "consensus activation release artifact root",
        &manifest.release_artifacts_sha256,
    )?;
    require_lower_hex(
        "consensus activation configuration root",
        &manifest.configuration_sha256,
    )?;
    require_lower_hex(
        "consensus activation desired-state digest",
        &manifest.desired_state_sha256,
    )?;
    validate_chain1266_p1_consensus_binding(
        &manifest.consensus_mode,
        &manifest.coordinator_id,
        &manifest.producer_ids,
        manifest.producer_turn_timeout_ms,
    )?;
    if genesis.consensus_version() != crate::synergy_types::POSY_PROTOCOL_VERSION {
        return Err(
            "consensus activation requires the immutable canonical PoSy Genesis; do not replace Genesis with a P1 variant"
                .to_string(),
        );
    }
    Ok(())
}

fn verified_from(
    signed: SignedConsensusActivationManifest,
    desired: DesiredStateActivationBinding,
    genesis: &GenesisDocument,
) -> Result<VerifiedConsensusActivation, String> {
    let expected = expected_request(signed.request.activation.clone());
    if signed.request != expected {
        return Err("consensus activation signature request is not canonical".to_string());
    }
    validate_manifest(&signed.request.activation, &desired, genesis)?;
    let signature = general_purpose::STANDARD
        .decode(&signed.signature_base64)
        .map_err(|error| format!("decode consensus activation ML-DSA-87 signature: {error}"))?;
    let canonical = serde_json::to_vec(&signed.request)
        .map_err(|error| format!("encode canonical consensus activation request: {error}"))?;
    let verified = Sign::mldsa87()
        .verify_ctx(
            &canonical,
            &signature,
            &desired.authority_public_key,
            CHAIN1266_CONSENSUS_ACTIVATION_SIGNATURE_DOMAIN.as_bytes(),
        )
        .map_err(|error| format!("verify consensus activation ML-DSA-87 signature: {error}"))?;
    if !verified {
        return Err("consensus activation ML-DSA-87 signature verification failed".to_string());
    }
    let root_bytes = serde_json::to_vec(&signed.request.activation)
        .map_err(|error| format!("encode canonical consensus activation manifest: {error}"))?;
    Ok(VerifiedConsensusActivation {
        manifest: signed.request.activation,
        root: ConsensusParameterRoot::from_canonical_manifest_bytes(&root_bytes),
    })
}

fn required_env_path(name: &str) -> Result<PathBuf, String> {
    env::var(name)
        .map(PathBuf::from)
        .map_err(|_| format!("{name} is required for coordinated P1 startup"))
}

/// Builds an unsigned activation record. The release controller must first
/// sign and verify the desired state, then use its existing custody signer to
/// sign this exact record. This function never reads a private key.
pub fn build_consensus_activation_manifest(
    desired_state_path: &Path,
    genesis: &GenesisDocument,
) -> Result<ConsensusActivationManifest, String> {
    let desired_bytes = fs::read(desired_state_path)
        .map_err(|error| format!("read desired state for activation: {error}"))?;
    let desired_hash = sha256_hex(&desired_bytes);
    let desired = binding_from_desired_state(parse_desired_state(&desired_bytes)?, desired_hash)?;
    let manifest = ConsensusActivationManifest {
        schema_version: ACTIVATION_SCHEMA_VERSION,
        action: ACTIVATION_ACTION.to_string(),
        release_id: desired.release_id.clone(),
        chain_id: desired.chain_id,
        chain_incarnation: desired.chain_incarnation,
        network_id: network_id_from_genesis(genesis)?,
        network_numeric_id: genesis.network_id(),
        genesis_hash: desired.genesis_hash.clone(),
        activation_height: CHAIN1266_P1_ACTIVATION_HEIGHT,
        consensus_mode: desired.consensus_mode.clone(),
        coordinator_id: desired.coordinator_id.clone(),
        producer_ids: desired.producer_ids.clone(),
        producer_turn_timeout_ms: desired.producer_turn_timeout_ms,
        validator_set_root: desired.validator_set_root.clone(),
        release_artifacts_sha256: desired.release_artifacts_sha256.clone(),
        configuration_sha256: desired.configuration_sha256.clone(),
        desired_state_sha256: desired.desired_state_sha256.clone(),
        authority_public_key_fingerprint: desired.authority_public_key_fingerprint.clone(),
    };
    validate_manifest(&manifest, &desired, genesis)?;
    Ok(manifest)
}

pub fn consensus_activation_signature_request(
    manifest: ConsensusActivationManifest,
) -> ConsensusActivationSignatureRequest {
    expected_request(manifest)
}

pub fn verify_signed_consensus_activation_file(
    activation_path: &Path,
    desired_state_path: &Path,
    desired_state_signature_path: &Path,
    genesis: &GenesisDocument,
) -> Result<VerifiedConsensusActivation, String> {
    // This verifies the exact existing desired-state authorization before its
    // public authority can be used to validate the second, narrower release
    // record. A copied public key is never sufficient.
    verify_signed_desired_state_file(desired_state_path, desired_state_signature_path)?;
    let desired_bytes = fs::read(desired_state_path)
        .map_err(|error| format!("read desired state for activation verification: {error}"))?;
    let desired = binding_from_desired_state(
        parse_desired_state(&desired_bytes)?,
        sha256_hex(&desired_bytes),
    )?;
    let activation_bytes = fs::read(activation_path)
        .map_err(|error| format!("read signed consensus activation: {error}"))?;
    let signed: SignedConsensusActivationManifest = serde_json::from_slice(&activation_bytes)
        .map_err(|error| format!("parse strict signed consensus activation: {error}"))?;
    verified_from(signed, desired, genesis)
}

/// Loads the two authorization files installed beside a P1 release. The
/// runtime calls this before it creates a signer, state store, or mailbox.
pub fn load_installed_consensus_activation(
    genesis: &GenesisDocument,
) -> Result<VerifiedConsensusActivation, String> {
    let activation_path = required_env_path(CONSENSUS_ACTIVATION_MANIFEST_ENV)?;
    let desired_path = required_env_path(crate::desired_state::DESIRED_STATE_ENV)?;
    let desired_signature_path =
        required_env_path(crate::desired_state::DESIRED_STATE_SIGNATURE_ENV)?;
    verify_signed_consensus_activation_file(
        &activation_path,
        &desired_path,
        &desired_signature_path,
        genesis,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pqc::{PQCAlgorithm, PQCManager};
    use crate::genesis::load_genesis_from_path_for_test;

    fn binding(public_key: Vec<u8>, genesis_hash: String) -> DesiredStateActivationBinding {
        DesiredStateActivationBinding {
            release_id: "chain1266-incarnation-4-rc1".to_string(),
            chain_id: 1266,
            chain_incarnation: 4,
            genesis_hash,
            validator_set_root: "22".repeat(32),
            consensus_mode: crate::desired_state::CHAIN1266_P1_CONSENSUS_MODE.to_string(),
            coordinator_id: crate::desired_state::CHAIN1266_P1_COORDINATOR_ID.to_string(),
            producer_ids: [
                "validator-2",
                "validator-3",
                "validator-4",
                "validator-5",
                "validator-6",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            producer_turn_timeout_ms: crate::desired_state::CHAIN1266_P1_PRODUCER_TURN_TIMEOUT_MS,
            release_artifacts_sha256: "33".repeat(32),
            configuration_sha256: "44".repeat(32),
            desired_state_sha256: "55".repeat(32),
            authority_public_key_fingerprint: format!("sha256:{}", sha256_hex(&public_key)),
            authority_public_key: public_key,
        }
    }

    #[test]
    fn signed_activation_binds_height_one_and_exact_producer_rotation() {
        let mut manager = PQCManager::new();
        let (public, private) = manager
            .generate_keypair(PQCAlgorithm::MLDSA87)
            .expect("generate activation test authority");
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let genesis =
            load_genesis_from_path_for_test(root.join("genesis.testnet-v3.identity-assigned.json"))
                .expect("load canonical immutable Genesis");
        let desired = binding(public.key_data, genesis.hash().to_string());
        let manifest = ConsensusActivationManifest {
            schema_version: ACTIVATION_SCHEMA_VERSION,
            action: ACTIVATION_ACTION.to_string(),
            release_id: desired.release_id.clone(),
            chain_id: 1266,
            chain_incarnation: 4,
            network_id: "synergy-testnet-v3".to_string(),
            network_numeric_id: genesis.network_id(),
            genesis_hash: desired.genesis_hash.clone(),
            activation_height: CHAIN1266_P1_ACTIVATION_HEIGHT,
            consensus_mode: desired.consensus_mode.clone(),
            coordinator_id: desired.coordinator_id.clone(),
            producer_ids: desired.producer_ids.clone(),
            producer_turn_timeout_ms: desired.producer_turn_timeout_ms,
            validator_set_root: desired.validator_set_root.clone(),
            release_artifacts_sha256: desired.release_artifacts_sha256.clone(),
            configuration_sha256: desired.configuration_sha256.clone(),
            desired_state_sha256: desired.desired_state_sha256.clone(),
            authority_public_key_fingerprint: desired.authority_public_key_fingerprint.clone(),
        };
        let request = consensus_activation_signature_request(manifest.clone());
        let signature = Sign::mldsa87()
            .sign_ctx(
                &serde_json::to_vec(&request).expect("encode activation request"),
                &private.key_data,
                CHAIN1266_CONSENSUS_ACTIVATION_SIGNATURE_DOMAIN.as_bytes(),
            )
            .expect("sign activation request");
        let signed = SignedConsensusActivationManifest {
            request,
            signature_base64: general_purpose::STANDARD.encode(signature),
        };
        let verified = verified_from(signed.clone(), desired.clone(), &genesis)
            .expect("valid signed immutable-Genesis P1 activation");
        assert_eq!(verified.manifest.activation_height, 1);
        assert!(!verified.root.is_zero());
        let mut altered = signed.clone();
        altered.request.activation.producer_ids.swap(0, 1);
        altered.signature_base64 = general_purpose::STANDARD.encode(
            Sign::mldsa87()
                .sign_ctx(
                    &serde_json::to_vec(&altered.request)
                        .expect("encode malformed activation request"),
                    &private.key_data,
                    CHAIN1266_CONSENSUS_ACTIVATION_SIGNATURE_DOMAIN.as_bytes(),
                )
                .expect("sign malformed activation request"),
        );
        assert!(verified_from(altered, desired, &genesis).is_err());
        assert_eq!(signed.request.activation, manifest);
    }

    #[test]
    fn activation_requires_immutable_posy_genesis_not_a_rewritten_p1_genesis() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let genesis =
            load_genesis_from_path_for_test(root.join("genesis.testnet-v3.identity-assigned.json"))
                .expect("load canonical immutable Genesis");
        assert_eq!(
            genesis.consensus_version(),
            crate::synergy_types::POSY_PROTOCOL_VERSION
        );
    }
}
