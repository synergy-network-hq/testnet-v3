//! Fail-closed Chain 1266 desired-state binding.
//!
//! The release controller verifies the signed release-tag provenance and
//! GitHub artifact attestation before installing this manifest.  Every role
//! process then independently verifies the installed manifest digest and all
//! local release inputs before it can open consensus or observer state.

use crate::consensus::simplified_posy::load_genesis_bound_simplified_activation;
use crate::consensus::testnet_v3_bootstrap::load_testnet_v3_genesis_bootstrap;
use crate::genesis::canonical_genesis;
use crate::posy_simplified_parameters::{
    POSY_SIMPLIFIED_CHAIN_INCARNATION, POSY_SIMPLIFIED_CONSENSUS_STATE_SCHEMA_VERSION,
};
use crate::role_profiles::RoleProfile;
use crate::synergy_types::{
    Epoch, SYNERGY_TESTNET_V3_CHAIN_ID, TESTNET_V3_CHAIN_INCARNATION,
    TESTNET_V3_CONSENSUS_STATE_SCHEMA_VERSION,
};
use base64::{engine::general_purpose, Engine as _};
use pqsynq::Sign;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
#[cfg(not(test))]
use std::sync::OnceLock;

pub const DESIRED_STATE_ENV: &str = "SYNERGY_DESIRED_STATE_MANIFEST";
pub const DESIRED_STATE_SHA256_ENV: &str = "SYNERGY_DESIRED_STATE_MANIFEST_SHA256";
pub const DESIRED_STATE_SIGNATURE_ENV: &str = "SYNERGY_DESIRED_STATE_SIGNATURE";
pub const CHAIN1266_DESIRED_STATE_SIGNATURE_DOMAIN: &str = "SYNERGY_CHAIN1266_DESIRED_STATE_V1";
pub const CHAIN1266_QUALIFICATION_MODE_ENV: &str = "SYNERGY_CHAIN1266_QUALIFICATION_MODE";
const PRODUCTION_GOVERNANCE_FINGERPRINT: &str =
    "sha256:7f296c61ad8c636dd21eb8c3dd360e981ba720cdef1b2a7e84f3c1107f6eb200";
const EXPECTED_SCHEMA_VERSION: u32 = 1;
pub const CHAIN1266_P1_CONSENSUS_MODE: &str = "coordinated_round_robin_v1";
pub const CHAIN1266_P1_COORDINATOR_ID: &str = "validator-1";
pub const CHAIN1266_P1_PRODUCER_IDS: [&str; 5] = [
    "validator-2",
    "validator-3",
    "validator-4",
    "validator-5",
    "validator-6",
];
pub const CHAIN1266_P1_PRODUCER_TURN_TIMEOUT_MS: u64 = 4_000;
pub const CHAIN1266_P3_CONSENSUS_MODE: &str = "posy_simplified_v3";
pub const CHAIN1266_P3_CONSENSUS_ALGORITHM: &str = "posy/3.0";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DesiredStateManifest {
    schema_version: u32,
    release_id: String,
    release_tag: String,
    chain: DesiredChain,
    source: DesiredSource,
    state: DesiredConsensusState,
    start_authority: DesiredStartAuthority,
    artifacts: BTreeMap<String, String>,
    configuration: BTreeMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DesiredChain {
    chain_id: u64,
    incarnation: u64,
    genesis_hash: String,
    validator_set_root: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DesiredSource {
    testnet_v3_revision: String,
    synq_revision: String,
    aegis_revision: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DesiredConsensusState {
    consensus_schema_version: u32,
    directory_namespace: String,
    mode: String,
    coordinator_id: String,
    producer_ids: Vec<String>,
    producer_turn_timeout_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DesiredStartAuthority {
    signature_algorithm: String,
    signature_domain: String,
    public_key_fingerprint: String,
    public_key_base64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DesiredStateSignatureRequest {
    pub schema_version: u32,
    pub action: String,
    pub release_id: String,
    pub chain_id: u64,
    pub chain_incarnation: u64,
    pub genesis_hash: String,
    pub desired_state_sha256: String,
    pub signature_algorithm: String,
    pub signature_domain: String,
    pub authority_public_key_fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedDesiredStateManifest {
    pub request: DesiredStateSignatureRequest,
    pub signature_base64: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDesiredStateIdentity {
    pub release_id: String,
    pub node_id: String,
    pub role_profile: String,
    pub chain_id: u64,
    pub chain_incarnation: u64,
    pub genesis_hash: String,
    pub validator_set_root: String,
    pub consensus_state_schema_version: u32,
    pub directory_namespace: String,
    pub testnet_v3_revision: String,
    pub synq_revision: String,
    pub aegis_revision: String,
    pub binary_sha256: String,
    pub configuration_sha256: String,
    pub desired_state_sha256: String,
    pub desired_state_signature_sha256: String,
    pub state_root: String,
}

#[cfg(not(test))]
static VERIFIED_DESIRED_STATE: OnceLock<VerifiedDesiredStateIdentity> = OnceLock::new();

pub fn verified_desired_state_identity() -> Option<VerifiedDesiredStateIdentity> {
    #[cfg(not(test))]
    {
        VERIFIED_DESIRED_STATE.get().cloned()
    }
    #[cfg(test)]
    {
        None
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    Ok(sha256_bytes(&bytes))
}

fn required_lower_hex(name: &str, value: &str, bytes: usize) -> Result<(), String> {
    if value.len() != bytes.saturating_mul(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "{name} is not canonical lowercase {bytes}-byte hex"
        ));
    }
    Ok(())
}

fn required_source_revision(name: &str, value: &str) -> Result<(), String> {
    required_lower_hex(name, value, 20)?;
    if value.bytes().all(|byte| byte == b'0') {
        return Err(format!("{name} must not be the all-zero Git revision"));
    }
    Ok(())
}

/// Rejects every consensus profile except the exact, temporary Chain 1266 P1
/// coordinator and producer rotation.  The desired-state signature covers the
/// serialized manifest digest, so these values cannot drift after signing.
pub fn validate_chain1266_p1_consensus_binding(
    mode: &str,
    coordinator_id: &str,
    producer_ids: &[String],
    producer_turn_timeout_ms: u64,
) -> Result<(), String> {
    if mode != CHAIN1266_P1_CONSENSUS_MODE
        || coordinator_id != CHAIN1266_P1_COORDINATOR_ID
        || producer_turn_timeout_ms != CHAIN1266_P1_PRODUCER_TURN_TIMEOUT_MS
        || producer_ids.len() != CHAIN1266_P1_PRODUCER_IDS.len()
        || producer_ids
            .iter()
            .map(String::as_str)
            .ne(CHAIN1266_P1_PRODUCER_IDS)
    {
        return Err(
            "desired-state consensus binding is not the canonical Chain 1266 P1 coordinated round-robin profile"
                .to_string(),
        );
    }
    Ok(())
}

fn validate_desired_state_p1_consensus(state: &DesiredConsensusState) -> Result<(), String> {
    validate_chain1266_p1_consensus_binding(
        &state.mode,
        &state.coordinator_id,
        &state.producer_ids,
        state.producer_turn_timeout_ms,
    )
}

/// Accepts exactly one of the two signed Chain-1266 release profiles.  P1 is
/// retained only so already-issued coordinated releases remain independently
/// verifiable.  Fresh P3 releases have no coordinator, producer ring, or
/// locally configurable producer timeout; all voting authority comes from the
/// Genesis-bound simplified activation.
fn validate_desired_state_consensus(state: &DesiredConsensusState) -> Result<(), String> {
    match state.mode.as_str() {
        CHAIN1266_P1_CONSENSUS_MODE => validate_desired_state_p1_consensus(state),
        CHAIN1266_P3_CONSENSUS_MODE => {
            if !state.coordinator_id.is_empty()
                || !state.producer_ids.is_empty()
                || state.producer_turn_timeout_ms != 0
            {
                return Err(
                    "fresh P3 desired state must not carry a coordinator, producer ring, or producer-turn timeout"
                        .to_string(),
                );
            }
            Ok(())
        }
        mode => Err(format!(
            "desired-state consensus mode {mode} is neither the isolated P1 profile nor fresh P3"
        )),
    }
}

fn expected_chain_profile(state: &DesiredConsensusState) -> Result<(u64, u32, String), String> {
    match state.mode.as_str() {
        CHAIN1266_P1_CONSENSUS_MODE => Ok((
            TESTNET_V3_CHAIN_INCARNATION,
            TESTNET_V3_CONSENSUS_STATE_SCHEMA_VERSION,
            format!(
                "chain-{SYNERGY_TESTNET_V3_CHAIN_ID}/incarnation-{TESTNET_V3_CHAIN_INCARNATION}"
            ),
        )),
        CHAIN1266_P3_CONSENSUS_MODE => Ok((
            POSY_SIMPLIFIED_CHAIN_INCARNATION,
            POSY_SIMPLIFIED_CONSENSUS_STATE_SCHEMA_VERSION,
            format!(
                "chain-{SYNERGY_TESTNET_V3_CHAIN_ID}/incarnation-{POSY_SIMPLIFIED_CHAIN_INCARNATION}"
            ),
        )),
        mode => Err(format!("unsupported desired-state consensus mode {mode}")),
    }
}

fn compiled_revision(name: &str, value: Option<&'static str>) -> Result<&'static str, String> {
    value
        .filter(|revision| !revision.trim().is_empty())
        .ok_or_else(|| format!("release binary omits compiled {name} revision"))
}

fn configured_manifest_path() -> Result<PathBuf, String> {
    env::var(DESIRED_STATE_ENV)
        .map(PathBuf::from)
        .map_err(|_| format!("{DESIRED_STATE_ENV} is required for Chain 1266 startup"))
}

fn configured_manifest_sha256() -> Result<String, String> {
    env::var(DESIRED_STATE_SHA256_ENV)
        .map_err(|_| format!("{DESIRED_STATE_SHA256_ENV} is required for Chain 1266 startup"))
}

fn configured_manifest_signature_path() -> Result<PathBuf, String> {
    env::var(DESIRED_STATE_SIGNATURE_ENV)
        .map(PathBuf::from)
        .map_err(|_| format!("{DESIRED_STATE_SIGNATURE_ENV} is required for Chain 1266 startup"))
}

fn state_root_matches_namespace(
    state_root: &Path,
    qualification_mode: bool,
    production_namespace: &str,
) -> bool {
    if !state_root.is_absolute()
        || state_root
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
        || state_root.file_name().and_then(|value| value.to_str()) != Some("data")
    {
        return false;
    }
    if qualification_mode {
        let qualification_root = Path::new("/var/lib/synergy/chain1266-qualification");
        let Ok(relative) = state_root.strip_prefix(qualification_root) else {
            return false;
        };
        // Require a run and a role below the dedicated root, rather than
        // accepting the root itself or a path that could overlap production.
        return relative.components().count() == 3;
    }
    state_root
        .parent()
        .is_some_and(|parent| parent.ends_with(Path::new(production_namespace)))
}

fn verify_desired_state_signature(
    manifest: &DesiredStateManifest,
    manifest_sha256: &str,
    signature_bytes: &[u8],
) -> Result<(), String> {
    let signed: SignedDesiredStateManifest = serde_json::from_slice(signature_bytes)
        .map_err(|error| format!("parse strict signed desired-state manifest: {error}"))?;
    let expected = DesiredStateSignatureRequest {
        schema_version: 1,
        action: "AUTHORIZE_DESIRED_STATE".to_string(),
        release_id: manifest.release_id.clone(),
        chain_id: manifest.chain.chain_id,
        chain_incarnation: manifest.chain.incarnation,
        genesis_hash: manifest.chain.genesis_hash.clone(),
        desired_state_sha256: manifest_sha256.to_string(),
        signature_algorithm: "ML-DSA-87".to_string(),
        signature_domain: CHAIN1266_DESIRED_STATE_SIGNATURE_DOMAIN.to_string(),
        authority_public_key_fingerprint: manifest.start_authority.public_key_fingerprint.clone(),
    };
    if signed.request != expected {
        return Err("signed desired-state request disagrees with the local manifest".to_string());
    }
    let public_key = general_purpose::STANDARD
        .decode(&manifest.start_authority.public_key_base64)
        .map_err(|error| format!("decode desired-state signing public key: {error}"))?;
    let signature = general_purpose::STANDARD
        .decode(&signed.signature_base64)
        .map_err(|error| format!("decode desired-state ML-DSA-87 signature: {error}"))?;
    let canonical = serde_json::to_vec(&signed.request)
        .map_err(|error| format!("encode canonical desired-state authorization: {error}"))?;
    let verified = Sign::mldsa87()
        .verify_ctx(
            &canonical,
            &signature,
            &public_key,
            CHAIN1266_DESIRED_STATE_SIGNATURE_DOMAIN.as_bytes(),
        )
        .map_err(|error| format!("verify desired-state ML-DSA-87 signature: {error}"))?;
    if !verified {
        return Err("desired-state ML-DSA-87 signature verification failed".to_string());
    }
    Ok(())
}

pub fn verify_signed_desired_state_file(
    manifest_path: &Path,
    signature_path: &Path,
) -> Result<DesiredStateSignatureRequest, String> {
    let manifest_bytes =
        fs::read(manifest_path).map_err(|error| format!("read desired-state manifest: {error}"))?;
    let signature_bytes = fs::read(signature_path)
        .map_err(|error| format!("read desired-state signature: {error}"))?;
    let manifest: DesiredStateManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("parse strict desired-state manifest: {error}"))?;
    validate_desired_state_consensus(&manifest.state)?;
    let (expected_incarnation, expected_consensus_schema, expected_namespace) =
        expected_chain_profile(&manifest.state)?;
    if manifest.schema_version != EXPECTED_SCHEMA_VERSION
        || manifest.chain.chain_id != SYNERGY_TESTNET_V3_CHAIN_ID
        || manifest.chain.incarnation != expected_incarnation
        || manifest.state.consensus_schema_version != expected_consensus_schema
        || manifest.state.directory_namespace != expected_namespace
        || manifest.start_authority.public_key_fingerprint != PRODUCTION_GOVERNANCE_FINGERPRINT
    {
        return Err(
            "signed desired state is outside its production Chain 1266 consensus profile"
                .to_string(),
        );
    }
    if manifest.start_authority.signature_algorithm != "ML-DSA-87"
        || manifest.start_authority.signature_domain
            != crate::consensus_start::CHAIN1266_START_SIGNATURE_DOMAIN
    {
        return Err(
            "signed desired state uses an unsupported Governance Authority profile".to_string(),
        );
    }
    let governance_public_key = general_purpose::STANDARD
        .decode(&manifest.start_authority.public_key_base64)
        .map_err(|error| format!("decode Governance Authority public key: {error}"))?;
    if governance_public_key.len() != 2_592 {
        return Err("Governance Authority public key is not ML-DSA-87".to_string());
    }
    if format!("sha256:{}", sha256_bytes(&governance_public_key))
        != manifest.start_authority.public_key_fingerprint
    {
        return Err("Governance Authority public key fingerprint mismatch".to_string());
    }
    let manifest_sha256 = sha256_bytes(&manifest_bytes);
    verify_desired_state_signature(&manifest, &manifest_sha256, &signature_bytes)?;
    let signed: SignedDesiredStateManifest = serde_json::from_slice(&signature_bytes)
        .map_err(|error| format!("parse strict signed desired-state manifest: {error}"))?;
    Ok(signed.request)
}

/// Verifies every local release input before any role opens chain-derived
/// state. The role-specific config path is the exact file passed to `start`;
/// hashing a deserialized structure would hide byte-level drift.
pub fn verify_chain1266_desired_state(
    profile: &RoleProfile,
    node_id: &str,
    config_path: &Path,
) -> Result<String, String> {
    let manifest_path = configured_manifest_path()?;
    let manifest_bytes = fs::read(&manifest_path)
        .map_err(|error| format!("read desired state {}: {error}", manifest_path.display()))?;
    let manifest_sha256 = sha256_bytes(&manifest_bytes);
    let expected_manifest_sha256 = configured_manifest_sha256()?;
    required_lower_hex(DESIRED_STATE_SHA256_ENV, &expected_manifest_sha256, 32)?;
    if manifest_sha256 != expected_manifest_sha256 {
        return Err(format!(
            "desired-state manifest hash mismatch: expected {expected_manifest_sha256}, found {manifest_sha256}"
        ));
    }

    let manifest: DesiredStateManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("parse strict desired-state manifest: {error}"))?;
    if manifest.schema_version != EXPECTED_SCHEMA_VERSION {
        return Err(format!(
            "desired-state schema mismatch: expected {EXPECTED_SCHEMA_VERSION}, found {}",
            manifest.schema_version
        ));
    }
    validate_desired_state_consensus(&manifest.state)?;
    let (expected_incarnation, expected_consensus_schema, expected_namespace) =
        expected_chain_profile(&manifest.state)?;
    let release_prefix = format!("chain1266-incarnation-{expected_incarnation}-");
    let release_sequence = manifest
        .release_id
        .strip_prefix(&release_prefix)
        .ok_or_else(|| {
            format!("desired-state release ID is outside incarnation {expected_incarnation}")
        })?;
    let tag_sequence = manifest
        .release_tag
        .strip_prefix("chain1266-v20.0.0-")
        .ok_or_else(|| "desired-state release tag is outside Chain 1266 v20.0.0".to_string())?
        .replace('.', "");
    if release_sequence.is_empty() || release_sequence != tag_sequence {
        return Err("desired-state release ID/tag binding is invalid".to_string());
    }
    if manifest.chain.chain_id != SYNERGY_TESTNET_V3_CHAIN_ID
        || manifest.chain.incarnation != expected_incarnation
    {
        return Err("desired-state Chain 1266 domain is invalid".to_string());
    }
    if manifest.state.consensus_schema_version != expected_consensus_schema
        || manifest.state.directory_namespace != expected_namespace
    {
        return Err("desired-state consensus schema or state namespace is invalid".to_string());
    }
    let qualification_mode = env::var(CHAIN1266_QUALIFICATION_MODE_ENV).as_deref() == Ok("1");
    let state_root = env::var("SYNERGY_DATA_PATH")
        .map(PathBuf::from)
        .map_err(|_| "SYNERGY_DATA_PATH is required for incarnation-isolated state".to_string())?;
    if !state_root_matches_namespace(
        &state_root,
        qualification_mode,
        &manifest.state.directory_namespace,
    ) {
        return Err(format!(
            "state root is outside the required Chain 1266 namespace {}",
            manifest.state.directory_namespace,
        ));
    }
    if manifest.start_authority.signature_algorithm != "ML-DSA-87"
        || manifest.start_authority.signature_domain
            != crate::consensus_start::CHAIN1266_START_SIGNATURE_DOMAIN
    {
        return Err(
            "desired-state start authority uses an unsupported signature profile".to_string(),
        );
    }
    let start_public_key = general_purpose::STANDARD
        .decode(&manifest.start_authority.public_key_base64)
        .map_err(|error| format!("decode desired-state start authority public key: {error}"))?;
    if start_public_key.len() != 2_592 {
        return Err("desired-state start authority is not an ML-DSA-87 public key".to_string());
    }
    let start_fingerprint = format!("sha256:{}", sha256_bytes(&start_public_key));
    if start_fingerprint != manifest.start_authority.public_key_fingerprint {
        return Err("desired-state start authority fingerprint mismatch".to_string());
    }
    let signature_path = configured_manifest_signature_path()?;
    let signature_bytes = fs::read(&signature_path).map_err(|error| {
        format!(
            "read signed desired state {}: {error}",
            signature_path.display()
        )
    })?;
    verify_desired_state_signature(&manifest, &manifest_sha256, &signature_bytes)?;

    let genesis = canonical_genesis()?;
    let private_qualification = qualification_mode
        && genesis
            .value()
            .get("env")
            .and_then(serde_json::Value::as_str)
            == Some("chain1266-private-qualification");
    if qualification_mode != private_qualification {
        return Err("qualification mode requires the private qualification Genesis".to_string());
    }
    if !private_qualification
        && manifest.start_authority.public_key_fingerprint != PRODUCTION_GOVERNANCE_FINGERPRINT
    {
        return Err(
            "production desired state is not signed by the frozen Governance Authority".to_string(),
        );
    }
    if genesis.chain_id() != manifest.chain.chain_id
        || genesis.chain_incarnation() != manifest.chain.incarnation
        || genesis.consensus_state_schema_version() != manifest.state.consensus_schema_version
        || genesis.hash() != manifest.chain.genesis_hash
    {
        return Err("local Genesis disagrees with desired state".to_string());
    }
    required_lower_hex("chain.genesis_hash", &manifest.chain.genesis_hash, 32)?;

    let active_root = if manifest.state.mode == CHAIN1266_P3_CONSENSUS_MODE {
        load_genesis_bound_simplified_activation(genesis.value())?
            .ok_or_else(|| {
                "fresh P3 desired state requires a Genesis-bound simplified activation".to_string()
            })?
            .frozen_validator_set
            .active_for_epoch(Epoch(0))
            .hash()?
            .to_hex()
    } else {
        load_testnet_v3_genesis_bootstrap(genesis)?
            .validator_set
            .active_for_epoch(Epoch(0))
            .hash()?
            .to_hex()
    };
    if active_root != manifest.chain.validator_set_root {
        return Err(format!(
            "active validator-set root mismatch: expected {}, found {active_root}",
            manifest.chain.validator_set_root
        ));
    }
    if manifest.state.mode == CHAIN1266_P3_CONSENSUS_MODE {
        let activation =
            load_genesis_bound_simplified_activation(genesis.value())?.ok_or_else(|| {
                "fresh P3 desired state requires a Genesis-bound simplified activation".to_string()
            })?;
        let active_set = activation.frozen_validator_set.active_for_epoch(Epoch(0));
        if active_set.validators.is_empty() {
            return Err(
                "fresh P3 desired state has no active validator in its Genesis activation"
                    .to_string(),
            );
        }
        if active_set.hash()?.to_hex() != manifest.chain.validator_set_root {
            return Err(
                "fresh P3 desired-state validator root differs from its Genesis activation"
                    .to_string(),
            );
        }
    }

    for (name, revision) in [
        (
            "source.testnet_v3_revision",
            &manifest.source.testnet_v3_revision,
        ),
        ("source.synq_revision", &manifest.source.synq_revision),
        ("source.aegis_revision", &manifest.source.aegis_revision),
    ] {
        required_source_revision(name, revision)?;
    }
    let compiled_testnet = compiled_revision(
        "Testnet-v3",
        option_env!("SYNERGY_TESTNET_V3_SOURCE_REVISION"),
    )?;
    let compiled_synq = compiled_revision("SynQ", option_env!("SYNERGY_SYNQ_SOURCE_REVISION"))?;
    let compiled_aegis = compiled_revision("Aegis", option_env!("SYNERGY_AEGIS_SOURCE_REVISION"))?;
    if compiled_testnet != manifest.source.testnet_v3_revision
        || compiled_synq != manifest.source.synq_revision
        || compiled_aegis != manifest.source.aegis_revision
    {
        return Err("compiled source revisions disagree with desired state".to_string());
    }

    let role_key = profile.compiled_profile;
    let expected_binary = manifest
        .artifacts
        .get(role_key)
        .ok_or_else(|| format!("desired state omits {role_key} artifact hash"))?;
    required_lower_hex("role artifact SHA-256", expected_binary, 32)?;
    let executable = env::current_exe()
        .map_err(|error| format!("resolve current release executable: {error}"))?;
    let actual_binary = sha256_file(&executable)?;
    if &actual_binary != expected_binary {
        return Err(format!(
            "{role_key} binary hash mismatch: expected {expected_binary}, found {actual_binary}"
        ));
    }

    let node_id = node_id.trim();
    if node_id.is_empty() {
        return Err("local node identity is empty".to_string());
    }
    let expected_config = manifest
        .configuration
        .get(node_id)
        .ok_or_else(|| format!("desired state omits {node_id} configuration hash"))?;
    required_lower_hex("role configuration SHA-256", expected_config, 32)?;
    let actual_config = sha256_file(config_path)?;
    if &actual_config != expected_config {
        return Err(format!(
            "{node_id} configuration hash mismatch: expected {expected_config}, found {actual_config}"
        ));
    }

    let identity = VerifiedDesiredStateIdentity {
        release_id: manifest.release_id.clone(),
        node_id: node_id.to_string(),
        role_profile: role_key.to_string(),
        chain_id: manifest.chain.chain_id,
        chain_incarnation: manifest.chain.incarnation,
        genesis_hash: manifest.chain.genesis_hash.clone(),
        validator_set_root: manifest.chain.validator_set_root.clone(),
        consensus_state_schema_version: manifest.state.consensus_schema_version,
        directory_namespace: manifest.state.directory_namespace.clone(),
        testnet_v3_revision: manifest.source.testnet_v3_revision.clone(),
        synq_revision: manifest.source.synq_revision.clone(),
        aegis_revision: manifest.source.aegis_revision.clone(),
        binary_sha256: actual_binary,
        configuration_sha256: actual_config,
        desired_state_sha256: manifest_sha256,
        desired_state_signature_sha256: sha256_bytes(&signature_bytes),
        state_root: state_root.display().to_string(),
    };
    #[cfg(not(test))]
    if let Some(installed) = VERIFIED_DESIRED_STATE.get() {
        if installed != &identity {
            return Err(
                "process attempted to install two different verified desired states".to_string(),
            );
        }
    } else if VERIFIED_DESIRED_STATE.set(identity).is_err() {
        return Err("failed to install verified desired-state identity".to_string());
    }

    Ok(manifest.release_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pqc::{PQCAlgorithm, PQCManager};

    #[test]
    fn qualification_state_namespace_is_separate_and_cannot_escape() {
        assert!(state_root_matches_namespace(
            Path::new("/var/lib/synergy/chain1266-qualification/run-1/validator-node-01/data"),
            true,
            "chain-1266/incarnation-4",
        ));
        assert!(!state_root_matches_namespace(
            Path::new("/var/lib/synergy/chain1266-qualification/data"),
            true,
            "chain-1266/incarnation-4",
        ));
        assert!(!state_root_matches_namespace(
            Path::new("/var/lib/synergy/chain1266-qualification/run-1/validator-node-01/../../incarnation-4/data"),
            true,
            "chain-1266/incarnation-4",
        ));
        assert!(!state_root_matches_namespace(
            Path::new("/var/lib/synergy/validator/chain-1266/incarnation-4/data"),
            true,
            "chain-1266/incarnation-4",
        ));
        assert!(state_root_matches_namespace(
            Path::new("/var/lib/synergy/validator/chain-1266/incarnation-4/data"),
            false,
            "chain-1266/incarnation-4",
        ));
    }

    #[test]
    fn p1_consensus_binding_rejects_legacy_posy_mode() {
        let producers = CHAIN1266_P1_PRODUCER_IDS
            .iter()
            .map(|producer| (*producer).to_string())
            .collect::<Vec<_>>();
        let error = validate_chain1266_p1_consensus_binding(
            "posy_v2_2",
            CHAIN1266_P1_COORDINATOR_ID,
            &producers,
            CHAIN1266_P1_PRODUCER_TURN_TIMEOUT_MS,
        )
        .expect_err("legacy PoSy must not be authorized in desired state");
        assert!(error.contains("canonical Chain 1266 P1"), "{error}");
    }

    #[test]
    fn p1_consensus_binding_rejects_reordered_producers() {
        let mut producers = CHAIN1266_P1_PRODUCER_IDS
            .iter()
            .map(|producer| (*producer).to_string())
            .collect::<Vec<_>>();
        producers.swap(0, 1);
        let error = validate_chain1266_p1_consensus_binding(
            CHAIN1266_P1_CONSENSUS_MODE,
            CHAIN1266_P1_COORDINATOR_ID,
            &producers,
            CHAIN1266_P1_PRODUCER_TURN_TIMEOUT_MS,
        )
        .expect_err("producer order must be bound by desired state");
        assert!(error.contains("canonical Chain 1266 P1"), "{error}");
    }

    #[test]
    fn p3_desired_state_rejects_every_local_authority_field() {
        let canonical = DesiredConsensusState {
            consensus_schema_version: POSY_SIMPLIFIED_CONSENSUS_STATE_SCHEMA_VERSION,
            directory_namespace: "chain-1266/incarnation-5".to_string(),
            mode: CHAIN1266_P3_CONSENSUS_MODE.to_string(),
            coordinator_id: String::new(),
            producer_ids: Vec::new(),
            producer_turn_timeout_ms: 0,
        };
        validate_desired_state_consensus(&canonical).expect("canonical P3 binding");
        assert_eq!(
            expected_chain_profile(&canonical).expect("fresh P3 chain profile"),
            (
                POSY_SIMPLIFIED_CHAIN_INCARNATION,
                POSY_SIMPLIFIED_CONSENSUS_STATE_SCHEMA_VERSION,
                "chain-1266/incarnation-5".to_string()
            )
        );

        let mut with_coordinator = canonical.clone();
        with_coordinator.coordinator_id = "validator-01".to_string();
        assert!(validate_desired_state_consensus(&with_coordinator).is_err());

        let mut with_producer = canonical.clone();
        with_producer.producer_ids.push("validator-02".to_string());
        assert!(validate_desired_state_consensus(&with_producer).is_err());

        let mut with_timeout = canonical;
        with_timeout.producer_turn_timeout_ms = 4_000;
        assert!(validate_desired_state_consensus(&with_timeout).is_err());
    }

    #[test]
    fn desired_state_signature_is_real_mldsa87_and_digest_bound() {
        let mut manager = PQCManager::new();
        let (public, private) = manager
            .generate_keypair(PQCAlgorithm::MLDSA87)
            .expect("generate ML-DSA-87 test authority");
        let fingerprint = format!("sha256:{}", sha256_bytes(&public.key_data));
        let mut manifest = DesiredStateManifest {
            schema_version: 1,
            release_id: "chain1266-incarnation-4-rc1".to_string(),
            release_tag: "chain1266-v20.0.0-rc.1".to_string(),
            chain: DesiredChain {
                chain_id: 1266,
                incarnation: 4,
                genesis_hash: "11".repeat(32),
                validator_set_root: "22".repeat(32),
            },
            source: DesiredSource {
                testnet_v3_revision: "33".repeat(20),
                synq_revision: "44".repeat(20),
                aegis_revision: "55".repeat(20),
            },
            state: DesiredConsensusState {
                consensus_schema_version: 4,
                directory_namespace: "chain-1266/incarnation-4".to_string(),
                mode: CHAIN1266_P1_CONSENSUS_MODE.to_string(),
                coordinator_id: CHAIN1266_P1_COORDINATOR_ID.to_string(),
                producer_ids: CHAIN1266_P1_PRODUCER_IDS
                    .iter()
                    .map(|producer| (*producer).to_string())
                    .collect(),
                producer_turn_timeout_ms: CHAIN1266_P1_PRODUCER_TURN_TIMEOUT_MS,
            },
            start_authority: DesiredStartAuthority {
                signature_algorithm: "ML-DSA-87".to_string(),
                signature_domain: crate::consensus_start::CHAIN1266_START_SIGNATURE_DOMAIN
                    .to_string(),
                public_key_fingerprint: fingerprint.clone(),
                public_key_base64: general_purpose::STANDARD.encode(&public.key_data),
            },
            artifacts: BTreeMap::new(),
            configuration: BTreeMap::new(),
        };
        let manifest_sha256 = sha256_bytes(
            &serde_json::to_vec(&manifest).expect("encode canonical desired-state manifest"),
        );
        let request = DesiredStateSignatureRequest {
            schema_version: 1,
            action: "AUTHORIZE_DESIRED_STATE".to_string(),
            release_id: manifest.release_id.clone(),
            chain_id: manifest.chain.chain_id,
            chain_incarnation: manifest.chain.incarnation,
            genesis_hash: manifest.chain.genesis_hash.clone(),
            desired_state_sha256: manifest_sha256.clone(),
            signature_algorithm: "ML-DSA-87".to_string(),
            signature_domain: CHAIN1266_DESIRED_STATE_SIGNATURE_DOMAIN.to_string(),
            authority_public_key_fingerprint: fingerprint,
        };
        let canonical = serde_json::to_vec(&request).expect("canonical request");
        let signature = Sign::mldsa87()
            .sign_ctx(
                &canonical,
                &private.key_data,
                CHAIN1266_DESIRED_STATE_SIGNATURE_DOMAIN.as_bytes(),
            )
            .expect("sign desired state");
        let signed = SignedDesiredStateManifest {
            request,
            signature_base64: general_purpose::STANDARD.encode(signature),
        };
        let bytes = serde_json::to_vec(&signed).expect("encode signature envelope");
        verify_desired_state_signature(&manifest, &manifest_sha256, &bytes)
            .expect("valid desired-state signature");
        manifest.state.producer_ids.swap(0, 1);
        let modified_manifest_sha256 = sha256_bytes(
            &serde_json::to_vec(&manifest).expect("encode altered desired-state manifest"),
        );
        assert!(
            verify_desired_state_signature(&manifest, &modified_manifest_sha256, &bytes).is_err(),
            "changing the P1 producer order must invalidate the digest-bound authorization"
        );
        let mut tampered_signature = general_purpose::STANDARD
            .decode(&signed.signature_base64)
            .expect("decode test signature");
        tampered_signature[0] ^= 0x01;
        let tampered_bytes = serde_json::to_vec(&SignedDesiredStateManifest {
            request: signed.request.clone(),
            signature_base64: general_purpose::STANDARD.encode(tampered_signature),
        })
        .expect("encode tampered signature envelope");
        assert!(
            verify_desired_state_signature(&manifest, &manifest_sha256, &tampered_bytes).is_err(),
            "flipping a real ML-DSA-87 signature byte must invalidate authorization"
        );
    }

    #[test]
    fn external_release_verifier_binds_governance_fingerprint_to_public_key() {
        let mut manager = PQCManager::new();
        let (public, private) = manager
            .generate_keypair(PQCAlgorithm::MLDSA87)
            .expect("generate unrelated ML-DSA-87 key");
        let manifest = serde_json::json!({
            "schema_version": 1,
            "release_id": "chain1266-incarnation-4-rc1",
            "release_tag": "chain1266-v20.0.0-rc.1",
            "chain": {
                "chain_id": 1266,
                "incarnation": 4,
                "genesis_hash": "11".repeat(32),
                "validator_set_root": "22".repeat(32),
            },
            "source": {
                "testnet_v3_revision": "33".repeat(20),
                "synq_revision": "44".repeat(20),
                "aegis_revision": "55".repeat(20),
            },
            "state": {
                "consensus_schema_version": TESTNET_V3_CONSENSUS_STATE_SCHEMA_VERSION,
                "directory_namespace": "chain-1266/incarnation-4",
                "mode": CHAIN1266_P1_CONSENSUS_MODE,
                "coordinator_id": CHAIN1266_P1_COORDINATOR_ID,
                "producer_ids": CHAIN1266_P1_PRODUCER_IDS,
                "producer_turn_timeout_ms": CHAIN1266_P1_PRODUCER_TURN_TIMEOUT_MS,
            },
            "start_authority": {
                "signature_algorithm": "ML-DSA-87",
                "signature_domain": crate::consensus_start::CHAIN1266_START_SIGNATURE_DOMAIN,
                // This field previously let the unrelated key below impersonate
                // the frozen authority when the release CLI did not recompute it.
                "public_key_fingerprint": PRODUCTION_GOVERNANCE_FINGERPRINT,
                "public_key_base64": general_purpose::STANDARD.encode(&public.key_data),
            },
            "artifacts": {},
            "configuration": {},
        });
        let manifest_bytes = serde_json::to_vec(&manifest).expect("encode manifest");
        let request = DesiredStateSignatureRequest {
            schema_version: 1,
            action: "AUTHORIZE_DESIRED_STATE".to_string(),
            release_id: "chain1266-incarnation-4-rc1".to_string(),
            chain_id: 1266,
            chain_incarnation: 4,
            genesis_hash: "11".repeat(32),
            desired_state_sha256: sha256_bytes(&manifest_bytes),
            signature_algorithm: "ML-DSA-87".to_string(),
            signature_domain: CHAIN1266_DESIRED_STATE_SIGNATURE_DOMAIN.to_string(),
            authority_public_key_fingerprint: PRODUCTION_GOVERNANCE_FINGERPRINT.to_string(),
        };
        let signature = Sign::mldsa87()
            .sign_ctx(
                &serde_json::to_vec(&request).expect("encode authorization"),
                &private.key_data,
                CHAIN1266_DESIRED_STATE_SIGNATURE_DOMAIN.as_bytes(),
            )
            .expect("sign unrelated authorization");
        let signature_bytes = serde_json::to_vec(&SignedDesiredStateManifest {
            request,
            signature_base64: general_purpose::STANDARD.encode(signature),
        })
        .expect("encode signed authorization");
        let manifest_path = crate::utils::test_temp_root(format!(
            "synergy-chain1266-forged-authority-{}-manifest.json",
            std::process::id()
        ));
        let signature_path = manifest_path.with_file_name(format!(
            "synergy-chain1266-forged-authority-{}-signature.json",
            std::process::id()
        ));
        fs::write(&manifest_path, manifest_bytes).expect("write forged manifest");
        fs::write(&signature_path, signature_bytes).expect("write forged signature");
        let error = verify_signed_desired_state_file(&manifest_path, &signature_path)
            .expect_err("unrelated public key must not impersonate Governance Authority");
        assert!(error.contains("public key fingerprint mismatch"), "{error}");
        let _ = fs::remove_file(manifest_path);
        let _ = fs::remove_file(signature_path);
    }
}
