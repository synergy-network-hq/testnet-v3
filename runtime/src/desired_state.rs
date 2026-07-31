//! Fail-closed Chain 1266 desired-state binding.
//!
//! The release controller verifies the signed release-tag provenance and
//! GitHub artifact attestation before installing this manifest.  Every role
//! process then independently verifies the installed manifest digest and all
//! local release inputs before it can open consensus or observer state.

use crate::consensus::testnet_v3_bootstrap::load_testnet_v3_genesis_bootstrap;
use crate::genesis::canonical_genesis;
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
const EXPECTED_QUORUM: u64 = 5;

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DesiredChain {
    chain_id: u64,
    incarnation: u64,
    genesis_hash: String,
    validator_set_root: String,
    quorum: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DesiredSource {
    testnet_v3_revision: String,
    synq_revision: String,
    aegis_revision: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DesiredConsensusState {
    consensus_schema_version: u32,
    directory_namespace: String,
}

#[derive(Debug, Deserialize)]
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
    required_lower_hex(name, value, 20)
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
    let release_sequence = manifest
        .release_id
        .strip_prefix("chain1266-incarnation-4-")
        .ok_or_else(|| "desired-state release ID is outside incarnation 4".to_string())?;
    let tag_sequence = manifest
        .release_tag
        .strip_prefix("chain1266-v20.0.0-")
        .ok_or_else(|| "desired-state release tag is outside Chain 1266 v20.0.0".to_string())?
        .replace('.', "");
    if release_sequence.is_empty() || release_sequence != tag_sequence {
        return Err("desired-state release ID/tag binding is invalid".to_string());
    }
    if manifest.chain.chain_id != SYNERGY_TESTNET_V3_CHAIN_ID
        || manifest.chain.incarnation != TESTNET_V3_CHAIN_INCARNATION
        || manifest.chain.quorum != EXPECTED_QUORUM
    {
        return Err("desired-state Chain 1266 domain or quorum is invalid".to_string());
    }
    if manifest.state.consensus_schema_version != TESTNET_V3_CONSENSUS_STATE_SCHEMA_VERSION
        || manifest.state.directory_namespace
            != format!(
                "chain-{}/incarnation-{}",
                SYNERGY_TESTNET_V3_CHAIN_ID, TESTNET_V3_CHAIN_INCARNATION
            )
    {
        return Err("desired-state consensus schema or state namespace is invalid".to_string());
    }
    let state_root = env::var("SYNERGY_DATA_PATH")
        .map(PathBuf::from)
        .map_err(|_| "SYNERGY_DATA_PATH is required for incarnation-isolated state".to_string())?;
    if !state_root.is_absolute()
        || state_root.file_name().and_then(|value| value.to_str()) != Some("data")
        || !state_root
            .parent()
            .is_some_and(|parent| parent.ends_with(Path::new(&manifest.state.directory_namespace)))
    {
        return Err(format!(
            "state root must be the data directory under absolute namespace {}",
            manifest.state.directory_namespace
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
    let private_qualification = env::var(CHAIN1266_QUALIFICATION_MODE_ENV).as_deref() == Ok("1")
        && genesis
            .value()
            .get("env")
            .and_then(serde_json::Value::as_str)
            == Some("chain1266-private-qualification");
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

    let bootstrap = load_testnet_v3_genesis_bootstrap(genesis)?;
    let active_root = bootstrap
        .validator_set
        .active_for_epoch(Epoch(0))
        .hash()?
        .to_hex();
    if active_root != manifest.chain.validator_set_root {
        return Err(format!(
            "active validator-set root mismatch: expected {}, found {active_root}",
            manifest.chain.validator_set_root
        ));
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
    fn desired_state_signature_is_real_mldsa87_and_digest_bound() {
        let mut manager = PQCManager::new();
        let (public, private) = manager
            .generate_keypair(PQCAlgorithm::MLDSA87)
            .expect("generate ML-DSA-87 test authority");
        let fingerprint = format!("sha256:{}", sha256_bytes(&public.key_data));
        let manifest = DesiredStateManifest {
            schema_version: 1,
            release_id: "chain1266-incarnation-4-rc1".to_string(),
            release_tag: "chain1266-v20.0.0-rc.1".to_string(),
            chain: DesiredChain {
                chain_id: 1266,
                incarnation: 4,
                genesis_hash: "11".repeat(32),
                validator_set_root: "22".repeat(32),
                quorum: 5,
            },
            source: DesiredSource {
                testnet_v3_revision: "33".repeat(20),
                synq_revision: "44".repeat(20),
                aegis_revision: "55".repeat(20),
            },
            state: DesiredConsensusState {
                consensus_schema_version: 4,
                directory_namespace: "chain-1266/incarnation-4".to_string(),
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
        let manifest_sha256 = "66".repeat(32);
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
        assert!(
            verify_desired_state_signature(&manifest, &"77".repeat(32), &bytes).is_err(),
            "changing the desired-state digest must invalidate the authorization"
        );
    }
}
