//! Offline issuance and verification of the first Testnet-v3 ETDAG admission
//! package.
//!
//! The runtime prepares the exact canonical ML-DSA-65 transcript from the
//! *applied* Genesis and public ML-KEM ingress records.  Custody software may
//! sign that request, but this module is the only code that turns those
//! detached votes into a `TargetAdmissionPackage`: it recomputes every input
//! and delegates final acceptance to the production ETDAG verifier.

use crate::consensus::testnet_v3_bootstrap::load_testnet_v3_genesis_bootstrap;
use crate::consensus::testnet_v3_finality_context::FinalizedTypedContextProvider;
use crate::consensus::typed_finality_store::TypedFinalityStore;
use crate::etdag::{
    target_admission_source_finality_root, EtdagDigest, EtdagSignedVote, IngressKemKeyRecord,
    IngressKemKeyRegistry, TargetAdmissionCertificate, TargetAdmissionContext,
    TargetAdmissionContextSpec, TargetAdmissionPackage, DOMAIN_TARGET_ADMISSION,
    INGRESS_KEM_REGISTRY_VERSION,
};
use crate::genesis::{load_genesis_from_path, GenesisDocument};
use crate::synergy_types::{
    ClusterId, Epoch, Hash, Height, ValidatorId, TESTNET_V3_CANONICAL_NETWORK_ID,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::{Sha3_256, Sha3_512};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub const TARGET_ADMISSION_REQUEST_SCHEMA_VERSION: u32 = 1;
pub const TARGET_ADMISSION_REQUEST_ARTIFACT_TYPE: &str =
    "testnet-v3-etdag-target-admission-request";
pub const TARGET_ADMISSION_VOTES_SCHEMA_VERSION: u32 = 1;
pub const TARGET_ADMISSION_VOTES_ARTIFACT_TYPE: &str = "testnet-v3-etdag-target-admission-votes";
pub const TARGET_ADMISSION_PACKAGE_SCHEMA_VERSION: u32 = 1;
pub const TARGET_ADMISSION_PACKAGE_ARTIFACT_TYPE: &str =
    "testnet-v3-etdag-target-admission-package";
pub const FIRST_ETDAG_TARGET_HEIGHT: u64 = 3;
const INGRESS_KEY_ID_DOMAIN: &[u8] = b"SYNERGY_TESTNET_V3_ETDAG_INGRESS_KEY_ID_V1";
const INITIAL_ACTIVE_VALIDATOR_COUNT: usize = 5;
const INITIAL_TARGET_ADMISSION_QUORUM: usize = 4;
const TESTNET_V3_POSY_PROTOCOL_VERSION: &str = "posy/3.0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TestnetV3TargetAdmissionSignerRequest {
    pub validator_id: ValidatorId,
    pub validator_identity_id: String,
    pub operator_address: String,
    pub consensus_key_id: String,
    pub consensus_public_key_base64: String,
    pub signature_algorithm: String,
    pub signature_domain: String,
    pub certificate_transcript_base64: String,
    pub domain_payload_sha3_512: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TestnetV3TargetAdmissionRequest {
    pub schema_version: u32,
    pub artifact_type: String,
    pub chain_id: u64,
    pub runtime_network_id: String,
    pub applied_genesis_sha256: String,
    pub applied_genesis_hash: String,
    pub source_finalized_height: Height,
    pub source_finality_context_digest_sha3_512: EtdagDigest,
    pub target_height: Height,
    pub signature_algorithm: String,
    pub signature_domain: String,
    pub context: TargetAdmissionContext,
    pub ingress_kem_registry: IngressKemKeyRegistry,
    pub signer_requests: Vec<TestnetV3TargetAdmissionSignerRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TestnetV3TargetAdmissionDetachedVote {
    pub validator_id: ValidatorId,
    pub signer_key_id: String,
    pub signature_algorithm: String,
    pub signature_base64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TestnetV3TargetAdmissionVotes {
    pub schema_version: u32,
    pub artifact_type: String,
    pub request_sha256: String,
    pub signature_domain: String,
    pub votes: Vec<TestnetV3TargetAdmissionDetachedVote>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TestnetV3TargetAdmissionPackageArtifact {
    pub schema_version: u32,
    pub artifact_type: String,
    pub request_sha256: String,
    pub package: TargetAdmissionPackage,
    pub package_digest: EtdagDigest,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicIngressRecord {
    validator_id: String,
    validator_identity_id: String,
    operator_address: String,
    genesis_key_bundle_hash: String,
    share_index: u8,
    ingress_key_id: String,
    algorithm: String,
    public_key_base64: String,
    public_key_sha3_256: String,
    validator_public_identity_sha256: String,
    validator_encrypted_identity_sha256: String,
    private_custody_file: String,
    private_custody_sha3_256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicIngressAdmissionBinding {
    runtime_registry_type: String,
    runtime_registry_domain: String,
    certificate_domain: String,
    required_consensus_algorithm: String,
    minimum_signers_for_five_validator_cluster: u8,
    requirement: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicIngressArtifact {
    schema_version: u32,
    artifact_type: String,
    status: String,
    chain_id: u64,
    runtime_network_id: String,
    protocol_version: String,
    genesis_candidate_sha256: String,
    genesis_hash: String,
    records: Vec<PublicIngressRecord>,
    admission_binding: PublicIngressAdmissionBinding,
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    serde_json::to_vec(value).map_err(|error| format!("canonical JSON serialization: {error}"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn sha3_256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha3_256::digest(bytes))
}

fn sha3_512_hex(bytes: &[u8]) -> String {
    hex::encode(Sha3_512::digest(bytes))
}

fn require_lower_hex(value: &str, expected_length: usize, label: &str) -> Result<(), String> {
    if value.len() != expected_length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "{label} must be {expected_length} lowercase hexadecimal characters"
        ));
    }
    Ok(())
}

fn ingress_key_id(applied_genesis_sha256: &str, validator_id: &str, public_key: &[u8]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(INGRESS_KEY_ID_DOMAIN);
    hasher.update([0]);
    hasher.update(applied_genesis_sha256.as_bytes());
    hasher.update([0]);
    hasher.update(validator_id.as_bytes());
    hasher.update([0]);
    hasher.update(public_key);
    hex::encode(hasher.finalize())
}

fn domain_payload(domain: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(domain.len() + 16 + payload.len());
    out.extend_from_slice(&(domain.len() as u64).to_be_bytes());
    out.extend_from_slice(domain.as_bytes());
    out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn deployed_genesis_state_root(genesis: &GenesisDocument) -> Result<Hash, String> {
    genesis
        .value()
        .get("execution")
        .and_then(|value| value.get("genesis_execution_state_root"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "finalized Genesis omits execution.genesis_execution_state_root".to_string())
        .and_then(|value| {
            Hash::from_hex(value).map_err(|error| {
                format!("finalized Genesis execution state root is invalid: {error}")
            })
        })
}

fn transient_finality_store_path() -> Result<std::path::PathBuf, String> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("clock failure: {error}"))?
        .as_nanos();
    Ok(std::env::temp_dir().join(format!(
        "synergy-testnet-v3-admission-preparation-{}-{nanos}.json",
        std::process::id()
    )))
}

fn load_public_ingress_registry(
    path: &Path,
    genesis: &GenesisDocument,
    applied_genesis_sha256: &str,
    target_height: Height,
) -> Result<(IngressKemKeyRegistry, BTreeMap<ValidatorId, String>), String> {
    let bytes = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    let artifact: PublicIngressArtifact = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse {}: {error}", path.display()))?;
    if artifact.schema_version != 1
        || artifact.artifact_type != "testnet-v3-etdag-ingress-key-records"
        || artifact.status != "generated_pending_target_admission_certificate"
        || artifact.chain_id != 1266
        || artifact.runtime_network_id != TESTNET_V3_CANONICAL_NETWORK_ID
        || artifact.protocol_version != TESTNET_V3_POSY_PROTOCOL_VERSION
        || artifact.genesis_candidate_sha256 != applied_genesis_sha256
        || artifact.genesis_hash != genesis.hash()
        || artifact.admission_binding.runtime_registry_type != "IngressKemKeyRegistry/v2"
        || artifact.admission_binding.runtime_registry_domain
            != "PoSy/ETDAG/IngressKemKeyRegistry/v3"
        || artifact.admission_binding.certificate_domain != DOMAIN_TARGET_ADMISSION
        || artifact.admission_binding.required_consensus_algorithm != "ML-DSA-65"
        || artifact
            .admission_binding
            .minimum_signers_for_five_validator_cluster
            != INITIAL_TARGET_ADMISSION_QUORUM as u8
        || artifact.records.len() != INITIAL_ACTIVE_VALIDATOR_COUNT
    {
        return Err("public ingress artifact is not bound to the applied Testnet-v3 Genesis runtime profile".to_string());
    }
    if artifact.admission_binding.requirement.trim().is_empty() {
        return Err("public ingress artifact admission requirement is empty".to_string());
    }

    let bootstrap = load_testnet_v3_genesis_bootstrap(genesis)?;
    let active = bootstrap.validator_set.active_for_epoch(Epoch(0));
    let by_id = active
        .validators
        .iter()
        .map(|validator| (validator.validator_id.clone(), validator))
        .collect::<BTreeMap<_, _>>();
    let genesis_records = genesis
        .value()
        .get("validators")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "Genesis validators are missing".to_string())?;
    let genesis_by_id = genesis_records
        .iter()
        .filter_map(|record| {
            record
                .get("validator_id")
                .and_then(serde_json::Value::as_str)
                .map(|id| (id.to_string(), record))
        })
        .collect::<BTreeMap<_, _>>();

    let mut records = Vec::with_capacity(artifact.records.len());
    let mut identity_ids = BTreeMap::new();
    let mut seen_validator_ids = BTreeSet::new();
    let mut seen_shares = BTreeSet::new();
    let mut seen_key_ids = BTreeSet::new();
    for record in artifact.records {
        require_lower_hex(
            &record.genesis_key_bundle_hash,
            64,
            "genesis_key_bundle_hash",
        )?;
        require_lower_hex(&record.public_key_sha3_256, 64, "public_key_sha3_256")?;
        require_lower_hex(
            &record.validator_public_identity_sha256,
            64,
            "validator_public_identity_sha256",
        )?;
        require_lower_hex(
            &record.validator_encrypted_identity_sha256,
            64,
            "validator_encrypted_identity_sha256",
        )?;
        require_lower_hex(
            &record.private_custody_sha3_256,
            64,
            "private_custody_sha3_256",
        )?;
        require_lower_hex(&record.ingress_key_id, 64, "ingress_key_id")?;
        if record.algorithm != "ML-KEM-1024"
            || record.share_index == 0
            || record.validator_identity_id.trim().is_empty()
            || record.operator_address.trim().is_empty()
            || record.private_custody_file.trim().is_empty()
        {
            return Err("public ingress record contains an invalid identity binding".to_string());
        }
        let validator_id = ValidatorId(record.validator_id.clone());
        let validator = by_id.get(&validator_id).ok_or_else(|| {
            format!(
                "ingress record names non-active validator {}",
                record.validator_id
            )
        })?;
        let genesis_record = genesis_by_id
            .get(&record.validator_id)
            .ok_or_else(|| format!("Genesis validator record missing {}", record.validator_id))?;
        if validator.validator_uma_id.0 != record.operator_address
            || genesis_record
                .get("key_bundle_hash")
                .and_then(serde_json::Value::as_str)
                != Some(record.genesis_key_bundle_hash.as_str())
            || !seen_validator_ids.insert(validator_id.clone())
            || !seen_shares.insert(record.share_index)
            || !seen_key_ids.insert(record.ingress_key_id.clone())
        {
            return Err(
                "public ingress record disagrees with the frozen active validator set".to_string(),
            );
        }
        let key_bytes = BASE64
            .decode(&record.public_key_base64)
            .map_err(|error| format!("decode ingress public key: {error}"))?;
        if key_bytes.len() != 1568
            || sha3_256_hex(&key_bytes) != record.public_key_sha3_256
            || ingress_key_id(applied_genesis_sha256, &record.validator_id, &key_bytes)
                != record.ingress_key_id
        {
            return Err("public ingress record ML-KEM key binding is invalid".to_string());
        }
        identity_ids.insert(validator_id.clone(), record.validator_identity_id);
        records.push(IngressKemKeyRecord {
            validator_id,
            ingress_key_id: record.ingress_key_id,
            share_index: record.share_index,
            key_bytes,
        });
    }
    records.sort_by(|left, right| {
        left.validator_id
            .cmp(&right.validator_id)
            .then_with(|| left.share_index.cmp(&right.share_index))
            .then_with(|| left.ingress_key_id.cmp(&right.ingress_key_id))
    });
    if seen_validator_ids.len() != INITIAL_ACTIVE_VALIDATOR_COUNT
        || seen_shares.len() != INITIAL_ACTIVE_VALIDATOR_COUNT
        || seen_key_ids.len() != INITIAL_ACTIVE_VALIDATOR_COUNT
    {
        return Err("public ingress artifact does not contain five unique authorities".to_string());
    }
    let registry = IngressKemKeyRegistry {
        registry_version: INGRESS_KEM_REGISTRY_VERSION,
        chain_id: crate::synergy_types::ChainId::synergy_testnet_v3(),
        network_id: crate::synergy_types::NetworkId::fresh_posy_testnet_v3(),
        protocol_version: TESTNET_V3_POSY_PROTOCOL_VERSION.to_string(),
        epoch: Epoch(0),
        target_height,
        assigned_cluster_id: ClusterId(0),
        records,
    };
    registry.validate_shape()?;
    Ok((registry, identity_ids))
}

/// Prepare the only first-height admission request supported by an unstarted
/// Testnet-v3 chain.  It is derived from the applied canonical Genesis, not
/// an operator-supplied hash or synthetic test context.
pub fn prepare_first_target_admission_request(
    genesis_path: &Path,
    ingress_records_path: &Path,
) -> Result<TestnetV3TargetAdmissionRequest, String> {
    let genesis_bytes = fs::read(genesis_path)
        .map_err(|error| format!("read applied Genesis {}: {error}", genesis_path.display()))?;
    let applied_genesis_sha256 = sha256_hex(&genesis_bytes);
    let genesis = load_genesis_from_path(genesis_path.to_path_buf())?;
    let consensus = genesis
        .consensus_parameters()
        .cloned()
        .ok_or_else(|| "applied Genesis omits finalized consensus parameters".to_string())?;
    consensus.require_genesis_binding()?;
    let bootstrap = load_testnet_v3_genesis_bootstrap(&genesis)?;
    let genesis_anchor = Hash::from_hex(genesis.hash())
        .map_err(|error| format!("applied Genesis hash is invalid: {error}"))?;
    let finality_store =
        TypedFinalityStore::at_path(transient_finality_store_path()?, genesis_anchor)?;
    let provider = FinalizedTypedContextProvider::new(
        bootstrap.clone(),
        consensus.protocol_config.clone(),
        finality_store,
        deployed_genesis_state_root(&genesis)?,
    )?;
    let initial_context = provider.recover_next_context()?;
    if initial_context.latest_finalized_height != Height(0)
        || initial_context.height_context.height != Height(1)
    {
        return Err(
            "first ETDAG admission preparation requires the applied Genesis H=0 finality context"
                .to_string(),
        );
    }
    let source_finality_context_digest =
        provider.canonical_finality_context_digest(&initial_context)?;
    let source_finality_context_root =
        target_admission_source_finality_root(&source_finality_context_digest)?;
    let target_height = Height(FIRST_ETDAG_TARGET_HEIGHT);
    let (ingress_kem_registry, identity_ids) = load_public_ingress_registry(
        ingress_records_path,
        &genesis,
        &applied_genesis_sha256,
        target_height,
    )?;
    let context = TargetAdmissionContext::derive(
        TargetAdmissionContextSpec {
            protocol_version: TESTNET_V3_POSY_PROTOCOL_VERSION.to_string(),
            epoch: Epoch(0),
            target_height,
            source_finalized_height: Height(0),
            source_finality_context_root,
            assigned_cluster_id: ClusterId(0),
            cluster_schedule_version: "dynamic-v3-floor7".to_string(),
            finalized_epoch_seed_root: bootstrap.finalized_epoch_seed_root,
            assigned_height_schedule_root: bootstrap.assigned_height_schedule_root(target_height.0),
            cryptographic_profile_root: bootstrap.cryptographic_profile_root,
            ingress_kem_registry_root: ingress_kem_registry.root()?,
        },
        &bootstrap.validator_set,
        &bootstrap.cluster_map,
        &consensus.protocol_config,
    )?;
    ingress_kem_registry.validate_against(&context, &bootstrap.validator_set)?;
    let certificate = TargetAdmissionCertificate {
        certificate_version: 2,
        target_context_root: context.root()?,
        ingress_kem_registry_root: context.ingress_kem_registry_root.clone(),
        source_finalized_height: context.source_finalized_height,
        source_finality_context_root: context.source_finality_context_root,
        signer_count: INITIAL_TARGET_ADMISSION_QUORUM as u64,
        signed_weight: 0,
        votes: Vec::new(),
    };
    let transcript = certificate.signing_bytes(&context)?;
    let payload_hash = sha3_512_hex(&domain_payload(DOMAIN_TARGET_ADMISSION, &transcript));
    let active = bootstrap.validator_set.active_for_epoch(Epoch(0));
    let mut signer_requests = active
        .active_for_cluster(ClusterId(0))
        .into_iter()
        .map(|validator| {
            let public_key = BASE64.encode(&validator.consensus_public_key.key_bytes);
            Ok(TestnetV3TargetAdmissionSignerRequest {
                validator_identity_id: identity_ids
                    .get(&validator.validator_id)
                    .cloned()
                    .ok_or_else(|| {
                        "active validator lacks public ingress identity binding".to_string()
                    })?,
                validator_id: validator.validator_id,
                operator_address: validator.validator_uma_id.0,
                consensus_key_id: validator.consensus_public_key.key_id.0,
                consensus_public_key_base64: public_key,
                signature_algorithm: "ML-DSA-65".to_string(),
                signature_domain: DOMAIN_TARGET_ADMISSION.to_string(),
                certificate_transcript_base64: BASE64.encode(&transcript),
                domain_payload_sha3_512: payload_hash.clone(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    signer_requests.sort_by(|left, right| left.validator_id.cmp(&right.validator_id));
    if signer_requests.len() != INITIAL_ACTIVE_VALIDATOR_COUNT {
        return Err(
            "first ETDAG admission must have exactly five active eligible signers".to_string(),
        );
    }
    Ok(TestnetV3TargetAdmissionRequest {
        schema_version: TARGET_ADMISSION_REQUEST_SCHEMA_VERSION,
        artifact_type: TARGET_ADMISSION_REQUEST_ARTIFACT_TYPE.to_string(),
        chain_id: 1266,
        runtime_network_id: TESTNET_V3_CANONICAL_NETWORK_ID.to_string(),
        applied_genesis_sha256,
        applied_genesis_hash: genesis.hash().to_string(),
        source_finalized_height: Height(0),
        source_finality_context_digest_sha3_512: source_finality_context_digest,
        target_height,
        signature_algorithm: "ML-DSA-65".to_string(),
        signature_domain: DOMAIN_TARGET_ADMISSION.to_string(),
        context,
        ingress_kem_registry,
        signer_requests,
    })
}

fn ensure_request_is_canonical(
    path: &Path,
) -> Result<(TestnetV3TargetAdmissionRequest, Vec<u8>), String> {
    let bytes = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    let request: TestnetV3TargetAdmissionRequest = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse {}: {error}", path.display()))?;
    let canonical = canonical_json(&request)?;
    if bytes != canonical {
        return Err("target admission request is not exact canonical JSON".to_string());
    }
    Ok((request, canonical))
}

fn ensure_votes_are_canonical(path: &Path) -> Result<TestnetV3TargetAdmissionVotes, String> {
    let bytes = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    let votes: TestnetV3TargetAdmissionVotes = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse {}: {error}", path.display()))?;
    if bytes != canonical_json(&votes)? {
        return Err("target admission votes are not exact canonical JSON".to_string());
    }
    Ok(votes)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("output has no parent: {}", path.display()))?;
    if !parent.is_dir() {
        return Err(format!(
            "output directory does not exist: {}",
            parent.display()
        ));
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("create {}: {error}", path.display()))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("write {}: {error}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o644))
            .map_err(|error| format!("set permissions {}: {error}", path.display()))?;
    }
    Ok(())
}

pub fn write_first_target_admission_request(
    genesis_path: &Path,
    ingress_records_path: &Path,
    output_path: &Path,
) -> Result<(TestnetV3TargetAdmissionRequest, String), String> {
    if output_path.exists() {
        return Err(format!("refusing to overwrite {}", output_path.display()));
    }
    let request = prepare_first_target_admission_request(genesis_path, ingress_records_path)?;
    let bytes = canonical_json(&request)?;
    let request_sha256 = sha256_hex(&bytes);
    write_new(output_path, &bytes)?;
    Ok((request, request_sha256))
}

/// Rebuild the request from current applied inputs, verify four detached
/// ML-DSA-65 votes using the production Aegis verifier, and return the runtime
/// `TargetAdmissionPackage` that a node may install.
pub fn verify_first_target_admission_votes(
    genesis_path: &Path,
    ingress_records_path: &Path,
    request_path: &Path,
    votes_path: &Path,
) -> Result<(TargetAdmissionPackage, String), String> {
    let (request, request_bytes) = ensure_request_is_canonical(request_path)?;
    let rebuilt = prepare_first_target_admission_request(genesis_path, ingress_records_path)?;
    if request != rebuilt {
        return Err("target admission request does not exactly match current applied Genesis and ingress records".to_string());
    }
    let request_sha256 = sha256_hex(&request_bytes);
    let votes = ensure_votes_are_canonical(votes_path)?;
    if votes.schema_version != TARGET_ADMISSION_VOTES_SCHEMA_VERSION
        || votes.artifact_type != TARGET_ADMISSION_VOTES_ARTIFACT_TYPE
        || votes.request_sha256 != request_sha256
        || votes.signature_domain != DOMAIN_TARGET_ADMISSION
        || votes.votes.len() != INITIAL_TARGET_ADMISSION_QUORUM
    {
        return Err(
            "target admission vote artifact is not an exact 4-of-5 Testnet-v3 certificate"
                .to_string(),
        );
    }
    let genesis = load_genesis_from_path(genesis_path.to_path_buf())?;
    let consensus = genesis
        .consensus_parameters()
        .cloned()
        .ok_or_else(|| "applied Genesis omits finalized consensus parameters".to_string())?;
    consensus.require_genesis_binding()?;
    let bootstrap = load_testnet_v3_genesis_bootstrap(&genesis)?;
    let active = bootstrap.validator_set.active_for_epoch(Epoch(0));
    let members = active.active_for_cluster(ClusterId(0));
    let transcript_certificate = TargetAdmissionCertificate {
        certificate_version: 2,
        target_context_root: request.context.root()?,
        ingress_kem_registry_root: request.context.ingress_kem_registry_root.clone(),
        source_finalized_height: request.context.source_finalized_height,
        source_finality_context_root: request.context.source_finality_context_root,
        signer_count: INITIAL_TARGET_ADMISSION_QUORUM as u64,
        signed_weight: 0,
        votes: Vec::new(),
    };
    let transcript = transcript_certificate.signing_bytes(&request.context)?;
    let expected_payload_hash = sha3_512_hex(&domain_payload(DOMAIN_TARGET_ADMISSION, &transcript));
    let expected_signers = request
        .signer_requests
        .iter()
        .map(|entry| (entry.validator_id.clone(), entry))
        .collect::<BTreeMap<_, _>>();
    if expected_signers.len() != INITIAL_ACTIVE_VALIDATOR_COUNT
        || request.signer_requests.iter().any(|entry| {
            entry.signature_algorithm != "ML-DSA-65"
                || entry.signature_domain != DOMAIN_TARGET_ADMISSION
                || entry.domain_payload_sha3_512 != expected_payload_hash
                || entry.certificate_transcript_base64 != BASE64.encode(&transcript)
        })
    {
        return Err(
            "request signer transcript is not the canonical runtime target-admission transcript"
                .to_string(),
        );
    }

    let mut seen = BTreeSet::new();
    let mut signed_weight = 0u64;
    let mut runtime_votes = Vec::with_capacity(votes.votes.len());
    for vote in votes.votes {
        if vote.signature_algorithm != "ML-DSA-65" || !seen.insert(vote.validator_id.clone()) {
            return Err(
                "target admission votes contain duplicate or non-ML-DSA-65 signers".to_string(),
            );
        }
        let request_signer = expected_signers
            .get(&vote.validator_id)
            .ok_or_else(|| "target admission vote signer is not in the request".to_string())?;
        let member = members
            .iter()
            .find(|member| member.validator_id == vote.validator_id)
            .ok_or_else(|| {
                "target admission vote signer is not in the active cluster".to_string()
            })?;
        if request_signer.consensus_key_id != member.consensus_public_key.key_id.0
            || request_signer.operator_address != member.validator_uma_id.0
            || vote.signer_key_id != member.consensus_public_key.key_id.0
        {
            return Err(
                "target admission vote signer does not match frozen Genesis consensus identity"
                    .to_string(),
            );
        }
        let signature_bytes = BASE64
            .decode(&vote.signature_base64)
            .map_err(|error| format!("decode target admission signature: {error}"))?;
        runtime_votes.push(EtdagSignedVote {
            signer_validator_id: vote.validator_id,
            signer_key_id: member.consensus_public_key.key_id.clone(),
            signature: crate::synergy_types::AegisPqSignature {
                algorithm: "mldsa65".to_string(),
                signature_bytes,
            },
        });
        signed_weight = signed_weight
            .checked_add(member.voting_weight)
            .ok_or_else(|| "target admission signed weight overflow".to_string())?;
    }
    runtime_votes.sort_by(|left, right| left.signer_validator_id.cmp(&right.signer_validator_id));
    let certificate = TargetAdmissionCertificate {
        certificate_version: 2,
        target_context_root: request.context.root()?,
        ingress_kem_registry_root: request.context.ingress_kem_registry_root.clone(),
        source_finalized_height: request.context.source_finalized_height,
        source_finality_context_root: request.context.source_finality_context_root,
        signer_count: runtime_votes.len() as u64,
        signed_weight,
        votes: runtime_votes,
    };
    let package = TargetAdmissionPackage {
        context: request.context,
        ingress_kem_registry: request.ingress_kem_registry,
        certificate,
    };
    package.verify(
        &bootstrap.verifier,
        &bootstrap.validator_set,
        &bootstrap.cluster_map,
        &consensus.protocol_config,
    )?;
    Ok((package, request_sha256))
}

pub fn write_verified_first_target_admission_package(
    genesis_path: &Path,
    ingress_records_path: &Path,
    request_path: &Path,
    votes_path: &Path,
    output_path: &Path,
) -> Result<(TestnetV3TargetAdmissionPackageArtifact, String), String> {
    if output_path.exists() {
        return Err(format!("refusing to overwrite {}", output_path.display()));
    }
    let (package, request_sha256) = verify_first_target_admission_votes(
        genesis_path,
        ingress_records_path,
        request_path,
        votes_path,
    )?;
    let package_digest = package.package_digest()?;
    let artifact = TestnetV3TargetAdmissionPackageArtifact {
        schema_version: TARGET_ADMISSION_PACKAGE_SCHEMA_VERSION,
        artifact_type: TARGET_ADMISSION_PACKAGE_ARTIFACT_TYPE.to_string(),
        request_sha256,
        package,
        package_digest,
    };
    let bytes = canonical_json(&artifact)?;
    let artifact_sha256 = sha256_hex(&bytes);
    write_new(output_path, &bytes)?;
    Ok((artifact, artifact_sha256))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_admission_domain_payload_matches_aegis_framing() {
        let payload = domain_payload(DOMAIN_TARGET_ADMISSION, b"target-admission");
        assert_eq!(
            &payload[..8],
            &(DOMAIN_TARGET_ADMISSION.len() as u64).to_be_bytes()
        );
        assert_eq!(
            &payload[8..8 + DOMAIN_TARGET_ADMISSION.len()],
            DOMAIN_TARGET_ADMISSION.as_bytes()
        );
        assert_eq!(
            sha3_512_hex(&payload).len(),
            128,
            "the request carries an unambiguous 512-bit transcript fingerprint"
        );
    }

    #[test]
    fn ingress_key_id_changes_when_the_applied_genesis_changes() {
        let key = vec![7; 1568];
        assert_ne!(
            ingress_key_id(&"a".repeat(64), "validator-02", &key),
            ingress_key_id(&"b".repeat(64), "validator-02", &key)
        );
    }
}
