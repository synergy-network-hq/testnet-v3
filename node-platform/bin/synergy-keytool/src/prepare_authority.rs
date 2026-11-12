//! Prepares one unsigned authority from explicit governed inputs and public custody.
//! No secret key, signing, deployment, or identity generation occurs here.
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use aegis_pqvm::pqc::signatures::mldsa::mldsa65;
use pqrust_traits::sign::PublicKey as _;
use serde::Deserialize;
use synergy_aegis::KeyPurpose;
use synergy_genesis::authority::{AuthorityPayload, ProtectedCutoffRelationship};
use synergy_identity::PublicNodeIdentity;
use synergy_posy::FrozenValidatorRegistry;

use crate::aegis_keys::{
    read_bounded, read_metadata, valid_consensus_node_address, write_public_json, KeyMetadata,
    MAX_KEY_BYTES, MAX_METADATA_BYTES,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicBundle {
    metadata_path: PathBuf,
    public_key_path: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidatorPublicCustody {
    public_identity_path: PathBuf,
    p2p: PublicBundle,
    consensus: PublicBundle,
    ingress: PublicBundle,
}

/// All Genesis, seed, profile, schedule, world-state and weight inputs are explicit.
/// Empty parameter/member roots request deterministic derivation; nonempty roots
/// are expected values and must match. Paths must be absolute public-file paths.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareAuthorityInput {
    authority: AuthorityPayload,
    validators: Vec<ValidatorPublicCustody>,
}

pub const CRYPTO_PROFILE_DOMAIN: &str = "SYNERGY_FRESH_CRYPTO_PROFILE_V1";
const PROCESSING_CRYPTO_PROFILE_DOMAIN: &str = "SYNERGY_ASYNC_CRYPTO_PROFILE_V1";
const PROCESSING_SCHEDULE_DOMAIN: &str = "SYNERGY_ASYNC_AUTHORIZATION_SCHEDULE_V1";
pub const CLUSTER_MAP_DOMAIN: &str = "SYNERGY_FRESH_SINGLE_CLUSTER_MAP_V1";
pub const HEIGHT_SCHEDULE_DOMAIN: &str = "SYNERGY_FRESH_TARGET_SCHEDULE_V1";
pub const REGISTRY_CONTEXT_DOMAIN: &str = "SYNERGY_FRESH_INGRESS_REGISTRY_CONTEXT_V1";
pub const GENESIS_REFERENCE_DOMAIN: &str = "SYNERGY_FRESH_GENESIS_REFERENCE_V1";
pub const GENESIS_SEED_DOMAIN: &str = "SYNERGY_FRESH_GENESIS_EPOCH_SEED_V1";

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum SeedSource {
    GenesisHash,
    ProvidedExpected { root: String },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareGenesisInput {
    #[serde(default = "current_genesis_format")]
    genesis_format_version: u32,
    authority: AuthorityPayload,
    validators: Vec<ValidatorPublicCustody>,
    #[serde(default)]
    formation_registrations: Vec<PathBuf>,
    network: synergy_genesis::network::GenesisNetwork,
    authority_trust_key_id: String,
    seed_source: SeedSource,
}

fn current_genesis_format() -> u32 {
    2
}

#[derive(serde::Serialize)]
struct CryptoProfileDescriptor {
    version: u32,
    profile_id: String,
    envelope_version: u32,
    decrypt_share_version: u32,
    author_and_reveal_signature: &'static str,
    ingress_kem: &'static str,
    ingress_public_key_bytes: usize,
    ingress_ciphertext_bytes: usize,
    aead: &'static str,
    aead_key_bytes: usize,
    aead_nonce_bytes: usize,
    sharing: &'static str,
    sharing_field_polynomial: u16,
    sharing_key_bytes: usize,
    member_count: usize,
    count_quorum: usize,
    reveal_threshold: usize,
    capsule_key_domain: &'static str,
    key_commitment_domain: &'static str,
    share_commitment_domain: &'static str,
    share_commitment_root_domain: &'static str,
    capsule_root_domain: &'static str,
}

#[derive(serde::Serialize)]
struct ClusterMapDescriptor<'a> {
    version: u32,
    chain_id: u64,
    network_id: &'a str,
    epoch: u64,
    cluster_id: u64,
    members: Vec<&'a synergy_posy::ValidatorRecord>,
}

#[derive(serde::Serialize)]
struct HeightScheduleDescriptor<'a> {
    version: u32,
    chain_id: u64,
    network_id: &'a str,
    epoch: u64,
    epoch_start_height: u64,
    epoch_end_height: u64,
    assigned_cluster_id: u64,
    cluster_map_root: &'a str,
    genesis_prepared_targets: Vec<u64>,
    first_normal_height: u64,
    bootstrap_execution_heights: [u64; 2],
    finalized_source_offset: u64,
    cutoff_relationship: &'static str,
}

/// Processing authorization anchors key validity; block advancement never expires
/// unfinished work. Inclusion and reveal authority remain native PoSy group state.
#[derive(serde::Serialize)]
struct ProcessingScheduleDescriptor<'a> {
    version: u32,
    chain_id: u64,
    network_id: &'a str,
    epoch: u64,
    epoch_start_height: u64,
    epoch_end_height: u64,
    assigned_cluster_id: u64,
    cluster_map_root: &'a str,
    processing_profile_id: &'static str,
    authorization_height_offset: u64,
    authorization_anchor_is_inclusion_deadline: bool,
    cutoff_relationship: &'static str,
}

fn derive_genesis(
    mut input: PrepareGenesisInput,
) -> Result<
    (
        synergy_genesis::builder::UnsignedGenesis,
        PrepareAuthorityInput,
    ),
    String,
> {
    input.network.validate()?;
    if input.network.protocol_version != synergy_posy::POSY_SIMPLIFIED_PROTOCOL_VERSION {
        return Err("Genesis protocol version differs from canonical PoSy runtime".into());
    }
    let authority = &mut input.authority;
    if authority.chain_id != input.network.chain_id
        || authority.network_id != input.network.network_id
        || authority.epoch != 1
        || authority.epoch_start_height != 1
        || authority.validators.len() != 5
        || authority
            .validators
            .iter()
            .any(|v| v.record.frozen_voting_weight != 100)
    {
        return Err("stability Genesis requires the explicit fresh Chain 1266 five-validator authority with weight 100 each".into());
    }
    authority
        .validators
        .sort_by(|a, b| a.record.validator_id.cmp(&b.record.validator_id));
    let registry = FrozenValidatorRegistry::new(
        authority.epoch,
        authority
            .validators
            .iter()
            .map(|v| v.record.clone())
            .collect(),
    )
    .map_err(|e| e.to_string())?;
    if registry.active_count() != 5 {
        return Err("stability Genesis members must all be active".into());
    }
    let policy = authority
        .protected
        .as_mut()
        .ok_or("explicit protected policy/world state required")?;
    let processing = match (policy.version, policy.cutoff_relationship) {
        (1, ProtectedCutoffRelationship::VcEventContextV1) => false,
        (2, ProtectedCutoffRelationship::ProcessingGroupsV1) => true,
        _ => return Err("unsupported protected policy version/cutoff relationship".into()),
    };
    if input.network.activation_unix.checked_mul(1000) != Some(policy.epoch_start_timestamp_ms) {
        return Err("Genesis activation differs from the signed epoch timestamp".into());
    }
    policy
        .parameters
        .validate()
        .map_err(|e| format!("invalid governed parameters: {e:?}"))?;
    if policy.assigned_cluster_id != 0 {
        return Err("fresh stability profile requires single cluster zero".into());
    }
    bind_expected_root(
        &mut policy.assigned_cluster_membership_root,
        registry.active_set_root().map_err(|e| e.to_string())?,
    )?;
    let count_quorum = synergy_genesis::certificate_quorum(registry.active_count())
        .map_err(|e| format!("count quorum: {e:?}"))?;
    let crypto = CryptoProfileDescriptor {
        version: 1,
        profile_id: if processing {
            synergy_etdag::PROCESSING_PROFILE_ID.into()
        } else {
            policy.parameters.profile_id.clone()
        },
        envelope_version: if processing { 1 } else { 2 },
        decrypt_share_version: if processing { 1 } else { 2 },
        author_and_reveal_signature: "ML-DSA-65",
        ingress_kem: "ML-KEM-1024",
        ingress_public_key_bytes: aegis_pqvm::pqc::kem::mlkem::mlkem1024::public_key_bytes(),
        ingress_ciphertext_bytes: aegis_pqvm::pqc::kem::mlkem::mlkem1024::ciphertext_bytes(),
        aead: "AES-256-GCM",
        aead_key_bytes: 32,
        aead_nonce_bytes: 12,
        sharing: "Shamir-GF256",
        sharing_field_polynomial: 0x11b,
        sharing_key_bytes: 32,
        member_count: 5,
        count_quorum,
        reveal_threshold: 5 - count_quorum + 1,
        capsule_key_domain: "PoSy/ETDAG/CapsuleKey/v3",
        key_commitment_domain: "PoSy/ETDAG/KeyCommitment/v3",
        share_commitment_domain: "PoSy/ETDAG/ShareCommitment/v3",
        share_commitment_root_domain: "PoSy/ETDAG/ShareCommitmentRoot/v3",
        capsule_root_domain: "PoSy/ETDAG/ShareCapsuleRoot/v3",
    };
    bind_expected_root(
        &mut policy.cryptographic_profile_root,
        synergy_posy::canonical_hash(
            if processing {
                PROCESSING_CRYPTO_PROFILE_DOMAIN
            } else {
                CRYPTO_PROFILE_DOMAIN
            },
            &crypto,
        )
        .map_err(|e| e.to_string())?,
    )?;
    let cluster = ClusterMapDescriptor {
        version: 1,
        chain_id: authority.chain_id,
        network_id: &authority.network_id,
        epoch: authority.epoch,
        cluster_id: 0,
        members: authority.validators.iter().map(|v| &v.record).collect(),
    };
    bind_expected_root(
        &mut policy.cluster_map_root,
        synergy_posy::canonical_hash(CLUSTER_MAP_DOMAIN, &cluster).map_err(|e| e.to_string())?,
    )?;
    if processing {
        let schedule = ProcessingScheduleDescriptor {
            version: 1,
            chain_id: authority.chain_id,
            network_id: &authority.network_id,
            epoch: authority.epoch,
            epoch_start_height: 1,
            epoch_end_height: authority.epoch_end_height,
            assigned_cluster_id: 0,
            cluster_map_root: &policy.cluster_map_root,
            processing_profile_id: synergy_etdag::PROCESSING_PROFILE_ID,
            authorization_height_offset: policy.parameters.target_height_offset,
            authorization_anchor_is_inclusion_deadline: false,
            cutoff_relationship: "processing_groups_v1",
        };
        bind_expected_root(
            &mut policy.assigned_height_schedule_root,
            synergy_posy::canonical_hash(PROCESSING_SCHEDULE_DOMAIN, &schedule)
                .map_err(|e| e.to_string())?,
        )?;
    } else {
        let schedule = HeightScheduleDescriptor {
            version: 1,
            chain_id: authority.chain_id,
            network_id: &authority.network_id,
            epoch: authority.epoch,
            epoch_start_height: 1,
            epoch_end_height: authority.epoch_end_height,
            assigned_cluster_id: 0,
            cluster_map_root: &policy.cluster_map_root,
            genesis_prepared_targets: (3..=policy.parameters.target_height_offset).collect(),
            first_normal_height: 3,
            bootstrap_execution_heights: [1, 2],
            finalized_source_offset: policy.parameters.target_height_offset,
            cutoff_relationship: "vc_event_context_v1",
        };
        bind_expected_root(
            &mut policy.assigned_height_schedule_root,
            synergy_posy::canonical_hash(HEIGHT_SCHEDULE_DOMAIN, &schedule)
                .map_err(|e| e.to_string())?,
        )?;
    }
    let schedule_version = if processing {
        "single-cluster-processing-groups-v1"
    } else if policy.parameters.target_height_offset == 5 {
        "single-cluster-f-plus-five-v1"
    } else {
        // The explicitly signed experimental profile is isolated A1 authority;
        // this does not choose or authorize a production activation.
        "single-cluster-lookahead-experimental-v1"
    };
    if !policy.cluster_schedule_version.is_empty()
        && policy.cluster_schedule_version != schedule_version
    {
        return Err("cluster schedule version differs from the signed lookahead profile".into());
    }
    policy.cluster_schedule_version = schedule_version.into();
    policy.ingress_kem_registry.records.sort_by(|a, b| {
        a.validator_id
            .cmp(&b.validator_id)
            .then(a.key_id.cmp(&b.key_id))
    });
    let context = synergy_genesis::EtdagDigest::from_canonical(
        REGISTRY_CONTEXT_DOMAIN,
        &(
            input.network.clone(),
            authority.epoch,
            authority.epoch_start_height,
            authority.epoch_end_height,
            &policy.assigned_cluster_membership_root,
            &policy.ingress_kem_registry.records,
        ),
    )
    .map_err(|e| format!("derive public ingress registry context: {e:?}"))?;
    if !policy.ingress_kem_registry.context_root.0.is_empty()
        && policy.ingress_kem_registry.context_root != context
    {
        return Err("explicit ingress registry context differs from public derivation".into());
    }
    policy.ingress_kem_registry.context_root = context;
    policy
        .ingress_kem_registry
        .validate_protected_profile()
        .map_err(|e| format!("ingress public registry: {e:?}"))?;
    let genesis = synergy_genesis::builder::UnsignedGenesis {
        format_version: input.genesis_format_version,
        network: input.network,
        validators: authority
            .validators
            .iter()
            .map(|v| synergy_genesis::validator_set::GenesisValidator {
                record: v.record.clone(),
                algorithm: v.algorithm,
                public_key: v.public_key.clone(),
            })
            .collect(),
        etdag: synergy_genesis::etdag::GenesisEtdag {
            parameters: policy.parameters.clone(),
            cryptographic_profile_root: policy.cryptographic_profile_root.clone(),
            ingress_kem_registry_root: policy
                .ingress_kem_registry
                .root()
                .map_err(|e| format!("ingress registry hash: {e:?}"))?,
        },
        initial_state_root: synergy_genesis::state_root(&policy.initial_world_state)
            .map_err(|e| format!("initial state: {e:?}"))?,
        authority_trust_key_id: input.authority_trust_key_id,
    };
    let genesis_hash = genesis.genesis_hash()?;
    match &mut authority.anchor_parent {
        synergy_posy::SimplifiedFinalityParent::Genesis {
            genesis_hash: expected,
            block_id,
            reference_id,
        } => {
            bind_expected_root(expected, genesis_hash.clone())?;
            bind_expected_root(block_id, genesis_hash.clone())?;
            bind_expected_root(
                reference_id,
                synergy_posy::canonical_hash(
                    GENESIS_REFERENCE_DOMAIN,
                    &(
                        authority.chain_id,
                        &authority.network_id,
                        authority.epoch,
                        &genesis_hash,
                        &genesis.initial_state_root,
                    ),
                )
                .map_err(|e| e.to_string())?,
            )?;
        }
        _ => return Err("fresh Genesis recipe cannot use a QC anchor".into()),
    }
    let seed = match input.seed_source {
        SeedSource::GenesisHash => synergy_posy::canonical_hash(
            GENESIS_SEED_DOMAIN,
            &(
                authority.chain_id,
                &authority.network_id,
                authority.epoch,
                &genesis_hash,
            ),
        )
        .map_err(|e| e.to_string())?,
        SeedSource::ProvidedExpected { root } if synergy_posy::is_hash(&root) => root,
        SeedSource::ProvidedExpected { .. } => {
            return Err("explicit epoch seed must be a canonical hash".into())
        }
    };
    bind_expected_root(&mut authority.finalized_epoch_seed_root, seed)?;
    bind_expected_root(
        &mut authority.consensus_parameter_root,
        policy.commitment()?,
    )?;
    authority.validate()?;
    Ok((
        genesis,
        PrepareAuthorityInput {
            authority: input.authority,
            validators: input.validators,
        },
    ))
}

pub fn prepare_genesis(
    input: &Path,
    genesis_output: &Path,
    authority_output: &Path,
) -> Result<(), String> {
    prepare_genesis_with_formation(input, genesis_output, authority_output, None)
}

#[cfg(unix)]
pub fn prepare_formation_genesis(
    input: &Path,
    context: &Path,
    context_pin: &str,
    genesis_output: &Path,
    authority_output: &Path,
    engine: crate::provider::Engine,
) -> Result<(), String> {
    let formation = crate::validator_formation::pinned_context(context, context_pin)?;
    prepare_genesis_with_formation(
        input,
        genesis_output,
        authority_output,
        Some((formation, engine)),
    )
}

fn prepare_genesis_with_formation(
    input: &Path,
    genesis_output: &Path,
    authority_output: &Path,
    formation: Option<(
        synergy_address_engine::validator_provisioning::FormationContext,
        crate::provider::Engine,
    )>,
) -> Result<(), String> {
    // Check both canonical output names before writing either. Atomic create_new
    // remains the final guard against concurrent creation.
    let mut outputs = BTreeSet::new();
    for path in [genesis_output, authority_output] {
        if std::fs::symlink_metadata(path).is_ok() {
            return Err(format!("refusing to overwrite {}", path.display()));
        }
        let parent = path.parent().ok_or("explicit output directory required")?;
        let canonical = std::fs::canonicalize(parent)
            .map_err(|e| format!("resolve output directory: {e}"))?
            .join(path.file_name().ok_or("output filename required")?);
        if !outputs.insert(canonical) {
            return Err("Genesis and authority output paths must differ".into());
        }
    }
    let mut request: PrepareGenesisInput = serde_json::from_slice(&read_bounded(
        input,
        MAX_METADATA_BYTES,
        "explicit fresh Genesis recipe",
    )?)
    .map_err(|e| format!("decode fresh Genesis recipe: {e}"))?;
    let registrations = std::mem::take(&mut request.formation_registrations);
    let (genesis, authority_input) = derive_genesis(request)?;
    let authority = if let Some((context, engine)) = formation {
        #[cfg(not(unix))]
        {
            let _ = (context, engine);
            return Err("Formation Genesis requires a Unix host".into());
        }
        #[cfg(unix)]
        {
            if context.network_id != genesis.network.network_id
                || context.chain_id_hex != format!("{:064x}", genesis.network.chain_id)
                || !authority_input.validators.is_empty()
                || registrations.len() != authority_input.authority.validators.len()
            {
                return Err("Exact formation context and registration coverage required".into());
            }
            let mut seen = BTreeSet::new();
            let guard = engine.lock().map_err(|_| "APQE provider unavailable")?;
            for path in registrations {
                let registration = crate::validator_formation::public_registration(&path)?;
                synergy_address_engine::validator_provisioning::verify_formation_registration(
                    &guard,
                    &registration,
                    &context,
                )?;
                if !seen.insert(registration.payload.identity.address.clone()) {
                    return Err("Duplicate formation registration identity".into());
                }
                crate::validator_formation::verify_authorized_keys(
                    &authority_input.authority,
                    &registration,
                )?;
            }
            authority_input.authority.validate()?;
            authority_input.authority
        }
    } else {
        if !registrations.is_empty() {
            return Err("Use the explicit native formation Genesis command".into());
        }
        validate_input(authority_input)?
    };
    authority.signing_bytes()?;
    write_public_json(genesis_output, &genesis)?;
    if let Err(error) = write_public_json(authority_output, &authority) {
        let _ = std::fs::remove_file(genesis_output);
        return Err(error);
    }
    Ok(())
}

fn public_bundle(bundle: &PublicBundle) -> Result<KeyMetadata, String> {
    if !bundle.metadata_path.is_absolute() || !bundle.public_key_path.is_absolute() {
        return Err("public custody paths must be absolute".into());
    }
    let metadata = read_metadata(&bundle.metadata_path)?;
    let public = read_bounded(&bundle.public_key_path, MAX_KEY_BYTES, "custody public key")?;
    if public != metadata.record.public_key {
        return Err("custody public key differs from its metadata".into());
    }
    Ok(metadata)
}

fn check_binding(
    metadata: &KeyMetadata,
    node_address: &str,
    purpose: KeyPurpose,
    algorithm: &str,
    key_id: Option<&str>,
    public: Option<&[u8]>,
) -> Result<(), String> {
    metadata.validate()?;
    if metadata.node_address.as_str() != node_address
        || metadata.record.purpose != purpose
        || metadata.algorithm != algorithm
        || key_id.is_some_and(|id| metadata.record.id.as_str() != id)
        || public.is_some_and(|bytes| metadata.record.public_key != bytes)
    {
        return Err(
            "public custody identity, purpose, algorithm or governed key binding differs".into(),
        );
    }
    if algorithm == "ML-DSA-65" {
        mldsa65::PublicKey::from_bytes(&metadata.record.public_key)
            .map_err(|_| "invalid ML-DSA-65 custody public key")?;
    }
    Ok(())
}

fn bind_expected_root(expected: &mut String, derived: String) -> Result<(), String> {
    if !expected.is_empty() && *expected != derived {
        return Err("explicit expected governed root differs from deterministic derivation".into());
    }
    *expected = derived;
    Ok(())
}

fn validate_input(mut input: PrepareAuthorityInput) -> Result<AuthorityPayload, String> {
    let authority = &mut input.authority;
    if authority.epoch_start_height != 1 || authority.anchor_parent.height() != 0 {
        return Err("fresh authority must start at H1 from explicit Genesis H0".into());
    }
    let registry = FrozenValidatorRegistry::new(
        authority.epoch,
        authority
            .validators
            .iter()
            .map(|v| v.record.clone())
            .collect(),
    )
    .map_err(|error| error.to_string())?;
    if registry.active_count() != authority.validators.len()
        || input.validators.len() != registry.active_count()
    {
        return Err("fresh public custody must cover exactly the active validator set".into());
    }
    let policy = authority
        .protected
        .as_mut()
        .ok_or("fresh authority requires complete protected policy")?;
    bind_expected_root(
        &mut policy.assigned_cluster_membership_root,
        registry.active_set_root().map_err(|e| e.to_string())?,
    )?;
    policy
        .ingress_kem_registry
        .validate_protected_profile()
        .map_err(|e| format!("governed ingress profile: {e:?}"))?;
    policy
        .ingress_kem_registry
        .root()
        .map_err(|e| format!("governed ingress root: {e:?}"))?;
    bind_expected_root(
        &mut authority.consensus_parameter_root,
        policy.commitment()?,
    )?;
    authority.validate()?;
    let policy = authority.protected.as_ref().unwrap();
    let mut seen = BTreeSet::new();
    for custody in &input.validators {
        if !custody.public_identity_path.is_absolute() {
            return Err("public identity path must be absolute".into());
        }
        let identity: PublicNodeIdentity = serde_json::from_slice(&read_bounded(
            &custody.public_identity_path,
            MAX_METADATA_BYTES,
            "public node identity",
        )?)
        .map_err(|error| format!("decode public identity: {error}"))?;
        let identity = identity
            .validate()
            .map_err(|error| format!("invalid public identity: {error:?}"))?;
        let address = identity.node_address.as_str();
        if !valid_consensus_node_address(address) {
            return Err("fresh validator custody requires a canonical synv1 node address".into());
        }
        if !seen.insert(address.to_owned()) {
            return Err("duplicate public custody node identity".into());
        }
        let validator = authority
            .validators
            .iter()
            .find(|v| v.record.validator_id == address)
            .ok_or("public custody node identity is outside governed membership")?;
        let p2p = public_bundle(&custody.p2p)?;
        check_binding(
            &p2p,
            address,
            KeyPurpose::P2pIdentity,
            "ML-DSA-65",
            None,
            None,
        )?;
        if p2p.public_key_fingerprint != identity.public_key_fingerprint {
            return Err("public identity fingerprint differs from P2P custody".into());
        }
        let consensus = public_bundle(&custody.consensus)?;
        check_binding(
            &consensus,
            address,
            KeyPurpose::PosyConsensus,
            "ML-DSA-65",
            Some(&validator.record.consensus_key_id),
            Some(&validator.public_key),
        )?;
        let ingress = public_bundle(&custody.ingress)?;
        let key = policy
            .ingress_kem_registry
            .records
            .iter()
            .find(|key| {
                key.validator_id == address
                    && key.activation_height <= 3
                    && key.retirement_height.is_none_or(|end| 3 < end)
            })
            .ok_or("no governed ingress key covers initial protected H3")?;
        check_binding(
            &ingress,
            address,
            KeyPurpose::EtdagDecryption,
            "ML-KEM-1024",
            Some(&key.key_id),
            Some(&key.public_key.public_key),
        )?;
        if [
            p2p.record.id.as_str(),
            consensus.record.id.as_str(),
            ingress.record.id.as_str(),
        ]
        .into_iter()
        .collect::<BTreeSet<_>>()
        .len()
            != 3
        {
            return Err(
                "distinct P2P, consensus and ingress key purposes require distinct key IDs".into(),
            );
        }
    }
    Ok(input.authority)
}

pub fn prepare(input: &Path, output: &Path) -> Result<(), String> {
    let request = serde_json::from_slice(&read_bounded(
        input,
        MAX_METADATA_BYTES,
        "fresh authority input",
    )?)
    .map_err(|error| format!("decode explicit fresh authority input: {error}"))?;
    let authority = validate_input(request)?;
    authority.signing_bytes()?;
    write_public_json(output, &authority)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use synergy_aegis::{KeyId, KeyRecord, KeyState};
    fn metadata() -> KeyMetadata {
        let address = synergy_address::derive_key_controlled_address(
            "synv1",
            &vec![42; synergy_address::FN_DSA_1024_PUBLIC_KEY_BYTES],
        )
        .unwrap();
        KeyMetadata::new(
            synergy_identity::NodeAddress::parse(address).unwrap(),
            KeyRecord {
                id: KeyId::new("consensus").unwrap(),
                purpose: KeyPurpose::PosyConsensus,
                state: KeyState::Generated,
                public_key: vec![1; mldsa65::public_key_bytes()],
            },
            "ML-DSA-65",
        )
        .unwrap()
    }
    #[test]
    fn explicit_public_binding_rejects_wrong_identity_purpose_key_and_expected_root() {
        let metadata = metadata();
        let address = metadata.node_address.as_str();
        let check = |address, purpose, key, public| {
            check_binding(
                &metadata,
                address,
                purpose,
                "ML-DSA-65",
                Some(key),
                Some(public),
            )
        };
        assert!(check(
            address,
            KeyPurpose::PosyConsensus,
            "consensus",
            &metadata.record.public_key
        )
        .is_ok());
        assert!(check(
            "outside-membership",
            KeyPurpose::PosyConsensus,
            "consensus",
            &metadata.record.public_key
        )
        .is_err());
        assert!(check(
            address,
            KeyPurpose::P2pIdentity,
            "consensus",
            &metadata.record.public_key
        )
        .is_err());
        assert!(check(
            address,
            KeyPurpose::PosyConsensus,
            "other",
            &metadata.record.public_key
        )
        .is_err());
        assert!(check(address, KeyPurpose::PosyConsensus, "consensus", &[2; 1952]).is_err());
        let mut expected = String::new();
        bind_expected_root(&mut expected, "derived".into()).unwrap();
        assert_eq!(expected, "derived");
        assert!(bind_expected_root(&mut expected, "different".into()).is_err());
        assert_eq!(expected, "derived");
    }
    #[test]
    fn unsigned_output_refuses_overwrite() {
        let dir =
            std::env::temp_dir().join(format!("synergy-prepare-authority-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let output = dir.join("unsigned.json");
        write_public_json(&output, &serde_json::json!({"explicit": true})).unwrap();
        let original = std::fs::read(&output).unwrap();
        assert!(write_public_json(&output, &serde_json::json!({"explicit": false})).is_err());
        assert_eq!(std::fs::read(&output).unwrap(), original);
        std::fs::remove_dir_all(dir).unwrap();
    }
    pub(crate) fn genesis_recipe() -> serde_json::Value {
        let ids = (0..5)
            .map(|i| {
                synergy_address::derive_key_controlled_address("synv1", &vec![i + 1; 1793]).unwrap()
            })
            .collect::<Vec<_>>();
        let validators = ids.iter().enumerate().map(|(i,id)| serde_json::json!({
            "record":{"validator_id":id,"consensus_key_id":format!("consensus-{i}"),"frozen_voting_weight":100,"status":"active"},
            "algorithm":"ml_dsa65","public_key":vec![1; mldsa65::public_key_bytes()]
        })).collect::<Vec<_>>();
        let keys = ids.iter().enumerate().map(|(i,id)| serde_json::json!({
            "key_id":format!("ingress-{i}"),"validator_id":id,"activation_height":1,"retirement_height":null,
            "public_key":{"algorithm":"ML-KEM-1024","public_key":vec![1; aegis_pqvm::pqc::kem::mlkem::mlkem1024::public_key_bytes()]}
        })).collect::<Vec<_>>();
        serde_json::json!({
            "authority":{"version":1,"chain_id":1266,"network_id":"stability-fixture","epoch":1,"epoch_start_height":1,
                "epoch_end_height":1000,"finalized_epoch_seed_root":"","consensus_parameter_root":"","validators":validators,
                "anchor_parent":{"kind":"genesis","reference":{"genesis_hash":"","block_id":"","reference_id":""}},
                "protected":{"version":1,"cutoff_relationship":"vc_event_context_v1","epoch_start_timestamp_ms":1700000000000u64,
                    "target_block_time_ms":1000,"parameters":{"profile_id":"POSY-ETDAG-v3.0","target_height_offset":5,
                        "max_outstanding_nonce_slots":4,"ciphertext_size_classes":[512,1024,2048,4096,8192,16384,32768,65536,131072],
                        "max_protected_gas":30000000,"max_protected_bytes":8388608},
                    "initial_world_state":{"accounts":{},"protocol":{}},"cryptographic_profile_root":"",
                    "ingress_kem_registry":{"context_root":"","records":keys},"cluster_schedule_version":"",
                    "assigned_height_schedule_root":"","cluster_map_root":"","assigned_cluster_id":0,"assigned_cluster_membership_root":""}},
            "validators":[],"network":{"chain_id":1266,"network_id":"stability-fixture","protocol_version":"posy/3.0","activation_unix":1700000000},
            "authority_trust_key_id":"authority-root","seed_source":{"kind":"genesis_hash"}
        })
    }

    #[test]
    fn public_genesis_derives_actual_state_genesis_anchor_and_descriptors() {
        let recipe = genesis_recipe();
        let (genesis, derived) =
            derive_genesis(serde_json::from_value(recipe.clone()).unwrap()).unwrap();
        let (_, second) = derive_genesis(serde_json::from_value(recipe).unwrap()).unwrap();
        let policy = derived.authority.protected.as_ref().unwrap();
        assert_eq!(
            genesis.initial_state_root,
            synergy_genesis::state_root(&policy.initial_world_state).unwrap()
        );
        assert_eq!(genesis.validators.len(), 5);
        assert!(genesis
            .validators
            .iter()
            .all(|v| v.record.frozen_voting_weight == 100));
        let expected = genesis.genesis_hash().unwrap();
        match &derived.authority.anchor_parent {
            synergy_posy::SimplifiedFinalityParent::Genesis {
                genesis_hash,
                block_id,
                ..
            } => {
                assert_eq!(genesis_hash, &expected);
                assert_eq!(block_id, &expected);
            }
            _ => panic!("fresh recipe produced non-Genesis anchor"),
        }
        assert_eq!(
            derived.authority.consensus_parameter_root,
            policy.commitment().unwrap()
        );
        assert_eq!(
            derived.authority.signing_bytes().unwrap(),
            second.authority.signing_bytes().unwrap()
        );
        assert_ne!(
            policy.cluster_map_root,
            policy.assigned_height_schedule_root
        );
    }

    #[test]
    fn legacy_public_release_recipe_preserves_exact_genesis_and_authority_bytes() {
        // Existing public release artifacts are the pre-async compatibility fixture.
        // Derivation does not open their host custody paths or use private material.
        let mut input: PrepareGenesisInput = serde_json::from_str(include_str!(
            "../../../networks/testnet/posy-stability/fresh-genesis-input.json"
        ))
        .unwrap();
        input.genesis_format_version = 1;
        let (genesis, derived) = derive_genesis(input).unwrap();
        let previous_genesis: synergy_genesis::builder::UnsignedGenesis = serde_json::from_str(
            include_str!("../../../networks/testnet/posy-stability/unsigned-genesis.json"),
        )
        .unwrap();
        let previous_authority: AuthorityPayload = serde_json::from_str(include_str!(
            "../../../networks/testnet/posy-stability/unsigned-authority.json"
        ))
        .unwrap();
        assert_eq!(
            genesis.canonical_bytes().unwrap(),
            previous_genesis.canonical_bytes().unwrap()
        );
        assert_eq!(
            derived.authority.signing_bytes().unwrap(),
            previous_authority.signing_bytes().unwrap()
        );
    }

    #[test]
    fn processing_recipe_binds_native_versions_without_changing_membership_or_parameters() {
        let recipe = genesis_recipe();
        let (legacy_genesis, legacy) =
            derive_genesis(serde_json::from_value(recipe.clone()).unwrap()).unwrap();
        let mut processing = recipe;
        processing["authority"]["protected"]["version"] = serde_json::json!(2);
        processing["authority"]["protected"]["cutoff_relationship"] =
            serde_json::json!("processing_groups_v1");
        let (genesis, derived) =
            derive_genesis(serde_json::from_value(processing.clone()).unwrap()).unwrap();
        let (_, again) =
            derive_genesis(serde_json::from_value(processing.clone()).unwrap()).unwrap();
        let policy = derived.authority.protected.as_ref().unwrap();
        let old = legacy.authority.protected.as_ref().unwrap();
        assert_eq!(genesis.validators, legacy_genesis.validators);
        assert_eq!(
            genesis.initial_state_root,
            legacy_genesis.initial_state_root
        );
        assert_eq!(
            serde_json::to_vec(&policy.parameters).unwrap(),
            serde_json::to_vec(&old.parameters).unwrap()
        );
        assert_eq!(policy.cluster_map_root, old.cluster_map_root);
        assert_eq!(
            policy.cluster_schedule_version,
            "single-cluster-processing-groups-v1"
        );
        assert_ne!(
            policy.cryptographic_profile_root,
            old.cryptographic_profile_root
        );
        assert_ne!(
            policy.assigned_height_schedule_root,
            old.assigned_height_schedule_root
        );
        assert_ne!(
            genesis.genesis_hash().unwrap(),
            legacy_genesis.genesis_hash().unwrap()
        );
        assert_eq!(
            derived.authority.signing_bytes().unwrap(),
            again.authority.signing_bytes().unwrap()
        );
        derived.authority.validate().unwrap();
        let expected = ProcessingScheduleDescriptor {
            version: 1,
            chain_id: 1266,
            network_id: "stability-fixture",
            epoch: 1,
            epoch_start_height: 1,
            epoch_end_height: 1000,
            assigned_cluster_id: 0,
            cluster_map_root: &policy.cluster_map_root,
            processing_profile_id: synergy_etdag::PROCESSING_PROFILE_ID,
            authorization_height_offset: 5,
            authorization_anchor_is_inclusion_deadline: false,
            cutoff_relationship: "processing_groups_v1",
        };
        assert_eq!(
            policy.assigned_height_schedule_root,
            synergy_posy::canonical_hash(PROCESSING_SCHEDULE_DOMAIN, &expected).unwrap()
        );
        // Legacy expected roots or schedule names cannot be relabeled as async.
        for (field, stale) in [
            (
                "cryptographic_profile_root",
                old.cryptographic_profile_root.clone(),
            ),
            (
                "assigned_height_schedule_root",
                old.assigned_height_schedule_root.clone(),
            ),
            (
                "cluster_schedule_version",
                old.cluster_schedule_version.clone(),
            ),
        ] {
            let mut invalid = processing.clone();
            invalid["authority"]["protected"][field] = serde_json::json!(stale);
            assert!(
                derive_genesis(serde_json::from_value(invalid).unwrap()).is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn public_genesis_rejects_unsupported_policy_version_relationship_pairs() {
        for (version, relationship) in [
            (1, "processing_groups_v1"),
            (2, "vc_event_context_v1"),
            (3, "processing_groups_v1"),
            (3, "vc_event_context_v1"),
        ] {
            let mut recipe = genesis_recipe();
            recipe["authority"]["protected"]["version"] = serde_json::json!(version);
            recipe["authority"]["protected"]["cutoff_relationship"] =
                serde_json::json!(relationship);
            assert_eq!(
                derive_genesis(serde_json::from_value(recipe).unwrap())
                    .err()
                    .unwrap(),
                "unsupported protected policy version/cutoff relationship"
            );
        }
    }

    #[test]
    fn public_genesis_refuses_inconsistent_expected_roots_and_activation() {
        for path in [
            "cryptographic_profile_root",
            "cluster_map_root",
            "assigned_height_schedule_root",
        ] {
            let mut value = genesis_recipe();
            value["authority"]["protected"][path] = serde_json::json!("a".repeat(64));
            assert!(
                derive_genesis(serde_json::from_value(value).unwrap()).is_err(),
                "{path}"
            );
        }
        let mut value = genesis_recipe();
        value["authority"]["anchor_parent"]["reference"]["genesis_hash"] =
            serde_json::json!("a".repeat(64));
        assert!(derive_genesis(serde_json::from_value(value).unwrap()).is_err());
        let mut value = genesis_recipe();
        value["network"]["activation_unix"] = serde_json::json!(1700000001);
        assert!(derive_genesis(serde_json::from_value(value).unwrap()).is_err());
        let mut value = genesis_recipe();
        value["authority"]["validators"][0]["record"]["frozen_voting_weight"] =
            serde_json::json!(99);
        assert!(derive_genesis(serde_json::from_value(value).unwrap()).is_err());
    }

    #[test]
    fn explicit_world_state_and_seed_choice_are_bound() {
        let (original, _) =
            derive_genesis(serde_json::from_value(genesis_recipe()).unwrap()).unwrap();
        let mut changed = genesis_recipe();
        changed["authority"]["protected"]["initial_world_state"]["protocol"]["fixture-config"] =
            serde_json::json!([1]);
        let (updated, _) = derive_genesis(serde_json::from_value(changed).unwrap()).unwrap();
        assert_ne!(original.initial_state_root, updated.initial_state_root);
        assert_ne!(
            original.genesis_hash().unwrap(),
            updated.genesis_hash().unwrap()
        );
        let mut explicit = genesis_recipe();
        explicit["seed_source"] =
            serde_json::json!({"kind":"provided_expected","root":"a".repeat(64)});
        explicit["authority"]["finalized_epoch_seed_root"] = serde_json::json!("a".repeat(64));
        let (_, derived) =
            derive_genesis(serde_json::from_value(explicit.clone()).unwrap()).unwrap();
        assert_eq!(derived.authority.finalized_epoch_seed_root, "a".repeat(64));
        explicit["authority"]["finalized_epoch_seed_root"] = serde_json::json!("b".repeat(64));
        assert!(derive_genesis(serde_json::from_value(explicit).unwrap()).is_err());
    }

    #[test]
    fn public_genesis_output_pair_refuses_overwrite_before_input_read() {
        let dir = std::env::temp_dir().join(format!(
            "synergy-genesis-nooverwrite-{}",
            std::process::id()
        ));
        std::fs::create_dir(&dir).unwrap();
        let genesis = dir.join("genesis.json");
        let authority = dir.join("authority.json");
        std::fs::write(&authority, b"original").unwrap();
        assert!(prepare_genesis(&dir.join("missing-input"), &genesis, &authority).is_err());
        assert!(!genesis.exists());
        assert_eq!(std::fs::read(&authority).unwrap(), b"original");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
