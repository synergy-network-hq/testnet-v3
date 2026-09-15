//! Verified frozen PoSy/ETDAG authority shared by protocol owners.
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use synergy_aegis::{
    AegisPolicy, AegisVerifier, KeyId, PqvmVerifier, Signature, SignatureAlgorithm, SigningContext,
};
use synergy_config::{ConsensusConfiguration, NodeConfiguration};
use synergy_data_availability::ProofVerifier;
use synergy_etdag::crypto::SignatureVerifier as EtdagSignatureVerifier;
use synergy_etdag::EtdagError;
use synergy_governance::{GovernanceVote, VoteVerifier};
use synergy_posy::{
    ConsensusSignatureVerifier, EpochTransitionAuthorization, FinalizedBlockRecord,
    FrozenValidatorRegistry, PosyError, PosyResult, SimplifiedEpochContext,
    SimplifiedFinalityParent, SimplifiedQuorumCertificate, ThreeQcFinality, ValidatorRecord,
};
use synergy_storage::{AtomicStore, NodeStorageLayout};
use synergy_sxcp::{SxcpExecutionAuthorizationVerifier, SxcpRelayExecution};

const MAX_AUTHORITY_BYTES: u64 = 1024 * 1024;
const MAX_TRUST_KEY_BYTES: u64 = 8 * 1024;
const MAX_CONSENSUS_MESSAGE_BYTES: usize = 1024 * 1024;
const AUTHORITY_DOMAIN: &[u8] = b"SYNERGY-POSY-AUTHORITY-BINDING-V1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityValidator {
    record: ValidatorRecord,
    algorithm: SignatureAlgorithm,
    public_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityPayload {
    version: u32,
    chain_id: u64,
    network_id: String,
    epoch: u64,
    epoch_start_height: u64,
    epoch_end_height: u64,
    finalized_epoch_seed_root: String,
    consensus_parameter_root: String,
    validators: Vec<AuthorityValidator>,
    anchor_parent: SimplifiedFinalityParent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedAuthorityBinding {
    payload: AuthorityPayload,
    signer_key_id: String,
    signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredEpochTransition {
    version: u32,
    next_epoch: u64,
    previous_authority_binding: Vec<u8>,
    finalized: FinalizedBlockRecord,
    finality_witness: Vec<u8>,
}

#[derive(Debug, Clone)]
struct ConsensusKey {
    validator: ValidatorRecord,
    algorithm: SignatureAlgorithm,
    public_key: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct VerifiedAuthority {
    pub registry: FrozenValidatorRegistry,
    pub epoch: SimplifiedEpochContext,
    pub anchor_parent: SimplifiedFinalityParent,
    verifier: PqvmVerifier,
    keys: BTreeMap<String, ConsensusKey>,
    chain_id: u64,
    binding_bytes: Vec<u8>,
}

impl VerifiedAuthority {
    pub fn consensus_binding(&self, validator_id: &str) -> Result<(&str, &[u8]), String> {
        let key = self
            .keys
            .get(validator_id)
            .ok_or_else(|| format!("validator {validator_id} has no frozen consensus key"))?;
        if key.algorithm != SignatureAlgorithm::MlDsa65 || !key.validator.may_sign_consensus() {
            return Err(format!(
                "validator {validator_id} has no active ML-DSA-65 authority"
            ));
        }
        Ok((
            key.validator.consensus_key_id.as_str(),
            key.public_key.as_slice(),
        ))
    }

    pub fn binding_bytes(&self) -> &[u8] {
        &self.binding_bytes
    }
}

#[derive(Debug, Clone, Default)]
pub struct AuthorityTransitionSignal {
    pending_epoch: Arc<Mutex<Option<u64>>>,
}

impl AuthorityTransitionSignal {
    pub fn stage(&self, epoch: u64) -> Result<(), String> {
        let mut pending = self
            .pending_epoch
            .lock()
            .map_err(|_| "authority transition signal lock is poisoned")?;
        match *pending {
            Some(existing) if existing != epoch => {
                Err("a different authority transition is already pending".into())
            }
            _ => {
                *pending = Some(epoch);
                Ok(())
            }
        }
    }

    pub fn take(&self) -> Result<Option<u64>, String> {
        self.pending_epoch
            .lock()
            .map(|mut pending| pending.take())
            .map_err(|_| "authority transition signal lock is poisoned".into())
    }
}

impl AegisVerifier for VerifiedAuthority {
    fn verify(
        &self,
        context: &SigningContext,
        message: &[u8],
        signature: &Signature,
        public_key: &[u8],
    ) -> Result<(), synergy_aegis::VerificationError> {
        self.verifier
            .verify(context, message, signature, public_key)
    }
}

impl ProofVerifier for VerifiedAuthority {
    fn governed_public_key(&self, key_id: &KeyId) -> Result<Vec<u8>, String> {
        self.keys
            .values()
            .find(|key| {
                key.validator.consensus_key_id == key_id.as_str()
                    && key.algorithm == SignatureAlgorithm::MlDsa65
                    && key.validator.may_sign_consensus()
            })
            .map(|key| key.public_key.clone())
            .ok_or_else(|| {
                format!(
                    "key {} is not governed active validator authority",
                    key_id.as_str()
                )
            })
    }
}

fn read_bounded(path: &std::path::Path, maximum: u64, label: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {label} {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(format!(
            "{label} must be a bounded regular non-symlink file"
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .and_then(|file| file.take(maximum + 1).read_to_end(&mut bytes))
        .map_err(|error| format!("read {label} {}: {error}", path.display()))?;
    if bytes.is_empty() || bytes.len() as u64 > maximum {
        return Err(format!("{label} changed size while loading"));
    }
    Ok(bytes)
}

pub fn load(configuration: &NodeConfiguration) -> Result<Option<Arc<VerifiedAuthority>>, String> {
    let Some(binding_path) = configuration.consensus.authority_binding.as_ref() else {
        return Ok(None);
    };
    if configuration.consensus.authority_trust_key_path.is_none() {
        return Ok(None);
    }
    let bytes = read_bounded(binding_path, MAX_AUTHORITY_BYTES, "PoSy authority binding")?;
    verify_binding_bytes(configuration, bytes).map(Some)
}

pub fn verify_binding_bytes(
    configuration: &NodeConfiguration,
    bytes: Vec<u8>,
) -> Result<Arc<VerifiedAuthority>, String> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_AUTHORITY_BYTES {
        return Err("PoSy authority binding exceeds its canonical bound".into());
    }
    let trust_path = configuration
        .consensus
        .authority_trust_key_path
        .as_ref()
        .ok_or("PoSy authority verification requires authority_trust_key_path")?;
    let binding: SignedAuthorityBinding = serde_json::from_slice(&bytes)
        .map_err(|error| format!("decode PoSy authority binding: {error}"))?;
    if binding.payload.version != 1
        || binding.payload.chain_id != configuration.chain_id
        || binding.payload.network_id != configuration.network_id
        || binding.signature.is_empty()
        || binding.signature.len() > 16 * 1024
    {
        return Err("PoSy authority binding is incompatible or malformed".into());
    }
    let trust_key = read_bounded(trust_path, MAX_TRUST_KEY_BYTES, "authority trust key")?;
    let signer_key_id = KeyId::new(binding.signer_key_id.clone())
        .map_err(|error| format!("invalid authority signer key id: {error}"))?;
    let policy = AegisPolicy {
        allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
        maximum_message_bytes: MAX_CONSENSUS_MESSAGE_BYTES,
        maximum_signature_bytes: 16 * 1024,
    };
    let verifier = PqvmVerifier::new(policy).map_err(|error| error.to_string())?;
    let payload = serde_json::to_vec(&binding.payload)
        .map_err(|error| format!("encode canonical authority payload: {error}"))?;
    let mut signing_bytes = Vec::with_capacity(AUTHORITY_DOMAIN.len() + payload.len());
    signing_bytes.extend_from_slice(AUTHORITY_DOMAIN);
    signing_bytes.extend_from_slice(&payload);
    verifier
        .verify(
            &SigningContext {
                domain: "SYNERGY-POSY-AUTHORITY-BINDING-V1".into(),
                chain_id: configuration.chain_id,
                epoch: Some(binding.payload.epoch),
                height: None,
            },
            &signing_bytes,
            &Signature {
                algorithm: SignatureAlgorithm::MlDsa65,
                key_id: signer_key_id,
                bytes: binding.signature,
            },
            &trust_key,
        )
        .map_err(|error| format!("verify PoSy authority binding: {error}"))?;

    let mut records = Vec::with_capacity(binding.payload.validators.len());
    let mut keys = BTreeMap::new();
    for authority in binding.payload.validators {
        authority
            .record
            .validate()
            .map_err(|error| error.to_string())?;
        if authority.algorithm != SignatureAlgorithm::MlDsa65 || authority.public_key.is_empty() {
            return Err("authority binding contains an unsupported consensus key".into());
        }
        if keys
            .insert(
                authority.record.validator_id.clone(),
                ConsensusKey {
                    validator: authority.record.clone(),
                    algorithm: authority.algorithm,
                    public_key: authority.public_key,
                },
            )
            .is_some()
        {
            return Err("authority binding contains a duplicate validator".into());
        }
        records.push(authority.record);
    }
    let registry = FrozenValidatorRegistry::new(binding.payload.epoch, records)
        .map_err(|error| error.to_string())?;
    let epoch = SimplifiedEpochContext::from_frozen_registry(
        binding.payload.chain_id,
        binding.payload.network_id,
        binding.payload.epoch,
        binding.payload.epoch_start_height,
        binding.payload.epoch_end_height,
        binding.payload.finalized_epoch_seed_root,
        binding.payload.consensus_parameter_root,
        &registry,
    )
    .map_err(|error| error.to_string())?;
    binding
        .payload
        .anchor_parent
        .validate_for_child_height(epoch.epoch_start_height)
        .map_err(|error| error.to_string())?;
    Ok(Arc::new(VerifiedAuthority {
        registry,
        epoch,
        anchor_parent: binding.payload.anchor_parent,
        verifier,
        keys,
        chain_id: configuration.chain_id,
        binding_bytes: bytes,
    }))
}

fn verify_transition_witness(
    previous: &VerifiedAuthority,
    finalized: &FinalizedBlockRecord,
    finality_witness: &[u8],
) -> Result<[SimplifiedQuorumCertificate; 3], String> {
    if finalized.height.checked_add(2) != Some(previous.epoch.epoch_end_height) {
        return Err(
            "authority transition requires finality closed by the epoch-boundary QC".into(),
        );
    }
    if finality_witness.is_empty() || finality_witness.len() > MAX_CONSENSUS_MESSAGE_BYTES {
        return Err("authority transition finality witness is missing or oversized".into());
    }
    let certificates: [SimplifiedQuorumCertificate; 3] =
        serde_json::from_slice(finality_witness)
            .map_err(|error| format!("decode authority transition finality witness: {error}"))?;
    let mut finality = ThreeQcFinality::default();
    for certificate in &certificates {
        certificate
            .verify(&previous.epoch, &previous.registry, previous)
            .map_err(|error| format!("verify authority transition QC: {error}"))?;
        finality
            .accept(certificate.clone())
            .map_err(|error| format!("verify authority transition ancestry: {error}"))?;
    }
    if finality.last_finalized() != Some(finalized) {
        return Err("authority transition witness differs from local finalized record".into());
    }
    Ok(certificates)
}

pub fn load_transition_finality_prefix(
    configuration: &NodeConfiguration,
    current: &VerifiedAuthority,
) -> Result<Option<(FinalizedBlockRecord, [SimplifiedQuorumCertificate; 3])>, String> {
    if current.epoch.epoch <= 1 {
        return Ok(None);
    }
    let layout = NodeStorageLayout::new(configuration.storage.data_directory.clone())
        .map_err(|error| format!("construct canonical storage layout: {error}"))?;
    let store = AtomicStore::new(
        layout.consensus().join("authority-transitions"),
        4 * 1024 * 1024,
    )
    .map_err(|error| format!("open authority transition store: {error}"))?;
    let path = format!("epoch-{:020}.json", current.epoch.epoch);
    if !store.exists(&path).map_err(|error| error.to_string())? {
        return Err(format!(
            "successor epoch {} lacks its verified transition witness",
            current.epoch.epoch
        ));
    }
    let bytes = store
        .read_bounded(&path)
        .map_err(|error| format!("read authority transition witness: {error}"))?;
    let stored: StoredEpochTransition = serde_json::from_slice(&bytes)
        .map_err(|error| format!("decode authority transition witness: {error}"))?;
    if stored.version != 1 || stored.next_epoch != current.epoch.epoch {
        return Err("stored authority transition identifies a different epoch".into());
    }
    let previous = verify_binding_bytes(configuration, stored.previous_authority_binding)?;
    if previous.epoch.epoch.saturating_add(1) != current.epoch.epoch {
        return Err("stored authority transition is not sequential".into());
    }
    let certificates = verify_transition_witness(
        previous.as_ref(),
        &stored.finalized,
        &stored.finality_witness,
    )?;
    let boundary = certificates
        .last()
        .ok_or("stored authority transition has no boundary QC")?;
    let boundary_reference = boundary.reference().map_err(|error| error.to_string())?;
    if current
        .anchor_parent
        .quorum_certificate_reference()
        .as_ref()
        != Some(&boundary_reference)
    {
        return Err("stored authority transition differs from current anchor".into());
    }
    Ok(Some((stored.finalized, certificates)))
}

pub fn verify_and_persist_transition(
    configuration: &NodeConfiguration,
    current: &VerifiedAuthority,
    finalized: &FinalizedBlockRecord,
    finality_witness: &[u8],
    next_binding_bytes: Vec<u8>,
    signal: &AuthorityTransitionSignal,
) -> Result<Arc<VerifiedAuthority>, String> {
    let certificates = verify_transition_witness(current, finalized, finality_witness)?;
    let boundary = certificates
        .last()
        .ok_or("authority transition witness has no boundary QC")?;
    let boundary_qc_id = boundary.id().map_err(|error| error.to_string())?;
    let next = verify_binding_bytes(configuration, next_binding_bytes.clone())?;
    match &next.anchor_parent {
        SimplifiedFinalityParent::QuorumCertificate {
            height,
            block_id,
            qc_id,
        } if *height == boundary.context.height
            && block_id == &boundary.block_id
            && qc_id == &boundary_qc_id => {}
        _ => {
            return Err(
                "next authority anchor does not match the verified epoch-boundary QC".into(),
            )
        }
    }
    let authorization = EpochTransitionAuthorization {
        previous_epoch: current.epoch.epoch,
        previous_epoch_context_root: current.epoch.root().map_err(|error| error.to_string())?,
        finalized_height: finalized.height,
        next_epoch: next.epoch.epoch,
        next_epoch_start_height: next.epoch.epoch_start_height,
        next_epoch_end_height: next.epoch.epoch_end_height,
        next_consensus_parameter_root: next.epoch.consensus_parameter_root.clone(),
        next_active_validator_set_root: next.epoch.active_validator_set_root.clone(),
        next_validator_consensus_key_root: next.epoch.validator_consensus_key_root.clone(),
        next_frozen_voting_weight_root: next.epoch.frozen_voting_weight_root.clone(),
    };
    authorization
        .validate(&current.epoch, &next.epoch, &next.registry)
        .map_err(|error| format!("validate finalized authority transition: {error}"))?;
    let layout = NodeStorageLayout::new(configuration.storage.data_directory.clone())
        .map_err(|error| format!("construct canonical storage layout: {error}"))?;
    let transition_store = AtomicStore::new(
        layout.consensus().join("authority-transitions"),
        4 * 1024 * 1024,
    )
    .map_err(|error| format!("open authority transition store: {error}"))?;
    let transition = StoredEpochTransition {
        version: 1,
        next_epoch: next.epoch.epoch,
        previous_authority_binding: current.binding_bytes.clone(),
        finalized: finalized.clone(),
        finality_witness: finality_witness.to_vec(),
    };
    transition_store
        .write_atomic(
            &format!("epoch-{:020}.json", next.epoch.epoch),
            &serde_json::to_vec(&transition)
                .map_err(|error| format!("encode authority transition witness: {error}"))?,
        )
        .map_err(|error| format!("persist authority transition witness: {error}"))?;
    persist_binding(configuration, &next_binding_bytes, next.epoch.epoch)?;
    signal.stage(next.epoch.epoch)?;
    Ok(next)
}

fn persist_binding(
    configuration: &NodeConfiguration,
    bytes: &[u8],
    next_epoch: u64,
) -> Result<(), String> {
    let path = configuration
        .consensus
        .authority_binding
        .as_ref()
        .ok_or("authority transition requires authority_binding path")?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect current authority binding: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("authority binding target must be a regular non-symlink file".into());
    }
    let parent = path
        .parent()
        .ok_or("authority binding path has no parent directory")?;
    let parent_metadata = fs::symlink_metadata(parent)
        .map_err(|error| format!("inspect authority binding directory: {error}"))?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err("authority binding parent must be a regular directory".into());
    }
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or("authority binding file name is invalid")?;
    let staging = parent.join(format!(
        ".{file_name}.epoch-{next_epoch}.{}.tmp",
        std::process::id()
    ));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&staging)
        .map_err(|error| format!("create authority transition staging file: {error}"))?;
    let write_result = file
        .write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("persist authority transition staging file: {error}"));
    drop(file);
    if let Err(error) = write_result {
        let _ = fs::remove_file(&staging);
        return Err(error);
    }
    if let Err(error) = fs::rename(&staging, path) {
        let _ = fs::remove_file(&staging);
        return Err(format!("commit authority transition binding: {error}"));
    }
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("sync authority transition directory: {error}"))
}

impl SxcpExecutionAuthorizationVerifier for VerifiedAuthority {
    fn verify_execution_authorization(&self, execution: &SxcpRelayExecution) -> Result<(), String> {
        let transcript = execution.signing_bytes()?;
        let mut signers = Vec::with_capacity(execution.signatures.len());
        let mut seen = std::collections::BTreeSet::new();
        for signature in &execution.signatures {
            if !seen.insert(signature.validator_id.as_str()) {
                return Err("SXCP authorization repeats a validator".into());
            }
            let key = self
                .keys
                .get(&signature.validator_id)
                .ok_or("SXCP authorization signer is not frozen authority")?;
            if key.validator.consensus_key_id != signature.key_id
                || key.algorithm != SignatureAlgorithm::MlDsa65
                || !key.validator.may_sign_consensus()
            {
                return Err("SXCP authorization uses a non-authoritative key".into());
            }
            let key_id = KeyId::new(signature.key_id.clone()).map_err(|error| error.to_string())?;
            self.verifier
                .verify(
                    &SigningContext {
                        domain: "SYNERGY-SXCP-RELAY-AUTHORIZATION-V1".into(),
                        chain_id: self.chain_id,
                        epoch: Some(self.epoch.epoch),
                        height: None,
                    },
                    &transcript,
                    &Signature {
                        algorithm: SignatureAlgorithm::MlDsa65,
                        key_id,
                        bytes: signature.signature.clone(),
                    },
                    &key.public_key,
                )
                .map_err(|error| format!("verify Aegis SXCP authorization: {error}"))?;
            signers.push(signature.validator_id.clone());
        }
        synergy_posy::verify_strict_dual_quorum(&self.registry.quorum_validators(), &signers)
            .map_err(|error| format!("SXCP authorization lacks frozen dual quorum: {error:?}"))
    }
}

impl VoteVerifier for VerifiedAuthority {
    fn verify(&self, vote: &GovernanceVote) -> Result<(), String> {
        vote.validate_shape()?;
        let key = self
            .keys
            .get(&vote.authority_id)
            .ok_or("governance voter is not in frozen authority")?;
        if key.validator.consensus_key_id != vote.key_id
            || key.algorithm != SignatureAlgorithm::MlDsa65
            || !key.validator.may_sign_consensus()
        {
            return Err("governance vote key is not active frozen authority".into());
        }
        let key_id = KeyId::new(vote.key_id.clone()).map_err(|error| error.to_string())?;
        self.verifier
            .verify(
                &SigningContext {
                    domain: "SYNERGY-GOVERNANCE-VOTE-V1".into(),
                    chain_id: self.chain_id,
                    epoch: Some(self.epoch.epoch),
                    height: None,
                },
                &vote.signing_bytes()?,
                &Signature {
                    algorithm: SignatureAlgorithm::MlDsa65,
                    key_id,
                    bytes: vote.signature.clone(),
                },
                &key.public_key,
            )
            .map_err(|error| format!("verify Aegis governance vote: {error}"))
    }
}

impl ConsensusSignatureVerifier for VerifiedAuthority {
    fn verify_consensus_signature(
        &self,
        domain: &str,
        payload: &[u8],
        validator: &ValidatorRecord,
        key_id: &str,
        epoch: u64,
        signature: &[u8],
    ) -> PosyResult<()> {
        let key = self
            .keys
            .get(&validator.validator_id)
            .ok_or_else(|| PosyError::UnknownValidator(validator.validator_id.clone()))?;
        if &key.validator != validator
            || key.validator.consensus_key_id != key_id
            || key.algorithm != SignatureAlgorithm::MlDsa65
            || epoch != self.epoch.epoch
        {
            return Err(PosyError::invalid(
                "consensus signature authority binding mismatch",
            ));
        }
        let key_id = KeyId::new(key_id.to_string())
            .map_err(|error| PosyError::invalid(error.to_string()))?;
        self.verifier
            .verify(
                &SigningContext {
                    domain: domain.to_string(),
                    chain_id: self.chain_id,
                    epoch: Some(epoch),
                    height: None,
                },
                payload,
                &Signature {
                    algorithm: key.algorithm,
                    key_id,
                    bytes: signature.to_vec(),
                },
                &key.public_key,
            )
            .map_err(|error| PosyError::invalid(format!("Aegis consensus signature: {error}")))
    }
}

impl EtdagSignatureVerifier for VerifiedAuthority {
    fn verify(
        &self,
        validator_id: &str,
        key_id: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), EtdagError> {
        let key = self
            .keys
            .get(validator_id)
            .ok_or_else(|| EtdagError::UnauthorizedValidator(validator_id.into()))?;
        if key.validator.consensus_key_id != key_id
            || key.algorithm != SignatureAlgorithm::MlDsa65
            || !key.validator.may_sign_consensus()
        {
            return Err(EtdagError::UnauthorizedValidator(validator_id.into()));
        }
        let key_id = KeyId::new(key_id.to_string()).map_err(|_| EtdagError::InvalidSignature)?;
        self.verifier
            .verify(
                &SigningContext {
                    domain: "SYNERGY-ETDAG-SIGNATURE-V1".into(),
                    chain_id: self.chain_id,
                    epoch: Some(self.epoch.epoch),
                    height: None,
                },
                message,
                &Signature {
                    algorithm: key.algorithm,
                    key_id,
                    bytes: signature.to_vec(),
                },
                &key.public_key,
            )
            .map_err(|_| EtdagError::InvalidSignature)
    }
}
