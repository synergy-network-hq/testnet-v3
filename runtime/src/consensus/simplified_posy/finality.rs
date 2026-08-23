//! Replayable protected-execution authority for simplified PoSy finality.
//!
//! Each finalized transaction is stored as an immutable, non-overwriting WAL
//! record. The WAL embeds complete QC evidence and references immutable
//! content-addressed proposal-material records. Startup re-verifies both
//! layers and re-executes every block from the pinned activation boundary.

use super::{
    DurableSimplifiedProposalMaterialStore, FinalizedBlockRecord, SimplifiedEpochContext,
    SimplifiedFinalityParent, SimplifiedFinalizationReceipt, SimplifiedFinalizationSink,
    SimplifiedFinalizationSinkError, SimplifiedFinalizationTransaction,
    SimplifiedQuorumCertificate, VerifiedSimplifiedEpochTransition,
};
use crate::crypto::aegis_pqvm::AegisPqvmVerifier;
use crate::etdag::EtdagParameters;
use crate::execution::{compute_state_root_after, ExecutionState};
use crate::synergy_types::{CanonicalSerialize, ClusterMap, Hash, ValidatorSet};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

const POSY_SIMPLIFIED_FINALITY_METADATA_FORMAT: &str =
    "synergy-posy-simplified-finality-metadata-v3";
const POSY_SIMPLIFIED_FINALITY_WAL_FORMAT: &str = "synergy-posy-simplified-finality-wal-record-v2";
const POSY_SIMPLIFIED_FINALITY_DIRECTORY: &str = "data/posy-v3-finality";
const POSY_SIMPLIFIED_FINALITY_METADATA_FILE: &str = "metadata.json";
pub const MAX_POSY_SIMPLIFIED_FINALITY_WAL_RECORD_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SimplifiedFinalityMetadata {
    format: String,
    epoch_context_root: Hash,
    certified_parent: SimplifiedFinalityParent,
    finalized_seed: FinalizedBlockRecord,
    transition_subject_root: Option<Hash>,
    boundary_execution_state_root: Hash,
}

impl SimplifiedFinalityMetadata {
    fn validate(&self, epoch_context: &SimplifiedEpochContext) -> Result<(), String> {
        if self.format != POSY_SIMPLIFIED_FINALITY_METADATA_FORMAT
            || self.epoch_context_root != epoch_context.root()?
            || self.boundary_execution_state_root.is_zero()
            || self
                .certified_parent
                .validate_for_child_height(epoch_context.epoch_start_height)
                .is_err()
            || self.finalized_seed.validate().is_err()
            || self.finalized_seed.height.0 > self.certified_parent.height().0
            || self.transition_subject_root.is_some_and(Hash::is_zero)
        {
            return Err("invalid simplified finality metadata".to_string());
        }
        if let Some(anchor) = &epoch_context.v2_boundary_anchor {
            if self
                .certified_parent
                .quorum_certificate_reference()
                .is_none_or(|reference| {
                    reference.height != anchor.height
                        || reference.block_id != anchor.block_id
                        || reference.qc_id != anchor.qc_finality_context_root
                })
                || self.finalized_seed.height != anchor.height
                || self.finalized_seed.block_id != anchor.block_id
                || self.finalized_seed.finality_reference_id() != anchor.qc_finality_context_root
                || self.transition_subject_root.is_some()
            {
                return Err(
                    "simplified finality metadata does not match the activation anchor".to_string(),
                );
            }
        }
        if let Some(anchor) = &epoch_context.v3_transition_anchor {
            if self
                .certified_parent
                .quorum_certificate_reference()
                .is_none_or(|reference| {
                    reference.height != anchor.certified_parent_height
                        || reference.block_id != anchor.certified_parent_block_id
                        || reference.qc_id != anchor.certified_parent_qc_id
                })
                || self.finalized_seed.height != anchor.finalized_seed_height
                || self.finalized_seed.block_id != anchor.finalized_seed_block_id
                || self.finalized_seed.finality_reference_id() != anchor.finalized_seed_qc_id
                || self.transition_subject_root != Some(anchor.transition_subject_root)
            {
                return Err(
                    "simplified finality metadata does not match the verified v3 transition"
                        .to_string(),
                );
            }
        } else if epoch_context.v2_boundary_anchor.is_none()
            && (self.certified_parent != self.finalized_seed.finality_parent
                || self.transition_subject_root.is_some())
        {
            return Err(
                "fresh simplified finality metadata split its canonical anchor".to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SimplifiedFinalityWalRecord {
    format: String,
    transaction: SimplifiedFinalizationTransaction,
    receipt: SimplifiedFinalizationReceipt,
}

impl SimplifiedFinalityWalRecord {
    fn new(transaction: SimplifiedFinalizationTransaction) -> Result<Self, String> {
        transaction.validate()?;
        let receipt = SimplifiedFinalizationReceipt {
            transaction_id: transaction.transaction_id,
            target_finalized: transaction.target_finalized.clone(),
        };
        let record = Self {
            format: POSY_SIMPLIFIED_FINALITY_WAL_FORMAT.to_string(),
            transaction,
            receipt,
        };
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> Result<(), String> {
        self.transaction.validate()?;
        if self.format != POSY_SIMPLIFIED_FINALITY_WAL_FORMAT
            || self.receipt.transaction_id != self.transaction.transaction_id
            || self.receipt.target_finalized != self.transaction.target_finalized
        {
            return Err("invalid simplified finality WAL receipt".to_string());
        }
        Ok(())
    }
}

/// Frozen verification inputs and boundary state for one simplified epoch.
pub struct SimplifiedFinalityEnvironment {
    pub epoch_context: SimplifiedEpochContext,
    pub validator_set: ValidatorSet,
    pub cluster_map: ClusterMap,
    pub etdag_parameters: EtdagParameters,
    pub consensus_verifier: AegisPqvmVerifier,
    pub etdag_verifier: AegisPqvmVerifier,
    pub anchor_finalized: FinalizedBlockRecord,
    pub boundary_execution_state: ExecutionState,
}

impl SimplifiedFinalityEnvironment {
    fn validate(
        &self,
        transition: Option<&VerifiedSimplifiedEpochTransition>,
    ) -> Result<SimplifiedFinalityMetadata, String> {
        self.epoch_context.validate_against(
            &self
                .validator_set
                .active_for_epoch(self.epoch_context.epoch),
        )?;
        self.etdag_parameters.validate()?;
        if self.cluster_map.epoch != self.epoch_context.epoch {
            return Err("simplified finality cluster map names another epoch".to_string());
        }
        let (certified_parent, transition_subject_root) = match transition {
            Some(transition) => {
                if self.epoch_context != *transition.next_epoch_context()
                    || self.validator_set != *transition.next_validator_set()
                    || self.anchor_finalized.height != transition.finalized_seed().height
                    || self.anchor_finalized.block_id != transition.finalized_seed().block_id
                    || self.anchor_finalized.finality_reference_id()
                        != transition.finalized_seed().qc_id
                {
                    return Err(
                        "simplified finality environment does not match the verified v3 transition"
                            .to_string(),
                    );
                }
                (
                    SimplifiedFinalityParent::quorum_certificate(
                        transition.certified_parent().clone(),
                    )?,
                    Some(transition.transition_subject_root()),
                )
            }
            None => {
                if self.epoch_context.v3_transition_anchor.is_some() {
                    return Err(
                        "v3-to-v3 finality requires a receiver-owned verified transition capability"
                            .to_string(),
                    );
                }
                (self.anchor_finalized.finality_parent.clone(), None)
            }
        };
        let metadata = SimplifiedFinalityMetadata {
            format: POSY_SIMPLIFIED_FINALITY_METADATA_FORMAT.to_string(),
            epoch_context_root: self.epoch_context.root()?,
            certified_parent,
            finalized_seed: self.anchor_finalized.clone(),
            transition_subject_root,
            boundary_execution_state_root: compute_state_root_after(
                &self.boundary_execution_state,
            )?,
        };
        metadata.validate(&self.epoch_context)?;
        Ok(metadata)
    }
}

/// Previous-epoch execution inputs retained only for the two certified tail
/// blocks that remain unfinalized at a v3 boundary.
#[derive(Clone)]
pub struct SimplifiedPreviousEpochFinalityReplay {
    pub material_store: DurableSimplifiedProposalMaterialStore,
    pub cluster_map: ClusterMap,
    pub etdag_parameters: EtdagParameters,
    pub consensus_verifier: AegisPqvmVerifier,
    pub etdag_verifier: AegisPqvmVerifier,
}

struct VerifiedV3FinalityTransition {
    transition: VerifiedSimplifiedEpochTransition,
    previous: SimplifiedPreviousEpochFinalityReplay,
}

/// Immutable-WAL finalization sink whose restart state is derived by replay.
pub struct DurableSimplifiedFinalitySink {
    directory: PathBuf,
    material_store: DurableSimplifiedProposalMaterialStore,
    environment: SimplifiedFinalityEnvironment,
    epoch_transition: Option<VerifiedV3FinalityTransition>,
    current_finalized: FinalizedBlockRecord,
    execution_state: ExecutionState,
}

static FINALITY_STORE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

impl DurableSimplifiedFinalitySink {
    pub fn for_epoch(
        material_store: DurableSimplifiedProposalMaterialStore,
        environment: SimplifiedFinalityEnvironment,
    ) -> Result<Self, String> {
        let directory = crate::utils::resolve_data_path(POSY_SIMPLIFIED_FINALITY_DIRECTORY)
            .join(environment.epoch_context.root()?.to_hex());
        Self::at_directory(directory, material_store, environment)
    }

    pub fn at_directory(
        directory: impl Into<PathBuf>,
        material_store: DurableSimplifiedProposalMaterialStore,
        environment: SimplifiedFinalityEnvironment,
    ) -> Result<Self, String> {
        Self::at_directory_internal(directory, material_store, environment, None)
    }

    pub fn for_epoch_from_verified_v3_transition(
        material_store: DurableSimplifiedProposalMaterialStore,
        environment: SimplifiedFinalityEnvironment,
        transition: VerifiedSimplifiedEpochTransition,
        previous: SimplifiedPreviousEpochFinalityReplay,
    ) -> Result<Self, String> {
        let directory = crate::utils::resolve_data_path(POSY_SIMPLIFIED_FINALITY_DIRECTORY)
            .join(environment.epoch_context.root()?.to_hex());
        Self::at_directory_from_verified_v3_transition(
            directory,
            material_store,
            environment,
            transition,
            previous,
        )
    }

    pub fn at_directory_from_verified_v3_transition(
        directory: impl Into<PathBuf>,
        material_store: DurableSimplifiedProposalMaterialStore,
        environment: SimplifiedFinalityEnvironment,
        transition: VerifiedSimplifiedEpochTransition,
        previous: SimplifiedPreviousEpochFinalityReplay,
    ) -> Result<Self, String> {
        if previous.material_store.epoch_context_root()
            != transition.previous_epoch_context().root()?
            || previous.cluster_map.epoch != transition.previous_epoch_context().epoch
        {
            return Err(
                "previous-epoch finality replay inputs do not match the verified transition"
                    .to_string(),
            );
        }
        previous.etdag_parameters.validate()?;
        Self::at_directory_internal(
            directory,
            material_store,
            environment,
            Some(VerifiedV3FinalityTransition {
                transition,
                previous,
            }),
        )
    }

    fn at_directory_internal(
        directory: impl Into<PathBuf>,
        material_store: DurableSimplifiedProposalMaterialStore,
        environment: SimplifiedFinalityEnvironment,
        epoch_transition: Option<VerifiedV3FinalityTransition>,
    ) -> Result<Self, String> {
        let directory = directory.into();
        if directory.as_os_str().is_empty() {
            return Err("simplified finality store directory is empty".to_string());
        }
        let metadata = environment.validate(
            epoch_transition
                .as_ref()
                .map(|transition| &transition.transition),
        )?;
        if material_store.epoch_context_root() != metadata.epoch_context_root {
            return Err(
                "simplified material and finality stores name different epochs".to_string(),
            );
        }
        let _guard = finality_store_lock()?;
        fs::create_dir_all(&directory).map_err(|error| {
            format!(
                "create simplified finality directory {}: {error}",
                directory.display()
            )
        })?;
        install_or_compare_canonical(
            &directory,
            &directory.join(POSY_SIMPLIFIED_FINALITY_METADATA_FILE),
            &metadata,
            64 * 1024,
        )?;
        let finalized_seed = metadata.finalized_seed.clone();
        let boundary_state = environment.boundary_execution_state.clone();
        let mut sink = Self {
            directory,
            material_store,
            environment,
            epoch_transition,
            current_finalized: finalized_seed,
            execution_state: boundary_state,
        };
        sink.replay_wal()?;
        Ok(sink)
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn current_finalized(&self) -> &FinalizedBlockRecord {
        &self.current_finalized
    }

    pub fn execution_state(&self) -> &ExecutionState {
        &self.execution_state
    }

    fn replay_wal(&mut self) -> Result<(), String> {
        let mut records = Vec::new();
        for entry in fs::read_dir(&self.directory).map_err(|error| {
            format!(
                "read simplified finality directory {}: {error}",
                self.directory.display()
            )
        })? {
            let entry = entry.map_err(|error| format!("read finality directory entry: {error}"))?;
            let path = entry.path();
            if path.file_name().and_then(|name| name.to_str())
                == Some(POSY_SIMPLIFIED_FINALITY_METADATA_FILE)
                || path.extension().and_then(|extension| extension.to_str()) != Some("json")
            {
                continue;
            }
            let height = parse_wal_height(&path)?;
            let record: SimplifiedFinalityWalRecord =
                read_canonical_bounded(&path, MAX_POSY_SIMPLIFIED_FINALITY_WAL_RECORD_BYTES)?;
            if record.transaction.target_finalized.height.0 != height {
                return Err("finality WAL filename and target height disagree".to_string());
            }
            records.push((height, record));
        }
        records.sort_by_key(|(height, _)| *height);
        for window in records.windows(2) {
            if window[0].0 == window[1].0 {
                return Err("multiple finality WAL records exist for one height".to_string());
            }
        }
        for (_, record) in records {
            let next_state = self.verify_and_replay_transaction(&record.transaction)?;
            self.execution_state = next_state;
            self.current_finalized = record.receipt.target_finalized;
        }
        Ok(())
    }

    fn verify_and_replay_transaction(
        &self,
        transaction: &SimplifiedFinalizationTransaction,
    ) -> Result<ExecutionState, String> {
        transaction.validate()?;
        if transaction.epoch_context_root != self.environment.epoch_context.root()?
            || transaction.expected_previous_finalized != self.current_finalized
        {
            return Err("finality transaction does not extend the durable epoch head".to_string());
        }
        let mut state = self.execution_state.clone();
        for certificate in &transaction.finality_witness {
            self.verify_certificate_for_replay(certificate)?;
        }
        for commitment in &transaction.commitments {
            self.verify_certificate_for_replay(&commitment.certificate)?;
            let is_previous_epoch =
                self.is_previous_transition_certificate(&commitment.certificate)?;
            let material = if is_previous_epoch {
                self.epoch_transition
                    .as_ref()
                    .ok_or_else(|| {
                        "previous-epoch finality commitment lacks a verified transition".to_string()
                    })?
                    .previous
                    .material_store
                    .load(commitment.qc_id)?
            } else {
                self.material_store.load(commitment.qc_id)?
            };
            if material.candidate_subject != commitment.certificate.subject()? {
                return Err(
                    "finalized QC does not certify its durable proposal material".to_string(),
                );
            }
            state = if is_previous_epoch {
                let transition = self.epoch_transition.as_ref().ok_or_else(|| {
                    "previous-epoch replay lost its verified transition".to_string()
                })?;
                material.replay_and_verify(
                    transition.transition.previous_epoch_context(),
                    &state,
                    &transition.previous.etdag_verifier,
                    transition.transition.previous_validator_set(),
                    &transition.previous.cluster_map,
                    &transition.previous.etdag_parameters,
                )?
            } else {
                material.replay_and_verify(
                    &self.environment.epoch_context,
                    &state,
                    &self.environment.etdag_verifier,
                    &self.environment.validator_set,
                    &self.environment.cluster_map,
                    &self.environment.etdag_parameters,
                )?
            };
        }
        Ok(state)
    }

    fn is_previous_transition_certificate(
        &self,
        certificate: &SimplifiedQuorumCertificate,
    ) -> Result<bool, String> {
        let certificate_root = certificate.context.epoch_context_root;
        if certificate_root == self.environment.epoch_context.root()? {
            return Ok(false);
        }
        let Some(transition) = &self.epoch_transition else {
            return Err("finality certificate names an unpinned epoch".to_string());
        };
        if certificate_root != transition.transition.previous_epoch_context().root()? {
            return Err("finality certificate names neither pinned transition epoch".to_string());
        }
        let certificate_id = certificate.id()?;
        if !transition
            .transition
            .transition_tail()
            .iter()
            .any(|tail| tail.id().ok() == Some(certificate_id))
        {
            return Err(
                "previous-epoch finality certificate is outside the verified transition tail"
                    .to_string(),
            );
        }
        Ok(true)
    }

    fn verify_certificate_for_replay(
        &self,
        certificate: &SimplifiedQuorumCertificate,
    ) -> Result<(), String> {
        if self.is_previous_transition_certificate(certificate)? {
            let transition = self
                .epoch_transition
                .as_ref()
                .ok_or_else(|| "previous-epoch QC verification lost its transition".to_string())?;
            certificate.verify(
                transition.transition.previous_epoch_context(),
                transition.transition.previous_validator_set(),
                &transition.previous.consensus_verifier,
            )?;
        } else {
            certificate.verify(
                &self.environment.epoch_context,
                &self.environment.validator_set,
                &self.environment.consensus_verifier,
            )?;
        }
        Ok(())
    }

    fn record_path(&self, target_height: u64) -> PathBuf {
        self.directory
            .join(format!("finality-{target_height:020}.json"))
    }
}

impl SimplifiedFinalizationSink for DurableSimplifiedFinalitySink {
    fn commit_finalization(
        &mut self,
        transaction: &SimplifiedFinalizationTransaction,
    ) -> Result<SimplifiedFinalizationReceipt, SimplifiedFinalizationSinkError> {
        transaction
            .validate()
            .map_err(SimplifiedFinalizationSinkError::CommitRejected)?;
        let expected_epoch_root = self
            .environment
            .epoch_context
            .root()
            .map_err(SimplifiedFinalizationSinkError::CommitRejected)?;
        if transaction.epoch_context_root != expected_epoch_root {
            return Err(SimplifiedFinalizationSinkError::CommitRejected(
                "finalization transaction names another epoch".to_string(),
            ));
        }
        let _guard = finality_store_lock().map_err(SimplifiedFinalizationSinkError::Unavailable)?;
        let path = self.record_path(transaction.target_finalized.height.0);
        if path.exists() {
            let existing: SimplifiedFinalityWalRecord =
                read_canonical_bounded(&path, MAX_POSY_SIMPLIFIED_FINALITY_WAL_RECORD_BYTES)
                    .map_err(SimplifiedFinalizationSinkError::Unavailable)?;
            if existing.transaction == *transaction {
                return Ok(existing.receipt);
            }
            return Err(SimplifiedFinalizationSinkError::CommitRejected(
                "a different finality transaction already owns the target height".to_string(),
            ));
        }
        let next_state = self
            .verify_and_replay_transaction(transaction)
            .map_err(SimplifiedFinalizationSinkError::CommitRejected)?;
        let record = SimplifiedFinalityWalRecord::new(transaction.clone())
            .map_err(SimplifiedFinalizationSinkError::CommitRejected)?;
        install_new_canonical(
            &self.directory,
            &path,
            &record,
            MAX_POSY_SIMPLIFIED_FINALITY_WAL_RECORD_BYTES,
        )
        .map_err(SimplifiedFinalizationSinkError::Unavailable)?;
        self.execution_state = next_state;
        self.current_finalized = transaction.target_finalized.clone();
        // This is only an availability cache.  The immutable WAL remains the
        // restart authority, but RPC readers must observe the state that was
        // just durably committed instead of the activation-boundary snapshot.
        let _ = crate::execution::publish_finalized_execution_state_snapshot(&self.execution_state);
        Ok(record.receipt)
    }
}

fn parse_wal_height(path: &Path) -> Result<u64, String> {
    let stem = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .ok_or_else(|| "finality WAL filename is not UTF-8".to_string())?;
    let encoded = stem
        .strip_prefix("finality-")
        .ok_or_else(|| "unexpected JSON file in finality WAL directory".to_string())?;
    if encoded.len() != 20 || !encoded.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("finality WAL height filename is not canonical".to_string());
    }
    encoded
        .parse::<u64>()
        .map_err(|error| format!("parse finality WAL height: {error}"))
}

fn finality_store_lock() -> Result<std::sync::MutexGuard<'static, ()>, String> {
    FINALITY_STORE_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| "simplified finality store lock poisoned".to_string())
}

fn read_canonical_bounded<T>(path: &Path, max_bytes: usize) -> Result<T, String>
where
    T: DeserializeOwned + Serialize + PartialEq,
{
    let bytes = fs::read(path)
        .map_err(|error| format!("read durable finality file {}: {error}", path.display()))?;
    if bytes.is_empty() || bytes.len() > max_bytes {
        return Err("durable finality file violates its decode bound".to_string());
    }
    T::assert_canonical_bytes(&bytes)
}

fn install_or_compare_canonical<T>(
    directory: &Path,
    path: &Path,
    value: &T,
    max_bytes: usize,
) -> Result<(), String>
where
    T: DeserializeOwned + Serialize + PartialEq,
{
    if path.exists() {
        let existing: T = read_canonical_bounded(path, max_bytes)?;
        return if existing == *value {
            Ok(())
        } else {
            Err("durable finality metadata conflicts with startup inputs".to_string())
        };
    }
    install_new_canonical(directory, path, value, max_bytes)
}

fn install_new_canonical<T>(
    directory: &Path,
    path: &Path,
    value: &T,
    max_bytes: usize,
) -> Result<(), String>
where
    T: Serialize,
{
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("encode durable finality record: {error}"))?;
    if bytes.is_empty() || bytes.len() > max_bytes {
        return Err("durable finality record violates its persistence bound".to_string());
    }
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("clock failure for finality persistence: {error}"))?
        .as_nanos();
    let temp = path.with_extension(format!("tmp-{}-{nonce}", std::process::id()));
    let result = (|| -> Result<(), String> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temp)
            .map_err(|error| format!("create finality temp {}: {error}", temp.display()))?;
        file.write_all(&bytes)
            .map_err(|error| format!("write finality temp {}: {error}", temp.display()))?;
        file.sync_all()
            .map_err(|error| format!("sync finality temp {}: {error}", temp.display()))?;
        fs::hard_link(&temp, path).map_err(|error| {
            format!(
                "atomically install durable finality file {}: {error}",
                path.display()
            )
        })?;
        fs::remove_file(&temp)
            .map_err(|error| format!("remove finality temp {}: {error}", temp.display()))?;
        File::open(directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("sync finality directory {}: {error}", directory.display()))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::simplified_posy::{
        compute_simplified_protected_execution_root, BlockVote, ConsensusObjectContext,
        DurableSimplifiedProposalMaterialStore, DurableSimplifiedProtectedMaterialAuthority,
        DurableSimplifiedProtectedMaterialAuthorityConfiguration, QuorumCertificateReference,
        SimplifiedEpochTransitionAuthorization, SimplifiedEpochTransitionProof,
        SimplifiedFinalityParent, SimplifiedFinalizedCommitment, SimplifiedProposal,
        SimplifiedQuorumCertificate, SimplifiedTransitionAuthorityVerifier,
        VerifiedSimplifiedProposalMaterial, POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN,
        POSY_SIMPLIFIED_EPOCH_TRANSITION_FORMAT, POSY_SIMPLIFIED_EPOCH_TRANSITION_SCHEMA_VERSION,
        POSY_SIMPLIFIED_PROTOCOL_VERSION,
    };
    use crate::consensus_parameters::ConsensusParameterRoot;
    use crate::crypto::aegis_pqvm::AegisPqvmSigner;
    use crate::execution::compute_receipt_root;
    use crate::synergy_types::{
        AegisPqKeyRole, AegisPqSignature, Block, BlockHeader, BlockId, ClusterId, Epoch, Height,
        Round, UmaId, ValidatorId, ValidatorRecord, ValidatorStatus,
        TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM,
    };

    struct Fixture {
        epoch_context: SimplifiedEpochContext,
        validators: ValidatorSet,
        cluster_map: ClusterMap,
        signer: AegisPqvmSigner,
        anchor: FinalizedBlockRecord,
        state: ExecutionState,
        material: super::super::VerifiedSimplifiedProposalMaterial,
        transaction: SimplifiedFinalizationTransaction,
    }

    #[derive(Debug, Clone, Copy)]
    struct TestTransitionAuthorityVerifier;

    impl SimplifiedTransitionAuthorityVerifier for TestTransitionAuthorityVerifier {
        fn verify_finalized_transition_authority(
            &self,
            finalized_qc: &SimplifiedQuorumCertificate,
            transition_subject_root: Hash,
            authority_evidence: &[u8],
        ) -> Result<(), String> {
            let expected = (
                transition_subject_root,
                finalized_qc.protected_execution_root,
            )
                .canonical_bytes()?;
            if authority_evidence == expected {
                Ok(())
            } else {
                Err("test transition authority is not finalized".to_string())
            }
        }
    }

    fn fixture() -> Fixture {
        let mut signer = AegisPqvmSigner::initialize_required().unwrap();
        let mut records = Vec::new();
        for index in 0..5 {
            let uma = UmaId(format!("uma:finality-validator-{index}"));
            let key_id = signer
                .generate_and_register_key(&uma.0, vec![AegisPqKeyRole::ConsensusVote], Epoch(9))
                .unwrap();
            let public_key = signer.public_key_record(&key_id).unwrap();
            records.push(ValidatorRecord {
                validator_id: ValidatorId(format!("finality-validator-{index}")),
                validator_uma_id: uma,
                consensus_public_key: public_key.clone(),
                peer_public_key: public_key.clone(),
                operator_public_key: public_key,
                voting_weight: 1,
                status: ValidatorStatus::Active,
                cluster_id: ClusterId(0),
                activation_epoch: Epoch(9),
            });
        }
        let validators = ValidatorSet {
            epoch: Epoch(9),
            validators: records,
        };
        let seed = Hash::from_domain_bytes("finality-test-seed", b"epoch-9");
        let epoch_context = SimplifiedEpochContext::derive(
            Epoch(9),
            Height(4_000),
            Height(4_999),
            seed,
            ConsensusParameterRoot::from_canonical_manifest_bytes(b"finality-parameters"),
            &validators,
        )
        .unwrap();
        let cluster_map = ClusterMap::derive_from_finalized_epoch_seed(&validators, seed).unwrap();
        let anchor_qc = QuorumCertificateReference {
            height: Height(3_999),
            block_id: BlockId::from_hash(Hash::from_domain_bytes(
                "finality-test-anchor-block",
                b"3999",
            )),
            qc_id: Hash::from_domain_bytes("finality-test-anchor-qc", b"3999"),
        };
        let anchor = FinalizedBlockRecord::from_quorum_certificate(anchor_qc.clone()).unwrap();
        let anchor_parent =
            SimplifiedFinalityParent::quorum_certificate(anchor_qc.clone()).unwrap();
        let state = ExecutionState::new();
        let state_root = compute_state_root_after(&state).unwrap();
        let object_context =
            ConsensusObjectContext::for_height(&epoch_context, Height(4_000), Round(0)).unwrap();
        let proposer = &validators.validators[0];
        let block = Block {
            header: BlockHeader {
                version: 3,
                chain_id: object_context.chain_id,
                network_id: object_context.network_id.clone(),
                protocol_version: POSY_SIMPLIFIED_PROTOCOL_VERSION.to_string(),
                height: object_context.height,
                round: object_context.round,
                epoch: object_context.epoch,
                cluster_id: ClusterId(0),
                height_context_root: object_context.epoch_context_root,
                parent_block_hash: Hash::from_hex(&anchor.block_id.0).unwrap(),
                parent_state_root: state_root,
                last_finalized_qc_hash: anchor.finality_reference_id(),
                proposer_validator_id: proposer.validator_id.clone(),
                proposer_uma_id: proposer.validator_uma_id.clone(),
                proposer_key_id: proposer.consensus_public_key.key_id.clone(),
                active_validator_set_hash: object_context.active_validator_set_root,
                eligible_validator_set_hash: object_context.active_validator_set_root,
                validator_consensus_key_root: object_context.validator_consensus_key_root,
                frozen_bonded_weight_root: object_context.frozen_voting_weight_root,
                cluster_schedule_version: "posy-v3-test-cluster".to_string(),
                cluster_map_hash: cluster_map.hash().unwrap(),
                assigned_cluster_membership_root: Hash::from_domain_bytes(
                    "finality-test",
                    b"cluster-membership",
                ),
                assigned_cluster_validator_count: 5,
                assigned_cluster_total_voting_weight: 5,
                proposer_schedule_hash: epoch_context.leader_ring_root,
                protocol_config_hash: ConsensusParameterRoot::from_hex(
                    &epoch_context.consensus_parameter_root,
                )
                .unwrap(),
                cryptographic_profile_root: Hash::from_domain_bytes("finality-test", b"crypto"),
                dag_frontier_root: Hash::from_domain_bytes("finality-test", b"dag"),
                tx_order_root: Hash::from_domain_bytes("finality-test", b"order"),
                tx_count: 0,
                protected_batch: None,
                evidence_root: Hash::from_domain_bytes("finality-test", b"evidence"),
                state_root_before: state_root,
                state_root_after: state_root,
                receipt_root: compute_receipt_root(&[]).unwrap(),
                app_version: 1,
                execution_version: 1,
                dag_version: 2,
                aegis_pqvm_version: "aegis-pqvm".to_string(),
                timestamp_ms_consensus_bounded: 1_000,
            },
            transactions: Vec::new(),
            proposer_signature: AegisPqSignature {
                algorithm: TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM.to_string(),
                signature_bytes: vec![1],
            },
        };
        let block_id = block.candidate_id().unwrap();
        let protected_execution_root = compute_simplified_protected_execution_root(
            &object_context,
            &block,
            &anchor.block_id,
            &anchor_parent,
            None,
            None,
        )
        .unwrap();
        let proposal = SimplifiedProposal {
            context: object_context,
            block_id: block_id.clone(),
            parent_block_id: anchor.block_id.clone(),
            parent: anchor_parent,
            takeover_tc_id: None,
            protected_execution_root,
            proposer_id: proposer.validator_id.clone(),
            proposer_key_id: proposer.consensus_public_key.key_id.clone(),
            proposer_signature: block.proposer_signature.clone(),
        };
        let (material, _) = VerifiedSimplifiedProposalMaterial::verify_core(
            &epoch_context,
            &proposal,
            block,
            &state,
        )
        .unwrap();
        let qc0 = signed_qc(
            &mut signer,
            &validators,
            proposal.context,
            block_id,
            anchor_qc,
            protected_execution_root,
        );
        let qc1 = signed_qc(
            &mut signer,
            &validators,
            ConsensusObjectContext::for_height(&epoch_context, Height(4_001), Round(0)).unwrap(),
            BlockId::from_hash(Hash::from_domain_bytes("finality-test-block", b"4001")),
            qc0.reference().unwrap(),
            Hash::from_domain_bytes("finality-test-execution", b"4001"),
        );
        let qc2 = signed_qc(
            &mut signer,
            &validators,
            ConsensusObjectContext::for_height(&epoch_context, Height(4_002), Round(0)).unwrap(),
            BlockId::from_hash(Hash::from_domain_bytes("finality-test-block", b"4002")),
            qc1.reference().unwrap(),
            Hash::from_domain_bytes("finality-test-execution", b"4002"),
        );
        let target =
            FinalizedBlockRecord::from_quorum_certificate(qc0.reference().unwrap()).unwrap();
        let commitment = SimplifiedFinalizedCommitment {
            height: target.height,
            block_id: target.block_id.clone(),
            parent_block_id: anchor.block_id.clone(),
            qc_id: target.finality_reference_id(),
            protected_execution_root,
            certificate: qc0.clone(),
        };
        let mut transaction = SimplifiedFinalizationTransaction {
            format: "synergy-posy-simplified-finalization-transaction-v3".to_string(),
            transaction_id: Hash::zero(),
            epoch_context_root: epoch_context.root().unwrap(),
            expected_previous_finalized: anchor.clone(),
            commitments: vec![commitment],
            target_finalized: target,
            finality_witness: vec![qc0, qc1, qc2],
        };
        transaction.transaction_id = transaction.recompute_id().unwrap();
        transaction.validate().unwrap();
        Fixture {
            epoch_context,
            validators,
            cluster_map,
            signer,
            anchor,
            state,
            material,
            transaction,
        }
    }

    fn signed_qc(
        signer: &mut AegisPqvmSigner,
        validators: &ValidatorSet,
        context: ConsensusObjectContext,
        block_id: BlockId,
        parent_qc: QuorumCertificateReference,
        protected_execution_root: Hash,
    ) -> SimplifiedQuorumCertificate {
        let mut votes = Vec::new();
        for validator in &validators.validators {
            let mut vote = BlockVote {
                context: context.clone(),
                block_id: block_id.clone(),
                parent_block_id: parent_qc.block_id.clone(),
                parent: SimplifiedFinalityParent::quorum_certificate(parent_qc.clone()).unwrap(),
                takeover_tc_id: None,
                protected_execution_root,
                validator_id: validator.validator_id.clone(),
                key_id: validator.consensus_public_key.key_id.clone(),
                signature: AegisPqSignature {
                    algorithm: String::new(),
                    signature_bytes: Vec::new(),
                },
            };
            vote.signature = signer
                .sign_domain(
                    POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN,
                    &vote.signing_bytes().unwrap(),
                    &vote.key_id,
                )
                .unwrap();
            votes.push(vote);
        }
        SimplifiedQuorumCertificate::from_votes(votes).unwrap()
    }

    fn core_material_and_qc(
        signer: &mut AegisPqvmSigner,
        epoch_context: &SimplifiedEpochContext,
        validators: &ValidatorSet,
        cluster_map: &ClusterMap,
        state: &ExecutionState,
        height: Height,
        parent_qc: QuorumCertificateReference,
        last_finalized_qc_id: Hash,
    ) -> (
        VerifiedSimplifiedProposalMaterial,
        SimplifiedQuorumCertificate,
    ) {
        let object_context =
            ConsensusObjectContext::for_height(epoch_context, height, Round(0)).unwrap();
        let proposer = &validators.validators[0];
        let state_root = compute_state_root_after(state).unwrap();
        let block = Block {
            header: BlockHeader {
                version: 3,
                chain_id: object_context.chain_id,
                network_id: object_context.network_id.clone(),
                protocol_version: POSY_SIMPLIFIED_PROTOCOL_VERSION.to_string(),
                height,
                round: Round(0),
                epoch: object_context.epoch,
                cluster_id: ClusterId(0),
                height_context_root: object_context.epoch_context_root,
                parent_block_hash: Hash::from_hex(&parent_qc.block_id.0).unwrap(),
                parent_state_root: state_root,
                last_finalized_qc_hash: last_finalized_qc_id,
                proposer_validator_id: proposer.validator_id.clone(),
                proposer_uma_id: proposer.validator_uma_id.clone(),
                proposer_key_id: proposer.consensus_public_key.key_id.clone(),
                active_validator_set_hash: object_context.active_validator_set_root,
                eligible_validator_set_hash: object_context.active_validator_set_root,
                validator_consensus_key_root: object_context.validator_consensus_key_root,
                frozen_bonded_weight_root: object_context.frozen_voting_weight_root,
                cluster_schedule_version: "posy-v3-transition-test".to_string(),
                cluster_map_hash: cluster_map.hash().unwrap(),
                assigned_cluster_membership_root: Hash::from_domain_bytes(
                    "finality-transition-test",
                    &height.0.to_le_bytes(),
                ),
                assigned_cluster_validator_count: validators.validators.len() as u64,
                assigned_cluster_total_voting_weight: validators
                    .validators
                    .iter()
                    .map(|validator| validator.voting_weight)
                    .sum(),
                proposer_schedule_hash: epoch_context.leader_ring_root,
                protocol_config_hash: ConsensusParameterRoot::from_hex(
                    &epoch_context.consensus_parameter_root,
                )
                .unwrap(),
                cryptographic_profile_root: Hash::from_domain_bytes(
                    "finality-transition-test",
                    b"crypto",
                ),
                dag_frontier_root: Hash::from_domain_bytes("finality-transition-test", b"dag"),
                tx_order_root: Hash::from_domain_bytes("finality-transition-test", b"order"),
                tx_count: 0,
                protected_batch: None,
                evidence_root: Hash::from_domain_bytes("finality-transition-test", b"evidence"),
                state_root_before: state_root,
                state_root_after: state_root,
                receipt_root: compute_receipt_root(&[]).unwrap(),
                app_version: 1,
                execution_version: 1,
                dag_version: 2,
                aegis_pqvm_version: "aegis-pqvm".to_string(),
                timestamp_ms_consensus_bounded: 10_000 + height.0,
            },
            transactions: Vec::new(),
            proposer_signature: AegisPqSignature {
                algorithm: TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM.to_string(),
                signature_bytes: vec![1],
            },
        };
        let block_id = block.candidate_id().unwrap();
        let protected_execution_root = compute_simplified_protected_execution_root(
            &object_context,
            &block,
            &parent_qc.block_id,
            &SimplifiedFinalityParent::quorum_certificate(parent_qc.clone()).unwrap(),
            None,
            None,
        )
        .unwrap();
        let proposal = SimplifiedProposal {
            context: object_context.clone(),
            proposer_id: proposer.validator_id.clone(),
            block_id: block_id.clone(),
            parent_block_id: parent_qc.block_id.clone(),
            parent: SimplifiedFinalityParent::quorum_certificate(parent_qc.clone()).unwrap(),
            takeover_tc_id: None,
            protected_execution_root,
            proposer_key_id: proposer.consensus_public_key.key_id.clone(),
            proposer_signature: block.proposer_signature.clone(),
        };
        let (material, _) =
            VerifiedSimplifiedProposalMaterial::verify_core(epoch_context, &proposal, block, state)
                .unwrap();
        let qc = signed_qc(
            signer,
            validators,
            object_context,
            block_id,
            parent_qc,
            protected_execution_root,
        );
        (material, qc)
    }

    fn unique_directory(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        crate::utils::test_temp_root(format!(
            "posy-simplified-finality-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn environment(fixture: &Fixture) -> SimplifiedFinalityEnvironment {
        let verifier = fixture.signer.verifier();
        SimplifiedFinalityEnvironment {
            epoch_context: fixture.epoch_context.clone(),
            validator_set: fixture.validators.clone(),
            cluster_map: fixture.cluster_map.clone(),
            etdag_parameters: EtdagParameters::default(),
            consensus_verifier: verifier.clone(),
            etdag_verifier: verifier,
            anchor_finalized: fixture.anchor.clone(),
            boundary_execution_state: fixture.state.clone(),
        }
    }

    #[test]
    fn durable_finality_replays_real_qcs_and_is_idempotent_across_restart() {
        let fixture = fixture();
        let root = fixture.epoch_context.root().unwrap();
        let material_directory = unique_directory("material");
        let finality_directory = unique_directory("wal");
        let material_store =
            DurableSimplifiedProposalMaterialStore::at_directory(&material_directory, root)
                .unwrap();
        material_store.install_verified(&fixture.material).unwrap();
        let mut sink = DurableSimplifiedFinalitySink::at_directory(
            &finality_directory,
            material_store.clone(),
            environment(&fixture),
        )
        .unwrap();
        let receipt = sink.commit_finalization(&fixture.transaction).unwrap();
        assert_eq!(
            receipt.target_finalized,
            fixture.transaction.target_finalized
        );
        assert_eq!(
            sink.commit_finalization(&fixture.transaction).unwrap(),
            receipt
        );
        drop(sink);

        let reopened = DurableSimplifiedFinalitySink::at_directory(
            &finality_directory,
            material_store,
            environment(&fixture),
        )
        .unwrap();
        assert_eq!(reopened.current_finalized(), &receipt.target_finalized);
        assert_eq!(reopened.execution_state(), &fixture.state);
        let _ = fs::remove_dir_all(material_directory);
        let _ = fs::remove_dir_all(finality_directory);
    }

    #[test]
    fn finality_wal_rejects_missing_material_and_anchor_substitution() {
        let fixture = fixture();
        let root = fixture.epoch_context.root().unwrap();
        let material_directory = unique_directory("missing-material");
        let finality_directory = unique_directory("anchor-substitution");
        let material_store =
            DurableSimplifiedProposalMaterialStore::at_directory(&material_directory, root)
                .unwrap();
        let mut sink = DurableSimplifiedFinalitySink::at_directory(
            &finality_directory,
            material_store.clone(),
            environment(&fixture),
        )
        .unwrap();
        assert!(matches!(
            sink.commit_finalization(&fixture.transaction),
            Err(SimplifiedFinalizationSinkError::CommitRejected(_))
        ));
        assert_eq!(sink.current_finalized(), &fixture.anchor);

        let mut wrong_environment = environment(&fixture);
        wrong_environment.anchor_finalized =
            FinalizedBlockRecord::from_quorum_certificate(QuorumCertificateReference {
                height: wrong_environment.anchor_finalized.height,
                block_id: wrong_environment.anchor_finalized.block_id.clone(),
                qc_id: Hash::from_domain_bytes("wrong-finality-anchor", b"3999"),
            })
            .unwrap();
        assert!(DurableSimplifiedFinalitySink::at_directory(
            &finality_directory,
            material_store,
            wrong_environment,
        )
        .is_err());
        let _ = fs::remove_dir_all(material_directory);
        let _ = fs::remove_dir_all(finality_directory);
    }

    #[test]
    fn v3_transition_finality_replays_distinct_seed_and_certified_parent() {
        let mut fixture = fixture();
        let previous_validators = fixture.validators.clone();
        let previous_seed = Hash::from_domain_bytes("finality-transition", b"previous-seed");
        let previous_context = SimplifiedEpochContext::derive(
            Epoch(9),
            Height(4_000),
            Height(4_002),
            previous_seed,
            ConsensusParameterRoot::from_canonical_manifest_bytes(b"finality-transition-previous"),
            &previous_validators,
        )
        .unwrap();
        let previous_cluster_map =
            ClusterMap::derive_from_finalized_epoch_seed(&previous_validators, previous_seed)
                .unwrap();
        let preceding_anchor = QuorumCertificateReference {
            height: Height(3_999),
            block_id: BlockId::from_hash(Hash::from_domain_bytes(
                "finality-transition",
                b"preceding-anchor",
            )),
            qc_id: Hash::from_domain_bytes("finality-transition", b"preceding-anchor-qc"),
        };
        let (material_4000, qc_4000) = core_material_and_qc(
            &mut fixture.signer,
            &previous_context,
            &previous_validators,
            &previous_cluster_map,
            &fixture.state,
            Height(4_000),
            preceding_anchor.clone(),
            preceding_anchor.qc_id,
        );
        let (material_4001, qc_4001) = core_material_and_qc(
            &mut fixture.signer,
            &previous_context,
            &previous_validators,
            &previous_cluster_map,
            &fixture.state,
            Height(4_001),
            qc_4000.reference().unwrap(),
            preceding_anchor.qc_id,
        );
        let (material_4002, qc_4002) = core_material_and_qc(
            &mut fixture.signer,
            &previous_context,
            &previous_validators,
            &previous_cluster_map,
            &fixture.state,
            Height(4_002),
            qc_4001.reference().unwrap(),
            qc_4000.id().unwrap(),
        );
        // The finalized seed is 4000. Materials 4001 and 4002 remain needed
        // after the boundary; 4000 is intentionally not installed below.
        let _ = material_4000;

        let mut next_records = previous_validators.validators.clone();
        for index in 5..7 {
            let uma = UmaId(format!("uma:finality-validator-{index}"));
            let key_id = fixture
                .signer
                .generate_and_register_key(&uma.0, vec![AegisPqKeyRole::ConsensusVote], Epoch(10))
                .unwrap();
            let public_key = fixture.signer.public_key_record(&key_id).unwrap();
            next_records.push(ValidatorRecord {
                validator_id: ValidatorId(format!("finality-validator-{index}")),
                validator_uma_id: uma,
                consensus_public_key: public_key.clone(),
                peer_public_key: public_key.clone(),
                operator_public_key: public_key,
                voting_weight: 1,
                status: ValidatorStatus::Active,
                cluster_id: ClusterId(0),
                activation_epoch: Epoch(10),
            });
        }
        let next_validators = ValidatorSet {
            epoch: Epoch(10),
            validators: next_records,
        }
        .canonicalized();
        let next_active = next_validators.active_for_epoch(Epoch(10));
        let next_parameter_root =
            ConsensusParameterRoot::from_canonical_manifest_bytes(b"finality-transition-next");
        let authorization = SimplifiedEpochTransitionAuthorization {
            schema_version: POSY_SIMPLIFIED_EPOCH_TRANSITION_SCHEMA_VERSION,
            previous_epoch: Epoch(9),
            previous_epoch_context_root: previous_context.root().unwrap(),
            finalized_height: Height(4_000),
            next_epoch: Epoch(10),
            next_epoch_start_height: Height(4_003),
            next_epoch_end_height: Height(5_002),
            next_consensus_parameter_root: next_parameter_root.to_hex(),
            next_active_validator_set_root: next_active.hash().unwrap(),
            next_validator_consensus_key_root: next_active.consensus_key_root().unwrap(),
            next_frozen_voting_weight_root: next_active.frozen_bonded_weight_root().unwrap(),
        };
        let authority_evidence = (
            authorization.root().unwrap(),
            qc_4000.protected_execution_root,
        )
            .canonical_bytes()
            .unwrap();
        let transition = SimplifiedEpochTransitionProof {
            format: POSY_SIMPLIFIED_EPOCH_TRANSITION_FORMAT.to_string(),
            previous_epoch_context: previous_context.clone(),
            previous_validator_set: previous_validators.clone().canonicalized(),
            next_validator_set: next_validators.clone(),
            authorization,
            finality_witness: vec![qc_4000.clone(), qc_4001.clone(), qc_4002.clone()],
            authority_evidence,
        }
        .verify(&fixture.signer.verifier(), &TestTransitionAuthorityVerifier)
        .unwrap();
        let next_context = transition.next_epoch_context().clone();
        let next_cluster_map = ClusterMap::derive_from_finalized_epoch_seed(
            &next_validators,
            next_context.finalized_epoch_seed_root,
        )
        .unwrap();
        let (material_4003, qc_4003) = core_material_and_qc(
            &mut fixture.signer,
            &next_context,
            &next_validators,
            &next_cluster_map,
            &fixture.state,
            Height(4_003),
            qc_4002.reference().unwrap(),
            qc_4000.id().unwrap(),
        );
        let qc_4004 = signed_qc(
            &mut fixture.signer,
            &next_validators,
            ConsensusObjectContext::for_height(&next_context, Height(4_004), Round(0)).unwrap(),
            BlockId::from_hash(Hash::from_domain_bytes("finality-transition", b"4004")),
            qc_4003.reference().unwrap(),
            Hash::from_domain_bytes("finality-transition-execution", b"4004"),
        );
        let qc_4005 = signed_qc(
            &mut fixture.signer,
            &next_validators,
            ConsensusObjectContext::for_height(&next_context, Height(4_005), Round(0)).unwrap(),
            BlockId::from_hash(Hash::from_domain_bytes("finality-transition", b"4005")),
            qc_4004.reference().unwrap(),
            Hash::from_domain_bytes("finality-transition-execution", b"4005"),
        );

        let commitment =
            |certificate: &SimplifiedQuorumCertificate| SimplifiedFinalizedCommitment {
                height: certificate.context.height,
                block_id: certificate.block_id.clone(),
                parent_block_id: certificate.parent_block_id.clone(),
                qc_id: certificate.id().unwrap(),
                protected_execution_root: certificate.protected_execution_root,
                certificate: certificate.clone(),
            };
        let target =
            FinalizedBlockRecord::from_quorum_certificate(qc_4003.reference().unwrap()).unwrap();
        let first_boundary_target =
            FinalizedBlockRecord::from_quorum_certificate(qc_4001.reference().unwrap()).unwrap();
        let finalized_seed =
            FinalizedBlockRecord::from_quorum_certificate(qc_4000.reference().unwrap()).unwrap();
        let mut first_boundary_transaction = SimplifiedFinalizationTransaction {
            format: "synergy-posy-simplified-finalization-transaction-v3".to_string(),
            transaction_id: Hash::zero(),
            epoch_context_root: next_context.root().unwrap(),
            expected_previous_finalized: finalized_seed.clone(),
            commitments: vec![commitment(&qc_4001)],
            target_finalized: first_boundary_target.clone(),
            finality_witness: vec![qc_4001.clone(), qc_4002.clone(), qc_4003.clone()],
        };
        first_boundary_transaction.transaction_id =
            first_boundary_transaction.recompute_id().unwrap();
        first_boundary_transaction.validate().unwrap();
        let mut transaction = SimplifiedFinalizationTransaction {
            format: "synergy-posy-simplified-finalization-transaction-v3".to_string(),
            transaction_id: Hash::zero(),
            epoch_context_root: next_context.root().unwrap(),
            expected_previous_finalized: first_boundary_target.clone(),
            commitments: vec![commitment(&qc_4002), commitment(&qc_4003)],
            target_finalized: target.clone(),
            finality_witness: vec![qc_4003, qc_4004, qc_4005],
        };
        transaction.transaction_id = transaction.recompute_id().unwrap();
        transaction.validate().unwrap();

        let previous_material_directory = unique_directory("transition-previous-material");
        let current_material_directory = unique_directory("transition-current-material");
        let finality_directory = unique_directory("transition-wal");
        let previous_material_store = DurableSimplifiedProposalMaterialStore::at_directory(
            &previous_material_directory,
            previous_context.root().unwrap(),
        )
        .unwrap();
        previous_material_store
            .install_verified(&material_4001)
            .unwrap();
        previous_material_store
            .install_verified(&material_4002)
            .unwrap();
        let current_material_store = DurableSimplifiedProposalMaterialStore::at_directory(
            &current_material_directory,
            next_context.root().unwrap(),
        )
        .unwrap();
        current_material_store
            .install_verified(&material_4003)
            .unwrap();

        let make_environment = || {
            let verifier = fixture.signer.verifier();
            SimplifiedFinalityEnvironment {
                epoch_context: next_context.clone(),
                validator_set: next_validators.clone(),
                cluster_map: next_cluster_map.clone(),
                etdag_parameters: EtdagParameters::default(),
                consensus_verifier: verifier.clone(),
                etdag_verifier: verifier,
                anchor_finalized: finalized_seed.clone(),
                boundary_execution_state: fixture.state.clone(),
            }
        };
        let make_previous = |store: DurableSimplifiedProposalMaterialStore| {
            let verifier = fixture.signer.verifier();
            SimplifiedPreviousEpochFinalityReplay {
                material_store: store,
                cluster_map: previous_cluster_map.clone(),
                etdag_parameters: EtdagParameters::default(),
                consensus_verifier: verifier.clone(),
                etdag_verifier: verifier,
            }
        };

        assert!(DurableSimplifiedFinalitySink::at_directory(
            unique_directory("transition-without-proof"),
            current_material_store.clone(),
            make_environment(),
        )
        .is_err());

        let mut sink = DurableSimplifiedFinalitySink::at_directory_from_verified_v3_transition(
            &finality_directory,
            current_material_store.clone(),
            make_environment(),
            transition.clone(),
            make_previous(previous_material_store.clone()),
        )
        .unwrap();
        assert_eq!(sink.current_finalized(), &finalized_seed);
        assert_ne!(
            sink.current_finalized().height,
            transition.certified_parent().height
        );
        sink.commit_finalization(&first_boundary_transaction)
            .unwrap();
        assert_eq!(sink.current_finalized(), &first_boundary_target);
        sink.commit_finalization(&transaction).unwrap();
        assert_eq!(sink.current_finalized(), &target);
        drop(sink);

        let reopened = DurableSimplifiedFinalitySink::at_directory_from_verified_v3_transition(
            &finality_directory,
            current_material_store.clone(),
            make_environment(),
            transition.clone(),
            make_previous(previous_material_store.clone()),
        )
        .unwrap();
        assert_eq!(reopened.current_finalized(), &target);
        assert_eq!(reopened.execution_state(), &fixture.state);

        let make_protected_authority_configuration = || {
            let verifier = fixture.signer.verifier();
            DurableSimplifiedProtectedMaterialAuthorityConfiguration {
                epoch_context: next_context.clone(),
                validator_set: next_validators.clone(),
                cluster_map: next_cluster_map.clone(),
                etdag_parameters: EtdagParameters::default(),
                consensus_verifier: verifier.clone(),
                etdag_verifier: verifier,
                anchor_finalized: finalized_seed.clone(),
                boundary_execution_state: fixture.state.clone(),
            }
        };
        let authority =
            DurableSimplifiedProtectedMaterialAuthority::new_from_verified_v3_transition(
                &finality_directory,
                current_material_store.clone(),
                make_protected_authority_configuration(),
                transition.clone(),
                make_previous(previous_material_store.clone()),
            )
            .unwrap();
        assert_eq!(authority.current_finalized_authority().unwrap().0, target);
        drop(authority);
        let restarted_authority =
            DurableSimplifiedProtectedMaterialAuthority::new_from_verified_v3_transition(
                &finality_directory,
                current_material_store.clone(),
                make_protected_authority_configuration(),
                transition.clone(),
                make_previous(previous_material_store.clone()),
            )
            .unwrap();
        assert_eq!(
            restarted_authority.current_finalized_authority().unwrap().0,
            target
        );

        let mut substituted_configuration = make_protected_authority_configuration();
        substituted_configuration.anchor_finalized = target.clone();
        let substituted_error =
            match DurableSimplifiedProtectedMaterialAuthority::new_from_verified_v3_transition(
                unique_directory("transition-protected-substituted"),
                current_material_store.clone(),
                substituted_configuration,
                transition.clone(),
                make_previous(previous_material_store.clone()),
            ) {
                Ok(_) => panic!("substituted transition configuration must fail"),
                Err(error) => error,
            };
        assert!(substituted_error.contains("does not match the verified v3 transition"));

        let empty_previous_directory = unique_directory("transition-empty-previous-material");
        let empty_previous_store = DurableSimplifiedProposalMaterialStore::at_directory(
            &empty_previous_directory,
            previous_context.root().unwrap(),
        )
        .unwrap();
        assert!(
            DurableSimplifiedProtectedMaterialAuthority::new_from_verified_v3_transition(
                &finality_directory,
                current_material_store.clone(),
                make_protected_authority_configuration(),
                transition.clone(),
                make_previous(empty_previous_store.clone()),
            )
            .is_err()
        );
        assert!(
            DurableSimplifiedFinalitySink::at_directory_from_verified_v3_transition(
                &finality_directory,
                current_material_store,
                make_environment(),
                transition,
                make_previous(empty_previous_store),
            )
            .is_err()
        );

        let _ = fs::remove_dir_all(previous_material_directory);
        let _ = fs::remove_dir_all(current_material_directory);
        let _ = fs::remove_dir_all(finality_directory);
        let _ = fs::remove_dir_all(empty_previous_directory);
    }
}
