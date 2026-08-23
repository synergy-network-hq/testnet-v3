//! Durable, schedule-neutral protected proposal material for simplified PoSy.
//!
//! Consensus proposals intentionally carry only stable identifiers and the
//! protected-execution root. This store retains the complete block/body and,
//! when ETDAG is active, the exact target context and public proof package that
//! validators independently verified before ECHO/VOTE. Records are keyed by
//! the stable certified-candidate ID and written one-per-file so an epoch does
//! not require rewriting or deserializing a multi-gigabyte monolith.

use super::{
    CertifiedCandidateSubject, FinalizedBlockRecord, SimplifiedEpochContext,
    SimplifiedFinalityParent, SimplifiedProposal, SimplifiedProposalDirective,
    SimplifiedProtectedProposalSource, POSY_SIMPLIFIED_PROTOCOL_VERSION,
};
use crate::consensus_parameters::ConsensusParameterRoot;
use crate::crypto::aegis_pqvm::AegisPqvmVerifier;
use crate::etdag::{EtdagDigest, EtdagParameters, ProtectedBlockInput, TargetAdmissionContext};
use crate::execution::{compute_state_root_after, execute_block, ExecutionState};
use crate::synergy_types::{
    AegisPqKeyId, AegisPqSignature, Block, BlockId, CanonicalSerialize, ClusterMap, Hash, Round,
    UmaId, ValidatorId, ValidatorSet,
};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

pub const POSY_SIMPLIFIED_MATERIAL_FORMAT: &str = "synergy-posy-simplified-protected-material-v2";
pub const MAX_POSY_SIMPLIFIED_MATERIAL_RECORD_BYTES: usize = 16 * 1024 * 1024;
const POSY_SIMPLIFIED_MATERIAL_DIRECTORY: &str = "data/posy-v3-protected-material";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerifiedSimplifiedProposalMaterial {
    pub format: String,
    pub epoch_context_root: Hash,
    pub stable_candidate_id: Hash,
    pub candidate_subject: CertifiedCandidateSubject,
    /// Proposal-envelope fields and the redundant block proposer signature are
    /// normalized away; the simplified proposal carries that authorization.
    pub canonical_block: Block,
    pub target_context: Option<TargetAdmissionContext>,
    pub protected_input: Option<ProtectedBlockInput>,
    /// Optional signer-independent dynamic-membership subject. When present,
    /// it is part of the protected-execution root certified by the QC and can
    /// therefore be used only by the durable transition-authority verifier.
    pub transition_subject_root: Option<Hash>,
}

#[derive(Serialize)]
struct ProtectedExecutionRootSubject<'a> {
    context: &'a super::ConsensusObjectContext,
    block_id: &'a BlockId,
    parent_block_id: &'a BlockId,
    parent: &'a SimplifiedFinalityParent,
    canonical_block_header: &'a crate::synergy_types::BlockHeader,
    transactions: &'a [crate::synergy_types::Transaction],
    target_context_root: Option<Hash>,
    protected_input_digest: Option<&'a EtdagDigest>,
    transition_subject_root: Option<Hash>,
}

impl VerifiedSimplifiedProposalMaterial {
    pub fn verify_core(
        epoch_context: &SimplifiedEpochContext,
        proposal: &SimplifiedProposal,
        block: Block,
        parent_execution_state: &ExecutionState,
    ) -> Result<(Self, ExecutionState), String> {
        Self::verify_core_with_transition_subject(
            epoch_context,
            proposal,
            block,
            parent_execution_state,
            None,
        )
    }

    /// As [`Self::verify_core`], but binds an already-validated dynamic
    /// membership subject into the QC-covered protected-execution root.
    pub fn verify_core_with_transition_subject(
        epoch_context: &SimplifiedEpochContext,
        proposal: &SimplifiedProposal,
        block: Block,
        parent_execution_state: &ExecutionState,
        transition_subject_root: Option<Hash>,
    ) -> Result<(Self, ExecutionState), String> {
        if !block.transactions.is_empty() || block.header.protected_batch.is_some() {
            return Err(
                "simplified core material must be an empty block without ETDAG commitment"
                    .to_string(),
            );
        }
        let next_state = verify_block_execution(parent_execution_state, &block)?;
        Self::finish_verified(
            epoch_context,
            proposal,
            block,
            None,
            None,
            transition_subject_root,
            next_state,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify_protected(
        epoch_context: &SimplifiedEpochContext,
        proposal: &SimplifiedProposal,
        block: Block,
        target_context: TargetAdmissionContext,
        protected_input: ProtectedBlockInput,
        parent_execution_state: &ExecutionState,
        verifier: &AegisPqvmVerifier,
        validator_set: &ValidatorSet,
        cluster_map: &ClusterMap,
        parameters: &EtdagParameters,
    ) -> Result<(Self, ExecutionState), String> {
        Self::verify_protected_with_transition_subject(
            epoch_context,
            proposal,
            block,
            target_context,
            protected_input,
            parent_execution_state,
            verifier,
            validator_set,
            cluster_map,
            parameters,
            None,
        )
    }

    /// As [`Self::verify_protected`], but binds an already-validated dynamic
    /// membership subject into the QC-covered protected-execution root.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_protected_with_transition_subject(
        epoch_context: &SimplifiedEpochContext,
        proposal: &SimplifiedProposal,
        block: Block,
        target_context: TargetAdmissionContext,
        protected_input: ProtectedBlockInput,
        parent_execution_state: &ExecutionState,
        verifier: &AegisPqvmVerifier,
        validator_set: &ValidatorSet,
        cluster_map: &ClusterMap,
        parameters: &EtdagParameters,
        transition_subject_root: Option<Hash>,
    ) -> Result<(Self, ExecutionState), String> {
        proposal.context.validate_against(epoch_context)?;
        validate_target_context_for_epoch(&target_context, epoch_context, proposal.context.height)?;
        let transactions = protected_input.verify_and_extract_transactions(
            verifier,
            &target_context,
            validator_set,
            cluster_map,
            parameters,
        )?;
        if transactions != block.transactions || block.header.protected_batch.is_none() {
            return Err(
                "protected material block body does not equal the verified ETDAG reveal"
                    .to_string(),
            );
        }
        let (next_state, receipts) =
            verify_block_execution_with_receipts(parent_execution_state, &block)?;
        let manifest = protected_input.build_execution_manifest(&transactions, &receipts)?;
        let commitment = protected_input.protected_batch_commitment(&manifest, &receipts)?;
        if block.header.protected_batch.as_ref() != Some(&commitment) {
            return Err(
                "protected material block header does not bind the verified ETDAG execution"
                    .to_string(),
            );
        }
        Self::finish_verified(
            epoch_context,
            proposal,
            block,
            Some(target_context),
            Some(protected_input),
            transition_subject_root,
            next_state,
        )
    }

    fn finish_verified(
        epoch_context: &SimplifiedEpochContext,
        proposal: &SimplifiedProposal,
        block: Block,
        target_context: Option<TargetAdmissionContext>,
        protected_input: Option<ProtectedBlockInput>,
        transition_subject_root: Option<Hash>,
        next_state: ExecutionState,
    ) -> Result<(Self, ExecutionState), String> {
        if transition_subject_root.is_some_and(Hash::is_zero) {
            return Err("simplified transition subject root is zero".to_string());
        }
        validate_block_binding(epoch_context, proposal, &block, transition_subject_root)?;
        let candidate_subject = CertifiedCandidateSubject::new(
            proposal.context.clone(),
            proposal.block_id.clone(),
            proposal.parent_block_id.clone(),
            proposal.parent.clone(),
            proposal.protected_execution_root,
        )?;
        let stable_candidate_id = candidate_subject.id()?;
        let canonical_block = canonical_stable_block(block);
        let record = Self {
            format: POSY_SIMPLIFIED_MATERIAL_FORMAT.to_string(),
            epoch_context_root: epoch_context.root()?,
            stable_candidate_id,
            candidate_subject,
            canonical_block,
            target_context,
            protected_input,
            transition_subject_root,
        };
        record.validate(epoch_context.root()?)?;
        Ok((record, next_state))
    }

    /// Re-verifies a durable record against the frozen epoch and executes it
    /// from the supplied parent state. Callers must use the returned state as
    /// the parent of the next consecutive finalized record.
    pub fn replay_and_verify(
        &self,
        epoch_context: &SimplifiedEpochContext,
        parent_execution_state: &ExecutionState,
        verifier: &AegisPqvmVerifier,
        validator_set: &ValidatorSet,
        cluster_map: &ClusterMap,
        parameters: &EtdagParameters,
    ) -> Result<ExecutionState, String> {
        self.validate(epoch_context.root()?)?;
        epoch_context.validate_against(&validator_set.active_for_epoch(epoch_context.epoch))?;
        match (&self.target_context, &self.protected_input) {
            (None, None) => verify_block_execution(parent_execution_state, &self.canonical_block),
            (Some(target_context), Some(protected_input)) => {
                validate_target_context_for_epoch(
                    target_context,
                    epoch_context,
                    self.candidate_subject.context.height,
                )?;
                let transactions = protected_input.verify_and_extract_transactions(
                    verifier,
                    target_context,
                    validator_set,
                    cluster_map,
                    parameters,
                )?;
                if transactions != self.canonical_block.transactions {
                    return Err(
                        "durable protected material body differs from its verified ETDAG reveal"
                            .to_string(),
                    );
                }
                let (next_state, receipts) = verify_block_execution_with_receipts(
                    parent_execution_state,
                    &self.canonical_block,
                )?;
                let manifest =
                    protected_input.build_execution_manifest(&transactions, &receipts)?;
                let commitment =
                    protected_input.protected_batch_commitment(&manifest, &receipts)?;
                if self.canonical_block.header.protected_batch.as_ref() != Some(&commitment) {
                    return Err(
                        "durable protected material header does not bind replayed ETDAG execution"
                            .to_string(),
                    );
                }
                Ok(next_state)
            }
            _ => Err(
                "target context and protected input must be both present or both absent"
                    .to_string(),
            ),
        }
    }

    /// Re-verifies a core-only durable record without constructing an ETDAG
    /// verifier.  This path is deliberately unavailable to protected records:
    /// once a finalized ETDAG permit is active, callers must use
    /// [`Self::replay_and_verify`] with the frozen validator/cluster authority
    /// and the production Aegis verifier.
    pub fn replay_core(
        &self,
        epoch_context: &SimplifiedEpochContext,
        parent_execution_state: &ExecutionState,
    ) -> Result<ExecutionState, String> {
        self.validate(epoch_context.root()?)?;
        if self.target_context.is_some() || self.protected_input.is_some() {
            return Err(
                "protected simplified material cannot use the core-only replay path".to_string(),
            );
        }
        verify_block_execution(parent_execution_state, &self.canonical_block)
    }

    pub fn validate(&self, expected_epoch_context_root: Hash) -> Result<(), String> {
        if self.format != POSY_SIMPLIFIED_MATERIAL_FORMAT
            || expected_epoch_context_root.is_zero()
            || self.epoch_context_root != expected_epoch_context_root
            || self.stable_candidate_id != self.candidate_subject.id()?
            || self.transition_subject_root.is_some_and(Hash::is_zero)
            || self.canonical_block.candidate_id()? != self.candidate_subject.block_id
            || self.canonical_block.header.round != Round(0)
            || !self
                .canonical_block
                .header
                .proposer_validator_id
                .0
                .is_empty()
            || !self.canonical_block.header.proposer_uma_id.0.is_empty()
            || !self.canonical_block.header.proposer_key_id.0.is_empty()
            || !self.canonical_block.proposer_signature.algorithm.is_empty()
            || !self
                .canonical_block
                .proposer_signature
                .signature_bytes
                .is_empty()
        {
            return Err("invalid simplified protected-material identity".to_string());
        }
        let expected_parent_hash = Hash::from_hex(&self.candidate_subject.parent_block_id.0)?;
        let parameter_root = ConsensusParameterRoot::from_hex(
            &self.candidate_subject.context.consensus_parameter_root,
        )?;
        if self.canonical_block.header.chain_id != self.candidate_subject.context.chain_id
            || self.canonical_block.header.network_id != self.candidate_subject.context.network_id
            || self.canonical_block.header.protocol_version
                != self.candidate_subject.context.protocol_version
            || self.canonical_block.header.parent_block_hash != expected_parent_hash
            || self.canonical_block.header.height != self.candidate_subject.context.height
            || self.canonical_block.header.epoch != self.candidate_subject.context.epoch
            || self.canonical_block.header.height_context_root
                != self.candidate_subject.context.epoch_context_root
            || self.canonical_block.header.active_validator_set_hash
                != self.candidate_subject.context.active_validator_set_root
            || self.canonical_block.header.eligible_validator_set_hash
                != self.candidate_subject.context.active_validator_set_root
            || self.canonical_block.header.validator_consensus_key_root
                != self.candidate_subject.context.validator_consensus_key_root
            || self.canonical_block.header.frozen_bonded_weight_root
                != self.candidate_subject.context.frozen_voting_weight_root
            || self.canonical_block.header.protocol_config_hash != parameter_root
            || self.canonical_block.header.parent_state_root
                != self.canonical_block.header.state_root_before
            || self.canonical_block.header.tx_count
                != u64::try_from(self.canonical_block.transactions.len())
                    .map_err(|_| "simplified material transaction count exceeds u64".to_string())?
        {
            return Err("simplified protected material block binding is invalid".to_string());
        }
        match (&self.target_context, &self.protected_input) {
            (None, None) => {
                if !self.canonical_block.transactions.is_empty()
                    || self.canonical_block.header.protected_batch.is_some()
                {
                    return Err("core material unexpectedly contains protected input".to_string());
                }
            }
            (Some(target), Some(input)) => {
                target.validate()?;
                input
                    .digest()?
                    .validate("simplified protected-input digest")?;
                if target.target_height != self.candidate_subject.context.height
                    || target.epoch != self.candidate_subject.context.epoch
                    || self.canonical_block.header.protected_batch.is_none()
                {
                    return Err("ETDAG material is not bound to the candidate slot".to_string());
                }
            }
            _ => {
                return Err(
                    "target context and protected input must be both present or both absent"
                        .to_string(),
                );
            }
        }
        let recomputed = compute_simplified_protected_execution_root_with_transition_subject(
            &self.candidate_subject.context,
            &self.canonical_block,
            &self.candidate_subject.parent_block_id,
            &self.candidate_subject.parent,
            self.target_context.as_ref(),
            self.protected_input.as_ref(),
            self.transition_subject_root,
        )?;
        if recomputed != self.candidate_subject.protected_execution_root {
            return Err("simplified protected-execution root mismatch".to_string());
        }
        let encoded = serde_json::to_vec(self)
            .map_err(|error| format!("encode simplified material for bounds: {error}"))?;
        if encoded.len() > MAX_POSY_SIMPLIFIED_MATERIAL_RECORD_BYTES {
            return Err(
                "simplified protected material exceeds the durable record bound".to_string(),
            );
        }
        Ok(())
    }

    pub fn from_canonical_bytes(
        bytes: &[u8],
        expected_epoch_context_root: Hash,
    ) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_POSY_SIMPLIFIED_MATERIAL_RECORD_BYTES {
            return Err("simplified protected material violates its decode bound".to_string());
        }
        let record = Self::assert_canonical_bytes(bytes)?;
        record.validate(expected_epoch_context_root)?;
        Ok(record)
    }
}

fn validate_target_context_for_epoch(
    target_context: &TargetAdmissionContext,
    epoch_context: &SimplifiedEpochContext,
    height: crate::synergy_types::Height,
) -> Result<(), String> {
    target_context.validate()?;
    if target_context.epoch != epoch_context.epoch
        || target_context.target_height != height
        || target_context.active_validator_set_root != epoch_context.active_validator_set_root
        || target_context.validator_consensus_key_root != epoch_context.validator_consensus_key_root
        || target_context.frozen_bonded_weight_root != epoch_context.frozen_voting_weight_root
        || target_context.consensus_parameter_root.to_hex()
            != epoch_context.consensus_parameter_root
    {
        return Err(
            "protected material target context differs from the simplified frozen epoch"
                .to_string(),
        );
    }
    Ok(())
}

pub fn compute_simplified_protected_execution_root(
    context: &super::ConsensusObjectContext,
    block: &Block,
    parent_block_id: &BlockId,
    parent: &SimplifiedFinalityParent,
    target_context: Option<&TargetAdmissionContext>,
    protected_input: Option<&ProtectedBlockInput>,
) -> Result<Hash, String> {
    compute_simplified_protected_execution_root_with_transition_subject(
        context,
        block,
        parent_block_id,
        parent,
        target_context,
        protected_input,
        None,
    )
}

/// Computes the exact QC-covered root for a proposal that optionally carries
/// a dynamic-membership transition subject. The root, rather than a mutable
/// side channel, is the only authority carried forward to epoch transition.
pub fn compute_simplified_protected_execution_root_with_transition_subject(
    context: &super::ConsensusObjectContext,
    block: &Block,
    parent_block_id: &BlockId,
    parent: &SimplifiedFinalityParent,
    target_context: Option<&TargetAdmissionContext>,
    protected_input: Option<&ProtectedBlockInput>,
    transition_subject_root: Option<Hash>,
) -> Result<Hash, String> {
    if (target_context.is_some()) != (protected_input.is_some()) {
        return Err(
            "protected-execution commitment requires both target context and protected input"
                .to_string(),
        );
    }
    let canonical_block = canonical_stable_block(block.clone());
    let block_id = canonical_block.candidate_id()?;
    let mut stable_context = context.clone();
    stable_context.round = Round(0);
    let target_context_root = target_context
        .map(TargetAdmissionContext::root)
        .transpose()?;
    let protected_input_digest = protected_input
        .map(ProtectedBlockInput::digest)
        .transpose()?;
    let subject = ProtectedExecutionRootSubject {
        context: &stable_context,
        block_id: &block_id,
        parent_block_id,
        parent,
        canonical_block_header: &canonical_block.header,
        transactions: &canonical_block.transactions,
        target_context_root,
        protected_input_digest: protected_input_digest.as_ref(),
        transition_subject_root,
    };
    let bytes = serde_json::to_vec(&subject)
        .map_err(|error| format!("serialize simplified protected-execution transcript: {error}"))?;
    Ok(Hash::from_domain_bytes(
        "SYNERGY_POSY_SIMPLIFIED_PROTECTED_EXECUTION_V2",
        &bytes,
    ))
}

fn validate_block_binding(
    epoch_context: &SimplifiedEpochContext,
    proposal: &SimplifiedProposal,
    block: &Block,
    transition_subject_root: Option<Hash>,
) -> Result<(), String> {
    proposal.context.validate_against(epoch_context)?;
    let parameter_root = ConsensusParameterRoot::from_hex(&epoch_context.consensus_parameter_root)?;
    if block.candidate_id()? != proposal.block_id
        || block.header.chain_id != proposal.context.chain_id
        || block.header.network_id != proposal.context.network_id
        || block.header.protocol_version != POSY_SIMPLIFIED_PROTOCOL_VERSION
        || block.header.height != proposal.context.height
        || block.header.round != proposal.context.round
        || block.header.epoch != proposal.context.epoch
        || block.header.height_context_root != proposal.context.epoch_context_root
        || block.header.proposer_validator_id != proposal.proposer_id
        || block.header.proposer_key_id != proposal.proposer_key_id
        || block.header.active_validator_set_hash != proposal.context.active_validator_set_root
        || block.header.eligible_validator_set_hash != proposal.context.active_validator_set_root
        || block.header.validator_consensus_key_root
            != proposal.context.validator_consensus_key_root
        || block.header.frozen_bonded_weight_root != proposal.context.frozen_voting_weight_root
        || block.header.protocol_config_hash != parameter_root
        || block.header.parent_state_root != block.header.state_root_before
        || block.header.tx_count
            != u64::try_from(block.transactions.len())
                .map_err(|_| "simplified material transaction count exceeds u64".to_string())?
        || block.header.parent_block_hash != Hash::from_hex(&proposal.parent_block_id.0)?
    {
        return Err("simplified proposal and protected block material disagree".to_string());
    }
    let recomputed = compute_simplified_protected_execution_root_with_transition_subject(
        &proposal.context,
        block,
        &proposal.parent_block_id,
        &proposal.parent,
        None,
        None,
        transition_subject_root,
    );
    if block.transactions.is_empty() && block.header.protected_batch.is_none() {
        if recomputed? != proposal.protected_execution_root {
            return Err("simplified core protected-execution root mismatch".to_string());
        }
    }
    Ok(())
}

fn verify_block_execution(state: &ExecutionState, block: &Block) -> Result<ExecutionState, String> {
    verify_block_execution_with_receipts(state, block).map(|(state, _)| state)
}

fn verify_block_execution_with_receipts(
    state: &ExecutionState,
    block: &Block,
) -> Result<(ExecutionState, Vec<crate::execution::TransactionReceipt>), String> {
    let state_root_before = compute_state_root_after(state)?;
    if block.header.state_root_before != state_root_before
        || block.header.parent_state_root != state_root_before
    {
        return Err("simplified block does not extend the supplied execution state".to_string());
    }
    let mut authorized = state.clone();
    for transaction in &block.transactions {
        authorized.mark_authorized_at(
            transaction,
            block
                .header
                .timestamp_ms_consensus_bounded
                .saturating_div(1_000),
        )?;
    }
    let execution = execute_block(block, &authorized)?;
    if execution.state_root_after != block.header.state_root_after
        || execution.receipt_root != block.header.receipt_root
    {
        return Err("simplified protected block execution roots mismatch".to_string());
    }
    Ok((execution.state, execution.receipts))
}

fn canonical_stable_block(mut block: Block) -> Block {
    block.header.round = Round(0);
    block.header.proposer_validator_id = ValidatorId(String::new());
    block.header.proposer_uma_id = UmaId(String::new());
    block.header.proposer_key_id = AegisPqKeyId(String::new());
    block.proposer_signature = AegisPqSignature {
        algorithm: String::new(),
        signature_bytes: Vec::new(),
    };
    block
}

#[derive(Debug, Clone)]
pub struct DurableSimplifiedProposalMaterialStore {
    directory: PathBuf,
    epoch_context_root: Hash,
}

static MATERIAL_STORE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

impl DurableSimplifiedProposalMaterialStore {
    pub fn for_epoch(epoch_context_root: Hash) -> Result<Self, String> {
        Self::at_directory(
            crate::utils::resolve_data_path(POSY_SIMPLIFIED_MATERIAL_DIRECTORY),
            epoch_context_root,
        )
    }

    pub fn at_directory(
        directory: impl Into<PathBuf>,
        epoch_context_root: Hash,
    ) -> Result<Self, String> {
        let directory = directory.into();
        if directory.as_os_str().is_empty() || epoch_context_root.is_zero() {
            return Err(
                "simplified material store requires a directory and epoch root".to_string(),
            );
        }
        Ok(Self {
            directory,
            epoch_context_root,
        })
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn epoch_context_root(&self) -> Hash {
        self.epoch_context_root
    }

    pub fn install_verified(
        &self,
        record: &VerifiedSimplifiedProposalMaterial,
    ) -> Result<(), String> {
        record.validate(self.epoch_context_root)?;
        let _guard = MATERIAL_STORE_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .map_err(|_| "simplified material store lock poisoned".to_string())?;
        fs::create_dir_all(&self.directory).map_err(|error| {
            format!(
                "create simplified material directory {}: {error}",
                self.directory.display()
            )
        })?;
        let path = self.record_path(record.stable_candidate_id);
        if path.exists() {
            let existing = self.load_unlocked(record.stable_candidate_id)?;
            if existing == *record {
                return Ok(());
            }
            return Err("SIMPLIFIED_PROTECTED_MATERIAL_CONFLICT".to_string());
        }
        let bytes = serde_json::to_vec(record)
            .map_err(|error| format!("encode simplified material record: {error}"))?;
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| format!("clock failure for material persistence: {error}"))?
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
                .map_err(|error| format!("create material temp {}: {error}", temp.display()))?;
            file.write_all(&bytes)
                .map_err(|error| format!("write material temp {}: {error}", temp.display()))?;
            file.sync_all()
                .map_err(|error| format!("sync material temp {}: {error}", temp.display()))?;
            match fs::hard_link(&temp, &path) {
                Ok(()) => {
                    fs::remove_file(&temp).map_err(|error| {
                        format!("remove linked material temp {}: {error}", temp.display())
                    })?;
                    sync_directory(&self.directory)
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let existing = self.load_unlocked(record.stable_candidate_id)?;
                    if existing != *record {
                        return Err("SIMPLIFIED_PROTECTED_MATERIAL_CONFLICT".to_string());
                    }
                    fs::remove_file(&temp).map_err(|remove_error| {
                        format!(
                            "remove idempotent material temp {}: {remove_error}",
                            temp.display()
                        )
                    })?;
                    Ok(())
                }
                Err(error) => Err(format!(
                    "atomically install material {}: {error}",
                    path.display()
                )),
            }
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }

    pub fn load(
        &self,
        stable_candidate_id: Hash,
    ) -> Result<VerifiedSimplifiedProposalMaterial, String> {
        let _guard = MATERIAL_STORE_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .map_err(|_| "simplified material store lock poisoned".to_string())?;
        self.load_unlocked(stable_candidate_id)
    }

    pub fn load_optional(
        &self,
        stable_candidate_id: Hash,
    ) -> Result<Option<VerifiedSimplifiedProposalMaterial>, String> {
        let _guard = MATERIAL_STORE_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .map_err(|_| "simplified material store lock poisoned".to_string())?;
        if stable_candidate_id.is_zero() {
            return Err("simplified material lookup candidate is zero".to_string());
        }
        if !self.record_path(stable_candidate_id).exists() {
            return Ok(None);
        }
        self.load_unlocked(stable_candidate_id).map(Some)
    }

    fn load_unlocked(
        &self,
        stable_candidate_id: Hash,
    ) -> Result<VerifiedSimplifiedProposalMaterial, String> {
        if stable_candidate_id.is_zero() {
            return Err("simplified material lookup candidate is zero".to_string());
        }
        let path = self.record_path(stable_candidate_id);
        let bytes = fs::read(&path)
            .map_err(|error| format!("read simplified material {}: {error}", path.display()))?;
        if bytes.len() > MAX_POSY_SIMPLIFIED_MATERIAL_RECORD_BYTES {
            return Err("simplified material record exceeds its decode bound".to_string());
        }
        let record: VerifiedSimplifiedProposalMaterial = serde_json::from_slice(&bytes)
            .map_err(|error| format!("parse simplified material {}: {error}", path.display()))?;
        if serde_json::to_vec(&record)
            .map_err(|error| format!("canonicalize simplified material: {error}"))?
            != bytes
        {
            return Err("simplified material record is not canonical".to_string());
        }
        record.validate(self.epoch_context_root)?;
        if record.stable_candidate_id != stable_candidate_id {
            return Err("simplified material filename and candidate disagree".to_string());
        }
        Ok(record)
    }

    fn record_path(&self, stable_candidate_id: Hash) -> PathBuf {
        self.directory
            .join(format!("{}.json", stable_candidate_id.to_hex()))
    }
}

/// Canonical construction and replay boundary behind the durable material
/// source. Production adapters must independently execute and verify ETDAG;
/// the wrapper supplies persistence, request serving, and candidate binding.
pub trait SimplifiedMaterialAdapter: Send {
    fn build_local(
        &mut self,
        epoch_context: &SimplifiedEpochContext,
        directive: &SimplifiedProposalDirective,
    ) -> Result<Option<(SimplifiedProposal, VerifiedSimplifiedProposalMaterial)>, String>;

    fn verify_received(
        &mut self,
        epoch_context: &SimplifiedEpochContext,
        proposal: &SimplifiedProposal,
        expected_finalized: &FinalizedBlockRecord,
        material: &VerifiedSimplifiedProposalMaterial,
    ) -> Result<Hash, String>;
}

/// Durable proposal source used by the operational driver and material-sync
/// protocol. No unverified record is exposed for ECHO or VOTE.
pub struct DurableVerifiedSimplifiedProposalSource<A> {
    epoch_context: SimplifiedEpochContext,
    store: DurableSimplifiedProposalMaterialStore,
    adapter: A,
}

impl<A: SimplifiedMaterialAdapter> DurableVerifiedSimplifiedProposalSource<A> {
    pub fn new(
        epoch_context: SimplifiedEpochContext,
        store: DurableSimplifiedProposalMaterialStore,
        adapter: A,
    ) -> Result<Self, String> {
        epoch_context.validate()?;
        if store.epoch_context_root() != epoch_context.root()? {
            return Err(
                "simplified proposal source and material store name different epochs".to_string(),
            );
        }
        Ok(Self {
            epoch_context,
            store,
            adapter,
        })
    }

    fn candidate_id(proposal: &SimplifiedProposal) -> Result<Hash, String> {
        CertifiedCandidateSubject::new(
            proposal.context.clone(),
            proposal.block_id.clone(),
            proposal.parent_block_id.clone(),
            proposal.parent.clone(),
            proposal.protected_execution_root,
        )?
        .id()
    }

    fn verify_candidate_material(
        &mut self,
        proposal: &SimplifiedProposal,
        expected_finalized: &FinalizedBlockRecord,
        material: &VerifiedSimplifiedProposalMaterial,
    ) -> Result<Hash, String> {
        let candidate_id = Self::candidate_id(proposal)?;
        if material.stable_candidate_id != candidate_id
            || material.candidate_subject
                != CertifiedCandidateSubject::new(
                    proposal.context.clone(),
                    proposal.block_id.clone(),
                    proposal.parent_block_id.clone(),
                    proposal.parent.clone(),
                    proposal.protected_execution_root,
                )?
        {
            return Err(
                "proposal material does not bind the requested stable candidate".to_string(),
            );
        }
        let root = self.adapter.verify_received(
            &self.epoch_context,
            proposal,
            expected_finalized,
            material,
        )?;
        if root.is_zero() || root != proposal.protected_execution_root {
            return Err("proposal material adapter reproduced another protected root".to_string());
        }
        Ok(root)
    }
}

impl<A: SimplifiedMaterialAdapter> SimplifiedProtectedProposalSource
    for DurableVerifiedSimplifiedProposalSource<A>
{
    fn proposal_for(
        &mut self,
        epoch_context: &SimplifiedEpochContext,
        directive: &SimplifiedProposalDirective,
    ) -> Result<Option<SimplifiedProposal>, String> {
        if epoch_context.root()? != self.epoch_context.root()? {
            return Err("proposal request names another durable material epoch".to_string());
        }
        if let Some(candidate) = &directive.mandatory_carry_candidate {
            let material = self.store.load(candidate.id()?)?;
            let proposal = SimplifiedProposal {
                context: directive.context.clone(),
                block_id: candidate.block_id.clone(),
                parent_block_id: candidate.parent_block_id.clone(),
                parent: candidate.parent.clone(),
                takeover_tc_id: directive.takeover_tc_id,
                protected_execution_root: candidate.protected_execution_root,
                proposer_id: directive.proposer_id.clone(),
                proposer_key_id: directive.proposer_key_id.clone(),
                proposer_signature: AegisPqSignature {
                    algorithm: String::new(),
                    signature_bytes: Vec::new(),
                },
            };
            self.verify_candidate_material(&proposal, &directive.finalized, &material)?;
            return Ok(Some(proposal));
        }
        let Some((proposal, material)) = self.adapter.build_local(epoch_context, directive)? else {
            return Ok(None);
        };
        self.verify_candidate_material(&proposal, &directive.finalized, &material)?;
        self.store.install_verified(&material)?;
        Ok(Some(proposal))
    }

    fn recompute_received_protected_execution_root(
        &mut self,
        proposal: &SimplifiedProposal,
        expected_finalized: &FinalizedBlockRecord,
    ) -> Result<Option<Hash>, String> {
        let candidate_id = Self::candidate_id(proposal)?;
        let Some(material) = self.store.load_optional(candidate_id)? else {
            return Ok(None);
        };
        self.verify_candidate_material(proposal, expected_finalized, &material)
            .map(Some)
    }

    fn install_received_material(
        &mut self,
        proposal: &SimplifiedProposal,
        expected_finalized: &FinalizedBlockRecord,
        material: VerifiedSimplifiedProposalMaterial,
    ) -> Result<Hash, String> {
        let root = self.verify_candidate_material(proposal, expected_finalized, &material)?;
        self.store.install_verified(&material)?;
        Ok(root)
    }

    fn material_for_serving(
        &mut self,
        stable_candidate_id: Hash,
    ) -> Result<Option<VerifiedSimplifiedProposalMaterial>, String> {
        self.store.load_optional(stable_candidate_id)
    }
}

fn sync_directory(directory: &Path) -> Result<(), String> {
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|error| format!("sync material directory {}: {error}", directory.display()))
}

#[cfg(test)]
mod tests {
    use super::super::{
        DurableSimplifiedProtectedExecutionTransitionAuthorityVerifier,
        SimplifiedFinalizedTransitionAuthorityEvidence, SimplifiedMaterialChunk,
        SimplifiedMaterialStager, SimplifiedQuorumCertificate,
        SimplifiedTransitionAuthorityVerifier, POSY_SIMPLIFIED_MATERIAL_CHUNK_FORMAT,
    };
    use super::*;
    use crate::consensus_parameters::ConsensusParameterRoot;
    use crate::execution::compute_receipt_root;
    use crate::synergy_types::{
        AegisPqPublicKey, ChainId, ClusterId, Epoch, Height, NetworkId, ValidatorRecord,
        ValidatorStatus, TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM,
        TESTNET_V3_MLDSA65_PUBLIC_KEY_BYTES,
    };

    fn validators() -> ValidatorSet {
        ValidatorSet {
            epoch: Epoch(9),
            validators: (0..5)
                .map(|index| {
                    let key = AegisPqPublicKey {
                        key_id: AegisPqKeyId(format!("material-key-{index}")),
                        algorithm: TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM.to_string(),
                        key_bytes: vec![index as u8 + 1; TESTNET_V3_MLDSA65_PUBLIC_KEY_BYTES],
                    };
                    ValidatorRecord {
                        validator_id: ValidatorId(format!("material-validator-{index}")),
                        validator_uma_id: UmaId(format!("uma:material-validator-{index}")),
                        consensus_public_key: key.clone(),
                        peer_public_key: key.clone(),
                        operator_public_key: key,
                        voting_weight: 1,
                        status: ValidatorStatus::Active,
                        cluster_id: ClusterId(0),
                        activation_epoch: Epoch(9),
                    }
                })
                .collect(),
        }
    }

    fn context() -> SimplifiedEpochContext {
        SimplifiedEpochContext::derive(
            Epoch(9),
            Height(4_000),
            Height(4_999),
            Hash::from_domain_bytes("material-test-seed", b"epoch-9"),
            ConsensusParameterRoot::from_canonical_manifest_bytes(b"material-parameters"),
            &validators(),
        )
        .unwrap()
    }

    fn core_material() -> (VerifiedSimplifiedProposalMaterial, ExecutionState) {
        core_material_with_transition_subject(None)
    }

    fn core_material_with_transition_subject(
        transition_subject_root: Option<Hash>,
    ) -> (VerifiedSimplifiedProposalMaterial, ExecutionState) {
        let context = context();
        let object_context =
            super::super::ConsensusObjectContext::for_height(&context, Height(4_000), Round(0))
                .unwrap();
        let parent_hash = Hash::from_domain_bytes("material-test-parent", b"height-3999");
        let parent_block_id = BlockId::from_hash(parent_hash);
        let parent_qc = QuorumCertificateReference {
            height: Height(3_999),
            block_id: parent_block_id.clone(),
            qc_id: Hash::from_domain_bytes("material-test-parent-qc", b"height-3999"),
        };
        let parent = SimplifiedFinalityParent::quorum_certificate(parent_qc.clone()).unwrap();
        let state = ExecutionState::new();
        let state_root = compute_state_root_after(&state).unwrap();
        let block = Block {
            header: crate::synergy_types::BlockHeader {
                version: 3,
                chain_id: ChainId::synergy_testnet_v3(),
                network_id: NetworkId::fresh_posy_testnet_v3(),
                protocol_version: POSY_SIMPLIFIED_PROTOCOL_VERSION.to_string(),
                height: Height(4_000),
                round: Round(0),
                epoch: Epoch(9),
                cluster_id: ClusterId(0),
                height_context_root: context.root().unwrap(),
                parent_block_hash: parent_hash,
                parent_state_root: state_root,
                last_finalized_qc_hash: parent_qc.qc_id,
                proposer_validator_id: context.leader_ring[0].clone(),
                proposer_uma_id: UmaId("uma:material-validator-0".to_string()),
                proposer_key_id: AegisPqKeyId("material-key-0".to_string()),
                active_validator_set_hash: context.active_validator_set_root,
                eligible_validator_set_hash: context.active_validator_set_root,
                validator_consensus_key_root: context.validator_consensus_key_root,
                frozen_bonded_weight_root: context.frozen_voting_weight_root,
                cluster_schedule_version: "posy-v3-one-cluster".to_string(),
                cluster_map_hash: Hash::from_domain_bytes("material-test", b"cluster-map"),
                assigned_cluster_membership_root: Hash::from_domain_bytes(
                    "material-test",
                    b"cluster-membership",
                ),
                assigned_cluster_validator_count: 5,
                assigned_cluster_total_voting_weight: 5,
                proposer_schedule_hash: context.leader_ring_root,
                protocol_config_hash: ConsensusParameterRoot::from_hex(
                    &context.consensus_parameter_root,
                )
                .unwrap(),
                cryptographic_profile_root: Hash::from_domain_bytes(
                    "material-test",
                    b"crypto-profile",
                ),
                dag_frontier_root: Hash::from_domain_bytes("material-test", b"dag"),
                tx_order_root: Hash::from_domain_bytes("material-test", b"empty-order"),
                tx_count: 0,
                protected_batch: None,
                evidence_root: Hash::from_domain_bytes("material-test", b"evidence"),
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
                signature_bytes: vec![7],
            },
        };
        let block_id = block.candidate_id().unwrap();
        let protected_execution_root =
            compute_simplified_protected_execution_root_with_transition_subject(
                &object_context,
                &block,
                &parent_block_id,
                &parent,
                None,
                None,
                transition_subject_root,
            )
            .unwrap();
        let proposal = SimplifiedProposal {
            context: object_context,
            block_id,
            parent_block_id,
            parent,
            takeover_tc_id: None,
            protected_execution_root,
            proposer_id: block.header.proposer_validator_id.clone(),
            proposer_key_id: block.header.proposer_key_id.clone(),
            proposer_signature: block.proposer_signature.clone(),
        };
        VerifiedSimplifiedProposalMaterial::verify_core_with_transition_subject(
            &context,
            &proposal,
            block,
            &state,
            transition_subject_root,
        )
        .unwrap()
    }

    fn unique_directory(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "posy-material-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn verified_core_material_is_stable_durable_and_idempotent() {
        let (record, state) = core_material();
        assert_eq!(state, ExecutionState::new());
        assert_eq!(
            record
                .replay_and_verify(
                    &context(),
                    &ExecutionState::new(),
                    &AegisPqvmVerifier::unavailable_for_startup_tests(),
                    &validators(),
                    &ClusterMap {
                        epoch: Epoch(9),
                        assignments: Vec::new(),
                    },
                    &EtdagParameters::default(),
                )
                .unwrap(),
            state
        );
        let directory = unique_directory("restart");
        let store = DurableSimplifiedProposalMaterialStore::at_directory(
            &directory,
            record.epoch_context_root,
        )
        .unwrap();
        store.install_verified(&record).unwrap();
        store.install_verified(&record).unwrap();
        let reopened = DurableSimplifiedProposalMaterialStore::at_directory(
            &directory,
            record.epoch_context_root,
        )
        .unwrap();
        assert_eq!(reopened.load(record.stable_candidate_id).unwrap(), record);
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn material_store_rejects_noncanonical_or_wrong_epoch_records() {
        let (record, _) = core_material();
        let directory = unique_directory("wrong-epoch");
        let wrong_store = DurableSimplifiedProposalMaterialStore::at_directory(
            &directory,
            Hash::from_domain_bytes("material-wrong-epoch", b"wrong"),
        )
        .unwrap();
        assert!(wrong_store.install_verified(&record).is_err());
        assert!(!directory.exists());

        let canonical_directory = unique_directory("noncanonical");
        let store = DurableSimplifiedProposalMaterialStore::at_directory(
            &canonical_directory,
            record.epoch_context_root,
        )
        .unwrap();
        store.install_verified(&record).unwrap();
        let path = store.record_path(record.stable_candidate_id);
        let mut bytes = fs::read(&path).unwrap();
        bytes.push(b'\n');
        fs::write(&path, bytes).unwrap();
        assert!(store.load(record.stable_candidate_id).is_err());
        let _ = fs::remove_dir_all(canonical_directory);
    }

    #[test]
    fn protected_execution_root_is_stable_across_takeover_rounds() {
        let (record, _) = core_material();
        let mut later_round = record.candidate_subject.context.clone();
        later_round.round = Round(19);
        let root = compute_simplified_protected_execution_root(
            &later_round,
            &record.canonical_block,
            &record.candidate_subject.parent_block_id,
            &record.candidate_subject.parent,
            None,
            None,
        )
        .unwrap();
        assert_eq!(root, record.candidate_subject.protected_execution_root);
    }

    fn certificate_for_material(
        material: &VerifiedSimplifiedProposalMaterial,
    ) -> SimplifiedQuorumCertificate {
        SimplifiedQuorumCertificate {
            context: material.candidate_subject.context.clone(),
            block_id: material.candidate_subject.block_id.clone(),
            parent_block_id: material.candidate_subject.parent_block_id.clone(),
            parent: material.candidate_subject.parent.clone(),
            takeover_tc_id: None,
            protected_execution_root: material.candidate_subject.protected_execution_root,
            participants: Vec::new(),
        }
    }

    #[test]
    fn durable_transition_authority_requires_qc_bound_material_subject() {
        let transition_subject_root =
            Hash::from_domain_bytes("material-transition-subject", b"epoch-10-membership");
        let (material, _) = core_material_with_transition_subject(Some(transition_subject_root));
        let certificate = certificate_for_material(&material);
        let directory = unique_directory("transition-authority");
        let store = DurableSimplifiedProposalMaterialStore::at_directory(
            &directory,
            material.epoch_context_root,
        )
        .unwrap();
        store.install_verified(&material).unwrap();
        let verifier = DurableSimplifiedProtectedExecutionTransitionAuthorityVerifier::new(store);
        let evidence = SimplifiedFinalizedTransitionAuthorityEvidence::from_finalized_qc(
            &certificate,
            transition_subject_root,
        )
        .unwrap()
        .canonical_record_bytes()
        .unwrap();
        verifier
            .verify_finalized_transition_authority(&certificate, transition_subject_root, &evidence)
            .unwrap();

        let (unbound_material, _) = core_material();
        let unbound_certificate = certificate_for_material(&unbound_material);
        let unbound_directory = unique_directory("transition-authority-unbound");
        let unbound_store = DurableSimplifiedProposalMaterialStore::at_directory(
            &unbound_directory,
            unbound_material.epoch_context_root,
        )
        .unwrap();
        unbound_store.install_verified(&unbound_material).unwrap();
        let unbound_verifier =
            DurableSimplifiedProtectedExecutionTransitionAuthorityVerifier::new(unbound_store);
        let unbound_evidence = SimplifiedFinalizedTransitionAuthorityEvidence::from_finalized_qc(
            &unbound_certificate,
            transition_subject_root,
        )
        .unwrap()
        .canonical_record_bytes()
        .unwrap();
        assert!(unbound_verifier
            .verify_finalized_transition_authority(
                &unbound_certificate,
                transition_subject_root,
                &unbound_evidence,
            )
            .is_err());

        let _ = fs::remove_dir_all(directory);
        let _ = fs::remove_dir_all(unbound_directory);
    }

    fn two_material_chunks(
        record: &VerifiedSimplifiedProposalMaterial,
        request_id: Hash,
    ) -> [SimplifiedMaterialChunk; 2] {
        let bytes = record.canonical_bytes().unwrap();
        let split = bytes.len() / 2;
        let record_root =
            Hash::from_domain_bytes("SYNERGY_POSY_SIMPLIFIED_MATERIAL_RECORD_V1", &bytes);
        let mut first = SimplifiedMaterialChunk {
            format: POSY_SIMPLIFIED_MATERIAL_CHUNK_FORMAT.to_string(),
            request_id,
            epoch_context_root: record.epoch_context_root,
            stable_candidate_id: record.stable_candidate_id,
            record_root,
            sequence: 0,
            total_chunks: 2,
            previous_chunk_root: None,
            payload: bytes[..split].to_vec(),
            chunk_root: Hash::zero(),
        };
        first.chunk_root = first.computed_root().unwrap();
        let mut second = SimplifiedMaterialChunk {
            format: POSY_SIMPLIFIED_MATERIAL_CHUNK_FORMAT.to_string(),
            request_id,
            epoch_context_root: record.epoch_context_root,
            stable_candidate_id: record.stable_candidate_id,
            record_root,
            sequence: 1,
            total_chunks: 2,
            previous_chunk_root: Some(first.chunk_root),
            payload: bytes[split..].to_vec(),
            chunk_root: Hash::zero(),
        };
        second.chunk_root = second.computed_root().unwrap();
        [first, second]
    }

    #[test]
    fn material_stream_is_request_correlated_peer_bound_and_replay_safe() {
        let (record, _) = core_material();
        let request_id = Hash::from_domain_bytes("material-sync-test", b"request");
        let [first, second] = two_material_chunks(&record, request_id);
        let peer = ValidatorId("material-peer".to_string());
        let other_peer = ValidatorId("other-material-peer".to_string());
        let now = std::time::Instant::now();
        let mut stager = SimplifiedMaterialStager::new(record.epoch_context_root).unwrap();
        assert!(stager.accept(&peer, first.clone(), now).is_err());
        stager
            .register_request(request_id, record.stable_candidate_id, &peer, now)
            .unwrap();
        assert!(stager.accept(&other_peer, first.clone(), now).is_err());
        assert!(stager.accept(&peer, first, now).unwrap().is_none());
        assert!(stager.accept(&other_peer, second.clone(), now).is_err());
        assert_eq!(
            stager.accept(&peer, second.clone(), now).unwrap(),
            Some(record)
        );
        assert!(stager.accept(&peer, second, now).is_err());
    }

    struct TestMaterialAdapter {
        local: Option<(SimplifiedProposal, VerifiedSimplifiedProposalMaterial)>,
    }

    impl SimplifiedMaterialAdapter for TestMaterialAdapter {
        fn build_local(
            &mut self,
            _epoch_context: &SimplifiedEpochContext,
            _directive: &SimplifiedProposalDirective,
        ) -> Result<Option<(SimplifiedProposal, VerifiedSimplifiedProposalMaterial)>, String>
        {
            Ok(self.local.take())
        }

        fn verify_received(
            &mut self,
            epoch_context: &SimplifiedEpochContext,
            proposal: &SimplifiedProposal,
            _expected_finalized: &FinalizedBlockRecord,
            material: &VerifiedSimplifiedProposalMaterial,
        ) -> Result<Hash, String> {
            material.validate(epoch_context.root()?)?;
            if material.candidate_subject.id()?
                != CertifiedCandidateSubject::new(
                    proposal.context.clone(),
                    proposal.block_id.clone(),
                    proposal.parent_block_id.clone(),
                    proposal.parent.clone(),
                    proposal.protected_execution_root,
                )?
                .id()?
            {
                return Err("test material candidate mismatch".to_string());
            }
            Ok(material.candidate_subject.protected_execution_root)
        }
    }

    fn proposal_for_material(
        epoch_context: &SimplifiedEpochContext,
        material: &VerifiedSimplifiedProposalMaterial,
    ) -> SimplifiedProposal {
        let proposer_id = epoch_context
            .authorized_proposer(material.candidate_subject.context.height, 0)
            .unwrap()
            .clone();
        let proposer_key_id = validators()
            .validators
            .into_iter()
            .find(|validator| validator.validator_id == proposer_id)
            .unwrap()
            .consensus_public_key
            .key_id;
        SimplifiedProposal {
            context: material.candidate_subject.context.clone(),
            block_id: material.candidate_subject.block_id.clone(),
            parent_block_id: material.candidate_subject.parent_block_id.clone(),
            parent: material.candidate_subject.parent.clone(),
            takeover_tc_id: None,
            protected_execution_root: material.candidate_subject.protected_execution_root,
            proposer_id,
            proposer_key_id,
            proposer_signature: AegisPqSignature {
                algorithm: TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM.to_string(),
                signature_bytes: vec![1],
            },
        }
    }

    #[test]
    fn durable_material_source_installs_before_serving_and_recovers_missing_remote_input() {
        let (material, _) = core_material();
        let epoch_context = context();
        let proposal = proposal_for_material(&epoch_context, &material);
        let directive = SimplifiedProposalDirective {
            context: proposal.context.clone(),
            parent: proposal.parent.clone(),
            finalized: FinalizedBlockRecord::from_quorum_certificate(
                proposal
                    .parent
                    .quorum_certificate_reference()
                    .unwrap()
                    .clone(),
            )
            .unwrap(),
            proposer_id: proposal.proposer_id.clone(),
            proposer_key_id: proposal.proposer_key_id.clone(),
            takeover_tc_id: None,
            mandatory_carry_candidate: None,
        };
        let source_directory = unique_directory("durable-source");
        let source_store = DurableSimplifiedProposalMaterialStore::at_directory(
            &source_directory,
            epoch_context.root().unwrap(),
        )
        .unwrap();
        let mut source = DurableVerifiedSimplifiedProposalSource::new(
            epoch_context.clone(),
            source_store.clone(),
            TestMaterialAdapter {
                local: Some((proposal.clone(), material.clone())),
            },
        )
        .unwrap();
        assert_eq!(
            source
                .proposal_for(&epoch_context, &directive)
                .unwrap()
                .unwrap(),
            proposal
        );
        assert_eq!(
            source
                .material_for_serving(material.stable_candidate_id)
                .unwrap(),
            Some(material.clone())
        );

        let target_directory = unique_directory("durable-target");
        let target_store = DurableSimplifiedProposalMaterialStore::at_directory(
            &target_directory,
            epoch_context.root().unwrap(),
        )
        .unwrap();
        let mut target = DurableVerifiedSimplifiedProposalSource::new(
            epoch_context,
            target_store,
            TestMaterialAdapter { local: None },
        )
        .unwrap();
        assert_eq!(
            target
                .recompute_received_protected_execution_root(&proposal, &directive.finalized)
                .unwrap(),
            None
        );
        assert_eq!(
            target
                .install_received_material(&proposal, &directive.finalized, material.clone())
                .unwrap(),
            proposal.protected_execution_root
        );
        assert_eq!(
            target
                .recompute_received_protected_execution_root(&proposal, &directive.finalized)
                .unwrap(),
            Some(proposal.protected_execution_root)
        );
        let _ = fs::remove_dir_all(source_directory);
        let _ = fs::remove_dir_all(target_directory);
    }
}
