//! Production protected-ETDAG material adapter for simplified PoSy.
//!
//! ETDAG supplies certified admission and protected execution material. The
//! simplified consensus driver supplies proposer and round authority. This
//! adapter deliberately keeps those authorities separate: it imports no
//! legacy proposer schedule and exposes no empty or plaintext fallback.

use super::{
    compute_simplified_protected_execution_root, ConsensusObjectContext,
    DurableSimplifiedFinalitySink, DurableSimplifiedProposalMaterialStore, FinalizedBlockRecord,
    QuorumCertificateReference, SimplifiedCoreMaterialAdapter, SimplifiedEpochContext,
    SimplifiedFinalityEnvironment, SimplifiedMaterialAdapter,
    SimplifiedPreviousEpochFinalityReplay, SimplifiedProposal, SimplifiedProposalDirective,
    VerifiedSimplifiedEpochTransition, VerifiedSimplifiedProposalMaterial,
    POSY_SIMPLIFIED_PROTOCOL_VERSION,
};
use crate::consensus_parameters::ConsensusParameterRoot;
use crate::crypto::aegis_pqvm::AegisPqvmVerifier;
use crate::dag_mempool::compute_tx_order_root;
use crate::etdag::{
    canonical_finality_context_digest, target_admission_source_finality_root, EtdagDigest,
    EtdagParameters, EtdagProtectedInputCoordinator, EtdagScheduleNeutralFinalityAuthority,
    ProtectedBlockInput, TargetAdmissionContext,
};
use crate::execution::{compute_state_root_after, execute_block, ExecutionState};
use crate::synergy_types::{
    AegisPqSignature, Block, BlockHeader, BlockId, CanonicalSerialize, ClusterMap, Hash,
    Transaction, TxId, ValidatorRecord, ValidatorSet,
};
use std::path::PathBuf;

pub const POSY_SIMPLIFIED_PROTECTED_BLOCK_VERSION: u32 = 3;

/// Exact durable-chain authority needed to execute one protected candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimplifiedProtectedMaterialAuthoritySnapshot {
    pub parent_execution_state: ExecutionState,
    pub canonical_finality_context_digest: EtdagDigest,
}

/// Supplies parent execution and canonical finalized-context authority.
///
/// Production wiring must reconstruct this snapshot from durable finalized
/// execution plus verified certified ancestors. There is intentionally no
/// default, no-op, or process-clock implementation.
pub trait SimplifiedProtectedMaterialAuthority: Send {
    fn authority_for_candidate(
        &mut self,
        context: &ConsensusObjectContext,
        parent_qc: &QuorumCertificateReference,
        finalized: &FinalizedBlockRecord,
    ) -> Result<SimplifiedProtectedMaterialAuthoritySnapshot, String>;
}

/// Maximum number of certified, not-yet-finalized ancestors permitted by the
/// simplified three-chain commit rule.
pub const MAX_SIMPLIFIED_PROTECTED_UNFINALIZED_ANCESTORS: usize = 2;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CanonicalSimplifiedProtectedFinalityContext {
    context_version: u32,
    epoch_context_root: Hash,
    source_finalized: FinalizedBlockRecord,
    source_finalized_state_root: Hash,
    source_active_validator_set_root: Hash,
    source_validator_consensus_key_root: Hash,
    source_frozen_voting_weight_root: Hash,
    source_cluster_map_root: Hash,
}

/// Canonical ETDAG ordering authority derived only from the finalized
/// simplified epoch binding and durable finalized record.
pub fn simplified_protected_finality_context_digest(
    epoch_context: &SimplifiedEpochContext,
    finalized: &FinalizedBlockRecord,
    finalized_execution_state: &ExecutionState,
    validator_set: &ValidatorSet,
    cluster_map: &ClusterMap,
) -> Result<EtdagDigest, String> {
    simplified_protected_finality_context_digest_from_state_root(
        epoch_context,
        finalized,
        compute_state_root_after(finalized_execution_state)?,
        validator_set,
        cluster_map,
    )
}

/// Recompute the canonical finalized-context authority from the exact durable
/// execution root. This lets downstream workers independently reject a
/// substituted finalized record or digest without reopening execution state.
pub fn simplified_protected_finality_context_digest_from_state_root(
    epoch_context: &SimplifiedEpochContext,
    finalized: &FinalizedBlockRecord,
    finalized_execution_state_root: Hash,
    validator_set: &ValidatorSet,
    cluster_map: &ClusterMap,
) -> Result<EtdagDigest, String> {
    epoch_context.validate_against(&validator_set.active_for_epoch(epoch_context.epoch))?;
    if finalized.qc_id.is_zero()
        || finalized.block_id.0.trim().is_empty()
        || finalized_execution_state_root.is_zero()
    {
        return Err("simplified finalized authority is empty".to_string());
    }
    let active = validator_set.active_for_epoch(epoch_context.epoch);
    if cluster_map.epoch != epoch_context.epoch
        || cluster_map
            != &ClusterMap::derive_from_finalized_epoch_seed(
                &active,
                epoch_context.finalized_epoch_seed_root,
            )?
    {
        return Err("simplified finality context has another ETDAG topology".to_string());
    }
    canonical_finality_context_digest(&CanonicalSimplifiedProtectedFinalityContext {
        context_version: 1,
        epoch_context_root: epoch_context.root()?,
        source_finalized: finalized.clone(),
        source_finalized_state_root: finalized_execution_state_root,
        source_active_validator_set_root: active.hash()?,
        source_validator_consensus_key_root: active.consensus_key_root()?,
        source_frozen_voting_weight_root: active.frozen_bonded_weight_root()?,
        source_cluster_map_root: cluster_map.hash()?,
    })
}

/// Frozen inputs required to reopen and independently replay the simplified
/// finality WAL on each authority query.
#[derive(Clone)]
pub struct DurableSimplifiedProtectedMaterialAuthorityConfiguration {
    pub epoch_context: SimplifiedEpochContext,
    pub validator_set: ValidatorSet,
    pub cluster_map: ClusterMap,
    pub etdag_parameters: EtdagParameters,
    pub consensus_verifier: AegisPqvmVerifier,
    pub etdag_verifier: AegisPqvmVerifier,
    pub anchor_finalized: FinalizedBlockRecord,
    pub boundary_execution_state: ExecutionState,
}

/// Durable production authority for protected proposal execution. Every query
/// reopens the immutable finality WAL, then replays the bounded certified tail
/// from content-addressed material records to the requested parent QC.
#[derive(Clone)]
pub struct DurableSimplifiedProtectedMaterialAuthority {
    finality_directory: PathBuf,
    material_store: DurableSimplifiedProposalMaterialStore,
    configuration: DurableSimplifiedProtectedMaterialAuthorityConfiguration,
    epoch_transition: Option<DurableSimplifiedProtectedMaterialEpochTransition>,
}

#[derive(Clone)]
struct DurableSimplifiedProtectedMaterialEpochTransition {
    transition: VerifiedSimplifiedEpochTransition,
    previous: SimplifiedPreviousEpochFinalityReplay,
}

impl DurableSimplifiedProtectedMaterialAuthority {
    pub fn epoch_context(&self) -> &SimplifiedEpochContext {
        &self.configuration.epoch_context
    }

    pub fn new(
        finality_directory: impl Into<PathBuf>,
        material_store: DurableSimplifiedProposalMaterialStore,
        configuration: DurableSimplifiedProtectedMaterialAuthorityConfiguration,
    ) -> Result<Self, String> {
        let authority = Self {
            finality_directory: finality_directory.into(),
            material_store,
            configuration,
            epoch_transition: None,
        };
        authority.validate_durable_names()?;
        authority.recover_finalized()?;
        Ok(authority)
    }

    pub fn new_from_verified_v3_transition(
        finality_directory: impl Into<PathBuf>,
        material_store: DurableSimplifiedProposalMaterialStore,
        configuration: DurableSimplifiedProtectedMaterialAuthorityConfiguration,
        transition: VerifiedSimplifiedEpochTransition,
        previous: SimplifiedPreviousEpochFinalityReplay,
    ) -> Result<Self, String> {
        if configuration.epoch_context != *transition.next_epoch_context()
            || configuration.validator_set != *transition.next_validator_set()
            || configuration.anchor_finalized.height != transition.finalized_seed().height
            || configuration.anchor_finalized.block_id != transition.finalized_seed().block_id
            || configuration.anchor_finalized.qc_id != transition.finalized_seed().qc_id
        {
            return Err(
                "protected material authority configuration does not match the verified v3 transition"
                    .to_string(),
            );
        }
        let authority = Self {
            finality_directory: finality_directory.into(),
            material_store,
            configuration,
            epoch_transition: Some(DurableSimplifiedProtectedMaterialEpochTransition {
                transition,
                previous,
            }),
        };
        authority.validate_durable_names()?;
        authority.recover_finalized()?;
        Ok(authority)
    }

    fn validate_durable_names(&self) -> Result<(), String> {
        if self.finality_directory.as_os_str().is_empty()
            || self.material_store.epoch_context_root()
                != self.configuration.epoch_context.root()?
        {
            return Err(
                "protected material authority names inconsistent durable state".to_string(),
            );
        }
        Ok(())
    }

    fn finality_environment(&self) -> SimplifiedFinalityEnvironment {
        SimplifiedFinalityEnvironment {
            epoch_context: self.configuration.epoch_context.clone(),
            validator_set: self.configuration.validator_set.clone(),
            cluster_map: self.configuration.cluster_map.clone(),
            etdag_parameters: self.configuration.etdag_parameters.clone(),
            consensus_verifier: self.configuration.consensus_verifier.clone(),
            etdag_verifier: self.configuration.etdag_verifier.clone(),
            anchor_finalized: self.configuration.anchor_finalized.clone(),
            boundary_execution_state: self.configuration.boundary_execution_state.clone(),
        }
    }

    fn recover_finalized(&self) -> Result<(FinalizedBlockRecord, ExecutionState), String> {
        let sink = match &self.epoch_transition {
            Some(epoch_transition) => {
                DurableSimplifiedFinalitySink::at_directory_from_verified_v3_transition(
                    self.finality_directory.clone(),
                    self.material_store.clone(),
                    self.finality_environment(),
                    epoch_transition.transition.clone(),
                    epoch_transition.previous.clone(),
                )?
            }
            None => DurableSimplifiedFinalitySink::at_directory(
                self.finality_directory.clone(),
                self.material_store.clone(),
                self.finality_environment(),
            )?,
        };
        Ok((
            sink.current_finalized().clone(),
            sink.execution_state().clone(),
        ))
    }

    pub fn current_finalized_authority(
        &self,
    ) -> Result<(FinalizedBlockRecord, EtdagDigest), String> {
        let (finalized, _, digest) = self.current_finalized_authority_with_state_root()?;
        Ok((finalized, digest))
    }

    pub fn current_finalized_authority_with_state_root(
        &self,
    ) -> Result<(FinalizedBlockRecord, Hash, EtdagDigest), String> {
        let (finalized, finalized_execution_state) = self.recover_finalized()?;
        let finalized_execution_state_root = compute_state_root_after(&finalized_execution_state)?;
        let digest = simplified_protected_finality_context_digest_from_state_root(
            &self.configuration.epoch_context,
            &finalized,
            finalized_execution_state_root,
            &self.configuration.validator_set,
            &self.configuration.cluster_map,
        )?;
        Ok((finalized, finalized_execution_state_root, digest))
    }

    fn durable_snapshot(
        &self,
        context: &ConsensusObjectContext,
        parent_qc: &QuorumCertificateReference,
        finalized: &FinalizedBlockRecord,
    ) -> Result<SimplifiedProtectedMaterialAuthoritySnapshot, String> {
        context.validate_against(&self.configuration.epoch_context)?;
        parent_qc.validate()?;
        if parent_qc.height.0.checked_add(1) != Some(context.height.0)
            || parent_qc.block_id.0.trim().is_empty()
        {
            return Err("protected material parent QC does not precede its candidate".to_string());
        }
        let (durable_finalized, mut parent_execution_state) = self.recover_finalized()?;
        if &durable_finalized != finalized {
            return Err(
                "protected material finalized pointer differs from the durable finality WAL"
                    .to_string(),
            );
        }
        let canonical_finality_context_digest = simplified_protected_finality_context_digest(
            &self.configuration.epoch_context,
            &durable_finalized,
            &parent_execution_state,
            &self.configuration.validator_set,
            &self.configuration.cluster_map,
        )?;
        let durable_reference = QuorumCertificateReference {
            height: durable_finalized.height,
            block_id: durable_finalized.block_id.clone(),
            qc_id: durable_finalized.qc_id,
        };
        if parent_qc.height.0 < durable_reference.height.0 {
            return Err("protected material parent precedes durable finality".to_string());
        }
        let distance = parent_qc
            .height
            .0
            .checked_sub(durable_reference.height.0)
            .ok_or_else(|| "protected material parent distance underflowed".to_string())?;
        if distance > MAX_SIMPLIFIED_PROTECTED_UNFINALIZED_ANCESTORS as u64 {
            return Err("protected material certified tail exceeds its replay bound".to_string());
        }

        let mut cursor = parent_qc.clone();
        let mut reverse_tail = Vec::new();
        while cursor.height.0 > durable_reference.height.0 {
            let material = self.material_store.load(cursor.qc_id)?;
            if material.stable_candidate_id != cursor.qc_id
                || material.candidate_subject.context.height != cursor.height
                || material.candidate_subject.block_id != cursor.block_id
            {
                return Err(
                    "protected material certified tail does not match its parent QC".to_string(),
                );
            }
            cursor = material.candidate_subject.parent_qc.clone();
            reverse_tail.push(material);
        }
        if cursor != durable_reference {
            return Err(
                "protected material certified tail does not extend durable finality".to_string(),
            );
        }
        for material in reverse_tail.iter().rev() {
            parent_execution_state = material.replay_and_verify(
                &self.configuration.epoch_context,
                &parent_execution_state,
                &self.configuration.etdag_verifier,
                &self.configuration.validator_set,
                &self.configuration.cluster_map,
                &self.configuration.etdag_parameters,
            )?;
        }
        Ok(SimplifiedProtectedMaterialAuthoritySnapshot {
            parent_execution_state,
            canonical_finality_context_digest,
        })
    }
}

impl SimplifiedProtectedMaterialAuthority for DurableSimplifiedProtectedMaterialAuthority {
    fn authority_for_candidate(
        &mut self,
        context: &ConsensusObjectContext,
        parent_qc: &QuorumCertificateReference,
        finalized: &FinalizedBlockRecord,
    ) -> Result<SimplifiedProtectedMaterialAuthoritySnapshot, String> {
        self.durable_snapshot(context, parent_qc, finalized)
    }
}

impl EtdagScheduleNeutralFinalityAuthority for DurableSimplifiedProtectedMaterialAuthority {
    fn canonical_finality_context_digest(
        &self,
        target_context: &TargetAdmissionContext,
    ) -> Result<EtdagDigest, String> {
        let (finalized, finalized_execution_state) = self.recover_finalized()?;
        let digest = simplified_protected_finality_context_digest(
            &self.configuration.epoch_context,
            &finalized,
            &finalized_execution_state,
            &self.configuration.validator_set,
            &self.configuration.cluster_map,
        )?;
        if target_context.epoch != self.configuration.epoch_context.epoch
            || target_context.source_finalized_height != finalized.height
            || target_context.source_finality_context_root
                != target_admission_source_finality_root(&digest)?
        {
            return Err(
                "ETDAG schedule-neutral ingress names another durable finalized source".to_string(),
            );
        }
        Ok(digest)
    }
}

/// One concrete source type lets runtime selection remain finalized-state
/// driven without dynamic dispatch in the consensus driver.
pub enum SimplifiedActivatedMaterialAdapter<A> {
    Core(SimplifiedCoreMaterialAdapter),
    Protected(SimplifiedProtectedMaterialAdapter<A>),
}

impl<A: SimplifiedProtectedMaterialAuthority> SimplifiedMaterialAdapter
    for SimplifiedActivatedMaterialAdapter<A>
{
    fn build_local(
        &mut self,
        epoch_context: &SimplifiedEpochContext,
        directive: &SimplifiedProposalDirective,
    ) -> Result<Option<(SimplifiedProposal, VerifiedSimplifiedProposalMaterial)>, String> {
        match self {
            Self::Core(adapter) => adapter.build_local(epoch_context, directive),
            Self::Protected(adapter) => adapter.build_local(epoch_context, directive),
        }
    }

    fn verify_received(
        &mut self,
        epoch_context: &SimplifiedEpochContext,
        proposal: &SimplifiedProposal,
        expected_finalized: &FinalizedBlockRecord,
        material: &VerifiedSimplifiedProposalMaterial,
    ) -> Result<Hash, String> {
        match self {
            Self::Core(adapter) => {
                adapter.verify_received(epoch_context, proposal, expected_finalized, material)
            }
            Self::Protected(adapter) => {
                adapter.verify_received(epoch_context, proposal, expected_finalized, material)
            }
        }
    }
}

/// Frozen non-scheduling inputs for protected block construction and replay.
#[derive(Clone)]
pub struct SimplifiedProtectedMaterialConfiguration {
    pub verifier: AegisPqvmVerifier,
    pub validator_set: ValidatorSet,
    /// ETDAG topology only. Simplified consensus quorum remains the complete
    /// frozen validator set and is not derived from this map.
    pub etdag_cluster_map: ClusterMap,
    pub consensus_parameter_root: ConsensusParameterRoot,
    pub etdag_parameters: EtdagParameters,
    pub cryptographic_profile_root: Hash,
    pub epoch_start_timestamp_ms: u64,
    pub target_block_time_ms: u64,
    pub app_version: u32,
    pub execution_version: u32,
    pub dag_version: u32,
    pub aegis_pqvm_version: String,
}

impl SimplifiedProtectedMaterialConfiguration {
    fn validate(&self, epoch_context: &SimplifiedEpochContext) -> Result<(), String> {
        let active = self.validator_set.active_for_epoch(epoch_context.epoch);
        epoch_context.validate_against(&active)?;
        if self.validator_set.epoch != epoch_context.epoch
            || self.etdag_cluster_map.epoch != epoch_context.epoch
            || self.etdag_cluster_map != self.etdag_cluster_map.canonicalized()
        {
            return Err("protected material topology is not frozen canonically".to_string());
        }
        self.etdag_cluster_map
            .validate_complete_balanced_assignment(&active)?;
        let expected_map = ClusterMap::derive_from_finalized_epoch_seed(
            &active,
            epoch_context.finalized_epoch_seed_root,
        )?;
        if self.etdag_cluster_map != expected_map {
            return Err(
                "protected material ETDAG map is not derived from the finalized epoch seed"
                    .to_string(),
            );
        }
        if self.consensus_parameter_root.to_hex() != epoch_context.consensus_parameter_root {
            return Err(
                "protected material parameters differ from the simplified frozen manifest"
                    .to_string(),
            );
        }
        self.etdag_parameters.validate()?;
        if self.cryptographic_profile_root.is_zero()
            || self.epoch_start_timestamp_ms == 0
            || self.target_block_time_ms == 0
            || self.app_version == 0
            || self.execution_version == 0
            || self.dag_version == 0
            || self.aegis_pqvm_version.trim().is_empty()
        {
            return Err("invalid simplified protected-material configuration".to_string());
        }
        Ok(())
    }
}

/// Canonical protected-ETDAG adapter used behind the durable material source.
pub struct SimplifiedProtectedMaterialAdapter<A> {
    epoch_context: SimplifiedEpochContext,
    coordinator: EtdagProtectedInputCoordinator,
    configuration: SimplifiedProtectedMaterialConfiguration,
    authority: A,
}

impl<A: SimplifiedProtectedMaterialAuthority> SimplifiedProtectedMaterialAdapter<A> {
    pub fn new(
        epoch_context: SimplifiedEpochContext,
        coordinator: EtdagProtectedInputCoordinator,
        configuration: SimplifiedProtectedMaterialConfiguration,
        authority: A,
    ) -> Result<Self, String> {
        configuration.validate(&epoch_context)?;
        Ok(Self {
            epoch_context,
            coordinator,
            configuration,
            authority,
        })
    }

    fn timestamp_for_height(&self, height: crate::synergy_types::Height) -> Result<u64, String> {
        let offset = height
            .0
            .checked_sub(self.epoch_context.epoch_start_height.0)
            .ok_or_else(|| "protected material height precedes the epoch".to_string())?;
        self.configuration
            .target_block_time_ms
            .checked_mul(offset)
            .and_then(|delta| {
                self.configuration
                    .epoch_start_timestamp_ms
                    .checked_add(delta)
            })
            .ok_or_else(|| "protected material timestamp overflowed".to_string())
    }

    fn proposer(&self, proposal: &SimplifiedProposal) -> Result<ValidatorRecord, String> {
        let proposer = self
            .configuration
            .validator_set
            .active_for_epoch(self.epoch_context.epoch)
            .validators
            .into_iter()
            .find(|validator| validator.validator_id == proposal.proposer_id)
            .ok_or_else(|| {
                "protected material proposer is absent from the frozen set".to_string()
            })?;
        if proposer.consensus_public_key.key_id != proposal.proposer_key_id {
            return Err("protected material proposer key differs from the frozen key".to_string());
        }
        Ok(proposer)
    }

    fn verify_target_context(
        &self,
        target_context: &TargetAdmissionContext,
        context: &ConsensusObjectContext,
        finalized: &FinalizedBlockRecord,
        finality_digest: &EtdagDigest,
    ) -> Result<(), String> {
        target_context.validate_against_parameter_root(
            &self.configuration.validator_set,
            &self.configuration.etdag_cluster_map,
            self.configuration.consensus_parameter_root,
        )?;
        if target_context.target_height != context.height
            || target_context.epoch != context.epoch
            || target_context.source_finalized_height != finalized.height
            || target_context.source_finality_context_root
                != target_admission_source_finality_root(finality_digest)?
            || target_context.finalized_epoch_seed_root
                != self.epoch_context.finalized_epoch_seed_root
            || target_context.active_validator_set_root != context.active_validator_set_root
            || target_context.validator_consensus_key_root != context.validator_consensus_key_root
            || target_context.frozen_bonded_weight_root != context.frozen_voting_weight_root
            || target_context.consensus_parameter_root.to_hex() != context.consensus_parameter_root
            || target_context.cryptographic_profile_root
                != self.configuration.cryptographic_profile_root
        {
            return Err(
                "certified ETDAG target context differs from simplified durable authority"
                    .to_string(),
            );
        }
        Ok(())
    }

    fn finality_digest_matches(
        protected_input: &ProtectedBlockInput,
        expected: &EtdagDigest,
    ) -> Result<(), String> {
        expected.validate("simplified protected finality context digest")?;
        if expected.is_zero()
            || protected_input
                .boc
                .bvc
                .batch_candidate
                .canonical_finality_context_digest
                != *expected
        {
            return Err(
                "protected material deterministic order names another finality context".to_string(),
            );
        }
        Ok(())
    }

    fn ordered_transaction_ids(transactions: &[Transaction]) -> Result<Vec<TxId>, String> {
        transactions
            .iter()
            .map(|transaction| {
                Ok(TxId::from_hash(Hash::from_domain_bytes(
                    "SYNERGY_EXECUTION_TX_ID_V1",
                    &transaction.canonical_bytes()?,
                )))
            })
            .collect()
    }

    fn evidence_root(
        parent_qc: &QuorumCertificateReference,
        finalized: &FinalizedBlockRecord,
    ) -> Result<Hash, String> {
        Ok(Hash::from_domain_bytes(
            "SYNERGY_POSY_SIMPLIFIED_PROTECTED_EVIDENCE_V1",
            &serde_json::to_vec(&(parent_qc, finalized))
                .map_err(|error| format!("serialize simplified protected evidence: {error}"))?,
        ))
    }

    fn verify_static_header(
        &self,
        proposal: &SimplifiedProposal,
        expected_finalized: &FinalizedBlockRecord,
        target_context: &TargetAdmissionContext,
        protected_input: &ProtectedBlockInput,
        material: &VerifiedSimplifiedProposalMaterial,
    ) -> Result<(), String> {
        let header = &material.canonical_block.header;
        let transaction_ids =
            Self::ordered_transaction_ids(&material.canonical_block.transactions)?;
        let expected_dag_frontier = Hash::from_domain_bytes(
            "SYNERGY_ETDAG_DAG_CUT_ROOT_V2",
            protected_input
                .dcc
                .candidate
                .causal_closure_root
                .0
                .as_bytes(),
        );
        if header.version != POSY_SIMPLIFIED_PROTECTED_BLOCK_VERSION
            || header.cluster_id != target_context.assigned_cluster_id
            || header.cluster_schedule_version != target_context.cluster_schedule_version
            || header.cluster_map_hash != target_context.cluster_map_root
            || header.assigned_cluster_membership_root
                != target_context.assigned_cluster_membership_root
            || header.assigned_cluster_validator_count
                != target_context.assigned_cluster_validator_count
            || header.assigned_cluster_total_voting_weight
                != target_context.assigned_cluster_total_voting_weight
            || header.proposer_schedule_hash != self.epoch_context.leader_ring_root
            || header.cryptographic_profile_root != self.configuration.cryptographic_profile_root
            || header.dag_frontier_root != expected_dag_frontier
            || header.tx_order_root != compute_tx_order_root(&transaction_ids)?
            || header.evidence_root != Self::evidence_root(&proposal.parent_qc, expected_finalized)?
            || header.last_finalized_qc_hash != expected_finalized.qc_id
            || header.timestamp_ms_consensus_bounded
                != self.timestamp_for_height(proposal.context.height)?
            || header.app_version != self.configuration.app_version
            || header.execution_version != self.configuration.execution_version
            || header.dag_version != self.configuration.dag_version
            || header.aegis_pqvm_version != self.configuration.aegis_pqvm_version
        {
            return Err(
                "simplified protected block has noncanonical static commitments".to_string(),
            );
        }
        Ok(())
    }

    fn build_block(
        &self,
        directive: &SimplifiedProposalDirective,
        proposer: &ValidatorRecord,
        target_context: &TargetAdmissionContext,
        protected_input: &ProtectedBlockInput,
        parent_state: &ExecutionState,
    ) -> Result<Block, String> {
        let transactions = protected_input.verify_and_extract_transactions(
            &self.configuration.verifier,
            target_context,
            &self.configuration.validator_set,
            &self.configuration.etdag_cluster_map,
            &self.configuration.etdag_parameters,
        )?;
        let transaction_ids = Self::ordered_transaction_ids(&transactions)?;
        let state_root_before = compute_state_root_after(parent_state)?;
        let timestamp = self.timestamp_for_height(directive.context.height)?;
        let mut block = Block {
            header: BlockHeader {
                version: POSY_SIMPLIFIED_PROTECTED_BLOCK_VERSION,
                chain_id: directive.context.chain_id,
                network_id: directive.context.network_id.clone(),
                protocol_version: POSY_SIMPLIFIED_PROTOCOL_VERSION.to_string(),
                height: directive.context.height,
                round: directive.context.round,
                epoch: directive.context.epoch,
                cluster_id: target_context.assigned_cluster_id,
                height_context_root: directive.context.epoch_context_root,
                parent_block_hash: Hash::from_hex(&directive.highest_qc.block_id.0)?,
                parent_state_root: state_root_before,
                last_finalized_qc_hash: directive.finalized.qc_id,
                proposer_validator_id: proposer.validator_id.clone(),
                proposer_uma_id: proposer.validator_uma_id.clone(),
                proposer_key_id: proposer.consensus_public_key.key_id.clone(),
                active_validator_set_hash: directive.context.active_validator_set_root,
                eligible_validator_set_hash: directive.context.active_validator_set_root,
                validator_consensus_key_root: directive.context.validator_consensus_key_root,
                frozen_bonded_weight_root: directive.context.frozen_voting_weight_root,
                cluster_schedule_version: target_context.cluster_schedule_version.clone(),
                cluster_map_hash: target_context.cluster_map_root,
                assigned_cluster_membership_root: target_context.assigned_cluster_membership_root,
                assigned_cluster_validator_count: target_context.assigned_cluster_validator_count,
                assigned_cluster_total_voting_weight: target_context
                    .assigned_cluster_total_voting_weight,
                proposer_schedule_hash: self.epoch_context.leader_ring_root,
                protocol_config_hash: ConsensusParameterRoot::from_hex(
                    &directive.context.consensus_parameter_root,
                )?,
                cryptographic_profile_root: self.configuration.cryptographic_profile_root,
                dag_frontier_root: Hash::from_domain_bytes(
                    "SYNERGY_ETDAG_DAG_CUT_ROOT_V2",
                    protected_input
                        .dcc
                        .candidate
                        .causal_closure_root
                        .0
                        .as_bytes(),
                ),
                tx_order_root: compute_tx_order_root(&transaction_ids)?,
                tx_count: u64::try_from(transactions.len())
                    .map_err(|_| "protected transaction count exceeds u64".to_string())?,
                protected_batch: None,
                evidence_root: Self::evidence_root(&directive.highest_qc, &directive.finalized)?,
                state_root_before,
                state_root_after: Hash::zero(),
                receipt_root: Hash::zero(),
                app_version: self.configuration.app_version,
                execution_version: self.configuration.execution_version,
                dag_version: self.configuration.dag_version,
                aegis_pqvm_version: self.configuration.aegis_pqvm_version.clone(),
                timestamp_ms_consensus_bounded: timestamp,
            },
            transactions,
            proposer_signature: AegisPqSignature {
                algorithm: String::new(),
                signature_bytes: Vec::new(),
            },
        };
        let mut authorized_state = parent_state.clone();
        for transaction in &block.transactions {
            authorized_state.mark_authorized_at(transaction, timestamp.saturating_div(1_000))?;
        }
        let execution = execute_block(&block, &authorized_state)?;
        let manifest =
            protected_input.build_execution_manifest(&block.transactions, &execution.receipts)?;
        let commitment =
            protected_input.protected_batch_commitment(&manifest, &execution.receipts)?;
        if commitment.protected_count != block.header.tx_count {
            return Err("protected batch count differs from block body".to_string());
        }
        block.header.protected_batch = Some(commitment);
        block.header.state_root_after = execution.state_root_after;
        block.header.receipt_root = execution.receipt_root;
        Ok(block)
    }
}

impl<A: SimplifiedProtectedMaterialAuthority> SimplifiedMaterialAdapter
    for SimplifiedProtectedMaterialAdapter<A>
{
    fn build_local(
        &mut self,
        epoch_context: &SimplifiedEpochContext,
        directive: &SimplifiedProposalDirective,
    ) -> Result<Option<(SimplifiedProposal, VerifiedSimplifiedProposalMaterial)>, String> {
        if epoch_context.root()? != self.epoch_context.root()?
            || directive.context.epoch_context_root != self.epoch_context.root()?
        {
            return Err("protected proposal request names another epoch".to_string());
        }
        let authority = self.authority.authority_for_candidate(
            &directive.context,
            &directive.highest_qc,
            &directive.finalized,
        )?;
        let ready = self
            .coordinator
            .load_ready_protected_material_schedule_neutral(
                directive.context.height,
                &authority.canonical_finality_context_digest,
                &self.configuration.verifier,
                &self.configuration.validator_set,
                &self.configuration.etdag_cluster_map,
                self.configuration.consensus_parameter_root,
                &self.configuration.etdag_parameters,
            );
        let (target_context, protected_input) = match ready {
            Ok(material) => material,
            Err(error) if error.contains("ETDAG_PROTECTED_INPUT_NOT_READY") => return Ok(None),
            Err(error) => return Err(error),
        };
        self.verify_target_context(
            &target_context,
            &directive.context,
            &directive.finalized,
            &authority.canonical_finality_context_digest,
        )?;
        Self::finality_digest_matches(
            &protected_input,
            &authority.canonical_finality_context_digest,
        )?;
        let unsigned_proposal = SimplifiedProposal {
            context: directive.context.clone(),
            proposer_id: directive.proposer_id.clone(),
            block_id: BlockId(String::new()),
            parent_block_id: directive.highest_qc.block_id.clone(),
            parent_qc: directive.highest_qc.clone(),
            takeover_tc_id: directive.takeover_tc_id,
            protected_execution_root: Hash::zero(),
            proposer_key_id: directive.proposer_key_id.clone(),
            proposer_signature: AegisPqSignature {
                algorithm: String::new(),
                signature_bytes: Vec::new(),
            },
        };
        let proposer = self.proposer(&unsigned_proposal)?;
        let block = self.build_block(
            directive,
            &proposer,
            &target_context,
            &protected_input,
            &authority.parent_execution_state,
        )?;
        let block_id = block.candidate_id()?;
        let protected_execution_root = compute_simplified_protected_execution_root(
            &directive.context,
            &block,
            &directive.highest_qc.block_id,
            &directive.highest_qc,
            Some(&target_context),
            Some(&protected_input),
        )?;
        let proposal = SimplifiedProposal {
            block_id,
            protected_execution_root,
            ..unsigned_proposal
        };
        let (material, _) = VerifiedSimplifiedProposalMaterial::verify_protected(
            epoch_context,
            &proposal,
            block,
            target_context,
            protected_input,
            &authority.parent_execution_state,
            &self.configuration.verifier,
            &self.configuration.validator_set,
            &self.configuration.etdag_cluster_map,
            &self.configuration.etdag_parameters,
        )?;
        let verified_target = material
            .target_context
            .as_ref()
            .ok_or_else(|| "verified protected material lost its target context".to_string())?;
        let verified_input = material
            .protected_input
            .as_ref()
            .ok_or_else(|| "verified protected material lost its ETDAG input".to_string())?;
        self.verify_static_header(
            &proposal,
            &directive.finalized,
            verified_target,
            verified_input,
            &material,
        )?;
        Ok(Some((proposal, material)))
    }

    fn verify_received(
        &mut self,
        epoch_context: &SimplifiedEpochContext,
        proposal: &SimplifiedProposal,
        expected_finalized: &FinalizedBlockRecord,
        material: &VerifiedSimplifiedProposalMaterial,
    ) -> Result<Hash, String> {
        if epoch_context.root()? != self.epoch_context.root()? {
            return Err("received protected material names another epoch".to_string());
        }
        let authority = self.authority.authority_for_candidate(
            &proposal.context,
            &proposal.parent_qc,
            expected_finalized,
        )?;
        let target_context = material.target_context.as_ref().ok_or_else(|| {
            "received protected proposal has no certified target context".to_string()
        })?;
        let protected_input = material.protected_input.as_ref().ok_or_else(|| {
            "received protected proposal has no protected ETDAG input".to_string()
        })?;
        let certified_target = self
            .coordinator
            .load_verified_target_admission_context_schedule_neutral(
                proposal.context.height,
                &self.configuration.verifier,
                &self.configuration.validator_set,
                &self.configuration.etdag_cluster_map,
                self.configuration.consensus_parameter_root,
            )?;
        if &certified_target != target_context {
            return Err(
                "received target context differs from the durable certified admission package"
                    .to_string(),
            );
        }
        self.verify_target_context(
            target_context,
            &proposal.context,
            expected_finalized,
            &authority.canonical_finality_context_digest,
        )?;
        Self::finality_digest_matches(
            protected_input,
            &authority.canonical_finality_context_digest,
        )?;
        self.proposer(proposal)?;
        self.verify_static_header(
            proposal,
            expected_finalized,
            target_context,
            protected_input,
            material,
        )?;
        material.replay_and_verify(
            epoch_context,
            &authority.parent_execution_state,
            &self.configuration.verifier,
            &self.configuration.validator_set,
            &self.configuration.etdag_cluster_map,
            &self.configuration.etdag_parameters,
        )?;
        Ok(material.candidate_subject.protected_execution_root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::simplified_posy::{
        DurableSimplifiedProposalMaterialStore, SimplifiedCoreMaterialConfiguration,
    };
    use crate::etdag::tests::{complete_protected_input, fixture, target_admission_package};
    use crate::synergy_types::{Epoch, Height, Round};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Clone)]
    struct ExactAuthority {
        expected_context: ConsensusObjectContext,
        expected_parent: QuorumCertificateReference,
        expected_finalized: FinalizedBlockRecord,
        snapshot: SimplifiedProtectedMaterialAuthoritySnapshot,
    }

    impl SimplifiedProtectedMaterialAuthority for ExactAuthority {
        fn authority_for_candidate(
            &mut self,
            context: &ConsensusObjectContext,
            parent_qc: &QuorumCertificateReference,
            finalized: &FinalizedBlockRecord,
        ) -> Result<SimplifiedProtectedMaterialAuthoritySnapshot, String> {
            if context != &self.expected_context
                || parent_qc != &self.expected_parent
                || finalized != &self.expected_finalized
            {
                return Err("test durable authority rejected substituted pointers".to_string());
            }
            Ok(self.snapshot.clone())
        }
    }

    struct TestSetup {
        epoch_context: SimplifiedEpochContext,
        directive: SimplifiedProposalDirective,
        coordinator: EtdagProtectedInputCoordinator,
        configuration: SimplifiedProtectedMaterialConfiguration,
        authority: ExactAuthority,
        admission_path: PathBuf,
        protected_path: PathBuf,
    }

    fn temp_root(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        crate::utils::test_temp_root(format!(
            "simplified-protected-material-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn setup(label: &str, install_protected: bool) -> TestSetup {
        let finality_digest = EtdagDigest::from_domain_bytes("finality", b"complete-input");
        let mut etdag_fixture = fixture(5, None);
        etdag_fixture.context.source_finality_context_root =
            target_admission_source_finality_root(&finality_digest).unwrap();
        let target_context = etdag_fixture.context.clone();
        let admission_package =
            target_admission_package(&mut etdag_fixture, target_context.clone());
        let protected_input = complete_protected_input(&mut etdag_fixture);
        let parameter_root = target_context.consensus_parameter_root;
        let epoch_context = SimplifiedEpochContext::derive(
            Epoch(0),
            target_context.target_height,
            Height(target_context.target_height.0 + 100),
            target_context.finalized_epoch_seed_root,
            parameter_root,
            &etdag_fixture.validator_set,
        )
        .unwrap();
        let parent = QuorumCertificateReference {
            height: Height(target_context.target_height.0 - 1),
            block_id: BlockId::from_hash(Hash::from_domain_bytes(
                "simplified-protected-test",
                b"parent-block",
            )),
            qc_id: Hash::from_domain_bytes("simplified-protected-test", b"parent-qc"),
        };
        let finalized = FinalizedBlockRecord {
            height: target_context.source_finalized_height,
            block_id: BlockId::from_hash(Hash::from_domain_bytes(
                "simplified-protected-test",
                b"finalized-block",
            )),
            qc_id: Hash::from_domain_bytes("simplified-protected-test", b"finalized-qc"),
        };
        let context = ConsensusObjectContext::for_height(
            &epoch_context,
            target_context.target_height,
            Round(0),
        )
        .unwrap();
        let proposer_id = epoch_context
            .authorized_proposer(context.height, 0)
            .unwrap()
            .clone();
        let proposer_key_id = etdag_fixture
            .validator_set
            .validators
            .iter()
            .find(|validator| validator.validator_id == proposer_id)
            .unwrap()
            .consensus_public_key
            .key_id
            .clone();
        let directive = SimplifiedProposalDirective {
            context: context.clone(),
            highest_qc: parent.clone(),
            finalized: finalized.clone(),
            proposer_id,
            proposer_key_id,
            takeover_tc_id: None,
            mandatory_carry_candidate: None,
        };
        let root = temp_root(label);
        let admission_path = root.join("admission.json");
        let protected_path = root.join("protected.json");
        let coordinator = EtdagProtectedInputCoordinator::at_paths(
            admission_path.clone(),
            protected_path.clone(),
        );
        if install_protected {
            coordinator
                .admit_certified_public_input_schedule_neutral(
                    &admission_package,
                    &protected_input,
                    &finality_digest,
                    &etdag_fixture.signer.verifier(),
                    &etdag_fixture.validator_set,
                    &etdag_fixture.cluster_map,
                    parameter_root,
                    &EtdagParameters::default(),
                )
                .unwrap();
        }
        let configuration = SimplifiedProtectedMaterialConfiguration {
            verifier: etdag_fixture.signer.verifier(),
            validator_set: etdag_fixture.validator_set,
            etdag_cluster_map: etdag_fixture.cluster_map,
            consensus_parameter_root: parameter_root,
            etdag_parameters: EtdagParameters::default(),
            cryptographic_profile_root: target_context.cryptographic_profile_root,
            epoch_start_timestamp_ms: 1_000_000,
            target_block_time_ms: 1_000,
            app_version: 1,
            execution_version: 1,
            dag_version: 2,
            aegis_pqvm_version: "aegis-pqvm-protected-v1".to_string(),
        };
        let authority = ExactAuthority {
            expected_context: context,
            expected_parent: parent,
            expected_finalized: finalized,
            snapshot: SimplifiedProtectedMaterialAuthoritySnapshot {
                parent_execution_state: ExecutionState::new(),
                canonical_finality_context_digest: finality_digest,
            },
        };
        TestSetup {
            epoch_context,
            directive,
            coordinator,
            configuration,
            authority,
            admission_path,
            protected_path,
        }
    }

    #[test]
    fn adapter_builds_replays_and_restarts_with_exact_durable_material() {
        let setup = setup("restart", true);
        let mut adapter = SimplifiedProtectedMaterialAdapter::new(
            setup.epoch_context.clone(),
            setup.coordinator,
            setup.configuration.clone(),
            setup.authority.clone(),
        )
        .unwrap();
        let (proposal, material) = adapter
            .build_local(&setup.epoch_context, &setup.directive)
            .unwrap()
            .unwrap();
        assert_eq!(
            adapter
                .verify_received(
                    &setup.epoch_context,
                    &proposal,
                    &setup.directive.finalized,
                    &material,
                )
                .unwrap(),
            proposal.protected_execution_root
        );

        let store_root = temp_root("material-store");
        let store = DurableSimplifiedProposalMaterialStore::at_directory(
            &store_root,
            setup.epoch_context.root().unwrap(),
        )
        .unwrap();
        store.install_verified(&material).unwrap();
        assert_eq!(store.load(material.stable_candidate_id).unwrap(), material);

        let restarted =
            EtdagProtectedInputCoordinator::at_paths(setup.admission_path, setup.protected_path);
        let mut restarted_adapter = SimplifiedProtectedMaterialAdapter::new(
            setup.epoch_context.clone(),
            restarted,
            setup.configuration,
            setup.authority,
        )
        .unwrap();
        assert_eq!(
            restarted_adapter
                .verify_received(
                    &setup.epoch_context,
                    &proposal,
                    &setup.directive.finalized,
                    &material,
                )
                .unwrap(),
            proposal.protected_execution_root
        );
    }

    #[test]
    fn adapter_rejects_body_context_input_execution_and_finality_substitution() {
        let setup = setup("adversarial", true);
        let mut adapter = SimplifiedProtectedMaterialAdapter::new(
            setup.epoch_context.clone(),
            setup.coordinator,
            setup.configuration,
            setup.authority,
        )
        .unwrap();
        let (proposal, material) = adapter
            .build_local(&setup.epoch_context, &setup.directive)
            .unwrap()
            .unwrap();

        let mut wrong_body = material.clone();
        wrong_body.canonical_block.transactions[0].amount_nwei += 1;
        assert!(adapter
            .verify_received(
                &setup.epoch_context,
                &proposal,
                &setup.directive.finalized,
                &wrong_body,
            )
            .is_err());

        let mut wrong_context = material.clone();
        wrong_context
            .target_context
            .as_mut()
            .unwrap()
            .source_finalized_height = Height(1);
        assert!(adapter
            .verify_received(
                &setup.epoch_context,
                &proposal,
                &setup.directive.finalized,
                &wrong_context,
            )
            .is_err());

        let mut wrong_input = material.clone();
        wrong_input
            .protected_input
            .as_mut()
            .unwrap()
            .epoch_randomness =
            Hash::from_domain_bytes("simplified-protected-test", b"wrong-randomness");
        assert!(adapter
            .verify_received(
                &setup.epoch_context,
                &proposal,
                &setup.directive.finalized,
                &wrong_input,
            )
            .is_err());

        let mut wrong_execution = material.clone();
        wrong_execution.canonical_block.header.state_root_after =
            Hash::from_domain_bytes("simplified-protected-test", b"wrong-state");
        assert!(adapter
            .verify_received(
                &setup.epoch_context,
                &proposal,
                &setup.directive.finalized,
                &wrong_execution,
            )
            .is_err());

        let mut wrong_finalized = setup.directive.finalized;
        wrong_finalized.qc_id =
            Hash::from_domain_bytes("simplified-protected-test", b"wrong-finality");
        assert!(adapter
            .verify_received(&setup.epoch_context, &proposal, &wrong_finalized, &material,)
            .is_err());
    }

    #[test]
    fn adapter_waits_without_proposing_when_certified_input_is_missing() {
        let setup = setup("not-ready", false);
        let mut adapter = SimplifiedProtectedMaterialAdapter::new(
            setup.epoch_context.clone(),
            setup.coordinator,
            setup.configuration,
            setup.authority,
        )
        .unwrap();
        assert!(adapter
            .build_local(&setup.epoch_context, &setup.directive)
            .unwrap()
            .is_none());
    }

    #[test]
    fn durable_authority_reopens_finality_and_replays_only_the_bounded_certified_tail() {
        let etdag_fixture = fixture(5, None);
        let parameter_root = etdag_fixture.context.consensus_parameter_root;
        let epoch_context = SimplifiedEpochContext::derive(
            Epoch(0),
            Height(6),
            Height(100),
            etdag_fixture.context.finalized_epoch_seed_root,
            parameter_root,
            &etdag_fixture.validator_set,
        )
        .unwrap();
        let finalized = FinalizedBlockRecord {
            height: Height(5),
            block_id: BlockId::from_hash(Hash::from_domain_bytes(
                "simplified-protected-durable-test",
                b"finalized-five",
            )),
            qc_id: Hash::from_domain_bytes(
                "simplified-protected-durable-test",
                b"finalized-five-qc",
            ),
        };
        let anchor_qc = QuorumCertificateReference {
            height: finalized.height,
            block_id: finalized.block_id.clone(),
            qc_id: finalized.qc_id,
        };
        let execution_state = ExecutionState::new();
        let mut core = SimplifiedCoreMaterialAdapter::new(
            epoch_context.clone(),
            SimplifiedCoreMaterialConfiguration {
                validator_set: etdag_fixture.validator_set.clone(),
                cluster_map: etdag_fixture.cluster_map.clone(),
                execution_state: execution_state.clone(),
                cryptographic_profile_root: etdag_fixture.context.cryptographic_profile_root,
                epoch_start_timestamp_ms: 1_000_000,
                target_block_time_ms: 1_000,
                app_version: 1,
                execution_version: 1,
                dag_version: 2,
                aegis_pqvm_version: "aegis-pqvm-durable-test-v1".to_string(),
            },
        )
        .unwrap();
        let directive = |height: Height, parent_qc: QuorumCertificateReference| {
            let context =
                ConsensusObjectContext::for_height(&epoch_context, height, Round(0)).unwrap();
            let proposer_id = epoch_context
                .authorized_proposer(height, 0)
                .unwrap()
                .clone();
            let proposer_key_id = etdag_fixture
                .validator_set
                .validators
                .iter()
                .find(|validator| validator.validator_id == proposer_id)
                .unwrap()
                .consensus_public_key
                .key_id
                .clone();
            SimplifiedProposalDirective {
                context,
                highest_qc: parent_qc,
                finalized: finalized.clone(),
                proposer_id,
                proposer_key_id,
                takeover_tc_id: None,
                mandatory_carry_candidate: None,
            }
        };
        let height_six = directive(Height(6), anchor_qc);
        let (proposal_six, material_six) = core
            .build_local(&epoch_context, &height_six)
            .unwrap()
            .unwrap();
        let qc_six = QuorumCertificateReference {
            height: Height(6),
            block_id: proposal_six.block_id,
            qc_id: material_six.stable_candidate_id,
        };
        let height_seven = directive(Height(7), qc_six);
        let (proposal_seven, material_seven) = core
            .build_local(&epoch_context, &height_seven)
            .unwrap()
            .unwrap();
        let qc_seven = QuorumCertificateReference {
            height: Height(7),
            block_id: proposal_seven.block_id,
            qc_id: material_seven.stable_candidate_id,
        };

        let root = temp_root("durable-authority");
        let material_store = DurableSimplifiedProposalMaterialStore::at_directory(
            root.join("material"),
            epoch_context.root().unwrap(),
        )
        .unwrap();
        material_store.install_verified(&material_six).unwrap();
        material_store.install_verified(&material_seven).unwrap();
        let verifier = etdag_fixture.signer.verifier();
        let authority_configuration = DurableSimplifiedProtectedMaterialAuthorityConfiguration {
            epoch_context: epoch_context.clone(),
            validator_set: etdag_fixture.validator_set,
            cluster_map: etdag_fixture.cluster_map,
            etdag_parameters: EtdagParameters::default(),
            consensus_verifier: verifier.clone(),
            etdag_verifier: verifier.clone(),
            anchor_finalized: finalized.clone(),
            boundary_execution_state: execution_state.clone(),
        };
        let finality_directory = root.join("finality");
        DurableSimplifiedFinalitySink::at_directory(
            &finality_directory,
            material_store.clone(),
            SimplifiedFinalityEnvironment {
                epoch_context: epoch_context.clone(),
                validator_set: authority_configuration.validator_set.clone(),
                cluster_map: authority_configuration.cluster_map.clone(),
                etdag_parameters: EtdagParameters::default(),
                consensus_verifier: verifier.clone(),
                etdag_verifier: verifier,
                anchor_finalized: finalized.clone(),
                boundary_execution_state: execution_state.clone(),
            },
        )
        .unwrap();
        let expected_finality_digest = simplified_protected_finality_context_digest(
            &epoch_context,
            &finalized,
            &execution_state,
            &authority_configuration.validator_set,
            &authority_configuration.cluster_map,
        )
        .unwrap();
        let mut authority = DurableSimplifiedProtectedMaterialAuthority::new(
            finality_directory,
            material_store,
            authority_configuration,
        )
        .unwrap();
        let target =
            ConsensusObjectContext::for_height(&epoch_context, Height(8), Round(0)).unwrap();
        let snapshot = authority
            .authority_for_candidate(&target, &qc_seven, &finalized)
            .unwrap();
        assert_eq!(snapshot.parent_execution_state, execution_state);
        assert_eq!(
            snapshot.canonical_finality_context_digest,
            expected_finality_digest
        );

        let mut wrong_finalized = finalized.clone();
        wrong_finalized.qc_id =
            Hash::from_domain_bytes("simplified-protected-durable-test", b"wrong-finality");
        assert!(authority
            .authority_for_candidate(&target, &qc_seven, &wrong_finalized)
            .unwrap_err()
            .contains("durable finality WAL"));

        let far_parent = QuorumCertificateReference {
            height: Height(9),
            block_id: BlockId::from_hash(Hash::from_domain_bytes(
                "simplified-protected-durable-test",
                b"far-parent",
            )),
            qc_id: Hash::from_domain_bytes("simplified-protected-durable-test", b"far-parent-qc"),
        };
        let far_target =
            ConsensusObjectContext::for_height(&epoch_context, Height(10), Round(0)).unwrap();
        assert!(authority
            .authority_for_candidate(&far_target, &far_parent, &finalized)
            .unwrap_err()
            .contains("replay bound"));
    }
}
