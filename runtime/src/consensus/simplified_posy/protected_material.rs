//! Production protected-ETDAG material adapter for simplified PoSy.
//!
//! ETDAG supplies certified admission and protected execution material. The
//! simplified consensus driver supplies proposer and round authority. This
//! adapter deliberately keeps those authorities separate: it imports no
//! legacy proposer schedule and exposes no empty or plaintext fallback.

use super::{
    compute_simplified_protected_execution_root_with_current_and_future_commitment,
    simplified_fee_market_header_fields, validate_simplified_fee_market_header_against_parent,
    ConsensusObjectContext, DurableSimplifiedFinalitySink, DurableSimplifiedProposalMaterialStore,
    FinalizedBlockRecord, SimplifiedCoreMaterialAdapter, SimplifiedEpochContext,
    SimplifiedFinalityEnvironment, SimplifiedFinalityParent, SimplifiedMaterialAdapter,
    SimplifiedParentFeeMarketState, SimplifiedPreviousEpochFinalityReplay, SimplifiedProposal,
    SimplifiedProposalDirective, VerifiedSimplifiedEpochTransition,
    VerifiedSimplifiedProposalMaterial, POSY_SIMPLIFIED_PROTOCOL_VERSION,
};
use crate::consensus::protected_pipeline_runtime::{
    GenesisBootstrapProtectedExecutionSource, ProtectedPipelineRuntime,
};
use crate::consensus_parameters::ConsensusParameterRoot;
use crate::crypto::aegis_pqvm::AegisPqvmVerifier;
use crate::dag_mempool::compute_tx_order_root;
use crate::etdag::{
    canonical_finality_context_digest, target_admission_source_finality_root,
    DeterministicProtectedExecutionInput, EtdagDigest, EtdagParameters,
    EtdagProtectedInputCoordinator, EtdagScheduleNeutralFinalityAuthority,
    NextProtectedBatchCommitment, ProtectedBatchSource, ProtectedExecutionTargetContext,
    TargetAdmissionContext, ETDAG_PROFILE_ID,
};
use crate::execution::{compute_state_root_after, execute_block, ExecutionState};
use crate::synergy_types::{
    AegisPqSignature, Block, BlockHeader, BlockId, CanonicalSerialize, ClusterMap, Hash,
    ProtectedBatchCommitment, Transaction, TxId, ValidatorRecord, ValidatorSet,
};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub const POSY_SIMPLIFIED_PROTECTED_BLOCK_VERSION: u32 = 3;

/// Single source of concrete, cryptographically replayable R11 protected
/// execution material. Implementations are expected to read the durable
/// `ProtectedPipeline` record; absence at H3+ is a hard not-ready condition.
pub trait SimplifiedProtectedExecutionInputSource: Send {
    fn load_ready_execution_input(
        &mut self,
        height: crate::synergy_types::Height,
    ) -> Result<Option<DeterministicProtectedExecutionInput>, String>;

    /// Commitment for the proposal's child height. It is derived from the
    /// child's durable cut/order and intentionally requires no reveal or
    /// concrete execution input.
    fn load_pre_reveal_commitment(
        &mut self,
        child_height: crate::synergy_types::Height,
    ) -> Result<Option<crate::etdag::NextProtectedBatchCommitment>, String> {
        Err(format!(
            "PROTECTED_PIPELINE_COMMITMENT_NOT_READY: no pre-reveal source for H{}",
            child_height.0
        ))
    }
}

/// Height-keyed bridge from simplified PoSy to the sole protected-pipeline
/// authority for that target.  It contains no material of its own: H1/H2 are
/// served only by the canonical Genesis source and H3+ only by the durable
/// normal-target coordinator.  A binding cannot be overwritten, which keeps
/// a restarted proposer from silently switching its protected subset.
#[derive(Clone, Default)]
pub struct CoordinatedProtectedExecutionInputSource {
    bindings: Arc<Mutex<BTreeMap<crate::synergy_types::Height, ProtectedExecutionBinding>>>,
}

#[derive(Clone)]
enum ProtectedExecutionBinding {
    Genesis(GenesisBootstrapProtectedExecutionSource),
    Normal(ProtectedPipelineRuntime),
}

impl CoordinatedProtectedExecutionInputSource {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register the immutable H1 or H2 bootstrap authority.  The source has
    /// already validated its exact Genesis-derived commitment and empty input.
    pub fn register_genesis_bootstrap(
        &self,
        height: crate::synergy_types::Height,
        source: GenesisBootstrapProtectedExecutionSource,
    ) -> Result<(), String> {
        if !matches!(height.0, 1 | 2) {
            return Err(format!(
                "PROTECTED_BOOTSTRAP_SOURCE_HEIGHT_INVALID: H{} is not a Genesis bootstrap height",
                height.0
            ));
        }
        self.register(height, ProtectedExecutionBinding::Genesis(source))
    }

    /// Register the durable H3+ coordinator for one normal ETDAG target.
    /// The coordinator owns the record, event reconciliation, and exact
    /// commitment; this bridge only routes PoSy's height-bound query to it.
    pub fn register_normal_target(&self, runtime: ProtectedPipelineRuntime) -> Result<(), String> {
        let target = runtime.target();
        let height = target.target_height;
        if height.0 < 3
            || !matches!(
                runtime.source(),
                ProtectedBatchSource::NormalEtdag | ProtectedBatchSource::NormalEtdagSteadyState
            )
        {
            return Err(format!(
                "PROTECTED_NORMAL_SOURCE_TARGET_INVALID: H{} is not a normal ETDAG target",
                height.0
            ));
        }
        self.register(height, ProtectedExecutionBinding::Normal(runtime))
    }

    fn register(
        &self,
        height: crate::synergy_types::Height,
        binding: ProtectedExecutionBinding,
    ) -> Result<(), String> {
        let mut bindings = self.bindings.lock().map_err(|_| {
            "PROTECTED_EXECUTION_SOURCE_REGISTRY_POISONED: protected source registry lock is poisoned"
                .to_string()
        })?;
        if bindings.contains_key(&height) {
            return Err(format!(
                "PROTECTED_EXECUTION_SOURCE_CONFLICT: H{} already has a protected authority",
                height.0
            ));
        }
        bindings.insert(height, binding);
        Ok(())
    }

    fn binding_for(
        &self,
        height: crate::synergy_types::Height,
    ) -> Result<ProtectedExecutionBinding, String> {
        self.bindings
            .lock()
            .map_err(|_| {
                "PROTECTED_EXECUTION_SOURCE_REGISTRY_POISONED: protected source registry lock is poisoned"
                    .to_string()
            })?
            .get(&height)
            .cloned()
            .ok_or_else(|| {
                format!(
                    "PROTECTED_PIPELINE_EXECUTION_INPUT_NOT_READY: no height-bound protected authority for H{}",
                    height.0
                )
            })
    }

    fn validate_loaded_input(
        height: crate::synergy_types::Height,
        binding: &ProtectedExecutionBinding,
        input: &DeterministicProtectedExecutionInput,
    ) -> Result<(), String> {
        let (expected_source, expected_normal_target) = match binding {
            ProtectedExecutionBinding::Genesis(_) => (ProtectedBatchSource::GenesisBootstrap, None),
            ProtectedExecutionBinding::Normal(runtime) => {
                (runtime.source(), Some(runtime.target()))
            }
        };
        if input.source != expected_source
            || input.next_commitment.target_height != height
            || input.protected_batch.target_height != height
        {
            return Err(format!(
                "PROTECTED_EXECUTION_SOURCE_BINDING_CONFLICT: H{} source or commitment differs from its coordinator",
                height.0
            ));
        }
        match (&input.target_context, expected_normal_target) {
            (ProtectedExecutionTargetContext::GenesisBootstrap { height_context }, None)
                if matches!(height.0, 1 | 2) && height_context.height == height => {}
            (ProtectedExecutionTargetContext::NormalEtdag { admission_context }, Some(target))
                if admission_context == target && admission_context.target_height == height => {}
            _ => {
                return Err(format!(
                    "PROTECTED_EXECUTION_SOURCE_TARGET_CONFLICT: concrete input does not name H{}'s registered target",
                    height.0
                ));
            }
        }
        input
            .next_commitment
            .validate_against_batch(&input.protected_batch)
            .map_err(|error| {
                format!(
                    "PROTECTED_EXECUTION_SOURCE_COMMITMENT_INVALID: concrete input commitment is invalid: {error}"
                )
            })?;
        input.digest().map_err(|error| {
            format!(
                "PROTECTED_EXECUTION_SOURCE_INPUT_INVALID: concrete input digest failed: {error}"
            )
        })?;
        Ok(())
    }
}

impl SimplifiedProtectedExecutionInputSource for CoordinatedProtectedExecutionInputSource {
    fn load_ready_execution_input(
        &mut self,
        height: crate::synergy_types::Height,
    ) -> Result<Option<DeterministicProtectedExecutionInput>, String> {
        let binding = self.binding_for(height)?;
        let input = match &binding {
            ProtectedExecutionBinding::Genesis(source) => source
                .load_ready_execution_input_for_target()
                .map_err(|error| format!("PROTECTED_BOOTSTRAP_SOURCE_LOOKUP_FAILED: {error}"))?,
            ProtectedExecutionBinding::Normal(runtime) => runtime
                .load_ready_execution_input_for_target()
                .map_err(|error| format!("PROTECTED_RUNTIME_SOURCE_LOOKUP_FAILED: {error}"))?,
        };
        if let Some(input) = &input {
            Self::validate_loaded_input(height, &binding, input)?;
        }
        Ok(input)
    }

    fn load_pre_reveal_commitment(
        &mut self,
        child_height: crate::synergy_types::Height,
    ) -> Result<Option<crate::etdag::NextProtectedBatchCommitment>, String> {
        let binding = self.binding_for(child_height)?;
        match binding {
            ProtectedExecutionBinding::Genesis(source) => source
                .load_ready_execution_input_for_target()
                .map(|input| input.map(|input| input.next_commitment))
                .map_err(|error| format!("PROTECTED_BOOTSTRAP_COMMITMENT_LOOKUP_FAILED: {error}")),
            ProtectedExecutionBinding::Normal(runtime) => runtime
                .pre_reveal_commitment()
                .map_err(|error| format!("PROTECTED_RUNTIME_COMMITMENT_LOOKUP_FAILED: {error}")),
        }
    }
}

pub(super) fn header_protected_batch(
    input: &DeterministicProtectedExecutionInput,
) -> Result<ProtectedBatchCommitment, String> {
    Ok(ProtectedBatchCommitment {
        profile_id: ETDAG_PROFILE_ID.to_string(),
        target_context_root: input.next_commitment.target_context_root.to_hex(),
        boc_digest: input.next_commitment.root()?.0,
        dcc_digest: input.protected_batch.cut_root.0.clone(),
        encrypted_set_root: input.protected_batch.eligible_set_root.0.clone(),
        protected_order_root: input.protected_batch.order_root.0.clone(),
        public_reveal_transcript_root: input.reveal_transcript_root.0.clone(),
        execution_manifest_root: input.digest()?.0,
        protected_gas_total: input.next_commitment.protected_gas,
        protected_count: input.next_commitment.protected_count,
    })
}

/// Exact durable-chain authority needed to execute one protected candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimplifiedProtectedMaterialAuthoritySnapshot {
    pub parent_execution_state: ExecutionState,
    pub canonical_finality_context_digest: EtdagDigest,
    /// Derived from the exact QC-keyed parent material. `None` is valid only
    /// for the distinct Genesis parent of fresh block one.
    pub parent_fee_market: Option<SimplifiedParentFeeMarketState>,
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
        parent: &SimplifiedFinalityParent,
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
    if finalized.validate().is_err()
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
    /// Fee state of the finalized execution boundary. It is `None` only for
    /// fresh Genesis; later epoch boundaries carry the previously verified
    /// finalized block's exact governed fields so restart does not guess or
    /// require replay below the retained boundary.
    pub anchor_finalized_fee_market: Option<SimplifiedParentFeeMarketState>,
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
            || configuration.anchor_finalized.finality_reference_id()
                != transition.finalized_seed().qc_id
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
        match self
            .configuration
            .anchor_finalized
            .quorum_certificate_reference()
        {
            None if self.configuration.anchor_finalized_fee_market.is_some() => {
                return Err("Genesis boundary cannot carry a quorum-derived fee state".to_string())
            }
            Some(reference) => {
                let parent = self
                    .configuration
                    .anchor_finalized_fee_market
                    .ok_or_else(|| {
                        "non-Genesis durable boundary has no finalized fee authority".to_string()
                    })?;
                simplified_fee_market_header_fields(
                    crate::synergy_types::Height(
                        reference.height.0.checked_add(1).ok_or_else(|| {
                            "finalized fee boundary height overflowed".to_string()
                        })?,
                    ),
                    Some(parent),
                )?;
            }
            None => {}
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
            anchor_finalized_fee_market: self.configuration.anchor_finalized_fee_market,
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
        parent: &SimplifiedFinalityParent,
        finalized: &FinalizedBlockRecord,
    ) -> Result<SimplifiedProtectedMaterialAuthoritySnapshot, String> {
        context.validate_against(&self.configuration.epoch_context)?;
        parent.validate_for_child_height(context.height)?;
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
        let durable_parent = durable_finalized.finality_parent.clone();
        if parent.height().0 < durable_parent.height().0 {
            return Err("protected material parent precedes durable finality".to_string());
        }
        let distance = parent
            .height()
            .0
            .checked_sub(durable_parent.height().0)
            .ok_or_else(|| "protected material parent distance underflowed".to_string())?;
        if distance > MAX_SIMPLIFIED_PROTECTED_UNFINALIZED_ANCESTORS as u64 {
            return Err("protected material certified tail exceeds its replay bound".to_string());
        }
        // Refuse an unbounded parent before looking up its material or fee
        // authority. A remote parent reference must not induce arbitrary
        // durable-store reads beyond the certified replay window.
        let parent_fee_market = self.parent_fee_market_state(parent)?;
        let mut replay_parent_fee_market = self.parent_fee_market_state(&durable_parent)?;

        let mut cursor = parent.clone();
        let mut reverse_tail = Vec::new();
        while cursor.height().0 > durable_parent.height().0 {
            let reference = cursor.quorum_certificate_reference().ok_or_else(|| {
                "Genesis reference cannot appear above the durable finality seed".to_string()
            })?;
            let material = self.material_store.load(reference.qc_id)?;
            if material.stable_candidate_id != reference.qc_id
                || material.candidate_subject.context.height != reference.height
                || material.candidate_subject.block_id != reference.block_id
            {
                return Err(
                    "protected material certified tail does not match its parent QC".to_string(),
                );
            }
            cursor = material.candidate_subject.parent.clone();
            reverse_tail.push(material);
        }
        if cursor != durable_parent {
            return Err(
                "protected material certified tail does not extend durable finality".to_string(),
            );
        }
        for material in reverse_tail.iter().rev() {
            parent_execution_state = material.replay_and_verify(
                &self.configuration.epoch_context,
                &parent_execution_state,
                replay_parent_fee_market,
                &self.configuration.etdag_verifier,
                &self.configuration.validator_set,
                &self.configuration.cluster_map,
                &self.configuration.etdag_parameters,
            )?;
            replay_parent_fee_market = Some(SimplifiedParentFeeMarketState::from_verified_header(
                &material.canonical_block.header,
            )?);
        }
        Ok(SimplifiedProtectedMaterialAuthoritySnapshot {
            parent_execution_state,
            canonical_finality_context_digest,
            parent_fee_market,
        })
    }

    fn parent_fee_market_state(
        &self,
        parent: &SimplifiedFinalityParent,
    ) -> Result<Option<SimplifiedParentFeeMarketState>, String> {
        let Some(reference) = parent.quorum_certificate_reference() else {
            return Ok(None);
        };
        if parent == &self.configuration.anchor_finalized.finality_parent {
            return self
                .configuration
                .anchor_finalized_fee_market
                .map(Some)
                .ok_or_else(|| {
                    "durable finalized boundary has no fee-market authority".to_string()
                });
        }
        let store = if reference.height.0 < self.configuration.epoch_context.epoch_start_height.0 {
            &self
                .epoch_transition
                .as_ref()
                .ok_or_else(|| {
                    "previous-epoch fee authority lacks a verified v3 transition".to_string()
                })?
                .previous
                .material_store
        } else {
            &self.material_store
        };
        let material = store.load(reference.qc_id)?;
        if material.stable_candidate_id != reference.qc_id
            || material.candidate_subject.context.height != reference.height
            || material.candidate_subject.block_id != reference.block_id
            || material.canonical_block.candidate_id()? != reference.block_id
        {
            return Err(
                "certified simplified parent fee authority does not match its QC".to_string(),
            );
        }
        SimplifiedParentFeeMarketState::from_verified_header(&material.canonical_block.header)
            .map(Some)
    }
}

impl SimplifiedProtectedMaterialAuthority for DurableSimplifiedProtectedMaterialAuthority {
    fn authority_for_candidate(
        &mut self,
        context: &ConsensusObjectContext,
        parent: &SimplifiedFinalityParent,
        finalized: &FinalizedBlockRecord,
    ) -> Result<SimplifiedProtectedMaterialAuthoritySnapshot, String> {
        self.durable_snapshot(context, parent, finalized)
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
    configuration: SimplifiedProtectedMaterialConfiguration,
    authority: A,
    execution_input_source: Option<Box<dyn SimplifiedProtectedExecutionInputSource>>,
}

impl<A: SimplifiedProtectedMaterialAuthority> SimplifiedProtectedMaterialAdapter<A> {
    pub fn new(
        epoch_context: SimplifiedEpochContext,
        _coordinator: EtdagProtectedInputCoordinator,
        configuration: SimplifiedProtectedMaterialConfiguration,
        authority: A,
    ) -> Result<Self, String> {
        configuration.validate(&epoch_context)?;
        Ok(Self {
            epoch_context,
            configuration,
            authority,
            execution_input_source: None,
        })
    }

    pub fn with_protected_pipeline_source(
        mut self,
        source: impl SimplifiedProtectedExecutionInputSource + 'static,
    ) -> Self {
        self.execution_input_source = Some(Box::new(source));
        self
    }

    fn ready_execution_input(
        &mut self,
        height: crate::synergy_types::Height,
    ) -> Result<DeterministicProtectedExecutionInput, String> {
        self.execution_input_source
            .as_mut()
            .ok_or_else(|| {
                "PROTECTED_PIPELINE_EXECUTION_INPUT_NOT_READY: no durable ProtectedPipeline source is configured"
                    .to_string()
            })?
            .load_ready_execution_input(height)?
            .ok_or_else(|| {
                format!(
                    "PROTECTED_PIPELINE_EXECUTION_INPUT_NOT_READY: no concrete execution input for H{}",
                    height.0
                )
            })
    }

    fn pre_reveal_commitment(
        &mut self,
        parent_height: crate::synergy_types::Height,
    ) -> Result<Option<NextProtectedBatchCommitment>, String> {
        let child_height = parent_height
            .0
            .checked_add(1)
            .map(crate::synergy_types::Height)
            .ok_or_else(|| "protected child height overflowed".to_string())?;
        self.execution_input_source
            .as_mut()
            .ok_or_else(|| {
                "PROTECTED_PIPELINE_EXECUTION_INPUT_NOT_READY: no durable ProtectedPipeline source is configured"
                    .to_string()
            })?
            .load_pre_reveal_commitment(child_height)
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

    fn verify_execution_target(
        &self,
        input: &DeterministicProtectedExecutionInput,
        context: &ConsensusObjectContext,
        finalized: &FinalizedBlockRecord,
        finality_digest: &EtdagDigest,
    ) -> Result<(), String> {
        match &input.target_context {
            ProtectedExecutionTargetContext::NormalEtdag { admission_context } => {
                self.verify_target_context(admission_context, context, finalized, finality_digest)
            }
            ProtectedExecutionTargetContext::GenesisBootstrap { height_context } => {
                height_context.validate_validator_and_cluster_bindings(
                    &self.configuration.validator_set,
                    &self.configuration.etdag_cluster_map,
                )?;
                if !matches!(context.height.0, 1 | 2)
                    || height_context.height != context.height
                    || height_context.epoch != context.epoch
                    || height_context.active_validator_set_root != context.active_validator_set_root
                    || height_context.validator_consensus_key_root
                        != context.validator_consensus_key_root
                    || height_context.frozen_bonded_weight_root != context.frozen_voting_weight_root
                    || height_context.consensus_parameter_root.to_hex()
                        != context.consensus_parameter_root
                {
                    return Err("Genesis protected input names another PoSy slot".to_string());
                }
                Ok(())
            }
        }
    }

    fn target_bindings(
        input: &DeterministicProtectedExecutionInput,
    ) -> (
        crate::synergy_types::ClusterId,
        String,
        Hash,
        Hash,
        u64,
        u64,
    ) {
        match &input.target_context {
            ProtectedExecutionTargetContext::GenesisBootstrap { height_context } => (
                height_context.assigned_cluster_id,
                height_context.cluster_schedule_version.clone(),
                height_context.cluster_map_root,
                height_context.assigned_cluster_membership_root,
                height_context.assigned_cluster_validator_count,
                height_context.assigned_cluster_total_voting_weight,
            ),
            ProtectedExecutionTargetContext::NormalEtdag { admission_context } => (
                admission_context.assigned_cluster_id,
                admission_context.cluster_schedule_version.clone(),
                admission_context.cluster_map_root,
                admission_context.assigned_cluster_membership_root,
                admission_context.assigned_cluster_validator_count,
                admission_context.assigned_cluster_total_voting_weight,
            ),
        }
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
        parent: &SimplifiedFinalityParent,
        finalized: &FinalizedBlockRecord,
    ) -> Result<Hash, String> {
        Ok(Hash::from_domain_bytes(
            "SYNERGY_POSY_SIMPLIFIED_PROTECTED_EVIDENCE_V1",
            &serde_json::to_vec(&(parent, finalized))
                .map_err(|error| format!("serialize simplified protected evidence: {error}"))?,
        ))
    }

    fn verify_static_header(
        &self,
        proposal: &SimplifiedProposal,
        expected_finalized: &FinalizedBlockRecord,
        protected_execution_input: &DeterministicProtectedExecutionInput,
        material: &VerifiedSimplifiedProposalMaterial,
    ) -> Result<(), String> {
        let (cluster_id, schedule, map_root, membership_root, validator_count, voting_weight) =
            Self::target_bindings(protected_execution_input);
        let header = &material.canonical_block.header;
        let transaction_ids =
            Self::ordered_transaction_ids(&material.canonical_block.transactions)?;
        let expected_dag_frontier = Hash::from_domain_bytes(
            "SYNERGY_ETDAG_DAG_CUT_ROOT_V2",
            protected_execution_input
                .protected_batch
                .cut_root
                .0
                .as_bytes(),
        );
        if header.version != POSY_SIMPLIFIED_PROTECTED_BLOCK_VERSION
            || header.cluster_id != cluster_id
            || header.cluster_schedule_version != schedule
            || header.cluster_map_hash != map_root
            || header.assigned_cluster_membership_root != membership_root
            || header.assigned_cluster_validator_count != validator_count
            || header.assigned_cluster_total_voting_weight != voting_weight
            || header.proposer_schedule_hash != self.epoch_context.leader_ring_root
            || header.cryptographic_profile_root != self.configuration.cryptographic_profile_root
            || header.dag_frontier_root != expected_dag_frontier
            || header.tx_order_root != compute_tx_order_root(&transaction_ids)?
            || header.evidence_root != Self::evidence_root(&proposal.parent, expected_finalized)?
            || header.last_finalized_qc_hash != expected_finalized.finality_reference_id()
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
        protected_execution_input: &DeterministicProtectedExecutionInput,
        transactions: Vec<Transaction>,
        parent_state: &ExecutionState,
        authority_parent_fee_market: Option<SimplifiedParentFeeMarketState>,
    ) -> Result<Block, String> {
        let (cluster_id, schedule, map_root, membership_root, validator_count, voting_weight) =
            Self::target_bindings(protected_execution_input);
        let transaction_ids = Self::ordered_transaction_ids(&transactions)?;
        let state_root_before = compute_state_root_after(parent_state)?;
        let timestamp = self.timestamp_for_height(directive.context.height)?;
        let fee_market = simplified_fee_market_header_fields(
            directive.context.height,
            authority_parent_fee_market,
        )?;
        // `BlockHeader` retains this serializable field for decoder
        // compatibility, but each value is derived solely from the concrete
        // R11 input rather than any retired certificate family.
        let header_protected_batch = header_protected_batch(protected_execution_input)?;
        let mut block = Block {
            header: BlockHeader {
                version: POSY_SIMPLIFIED_PROTECTED_BLOCK_VERSION,
                chain_id: directive.context.chain_id,
                network_id: directive.context.network_id.clone(),
                protocol_version: POSY_SIMPLIFIED_PROTOCOL_VERSION.to_string(),
                height: directive.context.height,
                round: directive.context.round,
                epoch: directive.context.epoch,
                cluster_id,
                height_context_root: directive.context.epoch_context_root,
                parent_block_hash: Hash::from_hex(&directive.parent.block_id().0)?,
                parent_state_root: state_root_before,
                last_finalized_qc_hash: directive.finalized.finality_reference_id(),
                proposer_validator_id: proposer.validator_id.clone(),
                proposer_uma_id: proposer.validator_uma_id.clone(),
                proposer_key_id: proposer.consensus_public_key.key_id.clone(),
                active_validator_set_hash: directive.context.active_validator_set_root,
                eligible_validator_set_hash: directive.context.active_validator_set_root,
                validator_consensus_key_root: directive.context.validator_consensus_key_root,
                frozen_bonded_weight_root: directive.context.frozen_voting_weight_root,
                cluster_schedule_version: schedule,
                cluster_map_hash: map_root,
                assigned_cluster_membership_root: membership_root,
                assigned_cluster_validator_count: validator_count,
                assigned_cluster_total_voting_weight: voting_weight,
                proposer_schedule_hash: self.epoch_context.leader_ring_root,
                protocol_config_hash: ConsensusParameterRoot::from_hex(
                    &directive.context.consensus_parameter_root,
                )?,
                cryptographic_profile_root: self.configuration.cryptographic_profile_root,
                dag_frontier_root: Hash::from_domain_bytes(
                    "SYNERGY_ETDAG_DAG_CUT_ROOT_V2",
                    protected_execution_input
                        .protected_batch
                        .cut_root
                        .0
                        .as_bytes(),
                ),
                tx_order_root: compute_tx_order_root(&transaction_ids)?,
                tx_count: u64::try_from(transactions.len())
                    .map_err(|_| "protected transaction count exceeds u64".to_string())?,
                protected_batch: Some(header_protected_batch),
                evidence_root: Self::evidence_root(&directive.parent, &directive.finalized)?,
                state_root_before,
                state_root_after: Hash::zero(),
                receipt_root: Hash::zero(),
                app_version: self.configuration.app_version,
                execution_version: self.configuration.execution_version,
                dag_version: self.configuration.dag_version,
                aegis_pqvm_version: self.configuration.aegis_pqvm_version.clone(),
                timestamp_ms_consensus_bounded: timestamp,
                base_fee_per_gas_nwei: fee_market.base_fee_per_gas_nwei,
                gas_used: 0,
                gas_limit: fee_market.gas_limit,
                pq_gas_used: 0,
                pq_gas_limit: fee_market.pq_gas_limit,
                pq_gas_multiplier: fee_market.pq_gas_multiplier,
                fee_market_version: fee_market.fee_market_version,
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
        block.header.state_root_after = execution.state_root_after;
        block.header.receipt_root = execution.receipt_root;
        block.header.gas_used = execution.gas_used_total;
        block.header.pq_gas_used = execution.pq_gas_used_total;
        validate_simplified_fee_market_header_against_parent(
            &block.header,
            authority_parent_fee_market,
        )?;
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
            &directive.parent,
            &directive.finalized,
        )?;
        let protected_execution_input = match self.ready_execution_input(directive.context.height) {
            Ok(input) => input,
            Err(error) if error.starts_with("PROTECTED_PIPELINE_EXECUTION_INPUT_NOT_READY") => {
                return Ok(None)
            }
            Err(error) => return Err(error),
        };
        self.verify_execution_target(
            &protected_execution_input,
            &directive.context,
            &directive.finalized,
            &authority.canonical_finality_context_digest,
        )?;
        let future_protected_batch_commitment =
            match self.pre_reveal_commitment(directive.context.height) {
                Ok(Some(commitment)) => commitment,
                Ok(None) => return Ok(None),
                Err(error) if error.starts_with("PROTECTED_PIPELINE_COMMITMENT_NOT_READY") => {
                    return Ok(None)
                }
                Err(error) => return Err(error),
            };
        let transactions = protected_execution_input.verify_and_extract_transactions(
            &self.configuration.verifier,
            &self.configuration.validator_set,
            &self.configuration.etdag_cluster_map,
            &self.configuration.etdag_parameters,
        )?;
        let unsigned_proposal = SimplifiedProposal {
            context: directive.context.clone(),
            proposer_id: directive.proposer_id.clone(),
            block_id: BlockId(String::new()),
            parent_block_id: directive.parent.block_id().clone(),
            parent: directive.parent.clone(),
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
            &protected_execution_input,
            transactions,
            &authority.parent_execution_state,
            authority.parent_fee_market,
        )?;
        let block_id = block.candidate_id()?;
        let protected_execution_root =
            compute_simplified_protected_execution_root_with_current_and_future_commitment(
                &directive.context,
                &block,
                directive.parent.block_id(),
                &directive.parent,
                &protected_execution_input,
                Some(&future_protected_batch_commitment),
            )?;
        let proposal = SimplifiedProposal {
            block_id,
            protected_execution_root,
            ..unsigned_proposal
        };
        let (material, _) =
            VerifiedSimplifiedProposalMaterial::verify_protected_with_future_commitment(
                epoch_context,
                &proposal,
                block,
                protected_execution_input,
                Some(future_protected_batch_commitment),
                &authority.parent_execution_state,
                authority.parent_fee_market,
                &self.configuration.verifier,
                &self.configuration.validator_set,
                &self.configuration.etdag_cluster_map,
                &self.configuration.etdag_parameters,
            )?;
        let verified_input = material.protected_execution_input.as_ref().ok_or_else(|| {
            "verified protected material lost its R11 execution input".to_string()
        })?;
        self.verify_static_header(&proposal, &directive.finalized, verified_input, &material)?;
        validate_simplified_fee_market_header_against_parent(
            &material.canonical_block.header,
            authority.parent_fee_market,
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
            &proposal.parent,
            expected_finalized,
        )?;
        let protected_execution_input = material
            .protected_execution_input
            .as_ref()
            .ok_or_else(|| "received protected proposal has no concrete R11 input".to_string())?;
        let locally_derived = self.ready_execution_input(proposal.context.height)?;
        if &locally_derived != protected_execution_input {
            return Err(
                "received protected input differs from the locally derived ProtectedPipeline record"
                    .to_string(),
            );
        }
        let locally_derived_future = self
            .pre_reveal_commitment(proposal.context.height)?
            .ok_or_else(|| {
                format!(
                    "PROTECTED_PIPELINE_COMMITMENT_NOT_READY: no child commitment is ready for proposal H{}",
                    proposal.context.height.0
                )
            })?;
        if material.future_protected_batch_commitment.as_ref() != Some(&locally_derived_future) {
            return Err(
                "received protected proposal child commitment differs from the locally derived pre-reveal commitment"
                    .to_string(),
            );
        }
        self.verify_execution_target(
            protected_execution_input,
            &proposal.context,
            expected_finalized,
            &authority.canonical_finality_context_digest,
        )?;
        self.proposer(proposal)?;
        self.verify_static_header(
            proposal,
            expected_finalized,
            protected_execution_input,
            material,
        )?;
        material.replay_and_verify(
            epoch_context,
            &authority.parent_execution_state,
            authority.parent_fee_market,
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
    use crate::consensus::protected_pipeline_runtime::GenesisBootstrapProtectedExecutionSource;
    use crate::consensus::simplified_posy::{
        DurableSimplifiedProposalMaterialStore, QuorumCertificateReference,
        SimplifiedCoreMaterialConfiguration,
    };
    use crate::consensus::testnet_v3_bootstrap::load_testnet_v3_genesis_bootstrap;
    use crate::etdag::tests::{complete_r11_execution_input, fixture};
    use crate::genesis::canonical_genesis;
    use crate::synergy_types::{
        ClusterId, Epoch, Height, HeightConsensusContext, HeightConsensusContextSpec,
        ProtocolConfig, Round, POSY_PROTOCOL_VERSION, TESTNET_V3_CLUSTER_SCHEDULE_VERSION,
    };
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Clone)]
    struct ExactAuthority {
        expected_context: ConsensusObjectContext,
        expected_parent: SimplifiedFinalityParent,
        expected_finalized: FinalizedBlockRecord,
        snapshot: SimplifiedProtectedMaterialAuthoritySnapshot,
    }

    impl SimplifiedProtectedMaterialAuthority for ExactAuthority {
        fn authority_for_candidate(
            &mut self,
            context: &ConsensusObjectContext,
            parent: &SimplifiedFinalityParent,
            finalized: &FinalizedBlockRecord,
        ) -> Result<SimplifiedProtectedMaterialAuthoritySnapshot, String> {
            if context != &self.expected_context
                || parent != &self.expected_parent
                || finalized != &self.expected_finalized
            {
                return Err("test durable authority rejected substituted pointers".to_string());
            }
            Ok(self.snapshot.clone())
        }
    }

    #[derive(Clone)]
    struct StaticExecutionInputSource {
        input: Option<DeterministicProtectedExecutionInput>,
    }

    impl SimplifiedProtectedExecutionInputSource for StaticExecutionInputSource {
        fn load_ready_execution_input(
            &mut self,
            height: crate::synergy_types::Height,
        ) -> Result<Option<DeterministicProtectedExecutionInput>, String> {
            match &self.input {
                Some(input)
                    if match &input.target_context {
                        ProtectedExecutionTargetContext::GenesisBootstrap { height_context } => {
                            height_context.height
                        }
                        ProtectedExecutionTargetContext::NormalEtdag { admission_context } => {
                            admission_context.target_height
                        }
                    } != height =>
                {
                    Err("test protected input source was asked for another height".to_string())
                }
                Some(input) => Ok(Some(input.clone())),
                None => Ok(None),
            }
        }
    }

    struct TestSetup {
        epoch_context: SimplifiedEpochContext,
        directive: SimplifiedProposalDirective,
        configuration: SimplifiedProtectedMaterialConfiguration,
        authority: ExactAuthority,
        execution_input: Option<DeterministicProtectedExecutionInput>,
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

    fn test_parent_fee_market() -> SimplifiedParentFeeMarketState {
        let parameters = crate::gas::fee_market_params_for_runtime().unwrap();
        SimplifiedParentFeeMarketState {
            base_fee_per_gas_nwei: parameters.initial_base_fee_nwei,
            gas_used: 0,
            fee_market_version: parameters.fee_market_version,
        }
    }

    #[test]
    fn coordinated_source_serves_only_the_registered_canonical_h1_bootstrap_input() {
        let genesis = canonical_genesis().expect("load canonical Testnet-v3 Genesis");
        let bootstrap =
            load_testnet_v3_genesis_bootstrap(genesis).expect("load typed Genesis bootstrap");
        let protocol = ProtocolConfig::testnet_v3();
        let height_context = HeightConsensusContext::derive(
            HeightConsensusContextSpec {
                protocol_version: POSY_PROTOCOL_VERSION.to_string(),
                height: Height(1),
                epoch: Epoch(0),
                assigned_cluster_id: ClusterId(0),
                cluster_schedule_version: TESTNET_V3_CLUSTER_SCHEDULE_VERSION.to_string(),
                finalized_epoch_seed_root: bootstrap.finalized_epoch_seed_root,
                assigned_height_schedule_root: bootstrap.assigned_height_schedule_root(1),
                cryptographic_profile_root: bootstrap.cryptographic_profile_root,
                prior_finalized_qc_or_transition_root: bootstrap.genesis_transition_root,
            },
            &bootstrap.validator_set,
            &bootstrap.cluster_map,
            &protocol,
        )
        .expect("derive H1 context");
        let genesis_anchor = Hash::from_hex(genesis.hash()).expect("decode Genesis anchor");
        let material = bootstrap
            .derive_genesis_bootstrap_protected_material(&protocol, genesis_anchor, &height_context)
            .expect("derive canonical H1 protected material");
        let source = GenesisBootstrapProtectedExecutionSource::new(material.clone())
            .expect("validate canonical bootstrap source");
        let mut bridge = CoordinatedProtectedExecutionInputSource::new();
        bridge
            .register_genesis_bootstrap(Height(1), source.clone())
            .expect("register H1 bootstrap source");
        assert!(bridge
            .register_genesis_bootstrap(Height(1), source)
            .unwrap_err()
            .contains("PROTECTED_EXECUTION_SOURCE_CONFLICT"));

        let input = bridge
            .load_ready_execution_input(Height(1))
            .expect("load H1 protected input")
            .expect("canonical bootstrap is immediately available");
        assert_eq!(input, material.execution_input);
        assert_eq!(input.next_commitment, material.next_commitment);

        let h2_context = bootstrap
            .derive_genesis_bootstrap_height_context(&protocol, genesis_anchor, Height(2))
            .expect("derive canonical H2 context");
        let h2_material = bootstrap
            .derive_genesis_bootstrap_protected_material(&protocol, genesis_anchor, &h2_context)
            .expect("derive canonical H2 protected material");
        bridge
            .register_genesis_bootstrap(
                Height(2),
                GenesisBootstrapProtectedExecutionSource::new(h2_material.clone())
                    .expect("validate canonical H2 bootstrap source"),
            )
            .expect("register H2 bootstrap source");
        assert_eq!(
            bridge
                .load_ready_execution_input(Height(2))
                .expect("load H2 protected input")
                .expect("canonical H2 bootstrap is immediately available"),
            h2_material.execution_input
        );
        assert!(bridge
            .load_ready_execution_input(Height(3))
            .unwrap_err()
            .contains("PROTECTED_PIPELINE_EXECUTION_INPUT_NOT_READY"));
    }

    fn setup(_label: &str, install_protected: bool) -> TestSetup {
        let finality_digest = EtdagDigest::from_domain_bytes("finality", b"complete-input");
        let mut etdag_fixture = fixture(5, None);
        etdag_fixture.context.source_finality_context_root =
            target_admission_source_finality_root(&finality_digest).unwrap();
        let target_context = etdag_fixture.context.clone();
        let execution_input =
            install_protected.then(|| complete_r11_execution_input(&mut etdag_fixture));
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
        let parent_qc = QuorumCertificateReference {
            height: Height(target_context.target_height.0 - 1),
            block_id: BlockId::from_hash(Hash::from_domain_bytes(
                "simplified-protected-test",
                b"parent-block",
            )),
            qc_id: Hash::from_domain_bytes("simplified-protected-test", b"parent-qc"),
        };
        let finalized_qc = QuorumCertificateReference {
            height: target_context.source_finalized_height,
            block_id: BlockId::from_hash(Hash::from_domain_bytes(
                "simplified-protected-test",
                b"finalized-block",
            )),
            qc_id: Hash::from_domain_bytes("simplified-protected-test", b"finalized-qc"),
        };
        let finalized = FinalizedBlockRecord::from_quorum_certificate(finalized_qc).unwrap();
        let parent = SimplifiedFinalityParent::quorum_certificate(parent_qc).unwrap();
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
            parent: parent.clone(),
            finalized: finalized.clone(),
            proposer_id,
            proposer_key_id,
            takeover_tc_id: None,
            mandatory_carry_candidate: None,
        };
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
                parent_fee_market: Some(test_parent_fee_market()),
            },
        };
        TestSetup {
            epoch_context,
            directive,
            configuration,
            authority,
            execution_input,
        }
    }

    #[test]
    fn adapter_builds_replays_and_restarts_with_exact_durable_material() {
        let setup = setup("restart", true);
        let execution_input = setup.execution_input.clone();
        let mut adapter = SimplifiedProtectedMaterialAdapter::new(
            setup.epoch_context.clone(),
            EtdagProtectedInputCoordinator::process_wide(),
            setup.configuration.clone(),
            setup.authority.clone(),
        )
        .unwrap()
        .with_protected_pipeline_source(StaticExecutionInputSource {
            input: execution_input.clone(),
        });
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

        let mut restarted_adapter = SimplifiedProtectedMaterialAdapter::new(
            setup.epoch_context.clone(),
            EtdagProtectedInputCoordinator::process_wide(),
            setup.configuration,
            setup.authority,
        )
        .unwrap()
        .with_protected_pipeline_source(StaticExecutionInputSource {
            input: execution_input,
        });
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
        let execution_input = setup.execution_input.clone();
        let mut adapter = SimplifiedProtectedMaterialAdapter::new(
            setup.epoch_context.clone(),
            EtdagProtectedInputCoordinator::process_wide(),
            setup.configuration,
            setup.authority,
        )
        .unwrap()
        .with_protected_pipeline_source(StaticExecutionInputSource {
            input: execution_input,
        });
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
        match &mut wrong_context
            .protected_execution_input
            .as_mut()
            .unwrap()
            .target_context
        {
            ProtectedExecutionTargetContext::NormalEtdag { admission_context } => {
                admission_context.source_finalized_height = Height(1);
            }
            ProtectedExecutionTargetContext::GenesisBootstrap { .. } => {
                panic!("normal ETDAG fixture unexpectedly used Genesis material")
            }
        }
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
            .protected_execution_input
            .as_mut()
            .unwrap()
            .next_commitment
            .order_seed = EtdagDigest::from_domain_bytes(
            "simplified-protected-test",
            b"wrong-protected-order-seed",
        );
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

        let wrong_finalized =
            FinalizedBlockRecord::from_quorum_certificate(QuorumCertificateReference {
                height: setup.directive.finalized.height,
                block_id: setup.directive.finalized.block_id.clone(),
                qc_id: Hash::from_domain_bytes("simplified-protected-test", b"wrong-finality"),
            })
            .unwrap();
        assert!(adapter
            .verify_received(&setup.epoch_context, &proposal, &wrong_finalized, &material,)
            .is_err());
    }

    #[test]
    fn adapter_waits_without_proposing_when_certified_input_is_missing() {
        let setup = setup("not-ready", false);
        let execution_input = setup.execution_input.clone();
        let mut adapter = SimplifiedProtectedMaterialAdapter::new(
            setup.epoch_context.clone(),
            EtdagProtectedInputCoordinator::process_wide(),
            setup.configuration,
            setup.authority,
        )
        .unwrap()
        .with_protected_pipeline_source(StaticExecutionInputSource {
            input: execution_input,
        });
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
        let anchor_qc = QuorumCertificateReference {
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
        let finalized = FinalizedBlockRecord::from_quorum_certificate(anchor_qc.clone()).unwrap();
        let execution_state = ExecutionState::new();
        let mut core = SimplifiedCoreMaterialAdapter::new(
            epoch_context.clone(),
            SimplifiedCoreMaterialConfiguration {
                validator_set: etdag_fixture.validator_set.clone(),
                cluster_map: etdag_fixture.cluster_map.clone(),
                execution_state: execution_state.clone(),
                parent_fee_market: Some(test_parent_fee_market()),
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
                parent: SimplifiedFinalityParent::quorum_certificate(parent_qc).unwrap(),
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
            anchor_finalized_fee_market: Some(test_parent_fee_market()),
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
                anchor_finalized_fee_market: Some(test_parent_fee_market()),
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
        let qc_seven_parent =
            SimplifiedFinalityParent::quorum_certificate(qc_seven.clone()).unwrap();
        let snapshot = authority
            .authority_for_candidate(&target, &qc_seven_parent, &finalized)
            .unwrap();
        assert_eq!(snapshot.parent_execution_state, execution_state);
        assert_eq!(
            snapshot.canonical_finality_context_digest,
            expected_finality_digest
        );

        let wrong_finalized =
            FinalizedBlockRecord::from_quorum_certificate(QuorumCertificateReference {
                height: finalized.height,
                block_id: finalized.block_id.clone(),
                qc_id: Hash::from_domain_bytes(
                    "simplified-protected-durable-test",
                    b"wrong-finality",
                ),
            })
            .unwrap();
        assert!(authority
            .authority_for_candidate(&target, &qc_seven_parent, &wrong_finalized)
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
        let far_parent = SimplifiedFinalityParent::quorum_certificate(far_parent).unwrap();
        assert!(authority
            .authority_for_candidate(&far_target, &far_parent, &finalized)
            .unwrap_err()
            .contains("replay bound"));
    }
}
