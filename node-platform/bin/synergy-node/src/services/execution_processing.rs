//! Live asynchronous assembly on the existing execution owner. Native PoSy
//! exports the slot; this module cannot advance height, select a leader or vote.
#[cfg(feature = "qualification-timing")]
use crate::services::qualification_timing::{
    processing_span as diagnostic_span, ProcessingStage as DiagnosticStage,
};

use super::*;
use crate::services::ingress::{ProcessingBuildRequest, ProcessingSnapshot};
use crate::services::processing_pipeline::{
    processing_order_seed, NativeProcessingParent, NativeProcessingPipeline,
};
use crate::services::processing_proposals::{
    ProcessingProposalError, ProcessingProposalInputs, ProcessingProposalStore,
};
use crate::services::protected_accounts::processing_execution::native::{
    with_live_wallet_dispatch, NativeProtectedDispatch,
};
use std::sync::Mutex;
use synergy_etdag::execution::ProcessingOrderGroup;
use synergy_execution::{
    ProcessingCandidateContext, ProcessingCandidateError, ProcessingEpochClose,
};

pub(in crate::services) fn execute_native_processing<D, V>(
    scheduler: &BlockExecutionScheduler<D, V>,
    authority: &VerifiedAuthority,
    context: ProcessingCandidateContext<'_>,
    parent: &NativeProcessingParent<'_>,
    publications: &[synergy_execution::ProcessingReadyRecord],
    pipeline: &NativeProcessingPipeline<'_>,
) -> Result<ExecutionCandidate, ProcessingCandidateError>
where
    D: synergy_execution::TransactionExecutor,
    V: synergy_transaction::AegisTransactionVerifier,
{
    let subject = authority
        .epoch_close_subject_at(context.height)
        .map_err(ProcessingCandidateError::Invalid)?;
    if subject.is_some() && parent.epoch_transition().is_some() {
        return Err(ProcessingCandidateError::Invalid(
            "closing subject cannot apply an opening processing transition".into(),
        ));
    }
    if let Some(journal) = pipeline.wallet_journal() {
        let wallet = journal.prepare(authority, pipeline, &context, parent.world())?;
        return execute_wallet_processing(
            scheduler,
            authority,
            context,
            parent,
            publications,
            pipeline,
            &wallet,
            subject,
        );
    }
    if authority.wallet_dispatch_policy().is_some() {
        return Err(ProcessingCandidateError::Invalid(
            "signed Wallet action policy requires an activated native journal".into(),
        ));
    }
    execute_combined_processing(
        scheduler,
        authority,
        context,
        parent,
        publications,
        pipeline,
        pipeline,
        None,
        subject,
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_wallet_processing<D, V>(
    scheduler: &BlockExecutionScheduler<D, V>,
    authority: &VerifiedAuthority,
    context: ProcessingCandidateContext<'_>,
    parent: &NativeProcessingParent<'_>,
    publications: &[synergy_execution::ProcessingReadyRecord],
    pipeline: &NativeProcessingPipeline<'_>,
    wallet: &NativeProtectedDispatch<'_>,
    subject: Option<String>,
) -> Result<ExecutionCandidate, ProcessingCandidateError>
where
    D: synergy_execution::TransactionExecutor,
    V: synergy_transaction::AegisTransactionVerifier,
{
    execute_combined_processing(
        scheduler,
        authority,
        context,
        parent,
        publications,
        pipeline,
        wallet,
        Some(wallet),
        subject,
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_combined_processing<D, V, R>(
    scheduler: &BlockExecutionScheduler<D, V>,
    authority: &VerifiedAuthority,
    mut context: ProcessingCandidateContext<'_>,
    parent: &NativeProcessingParent<'_>,
    publications: &[synergy_execution::ProcessingReadyRecord],
    pipeline: &NativeProcessingPipeline<'_>,
    readiness: &R,
    wallet: Option<&dyn synergy_execution::ProcessingNativeWalletActions>,
    subject: Option<String>,
) -> Result<ExecutionCandidate, ProcessingCandidateError>
where
    D: synergy_execution::TransactionExecutor,
    V: synergy_transaction::AegisTransactionVerifier,
    R: synergy_execution::ProcessingReadinessVerifier,
{
    if authority
        .ethereum_activation(parent.world(), Some(parent.world().budget()))
        .map_err(ProcessingCandidateError::Invalid)?
        .is_some_and(|selected| {
            crate::services::ethereum_activation::is_active(&selected, parent.world())
                .unwrap_or(false)
        })
    {
        let policy = synergy_aivm::ethereum_execution::EvmCompatibilityPolicy::load(parent.world())
            .map_err(|error| ProcessingCandidateError::Invalid(error.to_string()))?;
        context.maximum_gas = context.maximum_gas.min(policy.block_gas_limit);
    }
    let dispatch = crate::services::processing_pipeline::ethereum::EthereumDispatch {
        pipeline,
        authority,
        context,
        wallet,
    };
    let candidate = match subject {
        Some(subject_root) => scheduler.execute_processing_epoch_close_with_wallet_actions(
            ProcessingEpochClose {
                epoch_end_height: authority.epoch.epoch_end_height,
                subject_root: &subject_root,
            },
            context,
            parent.world(),
            publications,
            readiness,
            pipeline,
            Some(&dispatch),
        ),
        None => scheduler.execute_processing_candidate_with_wallet_actions(
            context,
            parent.world(),
            publications,
            readiness,
            pipeline,
            parent.epoch_transition(),
            Some(&dispatch),
        ),
    }?;
    crate::services::processing_pipeline::ethereum::finish_candidate(authority, candidate)
}

pub(super) struct ProcessingExecutionState {
    pub(super) store: Arc<Mutex<ProcessingProposalStore>>,
    pending: Option<(Arc<ProcessingBuildRequest>, Arc<ExecutionCandidate>)>,
    announced: Option<(u64, u64, String)>,
    pub(super) proof_cleanup_cursor: usize,
    pub(super) source_pin_retry: Option<u64>,
}
pub(super) struct PreviousProcessingState {
    pub(super) authority: Arc<VerifiedAuthority>,
    pub(super) store: Arc<Mutex<ProcessingProposalStore>>,
    pub(super) transition: super::super::authority::VerifiedTransitionContext,
}

impl PreviousProcessingState {
    pub(super) fn verify_autonomous_startup_replay(
        &self,
        finalized_height: u64,
    ) -> Result<(), String> {
        if !self.transition.is_autonomous()
            || finalized_height > self.authority.epoch.epoch_end_height
        {
            return Ok(());
        }
        let store = self
            .store
            .lock()
            .map_err(|_| "predecessor processing proposal journal lock poisoned")?;
        for qc in self
            .transition
            .certificates()
            .iter()
            .filter(|qc| qc.context.height >= finalized_height)
        {
            let height = qc.context.height;
            // This checks the original persisted inputs as well as the
            // independently authenticated VC, without using either to write state.
            store
                .try_with_validation(&qc.block_id, |vc| {
                    if vc.context.height != height
                        || vc.candidate.block_id != qc.block_id
                        || vc.candidate.parent_block_id != qc.parent_block_id
                        || vc.candidate.protected_execution_root != qc.protected_execution_root
                    {
                        return Err("predecessor execution inputs/VC conflict with autonomous QC".into());
                    }
                    Ok(())
                })
                .map_err(|error| {
                    format!("autonomous startup requires exact predecessor execution inputs/VC H{height}: {error}")
                })?;
        }
        Ok(())
    }
}

impl ProcessingExecutionState {
    pub(super) fn new(store: Arc<Mutex<ProcessingProposalStore>>) -> Self {
        Self {
            store,
            pending: None,
            announced: None,
            proof_cleanup_cursor: 0,
            source_pin_retry: None,
        }
    }
}

fn retryable(error: &ProcessingCandidateError) -> bool {
    use synergy_execution::{ProcessingPayloadError, ProcessingRegistryError};
    use synergy_state::world_resources::WorldResourceError;
    matches!(
        error,
        ProcessingCandidateError::Resource(WorldResourceError::Capacity { .. })
            | ProcessingCandidateError::Registry(ProcessingRegistryError::Resource(
                WorldResourceError::Capacity { .. }
            ))
            | ProcessingCandidateError::Payload(ProcessingPayloadError::Unavailable(_))
            | ProcessingCandidateError::Payload(ProcessingPayloadError::Resource(
                WorldResourceError::Capacity { .. }
            ))
            | ProcessingCandidateError::State(synergy_state::StateError::ResourcePressure { .. })
    ) || matches!(error, ProcessingCandidateError::Candidate(e) if candidate_resource_pressure(e))
        || matches!(error, ProcessingCandidateError::Execution(e) if execution_resource_pressure(e))
}

// Retry only typed capacity pressure or a not-yet-published ECHO proof.
// Authentication, corruption and durable-storage errors still fail closed.
fn retry_processing_store<T>(
    result: Result<T, ProcessingProposalError>,
) -> Result<Option<T>, String> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.is_retryable() => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

// A build request is a transient PoSy observation, not a certificate. Replay
// may already have advanced beyond it; this says nothing about the validity of
// a different block at the current execution height.
fn processing_build_is_obsolete(
    parent_height: u64,
    parent_block: &str,
    execution_height: u64,
    execution_block: &str,
) -> Result<bool, String> {
    if parent_height == execution_height && parent_block != execution_block {
        return Err(format!(
            "native processing slot conflicts with execution parent at height {execution_height}: request={parent_block}, execution={execution_block}"
        ));
    }
    Ok(parent_height < execution_height)
}

/// Ordinary replay is bounded by finality. A complete epoch is the only
/// exception: its two remaining certified candidates are needed by the next
/// authority, even though neither can yet be finalized.
fn needs_terminal_replay(epoch_end: u64, finalized: u64, executed: u64) -> bool {
    finalized != 0
        && finalized.checked_add(2) == Some(epoch_end)
        && (finalized..epoch_end).contains(&executed)
}

#[cfg(test)]
mod slot_regression {
    use super::{needs_terminal_replay, processing_build_is_obsolete};

    #[test]
    fn terminal_replay_is_limited_to_the_two_unfinalized_epoch_candidates() {
        let end = 20_000;
        assert!(!needs_terminal_replay(end, end - 3, end - 3));
        assert!(!needs_terminal_replay(end, end - 2, end - 3));
        assert!(needs_terminal_replay(end, end - 2, end - 2));
        assert!(needs_terminal_replay(end, end - 2, end - 1));
        assert!(!needs_terminal_replay(end, end - 2, end));
        assert!(!needs_terminal_replay(end, end - 1, end - 1));
        assert!(!needs_terminal_replay(2, 0, 0));
        assert!(!needs_terminal_replay(u64::MAX, u64::MAX, u64::MAX));
    }

    #[test]
    fn finalized_replay_obsoletes_old_slot_without_accepting_same_height_conflict() {
        let request_parent_height = 12_074;
        let request_parent = "parent-before-replay";
        assert!(!processing_build_is_obsolete(
            request_parent_height,
            request_parent,
            request_parent_height,
            request_parent,
        )
        .unwrap());
        let replay_tip = request_parent_height + 2;
        let replay_block = "verified-replay-tip";
        assert!(processing_build_is_obsolete(
            request_parent_height,
            request_parent,
            replay_tip,
            replay_block,
        )
        .unwrap());
        assert!(
            processing_build_is_obsolete(replay_tip, request_parent, replay_tip, replay_block)
                .unwrap_err()
                .contains("conflicts with execution parent at height 12076")
        );
        assert!(
            !processing_build_is_obsolete(replay_tip, replay_block, replay_tip, replay_block)
                .unwrap()
        );
        assert!(!processing_build_is_obsolete(
            replay_tip + 1,
            "requires-next-certified-parent",
            replay_tip,
            replay_block,
        )
        .unwrap());
    }
}

impl ExecutionService {
    #[allow(clippy::too_many_arguments)]
    fn execute_live_processing(
        &self,
        authority: &VerifiedAuthority,
        context: ProcessingCandidateContext<'_>,
        parent: &NativeProcessingParent<'_>,
        mut publications: Vec<synergy_execution::ProcessingReadyRecord>,
        pipeline: &NativeProcessingPipeline<'_>,
        snapshot: &ProcessingSnapshot,
        proposing: bool,
    ) -> Result<
        Option<(
            ExecutionCandidate,
            Vec<synergy_execution::ProcessingReadyRecord>,
        )>,
        ProcessingCandidateError,
    > {
        use super::super::processing_pipeline::NativeProcessingContext;
        use synergy_execution::{ParentProcessingRegistry, ProcessingPayloadError};
        use ProcessingCandidateError::{Invalid, Payload};

        let Some(policy) = authority.wallet_dispatch_policy() else {
            return execute_native_processing(
                &self.scheduler,
                authority,
                context,
                parent,
                &publications,
                pipeline,
            )
            .map(|candidate| Some((candidate, publications)));
        };
        let registry = ParentProcessingRegistry::read(
            parent.world().as_ref(),
            context.namespace_root,
            self.ingress.world_budget(),
        )?;
        // A previously published Wallet READY record must wait for its exact
        // durable original after process restart. Missing material is retryable.
        for record in registry.records() {
            if !pipeline.has_completion(&record.item.envelope_id)
                && !snapshot
                    .wallet_completions
                    .iter()
                    .any(|original| original.record.item.envelope_id == record.item.envelope_id)
            {
                return Err(Payload(ProcessingPayloadError::Unavailable(
                    record.item.envelope_id.clone(),
                )));
            }
        }
        // The certified proposal parent H-1 fixes the exact three-QC
        // finalized source at H-3, independently of each worker's observed tip.
        let finalized_height = context.height.saturating_sub(3);
        if finalized_height < policy.activation_finalized_height {
            // Settlement cannot be present before the first certified
            // activation height. Ordinary processing still advances PoSy.
            return self
                .execute_before_wallet_finality(authority, context, parent, &publications, pipeline)
                .map(|candidate| Some((candidate, publications)));
        }
        let Some((record, witness)) = self
            .ingress
            .finalized_record_with_witness(finalized_height)
            .map_err(Invalid)?
        else {
            return Ok(None);
        };
        if witness[2].context.height.checked_add(1) != Some(context.height)
            || witness[2].block_id != context.parent_block_id
        {
            return Err(Invalid(
                "Wallet finality witness does not end at the certified proposal parent".into(),
            ));
        }
        let Some(candidate) = self
            .candidate_store
            .get_budgeted(finalized_height)
            .map_err(|error| Invalid(error.to_string()))?
        else {
            return Ok(None);
        };
        if candidate.block_id != record.block_id {
            return Err(Invalid(
                "Wallet dispatch finalized World mismatches native history".into(),
            ));
        }
        let target = authority
            .protected_parameters()
            .map_err(Invalid)?
            .protected_target_height(record.height)
            .map_err(|error| Invalid(format!("{error:?}")))?;
        let Some(source_authority) = self.authority.autonomous_authority_at(target) else {
            return Ok(None);
        };
        let source_context = synergy_etdag::ProcessingContext {
            context_version: 1,
            profile_id: synergy_etdag::PROCESSING_PROFILE_ID.into(),
            authority: source_authority
                .protected_target(Some(&record), target)
                .map_err(Invalid)?
                .0,
        };
        let source = NativeProcessingContext::verify_owned_finalized(
            source_authority,
            &source_context,
            candidate,
            &witness,
            self.ingress.world_budget(),
        )
        .map_err(Invalid)?
        .with_lineage(&self.authority)
        .map_err(Invalid)?;
        let context = ProcessingCandidateContext {
            finalized_authorization_state: source
                .verified_finalized_source()
                .map_err(Invalid)?
                .world,
            ..context
        };
        let subject = authority
            .epoch_close_subject_at(context.height)
            .map_err(Invalid)?;
        if subject.is_some() && parent.epoch_transition().is_some() {
            return Err(Invalid(
                "closing subject cannot apply an opening processing transition".into(),
            ));
        }
        with_live_wallet_dispatch(
            authority,
            pipeline,
            &context,
            parent.world(),
            &source,
            &snapshot.wallet_completions,
            |dispatch| {
                if proposing {
                    for original in &snapshot.wallet_completions {
                        let record = &original.record;
                        if registry
                            .records()
                            .iter()
                            .any(|ready| ready.item.envelope_id == record.item.envelope_id)
                            || synergy_execution::verify_processing_record_assignment(
                                parent.world(),
                                context.namespace_root,
                                record,
                            )
                            .is_err()
                            || !dispatch.can_publish(record).map_err(Invalid)?
                        {
                            continue;
                        }
                        publications.push(record.clone());
                    }
                }
                execute_wallet_processing(
                    &self.scheduler,
                    authority,
                    context,
                    parent,
                    &publications,
                    pipeline,
                    dispatch,
                    subject,
                )
                .map(|candidate| Some((candidate, publications)))
            },
        )
    }

    fn execute_before_wallet_finality(
        &self,
        authority: &VerifiedAuthority,
        context: ProcessingCandidateContext<'_>,
        parent: &NativeProcessingParent<'_>,
        publications: &[synergy_execution::ProcessingReadyRecord],
        pipeline: &NativeProcessingPipeline<'_>,
    ) -> Result<ExecutionCandidate, ProcessingCandidateError> {
        let subject = authority
            .epoch_close_subject_at(context.height)
            .map_err(ProcessingCandidateError::Invalid)?;
        if subject.is_some() && parent.epoch_transition().is_some() {
            return Err(ProcessingCandidateError::Invalid(
                "closing subject cannot apply an opening processing transition".into(),
            ));
        }
        execute_combined_processing(
            &self.scheduler,
            authority,
            context,
            parent,
            publications,
            pipeline,
            pipeline,
            None,
            subject,
        )
    }
    pub(super) fn processing_authority_at(
        &self,
        height: u64,
    ) -> Result<&VerifiedAuthority, String> {
        if self.authority.epoch.contains_height(height) {
            return Ok(&self.authority);
        }
        if let Some(previous) = self.previous_processing.as_ref() {
            if previous.authority.epoch.contains_height(height)
                && height >= previous.transition.finalized().height
                && height <= self.authority.anchor_parent.height()
            {
                return Ok(&previous.authority);
            }
        }
        Err("processing height is outside authenticated current/transition authority".into())
    }

    pub(super) fn processing_store_at(
        &self,
        current: &Arc<Mutex<ProcessingProposalStore>>,
        height: u64,
    ) -> Result<Arc<Mutex<ProcessingProposalStore>>, String> {
        let authority = self.processing_authority_at(height)?;
        if authority.epoch.epoch == self.authority.epoch.epoch {
            Ok(Arc::clone(current))
        } else {
            Ok(Arc::clone(
                &self
                    .previous_processing
                    .as_ref()
                    .ok_or("processing transition store is absent")?
                    .store,
            ))
        }
    }

    pub(super) fn processing_parent<'a>(
        &'a self,
        store: &Arc<Mutex<ProcessingProposalStore>>,
        next_authority: &'a VerifiedAuthority,
    ) -> Result<Option<NativeProcessingParent<'a>>, String> {
        if self.execution_height == 0 {
            return NativeProcessingParent::genesis(&self.state, next_authority).map(Some);
        }
        let Some(candidate) = self.candidates.get(&self.execution_height) else {
            return Ok(None);
        };
        let parent_store = self.processing_store_at(store, candidate.height)?;
        let guard = parent_store
            .lock()
            .map_err(|_| "processing proposal journal lock poisoned")?;
        if !guard.has_validation(&candidate.block_id) {
            return Ok(None);
        }
        retry_processing_store(guard.try_with_validation(&candidate.block_id, |vc| {
            if self.authority.epoch.epoch == next_authority.epoch.epoch
                && candidate.height == self.authority.anchor_parent.height()
                && !self.authority.epoch.contains_height(candidate.height)
            {
                let previous = self
                    .previous_processing
                    .as_ref()
                    .ok_or("native processing transition parent lacks prior authority")?;
                NativeProcessingParent::verify_transition(
                    candidate,
                    vc,
                    &previous.authority,
                    next_authority,
                    &previous.transition,
                )
                .map_err(ProcessingProposalError::from)
            } else {
                NativeProcessingParent::verify(candidate, vc, next_authority)
                    .map_err(ProcessingProposalError::from)
            }
        }))
    }

    fn processing_execute_inputs(
        &self,
        store: &Arc<Mutex<ProcessingProposalStore>>,
        inputs: &ProcessingProposalInputs,
        snapshot: &ProcessingSnapshot,
    ) -> Result<Option<Arc<ExecutionCandidate>>, String> {
        let authority = self.processing_authority_at(inputs.context.height)?;
        #[cfg(feature = "qualification-timing")]
        let _diagnostic = diagnostic_span(DiagnosticStage::CandidateReplay);
        if inputs.context.height
            != self
                .execution_height
                .checked_add(1)
                .ok_or("processing height overflow")?
            || inputs.parent.block_id()
                != self
                    .candidates
                    .get(&self.execution_height)
                    .map_or(self.authority.anchor_parent.block_id(), |c| {
                        c.block_id.as_str()
                    })
        {
            return Err(
                "processing replay inputs do not extend the verified execution parent".into(),
            );
        }
        if let Some(group) = &inputs.ordered_group {
            for member in &group.members {
                if !snapshot.members.iter().any(|m| m.member() == member) {
                    self.ingress
                        .request_processing_handoff(member.envelope.tx_commitment.clone(), false)?;
                }
            }
        }
        for record in &inputs.publications {
            if !snapshot.completions.iter().any(|v| v.record == *record)
                && !snapshot
                    .wallet_completions
                    .iter()
                    .any(|v| v.record == *record)
            {
                self.ingress
                    .request_processing_handoff(record.item.envelope_id.clone(), true)?;
            }
        }
        if inputs.ordered_group.as_ref().is_some_and(|group| {
            group.members.iter().any(|member| {
                !snapshot
                    .members
                    .iter()
                    .any(|available| available.member() == member)
            })
        }) || inputs.publications.iter().any(|record| {
            !snapshot
                .completions
                .iter()
                .any(|available| available.record == *record)
                && !snapshot
                    .wallet_completions
                    .iter()
                    .any(|available| available.record == *record)
        }) {
            return Ok(None); // Missing verified material is retryable, never an empty substitution.
        }
        let Some(parent) = self.processing_parent(store, authority)? else {
            return Ok(None);
        };
        let members = snapshot
            .members
            .iter()
            .map(AsRef::as_ref)
            .collect::<Vec<_>>();
        let completions = snapshot
            .completions
            .iter()
            .map(AsRef::as_ref)
            .collect::<Vec<_>>();
        let pipeline = NativeProcessingPipeline::from_members(&parent, &members, &completions)?;
        let Some(namespace) = crate::services::processing_pipeline::try_processing_namespace(
            authority,
            self.ingress.world_budget(),
        )?
        else {
            return Ok(None);
        };
        let limits = authority.protected_parameters()?;
        let result = self.execute_live_processing(
            authority,
            ProcessingCandidateContext {
                ordered_group: inputs.ordered_group.as_ref(),
                height: inputs.context.height,
                parent_block_id: inputs.parent.block_id(),
                network: &self.network,
                consensus_timestamp_unix: authority
                    .consensus_timestamp_unix(inputs.context.height)?,
                namespace_root: &namespace,
                maximum_gas: limits.max_protected_gas,
                maximum_bytes: limits.max_protected_bytes,
                finalized_authorization_state: &self.finalized_state,
            },
            &parent,
            inputs.publications.clone(),
            &pipeline,
            snapshot,
            false,
        );
        let candidate = match result {
            Ok(Some((candidate, _))) => candidate,
            Ok(None) => return Ok(None),
            Err(e) if retryable(&e) => return Ok(None),
            Err(e) => return Err(e.to_string()),
        };
        if candidate.block_id != inputs.block_id
            || candidate.state_root != inputs.state_root
            || candidate.protected_execution_root != inputs.protected_execution_root
        {
            return Err("processing proposer inputs fail deterministic native replay".into());
        }
        Ok(Some(Arc::new(candidate)))
    }

    /// Canonical storage receives a speculative candidate only when the exact
    /// QC has been admitted by PoSy. An unsigned build instruction is not a QC.
    fn promote_processing_parent(
        &mut self,
        owner: &mut ProcessingExecutionState,
        request: &ProcessingBuildRequest,
        snapshot: &ProcessingSnapshot,
    ) -> Result<bool, String> {
        if request.parent.height() == self.execution_height {
            // The owner checked the exact block before consuming any inputs.
            return Ok(true);
        }
        if request.parent.height() > self.execution_height + 1 {
            // Restore certified transitions in order. A current build slot is
            // not permission to skip the historical execution gap.
            for _ in 0..MAX_BATCHES_PER_POLL {
                if self.execution_height + 1 >= request.parent.height() {
                    break;
                }
                if !self.promote_processing_next(owner, snapshot)? {
                    return Ok(false);
                }
            }
            if request.parent.height() != self.execution_height + 1 {
                return Ok(false);
            }
        }
        let authority = self.processing_authority_at(request.parent.height())?;
        let Some(qc) = self
            .qc_store
            .get_verified(
                request.parent.height(),
                &authority.epoch,
                &authority.registry,
                authority,
            )
            .map_err(|e| e.to_string())?
        else {
            return Ok(false);
        };
        let reference = request
            .parent
            .quorum_certificate_reference()
            .ok_or("processing parent lacks native QC reference")?;
        if qc.id().map_err(|e| e.to_string())? != reference.qc_id
            || qc.block_id != reference.block_id
        {
            return Err("processing parent differs from persisted native QC".into());
        }
        self.commit_processing_qc(owner, snapshot, &qc)
    }

    fn promote_processing_next(
        &mut self,
        owner: &mut ProcessingExecutionState,
        snapshot: &ProcessingSnapshot,
    ) -> Result<bool, String> {
        let authority = self.processing_authority_at(self.execution_height + 1)?;
        let Some(qc) = self
            .qc_store
            .get_verified(
                self.execution_height + 1,
                &authority.epoch,
                &authority.registry,
                authority,
            )
            .map_err(|e| e.to_string())?
        else {
            return Ok(false);
        };
        self.commit_processing_qc(owner, snapshot, &qc)
    }

    fn commit_processing_qc(
        &mut self,
        owner: &mut ProcessingExecutionState,
        snapshot: &ProcessingSnapshot,
        qc: &synergy_posy::SimplifiedQuorumCertificate,
    ) -> Result<bool, String> {
        #[cfg(feature = "qualification-timing")]
        let _diagnostic = diagnostic_span(DiagnosticStage::CandidateCommit);
        let store = self.processing_store_at(&owner.store, qc.context.height)?;
        let historical = qc.context.epoch != self.authority.epoch.epoch;
        let candidate = match owner
            .pending
            .as_ref()
            .filter(|(_, c)| c.block_id == qc.block_id)
        {
            Some((_, candidate)) => Arc::clone(candidate),
            None => {
                // Copy only the charged store handle. Release the journal lock
                // before replay; PoSy's durable validation publication can proceed.
                let guard = store
                    .lock()
                    .map_err(|_| "processing proposal journal lock poisoned")?;
                if !guard.contains(&qc.block_id) {
                    return Ok(false);
                }
                // Input guard is charged throughout replay; no World is loaded
                // from an untrusted pre-QC record.
                let Some(inputs) = retry_processing_store(guard.try_load_inputs(&qc.block_id))?
                else {
                    return Ok(false);
                };
                drop(guard);
                let Some(candidate) = self.processing_execute_inputs(&store, &inputs, snapshot)?
                else {
                    return Ok(false);
                };
                candidate
            }
        };
        if candidate.parent_block_id != qc.parent_block_id
            || candidate.protected_execution_root != qc.protected_execution_root
        {
            return Err("processing candidate conflicts with native QC".into());
        }
        match self.candidate_store.put_budgeted(&candidate, &self.state) {
            Ok(()) => {}
            Err(e) if candidate_resource_pressure(&e) => return Ok(false),
            Err(e) => return Err(e.to_string()),
        }
        if !self.pin_processing_candidate(&owner.store, &candidate)? {
            return Ok(false);
        }
        if !historical {
            let mut stages = store
                .lock()
                .map_err(|_| "processing proposal journal lock poisoned")?;
            if retry_processing_store(stages.try_archive_certified(qc, &candidate))?.is_none() {
                return Ok(false);
            }
            // Live reveal permission always resolves a QC-selected World. Exact
            // certified inputs/VCs now remain available through the archive.
            if retry_processing_store(stages.try_compact_certified_stage(qc, &Default::default()))?
                .is_none()
            {
                return Ok(false);
            }
        }
        self.ingress.publish_processing_certified_parent(
            Arc::clone(&candidate),
            qc,
            self.processing_authority_at(qc.context.height)?,
        )?;
        self.execution_height = candidate.height;
        self.state = Arc::clone(&candidate.state);
        self.candidates.insert(candidate.height, candidate);
        owner.pending = None;
        owner.announced = None;
        Ok(true)
    }

    pub(super) fn poll_processing_execution(&mut self) -> Result<(), String> {
        if let Some((id, height)) = self.ingress.take_processing_bootstrap_export()? {
            if height <= self.finalized_height {
                if let Some(candidate) = self
                    .candidate_store
                    .get_budgeted(height)
                    .map_err(|e| e.to_string())?
                {
                    if crate::services::processing_handoff::bootstrap_id(&candidate.block_id) == id
                    {
                        if let Some(owner) = &self.processing {
                            if let Ok(store) = self.processing_store_at(&owner.store, height) {
                                if let Ok((bytes, _permit)) = store
                                    .lock()
                                    .map_err(|_| "processing bootstrap export poisoned")?
                                    .try_export_sync(&candidate.block_id)
                                {
                                    let _ = crate::services::processing_handoff::publish_bootstrap(
                                        &candidate,
                                        &bytes,
                                        &self.ingress,
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        let Some(snapshot) = self.ingress.processing_snapshot()? else {
            return Ok(());
        };
        let mut owner = self
            .processing
            .take()
            .ok_or("processing execution owner unavailable")?;
        let result = (|| {
            // Epoch completion clears live proposal work. It must not disable
            // replay of already certified historical inputs imported by Sync.
            // Only the trusted PoSy finality floor authorizes this bounded pass;
            // the existing replay path still verifies each next QC/input/VC.
            let finality = self.ingress.latest_finality()?;
            let finalized = finality.as_ref().map_or(0, |record| record.height);
            for _ in 0..MAX_BATCHES_PER_POLL {
                if self.execution_height >= finalized
                    || !self.promote_processing_next(&mut owner, &snapshot)?
                {
                    break;
                }
            }
            // Read the latest slot after bounded finalized replay. Even this
            // observation can be behind the local verified execution tip.
            match self.ingress.processing_build_request()? {
                Some(request) => self.poll_processing_owner(&mut owner, request, &snapshot),
                None => {
                    if let Some(finality) = finality.as_ref() {
                        self.replay_terminal_processing_tail(&mut owner, &snapshot, finality)?;
                    }
                    Ok(())
                }
            }
        })();
        self.processing = Some(owner);
        result
    }

    fn replay_terminal_processing_tail(
        &mut self,
        owner: &mut ProcessingExecutionState,
        snapshot: &ProcessingSnapshot,
        finalized: &synergy_posy::FinalizedBlockRecord,
    ) -> Result<(), String> {
        let end = self.authority.epoch.epoch_end_height;
        if !needs_terminal_replay(end, finalized.height, self.execution_height) {
            return Ok(());
        }
        let mut witness = synergy_posy::ThreeQcFinality::default();
        let mut tail = Vec::with_capacity(2);
        for height in finalized.height..=end {
            let Some(qc) = self
                .qc_store
                .get_verified(
                    height,
                    &self.authority.epoch,
                    &self.authority.registry,
                    self.authority.as_ref(),
                )
                .map_err(|e| e.to_string())?
            else {
                return Ok(()); // No complete local proof yet.
            };
            witness.accept(qc.clone()).map_err(|e| e.to_string())?;
            if height > finalized.height {
                tail.push(qc);
            }
        }
        if witness.last_finalized() != Some(finalized) {
            return Err("terminal processing witness disagrees with local finality".into());
        }
        // Ordinary QC-selected replay checks VC, parent, state and ETDAG inputs.
        // This does not apply finality or produce a vote for either candidate.
        for qc in tail {
            if qc.context.height > self.execution_height
                && !self.commit_processing_qc(owner, snapshot, &qc)?
            {
                break;
            }
        }
        Ok(())
    }

    fn poll_processing_owner(
        &mut self,
        owner: &mut ProcessingExecutionState,
        request: Arc<ProcessingBuildRequest>,
        snapshot: &ProcessingSnapshot,
    ) -> Result<(), String> {
        let execution_block = self
            .candidates
            .get(&self.execution_height)
            .map_or(self.authority.anchor_parent.block_id(), |candidate| {
                candidate.block_id.as_str()
            });
        if processing_build_is_obsolete(
            request.parent.height(),
            request.parent.block_id(),
            self.execution_height,
            execution_block,
        )? {
            return Ok(());
        }
        // Sync establishes finalized state; the current proposal supplies the
        // two certified, unfinalized predecessors needed to reconstruct its
        // native parent. Import inputs only; commit still uses local PoSy QCs
        // and complete native transition replay in height order.
        for _ in 0..2 {
            let Some(frame) = self.ingress.take_processing_inputs(false)? else {
                break;
            };
            let parsed = serde_json::from_slice::<ProcessingProposalInputs>(&frame.payload);
            let mut current = false;
            if let Ok(inputs) = parsed {
                if frame.sender == request.proposer
                    && inputs.context == request.context
                    && inputs.parent == request.parent
                    && inputs.certified_ancestors.len() <= 2
                    && inputs.takeover_id.as_deref() == request.takeover.as_ref().map(|tc| tc.id())
                {
                    current = true;

                    for (qc, bytes) in &inputs.certified_ancestors {
                        if qc.context.height > request.parent.height()
                            || qc.context.height + 1 < request.parent.height()
                        {
                            continue;
                        }
                        let ancestor_store =
                            self.processing_store_at(&owner.store, qc.context.height)?;
                        if ancestor_store
                            .lock()
                            .map_err(|_| "processing proposal journal lock poisoned")?
                            .has_validation(&qc.block_id)
                        {
                            continue;
                        }
                        let authority = self.processing_authority_at(qc.context.height)?;
                        let local = self
                            .qc_store
                            .get_verified(
                                qc.context.height,
                                &authority.epoch,
                                &authority.registry,
                                authority,
                            )
                            .map_err(|e| e.to_string())?;
                        if local
                            .as_ref()
                            .map(|q| q.id())
                            .transpose()
                            .map_err(|e| e.to_string())?
                            != Some(qc.id().map_err(|e| e.to_string())?)
                        {
                            continue;
                        }
                        let imported = ancestor_store
                            .lock()
                            .map_err(|_| "processing proposal journal lock poisoned")?
                            .try_import_certified(bytes.as_bytes(), qc);
                        if retry_processing_store(imported)?.is_none() {
                            // The complete original frame owns any remaining ancestors.
                            self.ingress.queue_processing_inputs(
                                &frame.sender,
                                &frame.payload,
                                false,
                            )?;
                            return Ok(());
                        }
                    }
                }
            }
            if current {
                self.ingress
                    .queue_processing_inputs(&frame.sender, &frame.payload, false)?;
            }
        }
        if !self.promote_processing_parent(owner, &request, snapshot)? {
            return Ok(());
        }
        if owner
            .pending
            .as_ref()
            .is_some_and(|(r, _)| Arc::ptr_eq(r, &request))
        {
            return self.announce_processing_candidate(owner);
        }
        owner.pending = None;
        let local = self
            .ingress
            .processing_local_validator()?
            .ok_or("processing local identity unavailable")?;
        if request.proposer == local {
            #[cfg(feature = "qualification-timing")]
            let _diagnostic = diagnostic_span(DiagnosticStage::CandidateBuild);
            if let Some(carry) = request.mandatory_carry.as_ref() {
                let inputs = {
                    let guard = owner
                        .store
                        .lock()
                        .map_err(|_| "processing proposal journal lock poisoned")?;
                    if !guard.contains(&carry.block_id) {
                        return Ok(());
                    }
                    let Some(inputs) =
                        retry_processing_store(guard.try_load_inputs(&carry.block_id))?
                    else {
                        return Ok(());
                    };
                    inputs
                };
                let Some(candidate) =
                    self.processing_execute_inputs(&owner.store, &inputs, snapshot)?
                else {
                    return Ok(());
                };
                let staged = owner
                    .store
                    .lock()
                    .map_err(|_| "processing proposal journal lock poisoned")?
                    .try_stage(
                        Arc::clone(&request),
                        Arc::clone(&candidate),
                        inputs.ordered_group.as_ref(),
                        &inputs.publications,
                    );
                let Some(token) = retry_processing_store(staged)? else {
                    return Ok(());
                };
                self.ingress.submit_processing_candidate(token)?;
                owner.pending = Some((request, candidate));
                return self.announce_processing_candidate(owner);
            }
            let Some(parent) = self.processing_parent(&owner.store, &self.authority)? else {
                return Ok(());
            };
            let Some(namespace) = crate::services::processing_pipeline::try_processing_namespace(
                &self.authority,
                self.ingress.world_budget(),
            )?
            else {
                return Ok(());
            };
            let limits = self.authority.protected_parameters()?;
            let _scratch = match self.ingress.world_budget().reserve(
                32 * 1024 + snapshot.members.len() * 16 * 1024 + snapshot.completions.len() * 4096,
            ) {
                Ok(p) => p,
                Err(synergy_state::world_resources::WorldResourceError::Capacity { .. }) => {
                    return Ok(())
                }
                Err(e) => return Err(e.to_string()),
            };
            let members = snapshot
                .members
                .iter()
                .map(AsRef::as_ref)
                .collect::<Vec<_>>();
            let completions = snapshot
                .completions
                .iter()
                .map(AsRef::as_ref)
                .collect::<Vec<_>>();
            let pipeline = NativeProcessingPipeline::from_members(&parent, &members, &completions)?;
            let registry = match synergy_execution::ParentProcessingRegistry::read(
                parent.world(),
                &namespace,
                self.ingress.world_budget(),
            ) {
                Ok(registry) => registry,
                Err(synergy_execution::ProcessingRegistryError::Resource(
                    synergy_state::world_resources::WorldResourceError::Capacity { .. },
                )) => return Ok(()),
                Err(error) => return Err(error.to_string()),
            };
            let publications = snapshot
                .completions
                .iter()
                .filter(|completion| {
                    !registry
                        .records()
                        .iter()
                        .any(|r| r.item.envelope_id == completion.record.item.envelope_id)
                })
                .filter(|completion| {
                    synergy_execution::verify_processing_record_assignment(
                        parent.world(),
                        &namespace,
                        &completion.record,
                    )
                    .is_ok()
                })
                .map(|completion| completion.record.clone())
                .collect::<Vec<_>>();
            let (number, previous, open) =
                synergy_execution::processing_order_tip(parent.world(), &namespace)
                    .map_err(|e| e.to_string())?;
            let mut group = ProcessingOrderGroup {
                group_version: 1,
                namespace_root: namespace.clone(),
                group_number: number,
                previous_group_root: previous,
                order_seed: namespace.clone(),
                members: Vec::new(),
            };
            group.order_seed = processing_order_seed(&self.authority, &group)?;
            let mut unassigned = BTreeMap::new();
            for member in &snapshot.members {
                let member = member.member();
                let envelope = &member.envelope;
                if self
                    .state
                    .accounts
                    .get(&envelope.sender_id)
                    .map_or(0, |a| a.nonce)
                    > envelope.nonce_slot
                {
                    continue;
                }
                if synergy_execution::processing_member_claim_optional(
                    parent.world(),
                    &envelope.sender_id,
                    envelope.nonce_slot,
                )
                .map_err(|e| e.to_string())?
                .is_none()
                {
                    unassigned
                        .entry((envelope.sender_id.clone(), envelope.nonce_slot))
                        .or_insert(member);
                }
            }
            // A dependency must be in this same immutable ordering group.
            // Work with an unavailable dependency remains pending, not invalid.
            loop {
                let absent = unassigned
                    .iter()
                    .filter(|(_, m)| {
                        m.envelope
                            .protocol_dependencies
                            .iter()
                            .any(|d| !unassigned.values().any(|v| &v.envelope.tx_commitment == d))
                    })
                    .map(|(key, _)| key.clone())
                    .collect::<Vec<_>>();
                if absent.is_empty() {
                    break;
                }
                for key in absent {
                    unassigned.remove(&key);
                }
            }
            let eligible = unassigned
                .values()
                .map(|m| m.envelope.clone())
                .collect::<Vec<_>>();
            let ordered = synergy_etdag::canonical_content_blind_order(
                &eligible,
                &group.order_seed,
                limits.max_protected_gas,
                limits.max_protected_bytes,
            )
            .map_err(|e| format!("processing group order: {e:?}"))?;
            for envelope in ordered {
                group.members.push(
                    (*unassigned
                        .get(&(envelope.sender_id.clone(), envelope.nonce_slot))
                        .ok_or("processing member index disappeared")?)
                    .clone(),
                );
            }
            let group = (!group.members.is_empty() || open).then_some(group);
            let (candidate, publications) = match self.execute_live_processing(
                self.authority.as_ref(),
                ProcessingCandidateContext {
                    ordered_group: group.as_ref(),
                    height: request.context.height,
                    parent_block_id: request.parent.block_id(),
                    network: &self.network,
                    consensus_timestamp_unix: self
                        .authority
                        .consensus_timestamp_unix(request.context.height)?,
                    namespace_root: &namespace,
                    maximum_gas: limits.max_protected_gas,
                    maximum_bytes: limits.max_protected_bytes,
                    finalized_authorization_state: &self.finalized_state,
                },
                &parent,
                publications,
                &pipeline,
                snapshot,
                true,
            ) {
                Ok(Some((candidate, publications))) => (Arc::new(candidate), publications),
                Ok(None) => return Ok(()),
                Err(e) if retryable(&e) => return Ok(()),
                Err(e) => return Err(e.to_string()),
            };
            drop(pipeline);
            drop(parent);
            let staged = owner
                .store
                .lock()
                .map_err(|_| "processing proposal journal lock poisoned")?
                .try_stage(
                    Arc::clone(&request),
                    Arc::clone(&candidate),
                    group.as_ref(),
                    &publications,
                );
            let Some(token) = retry_processing_store(staged)? else {
                return Ok(());
            };
            self.ingress.submit_processing_candidate(token)?;
            owner.pending = Some((request, candidate));
            return self.announce_processing_candidate(owner);
        }
        for _ in 0..2 {
            let Some(frame) = self.ingress.take_processing_inputs(false)? else {
                break;
            };
            if frame.sender != request.proposer {
                continue;
            }
            let inputs: ProcessingProposalInputs = match serde_json::from_slice(&frame.payload) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if inputs.context != request.context
                || inputs.parent != request.parent
                || inputs.takeover_id.as_deref() != request.takeover.as_ref().map(|tc| tc.id())
            {
                continue;
            }
            let replayed = self.processing_execute_inputs(&owner.store, &inputs, snapshot);
            let candidate = match replayed {
                Ok(Some(candidate)) => candidate,
                Ok(None) => {
                    self.ingress
                        .queue_processing_inputs(&frame.sender, &frame.payload, false)?;
                    break;
                }
                Err(error) => {
                    #[cfg(test)]
                    eprintln!("processing proposer inputs rejected: {error}");
                    #[cfg(not(test))]
                    let _ = error;
                    continue;
                }
            };
            let staged = owner
                .store
                .lock()
                .map_err(|_| "processing proposal journal lock poisoned")?
                .try_stage(
                    Arc::clone(&request),
                    Arc::clone(&candidate),
                    inputs.ordered_group.as_ref(),
                    &inputs.publications,
                );
            let Some(token) = retry_processing_store(staged)? else {
                self.ingress
                    .queue_processing_inputs(&frame.sender, &frame.payload, false)?;
                return Ok(());
            };
            self.ingress.submit_processing_candidate(token)?;
            owner.pending = Some((Arc::clone(&request), candidate));
            break;
        }
        Ok(())
    }
    fn announce_processing_candidate(
        &self,
        owner: &mut ProcessingExecutionState,
    ) -> Result<(), String> {
        let Some((request, candidate)) = owner.pending.as_ref() else {
            return Ok(());
        };
        let local = self.ingress.processing_local_validator()?;
        if local.as_deref() != Some(request.proposer.as_str()) {
            return Ok(());
        }
        let id = (
            request.context.height,
            request.context.round,
            candidate.block_id.clone(),
        );
        if owner.announced.as_ref() == Some(&id) {
            return Ok(());
        }
        let guard = owner
            .store
            .lock()
            .map_err(|_| "processing proposal journal lock poisoned")?;
        let Some(inputs) = retry_processing_store(guard.try_load_inputs(&candidate.block_id))?
        else {
            return Ok(());
        };
        let queued = retry_processing_store((|| -> Result<bool, ProcessingProposalError> {
            let mut current = serde_json::to_value(&*inputs).map_err(|e| e.to_string())?;
            current["context"] =
                serde_json::to_value(&request.context).map_err(|e| e.to_string())?;
            current["parent"] = serde_json::to_value(&request.parent).map_err(|e| e.to_string())?;
            current["takeover_id"] =
                serde_json::to_value(request.takeover.as_ref().map(|tc| tc.id()))
                    .map_err(|e| e.to_string())?;
            let mut ancestors = Vec::new();
            let mut ancestor_permits = Vec::new();
            for height in request.parent.height().saturating_sub(1).max(1)..=request.parent.height()
            {
                let authority = self.processing_authority_at(height)?;
                let Some(qc) = self
                    .qc_store
                    .get_verified(height, &authority.epoch, &authority.registry, authority)
                    .map_err(|e| e.to_string())?
                else {
                    continue;
                };
                // The journal lock is already held by with_inputs.
                let (bytes, permit) = if authority.epoch.epoch == self.authority.epoch.epoch {
                    guard.try_export_sync(&qc.block_id)?
                } else {
                    self.previous_processing
                        .as_ref()
                        .ok_or("processing transition archive is absent")?
                        .store
                        .lock()
                        .map_err(|_| "processing proposal journal lock poisoned")?
                        .try_export_sync(&qc.block_id)?
                };
                ancestors.push((qc, String::from_utf8(bytes).map_err(|e| e.to_string())?));
                ancestor_permits.push(permit);
            }
            current["certified_ancestors"] =
                serde_json::to_value(&ancestors).map_err(|e| e.to_string())?;
            let bytes = serde_json::to_vec(&current).map_err(|e| e.to_string())?;
            self.ingress
                .queue_processing_inputs(&request.proposer, &bytes, true)
                .map_err(ProcessingProposalError::from)
        })())?;
        if queued == Some(true) {
            owner.announced = Some(id);
        }
        Ok(())
    }
}
