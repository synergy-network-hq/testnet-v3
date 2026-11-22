//! Engineering dispatch for the original protected ETDAG admission. The
//! approved ordinary scheduler and public admission registry cannot select it.
use super::{
    debug,
    processing_admission::{CandidateAdmission, CandidateAuthorization},
    sponsor_settlement::SponsoredOutcome,
    sponsored_admission::VerifiedSponsoredAdmission,
    transfer_admission::VerifiedTransferAdmission,
    CandidateProtectedAccounts, CandidateTransferExecution, ChainId, FinalizedSnapshot, Position,
    TransferCandidateContent,
};
use crate::services::processing_pipeline::{
    AuthenticatedProcessingOpening, NativeProcessingRecovery, ProcessingCompletionEvidence,
    Pw13FinalizedSource, RevealedProcessingPayload,
};
use crate::services::processing_store::{
    PendingProcessingStore, ProcessingAdmissionAuthenticator, ProcessingStoreError,
};
#[cfg(test)]
use std::collections::BTreeMap;
use std::sync::Arc;
use synergy_address_engine::apqe::provider::{variants::Mldsa87, PqProvider};
use synergy_aegis::ApqeIdentityVerifier;
use synergy_etdag::{
    execution::processing_admission_authorization_root, EtdagDigest, EtdagParameters,
    ProcessingContext, ProcessingEnvelope,
};
use synergy_execution::{
    decode_budgeted_pw13_engineering_candidate, processing_group_state, verify_processing_payload,
    BudgetedExecutionCandidate, FeeSchedule, ParentProcessingRegistry, ProcessingReadinessVerifier,
    ProcessingReadyRecord,
};
use synergy_state::{
    state_root,
    world_resources::{BudgetedWorld, WorldResourceBudget, WorldResourcePermit},
    WorldState,
};

enum ActionAuthorization {
    Transfer(VerifiedTransferAdmission),
    SponsoredEnrollment(VerifiedSponsoredAdmission),
}

pub(super) struct AuthorizedCandidateAdmission {
    authorization_root: EtdagDigest,
    parameters: EtdagParameters,
    valid_until_finalized_height: u64,
    action: ActionAuthorization,
}

pub(super) struct CandidateAuthorizationContext<'a> {
    pub(super) source: &'a FinalizedSnapshot<'a>,
    pub(super) provider: &'a PqProvider<Mldsa87>,
    pub(super) sponsor_verifier: Option<&'a ApqeIdentityVerifier>,
    pub(super) parameters: &'a EtdagParameters,
    pub(super) fee_schedule: &'a FeeSchedule,
    pub(super) metered_gas: u64,
}

impl CandidateProtectedAccounts<'_> {
    pub(super) fn authorize_processing_candidate(
        &self,
        context: &ProcessingContext,
        admission: &CandidateAdmission,
        terms: CandidateAuthorizationContext<'_>,
    ) -> Result<AuthorizedCandidateAdmission, String> {
        let (action, valid_until_finalized_height) = match &admission.authorization {
            CandidateAuthorization::Transfer(proof) => {
                let verified = self.verify_transfer_admission(
                    terms.provider,
                    terms.source,
                    context,
                    &admission.envelope,
                    proof,
                    terms.parameters,
                    terms.fee_schedule,
                    terms.metered_gas,
                )?;
                (
                    ActionAuthorization::Transfer(verified),
                    proof.resources.valid_until_finalized_height,
                )
            }
            CandidateAuthorization::SponsoredEnrollment(proof) => {
                let identity = terms
                    .sponsor_verifier
                    .ok_or("protected sponsor identity verifier is unavailable")?;
                let verified = self.verify_sponsored_admission(
                    terms.provider,
                    identity,
                    terms.source,
                    context,
                    &admission.envelope,
                    proof,
                    terms.parameters,
                    terms.fee_schedule,
                    terms.metered_gas,
                )?;
                (
                    ActionAuthorization::SponsoredEnrollment(verified),
                    proof.resources.valid_until_finalized_height,
                )
            }
        };
        let authorization_root =
            processing_admission_authorization_root(admission).map_err(debug)?;
        Ok(AuthorizedCandidateAdmission {
            authorization_root,
            parameters: terms.parameters.clone(),
            valid_until_finalized_height,
            action,
        })
    }
}

/// Metering and provider inputs come from the selected engineering rule set,
/// never from the pending journal or the proposal under review.
#[derive(Clone, Copy)]
pub(super) struct ProtectedRecoveryTerms<'a> {
    pub(super) provider: &'a PqProvider<Mldsa87>,
    pub(super) sponsor_verifier: Option<&'a ApqeIdentityVerifier>,
    pub(super) fee_schedule: &'a FeeSchedule,
    pub(super) metered_gas: u64,
}

pub(super) struct RecoveredProtectedAction<'a> {
    opening: AuthenticatedProcessingOpening,
    admission: AuthorizedCandidateAdmission,
    source: FinalizedSnapshot<'a>,
    context: &'a ProcessingContext,
    envelope: &'a ProcessingEnvelope,
    terms: ProtectedRecoveryTerms<'a>,
}

impl RecoveredProtectedAction<'_> {
    fn for_parent<'a>(
        &'a self,
        parent: &'a BudgetedWorld,
    ) -> Result<PreparedProtectedAction<'a>, String> {
        PreparedProtectedAction::from_opening(
            CandidateDispatch {
                source: &self.source,
                provider: self.terms.provider,
                sponsor_verifier: self.terms.sponsor_verifier,
                fee_schedule: self.terms.fee_schedule,
                admission: &self.admission,
            },
            self.opening.payload(self.envelope, self.context)?,
            parent,
        )
    }
}

impl CandidateProtectedAccounts<'_> {
    pub(super) fn native_finalized_snapshot<'a>(
        &'a self,
        verified: &Pw13FinalizedSource<'a>,
    ) -> Result<FinalizedSnapshot<'a>, String> {
        if ChainId::from_u64(verified.context.authority.chain_id).as_be_bytes()
            != &self.network.native_chain
            || super::inspection::hex_bytes(&self.network.genesis) != verified.genesis_hash
            || verified.consensus_time == 0
        {
            return Err(
                "protected recovery differs from the authenticated chain or Genesis".into(),
            );
        }
        Ok(FinalizedSnapshot {
            registry: self,
            world: verified.world,
            position: Position {
                height: verified.record.height,
                consensus_time: verified.consensus_time,
            },
            processing_finality_root: crate::services::authority::processing_finality_root(
                verified.record,
            )?,
        })
    }
}

/// Authenticates the unchanged pending journal against the certified source.
pub(super) struct ProtectedAdmissionRecovery<'a> {
    registry: &'a CandidateProtectedAccounts<'a>,
    recovery: NativeProcessingRecovery<'a>,
    snapshot: FinalizedSnapshot<'a>,
    context: &'a ProcessingContext,
    context_root: EtdagDigest,
    parameters: EtdagParameters,
    terms: ProtectedRecoveryTerms<'a>,
}

impl<'a> ProtectedAdmissionRecovery<'a> {
    pub(super) fn new(
        registry: &'a CandidateProtectedAccounts<'a>,
        recovery: NativeProcessingRecovery<'a>,
        terms: ProtectedRecoveryTerms<'a>,
    ) -> Result<Self, String> {
        let verified = recovery.source.pw13_finalized_source()?;
        let snapshot = registry.native_finalized_snapshot(&verified)?;
        Ok(Self {
            registry,
            recovery,
            snapshot,
            context: verified.context,
            context_root: verified.context.root().map_err(debug)?,
            parameters: verified.authority.protected_parameters()?,
            terms,
        })
    }

    pub(super) fn snapshot(&self) -> &FinalizedSnapshot<'a> {
        &self.snapshot
    }

    fn authorize(
        &self,
        admission: &CandidateAdmission,
    ) -> Result<AuthorizedCandidateAdmission, String> {
        self.registry.authorize_processing_candidate(
            self.context,
            admission,
            CandidateAuthorizationContext {
                source: &self.snapshot,
                provider: self.terms.provider,
                sponsor_verifier: self.terms.sponsor_verifier,
                parameters: &self.parameters,
                fee_schedule: self.terms.fee_schedule,
                metered_gas: self.terms.metered_gas,
            },
        )
    }

    pub(super) fn recover<'b>(
        &'b self,
        admission: &'b CandidateAdmission,
        evidence: &ProcessingCompletionEvidence,
        budget: &Arc<WorldResourceBudget>,
    ) -> Result<RecoveredProtectedAction<'b>, String> {
        let (opening, authorized) =
            self.recovery
                .recover_pw13(admission, evidence, budget, |original| {
                    self.authorize(original)
                })?;
        Ok(RecoveredProtectedAction {
            opening,
            admission: authorized,
            source: FinalizedSnapshot {
                registry: self.registry,
                world: self.snapshot.world,
                position: self.snapshot.position,
                processing_finality_root: self.snapshot.processing_finality_root.clone(),
            },
            context: self.context,
            envelope: &admission.envelope,
            terms: self.terms,
        })
    }
}

/// Binds each journal item to its own certified authorization source and
/// closed-order parent. A store can contain several contexts and several
/// reveal parents within one context.
pub(super) struct ProtectedJournalRecovery<'a> {
    pub(super) sources: &'a [ProtectedAdmissionRecovery<'a>],
}

impl ProtectedJournalRecovery<'_> {
    fn completion_source(
        &self,
        admission: &CandidateAdmission,
        evidence: &ProcessingCompletionEvidence,
    ) -> Result<&ProtectedAdmissionRecovery<'_>, String> {
        self.sources
            .iter()
            .find(|source| {
                source.context_root == admission.envelope.aad.processing_context_root
                    && source.recovery.reveal_parent.block_id
                        == evidence.reveal_validation.candidate.block_id
                    && source
                        .recovery
                        .dag_parents
                        .iter()
                        .map(|parent| parent.vertex_id())
                        .eq(evidence.parents.iter())
            })
            .ok_or_else(|| "protected journal lacks the exact certified reveal source".into())
    }

    fn with_action<T>(
        &self,
        pending: &PendingProcessingStore<CandidateAdmission>,
        record: &ProcessingReadyRecord,
        parent: &BudgetedWorld,
        parameters: &EtdagParameters,
        action: impl FnOnce(PreparedProtectedAction<'_>) -> Result<T, String>,
    ) -> Result<T, String> {
        pending
            .reconstruct_completion(
                &record.item.envelope_id,
                self,
                |context, admission, evidence, workspace| {
                    let run = || {
                        let source = self.completion_source(admission, evidence)?;
                        if source.context != context || source.parameters != *parameters {
                            return Err(
                                "protected processing context or limits differ from the authenticated admission"
                                    .into(),
                            );
                        }
                        let recovered = source.recover(admission, evidence, workspace)?;
                        action(recovered.for_parent(parent)?)
                    };
                    run().map_err(ProcessingStoreError::Verification)
                },
            )
            .map_err(debug)
    }
}

impl ProcessingAdmissionAuthenticator<CandidateAdmission> for ProtectedJournalRecovery<'_> {
    fn verify(
        &self,
        context: &ProcessingContext,
        timestamp: u64,
        admission: &CandidateAdmission,
    ) -> Result<(), String> {
        self.sources
            .iter()
            .find(|source| source.context == context)
            .ok_or("protected journal lacks its original authenticated context")?
            .verify(context, timestamp, admission)
    }

    fn verify_completion(
        &self,
        context: &ProcessingContext,
        admission: &CandidateAdmission,
        evidence: &ProcessingCompletionEvidence,
        budget: &Arc<WorldResourceBudget>,
    ) -> Result<(), String> {
        self.completion_source(admission, evidence)?
            .verify_completion(context, admission, evidence, budget)
    }
}

impl ProcessingAdmissionAuthenticator<CandidateAdmission> for ProtectedAdmissionRecovery<'_> {
    fn verify(
        &self,
        context: &ProcessingContext,
        timestamp: u64,
        admission: &CandidateAdmission,
    ) -> Result<(), String> {
        if context != self.context || timestamp != self.snapshot.position.consensus_time {
            return Err(
                "protected journal changed the authenticated context or source time".into(),
            );
        }
        self.authorize(admission).map(drop)
    }

    fn verify_completion(
        &self,
        context: &ProcessingContext,
        admission: &CandidateAdmission,
        evidence: &ProcessingCompletionEvidence,
        budget: &Arc<WorldResourceBudget>,
    ) -> Result<(), String> {
        if context != self.context {
            return Err("protected completion changed the authenticated context".into());
        }
        self.recover(admission, evidence, budget).map(drop)
    }
}

#[cfg(test)]
impl AuthorizedCandidateAdmission {
    pub(super) fn transfer(&self) -> &VerifiedTransferAdmission {
        let ActionAuthorization::Transfer(proof) = &self.action else {
            panic!("expected protected transfer authorization");
        };
        proof
    }

    pub(super) fn sponsor(&self) -> &VerifiedSponsoredAdmission {
        let ActionAuthorization::SponsoredEnrollment(proof) = &self.action else {
            panic!("expected sponsored enrollment authorization");
        };
        proof
    }
}

#[derive(Clone, Copy)]
pub(super) struct CandidateDispatch<'a> {
    pub(super) source: &'a FinalizedSnapshot<'a>,
    pub(super) provider: &'a PqProvider<Mldsa87>,
    pub(super) sponsor_verifier: Option<&'a ApqeIdentityVerifier>,
    pub(super) fee_schedule: &'a FeeSchedule,
    pub(super) admission: &'a AuthorizedCandidateAdmission,
}

/// The native caller supplies the authenticated finalized predecessor at this
/// slot. It may advance beyond the source that authorized the envelope.
#[derive(Clone, Copy)]
pub(super) struct CandidateSlot<'a> {
    pub(super) inclusion: Position,
    pub(super) finalized_parent: &'a FinalizedSnapshot<'a>,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum CandidateActionOutcome {
    Transfer(CandidateTransferExecution),
    SponsoredEnrollment(SponsoredOutcome, u128),
}

const READY_RECORD_RESERVATION: usize = 32 * 1024;

/// Stage just the recognized authorization and availability result. Plaintext
/// stays borrowed from the charged native opening for the life of this action.
pub(super) struct PreparedProtectedAction<'a> {
    dispatch: CandidateDispatch<'a>,
    opened: RevealedProcessingPayload<'a>,
    record: ProcessingReadyRecord,
    _permit: WorldResourcePermit,
}

impl<'a> PreparedProtectedAction<'a> {
    #[cfg(test)]
    pub(super) fn prepare(
        dispatch: CandidateDispatch<'a>,
        opened: RevealedProcessingPayload<'a>,
        parent: &'a BudgetedWorld,
        slot: CandidateSlot<'a>,
    ) -> Result<Self, String> {
        let action = Self::from_opening(dispatch, opened, parent)?;
        action.verify_publication(parent, &action.record, slot)?;
        Ok(action)
    }

    fn from_opening(
        dispatch: CandidateDispatch<'a>,
        opened: RevealedProcessingPayload<'a>,
        parent: &BudgetedWorld,
    ) -> Result<Self, String> {
        let permit = parent
            .budget()
            .reserve(READY_RECORD_RESERVATION)
            .map_err(debug)?;
        let record = opened.ready_record(parent)?;
        if record.authorization_root != dispatch.admission.authorization_root {
            return Err(
                "protected authorization differs from the original ordered admission".into(),
            );
        }
        Ok(Self {
            dispatch,
            opened,
            record,
            _permit: permit,
        })
    }

    fn verify_publication(
        &self,
        parent: &BudgetedWorld,
        record: &ProcessingReadyRecord,
        slot: CandidateSlot<'_>,
    ) -> Result<(), String> {
        if self.opened.ready_record(parent)? != *record {
            return Err(
                "protected READY publication differs from the authenticated opening".into(),
            );
        }
        // Refuse invalid decrypted content before publishing readiness. These
        // tentative ledger and receipt writes are never a publication effect.
        let mut trial =
            BudgetedWorld::try_clone_world(parent.as_ref(), parent.budget()).map_err(debug)?;
        self.execute(&mut trial, slot).map(drop)
    }

    fn verify_selection(
        &self,
        parent: &BudgetedWorld,
        record: &ProcessingReadyRecord,
    ) -> Result<(), String> {
        let mut original = self.opened.ready_record(parent)?;
        // The authenticated parent registry removes dependencies as their
        // exact envelopes are consumed. All other READY fields stay immutable.
        original
            .item
            .remaining_dependencies
            .retain(|id| record.item.remaining_dependencies.contains(id));
        if original != *record {
            return Err("selected protected READY lost its original reveal permission".into());
        }
        Ok(())
    }

    fn execute(
        &self,
        candidate: &mut BudgetedWorld,
        slot: CandidateSlot<'_>,
    ) -> Result<CandidateActionOutcome, String> {
        let inclusion = slot.inclusion;
        if inclusion.height < self.opened.envelope().aad.authorization_height {
            return Err("protected execution precedes the original authorization height".into());
        }
        let source = self.dispatch.source;
        let finalized = slot.finalized_parent;
        if !std::ptr::eq(source.registry, finalized.registry)
            || finalized.position.height < source.position.height
            || finalized.position.consensus_time < source.position.consensus_time
            || (finalized.position.height == source.position.height
                && finalized.processing_finality_root != source.processing_finality_root)
            || inclusion.height <= finalized.position.height
            || inclusion.consensus_time < finalized.position.consensus_time
        {
            return Err("protected execution has an inconsistent finalized predecessor".into());
        }
        if finalized.position.height > self.dispatch.admission.valid_until_finalized_height {
            return Err("protected authorization expired at the finalized predecessor".into());
        }
        verify_processing_payload(&self.record, self.opened.plaintext(), candidate.budget())
            .map_err(debug)?;
        let payer = self.record.sender_wallet.as_str();
        let expected_nonce = self.record.sender_nonce;
        if candidate.accounts.get(payer).map(|a| a.nonce) != Some(expected_nonce) {
            return Err("protected execution differs from the selected payer nonce".into());
        }
        let nonce_after = expected_nonce
            .checked_add(1)
            .ok_or("protected execution nonce overflow")?;
        let dispatch = &self.dispatch;
        let registry = dispatch.source.registry;
        let outcome = match &dispatch.admission.action {
            ActionAuthorization::Transfer(proof) => {
                CandidateActionOutcome::Transfer(registry.execute_engineering_transfer(
                    dispatch.provider,
                    dispatch.source,
                    candidate,
                    TransferCandidateContent::OpenedEtdag(self.opened, proof),
                    dispatch.fee_schedule,
                    proof.gas(),
                    inclusion,
                )?)
            }
            ActionAuthorization::SponsoredEnrollment(proof) => {
                let identity = dispatch
                    .sponsor_verifier
                    .ok_or("protected sponsor identity verifier is unavailable")?;
                let (outcome, fee) = registry.execute_opened_sponsored_enrollment(
                    dispatch.provider,
                    identity,
                    dispatch.source,
                    candidate,
                    inclusion,
                    self.opened,
                    proof,
                    dispatch.fee_schedule,
                )?;
                CandidateActionOutcome::SponsoredEnrollment(outcome, fee)
            }
        };
        if candidate.accounts.get(payer).map(|account| account.nonce) != Some(nonce_after) {
            return Err("protected execution did not consume exactly one selected nonce".into());
        }
        Ok(outcome)
    }
}

struct ProtectedReadiness<'a, F> {
    namespace: &'a EtdagDigest,
    verify_publication: F,
}

impl<F> ProcessingReadinessVerifier for ProtectedReadiness<'_, F>
where
    F: Fn(&ProcessingReadyRecord) -> Result<(), String>,
{
    fn first_unconsumed_position(
        &self,
        record: &ProcessingReadyRecord,
        parent: &WorldState,
    ) -> Result<Option<u32>, String> {
        let group = processing_group_state(parent, self.namespace, record.item.group_number)
            .map_err(debug)?;
        Ok(Some(group.next_position))
    }

    fn verify_publication(
        &self,
        record: &ProcessingReadyRecord,
        _: &WorldState,
    ) -> Result<(), String> {
        (self.verify_publication)(record)
    }

    fn identity_is_current(
        &self,
        record: &ProcessingReadyRecord,
        parent: &WorldState,
    ) -> Result<bool, String> {
        Ok(parent
            .accounts
            .get(&record.sender_wallet)
            .is_some_and(|account| {
                account.code_hash.is_none() && account.nonce <= record.sender_nonce
            }))
    }
}

/// Derived by the replay caller from the independently authenticated lineage
/// and candidate slot. It is never populated from the proposal being checked.
#[derive(Clone, Copy)]
pub(super) struct ProtectedCandidateContext<'a> {
    pub(super) parent_block_id: &'a str,
    pub(super) namespace: &'a EtdagDigest,
    pub(super) parameters: &'a EtdagParameters,
    pub(super) slot: CandidateSlot<'a>,
}

impl ProtectedCandidateContext<'_> {
    fn scope(&self, parent: &BudgetedWorld) -> Result<EtdagDigest, String> {
        let finalized = self.slot.finalized_parent;
        let inclusion = self.slot.inclusion;
        if !synergy_posy::is_hash(self.parent_block_id)
            || inclusion.height <= finalized.position.height
            || inclusion.consensus_time < finalized.position.consensus_time
        {
            return Err("protected candidate has invalid parent or slot coordinates".into());
        }
        let _scratch = parent.budget().reserve(8192).map_err(debug)?;
        let parent_world_root = state_root(parent.as_ref()).map_err(debug)?;
        EtdagDigest::from_canonical(
            "SYNERGY_POSY_PW13_ENGINEERING_SCOPE_V1",
            &(
                finalized.registry.network,
                self.parent_block_id,
                parent_world_root,
                self.namespace,
                self.parameters,
                inclusion.height,
                inclusion.consensus_time,
                finalized.position.height,
                finalized.position.consensus_time,
                &finalized.processing_finality_root,
            ),
        )
        .map_err(debug)
    }
}

/// Apply the selection and lifecycle from the single canonical parent. The
/// returned World contains both the protected settlement and READY consumption.
/// If anything fails, the private candidate is dropped along with all effects.
#[cfg(test)]
pub(super) fn execute_protected_candidate<'a>(
    parent: &BudgetedWorld,
    context: ProtectedCandidateContext<'a>,
    prepared: &[&'a PreparedProtectedAction<'a>],
    publications: &[&'a PreparedProtectedAction<'a>],
) -> Result<(BudgetedExecutionCandidate, Vec<CandidateActionOutcome>), String> {
    if prepared.len() > MAX_ACTIONS || publications.len() > MAX_ACTIONS {
        return Err("protected candidate exceeds action capacity".into());
    }
    let budget = parent.budget();
    let _index = budget
        .reserve((prepared.len() + publications.len()) * 256 + 16 * 1024)
        .map_err(debug)?;
    let mut actions = BTreeMap::new();
    for action in prepared {
        if action.dispatch.admission.parameters != *context.parameters {
            return Err(
                "protected processing limits differ from the authenticated admission".into(),
            );
        }
        if actions
            .insert(&action.record.item.envelope_id, *action)
            .is_some()
        {
            return Err("protected candidate has duplicate openings".into());
        }
    }
    let find = |record: &ProcessingReadyRecord| {
        actions
            .get(&record.item.envelope_id)
            .copied()
            .ok_or_else(|| "protected READY is missing its authenticated opening".to_owned())
    };
    // Every prepared action holds a bounded ready-record permit. Reserve the
    // same maximum for each temporary clone before allocating those clones.
    let _clones = budget
        .reserve(publications.len() * READY_RECORD_RESERVATION)
        .map_err(debug)?;
    let publication_records = publications
        .iter()
        .map(|item| item.record.clone())
        .collect::<Vec<_>>();
    assemble_protected_candidate(
        parent,
        context,
        &publication_records,
        |record| find(record)?.verify_publication(parent, record, context.slot),
        |record, candidate| {
            let action = find(record)?;
            action.verify_selection(parent, record)?;
            action.execute(candidate, context.slot)
        },
    )
}

const MAX_ACTIONS: usize = 4096;

fn assemble_protected_candidate(
    parent: &BudgetedWorld,
    context: ProtectedCandidateContext<'_>,
    publications: &[ProcessingReadyRecord],
    verify_publication: impl Fn(&ProcessingReadyRecord) -> Result<(), String>,
    execute: impl Fn(
        &ProcessingReadyRecord,
        &mut BudgetedWorld,
    ) -> Result<CandidateActionOutcome, String>,
) -> Result<(BudgetedExecutionCandidate, Vec<CandidateActionOutcome>), String> {
    let ProtectedCandidateContext {
        namespace,
        parameters,
        slot,
        ..
    } = context;
    parameters.validate().map_err(debug)?;
    if publications.len() > MAX_ACTIONS {
        return Err("protected candidate exceeds action capacity".into());
    }
    let scope = context.scope(parent)?;
    let budget = parent.budget();
    let readiness = ProtectedReadiness {
        namespace,
        verify_publication,
    };
    let registry =
        ParentProcessingRegistry::read(parent.as_ref(), namespace, budget).map_err(debug)?;
    let selected = registry
        .select(
            &readiness,
            parameters.max_protected_gas,
            parameters.max_protected_bytes,
        )
        .map_err(debug)?;
    let lifecycle = selected
        .prepare_lifecycle(publications, None, &readiness)
        .map_err(debug)?;
    let mut candidate = BudgetedWorld::try_clone_world(parent.as_ref(), budget).map_err(debug)?;
    let mut outcomes = Vec::with_capacity(selected.selection().item_indices.len());
    for record in selected.records() {
        outcomes.push(execute(record, &mut candidate)?);
    }
    let candidate = lifecycle
        .assemble_pw13_engineering(
            &selected,
            slot.inclusion.height,
            context.parent_block_id,
            &scope,
            candidate,
        )
        .map_err(debug)?;
    Ok((candidate, outcomes))
}

/// The proposal supplies publication records. Selection comes only from the
/// parent, and all openings come from the exact immutable journal entries.
/// This dispatcher only assembles the isolated PW13 engineering profile.
pub(super) fn execute_protected_journal_candidate(
    parent: &BudgetedWorld,
    context: ProtectedCandidateContext<'_>,
    publications: &[ProcessingReadyRecord],
    pending: &PendingProcessingStore<CandidateAdmission>,
    recovery: &ProtectedJournalRecovery<'_>,
) -> Result<(BudgetedExecutionCandidate, Vec<CandidateActionOutcome>), String> {
    assemble_protected_candidate(
        parent,
        context,
        publications,
        |record| {
            recovery.with_action(pending, record, parent, context.parameters, |action| {
                action.verify_publication(parent, record, context.slot)
            })
        },
        |record, candidate| {
            recovery.with_action(pending, record, parent, context.parameters, |action| {
                action.verify_selection(parent, record)?;
                action.execute(candidate, context.slot)
            })
        },
    )
}

pub(super) fn replay_protected_journal_candidate(
    received_bytes: &[u8],
    parent: &BudgetedWorld,
    context: ProtectedCandidateContext<'_>,
    publications: &[ProcessingReadyRecord],
    pending: &PendingProcessingStore<CandidateAdmission>,
    recovery: &ProtectedJournalRecovery<'_>,
) -> Result<BudgetedExecutionCandidate, String> {
    let received = decode_budgeted_pw13_engineering_candidate(received_bytes, parent.budget())
        .map_err(debug)?;
    let (regenerated, _) =
        execute_protected_journal_candidate(parent, context, publications, pending, recovery)?;
    verify_replayed_candidate(received, regenerated)
}

/// Replay using original authorization/opening evidence and the selected
/// parent. A well-formed claimed World or block identifier is insufficient.
#[cfg(test)]
pub(super) fn replay_protected_candidate<'a>(
    received_bytes: &[u8],
    parent: &BudgetedWorld,
    context: ProtectedCandidateContext<'a>,
    prepared: &[&'a PreparedProtectedAction<'a>],
    publications: &[&'a PreparedProtectedAction<'a>],
) -> Result<BudgetedExecutionCandidate, String> {
    let received = decode_budgeted_pw13_engineering_candidate(received_bytes, parent.budget())
        .map_err(debug)?;
    let (regenerated, _) = execute_protected_candidate(parent, context, prepared, publications)?;
    verify_replayed_candidate(received, regenerated)
}

fn verify_replayed_candidate(
    received: BudgetedExecutionCandidate,
    regenerated: BudgetedExecutionCandidate,
) -> Result<BudgetedExecutionCandidate, String> {
    if regenerated != received {
        return Err("protected execution candidate disagrees with canonical parent replay".into());
    }
    Ok(regenerated)
}
