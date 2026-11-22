//! Engineering dispatch for the original protected ETDAG admission. The
//! approved ordinary scheduler and public admission registry cannot select it.
use super::{
    debug,
    processing_admission::{CandidateAdmission, CandidateAuthorization},
    sponsor_settlement::SponsoredOutcome,
    sponsored_admission::VerifiedSponsoredAdmission,
    transfer_admission::VerifiedTransferAdmission,
    CandidateProtectedAccounts, CandidateTransferExecution, FinalizedSnapshot, Position,
    TransferCandidateContent,
};
use crate::services::processing_pipeline::RevealedProcessingPayload;
use std::collections::BTreeMap;
use synergy_address_engine::apqe::provider::{variants::Mldsa87, PqProvider};
use synergy_aegis::ApqeIdentityVerifier;
use synergy_etdag::{
    execution::processing_admission_authorization_root, EtdagDigest, EtdagParameters,
    ProcessingContext,
};
use synergy_execution::{
    processing_group_state, verify_processing_payload, FeeSchedule, ParentProcessingRegistry,
    ProcessingReadinessVerifier, ProcessingReadyRecord,
};
use synergy_state::{
    world_resources::{BudgetedWorld, WorldResourcePermit},
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
    published_from: &'a BudgetedWorld,
    publication_slot: CandidateSlot<'a>,
    _permit: WorldResourcePermit,
}

impl<'a> PreparedProtectedAction<'a> {
    pub(super) fn prepare(
        dispatch: CandidateDispatch<'a>,
        opened: RevealedProcessingPayload<'a>,
        parent: &'a BudgetedWorld,
        slot: CandidateSlot<'a>,
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
        let action = Self {
            dispatch,
            opened,
            record,
            published_from: parent,
            publication_slot: slot,
            _permit: permit,
        };
        // Refuse invalid decrypted content before publishing readiness. These
        // tentative ledger and receipt writes are never a publication effect.
        let mut trial =
            BudgetedWorld::try_clone_world(parent.as_ref(), parent.budget()).map_err(debug)?;
        action.execute(&mut trial, slot)?;
        Ok(action)
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

struct ProtectedReadiness<'a> {
    namespace: &'a EtdagDigest,
    slot: CandidateSlot<'a>,
    actions: BTreeMap<&'a EtdagDigest, &'a PreparedProtectedAction<'a>>,
}
impl ProtectedReadiness<'_> {
    fn action(
        &self,
        record: &ProcessingReadyRecord,
    ) -> Result<&PreparedProtectedAction<'_>, String> {
        let action = self
            .actions
            .get(&record.item.envelope_id)
            .ok_or("protected READY is missing its authenticated opening")?;
        if action.record != *record {
            return Err("protected READY differs from the authenticated opening".into());
        }
        Ok(action)
    }
}

impl ProcessingReadinessVerifier for ProtectedReadiness<'_> {
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
        parent: &WorldState,
    ) -> Result<(), String> {
        let action = self.action(record)?;
        if !std::ptr::eq(action.published_from.as_ref(), parent)
            || action.publication_slot.inclusion != self.slot.inclusion
            || !std::ptr::eq(
                action.publication_slot.finalized_parent,
                self.slot.finalized_parent,
            )
        {
            return Err("protected READY publication lost its validated parent or slot".into());
        }
        Ok(())
    }

    fn identity_is_current(
        &self,
        record: &ProcessingReadyRecord,
        parent: &WorldState,
    ) -> Result<bool, String> {
        self.action(record)?;
        Ok(parent
            .accounts
            .get(&record.sender_wallet)
            .is_some_and(|account| {
                account.code_hash.is_none() && account.nonce <= record.sender_nonce
            }))
    }
}

/// Apply the selection and lifecycle from the single canonical parent. The
/// returned World contains both the protected settlement and READY consumption.
/// If anything fails, the private candidate is dropped along with all effects.
pub(super) fn execute_protected_candidate<'a>(
    parent: &BudgetedWorld,
    namespace: &EtdagDigest,
    parameters: &EtdagParameters,
    slot: CandidateSlot<'a>,
    prepared: &[&'a PreparedProtectedAction<'a>],
    publications: &[&'a PreparedProtectedAction<'a>],
) -> Result<(BudgetedWorld, Vec<CandidateActionOutcome>), String> {
    const MAX_ACTIONS: usize = 4096;
    parameters.validate().map_err(debug)?;
    if prepared.len() > MAX_ACTIONS || publications.len() > MAX_ACTIONS {
        return Err("protected candidate exceeds action capacity".into());
    }
    let budget = parent.budget();
    let _index = budget
        .reserve((prepared.len() + publications.len()) * 256 + 16 * 1024)
        .map_err(debug)?;
    let mut readiness = ProtectedReadiness {
        namespace,
        slot,
        actions: BTreeMap::new(),
    };
    for action in prepared {
        if action.dispatch.admission.parameters != *parameters {
            return Err(
                "protected processing limits differ from the authenticated admission".into(),
            );
        }
        if readiness
            .actions
            .insert(&action.record.item.envelope_id, *action)
            .is_some()
        {
            return Err("protected candidate has duplicate openings".into());
        }
    }
    let publication_records = publications
        .iter()
        .map(|action| {
            readiness
                .action(&action.record)
                .map(|action| &action.record)
        })
        .collect::<Result<Vec<_>, _>>()?;
    // Every prepared action holds a bounded ready-record permit. Reserve the
    // same maximum for each temporary clone before allocating those clones.
    let _clones = budget
        .reserve(publication_records.len() * READY_RECORD_RESERVATION)
        .map_err(debug)?;
    let publication_records = publication_records.into_iter().cloned().collect::<Vec<_>>();
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
        .prepare_lifecycle(&publication_records, None, &readiness)
        .map_err(debug)?;
    let mut candidate = BudgetedWorld::try_clone_world(parent.as_ref(), budget).map_err(debug)?;
    let mut outcomes = Vec::with_capacity(selected.selection().item_indices.len());
    for record in selected.records() {
        let action = readiness.action(record)?;
        if action.opened.ready_record(parent)? != *record {
            return Err("selected protected READY lost its original reveal permission".into());
        }
        outcomes.push(action.execute(&mut candidate, slot)?);
    }
    Ok((lifecycle.apply(candidate).map_err(debug)?, outcomes))
}
