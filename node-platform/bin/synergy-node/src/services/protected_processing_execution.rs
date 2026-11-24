//! Engineering dispatch for the original protected ETDAG admission. The
//! approved ordinary scheduler and public admission registry cannot select it.
use super::{
    debug,
    processing_admission::{CandidateAdmission, CandidateAuthorization},
    processing_disposition::{self, Disposition, DispositionSlot},
    sponsor_settlement::SponsoredOutcome,
    sponsored_admission::VerifiedSponsoredAdmission,
    transfer_admission::VerifiedTransferAdmission,
    fee_free_enrollment::VerifiedFeeFreeEnrollmentAdmission,
    fee_free_synid::VerifiedFeeFreeSynIdAdmission,
    AccountIdentifier, CandidateProtectedAccounts, CandidateTransferExecution, ChainId,
    FinalizedSnapshot, Position, TransferCandidateContent,
};
use crate::services::processing_pipeline::{
    AuthenticatedProcessingOpening, NativeProcessingContext, NativeProcessingProgressRecovery,
    NativeProcessingRecovery, ProcessingCompletionEvidence, ProcessingProgressEvidence,
    Pw13FinalizedSource, RevealedProcessingPayload,
};
use crate::services::authority::VerifiedAuthority;
use crate::services::processing_store::{
    PendingProcessingIdentity, PendingProcessingStore, ProcessingAdmissionAuthenticator,
    ProcessingStoreError,
};
use std::collections::BTreeMap;
use std::sync::Arc;
use synergy_address_engine::apqe::provider::{variants::Mldsa87, PqProvider};
use synergy_aegis::ApqeIdentityVerifier;
use synergy_etdag::{
    admission::{Pw13SponsoredResources, Pw13TransferResources},
    execution::processing_admission_authorization_root,
    EtdagDigest, EtdagParameters, ProcessingContext, ProcessingEnvelope,
};
use synergy_execution::{
    decode_budgeted_pw13_engineering_candidate, processing_group_state, verify_processing_payload,
    BlockExecutionError, BudgetedExecutionCandidate, FeeSchedule, ParentProcessingRegistry,
    ProcessingNativeWalletActions, ProcessingReadinessVerifier,
    ProcessingReadyRecord,
};
use synergy_genesis::authority::ProtectedWalletDispatchPolicy;

#[path = "protected_processing_native.rs"]
pub(in crate::services) mod native;
#[path = "protected_processing_retirement.rs"]
pub(in crate::services) mod retirement;
use synergy_state::{
    state_root,
    world_resources::{BudgetedWorld, WorldResourceBudget, WorldResourcePermit},
    StateDiff, WorldState,
};

enum ActionAuthorization {
    Transfer(VerifiedTransferAdmission),
    SponsoredEnrollment(VerifiedSponsoredAdmission),
    FeeFreeEnrollment(VerifiedFeeFreeEnrollmentAdmission),
    FeeFreeSynId(VerifiedFeeFreeSynIdAdmission),
}

struct IntentTerms<'a> {
    valid_until_finalized_height: u64,
    digest: &'a [u8],
    policy: Option<&'a Pw13TransferResources>,
    fee_free: bool,
}

impl<'a> From<&'a Pw13TransferResources> for IntentTerms<'a> {
    fn from(resources: &'a Pw13TransferResources) -> Self {
        Self {
            valid_until_finalized_height: resources.valid_until_finalized_height,
            digest: &resources.native_intent_digest,
            policy: Some(resources), fee_free: false,
        }
    }
}

impl<'a> From<&'a Pw13SponsoredResources> for IntentTerms<'a> {
    fn from(resources: &'a Pw13SponsoredResources) -> Self {
        Self {
            valid_until_finalized_height: resources.valid_until_finalized_height,
            digest: &resources.sponsor_intent_digest,
            policy: None, fee_free: false,
        }
    }
}

impl<'a> From<&'a synergy_etdag::admission::Pw13FeeFreeEnrollmentResources> for IntentTerms<'a> {
 fn from(r:&'a synergy_etdag::admission::Pw13FeeFreeEnrollmentResources)->Self {Self{valid_until_finalized_height:r.valid_until_finalized_height,digest:&r.enrollment_intent_digest,policy:None,fee_free:true}}
}

impl<'a> From<&'a synergy_etdag::admission::Pw13FeeFreeSynIdResources> for IntentTerms<'a> {fn from(r:&'a synergy_etdag::admission::Pw13FeeFreeSynIdResources)->Self{Self{valid_until_finalized_height:r.valid_until_finalized_height,digest:&r.intent_digest,policy:None,fee_free:true}}}
impl IntentTerms<'_> {
    fn disposition(
        &self,
        record: &ProcessingReadyRecord,
        finalized: &FinalizedSnapshot<'_>,
    ) -> Result<Option<Disposition>, String> {
        if self.fee_free { return Ok(None); }
        if finalized.position.height > self.valid_until_finalized_height {
            return Ok(Some(Disposition::Expired));
        }
        let ledger = finalized
            .world
            .accounts
            .get(&record.sender_wallet)
            .filter(|account| account.code_hash.is_none())
            .ok_or("protected READY payer has no finalized account")?;
        if ledger.nonce > record.sender_nonce {
            return Ok(Some(Disposition::NonceSuperseded {
                finalized_nonce: ledger.nonce,
            }));
        }
        if let Some(signed) = self.policy {
            let registry = finalized.registry;
            let current = registry.read_policy(
                finalized.world,
                AccountIdentifier::from_bytes(signed.account),
            )?;
            if current.registered_height > finalized.position.height
                || current.native_recovery_since.is_some_and(|height| height > finalized.position.height)
                || current.policy_epoch < signed.policy_epoch
                || (current.policy_epoch == signed.policy_epoch
                    && current.policy_hash != signed.policy_hash)
            {
                return Err("protected READY policy disagrees with finalized history".into());
            }
            if current.policy_epoch > signed.policy_epoch {
                registry.current_policy(&current)?;
                return Ok(Some(Disposition::PolicySuperseded {
                    signed_policy_epoch: signed.policy_epoch,
                    finalized_policy_epoch: current.policy_epoch,
                }));
            }
        }
        Ok(None)
    }
}

pub(in crate::services) struct AuthorizedCandidateAdmission {
    authorization_root: EtdagDigest,
    parameters: EtdagParameters,
    action: ActionAuthorization,
}

impl AuthorizedCandidateAdmission {
    fn terms(&self) -> IntentTerms<'_> {
        match &self.action {
            ActionAuthorization::Transfer(proof) => proof.resources().into(),
            ActionAuthorization::SponsoredEnrollment(proof) => proof.resources().into(),
            ActionAuthorization::FeeFreeEnrollment(proof) => proof.resources().into(),
            ActionAuthorization::FeeFreeSynId(proof)=>proof.resources().into(),
        }
    }
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
        let action = match &admission.authorization {
            CandidateAuthorization::FeeFreeSynId(proof)=>ActionAuthorization::FeeFreeSynId(self.verify_fee_free_synid_admission(terms.provider,terms.source,context,&admission.envelope,proof,terms.parameters,terms.metered_gas)?),
            CandidateAuthorization::FeeFreeEnrollment(proof)=>ActionAuthorization::FeeFreeEnrollment(self.verify_fee_free_enrollment_admission(terms.provider,terms.source,context,&admission.envelope,proof,terms.parameters,terms.metered_gas)?),
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
                ActionAuthorization::Transfer(verified)
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
                ActionAuthorization::SponsoredEnrollment(verified)
            }
        };
        let authorization_root =
            processing_admission_authorization_root(admission).map_err(debug)?;
        Ok(AuthorizedCandidateAdmission {
            authorization_root,
            parameters: terms.parameters.clone(),
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
    pub(super) metering: ProtectedMetering<'a>,
}

#[derive(Clone, Copy)]
pub(super) enum ProtectedMetering<'a> {
    Governed(&'a ProtectedWalletDispatchPolicy),
    #[cfg(test)]
    Fixture(u64),
}

impl ProtectedMetering<'_> {
    fn for_admission(self, admission: &CandidateAdmission) -> Result<u64, String> {
        use crate::services::protected_action_wire::{ENROLL_COMMIT, ENROLL_REVEAL};
        match self {
            Self::Governed(policy) => match &admission.authorization {
                CandidateAuthorization::Transfer(_) | CandidateAuthorization::FeeFreeSynId(_)=> Ok(policy.transfer_gas),
                CandidateAuthorization::FeeFreeEnrollment(proof)=>match proof.resources.action {ENROLL_COMMIT=>Ok(policy.enroll_commit_gas),ENROLL_REVEAL=>Ok(policy.enroll_reveal_gas),_=>Err("invalid fee-free action".into())},
                CandidateAuthorization::SponsoredEnrollment(proof) => match proof.resources.action {
                    ENROLL_COMMIT => Ok(policy.enroll_commit_gas),
                    ENROLL_REVEAL => Ok(policy.enroll_reveal_gas),
                    _ => Err("wallet dispatch has no governed metering for the requested action".into()),
                },
            },
            #[cfg(test)]
            Self::Fixture(gas) => Ok(gas),
        }
    }
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

/// Retained only after the ETDAG owner persists the original completion.
/// The original finalized World is already charged by the native state owner.
pub(in crate::services) struct NativeProtectedCompletion {
    pub(in crate::services) record: ProcessingReadyRecord,
    context: ProcessingContext,
    envelope: ProcessingEnvelope,
    authorization: AuthorizedCandidateAdmission,
    opening: AuthenticatedProcessingOpening,
    original_world: Arc<BudgetedWorld>,
    original_position: Position,
    original_finality_root: EtdagDigest,
    policy: ProtectedWalletDispatchPolicy,
    _permit: WorldResourcePermit,
}

impl NativeProtectedCompletion {
    pub(in crate::services) fn retain(
        source: &NativeProcessingContext<'_>,
        original: &CandidateAdmission,
        reveal_parent: &BudgetedWorld,
        mut opening: AuthenticatedProcessingOpening,
        budget: &Arc<WorldResourceBudget>,
    ) -> Result<Self, String> {
        let native = source.pw13_finalized_source()?;
        with_native_protected_intake(source, |intake| {
            let authorization = intake.authorize(original)?;
            let envelope = &original.envelope;
            let permit = budget.reserve(
                crate::services::processing_pipeline::encoded_len(envelope)?.checked_mul(2)
                    .and_then(|bytes| bytes.checked_add(128 * 1024))
                    .ok_or("protected completion capacity overflow")?
            ).map_err(debug)?;
            let record = opening.payload(envelope, native.context)?.ready_record(reveal_parent)?;
            if record.authorization_root != authorization.authorization_root {
                return Err("retained Wallet completion changed its original authorization".into());
            }
            opening.retain_plaintext()?;
            Ok(Self {
                record,
                context: native.context.clone(),
                envelope: envelope.clone(),
                authorization,
                opening,
                original_world: source.retain_finalized_world()?,
                original_position: intake.snapshot.position,
                original_finality_root: intake.snapshot.processing_finality_root.clone(),
                policy: native.authority.wallet_dispatch_policy()
                    .ok_or("original Wallet policy absent")?.clone(),
                _permit: permit,
            })
        })
    }

    fn with_action<T>(
        &self,
        parent: &BudgetedWorld,
        registry: &CandidateProtectedAccounts<'_>,
        terms: ProtectedRecoveryTerms<'_>,
        action: impl FnOnce(PreparedProtectedAction<'_>) -> Result<T, String>,
    ) -> Result<T, String> {
        if !matches!(terms.metering, ProtectedMetering::Governed(policy) if policy == &self.policy) {
            return Err("retained Wallet completion has a different activated policy".into());
        }
        let source = FinalizedSnapshot {
            registry,
            world: self.original_world.as_ref(),
            position: self.original_position,
            processing_finality_root: self.original_finality_root.clone(),
        };
        let original = PreparedProtectedAction::from_opening(
            CandidateDispatch {
                source: &source,
                provider: terms.provider,
                sponsor_verifier: terms.sponsor_verifier,
                fee_schedule: terms.fee_schedule,
                admission: &self.authorization,
            },
            self.opening.payload(&self.envelope, &self.context)?,
            parent,
        )?;
        action(original)
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

/// A sponsored admission can be persisted as soon as the original source is
/// authenticated. No reveal parent or decrypted content exists at intake.
pub(in crate::services) struct ProtectedIntake<'a> {
    registry: &'a CandidateProtectedAccounts<'a>,
    snapshot: FinalizedSnapshot<'a>,
    context: &'a ProcessingContext,
    context_root: EtdagDigest,
    parameters: EtdagParameters,
    terms: ProtectedRecoveryTerms<'a>,
}

impl<'a> ProtectedIntake<'a> {
    pub(super) fn new(
        registry: &'a CandidateProtectedAccounts<'a>,
        source: &'a NativeProcessingContext<'a>,
        terms: ProtectedRecoveryTerms<'a>,
    ) -> Result<Self, String> {
        let verified = source.pw13_finalized_source()?;
        let snapshot = registry.native_finalized_snapshot(&verified)?;
        match terms.metering {
            ProtectedMetering::Governed(expected) => {
                native::require_dispatch_policy(verified.authority, verified.genesis_hash, verified.record, expected)?;
                let activation = registry.activated_enrollment(expected)?;
                activation.require_activation(snapshot.context()).map_err(debug)?;
                activation.require_proof_provider(terms.provider).map_err(debug)?;
                if terms.fee_schedule.collector != expected.fee_collector
                    || terms.fee_schedule.base_fee_per_gas_nwei != expected.base_fee_per_gas_nwei
                {
                    return Err("protected intake fees differ from signed action policy".into());
                }
            }
            #[cfg(test)]
            ProtectedMetering::Fixture(_) => {}
        }
        Ok(Self {
            registry,
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

    /// Admission-stage identity for the original bytes, returned only after
    /// the journal commits. The engineering path does not confer finality.
    pub(super) fn admit_sponsored_enrollment(
        &self,
        pending: &mut PendingProcessingStore<CandidateAdmission>,
        original: &[u8],
    ) -> Result<PendingProcessingIdentity, ProcessingStoreError> {
        if self.context.profile_id != synergy_etdag::admission::PW13_SPONSOR_CANDIDATE_PROFILE_ID {
            return Err(ProcessingStoreError::Verification(
                "sponsored enrollment requires the authenticated sponsor profile".into(),
            ));
        }
        pending.admit(
            self.context,
            self.snapshot.position.consensus_time,
            original,
            self,
        )
    }

    pub(in crate::services) fn authorize(
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
                metered_gas: self.terms.metering.for_admission(admission)?,
            },
        )
    }
}

pub(in crate::services) fn with_native_protected_intake<T>(
    source: &NativeProcessingContext<'_>,
    action: impl FnOnce(&ProtectedIntake<'_>) -> Result<T, String>,
) -> Result<T, String> {
    with_native_wallet_registry(source, |registry, terms| {
        let intake = ProtectedIntake::new(registry, source, terms)?;
        action(&intake)
    })
}

fn with_native_wallet_registry<T>(
    source: &NativeProcessingContext<'_>,
    action: impl FnOnce(&CandidateProtectedAccounts<'_>, ProtectedRecoveryTerms<'_>) -> Result<T, String>,
) -> Result<T, String> {
    let finalized = source.verified_finalized_source()?;
    let release = finalized.authority.native_wallet_release()?;
    let provider = release.proof_provider.lock().map_err(|_| "managed Wallet proof provider poisoned")?;
    let registry = CandidateProtectedAccounts::from_verified_release(
        &release.verified, &finalized, &release.wire, &provider,
    )?;
    let sponsor = finalized.authority.apqe_identity_verifier();
    action(
        &registry,
        ProtectedRecoveryTerms {
            provider: &provider,
            sponsor_verifier: sponsor.as_ref(),
            fee_schedule: &release.fees,
            metering: ProtectedMetering::Governed(release.verified.policy()),
        },
    )
}

impl ProcessingAdmissionAuthenticator<CandidateAdmission> for ProtectedIntake<'_> {
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
}

/// Authenticates the unchanged pending journal and the later reveal proof.
pub(super) struct ProtectedAdmissionRecovery<'a> {
    intake: ProtectedIntake<'a>,
    recovery: NativeProcessingRecovery<'a>,
}

impl<'a> ProtectedAdmissionRecovery<'a> {
    pub(super) fn new(
        registry: &'a CandidateProtectedAccounts<'a>,
        recovery: NativeProcessingRecovery<'a>,
        terms: ProtectedRecoveryTerms<'a>,
    ) -> Result<Self, String> {
        Ok(Self {
            intake: ProtectedIntake::new(registry, recovery.source, terms)?,
            recovery,
        })
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
                    self.intake.authorize(original)
                })?;
        Ok(RecoveredProtectedAction {
            opening,
            admission: authorized,
            source: FinalizedSnapshot {
                registry: self.intake.registry,
                world: self.intake.snapshot.world,
                position: self.intake.snapshot.position,
                processing_finality_root: self.intake.snapshot.processing_finality_root.clone(),
            },
            context: self.intake.context,
            envelope: &admission.envelope,
            terms: self.intake.terms,
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
    fn disposition(
        &self,
        pending: &PendingProcessingStore<CandidateAdmission>,
        record: &ProcessingReadyRecord,
        finalized: &FinalizedSnapshot<'_>,
    ) -> Result<Option<Disposition>, String> {
        pending
            .with_original(
                &record.item.envelope_id,
                self,
                |_, _, admission, workspace| {
                    let _policy =
                        workspace.reserve(super::MAX_STORED_POLICY_BYTES * 4 + 16 * 1024)?;
                    if admission.envelope.aad.processing_context_root
                        != record.processing_context_root
                        || admission.envelope.aad.sender_id != record.sender_wallet
                        || admission.envelope.aad.nonce_slot != record.sender_nonce
                        || processing_admission_authorization_root(admission)
                            .map_err(|error| ProcessingStoreError::Verification(debug(error)))?
                            != record.authorization_root
                    {
                        return Err(ProcessingStoreError::Verification(
                            "protected READY differs from the original authenticated admission"
                                .into(),
                        ));
                    }
                    let terms: IntentTerms<'_> = match &admission.authorization {
                        CandidateAuthorization::Transfer(proof) => (&proof.resources).into(),
                        CandidateAuthorization::FeeFreeSynId(proof)=>(&proof.resources).into(),
                        CandidateAuthorization::FeeFreeEnrollment(proof)=>(&proof.resources).into(),
                        CandidateAuthorization::SponsoredEnrollment(proof) => {
                            (&proof.resources).into()
                        }
                    };
                    terms
                        .disposition(record, finalized)
                        .map_err(ProcessingStoreError::Verification)
                },
            )
            .map_err(debug)
    }

    fn completion_source(
        &self,
        admission: &CandidateAdmission,
        evidence: &ProcessingCompletionEvidence,
    ) -> Result<&ProtectedAdmissionRecovery<'_>, String> {
        self.sources
            .iter()
            .find(|source| {
                source.intake.context_root == admission.envelope.aad.processing_context_root
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
                        if source.intake.context != context || source.intake.parameters != *parameters {
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
            .find(|source| source.intake.context == context)
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

    fn verify_progress(
        &self,
        context: &ProcessingContext,
        admission: &CandidateAdmission,
        evidence: &ProcessingProgressEvidence,
        budget: &Arc<WorldResourceBudget>,
    ) -> Result<(), String> {
        let source = self.sources.iter().find(|source| {
            source.intake.context == context
                && evidence.reveal_validation.as_ref().is_none_or(|validation| {
                    validation.candidate.block_id == source.recovery.reveal_parent.block_id
                })
                && source.recovery.dag_parents.iter().map(|parent| parent.vertex_id())
                    .eq(evidence.parents.iter())
        }).ok_or("protected progress lacks its original authenticated source/parent")?;
        NativeProcessingProgressRecovery {
            source: source.recovery.source,
            reveal_parent: evidence.reveal_validation.as_ref().map(|_| source.recovery.reveal_parent),
            dag_parents: source.recovery.dag_parents,
        }.verify_authenticated_progress(context, admission, evidence, budget, |original| {
            source.intake.authorize(original).map(drop)
        })
    }
}

impl ProcessingAdmissionAuthenticator<CandidateAdmission> for ProtectedAdmissionRecovery<'_> {
    fn verify(
        &self,
        context: &ProcessingContext,
        timestamp: u64,
        admission: &CandidateAdmission,
    ) -> Result<(), String> {
        self.intake.verify(context, timestamp, admission)
    }

    fn verify_completion(
        &self,
        context: &ProcessingContext,
        admission: &CandidateAdmission,
        evidence: &ProcessingCompletionEvidence,
        budget: &Arc<WorldResourceBudget>,
    ) -> Result<(), String> {
        if context != self.intake.context {
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
    Disposition(Disposition),
    FeeFreeEnrollment(synergy_etdag::admission::FeeFreeEnrollmentOutcome,String),
    FeeFreeSynId(synergy_etdag::admission::FeeFreeSynIdOutcome,String),
}

const READY_RECORD_RESERVATION: usize = 64 * 1024;

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
        self.validate_slot(slot)?;
        match self
            .dispatch
            .admission
            .terms()
            .disposition(record, slot.finalized_parent)?
        {
            Some(Disposition::Expired) => {
                return Err("protected authorization expired at the finalized predecessor".into());
            }
            Some(_) => return Err("superseded protected authorization cannot publish READY".into()),
            None => {}
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

    fn validate_slot(&self, slot: CandidateSlot<'_>) -> Result<(), String> {
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
        Ok(())
    }

    fn execute_selected(
        &self,
        candidate: &mut BudgetedWorld,
        slot: CandidateSlot<'_>,
        disposition: Option<Disposition>,
    ) -> Result<CandidateActionOutcome, String> {
        self.validate_slot(slot)?;
        let terms = self.dispatch.admission.terms();
        let _policy = candidate
            .budget()
            .reserve(super::MAX_STORED_POLICY_BYTES * 4 + 16 * 1024)
            .map_err(debug)?;
        if terms.disposition(&self.record, slot.finalized_parent)? != disposition {
            return Err(
                "protected READY disposition differs from exact authenticated replay".into(),
            );
        }
        let (outcome, receipt_key) = if let Some(disposition) = disposition {
            let change = processing_disposition::prepare(
                candidate.as_ref(),
                &self.record,
                self.opened.envelope().aad.authorization_height,
                terms.digest,
                terms.valid_until_finalized_height,
                DispositionSlot {
                    source_finalized_height: self.dispatch.source.position.height,
                    finalized: slot.finalized_parent,
                    inclusion: slot.inclusion,
                },
                disposition,
            )?;
            let key = change.key.clone();
            candidate
                .try_apply(&StateDiff {
                    protocol_changes: vec![change],
                    ..StateDiff::default()
                })
                .map_err(debug)?;
            (CandidateActionOutcome::Disposition(disposition), key)
        } else {
            let outcome = self.execute(candidate, slot)?;
            let key = match &outcome {
                CandidateActionOutcome::Transfer(transfer) => transfer.settlement_key.clone(),
                CandidateActionOutcome::FeeFreeEnrollment(_,key)|CandidateActionOutcome::FeeFreeSynId(_,key)=>key.clone(),
                CandidateActionOutcome::SponsoredEnrollment(..) => super::sponsor_settlement::receipt_key(
                    &self.record.sender_wallet,
                    self.record.sender_nonce,
                ),
                CandidateActionOutcome::Disposition(_) => unreachable!("handled above"),
            };
            (outcome, key)
        };
        retirement::record_outcome(candidate, slot.inclusion.height, &self.record, receipt_key)?;
        Ok(outcome)
    }

    fn execute(
        &self,
        candidate: &mut BudgetedWorld,
        slot: CandidateSlot<'_>,
    ) -> Result<CandidateActionOutcome, String> {
        let inclusion = slot.inclusion;
        verify_processing_payload(&self.record, self.opened.plaintext(), candidate.budget())
            .map_err(debug)?;
        if let ActionAuthorization::FeeFreeEnrollment(proof)=&self.dispatch.admission.action {
            let (outcome,key)=self.dispatch.source.registry.execute_opened_fee_free_enrollment(self.dispatch.provider,self.dispatch.source,slot.finalized_parent,candidate,inclusion,self.opened,proof)?;
            return Ok(CandidateActionOutcome::FeeFreeEnrollment(outcome,key));
        }
        if let ActionAuthorization::FeeFreeSynId(proof)=&self.dispatch.admission.action {let (outcome,key)=self.dispatch.source.registry.execute_opened_fee_free_synid(self.dispatch.source,slot.finalized_parent,candidate,inclusion,self.opened,proof)?;return Ok(CandidateActionOutcome::FeeFreeSynId(outcome,key));}
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
            ActionAuthorization::FeeFreeEnrollment(_)|ActionAuthorization::FeeFreeSynId(_)=>unreachable!("handled before financial nonce lookup"),
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
    dispositions: BTreeMap<&'a EtdagDigest, Disposition>,
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
        if record.sender_wallet.starts_with("enroll:") || record.sender_wallet.starts_with("synid:") {return Ok(record.sender_nonce<=1);}
        Ok(parent
            .accounts
            .get(&record.sender_wallet)
            .is_some_and(|account| {
                account.code_hash.is_none() && account.nonce <= record.sender_nonce
            }))
    }

    fn retires_without_nonce(&self, record: &ProcessingReadyRecord) -> bool {
        (record.sender_wallet.starts_with("enroll:") || record.sender_wallet.starts_with("synid:")) || self.dispositions.contains_key(&record.item.envelope_id)
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
        |record| {
            find(record)?
                .dispatch
                .admission
                .terms()
                .disposition(record, context.slot.finalized_parent)
        },
        |record, disposition, candidate| {
            let action = find(record)?;
            action.verify_selection(parent, record)?;
            action.execute_selected(candidate, context.slot, disposition)
        },
    )
}

const MAX_ACTIONS: usize = 4096;

fn assemble_protected_candidate(
    parent: &BudgetedWorld,
    context: ProtectedCandidateContext<'_>,
    publications: &[ProcessingReadyRecord],
    verify_publication: impl Fn(&ProcessingReadyRecord) -> Result<(), String>,
    disposition: impl Fn(&ProcessingReadyRecord) -> Result<Option<Disposition>, String>,
    execute: impl Fn(
        &ProcessingReadyRecord,
        Option<Disposition>,
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
    let registry =
        ParentProcessingRegistry::read(parent.as_ref(), namespace, budget).map_err(debug)?;
    let _dispositions = budget
        .reserve(registry.records().len() * 256 + 16 * 1024)
        .map_err(debug)?;
    let mut dispositions = BTreeMap::new();
    for record in registry.records() {
        if let Some(result) = disposition(record)? {
            dispositions.insert(&record.item.envelope_id, result);
        }
    }
    let readiness = ProtectedReadiness {
        namespace,
        verify_publication,
        dispositions,
    };
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
        outcomes.push(execute(
            record,
            readiness
                .dispositions
                .get(&record.item.envelope_id)
                .copied(),
            &mut candidate,
        )?);
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
        |record| recovery.disposition(pending, record, context.slot.finalized_parent),
        |record, disposition, candidate| {
            recovery.with_action(pending, record, parent, context.parameters, |action| {
                action.verify_selection(parent, record)?;
                action.execute_selected(candidate, context.slot, disposition)
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
