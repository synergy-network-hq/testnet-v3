//! Protected admission exercises the canonical durable processing store.
//! The engineering format is local to this candidate qualification.
use serde::{Deserialize, Serialize};
use synergy_etdag::{
    admission::{Pw13SponsoredAdmission, Pw13TransferAdmission},
    execution::ProcessingVertexAdmission,
    CertifiedEnvelopeRef, EtdagError, ProcessingContext, ProcessingEnvelope,
};
#[cfg(test)]
use synergy_etdag::EtdagDigest;
#[cfg(test)]
use synergy_state::world_resources::WorldResourceBudget;

#[cfg(test)]
use super::{
    debug,
    etdag_candidate::{CandidateOrderFixture, ClosedCandidateOrder},
    tests::Scratch,
    FinalizedSnapshot,
};
use crate::services::processing_store::{PendingProcessingIdentity, ProcessingAdmissionRecord};
#[cfg(test)]
use crate::services::processing_store::{
    PendingProcessingStore, ProcessingAdmissionAuthenticator, ProcessingStoreError,
    ProcessingStoreLimits, PROCESSING_INTAKE_HEADROOM_BYTES,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "authorization",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(super) enum CandidateAuthorization {
    Transfer(Pw13TransferAdmission),
    SponsoredEnrollment(Pw13SponsoredAdmission),
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CandidateAdmission {
    pub(super) envelope: ProcessingEnvelope,
    pub(super) authorization: CandidateAuthorization,
}

impl CandidateAdmission {
    pub(super) fn gas_limit(&self) -> u64 {
        match &self.authorization {
            CandidateAuthorization::Transfer(proof) => proof.resources.gas_limit,
            CandidateAuthorization::SponsoredEnrollment(proof) => proof.resources.gas_limit,
        }
    }
}

impl ProcessingVertexAdmission for CandidateAdmission {
    fn envelope(&self) -> &ProcessingEnvelope {
        &self.envelope
    }

    fn validate_vertex_resources(
        &self,
        reference: &CertifiedEnvelopeRef,
    ) -> Result<(), EtdagError> {
        self.envelope.validate()?;
        if self.gas_limit() != reference.gas_class_units {
            return Err(EtdagError::InvalidExecutionInput);
        }
        Ok(())
    }
}

impl ProcessingAdmissionRecord for CandidateAdmission {
    fn validate_context(&self, context: &ProcessingContext) -> Result<(), EtdagError> {
        match &self.authorization {
            CandidateAuthorization::Transfer(proof) => {
                proof.validate_context(&self.envelope, context)
            }
            CandidateAuthorization::SponsoredEnrollment(proof) => {
                proof.validate_context(&self.envelope, context)
            }
        }
    }

    fn identity(&self) -> PendingProcessingIdentity {
        PendingProcessingIdentity {
            envelope_id: self.envelope.envelope_id.clone(),
            context_root: self.envelope.aad.processing_context_root.clone(),
            sender_wallet: self.envelope.aad.sender_id.clone(),
            sender_nonce: self.envelope.aad.nonce_slot,
        }
    }
}

#[cfg(test)]
struct CandidateVerifier<'a, F> {
    context: &'a ProcessingContext,
    timestamp: u64,
    verify_proofs: F,
}

#[cfg(test)]
impl<F> ProcessingAdmissionAuthenticator<CandidateAdmission> for CandidateVerifier<'_, F>
where
    F: Fn(&ProcessingContext, &CandidateAdmission) -> Result<(), String>,
{
    fn verify(
        &self,
        context: &ProcessingContext,
        timestamp: u64,
        admission: &CandidateAdmission,
    ) -> Result<(), String> {
        if context != self.context || timestamp != self.timestamp {
            return Err(
                "protected admission requires its original authorized context and time".into(),
            );
        }
        (self.verify_proofs)(context, admission)
    }
}

/// Read back the exact encrypted request before permitting the native reveal
/// fixture to proceed. The proof callback verifies the recovered bytes against
/// the independently selected historical World and APQE provider.
#[cfg(test)]
pub(super) fn recover_before_reveal<T>(
    finalized: &FinalizedSnapshot<'_>,
    context: &ProcessingContext,
    original: CandidateAdmission,
    ordering: &CandidateOrderFixture<'_>,
    authorize: impl Fn(&ProcessingContext, &CandidateAdmission) -> Result<T, String>,
) -> Result<(T, Option<ClosedCandidateOrder>), String> {
    let root = Scratch::new();
    let namespace = EtdagDigest::from_canonical(
        "SYNERGY_PW13_ENGINEERING_PENDING_SCOPE_V1",
        &(&finalized.registry.network, &context.authority.network_id),
    )
    .map_err(debug)?;
    let limits = ProcessingStoreLimits {
        slots: 2,
        completion_bytes_per_item: 4 * 1024 * 1024,
    };
    let budget = WorldResourceBudget::new(PROCESSING_INTAKE_HEADROOM_BYTES + 128 * 1024 * 1024);
    let verify_proofs = |context: &ProcessingContext, request: &CandidateAdmission| {
        authorize(context, request).map(drop)
    };
    let timestamp = finalized.position.consensus_time;
    let verifier = CandidateVerifier {
        context,
        timestamp,
        verify_proofs,
    };
    let bytes = serde_json::to_vec(&original).map_err(debug)?;
    let mut store =
        PendingProcessingStore::open(&root.0, namespace.clone(), limits, &budget, &verifier)
            .map_err(debug)?;
    let identity = store
        .admit(context, timestamp, &bytes, &verifier)
        .map_err(debug)?;
    assert_eq!(identity, original.identity());
    drop(store);
    assert_eq!(budget.used(), 0);

    let altered_source = CandidateVerifier {
        timestamp: timestamp + 1,
        ..verifier
    };
    assert!(matches!(
        PendingProcessingStore::open(&root.0, namespace.clone(), limits, &budget, &altered_source),
        Err(ProcessingStoreError::Verification(_))
    ));
    assert_eq!(budget.used(), 0);
    let mut restored = PendingProcessingStore::open(&root.0, namespace, limits, &budget, &verifier)
        .map_err(debug)?;
    assert_eq!(restored.pending_identities().count(), 1);
    assert_eq!(
        restored
            .admit(context, timestamp, &bytes, &verifier)
            .map_err(debug)?,
        identity
    );
    let mut altered_bytes = bytes.clone();
    altered_bytes.push(b' ');
    assert!(matches!(
        restored.admit(context, timestamp, &altered_bytes, &verifier),
        Err(ProcessingStoreError::Invalid(_))
    ));
    assert_eq!(restored.pending_identities().count(), 1);

    restored
        .with_admission(
            &identity.envelope_id,
            &verifier,
            |stored_context, stored_time, stored| {
                assert_eq!(stored_time, timestamp);
                assert_eq!(serde_json::to_vec(stored).unwrap(), bytes);
                ordering
                    .certify(
                        stored.clone(),
                        stored_context,
                        finalized.world,
                        |admission| authorize(stored_context, admission),
                    )
                    .map(|(authorized, order)| (authorized, Some(order)))
                    .map_err(ProcessingStoreError::Verification)
            },
        )
        .map_err(debug)
}
