//! Engineering path for sponsored enrollment through the encrypted envelope.
use super::{
    debug, sponsor_digest, CandidateProtectedAccounts, EnrollmentProofs, FinalizedSnapshot,
    Mldsa87, Position, PqProvider, PublicKey, SignOptions, Signature, SponsorProof, WorldState,
};
use super::{
    etdag_candidate::OpenedCandidateEnvelope, settlement::EngineeringEtdagOpening,
    sponsor_settlement::SponsoredOutcome, transfer_admission,
};
use crate::services::{
    protected_action_wire::{decode_sponsor, ENROLL_COMMIT, ENROLL_REVEAL},
    protected_enrollment_wire::decode_sponsored,
};
use synergy_aegis::ApqeIdentityVerifier;
use synergy_etdag::{
    admission::{Pw13SponsoredAdmission, Pw13SponsoredResources, PW13_SPONSOR_ADMISSION_CONTEXT},
    EtdagParameters, ProcessingContext, ProcessingEnvelope,
};
use synergy_execution::FeeSchedule;

pub(super) struct VerifiedSponsoredAdmission {
    resources: Pw13SponsoredResources,
    public_key: Vec<u8>,
    fee_schedule: FeeSchedule,
    gas: u64,
}

impl CandidateProtectedAccounts<'_> {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn verify_sponsored_admission(
        &self,
        provider: &PqProvider<Mldsa87>,
        identity_verifier: &ApqeIdentityVerifier,
        finalized: &FinalizedSnapshot<'_>,
        context: &ProcessingContext,
        envelope: &ProcessingEnvelope,
        request: &Pw13SponsoredAdmission,
        limits: &EtdagParameters,
        fee_schedule: &FeeSchedule,
        gas: u64,
    ) -> Result<VerifiedSponsoredAdmission, String> {
        transfer_admission::require_source(finalized, context)?;
        request.validate_context(envelope, context).map_err(debug)?;
        let resources = &request.resources;
        if !std::ptr::eq(self, finalized.registry)
            || resources.genesis != self.network.genesis
            || !matches!(resources.action, ENROLL_COMMIT | ENROLL_REVEAL)
            || fee_schedule.collector.starts_with("synw")
        {
            return Err("PW13 sponsored admission differs from the authorized scope".into());
        }
        transfer_admission::verify_processing_resources(
            finalized,
            context,
            envelope,
            limits,
            fee_schedule,
            gas,
            resources.gas_limit,
            &resources.maximum_total_fee,
        )?;
        let key = PublicKey::from_bytes(&request.public_key).map_err(debug)?;
        self.verify_sponsor_binding(
            identity_verifier,
            &context.authority.network_id,
            finalized,
            finalized.world,
            &envelope.aad.sender_id,
            &request.binding,
            &key,
        )?;
        provider
            .verify(
                &resources.signing_digest().map_err(debug)?,
                &Signature::from_bytes(&request.signature).map_err(debug)?,
                &key,
                SignOptions::Pure {
                    context: PW13_SPONSOR_ADMISSION_CONTEXT,
                },
            )
            .map_err(debug)?;
        Ok(VerifiedSponsoredAdmission {
            resources: resources.clone(),
            public_key: request.public_key.clone(),
            fee_schedule: fee_schedule.clone(),
            gas,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn execute_opened_sponsored_enrollment(
        &self,
        provider: &PqProvider<Mldsa87>,
        identity_verifier: &ApqeIdentityVerifier,
        finalized: &FinalizedSnapshot<'_>,
        world: &mut WorldState,
        inclusion: Position,
        opened: &OpenedCandidateEnvelope,
        admission: &VerifiedSponsoredAdmission,
        fee_schedule: &FeeSchedule,
    ) -> Result<(SponsoredOutcome, u128), String> {
        let envelope = opened.envelope();
        let context = opened.context();
        transfer_admission::require_source(finalized, context)?;
        envelope.validate_context(context).map_err(debug)?;
        let content = decode_sponsored(opened.plaintext())?;
        let intent = decode_sponsor(content.sponsor_intent)?;
        let resources = &admission.resources;
        if resources.envelope_id != envelope.envelope_id
            || resources.sponsor_intent_digest != sponsor_digest(content.sponsor_intent)?
            || resources.genesis != intent.genesis
            || resources.action != intent.action
            || resources.maximum_total_fee != intent.max_fee
            || resources.valid_until_finalized_height != intent.valid_until
            || intent.payer != envelope.aad.sender_id
            || intent.nonce != envelope.aad.nonce_slot
            || content.signing_key.as_bytes() != admission.public_key.as_slice()
            || *fee_schedule != admission.fee_schedule
        {
            return Err("opened enrollment differs from the signed sponsor admission".into());
        }
        let opening = EngineeringEtdagOpening::from_opening(envelope, opened.plaintext())?;
        let proof = SponsorProof {
            intent: content.sponsor_intent,
            binding: &content.binding,
            signing_key: &content.signing_key,
            signature: &content.signature,
        };
        let network = &context.authority.network_id;
        if let Some(reveal) = content.reveal {
            self.execute_sponsored_reveal(
                provider,
                identity_verifier,
                network,
                finalized,
                world,
                inclusion,
                content.payload,
                &proof,
                EnrollmentProofs {
                    ordinary: &reveal.ordinary,
                    recovery: &reveal.recovery,
                    ownership: &reveal.ownership,
                    salt: &reveal.salt,
                },
                fee_schedule,
                admission.gas,
                Some(&opening),
            )
        } else {
            let (applied, fee) = self.execute_sponsored_commit(
                provider,
                identity_verifier,
                network,
                finalized,
                world,
                inclusion,
                content.payload,
                &proof,
                fee_schedule,
                admission.gas,
                Some(&opening),
            )?;
            let outcome = if applied {
                SponsoredOutcome::CommitApplied
            } else {
                SponsoredOutcome::DuplicatePaidCommit
            };
            Ok((outcome, fee))
        }
    }
}
