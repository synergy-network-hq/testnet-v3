//! Offline candidate for resource authorization before ETDAG reveals PW13
//! content. Production dispatch requires the approved profile and fee policy.
use super::{
    debug, display, AccountIdentifier, CandidateProtectedAccounts, CanonicalEnrollment,
    CanonicalNativeIntent, ChainId, FinalizedSnapshot, Mldsa87, PqProvider, Primitives, PublicKey,
    SignOptions, Signature,
};
use synergy_etdag::{
    admission::{Pw13TransferAdmission, Pw13TransferResources, PW13_ADMISSION_CONTEXT},
    EtdagParameters, ProcessingContext, ProcessingEnvelope,
};
use synergy_execution::FeeSchedule;

pub(super) struct VerifiedTransferAdmission {
    resources: Pw13TransferResources,
    gas: u64,
    fee_schedule: FeeSchedule,
}

pub(super) fn require_source(
    finalized: &FinalizedSnapshot<'_>,
    context: &ProcessingContext,
) -> Result<(), String> {
    let selected = &context.authority;
    if ChainId::from_u64(selected.chain_id).as_be_bytes()
        != &finalized.registry.network.native_chain
        || selected.source_finalized_height != finalized.position.height
        || selected.source_finality_context_root != finalized.processing_finality_root.0
    {
        return Err("PW13 admission differs from the authenticated finalized source".into());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn verify_processing_resources(
    finalized: &FinalizedSnapshot<'_>,
    context: &ProcessingContext,
    envelope: &ProcessingEnvelope,
    limits: &EtdagParameters,
    fee_schedule: &FeeSchedule,
    gas: u64,
    gas_limit: u64,
    maximum_total_fee: &[u8; 32],
) -> Result<(), String> {
    limits
        .validate_target_height(finalized.position.height, context.authority.target_height)
        .map_err(debug)?;
    if context.authority.target_height_offset != limits.target_height_offset {
        return Err("PW13 admission differs from the selected processing offset".into());
    }
    let payer = &envelope.aad.sender_id;
    let ledger = finalized
        .world
        .accounts
        .get(payer)
        .ok_or("PW13 payer state unavailable")?;
    fee_schedule.validate().map_err(display)?;
    let fee = u128::from(gas) * u128::from(fee_schedule.base_fee_per_gas_nwei);
    let mut total = [0u8; 32];
    total[16..].copy_from_slice(&fee.to_be_bytes());
    let nonce_ahead = envelope.aad.nonce_slot.checked_sub(ledger.nonce);
    if ledger.code_hash.is_some()
        || nonce_ahead.is_none_or(|ahead| ahead >= limits.max_outstanding_nonce_slots as u64)
        || gas == 0
        || gas > gas_limit
        || gas_limit > limits.max_protected_gas
        || envelope.ciphertext.len() as u64 > limits.max_protected_bytes
        || fee_schedule.collector == *payer
        || total > *maximum_total_fee
        || ledger.balance_nwei < fee
    {
        return Err("PW13 admission cannot cover the authorized nonce and resource cost".into());
    }
    Ok(())
}

impl CandidateProtectedAccounts<'_> {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn verify_transfer_admission(
        &self,
        provider: &PqProvider<Mldsa87>,
        finalized: &FinalizedSnapshot<'_>,
        context: &ProcessingContext,
        envelope: &ProcessingEnvelope,
        admission: &Pw13TransferAdmission,
        limits: &EtdagParameters,
        fee_schedule: &FeeSchedule,
        gas: u64,
    ) -> Result<VerifiedTransferAdmission, String> {
        if !std::ptr::eq(self, finalized.registry) {
            return Err("PW13 admission requires the selected registry".into());
        }
        require_source(finalized, context)?;
        admission
            .validate_context(envelope, context)
            .map_err(debug)?;
        let resources = &admission.resources;
        let digest = resources.signing_digest().map_err(debug)?;
        let account = AccountIdentifier::from_bytes(resources.account);
        let sender = account.to_native(&Primitives).map_err(display)?;
        let record = self.read_policy(finalized.world, account)?;
        let enrollment =
            CanonicalEnrollment::decode(&record.enrollment, self.wire).map_err(display)?;
        let policy = self.canonical_policy(&record, &enrollment)?;
        if resources.genesis != self.network.genesis
            || resources.policy_epoch != record.policy_epoch
            || resources.policy_hash != record.policy_hash
            || record.registered_height > finalized.position.height
            || envelope.aad.sender_id != sender
        {
            return Err(
                "PW13 admission differs from the current protected policy or account".into(),
            );
        }
        verify_processing_resources(
            finalized,
            context,
            envelope,
            limits,
            fee_schedule,
            gas,
            resources.gas_limit,
            &resources.maximum_total_fee,
        )?;

        // Exact D then P. The request carries no replacement verification keys.
        for (registered, proof) in policy.policy().roles[..2].iter().zip(&admission.proofs) {
            if proof.participant_id != registered.participant_id
                || proof.key_version != registered.key_version
            {
                return Err("PW13 admission is missing a current D or P proof".into());
            }
            provider
                .verify(
                    &digest,
                    &Signature::from_bytes(&proof.signature).map_err(debug)?,
                    &PublicKey::from_bytes(registered.auth_public_key).map_err(debug)?,
                    SignOptions::Pure {
                        context: PW13_ADMISSION_CONTEXT,
                    },
                )
                .map_err(debug)?;
        }
        Ok(VerifiedTransferAdmission {
            resources: resources.clone(),
            gas,
            fee_schedule: fee_schedule.clone(),
        })
    }
}

impl VerifiedTransferAdmission {
    pub(super) fn verify_opened(
        &self,
        finalized: &FinalizedSnapshot<'_>,
        intent: &CanonicalNativeIntent<'_>,
        envelope: &ProcessingEnvelope,
        context: &ProcessingContext,
        fee_schedule: &FeeSchedule,
        gas: u64,
    ) -> Result<(), String> {
        require_source(finalized, context)?;
        envelope.validate_context(context).map_err(debug)?;
        let resources = &self.resources;
        let body = intent.body();
        if envelope.envelope_id != resources.envelope_id
            || resources.genesis != *body.genesis.as_bytes()
            || resources.account != *body.account.as_bytes()
            || resources.policy_epoch != body.policy_epoch
            || envelope.aad.nonce_slot != body.transaction_nonce
            || resources.gas_limit != body.gas_limit
            || resources.maximum_total_fee != body.maximum_total_fee
            || resources.valid_until_finalized_height != body.valid_until_finalized_height
            || resources.native_intent_digest
                != intent.digest().map_err(display)?.as_bytes().as_slice()
            || self.gas != gas
            || self.fee_schedule != *fee_schedule
        {
            return Err("opened PW13 intent differs from the signed resource authorization".into());
        }
        Ok(())
    }
}
