//! SynID authorization uses the registered native D/P policy without spending.
use super::{
    debug, display, transfer_admission, AccountIdentifier, CandidateProtectedAccounts,
    FinalizedSnapshot, Mldsa87, Position, PqProvider, Primitives, ProtectedExecutionWorld,
    PublicKey, SignOptions, Signature,
};
use crate::services::processing_pipeline::RevealedProcessingPayload;
use synergy_etdag::{admission::*, EtdagParameters, ProcessingContext, ProcessingEnvelope};
use synergy_state::{ProtocolChange, StateDiff};
pub(super) struct VerifiedFeeFreeSynIdAdmission {
    request: Pw13FeeFreeSynIdAdmission,
    gas: u64,
}
impl VerifiedFeeFreeSynIdAdmission {
    pub(super) fn resources(&self) -> &Pw13FeeFreeSynIdResources {
        &self.request.resources
    }
}
impl CandidateProtectedAccounts<'_> {
    pub(super) fn verify_fee_free_synid_admission(
        &self,
        provider: &PqProvider<Mldsa87>,
        source: &FinalizedSnapshot<'_>,
        context: &ProcessingContext,
        envelope: &ProcessingEnvelope,
        request: &Pw13FeeFreeSynIdAdmission,
        limits: &EtdagParameters,
        gas: u64,
    ) -> Result<VerifiedFeeFreeSynIdAdmission, String> {
        transfer_admission::require_source(source, context)?;
        request.validate_context(envelope, context).map_err(debug)?;
        limits
            .validate_target_height(source.position.height, context.authority.target_height)
            .map_err(debug)?;
        let r = &request.resources;
        let record = self.read_policy(source.world, AccountIdentifier::from_bytes(r.account))?;
        let policy = self.current_policy(&record)?;
        if !std::ptr::eq(self, source.registry)
            || r.genesis != self.network.genesis
            || record.registered_height > source.position.height
            || record.policy_epoch != r.policy_epoch
            || record.policy_hash != r.policy_hash
            || gas == 0
            || gas > r.gas_limit
            || r.gas_limit > limits.max_protected_gas
            || envelope.ciphertext.len() as u64 > limits.max_protected_bytes
            || context.authority.target_height_offset != limits.target_height_offset
            || source.world.protocol.contains_key(&r.settlement_key())
        {
            return Err("fee-free SynID scope or resources rejected".into());
        }
        let digest = r.signing_digest().map_err(debug)?;
        for (role, proof) in policy.terms().roles[..2].iter().zip(&request.proofs) {
            if role.participant_id != proof.participant_id || role.key_version != proof.key_version
            {
                return Err("SynID requires exact current native D/P".into());
            }
            provider
                .verify(
                    &digest,
                    &Signature::from_bytes(&proof.signature).map_err(debug)?,
                    &PublicKey::from_bytes(role.auth_public_key).map_err(debug)?,
                    SignOptions::Pure {
                        context: PW13_FEE_FREE_SYNID_ADMISSION_CONTEXT,
                    },
                )
                .map_err(debug)?;
        }
        Ok(VerifiedFeeFreeSynIdAdmission {
            request: request.clone(),
            gas,
        })
    }
    pub(super) fn execute_opened_fee_free_synid(
        &self,
        source: &FinalizedSnapshot<'_>,
        finalized: &FinalizedSnapshot<'_>,
        world: &mut impl ProtectedExecutionWorld,
        inclusion: Position,
        opened: RevealedProcessingPayload<'_>,
        admission: &VerifiedFeeFreeSynIdAdmission,
    ) -> Result<(FeeFreeSynIdOutcome, String), String> {
        transfer_admission::require_source(source, opened.context())?;
        if opened.plaintext().len() > 1024 {
            return Err("SynID intent exceeds bound".into());
        }
        let intent: FeeFreeSynIdIntent =
            serde_json::from_slice(opened.plaintext()).map_err(display)?;
        let r = admission.resources();
        if intent.canonical_bytes().map_err(debug)? != opened.plaintext()
            || intent.signing_digest().map_err(debug)?.as_slice() != r.intent_digest
            || intent.genesis != r.genesis
            || intent.account != r.account
            || intent.policy_epoch != r.policy_epoch
            || intent.policy_hash != r.policy_hash
            || intent.valid_until_finalized_height != r.valid_until_finalized_height
            || r.envelope_id != opened.envelope().envelope_id
            || synergy_naming::normalize_wallet_syn_id(&intent.syn_id)? != intent.syn_id
        {
            return Err("opened SynID differs from exact D/P intent".into());
        }
        let key = r.settlement_key();
        if world.state().protocol.contains_key(&key) {
            return Err("SynID envelope already settled".into());
        }
        let owner = AccountIdentifier::from_bytes(r.account)
            .to_native(&Primitives)
            .map_err(display)?;
        let record = self.read_policy(finalized.world, AccountIdentifier::from_bytes(r.account))?;
        let table = synergy_naming::WALLET_PROTOCOL_STATE_KEY;
        let mut names = synergy_naming::WalletSynIdRegistry::decode(
            world.state().protocol.get(table).map(Vec::as_slice),
        )?;
        let outcome = if finalized.position.height > r.valid_until_finalized_height {
            FeeFreeSynIdOutcome::Expired
        } else if record.policy_epoch != r.policy_epoch || record.policy_hash != r.policy_hash {
            FeeFreeSynIdOutcome::PolicySuperseded
        } else if let Some(existing) = names.resolve(&intent.syn_id)? {
            if existing.address == owner {
                FeeFreeSynIdOutcome::AlreadyRegistered
            } else {
                FeeFreeSynIdOutcome::NameUnavailable
            }
        } else if !names.reverse(&owner)?.is_empty() {
            FeeFreeSynIdOutcome::AccountAlreadyNamed
        } else {
            names.register_authenticated(&intent.syn_id, &owner, inclusion.height)?;
            FeeFreeSynIdOutcome::Registered
        };
        let receipt = FeeFreeSynIdSettlement {
            version: 1,
            genesis: r.genesis,
            account: r.account,
            envelope_id: r.envelope_id.clone(),
            admission_digest: r.signing_digest().map_err(debug)?.to_vec(),
            syn_id: intent.syn_id,
            source_finalized_height: source.position.height,
            deciding_finalized_height: finalized.position.height,
            included_height: inclusion.height,
            gas_used: admission.gas,
            fee_nwei: 0,
            outcome: outcome.clone(),
        };
        let mut diff = StateDiff {
            protocol_changes: vec![ProtocolChange {
                key: key.clone(),
                expected_value: None,
                value: Some(serde_json::to_vec(&receipt).map_err(display)?),
            }],
            ..StateDiff::default()
        };
        if outcome == FeeFreeSynIdOutcome::Registered {
            diff.protocol_changes.push(ProtocolChange {
                key: table.into(),
                expected_value: world.state().protocol.get(table).cloned(),
                value: Some(names.encode()?),
            });
        }
        world.apply_protected(&[&diff]).map_err(debug)?;
        Ok((outcome, key))
    }
}
