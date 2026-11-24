//! Closed, independently authenticated enrollment. Metering never authorizes a debit.
use super::{
    debug, display, policy_variant::InitialEnrollment, transfer_admission,
    CandidateProtectedAccounts, EnrollmentSignature, EnrollmentVerifier, FinalizedSnapshot,
    InitialEnrollmentProofs, Mldsa87, Position, PqProvider, ProtectedExecutionWorld, PublicKey,
    SignOptions, Signature, VerifiedAccountEnrollment,
};
use super::{HashAlgorithm, Primitives};
use crate::services::{
    processing_pipeline::RevealedProcessingPayload,
    protected_action_wire::{self, Payload},
    protected_enrollment_wire::{self, EnrollmentContent},
};
use synergy_etdag::{admission::*, EtdagParameters, ProcessingContext, ProcessingEnvelope};
use synergy_state::{ProtocolChange, StateDiff};

pub(super) struct VerifiedFeeFreeEnrollmentAdmission {
    request: Pw13FeeFreeEnrollmentAdmission,
    gas: u64,
}
impl VerifiedFeeFreeEnrollmentAdmission {
    pub(super) fn resources(&self) -> &Pw13FeeFreeEnrollmentResources {
        &self.request.resources
    }
}
fn signature(proof: &InitialEnrollmentProof) -> Result<EnrollmentSignature, String> {
    Ok(EnrollmentSignature {
        schema_version: 1,
        role_id: proof.role_id,
        participant_id: proof.participant_id,
        key_version: proof.key_version,
        auth_algorithm: 1,
        signed_digest: proof
            .signed_digest
            .as_slice()
            .try_into()
            .map_err(|_| "invalid enrollment digest")?,
        signature: Signature::from_bytes(&proof.signature).map_err(debug)?,
    })
}
fn same_signature(a: &EnrollmentSignature, b: &EnrollmentSignature) -> bool {
    a.schema_version == b.schema_version
        && a.role_id == b.role_id
        && a.participant_id == b.participant_id
        && a.key_version == b.key_version
        && a.auth_algorithm == b.auth_algorithm
        && a.signed_digest == b.signed_digest
        && a.signature.as_bytes() == b.signature.as_bytes()
}
impl CandidateProtectedAccounts<'_> {
    fn verify_fee_free_roles<const N: usize>(
        &self,
        provider: &PqProvider<Mldsa87>,
        finalized: &FinalizedSnapshot<'_>,
        verified: &VerifiedAccountEnrollment<'_, '_, N>,
        request: &Pw13FeeFreeEnrollmentAdmission,
    ) -> Result<(), String> {
        match &self.verifier {
            EnrollmentVerifier::Candidate(v) => {
                v.verify_initial_enrollment(verified, finalized.context())
            }
            EnrollmentVerifier::Activated { verifier: v, .. } => {
                v.verify_initial_enrollment(verified, finalized.context())
            }
        }
        .map_err(display)?;
        let enrollment = verified.enrollment();
        if enrollment.account().as_bytes() != &request.resources.account {
            return Err("fee-free account differs from enrollment".into());
        }
        let digest = request.resources.signing_digest().map_err(debug)?;
        for (role, proof) in enrollment.policy().roles[..2].iter().zip(&request.proofs) {
            if role.participant_id != proof.participant_id || role.key_version != proof.key_version
            {
                return Err("fee-free admission lacks exact enrollment D/P".into());
            }
            provider
                .verify(
                    &digest,
                    &Signature::from_bytes(&proof.signature).map_err(debug)?,
                    &PublicKey::from_bytes(role.auth_public_key).map_err(debug)?,
                    SignOptions::Pure {
                        context: PW13_FEE_FREE_ENROLLMENT_ADMISSION_CONTEXT,
                    },
                )
                .map_err(debug)?;
        }
        Ok(())
    }
    pub(super) fn verify_fee_free_enrollment_admission(
        &self,
        provider: &PqProvider<Mldsa87>,
        finalized: &FinalizedSnapshot<'_>,
        context: &ProcessingContext,
        envelope: &ProcessingEnvelope,
        request: &Pw13FeeFreeEnrollmentAdmission,
        limits: &EtdagParameters,
        gas: u64,
    ) -> Result<VerifiedFeeFreeEnrollmentAdmission, String> {
        transfer_admission::require_source(finalized, context)?;
        request.validate_context(envelope, context).map_err(debug)?;
        limits
            .validate_target_height(finalized.position.height, context.authority.target_height)
            .map_err(debug)?;
        let r = &request.resources;
        if !std::ptr::eq(self, finalized.registry)
            || r.genesis != self.network.genesis
            || context.authority.target_height_offset != limits.target_height_offset
            || gas == 0
            || gas > r.gas_limit
            || r.gas_limit > limits.max_protected_gas
            || envelope.ciphertext.len() as u64 > limits.max_protected_bytes
            || finalized.world.protocol.contains_key(
                &fee_free_enrollment_settlement_key(&r.session_id, r.action).map_err(debug)?,
            )
        {
            return Err(
                "fee-free enrollment exceeds scope, resource bounds or completed session".into(),
            );
        }
        let ordinary = [
            signature(&request.ordinary[0])?,
            signature(&request.ordinary[1])?,
        ];
        let recovery = request.recovery.as_ref().map(signature).transpose()?;
        let ownership: [u8; 65] = request
            .ownership
            .as_slice()
            .try_into()
            .map_err(|_| "invalid enrollment ownership")?;
        match (
            InitialEnrollment::decode(&request.enrollment_bytes, self.wire)?,
            recovery.as_ref(),
        ) {
            (InitialEnrollment::PrimaryCompanion(e), None) => {
                if !self.verifier.admits_primary_companion() {
                    return Err("two-role enrollment not admitted".into());
                }
                let v = e
                    .verify_candidate_for_selected_chain(
                        provider,
                        &ordinary,
                        &self.chain,
                        &ownership,
                        finalized.position.consensus_time,
                    )
                    .map_err(display)?;
                self.verify_fee_free_roles(provider, finalized, &v, request)?;
            }
            (InitialEnrollment::WithRecovery(e), Some(recovery)) => {
                let v = e
                    .verify_candidate_for_selected_chain(
                        provider,
                        &ordinary,
                        recovery,
                        &self.chain,
                        &ownership,
                        finalized.position.consensus_time,
                    )
                    .map_err(display)?;
                self.verify_fee_free_roles(provider, finalized, &v, request)?;
            }
            _ => return Err("fee-free enrollment role set mismatch".into()),
        }
        Ok(VerifiedFeeFreeEnrollmentAdmission {
            request: request.clone(),
            gas,
        })
    }
    pub(super) fn execute_opened_fee_free_enrollment(
        &self,
        provider: &PqProvider<Mldsa87>,
        source: &FinalizedSnapshot<'_>,
        finalized: &FinalizedSnapshot<'_>,
        world: &mut impl ProtectedExecutionWorld,
        inclusion: Position,
        opened: RevealedProcessingPayload<'_>,
        admission: &VerifiedFeeFreeEnrollmentAdmission,
    ) -> Result<(FeeFreeEnrollmentOutcome, String), String> {
        transfer_admission::require_source(source, opened.context())?;
        let r = admission.resources();
        let (slots, reveal) = match protected_enrollment_wire::decode(opened.plaintext())? {
            EnrollmentContent::Commit { opaque } => (opaque, None),
            EnrollmentContent::Reveal(reveal) => (reveal.opaque, Some(reveal)),
        };
        let intent: FeeFreeEnrollmentIntent = serde_json::from_slice(slots[0]).map_err(display)?;
        let payload_hash = Primitives
            .hash(HashAlgorithm::Sha3256, slots[1])
            .map_err(debug)?;
        if intent.canonical_bytes().map_err(debug)? != slots[0]
            || !slots[2].is_empty()
            || intent.signing_digest().map_err(debug)?.as_slice() != r.enrollment_intent_digest
            || intent.genesis != r.genesis
            || intent.session_id != r.session_id
            || intent.account != r.account
            || intent.action != r.action
            || intent.commitment != r.commitment
            || intent.valid_until_finalized_height != r.valid_until_finalized_height
            || intent.payload_sha3_256.as_slice() != payload_hash
            || r.envelope_id != opened.envelope().envelope_id
        {
            return Err("opened fee-free enrollment differs from D/P authorization".into());
        }
        let key = fee_free_enrollment_settlement_key(&r.session_id, r.action).map_err(debug)?;
        if world.state().protocol.contains_key(&key) {
            return Err("fee-free session stage already consumed".into());
        }
        let proof_expiry =
            match InitialEnrollment::decode(&admission.request.enrollment_bytes, self.wire)? {
                InitialEnrollment::WithRecovery(e) => e.expires_at(),
                InitialEnrollment::PrimaryCompanion(e) => e.expires_at(),
            };
        let (business, outcome) = if finalized.position.height > r.valid_until_finalized_height
            || inclusion.consensus_time >= proof_expiry
        {
            (StateDiff::default(), FeeFreeEnrollmentOutcome::Expired)
        } else {
            match (protected_action_wire::decode(r.action, slots[1])?, reveal) {
                (Payload::Commit(commitment), None) if commitment == r.commitment => {
                    let commit = super::EnrollmentCommitment::from_bytes(commitment);
                    let applied = !world
                        .state()
                        .protocol
                        .contains_key(&super::commit_key(commit));
                    let diff = if applied {
                        self.prepare_commit(world.state(), commit, inclusion)?
                    } else {
                        StateDiff::default()
                    };
                    (
                        diff,
                        if applied {
                            FeeFreeEnrollmentOutcome::CommitApplied
                        } else {
                            FeeFreeEnrollmentOutcome::CommitAlreadyPresent
                        },
                    )
                }
                (Payload::Reveal { enrollment, salt }, Some(reveal))
                    if enrollment == admission.request.enrollment_bytes && salt == reveal.salt =>
                {
                    let ordinary = [
                        signature(&admission.request.ordinary[0])?,
                        signature(&admission.request.ordinary[1])?,
                    ];
                    let recovery = admission
                        .request
                        .recovery
                        .as_ref()
                        .map(signature)
                        .transpose()?;
                    if !reveal
                        .ordinary
                        .iter()
                        .zip(&ordinary)
                        .all(|(a, b)| same_signature(a, b))
                        || match (&reveal.recovery, &recovery) {
                            (None, None) => false,
                            (Some(a), Some(b)) => !same_signature(a, b),
                            _ => true,
                        }
                        || reveal.ownership.as_slice() != admission.request.ownership
                    {
                        return Err("fee-free reveal changed original enrollment proofs".into());
                    }
                    let commit_key =
                        super::commit_key(super::EnrollmentCommitment::from_bytes(r.commitment));
                    let commit = world
                        .state()
                        .protocol
                        .get(&commit_key)
                        .map(|bytes| {
                            self.decode_commitment(
                                bytes,
                                super::EnrollmentCommitment::from_bytes(r.commitment),
                            )
                        })
                        .transpose()?;
                    let used = commit.as_ref().is_some_and(|c| c.consumed);
                    let stale = commit.as_ref().is_some_and(|c| {
                        inclusion
                            .consensus_time
                            .checked_sub(c.consensus_time)
                            .is_none_or(|age| age >= super::REVEAL_WINDOW_SECONDS)
                    });
                    if stale {
                        (StateDiff::default(), FeeFreeEnrollmentOutcome::Expired)
                    } else if used
                        || world.state().protocol.contains_key(&super::account_key(
                            super::AccountIdentifier::from_bytes(r.account),
                        ))
                    {
                        (
                            StateDiff::default(),
                            FeeFreeEnrollmentOutcome::RevealRejectedCommitUsed,
                        )
                    } else {
                        let write = self.prepare_reveal(
                            provider,
                            finalized,
                            world.state(),
                            inclusion,
                            enrollment,
                            InitialEnrollmentProofs {
                                ordinary: &reveal.ordinary,
                                recovery: reveal.recovery.as_ref(),
                                ownership: &reveal.ownership,
                                salt: &salt,
                            },
                        )?;
                        if write.commitment != r.commitment {
                            return Err("fee-free commitment mismatch".into());
                        }
                        write.check_fee(world.state(), &StateDiff::default())?;
                        (write.diff, FeeFreeEnrollmentOutcome::RevealApplied)
                    }
                }
                _ => {
                    return Err(
                        "fee-free action is not the exact closed enrollment operation".into(),
                    )
                }
            }
        };
        let record = FeeFreeEnrollmentSettlement {
            version: 1,
            genesis: r.genesis,
            session_id: r.session_id,
            account: r.account,
            action: r.action,
            commitment: r.commitment,
            envelope_id: r.envelope_id.clone(),
            admission_digest: r.signing_digest().map_err(debug)?.to_vec(),
            source_finalized_height: source.position.height,
            source_consensus_timestamp_unix: source.position.consensus_time,
            deciding_finalized_height: finalized.position.height,
            included_height: inclusion.height,
            inclusion_consensus_timestamp_unix: inclusion.consensus_time,
            gas_used: admission.gas,
            fee_nwei: 0,
            outcome: outcome.clone(),
        };
        world
            .apply_protected(&[
                &business,
                &StateDiff {
                    protocol_changes: vec![ProtocolChange {
                        key: key.clone(),
                        expected_value: None,
                        value: Some(serde_json::to_vec(&record).map_err(display)?),
                    }],
                    ..StateDiff::default()
                },
            ])
            .map_err(debug)?;
        Ok((outcome, key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::{signature::hazmat::PrehashSigner, Signature as EcSignature, SigningKey};
    use synergy_address_engine::apqe::{
        account_binding::ExternalChainPolicy,
        address::{derive_account_identifier, ValidatedSec1PublicPoint},
        enrollment::*,
        enrollment_commit::UnactivatedCommitmentProfile,
        identity::{ChainId, NativeGenesisHash, WalletUuid},
        provider::Profile,
    };
    use synergy_posy::FinalizedBlockRecord;
    use synergy_state::{state_root, AccountState, FinalizedState, WorldState};

    fn snapshot<'a>(
        registry: &'a CandidateProtectedAccounts<'a>,
        world: &'a WorldState,
        height: u64,
        time: u64,
    ) -> FinalizedSnapshot<'a> {
        let record = FinalizedBlockRecord {
            height,
            block_id: format!("{height:064x}"),
            finality_certificate_id: "a".repeat(64),
            protected_execution_root: "b".repeat(64),
        };
        let pointer = FinalizedState {
            finalized_height: height,
            finalized_block_id: record.block_id.clone(),
            state_root: state_root(world).unwrap(),
        };
        registry
            .finalized_snapshot(world, &pointer, &record, time)
            .unwrap()
    }
    fn record(height: u64) -> FinalizedBlockRecord {
        FinalizedBlockRecord {
            height,
            block_id: format!("{height:064x}"),
            finality_certificate_id: "a".repeat(64),
            protected_execution_root: "b".repeat(64),
        }
    }
    fn hex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks_exact(2)
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect()
    }
    fn bstr(v: &[u8], out: &mut Vec<u8>) {
        let n = v.len();
        if n < 24 {
            out.push(0x40 + n as u8)
        } else if n < 256 {
            out.extend_from_slice(&[0x58, n as u8])
        } else {
            out.push(0x59);
            out.extend_from_slice(&(n as u16).to_be_bytes())
        };
        out.extend_from_slice(v)
    }
    fn frame(
        action: u16,
        intent: &[u8],
        payload: &[u8],
        proofs: &[EnrollmentSignature; 2],
        ownership: &[u8; 65],
        salt: &[u8; 32],
    ) -> Vec<u8> {
        let reveal = action == FEE_FREE_ENROLL_REVEAL;
        let mut out = vec![
            if reveal { 0x87 } else { 0x84 },
            0x19,
            0x70,
            if reveal { 2 } else { 1 },
        ];
        for slot in [intent, payload, &[]] {
            bstr(slot, &mut out)
        }
        if reveal {
            out.push(0x82);
            for p in proofs {
                out.extend_from_slice(&[0x87, 1, 1, 1, p.role_id]);
                bstr(&p.participant_id, &mut out);
                bstr(&p.signed_digest, &mut out);
                bstr(p.signature.as_bytes(), &mut out)
            }
            bstr(ownership, &mut out);
            bstr(salt, &mut out)
        }
        out
    }
    #[test]
    #[ignore = "requires explicit independently pinned actual native APQE providers"]
    fn real_native_zero_balance_fee_free_commit_reveal_synid_and_replay() {
        let report =
            std::path::PathBuf::from(std::env::var_os("APQE_ENGINEERING_NATIVE_REPORT").unwrap());
        let pin = std::env::var("APQE_ENGINEERING_NATIVE_REPORT_SHA256").unwrap();
        let provider = unsafe {
            PqProvider::<Mldsa87>::open_verified(
                std::env::var_os("CORE_APQE_MLDSA87_LIBRARY").unwrap(),
                hex(&std::env::var("CORE_APQE_MLDSA87_SHA256").unwrap())
                    .try_into()
                    .unwrap(),
                Profile::Validation,
            )
        }
        .unwrap();
        let (d, ds) = provider.generate_keypair().unwrap();
        let (p, ps) = provider.generate_keypair().unwrap();
        // Genuine native PQ proofs and envelope crypto. This ephemeral EC key
        // tests AccountBinding framing; separate DKG qualification owns shares.
        let ec = SigningKey::from_slice(&[9; 32]).unwrap();
        let public = ec.verifying_key().to_encoded_point(false);
        let point = ValidatedSec1PublicPoint::parse(&Primitives, public.as_bytes()).unwrap();
        let account = derive_account_identifier(&Primitives, &point).unwrap();
        let genesis = NativeGenesisHash::from_bytes([17; 32]);
        let chain = ChainId::from_u64(99999);
        let policy = ExternalChainPolicy::new(chain, genesis).unwrap();
        let wire = super::super::inspection::candidate_wire_profile().unwrap();
        let manifest = [34; 32];
        let data = PrimaryCompanionEnrollmentData {
            genesis,
            account,
            evm_public_key: *point.as_sec1_bytes(),
            public_policy: PrimaryCompanionPublicPolicy {
                genesis,
                account,
                policy_epoch: 0,
                roles: [
                    RoleRecord {
                        role_id: 0,
                        participant_id: [1; 32],
                        key_version: 1,
                        auth_algorithm: 1,
                        auth_public_key: d.as_bytes(),
                    },
                    RoleRecord {
                        role_id: 1,
                        participant_id: [2; 32],
                        key_version: 1,
                        auth_algorithm: 1,
                        auth_public_key: p.as_bytes(),
                    },
                ],
                evm_public_key: *point.as_sec1_bytes(),
                provider_manifest_hash: manifest,
                ordinary_change_delay: 7200,
                recovery_delay: 0,
                status: 0,
            },
            dkg_transcript_commitment: &[51; 32],
            nonce: [68; 32],
            issued_at: 100,
            expires_at: 200,
            wallet_uuid: WalletUuid::from_bytes([85; 16]),
        };
        let bytes = data.encode(&wire).unwrap();
        let enrollment = CanonicalPrimaryCompanionEnrollment::decode(&bytes, &wire).unwrap();
        let challenge = enrollment
            .account_binding_challenge_for_caller_validated_dkg(
                policy,
                &point,
                &manifest,
                data.dkg_transcript_commitment,
                101,
            )
            .unwrap();
        let ec_sig: EcSignature = ec.sign_prehash(challenge.digest().as_bytes()).unwrap();
        let (ownership, _) = challenge
            .verify_provider_der(ec_sig.to_der().as_bytes(), 101)
            .unwrap();
        let digest = enrollment.native_digest().unwrap();
        let initial = std::array::from_fn(|i| EnrollmentSignature {
            schema_version: 1,
            role_id: i as u8,
            participant_id: [i as u8 + 1; 32],
            key_version: 1,
            auth_algorithm: 1,
            signed_digest: digest,
            signature: provider
                .sign(
                    &digest,
                    if i == 0 { &ds } else { &ps },
                    SignOptions::Pure {
                        context: enrollment.native_signature_context(),
                    },
                )
                .unwrap(),
        });
        let rule = UnactivatedCommitmentProfile::candidate_concat_v1();
        let salt = [5; 32];
        let commitment = rule.commitment(&enrollment, &salt).unwrap();
        let mut registry =
            CandidateProtectedAccounts::new(chain, policy, &wire, rule, vec![manifest]).unwrap();
        registry.verifier = EnrollmentVerifier::Candidate(
            super::super::CandidateEnrollmentVerifier::new_with_primary_companion(
                genesis,
                chain,
                &wire,
                rule,
                vec![manifest],
            )
            .unwrap(),
        );
        let mut world = WorldState::default();
        world.accounts.insert(
            "treasury-observation".into(),
            AccountState {
                balance_nwei: 500000,
                nonce: 7,
                code_hash: None,
            },
        );
        let start = world.accounts.clone();
        let address = account.to_native(&Primitives).unwrap();
        let session = [77; 32];
        let mut last_admission = None;
        for (action, height, time) in [
            (FEE_FREE_ENROLL_COMMIT, 1, 101),
            (FEE_FREE_ENROLL_REVEAL, 8, 103),
        ] {
            let source_world = world.clone();
            let source = snapshot(&registry, &source_world, height, time);
            let payload = if action == FEE_FREE_ENROLL_COMMIT {
                let mut v = vec![0xa2, 0, 1, 1, 0x58, 32];
                v.extend_from_slice(commitment.as_bytes());
                v
            } else {
                let mut v = vec![0xa3, 0, 1, 1];
                bstr(&bytes, &mut v);
                v.push(2);
                bstr(&salt, &mut v);
                v
            };
            let intent = FeeFreeEnrollmentIntent {
                version: 1,
                genesis: *genesis.as_bytes(),
                session_id: session,
                account: *account.as_bytes(),
                action,
                commitment: *commitment.as_bytes(),
                payload_sha3_256: Primitives
                    .hash(HashAlgorithm::Sha3256, &payload)
                    .unwrap()
                    .try_into()
                    .unwrap(),
                valid_until_finalized_height: 50,
            };
            let content = frame(
                action,
                &intent.canonical_bytes().unwrap(),
                &payload,
                &initial,
                &ownership,
                &salt,
            );
            let sender = format!(
                "enroll:{}",
                session
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            );
            let (opened, authorized) = super::super::etdag_candidate::open_candidate_envelope(
                &content,
                &report,
                &pin,
                99999,
                &record(height),
                &sender,
                if action == FEE_FREE_ENROLL_COMMIT {
                    0
                } else {
                    1
                },
                super::super::etdag_candidate::CandidateEnvelopeProfile::FeeFreeEnrollment,
                None,
                |env, ctx, _| {
                    let resources = Pw13FeeFreeEnrollmentResources {
                        genesis: *genesis.as_bytes(),
                        session_id: session,
                        account: *account.as_bytes(),
                        action,
                        commitment: *commitment.as_bytes(),
                        enrollment_digest: fee_free_enrollment_candidate_digest(&bytes)
                            .unwrap()
                            .to_vec(),
                        enrollment_intent_digest: intent.signing_digest().unwrap().to_vec(),
                        gas_limit: 5,
                        valid_until_finalized_height: 50,
                        envelope_id: env.envelope_id.clone(),
                    };
                    let digest = resources.signing_digest().unwrap();
                    let request = Pw13FeeFreeEnrollmentAdmission {
                        resources,
                        enrollment_bytes: bytes.clone(),
                        ordinary: std::array::from_fn(|i| InitialEnrollmentProof {
                            role_id: i as u8,
                            participant_id: initial[i].participant_id,
                            key_version: 1,
                            signed_digest: initial[i].signed_digest.to_vec(),
                            signature: initial[i].signature.as_bytes().to_vec(),
                        }),
                        recovery: None,
                        ownership: ownership.to_vec(),
                        proofs: std::array::from_fn(|i| Pw13AdmissionProof {
                            participant_id: [i as u8 + 1; 32],
                            key_version: 1,
                            signature: provider
                                .sign(
                                    &digest,
                                    if i == 0 { &ds } else { &ps },
                                    SignOptions::Pure {
                                        context: PW13_FEE_FREE_ENROLLMENT_ADMISSION_CONTEXT,
                                    },
                                )
                                .unwrap()
                                .as_bytes()
                                .to_vec(),
                        }),
                    };
                    let mut invalid = request.clone();
                    invalid.proofs[0].signature[0] ^= 1;
                    assert!(registry
                        .verify_fee_free_enrollment_admission(
                            &provider,
                            &source,
                            ctx,
                            env,
                            &invalid,
                            &EtdagParameters::default(),
                            5
                        )
                        .is_err());
                    assert!(registry
                        .verify_fee_free_enrollment_admission(
                            &provider,
                            &source,
                            ctx,
                            env,
                            &request,
                            &EtdagParameters::default(),
                            6
                        )
                        .is_err());
                    let checked = registry.verify_fee_free_enrollment_admission(
                        &provider,
                        &source,
                        ctx,
                        env,
                        &request,
                        &EtdagParameters::default(),
                        5,
                    )?;
                    Ok((checked, None))
                },
            )
            .unwrap();
            let included = Position {
                height: height + 5,
                consensus_time: time + 1,
            };
            let (outcome, key) = registry
                .execute_opened_fee_free_enrollment(
                    &provider,
                    &source,
                    &source,
                    &mut world,
                    included,
                    opened.payload(),
                    &authorized,
                )
                .unwrap();
            assert_eq!(
                outcome,
                if action == FEE_FREE_ENROLL_COMMIT {
                    FeeFreeEnrollmentOutcome::CommitApplied
                } else {
                    FeeFreeEnrollmentOutcome::RevealApplied
                }
            );
            let receipt: FeeFreeEnrollmentSettlement =
                serde_json::from_slice(&world.protocol[&key]).unwrap();
            assert_eq!(receipt.fee_nwei, 0);
            assert!(registry
                .execute_opened_fee_free_enrollment(
                    &provider,
                    &source,
                    &source,
                    &mut world,
                    included,
                    opened.payload(),
                    &authorized
                )
                .is_err());
            last_admission = Some(authorized);
        }
        assert_eq!(world.accounts[&address].balance_nwei, 0);
        assert_eq!(world.accounts[&address].nonce, 0);
        assert_eq!(
            world.accounts["treasury-observation"],
            start["treasury-observation"]
        );
        assert_eq!(world.accounts.len(), 2);
        assert!(last_admission.is_some());
        // Optional initial name uses the newly registered D/P policy, without
        // consuming its financial nonce zero or consulting a funded payer.
        let source_world = world.clone();
        let source = snapshot(&registry, &source_world, 14, 105);
        let policy = registry.read_policy(&source_world, account).unwrap();
        let intent = FeeFreeSynIdIntent {
            version: 1,
            genesis: *genesis.as_bytes(),
            account: *account.as_bytes(),
            policy_epoch: policy.policy_epoch,
            policy_hash: policy.policy_hash,
            syn_id: "customer-zero.syn".into(),
            valid_until_finalized_height: 50,
        };
        let sender = format!(
            "synid:{}",
            account
                .as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        let (opened, authorized) = super::super::etdag_candidate::open_candidate_envelope(
            &intent.canonical_bytes().unwrap(),
            &report,
            &pin,
            99999,
            &record(14),
            &sender,
            0,
            super::super::etdag_candidate::CandidateEnvelopeProfile::FeeFreeSynId,
            None,
            |env, ctx, _| {
                let resources = Pw13FeeFreeSynIdResources {
                    genesis: *genesis.as_bytes(),
                    account: *account.as_bytes(),
                    policy_epoch: policy.policy_epoch,
                    policy_hash: policy.policy_hash,
                    intent_digest: intent.signing_digest().unwrap().to_vec(),
                    gas_limit: 5,
                    valid_until_finalized_height: 50,
                    envelope_id: env.envelope_id.clone(),
                };
                let digest = resources.signing_digest().unwrap();
                let request = Pw13FeeFreeSynIdAdmission {
                    resources,
                    proofs: std::array::from_fn(|i| Pw13AdmissionProof {
                        participant_id: [i as u8 + 1; 32],
                        key_version: 1,
                        signature: provider
                            .sign(
                                &digest,
                                if i == 0 { &ds } else { &ps },
                                SignOptions::Pure {
                                    context: PW13_FEE_FREE_SYNID_ADMISSION_CONTEXT,
                                },
                            )
                            .unwrap()
                            .as_bytes()
                            .to_vec(),
                    }),
                };
                let mut invalid = request.clone();
                invalid.proofs[1].signature[0] ^= 1;
                assert!(registry
                    .verify_fee_free_synid_admission(
                        &provider,
                        &source,
                        ctx,
                        env,
                        &invalid,
                        &EtdagParameters::default(),
                        5
                    )
                    .is_err());
                Ok((
                    registry.verify_fee_free_synid_admission(
                        &provider,
                        &source,
                        ctx,
                        env,
                        &request,
                        &EtdagParameters::default(),
                        5,
                    )?,
                    None,
                ))
            },
        )
        .unwrap();
        let (outcome, key) = registry
            .execute_opened_fee_free_synid(
                &source,
                &source,
                &mut world,
                Position {
                    height: 19,
                    consensus_time: 106,
                },
                opened.payload(),
                &authorized,
            )
            .unwrap();
        assert_eq!(outcome, FeeFreeSynIdOutcome::Registered);
        let receipt: FeeFreeSynIdSettlement =
            serde_json::from_slice(&world.protocol[&key]).unwrap();
        assert_eq!(receipt.fee_nwei, 0);
        let names = synergy_naming::WalletSynIdRegistry::decode(
            world
                .protocol
                .get(synergy_naming::WALLET_PROTOCOL_STATE_KEY)
                .map(Vec::as_slice),
        )
        .unwrap();
        assert_eq!(
            names.resolve("customer-zero.syn").unwrap().unwrap().address,
            address
        );
        assert_eq!(world.accounts[&address].balance_nwei, 0);
        assert_eq!(world.accounts[&address].nonce, 0);
        assert_eq!(
            world.accounts["treasury-observation"],
            start["treasury-observation"]
        );
        assert!(registry
            .execute_opened_fee_free_synid(
                &source,
                &source,
                &mut world,
                Position {
                    height: 20,
                    consensus_time: 107
                },
                opened.payload(),
                &authorized
            )
            .is_err());
        let reopened: WorldState =
            serde_json::from_slice(&serde_json::to_vec(&world).unwrap()).unwrap();
        assert_eq!(state_root(&world).unwrap(), state_root(&reopened).unwrap());
    }
}
