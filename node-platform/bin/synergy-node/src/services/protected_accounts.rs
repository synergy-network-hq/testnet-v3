//! Candidate-only adapter from APQE enrollment proofs to Core's committed World.
//! No RPC, ETDAG action dispatch, or genesis path may activate these assignments.
#![allow(dead_code)] // A governed wire/action/fee profile is required before runtime dispatch.

#[path = "protected_account_read.rs"]
pub(super) mod inspection;
#[path = "protected_settlement.rs"]
mod settlement;
#[path = "protected_sponsor_settlement.rs"]
mod sponsor_settlement;

#[cfg(test)]
#[path = "protected_etdag_candidate_tests.rs"]
mod etdag_candidate;
#[cfg(test)]
#[path = "protected_transfer_admission.rs"]
mod transfer_admission;
#[cfg(test)]
#[path = "protected_sponsored_admission.rs"]
mod sponsored_admission;
#[path = "protected_recovery.rs"]
pub(super) mod recovery;
#[path = "protected_transition_queue.rs"]
mod transition_queue;
#[path = "protected_transition_settlement.rs"]
mod transition_settlement;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use synergy_address_engine::apqe::{
    account_binding::ExternalChainPolicy,
    address::AccountIdentifier,
    authorization::{
        verify_signature_quorum_for_caller_validated_transcript, CallerValidatedTranscript,
        CurrentAccountState, EnrolledRole, IntentConstraints, NativeAction, NativePolicy, Role,
        RoleSignature, VerifiedSignatureQuorum, NATIVE_TX_CONTEXT,
    },
    enrollment::{
        CanonicalEnrollment, CanonicalPublicPolicy, EnrollmentSignature, UnactivatedWireProfile,
    },
    enrollment_commit::{
        EnrollmentCommitment, PendingEnrollmentCommitment, UnactivatedCommitmentProfile,
        REVEAL_WINDOW_SECONDS,
    },
    enrollment_registry::{CandidateEnrollmentVerifier, FinalizedEnrollmentContext, RegistryError},
    identity::{ChainId, NativeAccountCoordinate, NativeGenesisHash},
    native_intent::{CanonicalNativeIntent, NativeIntentBody},
    provider::{variants::Mldsa87, PqProvider, PublicKey, SignOptions, Signature},
    HashAlgorithm, Primitives,
};
use synergy_aegis::ApqeIdentityVerifier;
use synergy_identity::authorization::{
    canonical_binding_commitment_if_present, IdentityAuthorizationCarrier,
};
use synergy_posy::FinalizedBlockRecord;
use synergy_state::{
    state_root, AccountChange, FinalizedState, ProtocolChange, StateDiff, WorldState,
};

#[cfg(test)]
#[path = "protected_funding.rs"]
mod funding;

const COMMIT_PREFIX: &str = "apqe-protected-account-candidate/v1/commit/";
const ACCOUNT_PREFIX: &str = "apqe-protected-account-candidate/v1/policy/";
const TRANSITION_PREFIX: &str = "apqe-protected-account-candidate/v1/transition/";
const TRANSITION_DUE_PREFIX: &str = "apqe-protected-account-candidate/v1/transition-due/";
const MAX_ENROLLMENT_BYTES: usize = 24 * 1024;
// Internal bounded state values, not RPC or consensus-action wire assignments.
const MAX_STORED_POLICY_BYTES: usize = (MAX_ENROLLMENT_BYTES + 10 * 1024) * 4 + 4096;
const MAX_STORED_COMMIT_BYTES: usize = 1024;
const SPONSOR_SIGNATURE_DOMAIN: &str = "AEGIS/ENROLL-SPONSOR/v1";
const SPONSOR_CONTEXT: &[u8] = b"AEGIS.ENROLL.SPONSOR.V1";
const SPONSOR_PURPOSE: &str = "protected-enrollment-sponsorship";

pub(super) struct SponsorProof<'a> {
    pub(super) intent: &'a [u8],
    pub(super) binding: &'a IdentityAuthorizationCarrier,
    pub(super) signing_key: &'a PublicKey<Mldsa87>,
    pub(super) signature: &'a Signature<Mldsa87>,
}

struct PreparedSponsorFee {
    diff: StateDiff,
    payer: String,
    nonce: u64,
    signed_digest: String,
    fee: u128,
}

fn sponsor_digest(encoded: &[u8]) -> Result<Vec<u8>, String> {
    let mut hash = Primitives
        .hash_stream(HashAlgorithm::Sha3512)
        .map_err(debug)?;
    hash.update(SPONSOR_SIGNATURE_DOMAIN.as_bytes());
    hash.update(encoded);
    Ok(hash.finalize())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Network {
    native_chain: [u8; 32],
    genesis: [u8; 32],
    ownership_chain: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommitRecord {
    network: Network,
    commitment: [u8; 32],
    included_height: u64,
    consensus_time: u64,
    consumed: bool,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyRecord {
    network: Network,
    account: [u8; 20],
    policy_epoch: u64,
    policy_hash: [u8; 32],
    enrollment: Vec<u8>,
    registered_height: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    replacement_policy: Option<Vec<u8>>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScheduledPolicyChange {
    network: Network,
    account: [u8; 20],
    reference: [u8; 32],
    old_epoch: u64,
    old_hash: [u8; 32],
    new_hash: [u8; 32],
    policy: Vec<u8>,
    activation_at: u64,
    included_height: u64,
    included_time: u64,
    replace: u8,
}

impl ScheduledPolicyChange {
    fn due_entry(&self, mode: transition_queue::TransitionMode) -> transition_queue::DueTransition {
        transition_queue::DueTransition {
            account: AccountIdentifier::from_bytes(self.account),
            activation_at: self.activation_at,
            reference: self.reference,
            mode,
        }
    }

    #[cfg(test)]
    fn activation_outcome(
        &self,
        mode: transition_queue::TransitionMode,
        finalized: &FinalizedSnapshot<'_>,
        included: Position,
        next_epoch: u64,
    ) -> TransitionExecutionOutcome {
        TransitionExecutionOutcome {
            transition: self.due_entry(mode),
            kind: TransitionOutcomeKind::Activated,
            source_finalized_height: finalized.position.height,
            included,
            old_policy_epoch: self.old_epoch,
            resulting_policy_epoch: next_epoch,
            old_policy_hash: self.old_hash,
            resulting_policy_hash: self.new_hash,
            signed_charge: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum TransitionOutcomeKind {
    Canceled,
    Vetoed,
    Activated,
}

// Execution-owned candidate outcome staged in the same World diff as its effects.
// Readback is authenticated by an independently verified World root.
#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
struct TransitionExecutionOutcome {
    transition: transition_queue::DueTransition,
    kind: TransitionOutcomeKind,
    source_finalized_height: u64,
    included: Position,
    old_policy_epoch: u64,
    resulting_policy_epoch: u64,
    old_policy_hash: [u8; 32],
    resulting_policy_hash: [u8; 32],
    signed_charge: Option<SignedTransitionCharge>,
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
struct SignedTransitionCharge {
    action: u16,
    intent_id: [u8; 32],
    signed_digest: [u8; 64],
    gas_used: u64,
    fee_nwei: u128,
    nonce_before: u64,
    nonce_after: u64,
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn apply_transition_termination(
    pending: &ScheduledPolicyChange,
    mode: transition_queue::TransitionMode,
    kind: TransitionOutcomeKind,
    finalized: &FinalizedSnapshot<'_>,
    included: Position,
    intent: &CanonicalNativeIntent<'_>,
    fee: &synergy_execution::FeeSchedule,
    gas_used: u64,
    removals: [ProtocolChange; 2],
    world: &mut WorldState,
) -> Result<TransitionExecutionOutcome, String> {
    let body = intent.body();
    let (mut diff, fee_nwei) = engineering_policy_fee(body, fee, gas_used)?;
    let signed_charge = SignedTransitionCharge {
        action: body.action_type,
        intent_id: body.intent_id,
        signed_digest: *intent.digest().map_err(display)?.as_bytes(),
        gas_used,
        fee_nwei,
        nonce_before: body.transaction_nonce,
        nonce_after: body
            .transaction_nonce
            .checked_add(1)
            .ok_or("protected nonce exhausted")?,
    };
    let outcome = TransitionExecutionOutcome {
        transition: pending.due_entry(mode),
        kind,
        source_finalized_height: finalized.position.height,
        included,
        old_policy_epoch: pending.old_epoch,
        resulting_policy_epoch: pending.old_epoch,
        old_policy_hash: pending.old_hash,
        resulting_policy_hash: pending.old_hash,
        signed_charge: Some(signed_charge),
    };
    diff.protocol_changes.extend(removals);
    diff.protocol_changes
        .push(transition_settlement::prepare_transition_settlement(
            finalized, &outcome,
        )?);
    diff.apply(world).map_err(debug)?;
    Ok(outcome)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Position {
    pub(super) height: u64,
    pub(super) consensus_time: u64,
}

pub(super) struct EnrollmentProofs<'a> {
    pub(super) ordinary: &'a [EnrollmentSignature; 2],
    pub(super) recovery: &'a EnrollmentSignature,
    pub(super) ownership: &'a [u8; 65],
    pub(super) salt: &'a [u8; 32],
}

#[cfg(test)]
enum TransferCandidateContent<'a> {
    PlaintextFixture(&'a [u8]),
    OpenedEtdag(
        &'a etdag_candidate::OpenedCandidateEnvelope,
        &'a transfer_admission::VerifiedTransferAdmission,
    ),
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
struct CandidateTransferExecution {
    fee_nwei: u128,
    revert_reason: Option<settlement::TransferRevertReason>,
}

/// Construct only with the exact PoSy-verified finality record and its
/// authenticated finalized state pointer. The record itself is not a QC proof.
pub(super) struct FinalizedSnapshot<'a> {
    registry: &'a CandidateProtectedAccounts<'a>,
    world: &'a WorldState,
    position: Position,
    #[cfg(test)]
    processing_finality_root: synergy_etdag::EtdagDigest,
}

impl FinalizedSnapshot<'_> {
    fn context(&self) -> FinalizedEnrollmentContext {
        FinalizedEnrollmentContext {
            genesis: self.registry.chain.native_genesis(),
            external_chain: self.registry.chain.chain_id(),
            height: self.position.height,
            consensus_time: self.position.consensus_time,
        }
    }
}

pub(super) struct CandidateProtectedAccounts<'a> {
    network: Network,
    chain: ExternalChainPolicy,
    wire: &'a UnactivatedWireProfile,
    verifier: CandidateEnrollmentVerifier,
}

impl<'a> CandidateProtectedAccounts<'a> {
    /// The caller selects authenticated native/ownership networks and provider
    /// manifest admissions independently of request bytes.
    pub(super) fn new(
        native_chain: ChainId,
        chain: ExternalChainPolicy,
        wire: &'a UnactivatedWireProfile,
        commitment_profile: UnactivatedCommitmentProfile,
        admitted_provider_manifests: Vec<[u8; 32]>,
    ) -> Result<Self, String> {
        let network = Network {
            native_chain: *native_chain.as_be_bytes(),
            genesis: *chain.native_genesis().as_bytes(),
            ownership_chain: *chain.chain_id().as_be_bytes(),
        };
        if network.native_chain == [0; 32] || network.genesis == [0; 32] {
            return Err("invalid authenticated protected account network".into());
        }
        let verifier = CandidateEnrollmentVerifier::new(
            chain.native_genesis(),
            chain.chain_id(),
            wire,
            commitment_profile,
            admitted_provider_manifests,
        )
        .map_err(display)?;
        Ok(Self {
            network,
            chain,
            wire,
            verifier,
        })
    }

    pub(super) fn require_activation(&self) -> Result<(), RegistryError> {
        self.verifier.require_activation()
    }

    pub(super) fn finalized_snapshot<'s>(
        &'s self,
        world: &'s WorldState,
        durable: &FinalizedState,
        verified_finality: &FinalizedBlockRecord,
        consensus_time: u64,
    ) -> Result<FinalizedSnapshot<'s>, String> {
        if durable.finalized_height == 0
            || consensus_time == 0
            || durable.finalized_height != verified_finality.height
            || durable.finalized_block_id != verified_finality.block_id
            || !synergy_posy::is_hash(&verified_finality.block_id)
            || !synergy_posy::is_hash(&verified_finality.finality_certificate_id)
            || state_root(world).map_err(debug)? != durable.state_root
        {
            return Err("protected account snapshot does not match verified finality".into());
        }
        Ok(FinalizedSnapshot {
            registry: self,
            world,
            position: Position {
                height: durable.finalized_height,
                consensus_time,
            },
            #[cfg(test)]
            processing_finality_root: super::authority::processing_finality_root(verified_finality)?,
        })
    }

    /// Stage an authenticated action's commitment in the candidate World. Only
    /// PoSy's existing finalization path may make that World eligible for reveal.
    /// Fee authorization, quota and sponsorship policy are separate prerequisites.
    pub(super) fn prepare_commit(
        &self,
        world: &WorldState,
        commitment: EnrollmentCommitment,
        inclusion: Position,
    ) -> Result<StateDiff, String> {
        if inclusion.height == 0
            || inclusion.consensus_time == 0
            || commitment.as_bytes() == &[0; 32]
        {
            return Err("invalid protected enrollment commitment position or hash".into());
        }
        let key = commit_key(commitment);
        if world.protocol.contains_key(&key) {
            return Err("protected enrollment commitment already recorded".into());
        }
        Ok(StateDiff {
            protocol_changes: vec![ProtocolChange {
                key,
                expected_value: None,
                value: Some(encode(&CommitRecord {
                    network: self.network,
                    commitment: *commitment.as_bytes(),
                    included_height: inclusion.height,
                    consensus_time: inclusion.consensus_time,
                    consumed: false,
                })?),
            }],
            ..StateDiff::default()
        })
    }

    /// Engineering-only admission/fee preparation. Identity scope, intent
    /// signature and a spendable fee must all pass before staging any debit.
    #[allow(clippy::too_many_arguments)]
    fn prepare_sponsor_fee(
        &self,
        provider: &PqProvider<Mldsa87>,
        identity_verifier: &ApqeIdentityVerifier,
        network_id: &str,
        finalized: &FinalizedSnapshot<'_>,
        world: &WorldState,
        inclusion: Position,
        action: u16,
        action_payload: &[u8],
        proof: &SponsorProof<'_>,
        fee_schedule: &synergy_execution::FeeSchedule,
        gas_used: u64,
    ) -> Result<PreparedSponsorFee, String> {
        use super::protected_action_wire::decode_sponsor;
        let sponsor = decode_sponsor(proof.intent)?;
        if !std::ptr::eq(self, finalized.registry)
            || inclusion.height <= finalized.position.height
            || inclusion.consensus_time < finalized.position.consensus_time
            || sponsor.genesis != self.network.genesis
            || sponsor.valid_until < finalized.position.height
            || sponsor.action != action
            || sponsor.payload_hash.as_slice()
                != Primitives
                    .hash(HashAlgorithm::Sha3256, action_payload)
                    .map_err(debug)?
        {
            return Err(
                "sponsor intent not bound to this finalized network, action or expiry".into(),
            );
        }
        let payer = self.verify_sponsor_binding(
            identity_verifier, network_id, finalized, world, sponsor.payer, proof.binding,
            proof.signing_key,
        )?;
        let signed_digest = sponsor_digest(proof.intent)?;
        provider
            .verify(
                &signed_digest,
                proof.signature,
                proof.signing_key,
                SignOptions::Pure {
                    context: SPONSOR_CONTEXT,
                },
            )
            .map_err(debug)?;
        fee_schedule.validate().map_err(debug)?;
        let fee = u128::from(gas_used) * u128::from(fee_schedule.base_fee_per_gas_nwei);
        if gas_used == 0
            || fee_schedule.collector == payer
            || fee_schedule.collector.starts_with("synw")
            || (sponsor.max_fee[..16] == [0; 16] && sponsor.max_fee[16..] < fee.to_be_bytes()[..])
            || !world.accounts.get(&payer).is_some_and(|account| {
                account.code_hash.is_none()
                    && account.nonce == sponsor.nonce
                    && account.nonce < u64::MAX
                    && account.balance_nwei >= fee
            })
        {
            return Err("sponsor nonce, funds or fee cap insufficient".into());
        }
        Ok(PreparedSponsorFee {
            diff: StateDiff {
                changes: vec![
                    AccountChange {
                        account: payer.clone(),
                        debit_nwei: fee,
                        credit_nwei: 0,
                        expected_nonce: Some(sponsor.nonce),
                        code_hash: None,
                    },
                    AccountChange {
                        account: fee_schedule.collector.clone(),
                        debit_nwei: 0,
                        credit_nwei: fee,
                        expected_nonce: None,
                        code_hash: None,
                    },
                ],
                ..StateDiff::default()
            },
            payer,
            nonce: sponsor.nonce,
            signed_digest: inspection::hex_bytes(&signed_digest),
            fee,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_sponsor_binding(
        &self,
        identity_verifier: &ApqeIdentityVerifier,
        network_id: &str,
        finalized: &FinalizedSnapshot<'_>,
        world: &WorldState,
        payer: &str,
        binding: &IdentityAuthorizationCarrier,
        key: &PublicKey<Mldsa87>,
    ) -> Result<String, String> {
        if self.network.native_chain[..24] != [0; 24]
            || synergy_address::decode_address(payer)?.hrp != "syna"
        {
            return Err("unsupported sponsor network or address".into());
        }
        let chain_id = u64::from_be_bytes(self.network.native_chain[24..].try_into().unwrap());
        let commitment = canonical_binding_commitment_if_present(&finalized.world.protocol, payer)?
            .ok_or("sponsor is not registered in finalized state")?;
        if canonical_binding_commitment_if_present(&world.protocol, payer)?.as_ref() != Some(&commitment) {
            return Err("sponsor binding changed in execution state".into());
        }
        let authorized = binding.identity_address_for_key_for_admission_at_with_verifier(
            SPONSOR_SIGNATURE_DOMAIN,
            chain_id,
            network_id,
            "ML-DSA-87",
            key.as_bytes(),
            SPONSOR_PURPOSE,
            finalized.position.consensus_time,
            &commitment.binding_payload_sha3_256,
            Some(identity_verifier),
        )?;
        if authorized != payer
            || binding.binding.identity_root.public_key_sha3_256 != commitment.identity_root_public_key_sha3_256
            || commitment.effective_at_unix > finalized.position.consensus_time
        {
            return Err("sponsor payer differs from finalized binding".into());
        }
        Ok(authorized)
    }

    /// No network routes call this candidate. A paid deterministic duplicate
    /// has an explicit outcome; signing/fee/wire errors never enter settlement.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn execute_sponsored_commit(
        &self,
        provider: &PqProvider<Mldsa87>,
        identity_verifier: &ApqeIdentityVerifier,
        network_id: &str,
        finalized: &FinalizedSnapshot<'_>,
        world: &mut WorldState,
        inclusion: Position,
        payload: &[u8],
        proof: &SponsorProof<'_>,
        fee_schedule: &synergy_execution::FeeSchedule,
        gas_used: u64,
        opening: Option<&settlement::EngineeringEtdagOpening>,
    ) -> Result<(bool, u128), String> {
        use super::protected_action_wire::{decode, Payload, ENROLL_COMMIT};
        use sponsor_settlement::{prepare_sponsor_settlement, SponsoredOutcome};
        let Payload::Commit(hash) = decode(ENROLL_COMMIT, payload)? else {
            return Err("expected enrollment commitment".into());
        };
        let mut fee = self.prepare_sponsor_fee(
            provider,
            identity_verifier,
            network_id,
            finalized,
            world,
            inclusion,
            ENROLL_COMMIT,
            payload,
            proof,
            fee_schedule,
            gas_used,
        )?;
        let commitment = EnrollmentCommitment::from_bytes(hash);
        let existing = world.protocol.get(&commit_key(commitment));
        let applied = existing.is_none();
        let (commit, outcome) = if let Some(bytes) = existing {
            let record = self.decode_commitment(bytes, commitment)?;
            if record.included_height > inclusion.height
                || record.consensus_time > inclusion.consensus_time
            {
                return Err("duplicate commitment has a future inclusion position".into());
            }
            (StateDiff::default(), SponsoredOutcome::DuplicatePaidCommit)
        } else {
            (
                self.prepare_commit(world, commitment, inclusion)?,
                SponsoredOutcome::CommitApplied,
            )
        };
        let settlement = prepare_sponsor_settlement(
            finalized,
            world,
            &fee.payer,
            &fee.signed_digest,
            hash,
            outcome,
            gas_used,
            fee.fee,
            fee.nonce,
            inclusion,
            opening,
        )?;
        fee.diff.protocol_changes.push(settlement);
        StateDiff::apply_ordered_atomic(&[&commit, &fee.diff], world).map_err(debug)?;
        Ok((applied, fee.fee))
    }

    /// Execute inside the ordered candidate block. Validate enrollment against
    /// its finalized parent before classifying an exact earlier reveal as a
    /// paid revert. Any other failed write leaves both parties unchanged.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn execute_sponsored_reveal(
        &self,
        provider: &PqProvider<Mldsa87>,
        identity_verifier: &ApqeIdentityVerifier,
        network_id: &str,
        finalized: &FinalizedSnapshot<'_>,
        world: &mut WorldState,
        inclusion: Position,
        payload: &[u8],
        sponsor: &SponsorProof<'_>,
        proofs: EnrollmentProofs<'_>,
        fee_schedule: &synergy_execution::FeeSchedule,
        gas_used: u64,
        opening: Option<&settlement::EngineeringEtdagOpening>,
    ) -> Result<(sponsor_settlement::SponsoredOutcome, u128), String> {
        use super::protected_action_wire::{decode, Payload, ENROLL_REVEAL};
        use sponsor_settlement::{prepare_sponsor_settlement, SponsoredOutcome};
        let Payload::Reveal { enrollment, salt } = decode(ENROLL_REVEAL, payload)? else {
            return Err("expected enrollment reveal".into());
        };
        if proofs.salt != &salt {
            return Err("enrollment salt differs from the signed reveal payload".into());
        }
        let fee = self.prepare_sponsor_fee(
            provider,
            identity_verifier,
            network_id,
            finalized,
            world,
            inclusion,
            ENROLL_REVEAL,
            payload,
            sponsor,
            fee_schedule,
            gas_used,
        )?;
        let write = self.prepare_reveal(
            provider,
            finalized,
            finalized.world,
            inclusion,
            enrollment,
            proofs,
        )?;
        write.check_fee(world, &fee.diff)?;
        let (outcome, business) = if world.accounts.contains_key(&write.address)
            && write
                .diff
                .protocol_changes
                .iter()
                .all(|change| world.protocol.get(&change.key) == change.value.as_ref())
        {
            // The same commitment and initial policy were applied earlier in
            // this block. The registration height is part of the policy bytes.
            (
                SponsoredOutcome::RevealRevertedCommitUsed,
                StateDiff::default(),
            )
        } else {
            (SponsoredOutcome::RevealApplied, write.diff)
        };
        let settlement = StateDiff {
            protocol_changes: vec![prepare_sponsor_settlement(
                finalized,
                world,
                &fee.payer,
                &fee.signed_digest,
                write.commitment,
                outcome,
                gas_used,
                fee.fee,
                fee.nonce,
                inclusion,
                opening,
            )?],
            ..StateDiff::default()
        };
        StateDiff::apply_ordered_atomic(&[&business, &fee.diff, &settlement], world)
            .map_err(debug)?;
        Ok((outcome, fee.fee))
    }

    /// The finalized snapshot is independent of the working proposal overlay:
    /// an unfinalized or same-block commitment cannot authorize a reveal.
    pub(super) fn prepare_reveal(
        &self,
        provider: &PqProvider<Mldsa87>,
        finalized: &FinalizedSnapshot<'_>,
        world: &WorldState,
        inclusion: Position,
        enrollment_bytes: &[u8],
        proofs: EnrollmentProofs<'_>,
    ) -> Result<CandidateEnrollmentWrite, String> {
        if !std::ptr::eq(self, finalized.registry)
            || inclusion.height <= finalized.position.height
            || inclusion.consensus_time < finalized.position.consensus_time
        {
            return Err("protected reveal requires the selected finalized parent".into());
        }
        let context = finalized.context();
        let enrollment =
            CanonicalEnrollment::decode(enrollment_bytes, self.wire).map_err(display)?;
        let verified = enrollment
            .verify_candidate_for_selected_chain(
                provider,
                proofs.ordinary,
                proofs.recovery,
                &self.chain,
                proofs.ownership,
                inclusion.consensus_time,
            )
            .map_err(display)?;
        let commitment = self
            .verifier
            .reveal_commitment(&verified, proofs.salt, context)
            .map_err(display)?;
        let (expected, commit) = self.pending_commit(finalized.world, commitment)?;
        if inclusion
            .consensus_time
            .checked_sub(commit.consensus_time)
            .is_none_or(|age| age >= REVEAL_WINDOW_SECONDS)
        {
            return Err("protected reveal expired before candidate inclusion".into());
        }
        let pending = PendingEnrollmentCommitment::from_authenticated_finalized_state(
            self.chain.native_genesis(),
            commitment,
            commit.included_height,
            commit.consensus_time,
        );
        let (checked_pending, checked_context, record) = self
            .verifier
            .prepare_registration(&verified, proofs.salt, pending, context)
            .map_err(display)?
            .into_parts();
        if checked_pending != pending
            || checked_context != context
            || record.genesis() != context.genesis
            || record.external_chain() != context.external_chain
            || record.registration_height() != context.height
            || record.transaction_nonce() != 0
        {
            return Err("APQE protected write set does not match selected state".into());
        }
        self.prepare_registry_insert(
            world,
            expected,
            commit,
            PolicyRecord {
                network: self.network,
                account: *record.account().as_bytes(),
                policy_epoch: record.policy_epoch(),
                policy_hash: *record.policy_hash(),
                enrollment: record.enrollment_bytes().to_vec(),
                registered_height: inclusion.height,
                replacement_policy: None,
            },
        )
    }

    fn pending_commit<'s>(
        &self,
        world: &'s WorldState,
        commitment: EnrollmentCommitment,
    ) -> Result<(&'s [u8], CommitRecord), String> {
        let bytes = world
            .protocol
            .get(&commit_key(commitment))
            .ok_or("protected enrollment commitment missing from finalized state")?;
        let record = self.decode_commitment(bytes, commitment)?;
        if record.consumed {
            return Err("protected enrollment commitment is used".into());
        }
        Ok((bytes, record))
    }

    fn decode_commitment(
        &self,
        bytes: &[u8],
        commitment: EnrollmentCommitment,
    ) -> Result<CommitRecord, String> {
        let record: CommitRecord = decode(bytes, MAX_STORED_COMMIT_BYTES)?;
        if encode(&record)? != bytes
            || record.network != self.network
            || record.commitment != *commitment.as_bytes()
            || record.commitment == [0; 32]
            || record.included_height == 0
            || record.consensus_time == 0
        {
            return Err("protected enrollment commitment is malformed or mismatched".into());
        }
        Ok(record)
    }

    fn prepare_registry_insert(
        &self,
        world: &WorldState,
        expected_commit_bytes: &[u8],
        pending: CommitRecord,
        policy: PolicyRecord,
    ) -> Result<CandidateEnrollmentWrite, String> {
        let account = AccountIdentifier::from_bytes(policy.account);
        let address = account.to_native(&Primitives).map_err(display)?;
        let account_key = account_key(account);
        let commit_key = commit_key(EnrollmentCommitment::from_bytes(pending.commitment));
        if world.protocol.contains_key(&account_key)
            || world.protocol.get(&commit_key).map(Vec::as_slice) != Some(expected_commit_bytes)
            || !eligible_account(world, &address)
        {
            return Err("protected account exists or registration state changed".into());
        }
        Ok(CandidateEnrollmentWrite {
            address: address.clone(),
            commitment: pending.commitment,
            diff: StateDiff {
                changes: vec![AccountChange {
                    account: address,
                    debit_nwei: 0,
                    credit_nwei: 0,
                    expected_nonce: None,
                    code_hash: None,
                }],
                protocol_changes: vec![
                    ProtocolChange {
                        key: commit_key,
                        expected_value: Some(expected_commit_bytes.to_vec()),
                        value: Some(encode(&CommitRecord {
                            consumed: true,
                            ..pending
                        })?),
                    },
                    ProtocolChange {
                        key: account_key,
                        expected_value: None,
                        value: Some(encode(&policy)?),
                    },
                ],
            },
        })
    }

    fn read_policy(
        &self,
        world: &WorldState,
        account: AccountIdentifier,
    ) -> Result<PolicyRecord, String> {
        let bytes = world
            .protocol
            .get(&account_key(account))
            .ok_or("protected account not registered")?;
        let record: PolicyRecord = decode(bytes, MAX_STORED_POLICY_BYTES)?;
        if encode(&record)? != *bytes
            || record.network != self.network
            || record.account != *account.as_bytes()
            || record.registered_height == 0
        {
            return Err("protected account registration network or identifier mismatch".into());
        }
        Ok(record)
    }

    fn canonical_policy<'p>(
        &self,
        record: &'p PolicyRecord,
        enrollment: &'p CanonicalEnrollment<'_>,
    ) -> Result<CanonicalPublicPolicy<'p>, String> {
        let bytes = match &record.replacement_policy {
            Some(policy) if record.policy_epoch > enrollment.policy().policy_epoch => {
                policy.as_slice()
            }
            None if record.policy_epoch == enrollment.policy().policy_epoch => {
                enrollment.canonical_policy()
            }
            _ => return Err("protected policy epoch has no matching policy source".into()),
        };
        let policy = CanonicalPublicPolicy::decode(bytes, self.wire).map_err(display)?;
        if enrollment.genesis() != self.chain.native_genesis()
            || enrollment.account().as_bytes() != &record.account
            || policy.policy().genesis != enrollment.genesis()
            || policy.policy().account != enrollment.account()
            || &policy.policy().evm_public_key != enrollment.evm_public_key()
            || policy.policy().policy_epoch != record.policy_epoch
            || policy.hash().map_err(display)? != record.policy_hash
        {
            return Err("protected account policy does not match its canonical state".into());
        }
        Ok(policy)
    }

    /// Verifies only a candidate spend's signatures and current nonce/policy.
    /// The caller must supply the selected action decoder; no action assignment
    /// or fee semantics are inferred from an unsigned label. A returned quorum
    /// is not permission to execute or publish a receipt.
    pub(super) fn verify_spend<T>(
        &self,
        provider: &PqProvider<Mldsa87>,
        finalized: &FinalizedSnapshot<'_>,
        world: &WorldState,
        encoded_intent: &[u8],
        max_action_payload: usize,
        decode_selected_spend: impl FnOnce(&NativeIntentBody<'_>) -> Result<T, String>,
        signatures: &[RoleSignature; 2],
    ) -> Result<(T, VerifiedSignatureQuorum), String> {
        self.verify_native_pair(
            provider,
            finalized,
            world,
            encoded_intent,
            max_action_payload,
            signatures,
            |body| decode_selected_spend(body).map(|data| (data, NativeAction::Spend)),
            finalized.position.consensus_time,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_native_pair<'i, T>(
        &self,
        provider: &PqProvider<Mldsa87>,
        finalized: &FinalizedSnapshot<'_>,
        world: &WorldState,
        encoded_intent: &'i [u8],
        max_action_payload: usize,
        signatures: &[RoleSignature; 2],
        decode: impl FnOnce(&NativeIntentBody<'i>) -> Result<(T, NativeAction), String>,
        consensus_time: u64,
    ) -> Result<(T, VerifiedSignatureQuorum), String> {
        let intent =
            CanonicalNativeIntent::decode(encoded_intent, max_action_payload).map_err(display)?;
        let body = intent.body();
        let (state, policy) =
            self.current_native_authority(finalized, world, body.account, consensus_time)?;
        intent.check_state(&state).map_err(display)?;
        let (decoded, action) = decode(body)?;
        let digest = intent.digest().map_err(display)?;
        let transcript = CallerValidatedTranscript::from_caller_validated_digest(
            &digest,
            NATIVE_TX_CONTEXT,
            IntentConstraints {
                network_account: state.network_account,
                policy_epoch: body.policy_epoch,
                nonce: body.transaction_nonce,
                valid_from_height: 0, // The published outer body only signs the upper bound.
                valid_until_height: body.valid_until_finalized_height,
                action,
            },
        );
        let quorum = verify_signature_quorum_for_caller_validated_transcript(
            provider,
            &policy,
            &state,
            &transcript,
            signatures,
        )
        .map_err(display)?;
        Ok((decoded, quorum))
    }

    fn current_native_authority(
        &self,
        finalized: &FinalizedSnapshot<'_>,
        world: &WorldState,
        account: AccountIdentifier,
        consensus_time: u64,
    ) -> Result<(CurrentAccountState, NativePolicy), String> {
        if !std::ptr::eq(self, finalized.registry) {
            return Err("protected intent requires the selected finalized parent".into());
        }
        let record = self.read_policy(finalized.world, account)?;
        if record != self.read_policy(world, account)?
            || record.registered_height > finalized.position.height
        {
            return Err("protected policy changed or is not finalized".into());
        }
        let enrollment =
            CanonicalEnrollment::decode(&record.enrollment, self.wire).map_err(display)?;
        let current = self.canonical_policy(&record, &enrollment)?;
        let address = account.to_native(&Primitives).map_err(display)?;
        let ledger = world
            .accounts
            .get(&address)
            .ok_or("protected ledger account missing")?;
        if ledger.code_hash.is_some() {
            return Err("protected account has conflicting executable state".into());
        }
        let state = CurrentAccountState {
            network_account: NativeAccountCoordinate {
                chain_id: ChainId::from_be_bytes(self.network.native_chain),
                genesis: self.chain.native_genesis(),
                account,
            },
            policy_epoch: record.policy_epoch,
            next_nonce: ledger.nonce,
            height: finalized.position.height,
            consensus_time,
            recovery_vetoed: false, // External-share recovery remains disabled.
        };
        let [d, p, r] = current.policy().roles;
        let enrolled =
            |role, registered: synergy_address_engine::apqe::enrollment::RoleRecord<'_>| {
                Ok::<_, String>(EnrolledRole {
                    role,
                    participant_id: registered.participant_id,
                    public_key: PublicKey::from_bytes(registered.auth_public_key).map_err(debug)?,
                })
            };
        let policy = NativePolicy::from_authenticated_enrollment(
            state.network_account,
            record.policy_epoch,
            record.policy_hash,
            [
                enrolled(Role::D, d)?,
                enrolled(Role::P, p)?,
                enrolled(Role::R, r)?,
            ],
        )
        .map_err(display)?;
        Ok((state, policy))
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn schedule_ordinary_replacement(
        &self,
        provider: &PqProvider<Mldsa87>,
        finalized: &FinalizedSnapshot<'_>,
        world: &mut WorldState,
        inclusion: Position,
        encoded: &[u8],
        signatures: &[RoleSignature; 2],
        possession: &Signature<Mldsa87>,
        fee: &synergy_execution::FeeSchedule,
        gas: u64,
    ) -> Result<[u8; 32], String> {
        use super::protected_action_wire::{decode, Payload, MAX_POLICY, POLICY_SCHEDULE};
        use synergy_address_engine::apqe::policy_transition::{
            check_policy_replacement, PolicyReplacementRequest, ReplacementMode,
        };
        if inclusion.height <= finalized.position.height
            || inclusion.consensus_time < finalized.position.consensus_time
        {
            return Err("invalid policy scheduling position".into());
        }
        let limit = MAX_POLICY + 128;
        let intent = CanonicalNativeIntent::decode(encoded, limit).map_err(display)?;
        let body = intent.body();
        let (data, _) = self.verify_native_pair(
            provider,
            finalized,
            world,
            encoded,
            limit,
            signatures,
            |body| {
                if body.action_type != POLICY_SCHEDULE {
                    return Err("expected POLICY_CHANGE_SCHEDULE".into());
                }
                let data = decode(POLICY_SCHEDULE, body.action_payload)?;
                let Payload::Schedule { activation_at, .. } = data else {
                    return Err("expected policy change payload".into());
                };
                Ok((data, NativeAction::RoutinePolicyChange { activation_at }))
            },
            inclusion.consensus_time,
        )?;
        let Payload::Schedule {
            role,
            old_policy,
            new_policy,
            new_policy_hash,
            activation_at,
            ..
        } = data
        else {
            return Err("invalid policy schedule".into());
        };
        let record = self.read_policy(world, body.account)?;
        let enrollment =
            CanonicalEnrollment::decode(&record.enrollment, self.wire).map_err(display)?;
        let current = self.canonical_policy(&record, &enrollment)?;
        let proposed = CanonicalPublicPolicy::decode(new_policy, self.wire).map_err(display)?;
        let replace = if role == 0 { Role::D } else { Role::P };
        let checked = check_policy_replacement(
            &current,
            &proposed,
            PolicyReplacementRequest {
                mode: ReplacementMode::Ordinary,
                replace,
                expected_old_policy_hash: old_policy,
                expected_new_policy_hash: new_policy_hash,
                activation_at,
            },
            inclusion.consensus_time,
        )
        .map_err(display)?;
        provider
            .verify(
                intent.digest().map_err(display)?.as_bytes(),
                possession,
                &PublicKey::from_bytes(
                    checked.proposed_policy().policy().roles[usize::from(role)].auth_public_key,
                )
                .map_err(debug)?,
                SignOptions::Pure {
                    context: b"AEGIS.NEW.ROLE.POP.V1",
                },
            )
            .map_err(debug)?;
        let mut hash = Primitives
            .hash_stream(HashAlgorithm::Sha3256)
            .map_err(debug)?;
        hash.update(b"AEGIS/PROTECTED-PENDING/v1");
        hash.update(encoded);
        let reference: [u8; 32] = hash
            .finalize()
            .try_into()
            .map_err(|_| "invalid pending digest length")?;
        let key = transition_key(body.account);
        let pending = ScheduledPolicyChange {
            network: self.network,
            account: *body.account.as_bytes(),
            reference,
            old_epoch: record.policy_epoch,
            old_hash: old_policy,
            new_hash: new_policy_hash,
            policy: new_policy.to_vec(),
            activation_at,
            included_height: inclusion.height,
            included_time: inclusion.consensus_time,
            replace: role,
        };
        let (mut diff, _) = engineering_policy_fee(body, fee, gas)?;
        diff.protocol_changes.push(
            pending
                .due_entry(transition_queue::TransitionMode::Ordinary)
                .insert()?,
        );
        diff.protocol_changes.push(ProtocolChange {
            key,
            expected_value: None,
            value: Some(encode(&pending)?),
        });
        diff.apply(world).map_err(debug)?;
        Ok(reference)
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn cancel_ordinary_replacement(
        &self,
        provider: &PqProvider<Mldsa87>,
        finalized: &FinalizedSnapshot<'_>,
        world: &mut WorldState,
        inclusion: Position,
        encoded: &[u8],
        signatures: &[RoleSignature; 2],
        fee: &synergy_execution::FeeSchedule,
        gas: u64,
    ) -> Result<TransitionExecutionOutcome, String> {
        use super::protected_action_wire::{decode, Payload, POLICY_CANCEL};
        if inclusion.height <= finalized.position.height
            || inclusion.consensus_time < finalized.position.consensus_time
        {
            return Err("invalid policy cancellation position".into());
        }
        let intent = CanonicalNativeIntent::decode(encoded, 40).map_err(display)?;
        let body = intent.body();
        let (reference, _) = self.verify_spend(
            provider,
            finalized,
            world,
            encoded,
            40,
            |body| match decode(body.action_type, body.action_payload)? {
                Payload::Pending(reference) if body.action_type == POLICY_CANCEL => Ok(reference),
                _ => Err("expected POLICY_CHANGE_CANCEL".into()),
            },
            signatures,
        )?;
        let key = transition_key(body.account);
        let bytes = world
            .protocol
            .get(&key)
            .ok_or("no pending ordinary policy change")?;
        let pending: ScheduledPolicyChange = decode_stored_policy_change(bytes)?;
        if encode(&pending)? != *bytes
            || pending.reference != reference
            || pending.network != self.network
            || pending.account != *body.account.as_bytes()
            || pending.old_epoch != body.policy_epoch
            || inclusion.consensus_time >= pending.activation_at
        {
            return Err("policy cancellation target, epoch or deadline differs".into());
        }
        use transition_queue::TransitionMode::Ordinary;
        let removals = [
            pending.due_entry(Ordinary).remove()?,
            ProtocolChange {
                key,
                expected_value: Some(bytes.clone()),
                value: None,
            },
        ];
        apply_transition_termination(
            &pending,
            Ordinary,
            TransitionOutcomeKind::Canceled,
            finalized,
            inclusion,
            &intent,
            fee,
            gas,
            removals,
            world,
        )
    }

    #[cfg(test)]
    fn activate_ordinary_replacement(
        &self,
        finalized: &FinalizedSnapshot<'_>,
        world: &mut WorldState,
        inclusion: Position,
        account: AccountIdentifier,
    ) -> Result<(), String> {
        let (_, plan) = self.prepare_ordinary_activation(finalized, world, inclusion, account)?;
        plan.apply(world).map_err(debug)
    }

    #[cfg(test)]
    fn prepare_ordinary_activation(
        &self,
        finalized: &FinalizedSnapshot<'_>,
        world: &WorldState,
        inclusion: Position,
        account: AccountIdentifier,
    ) -> Result<(TransitionExecutionOutcome, StateDiff), String> {
        use synergy_address_engine::apqe::policy_transition::{
            check_policy_replacement, PolicyReplacementRequest, ReplacementMode,
        };
        if !std::ptr::eq(self, finalized.registry)
            || inclusion.height <= finalized.position.height
            || inclusion.consensus_time < finalized.position.consensus_time
        {
            return Err("invalid policy activation position".into());
        }
        let key = transition_key(account);
        let bytes = finalized
            .world
            .protocol
            .get(&key)
            .ok_or("policy schedule not finalized")?;
        let pending = decode_stored_policy_change(bytes)?;
        if encode(&pending)? != *bytes
            || world.protocol.get(&key) != Some(bytes)
            || pending.network != self.network
            || pending.account != *account.as_bytes()
            || !(1..=finalized.position.height).contains(&pending.included_height)
            || !(1..=finalized.position.consensus_time).contains(&pending.included_time)
            || pending.activation_at > inclusion.consensus_time
        {
            return Err("policy schedule not eligible at this activation position".into());
        }
        let mut record = self.read_policy(finalized.world, account)?;
        let address = account.to_native(&Primitives).map_err(display)?;
        if record != self.read_policy(world, account)?
            || record.policy_epoch != pending.old_epoch
            || record.policy_hash != pending.old_hash
            || !world
                .accounts
                .get(&address)
                .is_some_and(|a| a.code_hash.is_none())
        {
            return Err("activation policy changed or ledger account unavailable".into());
        }
        let policy = CanonicalPublicPolicy::decode(&pending.policy, self.wire).map_err(display)?;
        {
            let enrollment =
                CanonicalEnrollment::decode(&record.enrollment, self.wire).map_err(display)?;
            let current = self.canonical_policy(&record, &enrollment)?;
            let replace = match pending.replace {
                0 => Role::D,
                1 => Role::P,
                _ => return Err("invalid recorded replacement role".into()),
            };
            let _checked = check_policy_replacement(
                &current,
                &policy,
                PolicyReplacementRequest {
                    mode: ReplacementMode::Ordinary,
                    replace,
                    expected_old_policy_hash: pending.old_hash,
                    expected_new_policy_hash: pending.new_hash,
                    activation_at: pending.activation_at,
                },
                pending.included_time,
            )
            .map_err(display)?;
        }
        let policy_key = account_key(account);
        let expected = world.protocol.get(&policy_key).cloned();
        record.policy_epoch = policy.policy().policy_epoch;
        let outcome = pending.activation_outcome(
            transition_queue::TransitionMode::Ordinary,
            finalized,
            inclusion,
            record.policy_epoch,
        );
        let due = outcome.transition;
        let settlement = transition_settlement::prepare_transition_settlement(finalized, &outcome)?;
        record.policy_hash = pending.new_hash;
        record.replacement_policy = Some(pending.policy);
        Ok((
            outcome,
            StateDiff {
                changes: vec![],
                protocol_changes: vec![
                    due.remove()?,
                    settlement,
                    ProtocolChange {
                        key,
                        expected_value: Some(bytes.clone()),
                        value: None,
                    },
                    ProtocolChange {
                        key: policy_key,
                        expected_value: expected,
                        value: Some(encode(&record)?),
                    },
                ],
            },
        ))
    }

    /// Process a bounded prefix of the finalized engineering deadline index
    /// before applying user actions. Continuity and live scheduling still
    /// require independently authorized protocol inputs.
    #[cfg(test)]
    fn apply_due_transitions_fixture(
        &self,
        finalized: &FinalizedSnapshot<'_>,
        world: &mut WorldState,
        inclusion: Position,
        visit_limit: usize,
    ) -> Result<Vec<TransitionExecutionOutcome>, String> {
        use transition_queue::TransitionMode;
        if !std::ptr::eq(self, finalized.registry)
            || inclusion.height <= finalized.position.height
            || inclusion.consensus_time < finalized.position.consensus_time
        {
            return Err("invalid protected scheduler position".into());
        }
        let due = transition_queue::due(finalized.world, inclusion.consensus_time, visit_limit)?;
        let mut activated = Vec::new();
        let mut batch = StateDiff::default();
        for entry in due {
            let index_key = entry.key();
            let pending_key = transition_key(entry.account);
            let expected = finalized
                .world
                .protocol
                .get(&pending_key)
                .ok_or("finalized deadline index has no matching pending transition")?;
            let pending = world.protocol.get(&pending_key);
            let index = world.protocol.get(&index_key);
            if pending.is_none() && index.is_none() {
                // A previous finalized or speculative canonical operation
                // removed both entries, including cancel and veto.
                continue;
            }
            if pending != Some(expected) || index != finalized.world.protocol.get(&index_key) {
                return Err("protected deadline index or pending transition changed".into());
            }
            let (prepared, plan) = match entry.mode {
                TransitionMode::Ordinary => {
                    self.prepare_ordinary_activation(finalized, world, inclusion, entry.account)?
                }
                TransitionMode::Recovery => self.prepare_recovery_activation_fixture(
                    finalized,
                    world,
                    inclusion,
                    entry.account,
                )?,
            };
            if prepared.transition != entry {
                return Err("deadline index differs from verified pending transition".into());
            }
            batch.protocol_changes.extend(plan.protocol_changes);
            activated.push(prepared);
        }
        batch.apply(world).map_err(debug)?;
        Ok(activated)
    }

    #[cfg(test)]
    fn require_finalized_recipient(
        &self,
        finalized: &FinalizedSnapshot<'_>,
        world: &WorldState,
        recipient: AccountIdentifier,
    ) -> Result<String, String> {
        if !std::ptr::eq(self, finalized.registry) {
            return Err("protected credit uses a different registry".into());
        }
        let record = self.read_policy(finalized.world, recipient)?;
        if record.registered_height > finalized.position.height
            || record != self.read_policy(world, recipient)?
        {
            return Err("invalid or unfinalized protected recipient".into());
        }
        let enrollment = CanonicalEnrollment::decode(&record.enrollment, self.wire)
            .map_err(display)?;
        self.canonical_policy(&record, &enrollment)?;
        let address = recipient.to_native(&Primitives).map_err(display)?;
        for source in [finalized.world, world] {
            if !source
                .accounts
                .get(&address)
                .is_some_and(|account| account.code_hash.is_none())
            {
                return Err("protected recipient ledger state is absent or invalid".into());
            }
        }
        Ok(address)
    }

    /// Candidate execution is test-only until an actual admission profile binds
    /// these bytes, verification rules and the fee schedule to consensus.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn execute_engineering_transfer(
        &self,
        provider: &PqProvider<Mldsa87>,
        finalized: &FinalizedSnapshot<'_>,
        world: &mut WorldState,
        action_content: TransferCandidateContent<'_>,
        fee_schedule: &synergy_execution::FeeSchedule,
        gas: u64,
        inclusion: Position,
    ) -> Result<CandidateTransferExecution, String> {
        use super::protected_action_wire::{decode_transfer, decode_transfer_content};
        use settlement::TransferRevertReason;
        const TRANSFER_MAX: usize = 60;
        let (decrypted_content, opened) = match action_content {
            TransferCandidateContent::PlaintextFixture(bytes) => (bytes, None),
            TransferCandidateContent::OpenedEtdag(opened, admission) => {
                (opened.plaintext(), Some((opened, admission)))
            }
        };
        let content = decode_transfer_content(decrypted_content)?;
        let intent =
            CanonicalNativeIntent::decode(content.intent, TRANSFER_MAX).map_err(display)?;
        let body = intent.body();
        let digest = intent.digest().map_err(display)?;
        let sender_record = self.read_policy(finalized.world, body.account)?;
        let sender_enrollment =
            CanonicalEnrollment::decode(&sender_record.enrollment, self.wire).map_err(display)?;
        let sender_policy = self.canonical_policy(&sender_record, &sender_enrollment)?;
        let build_proof = |index: usize, role: Role| -> Result<RoleSignature, String> {
            let supplied = &content.proofs[index];
            let registered = sender_policy.policy().roles[index];
            if supplied.participant_id != registered.participant_id
                || supplied.key_version != registered.key_version
                || &supplied.digest != digest.as_bytes()
            {
                return Err("transfer proof differs from canonical intent or enrolled role".into());
            }
            Ok(RoleSignature {
                role,
                signature: Signature::from_bytes(supplied.signature).map_err(debug)?,
            })
        };
        let signatures = [build_proof(0, Role::D)?, build_proof(1, Role::P)?];
        let ((recipient, amount), _) = self.verify_spend(
            provider,
            finalized,
            world,
            content.intent,
            TRANSFER_MAX,
            decode_transfer,
            &signatures,
        )?;
        if recipient == body.account {
            return Err("protected transfer cannot credit its sender".into());
        }
        let recipient_address = self.require_finalized_recipient(finalized, world, recipient)?;
        let sender = body.account.to_native(&Primitives).map_err(display)?;
        if let Some((opened, admission)) = opened {
            let envelope = opened.envelope();
            admission.verify_opened(finalized, &intent, envelope, opened.context(), fee_schedule, gas)?;
        }
        let opened_envelope = opened.map(|(opened, _)| opened.envelope());
        fee_schedule.validate().map_err(display)?;
        let fee = u128::from(gas) * u128::from(fee_schedule.base_fee_per_gas_nwei);
        if gas == 0
            || gas > body.gas_limit
            || fee_schedule.collector == sender
            || fee_schedule.collector == recipient_address
            || body.intent_id == [0; 32]
            || (body.maximum_total_fee[..16] == [0; 16]
                && body.maximum_total_fee[16..] < fee.to_be_bytes()[..])
        {
            return Err("protected transfer exceeds fee or gas authorization".into());
        }
        let debit = amount
            .checked_add(fee)
            .ok_or("protected transfer debit overflow")?;
        let available = world
            .accounts
            .get(&sender)
            .ok_or("protected sender ledger state is missing")?
            .balance_nwei;
        let revert_reason = if available < debit {
            Some(TransferRevertReason::InsufficientTransferBalance)
        } else if world.accounts[&recipient_address]
            .balance_nwei
            .checked_add(amount)
            .is_none()
        {
            Some(TransferRevertReason::RecipientBalanceOverflow)
        } else {
            None
        };
        // Check the original ID before reporting balance failures for an
        // operation whose recorded effects may have changed those balances.
        let settlement = settlement::prepare_transfer_settlement(
            finalized,
            world,
            &intent,
            decrypted_content,
            opened_envelope,
            recipient,
            amount,
            gas,
            fee,
            inclusion,
            revert_reason,
        )?;
        if available < fee {
            return Err("protected sender cannot settle the fee".into());
        }
        // A paid revert is reserved for execution against the ordered World
        // after the transfer was feasible at the certified source. Invalid
        // source balances or an unpayable fee do not enter this branch.
        if revert_reason.is_some()
            && (!finalized
                .world
                .accounts
                .get(&sender)
                .is_some_and(|account| {
                    account.code_hash.is_none() && account.balance_nwei >= debit
                })
                || finalized.world.accounts[&recipient_address]
                    .balance_nwei
                    .checked_add(amount)
                    .is_none())
        {
            return Err("protected transfer was infeasible at the finalized source".into());
        }
        let mut changes = vec![
            AccountChange {
                account: sender,
                debit_nwei: if revert_reason.is_some() { fee } else { debit },
                credit_nwei: 0,
                expected_nonce: Some(body.transaction_nonce),
                code_hash: None,
            },
            AccountChange {
                account: fee_schedule.collector.clone(),
                debit_nwei: 0,
                credit_nwei: fee,
                expected_nonce: None,
                code_hash: None,
            },
        ];
        if revert_reason.is_none() {
            changes.push(AccountChange {
                account: recipient_address,
                debit_nwei: 0,
                credit_nwei: amount,
                expected_nonce: None,
                code_hash: None,
            });
        }
        let diff = StateDiff {
            changes,
            protocol_changes: vec![settlement],
        };
        StateDiff::apply_ordered_atomic(&[&diff], world).map_err(debug)?;
        Ok(CandidateTransferExecution {
            fee_nwei: fee,
            revert_reason,
        })
    }
}

/// Keep unchecked writes private. A stale account, spent commit, existing policy
/// or failing approved fee diff must leave both the ledger and protocol untouched.
pub(super) struct CandidateEnrollmentWrite {
    address: String,
    commitment: [u8; 32],
    diff: StateDiff,
}

impl CandidateEnrollmentWrite {
    pub(super) fn apply_with_fee(
        self,
        world: &mut WorldState,
        authorized_fee_diff: &StateDiff,
    ) -> Result<(), String> {
        self.check_fee(world, authorized_fee_diff)?;
        StateDiff::apply_ordered_atomic(&[&self.diff, authorized_fee_diff], world).map_err(debug)
    }

    fn check_fee(&self, world: &WorldState, authorized_fee_diff: &StateDiff) -> Result<(), String> {
        if !eligible_account(world, &self.address)
            || authorized_fee_diff
                .changes
                .iter()
                .any(|change| change.account == self.address)
            || authorized_fee_diff.protocol_changes.iter().any(|change| {
                change.key.starts_with(ACCOUNT_PREFIX)
                    || change.key.starts_with(COMMIT_PREFIX)
                    || change.key.starts_with(TRANSITION_PREFIX)
                    || change.key.starts_with(TRANSITION_DUE_PREFIX)
                    || settlement::owns_key(&change.key)
                    || sponsor_settlement::owns_key(&change.key)
                    || transition_settlement::owns_key(&change.key)
            })
        {
            return Err("protected enrollment conflicts with existing state or fee writes".into());
        }
        Ok(())
    }
}

fn eligible_account(world: &WorldState, address: &str) -> bool {
    world
        .accounts
        .get(address)
        .is_none_or(|a| a.nonce == 0 && a.code_hash.is_none())
        && match synergy_identity::authorization::canonical_binding_commitment_if_present(
            &world.protocol,
            address,
        ) {
            Ok(None) => true,
            Ok(Some(_)) => false,
            Err(_) => !world.protocol.contains_key(
                synergy_identity::authorization::IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY,
            ),
        }
}

fn transition_key(account: AccountIdentifier) -> String {
    account_key(account).replacen(ACCOUNT_PREFIX, TRANSITION_PREFIX, 1)
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum PendingTransitionRecord {
    Ordinary(ScheduledPolicyChange),
    Recovery(recovery::PendingRecovery),
}

fn inspect_pending_transition(
    snapshot: &FinalizedSnapshot<'_>,
    account: AccountIdentifier,
) -> Result<serde_json::Value, String> {
    use synergy_address_engine::apqe::policy_transition::{
        check_policy_replacement, PolicyReplacementRequest, ReplacementMode,
    };
    use transition_queue::TransitionMode;
    let Some(bytes) = snapshot.world.protocol.get(&transition_key(account)) else {
        return Ok(serde_json::Value::Null);
    };
    let decoded: PendingTransitionRecord =
        decode(bytes, super::protected_action_wire::MAX_POLICY * 4 + 4096)?;
    if encode(&decoded)? != *bytes {
        return Err("pending transition record is not canonical".into());
    }
    let (change, mode, replacement_mode) = match &decoded {
        PendingTransitionRecord::Ordinary(change) => {
            (change, TransitionMode::Ordinary, ReplacementMode::Ordinary)
        }
        PendingTransitionRecord::Recovery(recovery) => {
            if recovery.continuity_reference == [0; 32] {
                return Err("pending recovery continuity reference is absent".into());
            }
            (
                &recovery.change,
                TransitionMode::Recovery,
                ReplacementMode::Recovery,
            )
        }
    };
    let registry = snapshot.registry;
    let active = registry.read_policy(snapshot.world, account)?;
    if change.network != registry.network
        || change.account != *account.as_bytes()
        || change.old_epoch != active.policy_epoch
        || change.old_hash != active.policy_hash
        || !(active.registered_height..=snapshot.position.height).contains(&change.included_height)
        || change.included_height == 0
        || !(1..=snapshot.position.consensus_time).contains(&change.included_time)
    {
        return Err("pending transition does not match the selected finalized account".into());
    }
    let replace = match change.replace {
        0 => Role::D,
        1 => Role::P,
        _ => return Err("pending transition replacement role is invalid".into()),
    };
    let enrollment =
        CanonicalEnrollment::decode(&active.enrollment, registry.wire).map_err(display)?;
    let current = registry.canonical_policy(&active, &enrollment)?;
    let proposed = CanonicalPublicPolicy::decode(&change.policy, registry.wire).map_err(display)?;
    let _validated = check_policy_replacement(
        &current,
        &proposed,
        PolicyReplacementRequest {
            mode: replacement_mode,
            replace,
            expected_old_policy_hash: change.old_hash,
            expected_new_policy_hash: change.new_hash,
            activation_at: change.activation_at,
        },
        change.included_time,
    )
    .map_err(display)?;
    change.due_entry(mode).verify_index(snapshot.world)?;
    Ok(serde_json::json!({
        "status": "scheduled_candidate",
        "mode": match mode { TransitionMode::Ordinary => "ordinary", TransitionMode::Recovery => "recovery" },
        "pending_reference": inspection::hex_bytes(&change.reference),
        "replaced_role": change.replace,
        "old_policy_epoch": change.old_epoch,
        "old_policy_hash": inspection::hex_bytes(&change.old_hash),
        "new_policy_hash": inspection::hex_bytes(&change.new_hash),
        "scheduled_height": change.included_height,
        "scheduled_consensus_timestamp_unix": change.included_time,
        "activation_timestamp_unix": change.activation_at,
    }))
}

#[cfg(test)]
fn decode_stored_policy_change(bytes: &[u8]) -> Result<ScheduledPolicyChange, String> {
    decode(bytes, super::protected_action_wire::MAX_POLICY * 4 + 4096)
}

#[cfg(test)]
fn engineering_policy_fee(
    body: &NativeIntentBody<'_>,
    fee: &synergy_execution::FeeSchedule,
    gas: u64,
) -> Result<(StateDiff, u128), String> {
    fee.validate().map_err(debug)?;
    let sender = body.account.to_native(&Primitives).map_err(display)?;
    let amount = u128::from(gas) * u128::from(fee.base_fee_per_gas_nwei);
    if gas == 0
        || gas > body.gas_limit
        || body.intent_id == [0; 32]
        || fee.collector.starts_with("synw")
        || (body.maximum_total_fee[..16] == [0; 16]
            && body.maximum_total_fee[16..] < amount.to_be_bytes()[..])
    {
        return Err("policy change exceeds signed fee or gas authorization".into());
    }
    Ok((
        StateDiff {
            changes: vec![
                AccountChange {
                    account: sender,
                    debit_nwei: amount,
                    credit_nwei: 0,
                    expected_nonce: Some(body.transaction_nonce),
                    code_hash: None,
                },
                AccountChange {
                    account: fee.collector.clone(),
                    debit_nwei: 0,
                    credit_nwei: amount,
                    expected_nonce: None,
                    code_hash: None,
                },
            ],
            ..StateDiff::default()
        },
        amount,
    ))
}

fn commit_key(commitment: EnrollmentCommitment) -> String {
    let mut key = String::with_capacity(COMMIT_PREFIX.len() + 64);
    key.push_str(COMMIT_PREFIX);
    for byte in commitment.as_bytes() {
        use std::fmt::Write as _;
        write!(key, "{byte:02x}").expect("writing to String is infallible");
    }
    key
}

fn account_key(account: AccountIdentifier) -> String {
    format!("{ACCOUNT_PREFIX}{}", account.lowercase_hex())
}

fn encode<T: Serialize>(record: &T) -> Result<Vec<u8>, String> {
    serde_json::to_vec(record).map_err(display)
}

fn decode<T: DeserializeOwned>(bytes: &[u8], maximum: usize) -> Result<T, String> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err("protected account state record size rejected".into());
    }
    serde_json::from_slice(bytes).map_err(display)
}

fn display(error: impl std::fmt::Display) -> String {
    error.to_string()
}
fn debug(error: impl std::fmt::Debug) -> String {
    format!("{error:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use synergy_address_engine::apqe::{
        address::ValidatedSec1PublicPoint,
        enrollment::{EnrollmentData, PublicPolicy, RoleRecord},
        identity::WalletUuid,
        provider::{Profile, SignOptions, Signature},
    };
    use synergy_state::{AccountState, FinalizedStateStore};

    fn wire() -> UnactivatedWireProfile {
        inspection::candidate_wire_profile().unwrap()
    }

    fn registry<'a>(
        wire: &'a UnactivatedWireProfile,
        genesis: NativeGenesisHash,
        manifest: [u8; 32],
    ) -> CandidateProtectedAccounts<'a> {
        CandidateProtectedAccounts::new(
            ChainId::from_u64(99999),
            ExternalChainPolicy::new(ChainId::from_u64(1), genesis).unwrap(),
            wire,
            UnactivatedCommitmentProfile::candidate_concat_v1(),
            vec![manifest],
        )
        .unwrap()
    }

    fn position(height: u64, consensus_time: u64) -> Position {
        Position {
            height,
            consensus_time,
        }
    }

    pub(super) fn finalized(
        height: u64,
        world: &WorldState,
    ) -> (FinalizedState, FinalizedBlockRecord) {
        let root = state_root(world).unwrap();
        let block_id = synergy_block::hash_block_bytes(
            &serde_json::to_vec(&("pw13-fixture-block", height, &root)).unwrap(),
        );
        (
            FinalizedState {
                finalized_height: height,
                finalized_block_id: block_id.clone(),
                state_root: root,
            },
            FinalizedBlockRecord {
                height,
                block_id,
                finality_certificate_id: "a".repeat(64),
                protected_execution_root: "b".repeat(64),
            },
        )
    }

    #[test]
    #[ignore = "requires independently authenticated engineering and validation APQE artifacts"]
    fn protected_sponsor_commit_and_reveal_settle_once_with_exact_native_proofs() {
        use super::super::protected_action_wire::{decode_sponsor, ENROLL_COMMIT, ENROLL_REVEAL};
        use super::super::protected_enrollment_wire::{decode_sponsored, encode_sponsored_fixture};
        use sponsor_settlement::SponsoredOutcome::{CommitApplied, RevealApplied, RevealRevertedCommitUsed};
        use std::sync::{Arc, Mutex};
        use synergy_address_engine::{apqe::native_manifest::validator_engine, types::Algorithm};
        use synergy_etdag::{
            admission::{Pw13SponsoredAdmission, Pw13SponsoredResources, PW13_SPONSOR_ADMISSION_CONTEXT},
            EtdagParameters,
        };
        use synergy_identity::authorization::*;

        let report = PathBuf::from(std::env::var_os("APQE_TRUSTED_NATIVE_REPORT").unwrap());
        let report_pin = hex(&std::env::var("APQE_AUTHENTICATED_REPORT_SHA256").unwrap())
            .try_into()
            .unwrap();
        let engine = Arc::new(Mutex::new(
            unsafe { validator_engine(&report, report_pin) }.unwrap(),
        ));
        let verifier = ApqeIdentityVerifier::new(engine.clone()).unwrap();
        let authoring_engine = engine.clone();
        let provider = unsafe {
            PqProvider::<Mldsa87>::open_verified(
                PathBuf::from(std::env::var_os("CORE_APQE_MLDSA87_LIBRARY").unwrap()),
                hex(&std::env::var("CORE_APQE_MLDSA87_SHA256").unwrap())
                    .try_into()
                    .unwrap(),
                Profile::Validation,
            )
        }
        .unwrap();
        let engine = engine.lock().unwrap();
        let root = engine.generate_keypair(Algorithm::FnDsa1024).unwrap();
        let signer = engine.generate_keypair(Algorithm::MlDsa87).unwrap();
        let key = PublicKey::<Mldsa87>::from_bytes(&signer.public_key).unwrap();
        let address =
            synergy_address::derive_key_controlled_address("syna", &root.public_key).unwrap();
        let hex_string =
            |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let hash =
            |bytes: &[u8]| hex_string(&Primitives.hash(HashAlgorithm::Sha3256, bytes).unwrap());
        let mut binding: IdentityAuthorizationBinding = serde_json::from_value(serde_json::json!({
            "schema_version":AUTH_BINDING_SCHEMA_VERSION,"binary_encoding":AUTH_BINDING_BINARY_ENCODING,
            "identity_id":"engineering-only-sponsor","identity_address":address,
            "identity_root":{"algorithm":"FN-DSA-1024","public_key":hex_string(&root.public_key),
                "public_key_sha3_256":hash(&root.public_key)},
            "authorization_policy":{"policy_type":"single-key","threshold":1,"principals":[{
                "principal_id":"sponsor","principal_type":"public-key","algorithm":"ML-DSA-87",
                "public_key":hex_string(&signer.public_key),"public_key_sha3_256":hash(&signer.public_key),
                "status":"active","purposes":[SPONSOR_PURPOSE]}]},
            "authorization_scopes":[{"signature_domain":SPONSOR_SIGNATURE_DOMAIN,
                "chain_id":99999,"network_id":"test-sponsor", "purpose":SPONSOR_PURPOSE}],
            "current_auth_key_hash":hash(&signer.public_key),"auth_key_history":[],"supersession_history":[],
            "effective_at":"1970-01-01T00:00:10Z","binding_payload_sha3_256":"",
            "proofs":{"identity_root":{"algorithm":"FN-DSA-1024","signature":""}}
        })).unwrap();
        let bytes = canonical_binding_payload(&binding).unwrap();
        binding.binding_payload_sha3_256 = hash(&bytes);
        let message = [AUTH_BINDING_SIGNATURE_DOMAIN, &bytes].concat();
        binding.proofs.identity_root.signature = hex_string(
            &engine
                .sign(
                    Algorithm::FnDsa1024,
                    root.private_key.as_bytes(),
                    &message,
                    SignOptions::default(),
                )
                .unwrap(),
        );
        binding.proofs.authorization_key_possession = vec![AuthorizationKeyPossessionProof {
            principal_id: "sponsor".into(),
            algorithm: "ML-DSA-87".into(),
            signature: hex_string(
                &engine
                    .sign(
                        Algorithm::MlDsa87,
                        signer.private_key.as_bytes(),
                        &message,
                        SignOptions::default(),
                    )
                    .unwrap(),
            ),
        }];
        let carrier = IdentityAuthorizationCarrier {
            schema_version: AUTHORIZATION_CARRIER_SCHEMA_VERSION,
            signature_domain: SPONSOR_SIGNATURE_DOMAIN.into(),
            binding,
        };
        let canonical_carrier = carrier.canonical_json_bytes().unwrap();
        drop(engine);
        let admitted = IdentityAuthorizationBindingCommitment::from_verified_binding_with_verifier(
            &carrier.binding,
            1000,
            Some(&verifier),
        )
        .unwrap();
        let fixture = load_enrollment_fixture();
        let wire = wire();
        let encoded = fixture_bytes(&fixture, "enrollment_cbor");
        let enrollment = CanonicalEnrollment::decode(&encoded, &wire).unwrap();
        let genesis = enrollment.genesis();
        let registry = registry(&wire, genesis, enrollment.policy().provider_manifest_hash);
        let (funding, mut base) = funding::FundingFixture::new(
            authoring_engine.clone(),
            &synergy_config::ApqeProviderConfiguration {
                report_path: report.clone(),
                authenticated_report_sha256: inspection::hex_bytes(&report_pin),
            },
            synergy_transaction::NetworkBinding::new(99999, "test-sponsor").unwrap(),
            enrollment.account(),
            1004,
        );
        let bindings = base
            .protocol
            .get_mut(IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY)
            .unwrap();
        let mut commitments: std::collections::BTreeMap<_, _> =
            serde_json::from_slice(bindings).unwrap();
        assert!(commitments.insert(address.clone(), admitted).is_none());
        *bindings = serde_json::to_vec(&commitments).unwrap();
        base.accounts.insert(
            address.clone(),
            AccountState {
                balance_nwei: 100,
                ..Default::default()
            },
        );
        let (pointer, certificate) = finalized(1, &base);
        let snapshot = registry
            .finalized_snapshot(&base, &pointer, &certificate, 1000)
            .unwrap();
        let mut world = base.clone();
        let commitment = EnrollmentCommitment::from_bytes(
            fixture_bytes(&fixture, "commitment").try_into().unwrap(),
        );
        let mut payload = vec![0xa2, 0, 1, 1, 0x58, 32];
        payload.extend_from_slice(commitment.as_bytes());
        let schedule = synergy_execution::FeeSchedule {
            base_fee_per_gas_nwei: 2,
            collector: "test-collector".into(),
        };
        let limits = EtdagParameters::default();
        let pin = std::env::var("APQE_AUTHENTICATED_REPORT_SHA256").unwrap();
        let open = |content: &[u8], authorized_intent: &[u8], snapshot: &FinalizedSnapshot<'_>,
                    source: &FinalizedBlockRecord| {
            let sponsor = decode_sponsor(authorized_intent)?;
            etdag_candidate::open_candidate_envelope(
                content, &report, &pin, 99999, source, &address, sponsor.nonce,
                etdag_candidate::CandidateEnvelopeProfile::SponsoredEnrollment,
                |envelope, context| {
                    let resources = Pw13SponsoredResources {
                        genesis: sponsor.genesis,
                        action: sponsor.action,
                        gas_limit: 5,
                        maximum_total_fee: sponsor.max_fee,
                        valid_until_finalized_height: sponsor.valid_until,
                        sponsor_intent_digest: sponsor_digest(authorized_intent)?,
                        envelope_id: envelope.envelope_id.clone(),
                    };
                    let digest = resources.signing_digest().map_err(debug)?;
                    let signature = authoring_engine.lock().unwrap().sign(
                        Algorithm::MlDsa87, signer.private_key.as_bytes(), &digest,
                        SignOptions::Pure { context: PW13_SPONSOR_ADMISSION_CONTEXT },
                    ).map_err(debug)?;
                    let request = Pw13SponsoredAdmission {
                        resources, signature, binding: carrier.clone(),
                        public_key: key.as_bytes().to_vec(),
                    };
                    let authorize = |request: &Pw13SponsoredAdmission| registry.verify_sponsored_admission(
                        &provider, &verifier, snapshot, context, envelope, request, &limits,
                        &schedule, 5,
                    );
                    let admitted = authorize(&request)?;
                    let mut tampered = request.clone();
                    tampered.resources.maximum_total_fee[0] ^= 1;
                    assert!(authorize(&tampered).is_err());
                    Ok(admitted)
                },
            )
        };
        let intent_for = |nonce: u8, cap: u8, expiry: u8, action: u16, content: &[u8]| {
            let mut bytes = vec![0xa8, 0, 1, 1, 0x58, 32];
            bytes.extend_from_slice(genesis.as_bytes());
            bytes.extend_from_slice(&[2, 0x78, address.len().try_into().unwrap()]);
            bytes.extend_from_slice(address.as_bytes());
            bytes.extend_from_slice(&[3, nonce, 4, 0x19]);
            bytes.extend_from_slice(&action.to_be_bytes());
            bytes.extend_from_slice(&[5, 0x58, 32]);
            bytes.extend_from_slice(&Primitives.hash(HashAlgorithm::Sha3256, content).unwrap());
            bytes.extend_from_slice(&[6, 0x58, 32]);
            bytes.extend_from_slice(&[0; 31]);
            bytes.extend_from_slice(&[cap, 7, expiry]);
            bytes
        };
        let execute = |world: &mut WorldState,
                       encoded: &[u8],
                       signed: &[u8],
                       network,
                       content: &[u8]| {
            // Open the same authenticated engineering provider for contextual
            // signing; the test verifies independently with the validation ABI.
            let signature =
                verifier_test_signer(&report, report_pin, signer.private_key.as_bytes(), signed);
            let bytes = encode_sponsored_fixture(
                encoded,
                content,
                [canonical_carrier.as_slice(), key.as_bytes(), signature.as_bytes()],
                None,
            );
            let decoded = decode_sponsored(&bytes)?;
            registry.execute_sponsored_commit(
                &provider,
                &verifier,
                network,
                &snapshot,
                world,
                position(2, 1001),
                decoded.payload,
                &SponsorProof {
                    intent: decoded.sponsor_intent,
                    binding: &decoded.binding,
                    signing_key: &decoded.signing_key,
                    signature: &decoded.signature,
                },
                &schedule,
                5,
                None,
            )
        };
        let commit_intent =
            |nonce, cap, expiry| intent_for(nonce, cap, expiry, ENROLL_COMMIT, &payload);
        let first = commit_intent(0, 10, 1);
        let mut padded_carrier = canonical_carrier.clone();
        padded_carrier.push(b' ');
        let first_signature =
            verifier_test_signer(&report, report_pin, signer.private_key.as_bytes(), &first);
        let noncanonical = encode_sponsored_fixture(
            &first,
            &payload,
            [padded_carrier.as_slice(), key.as_bytes(), first_signature.as_bytes()],
            None,
        );
        assert_eq!(
            decode_sponsored(&noncanonical).err(),
            Some("INVALID_SPONSOR_CARRIER")
        );
        let first_content = encode_sponsored_fixture(
            &first, &payload, [canonical_carrier.as_slice(), key.as_bytes(), first_signature.as_bytes()],
            None,
        );
        let (first_opening, first_admission) = open(&first_content, &first, &snapshot, &certificate).unwrap();
        let mut alternate_payload = payload.clone();
        alternate_payload[6] ^= 1;
        let alternate = intent_for(0, 10, 1, ENROLL_COMMIT, &alternate_payload);
        let alternate_signature =
            verifier_test_signer(&report, report_pin, signer.private_key.as_bytes(), &alternate);
        let altered_content = encode_sponsored_fixture(
            &alternate, &alternate_payload,
            [canonical_carrier.as_slice(), key.as_bytes(), alternate_signature.as_bytes()],
            None,
        );
        let (altered_opening, altered_admission) =
            open(&altered_content, &first, &snapshot, &certificate).unwrap();
        assert_eq!(
            registry.execute_opened_sponsored_enrollment(
                &provider, &verifier, &snapshot, &mut world, position(2, 1001),
                &altered_opening, &altered_admission, &schedule,
            ).unwrap_err(),
            "opened enrollment differs from the signed sponsor admission",
        );
        assert_eq!(world, base);
        assert_eq!(
            registry.execute_opened_sponsored_enrollment(
                &provider, &verifier, &snapshot, &mut world, position(2, 1001),
                &first_opening, &first_admission, &schedule,
            ).unwrap(),
            (CommitApplied, 10)
        );
        let after_first = state_root(&world).unwrap();
        let second = commit_intent(1, 10, 1);
        let mut changed_payload = payload.clone();
        changed_payload[6] ^= 1;
        for (encoded, signed, network, content) in [
            (first.clone(), first.clone(), "test-sponsor", &payload),
            (second.clone(), first.clone(), "test-sponsor", &payload),
            (second.clone(), second.clone(), "other-network", &payload),
            (
                second.clone(),
                second.clone(),
                "test-sponsor",
                &changed_payload,
            ),
            (
                commit_intent(1, 9, 1),
                commit_intent(1, 9, 1),
                "test-sponsor",
                &payload,
            ),
            (
                commit_intent(1, 10, 0),
                commit_intent(1, 10, 0),
                "test-sponsor",
                &payload,
            ),
        ] {
            assert!(execute(&mut world, &encoded, &signed, network, content).is_err());
            assert_eq!(state_root(&world).unwrap(), after_first);
        }
        let commitment_key = commit_key(commitment);
        let original_commitment = world.protocol[&commitment_key].clone();
        let mut malformed = world.clone();
        malformed
            .protocol
            .insert(commitment_key.clone(), vec![0xff]);
        let malformed_before = malformed.clone();
        assert!(execute(&mut malformed, &second, &second, "test-sponsor", &payload).is_err());
        assert_eq!(malformed, malformed_before);
        assert_eq!(
            execute(&mut world, &second, &second, "test-sponsor", &payload).unwrap(),
            (false, 10)
        );
        assert_eq!(world.protocol[&commitment_key], original_commitment);
        assert_eq!(world.accounts[&address].balance_nwei, 80);
        assert_eq!(world.accounts[&address].nonce, 2);
        assert_eq!(world.accounts[&schedule.collector].balance_nwei, 20);

        let salt: [u8; 32] = fixture_bytes(&fixture, "commit_salt").try_into().unwrap();
        let (ordinary, recovery, ownership) = enrollment_proofs(&fixture, &enrollment, &registry);
        let target = enrollment.account().to_native(&Primitives).unwrap();
        let committed = world.clone();
        let (pointer, certificate) = finalized(3, &committed);
        let snapshot = registry
            .finalized_snapshot(&committed, &pointer, &certificate, 1002)
            .unwrap();

        // Exact canonical DCBOR reveal payload; its own salt is signed.
        let length = u16::try_from(encoded.len()).unwrap();
        assert!(length > 255);
        let mut reveal = vec![0xa3, 0, 1, 1, 0x59];
        reveal.extend_from_slice(&length.to_be_bytes());
        reveal.extend_from_slice(&encoded);
        reveal.extend_from_slice(&[2, 0x58, 32]);
        reveal.extend_from_slice(&salt);
        let position = position(4, 1003);
        let reveal_intent = intent_for(2, 10, 3, ENROLL_REVEAL, &reveal);
        let signature = verifier_test_signer(
            &report,
            report_pin,
            signer.private_key.as_bytes(),
            &reveal_intent,
        );
        let execute_reveal = |world: &mut WorldState,
                              content: &[u8],
                              proof_salt: &[u8; 32],
                              parent: &FinalizedSnapshot<'_>,
                              at: Position,
                              intent: &[u8],
                              signature: &Signature<Mldsa87>| {
            let bytes = encode_sponsored_fixture(
                intent,
                content,
                [canonical_carrier.as_slice(), key.as_bytes(), signature.as_bytes()],
                Some(EnrollmentProofs {
                    ordinary: &ordinary,
                    recovery: &recovery,
                    ownership: &ownership,
                    salt: proof_salt,
                }),
            );
            let decoded = decode_sponsored(&bytes)?;
            let opened = decoded.reveal.ok_or("missing decoded enrollment proofs")?;
            registry.execute_sponsored_reveal(
                &provider,
                &verifier,
                "test-sponsor",
                parent,
                world,
                at,
                decoded.payload,
                &SponsorProof {
                    intent: decoded.sponsor_intent,
                    binding: &decoded.binding,
                    signing_key: &decoded.signing_key,
                    signature: &decoded.signature,
                },
                EnrollmentProofs {
                    ordinary: &opened.ordinary,
                    recovery: &opened.recovery,
                    ownership: &opened.ownership,
                    salt: &opened.salt,
                },
                &schedule,
                5,
                None,
            )
        };
        let mut bad_salt = salt;
        bad_salt[0] ^= 1;
        let mut altered = reveal.clone();
        let salt_offset = altered.len() - salt.len();
        altered[salt_offset..].copy_from_slice(&bad_salt);
        let bad_intent = intent_for(2, 10, 3, ENROLL_REVEAL, &altered);
        let bad_signature = verifier_test_signer(
            &report,
            report_pin,
            signer.private_key.as_bytes(),
            &bad_intent,
        );
        for (content, proof_salt, intent, signature) in [
            (&reveal, &bad_salt, &reveal_intent, &signature),
            (&altered, &bad_salt, &reveal_intent, &signature),
            (&altered, &bad_salt, &bad_intent, &bad_signature),
        ] {
            assert!(execute_reveal(
                &mut world, content, proof_salt, &snapshot, position, intent, signature
            )
            .is_err());
        }
        assert_eq!(world, committed);

        // A failure crediting the collector rolls back account creation,
        // commitment consumption, sponsor debit and settlement together.
        let mut collector_overflow = committed.clone();
        collector_overflow
            .accounts
            .get_mut(&schedule.collector)
            .unwrap()
            .balance_nwei = u128::MAX;
        let before_overflow = collector_overflow.clone();
        assert!(execute_reveal(
            &mut collector_overflow,
            &reveal,
            &salt,
            &snapshot,
            position,
            &reveal_intent,
            &signature
        )
        .is_err());
        assert_eq!(collector_overflow, before_overflow);

        let expired_at = Position {
            consensus_time: 1001 + REVEAL_WINDOW_SECONDS,
            ..position
        };
        let expired = execute_reveal(
            &mut world,
            &reveal,
            &salt,
            &snapshot,
            expired_at,
            &reveal_intent,
            &signature,
        )
        .unwrap_err();
        assert_eq!(
            expired,
            "protected reveal expired before candidate inclusion"
        );
        assert_eq!(world, committed);
        let reveal_content = encode_sponsored_fixture(
            &reveal_intent, &reveal,
            [canonical_carrier.as_slice(), key.as_bytes(), signature.as_bytes()],
            Some(EnrollmentProofs { ordinary: &ordinary, recovery: &recovery, ownership: &ownership, salt: &salt }),
        );
        let (reveal_opening, reveal_admission) =
            open(&reveal_content, &reveal_intent, &snapshot, &certificate).unwrap();
        assert_eq!(
            registry.execute_opened_sponsored_enrollment(
                &provider, &verifier, &snapshot, &mut world, position, &reveal_opening,
                &reveal_admission, &schedule,
            ).unwrap(),
            (RevealApplied, 10)
        );
        assert_eq!(world.accounts[&target], AccountState::default());
        assert_eq!(world.accounts[&address].balance_nwei, 70);
        assert_eq!(world.accounts[&address].nonce, 3);
        assert_eq!(world.accounts[&schedule.collector].balance_nwei, 30);
        assert!(registry.pending_commit(&world, commitment).is_err());
        assert_eq!(
            registry
                .read_policy(&world, enrollment.account())
                .unwrap()
                .enrollment,
            encoded
        );
        let applied = world.clone();
        let fresh_intent = intent_for(3, 10, 3, ENROLL_REVEAL, &reveal);
        let fresh_signature = verifier_test_signer(
            &report,
            report_pin,
            signer.private_key.as_bytes(),
            &fresh_intent,
        );
        assert!(execute_reveal(
            &mut world,
            &reveal,
            &salt,
            &snapshot,
            position,
            &reveal_intent,
            &signature
        )
        .is_err());
        assert_eq!(world, applied);

        // A corrupt overlay is not an authenticated earlier reveal.
        let mut damaged = applied.clone();
        damaged
            .protocol
            .insert(account_key(enrollment.account()), vec![0xff]);
        let damaged_before = damaged.clone();
        assert!(execute_reveal(
            &mut damaged,
            &reveal,
            &salt,
            &snapshot,
            position,
            &fresh_intent,
            &fresh_signature
        )
        .is_err());
        assert_eq!(damaged, damaged_before);

        let mut exhausted = applied.clone();
        exhausted.accounts.get_mut(&address).unwrap().balance_nwei = 9;
        let exhausted_before = exhausted.clone();
        assert!(execute_reveal(
            &mut exhausted,
            &reveal,
            &salt,
            &snapshot,
            position,
            &fresh_intent,
            &fresh_signature
        )
        .is_err());
        assert_eq!(exhausted, exhausted_before);

        assert_eq!(
            execute_reveal(
                &mut world,
                &reveal,
                &salt,
                &snapshot,
                position,
                &fresh_intent,
                &fresh_signature
            )
            .unwrap(),
            (RevealRevertedCommitUsed, 10)
        );
        assert_eq!(world.accounts[&address].balance_nwei, 60);
        assert_eq!(world.accounts[&address].nonce, 4);
        assert_eq!(world.accounts[&schedule.collector].balance_nwei, 40);
        assert_eq!(world.accounts[&target], applied.accounts[&target]);
        for key in [commitment_key, account_key(enrollment.account())] {
            assert_eq!(world.protocol[&key], applied.protocol[&key]);
        }
        let settled = world.clone();
        assert!(execute_reveal(
            &mut world,
            &reveal,
            &salt,
            &snapshot,
            position,
            &fresh_intent,
            &fresh_signature
        )
        .is_err());
        assert_eq!(world, settled);
        let (settled_pointer, settled_finality) = finalized(4, &settled);
        let settled_parent = registry
            .finalized_snapshot(&settled, &settled_pointer, &settled_finality, 1003)
            .unwrap();
        let later_intent = intent_for(4, 10, 4, ENROLL_REVEAL, &reveal);
        let later_signature = verifier_test_signer(
            &report,
            report_pin,
            signer.private_key.as_bytes(),
            &later_intent,
        );
        let later = execute_reveal(
            &mut world,
            &reveal,
            &salt,
            &settled_parent,
            Position {
                height: 5,
                consensus_time: 1004,
            },
            &later_intent,
            &later_signature,
        )
        .unwrap_err();
        assert_eq!(later, "protected enrollment commitment is used");
        assert_eq!(world, settled);

        let scratch = Scratch::new();
        let (tip, _) = finalized(4, &world);
        let mut store = FinalizedStateStore::load(&scratch.0).unwrap();
        store
            .commit_verified_world_state(pointer, &committed)
            .unwrap();
        store
            .commit_verified_world_transition(tip.clone(), &committed, &world)
            .unwrap();
        drop(store);
        let store = FinalizedStateStore::load(&scratch.0).unwrap();
        let reopened = store.current_world_state().unwrap().unwrap();
        assert_eq!(reopened, world);
        let query_receipt = |state: &WorldState,
                             height,
                             time,
                             selectors: Vec<serde_json::Value>| {
            let (tip, finality) = finalized(height, state);
            let query = serde_json::from_value(serde_json::json!({
                "height": height,
                "block_id": finality.block_id,
                "state_root": tip.state_root,
                "ownership_chain_id": inspection::hex_bytes(&registry.network.ownership_chain),
                "provider_manifests": [inspection::hex_bytes(&enrollment.policy().provider_manifest_hash)],
                "commitments": [inspection::hex_bytes(commitment.as_bytes())],
                "sponsorships": selectors,
            })).unwrap();
            inspection::inspect(
                state,
                &finality,
                &tip.state_root,
                time,
                99999,
                &inspection::hex_bytes(genesis.as_bytes()),
                query,
            )
        };
        let selector = |nonce_before, intent: &[u8]| {
            serde_json::json!({
                "payer": address,
                "nonce_before": nonce_before,
                "signed_sponsor_digest": inspection::hex_bytes(&sponsor_digest(intent).unwrap()),
            })
        };
        let before = query_receipt(&committed, 3, 1002, vec![selector(2, &reveal_intent)]).unwrap();
        assert_eq!(before["commitments"][0]["status"], "unconsumed");
        assert_eq!(
            before["sponsorships"][0]["status"],
            "no_settlement_in_snapshot"
        );
        let first_evidence = settlement::EngineeringEtdagOpening::from_opening(
            first_opening.envelope(), &first_content,
        ).unwrap();
        let reveal_evidence = settlement::EngineeringEtdagOpening::from_opening(
            reveal_opening.envelope(), &reveal_content,
        ).unwrap();
        let mut commit_selector = selector(0, &first);
        commit_selector["engineering_etdag_opening"] = serde_json::json!(first_evidence);
        let mut reveal_selector = selector(2, &reveal_intent);
        reveal_selector["engineering_etdag_opening"] = serde_json::json!(reveal_evidence);
        let after = query_receipt(
            &reopened,
            4,
            1003,
            vec![
                commit_selector,
                selector(1, &second),
                reveal_selector.clone(),
                selector(3, &fresh_intent),
            ],
        )
        .unwrap();
        assert_eq!(after["sponsorships"][0]["engineering_etdag_opening"], serde_json::json!(first_evidence));
        assert_eq!(after["sponsorships"][2]["engineering_etdag_opening"], serde_json::json!(reveal_evidence));
        reveal_selector["engineering_etdag_opening"] = serde_json::json!(first_evidence);
        assert!(query_receipt(&reopened, 4, 1003, vec![reveal_selector]).is_err());
        assert_eq!(after["commitments"][0]["status"], "consumed");
        for (nonce, status) in [
            "commit_applied_candidate",
            "duplicate_paid_commit_candidate",
            "reveal_applied_candidate",
            "reveal_reverted_commit_used_candidate",
        ]
        .into_iter()
        .enumerate()
        {
            let receipt = &after["sponsorships"][nonce];
            assert_eq!(receipt["status"], status);
            assert_eq!(receipt["nonce_before"], nonce);
            assert_eq!(receipt["nonce_after"], nonce + 1);
            assert_eq!(receipt["payer"], address);
            assert_eq!(
                receipt["commitment"],
                inspection::hex_bytes(commitment.as_bytes())
            );
            assert_eq!(receipt["gas_used"], 5);
            assert_eq!(receipt["fee_nwei"], "10");
            let (source, included, timestamp) = if nonce >= 2 {
                (3, 4, 1003)
            } else {
                (1, 2, 1001)
            };
            assert_eq!(receipt["source_finalized_height"], source);
            assert_eq!(receipt["included_height"], included);
            assert_eq!(receipt["inclusion_consensus_timestamp_unix"], timestamp);
        }
        assert!(query_receipt(&reopened, 4, 1003, vec![selector(2, &bad_intent)]).is_err());
        let (funding_tip, funding_finality) = finalized(4, &reopened);
        let funding_parent = registry
            .finalized_snapshot(&reopened, &funding_tip, &funding_finality, 1003)
            .unwrap();
        funding.qualify(&snapshot, &funding_parent, store, &scratch.0);
        assert_eq!(
            registry.require_activation(),
            Err(RegistryError::ProfileUnapproved)
        );
    }

    fn verifier_test_signer(
        report: &std::path::Path,
        pin: [u8; 32],
        key: &[u8],
        encoded: &[u8],
    ) -> Signature<Mldsa87> {
        use synergy_address_engine::{apqe::native_manifest::validator_engine, types::Algorithm};
        let engine = unsafe { validator_engine(report, pin) }.unwrap();
        Signature::from_bytes(
            &engine
                .sign(
                    Algorithm::MlDsa87,
                    key,
                    &sponsor_digest(encoded).unwrap(),
                    SignOptions::Pure {
                        context: SPONSOR_CONTEXT,
                    },
                )
                .unwrap(),
        )
        .unwrap()
    }

    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "core-protected-accounts-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn protected_candidate_commit_is_durable_and_conflicting_state_is_rejected() {
        let wire = wire();
        let registry = registry(&wire, NativeGenesisHash::from_bytes([5; 32]), [6; 32]);
        assert_eq!(
            registry.require_activation(),
            Err(RegistryError::ProfileUnapproved)
        );
        let commitment = EnrollmentCommitment::from_bytes([3; 32]);
        let mut world = WorldState::default();
        let write = registry
            .prepare_commit(&world, commitment, position(1, 1000))
            .unwrap();
        write.apply(&mut world).unwrap();
        let after = world.clone();
        assert!(write.apply(&mut world).is_err());
        assert_eq!(world, after);
        assert!(registry
            .prepare_commit(&world, commitment, position(2, 1001))
            .is_err());

        let scratch = Scratch::new();
        let mut store = FinalizedStateStore::load(&scratch.0).unwrap();
        let (pointer, certificate) = finalized(1, &world);
        store
            .commit_verified_world_state(pointer.clone(), &world)
            .unwrap();
        drop(store);
        let store = FinalizedStateStore::load(&scratch.0).unwrap();
        let from_disk = store.current_world_state().unwrap().unwrap();
        assert_eq!(from_disk, world);
        let snapshot = registry
            .finalized_snapshot(&from_disk, &pointer, &certificate, 1000)
            .unwrap();
        assert_eq!(
            snapshot.context().genesis,
            NativeGenesisHash::from_bytes([5; 32])
        );
        let (_, pending) = registry.pending_commit(snapshot.world, commitment).unwrap();
        assert_eq!(pending.included_height, 1);
        assert!(registry
            .finalized_snapshot(&WorldState::default(), &pointer, &certificate, 1000)
            .is_err());
        let mut wrong_pointer = pointer;
        wrong_pointer.finalized_height = 2;
        assert!(registry
            .finalized_snapshot(&from_disk, &wrong_pointer, &certificate, 1001)
            .is_err());
        let other = self::registry(&wire, NativeGenesisHash::from_bytes([7; 32]), [6; 32]);
        assert!(other.pending_commit(&from_disk, commitment).is_err());
    }

    fn hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn load_enrollment_fixture() -> serde_json::Value {
        let path = std::env::var_os("CORE_APQE_ENROLLMENT_FIXTURE").unwrap();
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    fn fixture_bytes(fixture: &serde_json::Value, name: &str) -> Vec<u8> {
        hex(fixture[name].as_str().unwrap())
    }

    fn enrollment_proofs(
        fixture: &serde_json::Value,
        enrollment: &CanonicalEnrollment<'_>,
        registry: &CandidateProtectedAccounts<'_>,
    ) -> ([EnrollmentSignature; 2], EnrollmentSignature, [u8; 65]) {
        let signature = |i: usize| {
            let role = enrollment.policy().roles[i];
            EnrollmentSignature {
                schema_version: 1,
                role_id: role.role_id,
                participant_id: role.participant_id,
                key_version: role.key_version,
                auth_algorithm: role.auth_algorithm,
                signed_digest: if i < 2 {
                    enrollment.native_digest()
                } else {
                    enrollment.recovery_ack_digest()
                }
                .unwrap(),
                signature: Signature::from_bytes(&hex(fixture["role_signatures"][i]
                    .as_str()
                    .unwrap()))
                .unwrap(),
            }
        };
        let ordinary = [signature(0), signature(1)];
        let recovery = signature(2);
        let binding = enrollment.binding_fields().unwrap();
        let point =
            ValidatedSec1PublicPoint::parse(&Primitives, enrollment.evm_public_key()).unwrap();
        let ownership = Primitives
            .secp256k1_normalize_der_prehash(
                binding.digest(&registry.chain).unwrap().as_bytes(),
                &fixture_bytes(fixture, "ecdsa_der"),
                point.as_sec1_bytes(),
            )
            .unwrap();
        (ordinary, recovery, ownership)
    }

    #[test]
    #[ignore = "requires explicit APQE fixture and pinned native signing, validation and KEM artifacts"]
    fn protected_candidate_apqe_proofs_are_atomic_and_survive_restart() {
        use TransferCandidateContent::{OpenedEtdag, PlaintextFixture};
        use synergy_etdag::admission::{
            Pw13AdmissionProof, Pw13TransferAdmission, Pw13TransferResources, PW13_ADMISSION_CONTEXT,
        };
        use synergy_etdag::{EtdagParameters, ProcessingContext, ProcessingEnvelope};
        let fixture = load_enrollment_fixture();
        let bytes = |name: &str| fixture_bytes(&fixture, name);
        let library_path = PathBuf::from(std::env::var_os("CORE_APQE_MLDSA87_LIBRARY").unwrap());
        let digest = hex(&std::env::var("CORE_APQE_MLDSA87_SHA256").unwrap())
            .try_into()
            .unwrap();
        // Only an independently selected, digest-pinned validation library.
        let provider = unsafe {
            PqProvider::<Mldsa87>::open_verified(library_path, digest, Profile::Validation)
        }
        .unwrap();
        let wire = wire();
        let encoded = bytes("enrollment_cbor");
        let enrollment = CanonicalEnrollment::decode(&encoded, &wire).unwrap();
        let registry = registry(
            &wire,
            enrollment.genesis(),
            enrollment.policy().provider_manifest_hash,
        );
        let (ordinary, recovery, ownership) = enrollment_proofs(&fixture, &enrollment, &registry);
        let salt = bytes("commit_salt").try_into().unwrap();
        let commitment = EnrollmentCommitment::from_bytes(bytes("commitment").try_into().unwrap());
        let address = enrollment.account().to_native(&Primitives).unwrap();
        let sponsor = "candidate-test-sponsor";
        let mut world = WorldState::default();
        world.accounts.insert(
            address.clone(),
            AccountState {
                balance_nwei: 19,
                ..AccountState::default()
            },
        );
        world.accounts.insert(
            sponsor.into(),
            AccountState {
                balance_nwei: 9,
                ..AccountState::default()
            },
        );
        let staged_commit = registry
            .prepare_commit(&world, commitment, position(1, 1000))
            .unwrap();
        staged_commit.apply(&mut world).unwrap();
        let (f1, p1) = finalized(1, &world);
        let (f2, p2) = finalized(2, &world);
        let early = registry.finalized_snapshot(&world, &f1, &p1, 1000).unwrap();
        let ready = registry.finalized_snapshot(&world, &f2, &p2, 1001).unwrap();
        let proof = |salt| EnrollmentProofs {
            ordinary: &ordinary,
            recovery: &recovery,
            ownership: &ownership,
            salt,
        };
        assert!(registry
            .prepare_reveal(
                &provider,
                &early,
                &world,
                position(2, 1001),
                &encoded,
                proof(&salt)
            )
            .is_err());
        assert!(registry
            .prepare_reveal(
                &provider,
                &ready,
                &world,
                position(3, 8200),
                &encoded,
                proof(&salt)
            )
            .is_err());
        let wrong_salt = [0; 32];
        assert!(registry
            .prepare_reveal(
                &provider,
                &ready,
                &world,
                position(3, 1002),
                &encoded,
                proof(&wrong_salt)
            )
            .is_err());
        let mut other_world = world.clone();
        other_world.protocol.remove(&commit_key(commitment));
        assert!(registry
            .prepare_reveal(
                &provider,
                &ready,
                &other_world,
                position(3, 1002),
                &encoded,
                proof(&salt)
            )
            .is_err());
        let prepare = || {
            registry
                .prepare_reveal(
                    &provider,
                    &ready,
                    &world,
                    position(3, 1002),
                    &encoded,
                    proof(&salt),
                )
                .unwrap()
        };
        let fee = |debit_nwei| StateDiff {
            changes: vec![AccountChange {
                account: sponsor.into(),
                debit_nwei,
                credit_nwei: 0,
                expected_nonce: Some(0),
                code_hash: None,
            }],
            ..StateDiff::default()
        };
        let mut working = world.clone();
        assert!(prepare().apply_with_fee(&mut working, &fee(10)).is_err());
        assert_eq!(working, world);
        working.accounts.get_mut(&address).unwrap().nonce = 1;
        let conflicting = working.clone();
        assert!(prepare().apply_with_fee(&mut working, &fee(2)).is_err());
        assert_eq!(working, conflicting);
        let mut working = world.clone();
        prepare().apply_with_fee(&mut working, &fee(2)).unwrap();
        assert_eq!(working.accounts[&address].balance_nwei, 19);
        assert_eq!(working.accounts[&address].nonce, 0);
        assert_eq!(working.accounts[sponsor].balance_nwei, 7);
        assert_eq!(working.accounts[sponsor].nonce, 1);
        assert!(registry.pending_commit(&working, commitment).is_err());
        assert_eq!(
            registry
                .read_policy(&working, enrollment.account())
                .unwrap()
                .enrollment,
            encoded
        );
        let unchanged = working.clone();
        assert!(prepare().apply_with_fee(&mut working, &fee(2)).is_err());
        assert_eq!(working, unchanged);

        let scratch = Scratch::new();
        let mut store = FinalizedStateStore::load(&scratch.0).unwrap();
        store.commit_verified_world_state(f1, &world).unwrap();
        store
            .commit_verified_world_transition(f2, &world, &world)
            .unwrap();
        store
            .commit_verified_world_transition(finalized(3, &working).0, &world, &working)
            .unwrap();
        drop(store);
        let store = FinalizedStateStore::load(&scratch.0).unwrap();
        let restored = store.current_world_state().unwrap().unwrap();
        assert_eq!(restored, working);
        assert_eq!(
            registry
                .read_policy(&restored, enrollment.account())
                .unwrap()
                .registered_height,
            3
        );

        let as_hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let absent = AccountIdentifier::from_bytes([0x77; 20])
            .to_native(&Primitives)
            .unwrap();
        let observe = |world: &WorldState,
                       pointer: &FinalizedState,
                       record: &FinalizedBlockRecord,
                       addresses,
                       time,
                       transition_settlements: &[serde_json::Value]| {
            inspection::inspect(
                world,
                record,
                &pointer.state_root,
                time,
                99999,
                &as_hex(enrollment.genesis().as_bytes()),
                serde_json::from_value(serde_json::json!({
                    "height": pointer.finalized_height,
                    "block_id": pointer.finalized_block_id,
                    "state_root": pointer.state_root,
                    "ownership_chain_id": as_hex(ChainId::from_u64(1).as_be_bytes()),
                    "provider_manifests": [as_hex(&enrollment.policy().provider_manifest_hash)],
                    "addresses": addresses,
                    "commitments": [as_hex(commitment.as_bytes())],
                    "transition_settlements": transition_settlements,
                }))
                .unwrap(),
            )
        };
        let (before, before_finality) = finalized(2, &world);
        let pending = observe(&world, &before, &before_finality, vec![&absent], 1001, &[]).unwrap();
        assert_eq!(pending["commitments"][0]["status"], "unconsumed");
        assert_eq!(pending["commitments"][0]["included_height"], 1);
        assert_eq!(pending["accounts"][0]["status"], "absent");
        let (after, after_finality) = finalized(3, &restored);
        let enrolled = observe(
            &restored,
            &after,
            &after_finality,
            vec![&address, &absent],
            1002,
            &[],
        )
        .unwrap();
        assert_eq!(enrolled["status"], "unactivated_candidate");
        assert_eq!(enrolled["commitments"][0]["status"], "consumed");
        assert_eq!(enrolled["accounts"][0]["status"], "enrolled");
        assert_eq!(
            enrolled["accounts"][0]["policy_hash"],
            as_hex(&enrollment.policy_hash().unwrap())
        );
        assert_eq!(enrolled["accounts"][0]["balance_nwei"], "19");
        assert_eq!(enrolled["accounts"][0]["next_nonce"], 0);
        assert_eq!(
            enrolled["accounts"][0]["roles"].as_array().unwrap().len(),
            3
        );
        assert_eq!(enrolled["accounts"][1]["status"], "absent");
        let mut altered = restored.clone();
        altered.accounts.get_mut(&address).unwrap().balance_nwei += 1;
        assert!(observe(&altered, &after, &after_finality, vec![&address], 1002, &[]).is_err());
        altered.accounts.remove(&address);
        let (partial, partial_finality) = finalized(3, &altered);
        assert!(observe(
            &altered,
            &partial,
            &partial_finality,
            vec![&address],
            1002,
            &[]
        )
        .is_err());

        // The independent enrollment proof vector has no available signing keys.
        // Exercise the separate quorum adapter using fresh genuine APQE keys in a
        // test-only trusted World fixture for the same canonical address.
        let keys = [(); 3].map(|()| provider.generate_keypair().unwrap());
        let policy = PublicPolicy {
            roles: std::array::from_fn(|i| RoleRecord {
                role_id: i as u8,
                participant_id: [i as u8 + 1; 32],
                key_version: 1,
                auth_algorithm: 1,
                auth_public_key: keys[i].0.as_bytes(),
            }),
            ..*enrollment.policy()
        };
        let spend_enrollment = EnrollmentData {
            genesis: enrollment.genesis(),
            account: enrollment.account(),
            evm_public_key: *enrollment.evm_public_key(),
            public_policy: policy,
            dkg_transcript_commitment: enrollment.dkg_transcript_commitment(),
            nonce: enrollment.nonce(),
            issued_at: enrollment.issued_at(),
            expires_at: enrollment.expires_at(),
            wallet_uuid: WalletUuid::from_bytes(*enrollment.wallet_uuid().as_bytes()),
        }
        .encode(&wire)
        .unwrap();
        let new_hash = CanonicalEnrollment::decode(&spend_enrollment, &wire)
            .unwrap()
            .policy_hash()
            .unwrap();
        let mut spend_base = restored;
        let mut record = registry
            .read_policy(&spend_base, enrollment.account())
            .unwrap();
        record.enrollment = spend_enrollment;
        record.policy_hash = new_hash;
        spend_base
            .protocol
            .insert(account_key(enrollment.account()), encode(&record).unwrap());
        // Public 2G point, used only for canonical recipient-state validation.
        // This trusted World fixture asserts no DKG or recipient possession proof.
        let recipient_point: [u8; 65] = hex(concat!(
            "04c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"
        ))
        .try_into()
        .unwrap();
        let recipient = synergy_address_engine::apqe::address::derive_account_identifier(
            &Primitives,
            &synergy_address_engine::apqe::address::ValidatedSec1PublicPoint::parse(
                &Primitives,
                &recipient_point,
            )
            .unwrap(),
        )
        .unwrap();
        assert_ne!(recipient, enrollment.account());
        let recipient_address = recipient.to_native(&Primitives).unwrap();
        let recipient_keys = [(); 3].map(|()| provider.generate_keypair().unwrap());
        let recipient_policy = PublicPolicy {
            account: recipient,
            evm_public_key: recipient_point,
            roles: std::array::from_fn(|index| RoleRecord {
                role_id: index as u8,
                participant_id: [21 + index as u8; 32],
                key_version: 1,
                auth_algorithm: 1,
                auth_public_key: recipient_keys[index].0.as_bytes(),
            }),
            ..*enrollment.policy()
        };
        record.account = *recipient.as_bytes();
        record.enrollment = EnrollmentData {
            genesis: enrollment.genesis(),
            account: recipient,
            evm_public_key: recipient_point,
            public_policy: recipient_policy,
            dkg_transcript_commitment: enrollment.dkg_transcript_commitment(),
            nonce: enrollment.nonce(),
            issued_at: enrollment.issued_at(),
            expires_at: enrollment.expires_at(),
            wallet_uuid: WalletUuid::from_bytes([44; 16]),
        }
        .encode(&wire)
        .unwrap();
        record.policy_hash = CanonicalEnrollment::decode(&record.enrollment, &wire)
            .unwrap()
            .policy_hash()
            .unwrap();
        spend_base
            .protocol
            .insert(account_key(recipient), encode(&record).unwrap());
        spend_base
            .accounts
            .insert(recipient_address.clone(), Default::default());
        spend_base.accounts.get_mut(&address).unwrap().balance_nwei = 900_000;
        let (snapshot_pointer, snapshot_proof) = finalized(3, &spend_base);
        let snapshot = registry
            .finalized_snapshot(&spend_base, &snapshot_pointer, &snapshot_proof, 1002)
            .unwrap();
        let mut payload = vec![0xa3, 0, 1, 1, 0x54];
        payload.extend_from_slice(recipient.as_bytes());
        payload.extend_from_slice(&[2, 0x58, 32]);
        payload.extend_from_slice(&[0; 31]);
        payload.push(7);
        let mut maximum_total_fee = [0; 32];
        maximum_total_fee[16..].copy_from_slice(&840_000_u128.to_be_bytes());
        let body = NativeIntentBody {
            genesis: enrollment.genesis(),
            account: enrollment.account(),
            policy_epoch: 0,
            transaction_nonce: 0,
            action_type: super::super::protected_action_wire::TRANSFER,
            action_payload: &payload,
            gas_limit: 21_000,
            maximum_total_fee,
            valid_until_finalized_height: 4,
            intent_id: [1; 32],
        };
        let intent = body.encode(128).unwrap();
        let digest = CanonicalNativeIntent::decode(&intent, 128)
            .unwrap()
            .digest()
            .unwrap();
        let proofs = |roles: [(Role, usize); 2]| {
            roles.map(|(role, i)| RoleSignature {
                role,
                signature: provider
                    .sign(
                        digest.as_bytes(),
                        &keys[i].1,
                        SignOptions::Pure {
                            context: NATIVE_TX_CONTEXT,
                        },
                    )
                    .unwrap(),
            })
        };
        let ordinary = proofs([(Role::D, 0), (Role::P, 1)]);
        let check = |candidate, input, signatures| {
            registry.verify_spend(
                &provider,
                &snapshot,
                candidate,
                input,
                128,
                super::super::protected_action_wire::decode_transfer,
                signatures,
            )
        };
        let recovery_proofs = proofs([(Role::D, 0), (Role::R, 2)]);
        let changed_intent = NativeIntentBody {
            valid_until_finalized_height: 5,
            ..body
        }
        .encode(128)
        .unwrap();
        let mut reexecuted = spend_base.clone();
        reexecuted.accounts.get_mut(&address).unwrap().nonce = 1;
        assert!(check(&spend_base, &intent, &ordinary).is_ok());
        assert!(check(&spend_base, &intent, &recovery_proofs).is_err());
        assert!(check(&spend_base, &changed_intent, &ordinary).is_err());
        assert!(check(&reexecuted, &intent, &ordinary).is_err());
        let schedule = synergy_execution::FeeSchedule {
            base_fee_per_gas_nwei: 40,
            collector: "test-collector".into(),
        };
        fn bstr(output: &mut Vec<u8>, bytes: &[u8]) {
            match bytes.len() {
                len @ 0..=23 => output.push(0x40 | len as u8),
                len @ 24..=255 => output.extend_from_slice(&[0x58, len as u8]),
                len => {
                    output.push(0x59);
                    output.extend_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
                }
            }
            output.extend_from_slice(bytes);
        }
        let transfer_frame = |intent: &[u8], digest: &[u8], proofs: &[RoleSignature; 2]| {
            let mut content = vec![0x84, 0x19, 0x70, 0x03];
            bstr(&mut content, intent);
            content.push(0x82);
            let first_role = content.len();
            for (index, proof) in proofs.iter().enumerate() {
                content.extend_from_slice(&[0x87, 1, 1, 1, index as u8]);
                bstr(&mut content, &[index as u8 + 1; 32]);
                bstr(&mut content, digest);
                bstr(&mut content, proof.signature.as_bytes());
            }
            content.push(0xf6);
            (content, first_role)
        };
        let (content, first_role) = transfer_frame(&intent, digest.as_bytes(), &ordinary);
        let inclusion = position(4, 1003);
        // Separately alter algorithm, current key version, role, participant,
        // signed digest or signature while keeping the other fields genuine.
        for offset in [2, 3, 4, 7, 41, 108] {
            let mut tampered = content.clone();
            tampered[first_role + offset] ^= 2;
            let mut candidate = spend_base.clone();
            assert!(registry
                .execute_engineering_transfer(
                    &provider,
                    &snapshot,
                    &mut candidate,
                    PlaintextFixture(&tampered),
                    &schedule,
                    21_000,
                    inclusion,
                )
                .is_err());
            assert_eq!(candidate, spend_base);
        }
        // Matching records in both snapshots do not establish a valid recipient.
        // Reject the former sender-record relabeling even under a matching root.
        for invalid in 0..4 {
            let mut substituted = spend_base.clone();
            let mut bad = registry.read_policy(&substituted, recipient).unwrap();
            match invalid {
                0 => {
                    bad = registry
                        .read_policy(&substituted, enrollment.account())
                        .unwrap();
                    bad.account = *recipient.as_bytes();
                }
                1 => bad.registered_height = 4,
                2 => {
                    substituted.accounts.remove(&recipient_address);
                }
                _ => {
                    substituted
                        .accounts
                        .get_mut(&recipient_address)
                        .unwrap()
                        .code_hash = Some("conflicting-executable-state".into());
                }
            }
            substituted
                .protocol
                .insert(account_key(recipient), encode(&bad).unwrap());
            let (pointer, proof) = finalized(3, &substituted);
            let finalized = registry
                .finalized_snapshot(&substituted, &pointer, &proof, 1002)
                .unwrap();
            let mut candidate = substituted.clone();
            assert!(registry
                .execute_engineering_transfer(
                    &provider,
                    &finalized,
                    &mut candidate,
                    PlaintextFixture(&content),
                    &schedule,
                    21_000,
                    inclusion,
                )
                .is_err());
            assert_eq!(candidate, substituted);
        }
        let report_path = PathBuf::from(std::env::var_os("APQE_TRUSTED_NATIVE_REPORT").unwrap());
        let report_pin = std::env::var("APQE_AUTHENTICATED_REPORT_SHA256").unwrap();
        let limits = EtdagParameters::default();
        let make_admission = |envelope: &ProcessingEnvelope, intent: &CanonicalNativeIntent<'_>| {
            let body = intent.body();
            let resources = Pw13TransferResources {
                genesis: *body.genesis.as_bytes(),
                account: *body.account.as_bytes(),
                policy_epoch: body.policy_epoch,
                policy_hash: new_hash,
                gas_limit: body.gas_limit,
                maximum_total_fee: body.maximum_total_fee,
                valid_until_finalized_height: body.valid_until_finalized_height,
                native_intent_digest: intent.digest().unwrap().as_bytes().to_vec(),
                envelope_id: envelope.envelope_id.clone(),
            };
            let digest = resources.signing_digest().unwrap();
            let proofs = [0, 1].map(|i| Pw13AdmissionProof {
                participant_id: policy.roles[i].participant_id,
                key_version: policy.roles[i].key_version,
                signature: provider
                    .sign(
                        &digest,
                        &keys[i].1,
                        SignOptions::Pure { context: PW13_ADMISSION_CONTEXT },
                    )
                    .unwrap()
                    .as_bytes()
                    .to_vec(),
            });
            Pw13TransferAdmission { resources, proofs }
        };
        let authenticate = |snapshot: &FinalizedSnapshot<'_>,
                            envelope: &ProcessingEnvelope,
                            context: &ProcessingContext,
                            request: &Pw13TransferAdmission| {
            registry.verify_transfer_admission(
                &provider, snapshot, context, envelope, request, &limits, &schedule, 21_000,
            )
        };
        let open = |bytes: &[u8], signed_intent: &[u8], nonce,
                    snapshot: &FinalizedSnapshot<'_>, source: &FinalizedBlockRecord| {
            let signed = CanonicalNativeIntent::decode(signed_intent, 128).unwrap();
            etdag_candidate::open_candidate_envelope(
                bytes,
                &report_path,
                &report_pin,
                99999,
                source,
                &address,
                nonce,
                etdag_candidate::CandidateEnvelopeProfile::Transfer,
                |envelope, context| {
                    authenticate(snapshot, envelope, context, &make_admission(envelope, &signed))
                },
            )
        };
        let (opened, admission) =
            open(&content, &intent, body.transaction_nonce, &snapshot, &snapshot_proof).unwrap();
        assert_eq!(opened.plaintext(), content);
        let original_request = make_admission(
            opened.envelope(),
            &CanonicalNativeIntent::decode(&intent, 128).unwrap(),
        );
        let mut bad_role = original_request.clone();
        let recovery = policy.roles[2];
        bad_role.proofs[1] = Pw13AdmissionProof {
            participant_id: recovery.participant_id,
            key_version: recovery.key_version,
            signature: provider
                .sign(
                    &bad_role.resources.signing_digest().unwrap(),
                    &keys[2].1,
                    SignOptions::Pure { context: PW13_ADMISSION_CONTEXT },
                )
                .unwrap()
                .as_bytes()
                .to_vec(),
        };
        let mut resources_tampered = original_request.clone();
        resources_tampered.resources.maximum_total_fee[0] ^= 1;
        let mut wrong_signature = original_request.clone();
        wrong_signature.proofs[0].signature = ordinary[0].signature.as_bytes().to_vec();
        for invalid in [&bad_role, &resources_tampered, &wrong_signature] {
            assert!(authenticate(&snapshot, opened.envelope(), opened.context(), invalid).is_err());
        }
        assert!(open(&content, &intent, 4, &snapshot, &snapshot_proof).is_err());
        let (mismatched, mismatched_admission) = open(
            &content, &intent, body.transaction_nonce + 1, &snapshot, &snapshot_proof,
        ).unwrap();
        let mut rejected = spend_base.clone();
        assert_eq!(
            registry
                .execute_engineering_transfer(
                    &provider,
                    &snapshot,
                    &mut rejected,
                    OpenedEtdag(&mismatched, &mismatched_admission),
                    &schedule,
                    21_000,
                    inclusion,
                )
                .unwrap_err(),
            "opened PW13 intent differs from the signed resource authorization",
        );
        assert_eq!(rejected, spend_base);
        let mut tampered_proof = content.clone();
        tampered_proof[first_role + 108] ^= 2;
        let (invalid, invalid_admission) =
            open(&tampered_proof, &intent, body.transaction_nonce, &snapshot, &snapshot_proof).unwrap();
        assert!(registry
            .execute_engineering_transfer(
                &provider,
                &snapshot,
                &mut rejected,
                OpenedEtdag(&invalid, &invalid_admission),
                &schedule,
                21_000,
                inclusion,
            )
            .is_err());
        assert_eq!(rejected, spend_base);
        let envelope = opened.envelope();
        let context_root = opened.context().root().unwrap();
        let opening = settlement::EngineeringEtdagOpening {
            envelope_id: envelope.envelope_id.clone(),
            processing_context_root: context_root.clone(),
            authorization_height: envelope.aad.authorization_height,
            payload_root: synergy_execution::processing_payload_root(
                &context_root,
                &envelope.envelope_id,
                &content,
            )
            .unwrap(),
        };
        let mut world = spend_base.clone();
        assert_eq!(
            registry
                .execute_engineering_transfer(
                    &provider,
                    &snapshot,
                    &mut world,
                    OpenedEtdag(&opened, &admission),
                    &schedule,
                    21_000,
                    inclusion,
                )
                .unwrap(),
            CandidateTransferExecution {
                fee_nwei: 840_000,
                revert_reason: None,
            }
        );
        assert_eq!(world.accounts[&address].balance_nwei, 59_993);
        assert_eq!(world.accounts[&address].nonce, 1);
        assert_eq!(world.accounts[&recipient_address].balance_nwei, 7);
        assert_eq!(world.accounts[&schedule.collector].balance_nwei, 840_000);
        let after = state_root(&world).unwrap();
        let (retried_opening, retried_admission) =
            open(&content, &intent, body.transaction_nonce, &snapshot, &snapshot_proof).unwrap();
        assert_ne!(retried_opening.envelope().envelope_id, envelope.envelope_id);
        assert!(authenticate(
            &snapshot, retried_opening.envelope(), retried_opening.context(), &original_request,
        ).is_err());
        assert!(registry
            .execute_engineering_transfer(
                &provider,
                &snapshot,
                &mut world,
                OpenedEtdag(&retried_opening, &retried_admission),
                &schedule,
                21_000,
                inclusion,
            )
            .is_err());
        assert_eq!(state_root(&world).unwrap(), after);
        let mut too_expensive = spend_base.clone();
        let before = state_root(&too_expensive).unwrap();
        assert!(registry
            .execute_engineering_transfer(
                &provider,
                &snapshot,
                &mut too_expensive,
                OpenedEtdag(&opened, &admission),
                &schedule,
                21_001,
                inclusion,
            )
            .is_err());
        assert_eq!(state_root(&too_expensive).unwrap(), before);

        // A failure during the atomic write cannot leave a settlement behind.
        let mut saturated = spend_base.clone();
        saturated
            .accounts
            .get_mut(&recipient_address)
            .unwrap()
            .balance_nwei = u128::MAX;
        let (saturated_pointer, saturated_proof) = finalized(3, &saturated);
        let saturated_snapshot = registry
            .finalized_snapshot(&saturated, &saturated_pointer, &saturated_proof, 1002)
            .unwrap();
        assert!(authenticate(
            &saturated_snapshot, opened.envelope(), opened.context(), &original_request,
        ).is_err());
        let (saturated_opening, saturated_admission) =
            open(&content, &intent, body.transaction_nonce, &saturated_snapshot, &saturated_proof).unwrap();
        let mut failed = saturated.clone();
        assert!(registry
            .execute_engineering_transfer(
                &provider,
                &saturated_snapshot,
                &mut failed,
                OpenedEtdag(&saturated_opening, &saturated_admission),
                &schedule,
                21_000,
                inclusion,
            )
            .is_err());
        assert_eq!(failed, saturated);

        let mut funded = spend_base.clone();
        funded.accounts.get_mut(&address).unwrap().balance_nwei = 1_690_100;
        let (funded_tip, funded_proof) = finalized(3, &funded);
        let funded_snapshot = registry
            .finalized_snapshot(&funded, &funded_tip, &funded_proof, 1002)
            .unwrap();
        let (funded_opening, funded_admission) =
            open(&content, &intent, body.transaction_nonce, &funded_snapshot, &funded_proof).unwrap();
        let mut ordered = funded.clone();
        registry
            .execute_engineering_transfer(
                &provider,
                &funded_snapshot,
                &mut ordered,
                OpenedEtdag(&funded_opening, &funded_admission),
                &schedule,
                21_000,
                inclusion,
            )
            .unwrap();
        assert_eq!(ordered.accounts[&address].balance_nwei, 850_093);
        let mut second_payload = payload.clone();
        let amount_offset = second_payload.len() - 16;
        second_payload[amount_offset..].copy_from_slice(&11_000_u128.to_be_bytes());
        let second_body = NativeIntentBody {
            action_payload: &second_payload,
            transaction_nonce: 1,
            intent_id: [0x32; 32],
            ..body
        };
        let second_intent = second_body.encode(128).unwrap();
        let second_digest = CanonicalNativeIntent::decode(&second_intent, 128)
            .unwrap()
            .digest()
            .unwrap();
        let second_roles = [(Role::D, 0), (Role::P, 1)].map(|(role, index)| RoleSignature {
            role,
            signature: provider
                .sign(
                    second_digest.as_bytes(),
                    &keys[index].1,
                    SignOptions::Pure {
                        context: NATIVE_TX_CONTEXT,
                    },
                )
                .unwrap(),
        });
        let (second_content, _) =
            transfer_frame(&second_intent, second_digest.as_bytes(), &second_roles);
        let (second_opening, second_admission) = open(
            &second_content, &second_intent, second_body.transaction_nonce, &funded_snapshot, &funded_proof,
        ).unwrap();
        let (substituted, substituted_admission) = open(
            &second_content, &intent, second_body.transaction_nonce, &funded_snapshot, &funded_proof,
        ).unwrap();
        let mut substitution_candidate = ordered.clone();
        assert_eq!(
            registry
                .execute_engineering_transfer(
                    &provider,
                    &funded_snapshot,
                    &mut substitution_candidate,
                    OpenedEtdag(&substituted, &substituted_admission),
                    &schedule,
                    21_000,
                    inclusion,
                )
                .unwrap_err(),
            "opened PW13 intent differs from the signed resource authorization",
        );
        assert_eq!(substitution_candidate, ordered);
        let second_transfer = |candidate: &mut WorldState| {
            registry.execute_engineering_transfer(
                &provider,
                &funded_snapshot,
                candidate,
                OpenedEtdag(&second_opening, &second_admission),
                &schedule,
                21_000,
                inclusion,
            )
        };
        let mut out_of_order = funded.clone();
        assert!(second_transfer(&mut out_of_order).is_err());
        assert_eq!(out_of_order, funded);
        let mut unpayable = ordered.clone();
        unpayable.accounts.get_mut(&address).unwrap().balance_nwei = 839_999;
        let unpayable_before = unpayable.clone();
        assert!(second_transfer(&mut unpayable).is_err());
        assert_eq!(unpayable, unpayable_before);
        let mut full_collector = ordered.clone();
        full_collector
            .accounts
            .get_mut(&schedule.collector)
            .unwrap()
            .balance_nwei = u128::MAX;
        let full_collector_before = full_collector.clone();
        assert!(second_transfer(&mut full_collector).is_err());
        assert_eq!(full_collector, full_collector_before);
        assert_eq!(
            second_transfer(&mut ordered).unwrap(),
            CandidateTransferExecution {
                fee_nwei: 840_000,
                revert_reason: Some(settlement::TransferRevertReason::InsufficientTransferBalance),
            }
        );
        assert_eq!(ordered.accounts[&address].balance_nwei, 10_093);
        assert_eq!(ordered.accounts[&address].nonce, 2);
        assert_eq!(ordered.accounts[&recipient_address].balance_nwei, 7);
        assert_eq!(
            ordered.accounts[&schedule.collector].balance_nwei,
            1_680_000
        );
        let attempted_again = ordered.clone();
        assert!(second_transfer(&mut ordered).is_err());
        assert_eq!(ordered, attempted_again);

        let reverted_disk = Scratch::new();
        let (reverted_tip, reverted_proof) = finalized(4, &ordered);
        let mut revert_store = FinalizedStateStore::load(&reverted_disk.0).unwrap();
        revert_store
            .commit_verified_world_state(funded_tip.clone(), &funded)
            .unwrap();
        revert_store
            .commit_verified_world_transition(reverted_tip.clone(), &funded, &ordered)
            .unwrap();
        drop(revert_store);
        let restored_revert = FinalizedStateStore::load(&reverted_disk.0)
            .unwrap()
            .current_world_state()
            .unwrap()
            .unwrap();
        let revert_snapshot = registry
            .finalized_snapshot(&restored_revert, &reverted_tip, &reverted_proof, 1003)
            .unwrap();
        let revert_receipt = settlement::inspect_transfer_settlement(
            &revert_snapshot,
            enrollment.account(),
            second_body.intent_id,
            &as_hex(second_digest.as_bytes()),
            None,
        )
        .unwrap();
        assert_eq!(revert_receipt["status"], "reverted_candidate");
        assert_eq!(
            revert_receipt["revert_reason"],
            "insufficient_transfer_balance"
        );
        assert_eq!(
            revert_receipt["engineering_etdag_opening"]["envelope_id"],
            serde_json::json!(second_opening.envelope().envelope_id)
        );
        assert_eq!(revert_receipt["amount_nwei"], "11000");
        assert_eq!(revert_receipt["credited_nwei"], "0");
        assert_eq!(revert_receipt["fee_nwei"], "840000");
        assert_eq!(revert_receipt["nonce_before"], 1);
        assert_eq!(revert_receipt["nonce_after"], 2);

        // A recipient credit that became infeasible during ordering can
        // revert with a fee only. The certified base here still permits it.
        let mut ordered_credit = spend_base.clone();
        ordered_credit
            .accounts
            .get_mut(&recipient_address)
            .unwrap()
            .balance_nwei = u128::MAX;
        assert_eq!(
            registry
                .execute_engineering_transfer(
                    &provider,
                    &snapshot,
                    &mut ordered_credit,
                    OpenedEtdag(&opened, &admission),
                    &schedule,
                    21_000,
                    inclusion,
                )
                .unwrap()
                .revert_reason,
            Some(settlement::TransferRevertReason::RecipientBalanceOverflow),
        );
        assert_eq!(
            ordered_credit.accounts[&recipient_address].balance_nwei,
            u128::MAX
        );
        assert_eq!(ordered_credit.accounts[&address].balance_nwei, 60_000);
        assert_eq!(ordered_credit.accounts[&address].nonce, 1);

        // Reopen the ledger and reconcile the original signed intent. The
        // finalized snapshot authenticates the same World as the nonce/fee writes.
        let receipt_scratch = Scratch::new();
        let (after_pointer, after_proof) = finalized(4, &world);
        let mut receipt_store = FinalizedStateStore::load(&receipt_scratch.0).unwrap();
        receipt_store
            .commit_verified_world_state(snapshot_pointer.clone(), &spend_base)
            .unwrap();
        receipt_store
            .commit_verified_world_transition(after_pointer.clone(), &spend_base, &world)
            .unwrap();
        drop(receipt_store);
        let receipt_store = FinalizedStateStore::load(&receipt_scratch.0).unwrap();
        let reopened = receipt_store.current_world_state().unwrap().unwrap();
        let settled = registry
            .finalized_snapshot(&reopened, &after_pointer, &after_proof, 1003)
            .unwrap();
        let original_digest = inspection::hex_bytes(digest.as_bytes());
        let original_id = body.intent_id;
        let not_included = settlement::inspect_transfer_settlement(
            &snapshot,
            enrollment.account(),
            original_id,
            &original_digest,
            Some(&opening),
        )
        .unwrap();
        assert_eq!(not_included["status"], "no_settlement_in_snapshot");
        let report = inspection::inspect(
            &reopened,
            &after_proof,
            &after_pointer.state_root,
            1003,
            99999,
            &as_hex(enrollment.genesis().as_bytes()),
            serde_json::from_value(serde_json::json!({
                "height": after_pointer.finalized_height,
                "block_id": after_pointer.finalized_block_id,
                "state_root": after_pointer.state_root,
                "ownership_chain_id": as_hex(ChainId::from_u64(1).as_be_bytes()),
                "provider_manifests": [as_hex(&enrollment.policy().provider_manifest_hash)],
                "addresses": [address, recipient_address],
                "settlements": [{
                    "sender": address,
                    "intent_id": as_hex(&original_id),
                    "signed_intent_digest": original_digest,
                    "engineering_etdag_opening": opening,
                }],
            }))
            .unwrap(),
        )
        .unwrap();
        let result = &report["settlements"][0];
        assert_eq!(report["accounts"][0]["balance_nwei"], "59993");
        assert_eq!(report["accounts"][0]["next_nonce"], 1);
        assert_eq!(report["accounts"][1]["balance_nwei"], "7");
        assert_eq!(result["status"], "applied_candidate");
        assert_eq!(
            result["engineering_etdag_opening"],
            serde_json::to_value(&opening).unwrap()
        );
        let substituted_opening = settlement::EngineeringEtdagOpening {
            envelope_id: retried_opening.envelope().envelope_id.clone(),
            ..opening
        };
        assert!(settlement::inspect_transfer_settlement(
            &settled,
            enrollment.account(),
            original_id,
            &original_digest,
            Some(&substituted_opening),
        )
        .is_err());
        assert_eq!(result["recipient"], recipient_address);
        assert_eq!(result["nonce_before"], 0);
        assert_eq!(result["nonce_after"], 1);
        assert_eq!(result["fee_nwei"], "840000");
        assert_eq!(result["gas_used"], 21_000);
        assert_eq!(result["amount_nwei"], "7");
        assert_eq!(
            result["decrypted_content_sha3_256"],
            as_hex(&Primitives.hash(HashAlgorithm::Sha3256, &content).unwrap())
        );
        assert_eq!(result["included_height"], 4);
        assert_eq!(result["inclusion_consensus_timestamp_unix"], 1003);

        let same_id = NativeIntentBody {
            transaction_nonce: 1,
            ..body
        }
        .encode(128)
        .unwrap();
        let same_id_digest = CanonicalNativeIntent::decode(&same_id, 128)
            .unwrap()
            .digest()
            .unwrap();
        let same_id_proofs = [(Role::D, 0), (Role::P, 1)].map(|(role, index)| RoleSignature {
            role,
            signature: provider
                .sign(
                    same_id_digest.as_bytes(),
                    &keys[index].1,
                    SignOptions::Pure {
                        context: NATIVE_TX_CONTEXT,
                    },
                )
                .unwrap(),
        });
        let (same_id_content, _) =
            transfer_frame(&same_id, same_id_digest.as_bytes(), &same_id_proofs);
        let mut retried = reopened.clone();
        let collision = registry.execute_engineering_transfer(
            &provider,
            &settled,
            &mut retried,
            PlaintextFixture(&same_id_content),
            &schedule,
            21_000,
            position(5, 1004),
        );
        assert_eq!(
            collision.unwrap_err(),
            "protected intent already has a candidate settlement"
        );
        assert_eq!(retried, reopened);
        assert!(settlement::inspect_transfer_settlement(
            &settled,
            enrollment.account(),
            original_id,
            &inspection::hex_bytes(same_id_digest.as_bytes()),
            None,
        )
        .is_err());

        // Use the same independently reloaded enrollment and genuine test
        // signing keys. The candidate must survive a second durable restart.
        use super::super::protected_action_wire::{POLICY_CANCEL, POLICY_SCHEDULE};
        let replacement = provider.generate_keypair().unwrap();
        let mut changed_roles = policy.roles;
        changed_roles[0] = RoleRecord {
            role_id: 0,
            participant_id: [91; 32],
            key_version: 2,
            auth_algorithm: 1,
            auth_public_key: replacement.0.as_bytes(),
        };
        let proposed = PublicPolicy {
            policy_epoch: 1,
            roles: changed_roles,
            ..policy
        }
        .encode(&wire)
        .unwrap();
        let proposed_hash = CanonicalPublicPolicy::decode(&proposed, &wire)
            .unwrap()
            .hash()
            .unwrap();
        let activate_at = 8203;
        let mut schedule_payload = vec![0xa7, 0, 1, 1, 0, 2, 0x58, 32];
        schedule_payload.extend_from_slice(&new_hash);
        schedule_payload.extend_from_slice(&[3, 0x59]);
        schedule_payload.extend_from_slice(&(proposed.len() as u16).to_be_bytes());
        schedule_payload.extend_from_slice(&proposed);
        schedule_payload.extend_from_slice(&[4, 0x58, 32]);
        schedule_payload.extend_from_slice(&proposed_hash);
        schedule_payload.extend_from_slice(&[5, 1, 6, 0x19]);
        schedule_payload.extend_from_slice(&(activate_at as u16).to_be_bytes());
        let schedule_intent = NativeIntentBody {
            action_type: POLICY_SCHEDULE,
            action_payload: &schedule_payload,
            ..body
        }
        .encode(12_000)
        .unwrap();
        let sign_policy = |encoded: &[u8], context, d: usize| {
            let digest = CanonicalNativeIntent::decode(encoded, 12_000)
                .unwrap()
                .digest()
                .unwrap();
            [Role::D, Role::P].map(|role| RoleSignature {
                role,
                signature: provider
                    .sign(
                        digest.as_bytes(),
                        &keys[if role == Role::D { d } else { 1 }].1,
                        SignOptions::Pure { context },
                    )
                    .unwrap(),
            })
        };
        let policy_proofs = sign_policy(&schedule_intent, NATIVE_TX_CONTEXT, 0);
        let target_digest = CanonicalNativeIntent::decode(&schedule_intent, 12_000)
            .unwrap()
            .digest()
            .unwrap();
        let new_pop = provider
            .sign(
                target_digest.as_bytes(),
                &replacement.1,
                SignOptions::Pure {
                    context: b"AEGIS.NEW.ROLE.POP.V1",
                },
            )
            .unwrap();
        let wrong_pop = provider
            .sign(
                target_digest.as_bytes(),
                &keys[0].1,
                SignOptions::Pure {
                    context: b"AEGIS.NEW.ROLE.POP.V1",
                },
            )
            .unwrap();
        let stage = |world: &mut WorldState, time, pop| {
            registry.schedule_ordinary_replacement(
                &provider,
                &snapshot,
                world,
                position(4, time),
                &schedule_intent,
                &policy_proofs,
                pop,
                &schedule,
                1,
            )
        };
        let mut pending_world = spend_base.clone();
        assert!(stage(&mut pending_world, 1004, &new_pop).is_err());
        assert!(stage(&mut pending_world, 1003, &wrong_pop).is_err());
        assert_eq!(pending_world, spend_base);
        let reference = stage(&mut pending_world, 1003, &new_pop).unwrap();
        assert!(stage(&mut pending_world, 1003, &new_pop).is_err());
        assert_eq!(
            registry
                .read_policy(&pending_world, enrollment.account())
                .unwrap()
                .policy_epoch,
            0
        );
        assert_eq!(pending_world.accounts[&address].nonce, 1);
        assert!(registry
            .activate_ordinary_replacement(
                &snapshot,
                &mut pending_world,
                position(5, activate_at),
                enrollment.account()
            )
            .is_err());

        // Both accounts independently sign appointments for the same
        // deadline. Finalizing batches with visit_limit=1 must keep the
        // second account queued, even across a restart.
        let mut multi = pending_world.clone();
        multi
            .accounts
            .get_mut(&recipient_address)
            .unwrap()
            .balance_nwei = 100;
        let second_key = provider.generate_keypair().unwrap();
        let mut second_roles = recipient_policy.roles;
        second_roles[0] = RoleRecord {
            role_id: 0,
            participant_id: [31; 32],
            key_version: 2,
            auth_algorithm: 1,
            auth_public_key: second_key.0.as_bytes(),
        };
        let second_policy = PublicPolicy {
            roles: second_roles,
            policy_epoch: 1,
            ..recipient_policy
        }
        .encode(&wire)
        .unwrap();
        let target_hash = CanonicalPublicPolicy::decode(&second_policy, &wire)
            .unwrap()
            .hash()
            .unwrap();
        let previous_hash = registry
            .read_policy(&spend_base, recipient)
            .unwrap()
            .policy_hash;
        let mut second_payload = vec![0xa7, 0, 1, 1, 0, 2, 0x58, 32];
        second_payload.extend_from_slice(&previous_hash);
        second_payload.extend_from_slice(&[3, 0x59]);
        second_payload
            .extend_from_slice(&u16::try_from(second_policy.len()).unwrap().to_be_bytes());
        second_payload.extend_from_slice(&second_policy);
        second_payload.extend_from_slice(&[4, 0x58, 32]);
        second_payload.extend_from_slice(&target_hash);
        second_payload.extend_from_slice(&[5, 1, 6, 0x19]);
        second_payload.extend_from_slice(&(activate_at as u16).to_be_bytes());
        let second_intent = NativeIntentBody {
            account: recipient,
            action_type: POLICY_SCHEDULE,
            action_payload: &second_payload,
            intent_id: [21; 32],
            ..body
        }
        .encode(12_000)
        .unwrap();
        let second_digest = CanonicalNativeIntent::decode(&second_intent, 12_000)
            .unwrap()
            .digest()
            .unwrap();
        let second_proofs = [Role::D, Role::P].map(|role| RoleSignature {
            role,
            signature: provider
                .sign(
                    second_digest.as_bytes(),
                    &recipient_keys[usize::from(role == Role::P)].1,
                    SignOptions::Pure {
                        context: NATIVE_TX_CONTEXT,
                    },
                )
                .unwrap(),
        });
        let second_pop = provider
            .sign(
                second_digest.as_bytes(),
                &second_key.1,
                SignOptions::Pure {
                    context: b"AEGIS.NEW.ROLE.POP.V1",
                },
            )
            .unwrap();
        registry
            .schedule_ordinary_replacement(
                &provider,
                &snapshot,
                &mut multi,
                position(4, 1003),
                &second_intent,
                &second_proofs,
                &second_pop,
                &schedule,
                1,
            )
            .unwrap();
        assert!(registry
            .apply_due_transitions_fixture(&snapshot, &mut multi, position(5, activate_at), 2,)
            .unwrap()
            .is_empty());
        let (multi_tip, multi_finality) = finalized(4, &multi);
        let multi_snapshot = registry
            .finalized_snapshot(&multi, &multi_tip, &multi_finality, 1003)
            .unwrap();
        let mut expected_accounts = [enrollment.account(), recipient];
        expected_accounts.sort_by_key(|account| *account.as_bytes());
        let indexed = transition_queue::due(&multi, activate_at, 2).unwrap();
        assert_eq!(
            indexed
                .iter()
                .map(|entry| entry.account)
                .collect::<Vec<_>>(),
            expected_accounts
        );
        let mut corrupt = multi.clone();
        corrupt.protocol.insert(indexed[1].key(), vec![0xff]);
        let corrupt_before = corrupt.clone();
        assert!(registry
            .apply_due_transitions_fixture(
                &multi_snapshot,
                &mut corrupt,
                position(5, activate_at),
                2,
            )
            .is_err());
        assert_eq!(corrupt, corrupt_before);
        let mut first_batch = multi.clone();
        assert!(registry
            .apply_due_transitions_fixture(
                &multi_snapshot,
                &mut first_batch,
                position(5, activate_at - 1),
                1,
            )
            .unwrap()
            .is_empty());
        assert_eq!(first_batch, multi);
        let first_outcomes = registry
            .apply_due_transitions_fixture(
                &multi_snapshot,
                &mut first_batch,
                position(5, activate_at),
                1,
            )
            .unwrap();
        assert_eq!(first_batch.accounts, multi.accounts);
        assert!(first_batch.protocol.contains_key(&indexed[1].key()));
        let batch_disk = Scratch::new();
        let (batch_tip, batch_finality) = finalized(5, &first_batch);
        let mut batch_store = FinalizedStateStore::load(&batch_disk.0).unwrap();
        batch_store
            .commit_verified_world_state(multi_tip, &multi)
            .unwrap();
        batch_store
            .commit_verified_world_transition(batch_tip.clone(), &multi, &first_batch)
            .unwrap();
        drop(batch_store);
        let reopened = FinalizedStateStore::load(&batch_disk.0)
            .unwrap()
            .current_world_state()
            .unwrap()
            .unwrap();
        assert_eq!(reopened, first_batch);
        let reopened_snapshot = registry
            .finalized_snapshot(&reopened, &batch_tip, &batch_finality, activate_at)
            .unwrap();
        let second_outcomes = registry
            .apply_due_transitions_fixture(
                &reopened_snapshot,
                &mut first_batch,
                position(6, activate_at),
                1,
            )
            .unwrap();
        for (offset, outcomes) in [first_outcomes, second_outcomes].iter().enumerate() {
            let [outcome] = outcomes.as_slice() else {
                panic!("expected one due activation per batch");
            };
            let entry = indexed[offset];
            let source_height = 4 + offset as u64;
            assert_eq!(outcome.transition, entry);
            assert_eq!(outcome.kind, TransitionOutcomeKind::Activated);
            assert_eq!(outcome.source_finalized_height, source_height);
            assert_eq!(outcome.included, position(source_height + 1, activate_at));
            assert_eq!(outcome.old_policy_epoch, 0);
            assert_eq!(outcome.resulting_policy_epoch, 1);
            assert_eq!(
                outcome.old_policy_hash,
                registry
                    .read_policy(&multi, entry.account)
                    .unwrap()
                    .policy_hash
            );
            assert_eq!(
                outcome.resulting_policy_hash,
                registry
                    .read_policy(&first_batch, entry.account)
                    .unwrap()
                    .policy_hash
            );
            assert!(outcome.signed_charge.is_none());
        }
        assert_eq!(first_batch.accounts, multi.accounts);
        for entry in indexed {
            assert!(!first_batch.protocol.contains_key(&entry.key()));
            assert!(!first_batch
                .protocol
                .contains_key(&transition_key(entry.account)));
            assert_eq!(
                registry
                    .read_policy(&first_batch, entry.account)
                    .unwrap()
                    .policy_epoch,
                1
            );
        }

        let pending_disk = Scratch::new();
        let parent = finalized(4, &pending_world);
        FinalizedStateStore::load(&pending_disk.0)
            .unwrap()
            .commit_verified_world_state(parent.0.clone(), &pending_world)
            .unwrap();
        let persisted = FinalizedStateStore::load(&pending_disk.0)
            .unwrap()
            .current_world_state()
            .unwrap()
            .unwrap();
        let finalized_pending = registry
            .finalized_snapshot(&persisted, &parent.0, &parent.1, 1003)
            .unwrap();
        let transition_selector = serde_json::json!({
            "address": address,
            "pending_reference": as_hex(&reference),
        });
        let observed = observe(
            &persisted,
            &parent.0,
            &parent.1,
            vec![&address],
            1003,
            std::slice::from_ref(&transition_selector),
        )
        .unwrap();
        assert_eq!(
            observed["transition_settlements"][0]["status"],
            "no_transition_settlement_in_snapshot"
        );
        assert_eq!(
            observed["accounts"][0]["pending_transition"],
            serde_json::json!({
                "status": "scheduled_candidate",
                "mode": "ordinary",
                "pending_reference": as_hex(&reference),
                "replaced_role": 0,
                "old_policy_epoch": 0,
                "old_policy_hash": as_hex(&new_hash),
                "new_policy_hash": as_hex(&proposed_hash),
                "scheduled_height": 4,
                "scheduled_consensus_timestamp_unix": 1003,
                "activation_timestamp_unix": activate_at,
            })
        );
        let mut cancel_payload = vec![0xa2, 0, 1, 1, 0x58, 32];
        cancel_payload.extend_from_slice(&reference);
        let cancel_intent = NativeIntentBody {
            transaction_nonce: 1,
            action_type: POLICY_CANCEL,
            action_payload: &cancel_payload,
            ..body
        }
        .encode(40)
        .unwrap();
        let cancel_proofs = sign_policy(&cancel_intent, NATIVE_TX_CONTEXT, 0);
        let cancel = |world: &mut WorldState, time| {
            registry.cancel_ordinary_replacement(
                &provider,
                &finalized_pending,
                world,
                position(5, time),
                &cancel_intent,
                &cancel_proofs,
                &schedule,
                1,
            )
        };
        let mut canceled = persisted.clone();
        assert!(cancel(&mut canceled, activate_at).is_err());
        let canceled_outcome = cancel(&mut canceled, activate_at - 1).unwrap();
        let signed = CanonicalNativeIntent::decode(&cancel_intent, 40).unwrap();
        assert_eq!(canceled_outcome.kind, TransitionOutcomeKind::Canceled);
        assert_eq!(canceled_outcome.transition.account, enrollment.account());
        assert_eq!(canceled_outcome.transition.reference, reference);
        assert_eq!(canceled_outcome.source_finalized_height, 4);
        assert_eq!(canceled_outcome.included, position(5, activate_at - 1));
        assert_eq!(canceled_outcome.old_policy_epoch, 0);
        assert_eq!(canceled_outcome.resulting_policy_epoch, 0);
        assert_eq!(canceled_outcome.old_policy_hash, new_hash);
        assert_eq!(canceled_outcome.resulting_policy_hash, new_hash);
        assert_eq!(
            canceled_outcome.signed_charge,
            Some(SignedTransitionCharge {
                action: POLICY_CANCEL,
                intent_id: signed.body().intent_id,
                signed_digest: *signed.digest().unwrap().as_bytes(),
                gas_used: 1,
                fee_nwei: u128::from(schedule.base_fee_per_gas_nwei),
                nonce_before: 1,
                nonce_after: 2,
            })
        );
        assert!(registry
            .activate_ordinary_replacement(
                &finalized_pending,
                &mut canceled,
                position(5, activate_at),
                enrollment.account()
            )
            .is_err());
        assert_eq!(canceled.accounts[&address].nonce, 2);
        assert_eq!(
            registry
                .read_policy(&canceled, enrollment.account())
                .unwrap()
                .policy_epoch,
            0
        );
        let original_digest = as_hex(signed.digest().unwrap().as_bytes());
        let mut cancel_selector = transition_selector.clone();
        cancel_selector["signed_intent_digest"] = serde_json::json!(original_digest);
        let canceled_tip = finalized(5, &canceled);
        let canceled_disk = Scratch::new();
        let mut canceled_store = FinalizedStateStore::load(&canceled_disk.0).unwrap();
        canceled_store
            .commit_verified_world_state(parent.0.clone(), &persisted)
            .unwrap();
        canceled_store
            .commit_verified_world_transition(canceled_tip.0.clone(), &persisted, &canceled)
            .unwrap();
        drop(canceled_store);
        let restored_cancel = FinalizedStateStore::load(&canceled_disk.0)
            .unwrap()
            .current_world_state()
            .unwrap()
            .unwrap();
        let canceled_read = |selected: &[serde_json::Value]| {
            observe(
                &restored_cancel,
                &canceled_tip.0,
                &canceled_tip.1,
                vec![&address],
                activate_at - 1,
                selected,
            )
        };
        let result = canceled_read(std::slice::from_ref(&cancel_selector)).unwrap();
        let record = &result["transition_settlements"][0];
        assert_eq!(record["status"], "canceled_candidate");
        assert_eq!(record["pending_reference"], as_hex(&reference));
        assert_eq!(
            record["signed_charge"],
            serde_json::json!({
                "action": POLICY_CANCEL,
                "intent_id": as_hex(&signed.body().intent_id),
                "signed_intent_digest": original_digest,
                "gas_used": 1,
                "fee_nwei": schedule.base_fee_per_gas_nwei.to_string(),
                "nonce_before": 1,
                "nonce_after": 2,
            })
        );
        let mut conflicting_selector = cancel_selector.clone();
        conflicting_selector["signed_intent_digest"] = serde_json::json!("a5".repeat(64));
        assert!(canceled_read(&[conflicting_selector]).is_err());
        assert!(canceled_read(&[cancel_selector.clone(), cancel_selector.clone()]).is_err());
        let write = transition_settlement::prepare_transition_settlement(
            &finalized_pending,
            &canceled_outcome,
        )
        .unwrap();
        let mut conflict = persisted.clone();
        conflict.protocol.insert(write.key, write.value.unwrap());
        let unchanged = conflict.clone();
        assert!(cancel(&mut conflict, activate_at - 1).is_err());
        assert_eq!(conflict, unchanged);

        let mut activated = persisted.clone();
        let activate = |world: &mut WorldState, time| {
            registry.activate_ordinary_replacement(
                &finalized_pending,
                world,
                position(5, time),
                enrollment.account(),
            )
        };
        assert!(activate(&mut activated, activate_at - 1).is_err());
        assert_eq!(activated, persisted);
        activate(&mut activated, activate_at).unwrap();
        let root = state_root(&activated).unwrap();
        assert!(activate(&mut activated, activate_at).is_err());
        assert_eq!(state_root(&activated).unwrap(), root);
        assert_eq!(activated.accounts[&address], persisted.accounts[&address]);
        let current_record = registry
            .read_policy(&activated, enrollment.account())
            .unwrap();
        assert_eq!(current_record.policy_epoch, 1);
        assert_eq!(current_record.policy_hash, proposed_hash);
        let post = finalized(5, &activated);
        let post_snapshot = registry
            .finalized_snapshot(&activated, &post.0, &post.1, activate_at)
            .unwrap();
        let settled = observe(
            &activated,
            &post.0,
            &post.1,
            vec![&address],
            activate_at,
            &[transition_selector],
        )
        .unwrap();
        assert_eq!(
            settled["accounts"][0].get("pending_transition"),
            Some(&serde_json::Value::Null)
        );
        let activation = &settled["transition_settlements"][0];
        assert_eq!(activation["status"], "activated_candidate");
        assert_eq!(
            activation.get("signed_charge"),
            Some(&serde_json::Value::Null)
        );
        let new_intent = NativeIntentBody {
            policy_epoch: 1,
            transaction_nonce: 1,
            valid_until_finalized_height: 5,
            ..body
        }
        .encode(128)
        .unwrap();
        let old_key = sign_policy(&new_intent, NATIVE_TX_CONTEXT, 0);
        let digest = CanonicalNativeIntent::decode(&new_intent, 128)
            .unwrap()
            .digest()
            .unwrap();
        let new_key = [
            RoleSignature {
                role: Role::D,
                signature: provider
                    .sign(
                        digest.as_bytes(),
                        &replacement.1,
                        SignOptions::Pure {
                            context: NATIVE_TX_CONTEXT,
                        },
                    )
                    .unwrap(),
            },
            sign_policy(&new_intent, NATIVE_TX_CONTEXT, 0)
                .into_iter()
                .last()
                .unwrap(),
        ];
        let verify = |bytes, sigs| {
            registry.verify_spend(
                &provider,
                &post_snapshot,
                &activated,
                bytes,
                128,
                super::super::protected_action_wire::decode_transfer,
                sigs,
            )
        };
        assert!(verify(&intent, &ordinary).is_err());
        assert!(verify(&new_intent, &old_key).is_err());
        assert!(verify(&new_intent, &new_key).is_ok());
    }
}
