//! Candidate-only adapter from APQE enrollment proofs to Core's committed World.
//! No RPC, ETDAG action dispatch, or genesis path may activate these assignments.
#![allow(dead_code)] // A governed wire/action/fee profile is required before runtime dispatch.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use synergy_address_engine::apqe::{
    account_binding::ExternalChainPolicy,
    address::AccountIdentifier,
    authorization::{
        verify_signature_quorum_for_caller_validated_transcript, CallerValidatedTranscript,
        CurrentAccountState, EnrolledRole, IntentConstraints, NativeAction, NativePolicy, Role,
        RoleSignature, VerifiedSignatureQuorum, NATIVE_TX_CONTEXT,
    },
    enrollment::{CanonicalEnrollment, EnrollmentSignature, UnactivatedWireProfile},
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

const COMMIT_PREFIX: &str = "apqe-protected-account-candidate/v1/commit/";
const ACCOUNT_PREFIX: &str = "apqe-protected-account-candidate/v1/policy/";
const MAX_ENROLLMENT_BYTES: usize = 24 * 1024;
// Internal bounded state values, not RPC or consensus-action wire assignments.
const MAX_STORED_POLICY_BYTES: usize = MAX_ENROLLMENT_BYTES * 4 + 4096;
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

/// Construct only with the exact PoSy-verified finality record and its
/// authenticated finalized state pointer. The record itself is not a QC proof.
pub(super) struct FinalizedSnapshot<'a> {
    registry: &'a CandidateProtectedAccounts<'a>,
    world: &'a WorldState,
    position: Position,
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
    ) -> Result<(StateDiff, u128), String> {
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
        if self.network.native_chain[..24] != [0; 24]
            || synergy_address::decode_address(sponsor.payer)?.hrp != "syna"
        {
            return Err("unsupported sponsor network or address".into());
        }
        let chain_id = u64::from_be_bytes(self.network.native_chain[24..].try_into().unwrap());
        let commitment =
            canonical_binding_commitment_if_present(&finalized.world.protocol, sponsor.payer)?
                .ok_or("sponsor is not registered in finalized state")?;
        if canonical_binding_commitment_if_present(&world.protocol, sponsor.payer)?.as_ref()
            != Some(&commitment)
        {
            return Err("sponsor binding changed in execution state".into());
        }
        let payer = proof
            .binding
            .identity_address_for_key_for_admission_at_with_verifier(
                SPONSOR_SIGNATURE_DOMAIN,
                chain_id,
                network_id,
                "ML-DSA-87",
                proof.signing_key.as_bytes(),
                SPONSOR_PURPOSE,
                finalized.position.consensus_time,
                &commitment.binding_payload_sha3_256,
                Some(identity_verifier),
            )?;
        if payer != sponsor.payer
            || proof.binding.binding.identity_root.public_key_sha3_256
                != commitment.identity_root_public_key_sha3_256
            || commitment.effective_at_unix > finalized.position.consensus_time
        {
            return Err("sponsor payer differs from finalized binding".into());
        }
        provider
            .verify(
                &sponsor_digest(proof.intent)?,
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
        Ok((
            StateDiff {
                changes: vec![
                    AccountChange {
                        account: payer,
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
            fee,
        ))
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
    ) -> Result<(bool, u128), String> {
        use super::protected_action_wire::{decode, Payload, ENROLL_COMMIT};
        let Payload::Commit(hash) = decode(ENROLL_COMMIT, payload)? else {
            return Err("expected enrollment commitment".into());
        };
        let (fee_diff, fee) = self.prepare_sponsor_fee(
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
        if world.protocol.contains_key(&commit_key(commitment)) {
            fee_diff.apply(world).map_err(debug)?;
            return Ok((false, fee));
        }
        let commit = self.prepare_commit(world, commitment, inclusion)?;
        StateDiff::apply_ordered_atomic(&[&commit, &fee_diff], world).map_err(debug)?;
        Ok((true, fee))
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
        let record: CommitRecord = decode(bytes, MAX_STORED_COMMIT_BYTES)?;
        if record.network != self.network
            || record.commitment != *commitment.as_bytes()
            || record.included_height == 0
            || record.consensus_time == 0
            || record.consumed
        {
            return Err("protected enrollment commitment is used or mismatched".into());
        }
        Ok((bytes, record))
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
        if record.network != self.network
            || record.account != *account.as_bytes()
            || record.registered_height == 0
        {
            return Err("protected account registration network or identifier mismatch".into());
        }
        Ok(record)
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
        if !std::ptr::eq(self, finalized.registry) {
            return Err("protected intent requires the selected finalized parent".into());
        }
        let intent =
            CanonicalNativeIntent::decode(encoded_intent, max_action_payload).map_err(display)?;
        let body = intent.body();
        let record = self.read_policy(finalized.world, body.account)?;
        if record != self.read_policy(world, body.account)?
            || record.registered_height > finalized.position.height
        {
            return Err("protected policy changed or is not finalized".into());
        }
        let enrollment =
            CanonicalEnrollment::decode(&record.enrollment, self.wire).map_err(display)?;
        if enrollment.genesis() != self.chain.native_genesis()
            || enrollment.account() != body.account
            || enrollment.policy().policy_epoch != record.policy_epoch
            || enrollment.policy_hash().map_err(display)? != record.policy_hash
        {
            return Err("protected account policy does not match its canonical enrollment".into());
        }
        let address = body.account.to_native(&Primitives).map_err(display)?;
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
                account: body.account,
            },
            policy_epoch: record.policy_epoch,
            next_nonce: ledger.nonce,
            height: finalized.position.height,
            consensus_time: finalized.position.consensus_time,
            recovery_vetoed: false, // Only ordinary D/P spending is eligible here.
        };
        intent.check_state(&state).map_err(display)?;
        let decoded = decode_selected_spend(body)?;
        let [d, p, r] = enrollment.policy().roles;
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
                action: NativeAction::Spend,
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

    /// Candidate execution is test-only until an actual admission profile binds
    /// these bytes, verification rules and the fee schedule to consensus.
    #[cfg(test)]
    fn execute_engineering_transfer(
        &self,
        provider: &PqProvider<Mldsa87>,
        finalized: &FinalizedSnapshot<'_>,
        world: &mut WorldState,
        encoded_intent: &[u8],
        signatures: &[RoleSignature; 2],
        fee_schedule: &synergy_execution::FeeSchedule,
        gas: u64,
    ) -> Result<u128, String> {
        use super::protected_action_wire::decode_transfer;
        const TRANSFER_MAX: usize = 60;
        let intent =
            CanonicalNativeIntent::decode(encoded_intent, TRANSFER_MAX).map_err(display)?;
        let body = intent.body();
        let ((recipient, amount), _) = self.verify_spend(
            provider,
            finalized,
            world,
            encoded_intent,
            TRANSFER_MAX,
            decode_transfer,
            signatures,
        )?;
        if recipient == body.account
            || self.read_policy(world, recipient)?
                != self.read_policy(finalized.world, recipient)?
        {
            return Err("invalid or unfinalized protected recipient".into());
        }
        let sender = body.account.to_native(&Primitives).map_err(display)?;
        let recipient = recipient.to_native(&Primitives).map_err(display)?;
        if !world
            .accounts
            .get(&recipient)
            .is_some_and(|account| account.code_hash.is_none())
        {
            return Err("protected recipient ledger state is absent or invalid".into());
        }
        fee_schedule.validate().map_err(display)?;
        let fee = u128::from(gas) * u128::from(fee_schedule.base_fee_per_gas_nwei);
        if gas == 0
            || gas > body.gas_limit
            || fee_schedule.collector == sender
            || fee_schedule.collector == recipient
            || body.intent_id == [0; 32]
            || (body.maximum_total_fee[..16] == [0; 16]
                && body.maximum_total_fee[16..] < fee.to_be_bytes()[..])
        {
            return Err("protected transfer exceeds fee or gas authorization".into());
        }
        let debit = amount
            .checked_add(fee)
            .ok_or("protected transfer debit overflow")?;
        let diff = StateDiff {
            changes: vec![
                AccountChange {
                    account: sender,
                    debit_nwei: debit,
                    credit_nwei: 0,
                    expected_nonce: Some(body.transaction_nonce),
                    code_hash: None,
                },
                AccountChange {
                    account: recipient,
                    debit_nwei: 0,
                    credit_nwei: amount,
                    expected_nonce: None,
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
        };
        StateDiff::apply_ordered_atomic(&[&diff], world).map_err(debug)?;
        Ok(fee)
    }
}

/// Keep unchecked writes private. A stale account, spent commit, existing policy
/// or failing approved fee diff must leave both the ledger and protocol untouched.
pub(super) struct CandidateEnrollmentWrite {
    address: String,
    diff: StateDiff,
}

impl CandidateEnrollmentWrite {
    pub(super) fn apply_with_fee(
        self,
        world: &mut WorldState,
        authorized_fee_diff: &StateDiff,
    ) -> Result<(), String> {
        if !eligible_account(world, &self.address)
            || authorized_fee_diff
                .changes
                .iter()
                .any(|change| change.account == self.address)
            || authorized_fee_diff.protocol_changes.iter().any(|change| {
                change.key.starts_with(ACCOUNT_PREFIX) || change.key.starts_with(COMMIT_PREFIX)
            })
        {
            return Err("protected enrollment conflicts with existing state or fee writes".into());
        }
        StateDiff::apply_ordered_atomic(&[&self.diff, authorized_fee_diff], world).map_err(debug)
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
        enrollment::{EnrollmentData, PublicPolicy, RoleRecord, UnactivatedWireAssignments},
        identity::WalletUuid,
        provider::{Profile, SignOptions, Signature},
    };
    use synergy_state::{AccountState, FinalizedStateStore};

    fn wire() -> UnactivatedWireProfile {
        UnactivatedWireProfile::new(UnactivatedWireAssignments {
            ordinary_roles_key: 0,
            recovery_pairs_key: 1,
            recovery_only_key: 2,
            initial_status: 0,
            initial_epoch: 0,
            mldsa87_algorithm_id: 1,
            dkg_commitment_bytes: 32,
            recovery_ack_domain: b"AEGIS/RECOVERY-ENROLL/v1",
            recovery_ack_context: b"AEGIS.RECOVERY.ENROLL.V1",
        })
        .unwrap()
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

    fn finalized(height: u64, world: &WorldState) -> (FinalizedState, FinalizedBlockRecord) {
        let block_id = format!("{height:064x}");
        (
            FinalizedState {
                finalized_height: height,
                finalized_block_id: block_id.clone(),
                state_root: state_root(world).unwrap(),
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
    fn protected_sponsor_pays_once_and_paid_duplicate_never_changes_commitment() {
        use std::sync::{Arc, Mutex};
        use synergy_address_engine::{apqe::native_manifest::validator_engine, types::Algorithm};
        use synergy_identity::authorization::*;

        let report = PathBuf::from(std::env::var_os("APQE_TRUSTED_NATIVE_REPORT").unwrap());
        let report_pin = hex(&std::env::var("APQE_AUTHENTICATED_REPORT_SHA256").unwrap())
            .try_into()
            .unwrap();
        let engine = Arc::new(Mutex::new(
            unsafe { validator_engine(&report, report_pin) }.unwrap(),
        ));
        let verifier = ApqeIdentityVerifier::new(engine.clone()).unwrap();
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
        let key = PublicKey::from_bytes(&signer.public_key).unwrap();
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
        drop(engine);
        let admitted = IdentityAuthorizationBindingCommitment::from_verified_binding_with_verifier(
            &carrier.binding,
            1000,
            Some(&verifier),
        )
        .unwrap();
        let mut base = WorldState::default();
        base.protocol.insert(
            IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY.into(),
            serde_json::to_vec(&std::collections::BTreeMap::from([(
                address.clone(),
                admitted,
            )]))
            .unwrap(),
        );
        base.accounts.insert(
            address.clone(),
            AccountState {
                balance_nwei: 100,
                ..Default::default()
            },
        );
        let wire = wire();
        let genesis = NativeGenesisHash::from_bytes([0x11; 32]);
        let registry = registry(&wire, genesis, [0x22; 32]);
        let (pointer, certificate) = finalized(1, &base);
        let snapshot = registry
            .finalized_snapshot(&base, &pointer, &certificate, 1000)
            .unwrap();
        let mut world = base.clone();
        let mut payload = vec![0xa2, 0, 1, 1, 0x58, 32];
        payload.extend_from_slice(&[0x33; 32]);
        let schedule = synergy_execution::FeeSchedule {
            base_fee_per_gas_nwei: 2,
            collector: "test-collector".into(),
        };
        let intent_for = |nonce: u8, cap: u8, expiry: u8| {
            let mut bytes = vec![0xa8, 0, 1, 1, 0x58, 32];
            bytes.extend_from_slice(genesis.as_bytes());
            bytes.extend_from_slice(&[2, 0x78, address.len().try_into().unwrap()]);
            bytes.extend_from_slice(address.as_bytes());
            bytes.extend_from_slice(&[3, nonce, 4, 0x19, 0x70, 1, 5, 0x58, 32]);
            bytes.extend_from_slice(&Primitives.hash(HashAlgorithm::Sha3256, &payload).unwrap());
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
            registry.execute_sponsored_commit(
                &provider,
                &verifier,
                network,
                &snapshot,
                world,
                position(2, 1001),
                content,
                &SponsorProof {
                    intent: encoded,
                    binding: &carrier,
                    signing_key: &key,
                    signature: &signature,
                },
                &schedule,
                5,
            )
        };
        let first = intent_for(0, 10, 1);
        assert_eq!(
            execute(&mut world, &first, &first, "test-sponsor", &payload).unwrap(),
            (true, 10)
        );
        let after_first = state_root(&world).unwrap();
        let second = intent_for(1, 10, 1);
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
                intent_for(1, 9, 1),
                intent_for(1, 9, 1),
                "test-sponsor",
                &payload,
            ),
            (
                intent_for(1, 10, 0),
                intent_for(1, 10, 0),
                "test-sponsor",
                &payload,
            ),
        ] {
            assert!(execute(&mut world, &encoded, &signed, network, content).is_err());
            assert_eq!(state_root(&world).unwrap(), after_first);
        }
        let records = world.protocol.clone();
        assert_eq!(
            execute(&mut world, &second, &second, "test-sponsor", &payload).unwrap(),
            (false, 10)
        );
        assert_eq!(world.protocol, records);
        assert_eq!(world.accounts[&address].balance_nwei, 80);
        assert_eq!(world.accounts[&address].nonce, 2);
        assert_eq!(world.accounts[&schedule.collector].balance_nwei, 20);
    }

    fn verifier_test_signer(
        report: &std::path::Path,
        pin: [u8; 32],
        key: &[u8],
        encoded: &[u8],
    ) -> Signature<Mldsa87> {
        use synergy_address_engine::{apqe::native_manifest::validator_engine, types::Algorithm};
        let mut engine = unsafe { validator_engine(report, pin) }.unwrap();
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

    #[test]
    #[ignore = "requires explicit APQE public fixture and pinned native validation artifact"]
    fn protected_candidate_apqe_proofs_are_atomic_and_survive_restart() {
        let fixture_path = std::env::var_os("CORE_APQE_ENROLLMENT_FIXTURE").unwrap();
        let fixture: serde_json::Value =
            serde_json::from_slice(&std::fs::read(fixture_path).unwrap()).unwrap();
        let bytes = |name: &str| hex(fixture[name].as_str().unwrap());
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
                &bytes("ecdsa_der"),
                point.as_sec1_bytes(),
            )
            .unwrap();
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
        let recipient = AccountIdentifier::from_bytes([44; 20]);
        let recipient_address = recipient.to_native(&Primitives).unwrap();
        record.account = *recipient.as_bytes();
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
        let mut world = spend_base.clone();
        assert_eq!(
            registry
                .execute_engineering_transfer(
                    &provider, &snapshot, &mut world, &intent, &ordinary, &schedule, 21_000,
                )
                .unwrap(),
            840_000
        );
        assert_eq!(world.accounts[&address].balance_nwei, 59_993);
        assert_eq!(world.accounts[&address].nonce, 1);
        assert_eq!(world.accounts[&recipient_address].balance_nwei, 7);
        assert_eq!(world.accounts[&schedule.collector].balance_nwei, 840_000);
        let after = state_root(&world).unwrap();
        assert!(registry
            .execute_engineering_transfer(
                &provider, &snapshot, &mut world, &intent, &ordinary, &schedule, 21_000,
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
                &intent,
                &ordinary,
                &schedule,
                21_001,
            )
            .is_err());
        assert_eq!(state_root(&too_expensive).unwrap(), before);
    }
}
