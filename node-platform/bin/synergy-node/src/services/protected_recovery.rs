//! Native-only recovery preparation and isolated state-machine qualification.
//!
//! PW13 requires independent provider/DKG continuity for recovery payload key 7.
//! Its digest alone and equality of aggregate points are not that evidence. This
//! check deliberately confers no permission to stage or activate a live recovery.
use super::*;
use synergy_address_engine::apqe::policy_transition::{
    check_policy_replacement, PolicyReplacementRequest, ReplacementMode,
};

pub(super) struct NativeRecoveryCheck {
    pub(super) pending_reference: [u8; 32],
    pub(super) continuity_reference: [u8; 32],
    pub(super) new_policy_hash: [u8; 32],
    pub(super) activation_at: u64,
    pub(super) replacement: Role,
    // Keep the actual cryptographic result distinct from continuity evidence.
    pub(super) native_quorum: VerifiedSignatureQuorum,
    #[cfg(test)]
    pending: PendingRecovery,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PendingRecovery {
    pub(super) change: ScheduledPolicyChange,
    pub(super) continuity_reference: [u8; 32],
}

impl CandidateProtectedAccounts<'_> {
    /// Check R+survivor, exact canonical policy delta, nonce and replacement PoP.
    /// No fees/nonces/pending state are changed, and continuity is NOT verified.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn inspect_recovery_schedule(
        &self,
        provider: &PqProvider<Mldsa87>,
        finalized: &FinalizedSnapshot<'_>,
        world: &WorldState,
        inclusion: Position,
        encoded: &[u8],
        signatures: &[RoleSignature; 2],
        possession: &Signature<Mldsa87>,
    ) -> Result<NativeRecoveryCheck, String> {
        use super::super::protected_action_wire::{decode, Payload, MAX_POLICY, RECOVERY_SCHEDULE};
        if inclusion.height <= finalized.position.height
            || inclusion.consensus_time < finalized.position.consensus_time
        {
            return Err("invalid recovery scheduling position".into());
        }
        let limit = MAX_POLICY + 160;
        let intent = CanonicalNativeIntent::decode(encoded, limit).map_err(display)?;
        let body = intent.body();
        let pending_key = account_key(body.account).replacen(ACCOUNT_PREFIX, TRANSITION_PREFIX, 1);
        if world.protocol.contains_key(&pending_key)
            || finalized.world.protocol.contains_key(&pending_key)
        {
            return Err("protected account already has a pending transition".into());
        }
        let (payload, native_quorum) = self.verify_native_pair(
            provider,
            finalized,
            world,
            encoded,
            limit,
            signatures,
            |body| {
                if body.action_type != RECOVERY_SCHEDULE {
                    return Err("expected RECOVERY_SCHEDULE".into());
                }
                let payload = decode(RECOVERY_SCHEDULE, body.action_payload)?;
                let Payload::Schedule {
                    role,
                    old_policy,
                    new_policy_hash,
                    activation_at,
                    ..
                } = payload
                else {
                    return Err("expected recovery schedule payload".into());
                };
                let replace = if role == 0 { Role::D } else { Role::P };
                Ok((
                    payload,
                    NativeAction::RecoveryTransition {
                        replace,
                        activation_at,
                        old_policy_hash: old_policy,
                        new_policy_hash,
                    },
                ))
            },
            inclusion.consensus_time,
        )?;
        let Payload::Schedule {
            role,
            old_policy,
            new_policy,
            new_policy_hash,
            activation_at,
            continuity: Some(continuity_reference),
            ..
        } = payload
        else {
            return Err("recovery continuity reference absent".into());
        };
        let record = self.read_policy(world, body.account)?;
        let current = self.current_policy(&record)?;
        let proposed = CanonicalPublicPolicy::decode(new_policy, self.wire).map_err(display)?;
        let replacement = if role == 0 { Role::D } else { Role::P };
        let checked = check_policy_replacement(
            current.with_recovery()?,
            &proposed,
            PolicyReplacementRequest {
                mode: ReplacementMode::Recovery,
                replace: replacement,
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
        let pending_reference = hash
            .finalize()
            .try_into()
            .map_err(|_| "invalid recovery reference digest")?;
        Ok(NativeRecoveryCheck {
            pending_reference,
            continuity_reference,
            new_policy_hash,
            activation_at,
            replacement,
            native_quorum,
            #[cfg(test)]
            pending: PendingRecovery {
                change: ScheduledPolicyChange {
                    network: self.network,
                    account: *body.account.as_bytes(),
                    reference: pending_reference,
                    old_epoch: record.policy_epoch,
                    old_hash: old_policy,
                    new_hash: new_policy_hash,
                    policy: new_policy.to_vec(),
                    activation_at,
                    included_height: inclusion.height,
                    included_time: inclusion.consensus_time,
                    replace: role,
                },
                continuity_reference,
            },
        })
    }

    /// Exercise post-admission state handling in fixtures with synthetic
    /// continuity input. A reference is never accepted as a continuity proof.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn apply_recovery_schedule_fixture(
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
        let checked = self.inspect_recovery_schedule(
            provider, finalized, world, inclusion, encoded, signatures, possession,
        )?;
        let limit = super::super::protected_action_wire::MAX_POLICY + 160;
        let intent = CanonicalNativeIntent::decode(encoded, limit).map_err(display)?;
        let (mut diff, _) = engineering_policy_fee(intent.body(), fee, gas)?;
        diff.protocol_changes.push(
            checked
                .pending
                .change
                .due_entry(transition_queue::TransitionMode::Recovery)
                .insert()?,
        );
        diff.protocol_changes.push(ProtocolChange {
            key: transition_key(intent.body().account),
            expected_value: None,
            value: Some(encode(&checked.pending)?),
        });
        diff.apply(world).map_err(debug)?;
        Ok(checked.pending_reference)
    }

    #[cfg(test)]
    fn finalized_recovery(
        &self,
        finalized: &FinalizedSnapshot<'_>,
        world: &WorldState,
        inclusion: Position,
        account: AccountIdentifier,
    ) -> Result<(PendingRecovery, Role, ProtocolChange), String> {
        use super::super::protected_action_wire::MAX_POLICY;
        if !std::ptr::eq(self, finalized.registry)
            || inclusion.height <= finalized.position.height
            || inclusion.consensus_time < finalized.position.consensus_time
        {
            return Err("invalid recovery execution position".into());
        }
        let key = transition_key(account);
        let bytes = finalized
            .world
            .protocol
            .get(&key)
            .ok_or("recovery schedule not finalized")?;
        if world.protocol.get(&key) != Some(bytes) {
            return Err("finalized recovery schedule differs from the working block".into());
        }
        let pending: PendingRecovery = decode(bytes, MAX_POLICY * 4 + 4096)?;
        let change = &pending.change;
        let record = self.read_policy(finalized.world, account)?;
        if encode(&pending)? != *bytes
            || change.network != self.network
            || change.account != *account.as_bytes()
            || change.reference == [0; 32]
            || change.old_epoch != record.policy_epoch
            || change.old_hash != record.policy_hash
            || record != self.read_policy(world, account)?
            || !(1..=finalized.position.height).contains(&change.included_height)
            || !(1..=finalized.position.consensus_time).contains(&change.included_time)
            || pending.continuity_reference == [0; 32]
        {
            return Err(
                "recovery schedule differs from the authenticated account or inclusion".into(),
            );
        }
        let replace = match change.replace {
            0 => Role::D,
            1 => Role::P,
            _ => return Err("invalid recorded recovery replacement role".into()),
        };
        let current = self.current_policy(&record)?;
        let proposed = CanonicalPublicPolicy::decode(&change.policy, self.wire).map_err(display)?;
        let _checked = check_policy_replacement(
            current.with_recovery()?,
            &proposed,
            PolicyReplacementRequest {
                mode: ReplacementMode::Recovery,
                replace,
                expected_old_policy_hash: change.old_hash,
                expected_new_policy_hash: change.new_hash,
                activation_at: change.activation_at,
            },
            change.included_time,
        )
        .map_err(display)?;
        Ok((
            pending,
            replace,
            ProtocolChange {
                key,
                expected_value: Some(bytes.clone()),
                value: None,
            },
        ))
    }

    /// A finalized schedule may already have been canceled or vetoed in the
    /// working block. The same-value precondition above prevents resurrection.
    #[cfg(test)]
    fn recovery_to_terminate(
        &self,
        finalized: &FinalizedSnapshot<'_>,
        world: &WorldState,
        inclusion: Position,
        body: &NativeIntentBody<'_>,
        reference: [u8; 32],
    ) -> Result<(ScheduledPolicyChange, Role, [ProtocolChange; 2]), String> {
        let (pending, replace, removal) =
            self.finalized_recovery(finalized, world, inclusion, body.account)?;
        if pending.change.reference != reference
            || pending.change.old_epoch != body.policy_epoch
            || inclusion.consensus_time >= pending.change.activation_at
        {
            return Err("recovery reference, epoch or deadline differs".into());
        }
        let due = pending
            .change
            .due_entry(transition_queue::TransitionMode::Recovery);
        Ok((pending.change, replace, [removal, due.remove()?]))
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn cancel_recovery(
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
        use super::super::protected_action_wire::{decode, Payload, RECOVERY_CANCEL};
        let intent = CanonicalNativeIntent::decode(encoded, 40).map_err(display)?;
        let (reference, _) = self.verify_spend(
            provider,
            finalized,
            world,
            encoded,
            40,
            |body| match decode(body.action_type, body.action_payload)? {
                Payload::Pending(reference) if body.action_type == RECOVERY_CANCEL => Ok(reference),
                _ => Err("expected RECOVERY_CANCEL".into()),
            },
            signatures,
        )?;
        let (pending, _, removals) =
            self.recovery_to_terminate(finalized, world, inclusion, intent.body(), reference)?;
        apply_transition_termination(
            &pending,
            transition_queue::TransitionMode::Recovery,
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

    /// Qualify the native policy write only. A live activation must also
    /// verify genuine continuity evidence and use the governed scheduler.
    #[cfg(test)]
    fn activate_recovery_fixture(
        &self,
        finalized: &FinalizedSnapshot<'_>,
        world: &mut WorldState,
        inclusion: Position,
        account: AccountIdentifier,
    ) -> Result<(), String> {
        let (_, plan) =
            self.prepare_recovery_activation_fixture(finalized, world, inclusion, account)?;
        plan.apply(world).map_err(debug)
    }

    #[cfg(test)]
    pub(super) fn prepare_recovery_activation_fixture(
        &self,
        finalized: &FinalizedSnapshot<'_>,
        world: &WorldState,
        inclusion: Position,
        account: AccountIdentifier,
    ) -> Result<(TransitionExecutionOutcome, StateDiff), String> {
        let (pending, _, removal) =
            self.finalized_recovery(finalized, world, inclusion, account)?;
        let address = account.to_native(&Primitives).map_err(display)?;
        if inclusion.consensus_time < pending.change.activation_at
            || !world
                .accounts
                .get(&address)
                .is_some_and(|account| account.code_hash.is_none())
        {
            return Err(
                "recovery activation is premature or the ledger account is unavailable".into(),
            );
        }
        let mut record = self.read_policy(world, account)?;
        let policy_key = account_key(account);
        let expected_value = world.protocol.get(&policy_key).cloned();
        record.policy_epoch = pending
            .change
            .old_epoch
            .checked_add(1)
            .ok_or("recovery policy epoch overflow")?;
        let outcome = pending.change.activation_outcome(
            transition_queue::TransitionMode::Recovery,
            finalized,
            inclusion,
            record.policy_epoch,
        );
        let due = outcome.transition;
        let settlement = transition_settlement::prepare_transition_settlement(finalized, &outcome)?;
        record.policy_hash = pending.change.new_hash;
        record.replacement_policy = Some(pending.change.policy);
        Ok((
            outcome,
            StateDiff {
                changes: Vec::new(),
                protocol_changes: vec![
                    removal,
                    due.remove()?,
                    settlement,
                    ProtocolChange {
                        key: policy_key,
                        expected_value,
                        value: Some(encode(&record)?),
                    },
                ],
            },
        ))
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn veto_recovery(
        &self,
        provider: &PqProvider<Mldsa87>,
        finalized: &FinalizedSnapshot<'_>,
        world: &mut WorldState,
        inclusion: Position,
        encoded: &[u8],
        signature: &RoleSignature,
        fee: &synergy_execution::FeeSchedule,
        gas: u64,
    ) -> Result<TransitionExecutionOutcome, String> {
        use super::super::protected_action_wire::{decode, Payload, RECOVERY_VETO};
        use synergy_address_engine::apqe::authorization::verify_caller_validated_native_spend_role;
        let intent = CanonicalNativeIntent::decode(encoded, 40).map_err(display)?;
        let body = intent.body();
        let Payload::Pending(reference) = decode(RECOVERY_VETO, body.action_payload)? else {
            return Err("expected recovery veto reference".into());
        };
        if body.action_type != RECOVERY_VETO {
            return Err("expected RECOVERY_VETO".into());
        }
        let (pending, replaced, removals) =
            self.recovery_to_terminate(finalized, world, inclusion, body, reference)?;
        let (state, policy) = self.current_native_authority(
            finalized,
            world,
            body.account,
            inclusion.consensus_time,
        )?;
        verify_caller_validated_native_spend_role(
            provider, &intent, &policy, &state, replaced, signature,
        )
        .map_err(display)?;
        apply_transition_termination(
            &pending,
            transition_queue::TransitionMode::Recovery,
            TransitionOutcomeKind::Vetoed,
            finalized,
            inclusion,
            &intent,
            fee,
            gas,
            removals,
            world,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use synergy_address_engine::apqe::{
        address::{derive_account_identifier, ValidatedSec1PublicPoint},
        authorization::{ORDINARY_POLICY_DELAY_SECONDS, RECOVERY_DELAY_SECONDS},
        enrollment::{EnrollmentData, PublicPolicy, RoleRecord},
        identity::WalletUuid,
        provider::Profile,
    };
    use synergy_state::AccountState;

    struct RecoveryScratch(std::path::PathBuf);
    impl Drop for RecoveryScratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn durable_position(height: u64, world: &WorldState) -> (FinalizedState, FinalizedBlockRecord) {
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
    fn hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }
    fn payload(
        role: u8,
        old: [u8; 32],
        policy: &[u8],
        hash: [u8; 32],
        at: u64,
        continuity: [u8; 32],
    ) -> Vec<u8> {
        let mut bytes = vec![0xa8, 0, 1, 1, role, 2, 0x58, 32];
        bytes.extend_from_slice(&old);
        bytes.extend_from_slice(&[3, 0x59]);
        bytes.extend_from_slice(&u16::try_from(policy.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(policy);
        bytes.extend_from_slice(&[4, 0x58, 32]);
        bytes.extend_from_slice(&hash);
        bytes.extend_from_slice(&[5, 1, 6, 0x1a]);
        bytes.extend_from_slice(&u32::try_from(at).unwrap().to_be_bytes());
        bytes.extend_from_slice(&[7, 0x58, 32]);
        bytes.extend_from_slice(&continuity);
        bytes
    }

    #[test]
    #[ignore = "requires independently pinned native APQE ML-DSA-87 validation library"]
    fn recovery_fixture_checks_both_lost_roles_through_restart_and_rotation() {
        use super::super::super::protected_action_wire::{POLICY_SCHEDULE, RECOVERY_SCHEDULE};
        let path = std::path::PathBuf::from(std::env::var_os("CORE_APQE_MLDSA87_LIBRARY").unwrap());
        let digest = hex(&std::env::var("CORE_APQE_MLDSA87_SHA256").unwrap())
            .try_into()
            .unwrap();
        let provider =
            unsafe { PqProvider::<Mldsa87>::open_verified(path, digest, Profile::Validation) }
                .unwrap();
        let wire = super::super::inspection::candidate_wire_profile().unwrap();
        let point = ValidatedSec1PublicPoint::parse(
            &Primitives,
            &hex(concat!(
                "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
            )),
        )
        .unwrap();
        let account = derive_account_identifier(&Primitives, &point).unwrap();
        let genesis = NativeGenesisHash::from_bytes([5; 32]);
        let keys = [(); 4].map(|()| provider.generate_keypair().unwrap());
        let policy = PublicPolicy {
            genesis,
            account,
            policy_epoch: 0,
            roles: std::array::from_fn(|i| RoleRecord {
                role_id: i as u8,
                participant_id: [i as u8 + 1; 32],
                key_version: 1,
                auth_algorithm: 1,
                auth_public_key: keys[i].0.as_bytes(),
            }),
            evm_public_key: *point.as_sec1_bytes(),
            provider_manifest_hash: [6; 32],
            ordinary_change_delay: ORDINARY_POLICY_DELAY_SECONDS,
            recovery_delay: RECOVERY_DELAY_SECONDS,
            status: 0,
        };
        let enrollment = EnrollmentData {
            genesis,
            account,
            evm_public_key: policy.evm_public_key,
            public_policy: policy,
            dkg_transcript_commitment: &[7; 32],
            nonce: [8; 32],
            issued_at: 900,
            expires_at: 2000,
            wallet_uuid: WalletUuid::from_bytes([9; 16]),
        }
        .encode(&wire)
        .unwrap();
        let old_hash = CanonicalEnrollment::decode(&enrollment, &wire)
            .unwrap()
            .policy_hash()
            .unwrap();
        let registry = CandidateProtectedAccounts::new(
            ChainId::from_u64(99999),
            ExternalChainPolicy::new(ChainId::from_u64(1), genesis).unwrap(),
            &wire,
            UnactivatedCommitmentProfile::candidate_concat_v1(),
            vec![[6; 32]],
        )
        .unwrap();
        let mut world = WorldState::default();
        world.protocol.insert(
            account_key(account),
            encode(&PolicyRecord {
                network: registry.network,
                account: *account.as_bytes(),
                policy_epoch: 0,
                policy_hash: old_hash,
                enrollment,
                registered_height: 1,
                replacement_policy: None,
                native_recovery_since: None,
            })
            .unwrap(),
        );
        world.accounts.insert(
            account.to_native(&Primitives).unwrap(),
            AccountState {
                balance_nwei: 1_000_000,
                nonce: 9,
                ..Default::default()
            },
        );
        let original = world.clone();
        let (pointer, proof) = super::super::tests::finalized(10, &world);
        let snapshot = registry.finalized_snapshot(&world, &pointer, &proof, 1000).unwrap();
        let inclusion = Position {
            height: 11,
            consensus_time: 1001,
        };
        let at = inclusion.consensus_time + RECOVERY_DELAY_SECONDS;
        for role in [0u8, 1] {
            let mut new_roles = policy.roles;
            new_roles[usize::from(role)] = RoleRecord {
                role_id: role,
                participant_id: [44; 32],
                key_version: 2,
                auth_algorithm: 1,
                auth_public_key: keys[3].0.as_bytes(),
            };
            let proposed = PublicPolicy {
                roles: new_roles,
                policy_epoch: 1,
                ..policy
            }
            .encode(&wire)
            .unwrap();
            let new_hash = CanonicalPublicPolicy::decode(&proposed, &wire)
                .unwrap()
                .hash()
                .unwrap();
            let make = |at, continuity, nonce, action| {
                let payload = payload(role, old_hash, &proposed, new_hash, at, continuity);
                NativeIntentBody {
                    genesis,
                    account,
                    policy_epoch: 0,
                    transaction_nonce: nonce,
                    action_type: action,
                    action_payload: &payload,
                    gas_limit: 1,
                    maximum_total_fee: [0; 32],
                    valid_until_finalized_height: 20,
                    intent_id: [10; 32],
                }
                .encode(12_000)
                .unwrap()
            };
            let sign = |encoded: &[u8], roles: [(Role, usize); 2]| {
                let digest = CanonicalNativeIntent::decode(encoded, 12_000)
                    .unwrap()
                    .digest()
                    .unwrap();
                roles.map(|(role, index)| RoleSignature {
                    role,
                    signature: provider
                        .sign(
                            digest.as_bytes(),
                            &keys[index].1,
                            SignOptions::Pure {
                                context: NATIVE_TX_CONTEXT,
                            },
                        )
                        .unwrap(),
                })
            };
            let pop = |encoded: &[u8], key: usize| {
                let digest = CanonicalNativeIntent::decode(encoded, 12_000)
                    .unwrap()
                    .digest()
                    .unwrap();
                provider
                    .sign(
                        digest.as_bytes(),
                        &keys[key].1,
                        SignOptions::Pure {
                            context: b"AEGIS.NEW.ROLE.POP.V1",
                        },
                    )
                    .unwrap()
            };
            let survivor = if role == 0 {
                (Role::P, 1)
            } else {
                (Role::D, 0)
            };
            let required = [survivor, (Role::R, 2)];
            let encoded = make(at, [11; 32], 9, RECOVERY_SCHEDULE);
            let signatures = sign(&encoded, required);
            let possession = pop(&encoded, 3);
            let checked = registry
                .inspect_recovery_schedule(
                    &provider,
                    &snapshot,
                    &world,
                    inclusion,
                    &encoded,
                    &signatures,
                    &possession,
                )
                .unwrap();
            assert_eq!(checked.activation_at, at);
            assert_eq!(
                checked.replacement,
                if role == 0 { Role::D } else { Role::P }
            );
            assert_eq!(checked.continuity_reference, [11; 32]); // Reference only, never proof.
            assert_eq!(checked.new_policy_hash, new_hash);
            assert_ne!(checked.pending_reference, [0; 32]);
            assert_eq!(world, original); // No nonce, fee, policy or pending state mutation.
            for wrong_roles in [
                [(Role::D, 0), (Role::P, 1)],
                [
                    (if role == 0 { Role::D } else { Role::P }, usize::from(role)),
                    (Role::R, 2),
                ],
                [(Role::R, 2), (Role::R, 2)],
            ] {
                assert!(registry
                    .inspect_recovery_schedule(
                        &provider,
                        &snapshot,
                        &world,
                        inclusion,
                        &encoded,
                        &sign(&encoded, wrong_roles),
                        &possession
                    )
                    .is_err());
            }
            assert!(registry
                .inspect_recovery_schedule(
                    &provider,
                    &snapshot,
                    &world,
                    inclusion,
                    &encoded,
                    &signatures,
                    &pop(&encoded, 0)
                )
                .is_err());
            for bad in [
                make(at - 1, [11; 32], 9, RECOVERY_SCHEDULE),
                make(at, [0; 32], 9, RECOVERY_SCHEDULE),
                make(at, [11; 32], 10, RECOVERY_SCHEDULE),
                make(at, [11; 32], 9, POLICY_SCHEDULE),
            ] {
                assert!(registry
                    .inspect_recovery_schedule(
                        &provider,
                        &snapshot,
                        &world,
                        inclusion,
                        &bad,
                        &sign(&bad, required),
                        &pop(&bad, 3)
                    )
                    .is_err());
            }
            let mut pending = world.clone();
            pending.protocol.insert(
                account_key(account).replacen(ACCOUNT_PREFIX, TRANSITION_PREFIX, 1),
                vec![1],
            );
            assert!(registry
                .inspect_recovery_schedule(
                    &provider,
                    &snapshot,
                    &pending,
                    inclusion,
                    &encoded,
                    &signatures,
                    &possession
                )
                .is_err());
            let (pending_pointer, pending_proof) =
                super::super::tests::finalized(snapshot.position.height, &pending);
            let pending_snapshot = registry
                .finalized_snapshot(
                    &pending,
                    &pending_pointer,
                    &pending_proof,
                    snapshot.position.consensus_time,
                )
                .unwrap();
            assert!(registry
                .inspect_recovery_schedule(
                    &provider,
                    &pending_snapshot,
                    &world,
                    inclusion,
                    &encoded,
                    &signatures,
                    &possession
                )
                .is_err());
            let reversed = Position {
                height: 10,
                consensus_time: 1001,
            };
            assert!(registry
                .inspect_recovery_schedule(
                    &provider,
                    &snapshot,
                    &world,
                    reversed,
                    &encoded,
                    &signatures,
                    &possession
                )
                .is_err());
            assert_eq!(world, original);

            // Real native role proofs; key7 remains a SYNTHETIC continuity
            // reference. Fixture-only scheduling grants no DKG/activation authority.
            let fee_schedule = synergy_execution::FeeSchedule {
                base_fee_per_gas_nwei: 2,
                collector: "recovery-fixture-fee-collector".into(),
            };
            let address = account.to_native(&Primitives).unwrap();
            let policy_key = account_key(account);
            let pending_key = transition_key(account);
            let original_policy = world.protocol[&policy_key].clone();
            let mut paid_body = *CanonicalNativeIntent::decode(&encoded, 12_000)
                .unwrap()
                .body();
            paid_body.maximum_total_fee[31] = 2;
            let paid = paid_body.encode(12_000).unwrap();
            let paid_proofs = sign(&paid, required);
            let paid_pop = pop(&paid, 3);
            let mut scheduled_world = world.clone();
            assert!(registry
                .apply_recovery_schedule_fixture(
                    &provider,
                    &snapshot,
                    &mut scheduled_world,
                    inclusion,
                    &encoded,
                    &signatures,
                    &possession,
                    &fee_schedule,
                    1
                )
                .is_err());
            assert_eq!(scheduled_world, world);
            let reference = registry
                .apply_recovery_schedule_fixture(
                    &provider,
                    &snapshot,
                    &mut scheduled_world,
                    inclusion,
                    &paid,
                    &paid_proofs,
                    &paid_pop,
                    &fee_schedule,
                    1,
                )
                .unwrap();
            assert_ne!(reference, [0; 32]);
            assert_eq!(scheduled_world.accounts[&address].nonce, 10);
            assert_eq!(scheduled_world.accounts[&address].balance_nwei, 999_998);
            assert_eq!(
                scheduled_world.accounts[&fee_schedule.collector].balance_nwei,
                2
            );
            assert_eq!(scheduled_world.protocol[&policy_key], original_policy);
            let pending_bytes = scheduled_world.protocol[&pending_key].clone();
            let scheduled_root = state_root(&scheduled_world).unwrap();
            let prior = scheduled_world.clone();
            assert!(registry
                .apply_recovery_schedule_fixture(
                    &provider,
                    &snapshot,
                    &mut scheduled_world,
                    inclusion,
                    &paid,
                    &paid_proofs,
                    &paid_pop,
                    &fee_schedule,
                    1
                )
                .is_err());
            assert_eq!(scheduled_world, prior); // No duplicate charge.

            let scratch = RecoveryScratch(std::env::temp_dir().join(format!(
                    "recovery-pending-{}-{}-{}",
                    std::process::id(),
                    role,
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                )));
            std::fs::create_dir(&scratch.0).unwrap();
            let mut store = synergy_state::FinalizedStateStore::load(&scratch.0).unwrap();
            store
                .commit_verified_world_state(durable_position(10, &world).0, &world)
                .unwrap();
            let (pending_pointer, pending_certificate) = durable_position(11, &scheduled_world);
            store
                .commit_verified_world_transition(pending_pointer.clone(), &world, &scheduled_world)
                .unwrap();
            drop(store);
            let mut store = synergy_state::FinalizedStateStore::load(&scratch.0).unwrap();
            let restored = store.current_world_state().unwrap().unwrap();
            assert_eq!(restored, scheduled_world);
            assert_eq!(state_root(&restored).unwrap(), scheduled_root);
            assert_eq!(restored.protocol[&pending_key], pending_bytes);
            let pending_snapshot = registry
                .finalized_snapshot(
                    &restored,
                    &pending_pointer,
                    &pending_certificate,
                    inclusion.consensus_time,
                )
                .unwrap();
            let due = transition_queue::DueTransition {
                account,
                activation_at: at,
                reference,
                mode: transition_queue::TransitionMode::Recovery,
            };
            let initial_policy_hash = registry.read_policy(&world, account).unwrap().policy_hash;
            let observe_pending = |state: &WorldState, time: u64| {
                let (pointer, certificate) = durable_position(12, state);
                let selected = registry.finalized_snapshot(state, &pointer, &certificate, time)?;
                inspect_pending_transition(&selected, account)
            };
            assert_eq!(
                inspect_pending_transition(&pending_snapshot, account).unwrap(),
                serde_json::json!({
                    "status": "scheduled_candidate", "mode": "recovery",
                    "pending_reference": inspection::hex_bytes(&reference),
                    "replaced_role": role, "old_policy_epoch": 0,
                    "old_policy_hash": inspection::hex_bytes(&initial_policy_hash),
                    "new_policy_hash": inspection::hex_bytes(&new_hash),
                    "scheduled_height": 11,
                    "scheduled_consensus_timestamp_unix": inclusion.consensus_time,
                    "activation_timestamp_unix": at,
                })
            );
            let mut missing_index = restored.clone();
            assert!(missing_index.protocol.remove(&due.key()).is_some());
            assert!(observe_pending(&missing_index, inclusion.consensus_time).is_err());
            assert!(inspect_pending_transition(&snapshot, account)
                .unwrap()
                .is_null());
            // Pending evidence is not a terminal settlement or proof that a
            // subsequent nonce remains unspent.
            let before_terminal = transition_settlement::inspect_transition_settlement(
                &pending_snapshot,
                account,
                reference,
                None,
            )
            .unwrap();
            assert_eq!(
                before_terminal["status"],
                "no_transition_settlement_in_snapshot"
            );
            let assert_paid_settlement =
                |selected: &FinalizedSnapshot<'_>, status: &str, input: &[u8]| {
                    let signed_digest = inspection::hex_bytes(
                        CanonicalNativeIntent::decode(input, 12_000)
                            .unwrap()
                            .digest()
                            .unwrap()
                            .as_bytes(),
                    );
                    let observed = transition_settlement::inspect_transition_settlement(
                        selected,
                        account,
                        reference,
                        Some(&signed_digest),
                    )
                    .unwrap();
                    assert_eq!(observed["status"], status);
                    let charge = &observed["signed_charge"];
                    assert!(charge.is_object());
                    let intent = CanonicalNativeIntent::decode(input, 12_000).unwrap();
                    assert_eq!(charge.as_object().unwrap().len(), 7);
                    assert_eq!(charge["action"], intent.body().action_type);
                    assert_eq!(
                        charge["intent_id"],
                        inspection::hex_bytes(&intent.body().intent_id)
                    );
                    assert_eq!(charge["signed_intent_digest"], signed_digest);
                    assert_eq!(charge["gas_used"], 1);
                    assert_eq!(charge["fee_nwei"], "2");
                    assert_eq!(charge["nonce_before"], 10);
                    assert_eq!(charge["nonce_after"], 11);
                    let foreign_digest = "ff".repeat(64);
                    assert!(transition_settlement::inspect_transition_settlement(
                        selected,
                        account,
                        reference,
                        Some(&foreign_digest),
                    )
                    .is_err());
                };
            let cancel_at = Position {
                height: 12,
                consensus_time: at - 1,
            };
            let make_terminal = |action, target: [u8; 32], expiry| {
                let mut payload = vec![0xa2, 0, 1, 1, 0x58, 32];
                payload.extend_from_slice(&target);
                NativeIntentBody {
                    action_type: action,
                    action_payload: &payload,
                    transaction_nonce: 10,
                    valid_until_finalized_height: expiry,
                    intent_id: [12; 32],
                    ..paid_body
                }
                .encode(12_000)
                .unwrap()
            };
            let cancellation = make_terminal(
                super::super::super::protected_action_wire::RECOVERY_CANCEL,
                reference,
                11,
            );
            let cancel_proofs = sign(&cancellation, [(Role::D, 0), (Role::P, 1)]);
            let mut cancelled = restored.clone();
            for (input, roles, position) in [
                (
                    make_terminal(
                        super::super::super::protected_action_wire::RECOVERY_CANCEL,
                        [99; 32],
                        11,
                    ),
                    [(Role::D, 0), (Role::P, 1)],
                    cancel_at,
                ),
                (
                    make_terminal(
                        super::super::super::protected_action_wire::RECOVERY_CANCEL,
                        reference,
                        10,
                    ),
                    [(Role::D, 0), (Role::P, 1)],
                    cancel_at,
                ),
                (cancellation.clone(), required, cancel_at),
                (
                    cancellation.clone(),
                    [(Role::D, 0), (Role::P, 1)],
                    Position {
                        height: 12,
                        consensus_time: at,
                    },
                ),
            ] {
                let before = cancelled.clone();
                assert!(registry
                    .cancel_recovery(
                        &provider,
                        &pending_snapshot,
                        &mut cancelled,
                        position,
                        &input,
                        &sign(&input, roles),
                        &fee_schedule,
                        1
                    )
                    .is_err());
                assert_eq!(cancelled, before);
                assert_eq!(state_root(&cancelled).unwrap(), scheduled_root);
            }
            let canceled_outcome = registry
                .cancel_recovery(
                    &provider,
                    &pending_snapshot,
                    &mut cancelled,
                    cancel_at,
                    &cancellation,
                    &cancel_proofs,
                    &fee_schedule,
                    1,
                )
                .unwrap();
            assert_eq!(canceled_outcome.transition, due);
            assert_eq!(canceled_outcome.kind, TransitionOutcomeKind::Canceled);
            assert_eq!(canceled_outcome.source_finalized_height, 11);
            assert_eq!(canceled_outcome.included, cancel_at);
            assert_eq!(canceled_outcome.old_policy_epoch, 0);
            assert_eq!(canceled_outcome.resulting_policy_epoch, 0);
            assert_eq!(canceled_outcome.old_policy_hash, initial_policy_hash);
            assert_eq!(canceled_outcome.resulting_policy_hash, initial_policy_hash);
            let assert_charge = |outcome: &TransitionExecutionOutcome, input: &[u8]| {
                let intent = CanonicalNativeIntent::decode(input, 12_000).unwrap();
                let charge = outcome.signed_charge.as_ref().unwrap();
                assert_eq!(charge.action, intent.body().action_type);
                assert_eq!(charge.intent_id, intent.body().intent_id);
                assert_eq!(charge.signed_digest, *intent.digest().unwrap().as_bytes());
                assert_eq!(charge.gas_used, 1);
                assert_eq!(charge.fee_nwei, 2);
                assert_eq!(charge.nonce_before, 10);
                assert_eq!(charge.nonce_after, 11);
            };
            assert_charge(&canceled_outcome, &cancellation);
            assert!(observe_pending(&cancelled, cancel_at.consensus_time)
                .unwrap()
                .is_null());
            assert!(!cancelled.protocol.contains_key(&due.key()));
            assert!(!cancelled.protocol.contains_key(&pending_key));
            assert_eq!(cancelled.protocol[&policy_key], original_policy);
            assert_eq!(cancelled.accounts[&address].nonce, 11);
            assert_eq!(cancelled.accounts[&address].balance_nwei, 999_996);
            assert_eq!(cancelled.accounts[&fee_schedule.collector].balance_nwei, 4);
            let cancelled_copy = cancelled.clone();
            assert!(registry
                .cancel_recovery(
                    &provider,
                    &pending_snapshot,
                    &mut cancelled,
                    cancel_at,
                    &cancellation,
                    &cancel_proofs,
                    &fee_schedule,
                    1
                )
                .is_err());
            assert_eq!(cancelled, cancelled_copy);
            store
                .commit_verified_world_transition(
                    durable_position(12, &cancelled).0,
                    &restored,
                    &cancelled,
                )
                .unwrap();
            drop(store);
            let store = synergy_state::FinalizedStateStore::load(&scratch.0).unwrap();
            let reopened_cancelled = store.current_world_state().unwrap().unwrap();
            assert_eq!(reopened_cancelled, cancelled);
            let (cancel_tip, cancel_finality) = durable_position(12, &reopened_cancelled);
            let cancelled_snapshot = registry
                .finalized_snapshot(
                    &reopened_cancelled,
                    &cancel_tip,
                    &cancel_finality,
                    cancel_at.consensus_time,
                )
                .unwrap();
            assert_paid_settlement(&cancelled_snapshot, "canceled_candidate", &cancellation);
            drop(store);

            // The current role being replaced may veto; the survivor, R, new
            // key and wrong signing domain may not fill that unilateral slot.
            let veto = make_terminal(
                super::super::super::protected_action_wire::RECOVERY_VETO,
                reference,
                11,
            );
            let single = |input: &[u8], claimed_role, key: usize, context| {
                let digest = CanonicalNativeIntent::decode(input, 12_000)
                    .unwrap()
                    .digest()
                    .unwrap();
                RoleSignature {
                    role: claimed_role,
                    signature: provider
                        .sign(
                            digest.as_bytes(),
                            &keys[key].1,
                            SignOptions::Pure { context },
                        )
                        .unwrap(),
                }
            };
            let replaced = if role == 0 { Role::D } else { Role::P };
            let mut vetoed = restored.clone();
            for proof in [
                single(&veto, survivor.0, survivor.1, NATIVE_TX_CONTEXT),
                single(&veto, Role::R, 2, NATIVE_TX_CONTEXT),
                single(&veto, replaced, 3, NATIVE_TX_CONTEXT),
                single(&veto, replaced, usize::from(role), b"AEGIS.NEW.ROLE.POP.V1"),
            ] {
                assert!(registry
                    .veto_recovery(
                        &provider,
                        &pending_snapshot,
                        &mut vetoed,
                        cancel_at,
                        &veto,
                        &proof,
                        &fee_schedule,
                        1
                    )
                    .is_err());
                assert_eq!(vetoed, restored);
            }
            let veto_proof = single(&veto, replaced, usize::from(role), NATIVE_TX_CONTEXT);
            assert!(registry
                .veto_recovery(
                    &provider,
                    &pending_snapshot,
                    &mut vetoed,
                    Position {
                        height: 12,
                        consensus_time: at
                    },
                    &veto,
                    &veto_proof,
                    &fee_schedule,
                    1
                )
                .is_err());
            assert_eq!(vetoed, restored);
            let other_veto = make_terminal(
                super::super::super::protected_action_wire::RECOVERY_VETO,
                [99; 32],
                11,
            );
            assert!(registry
                .veto_recovery(
                    &provider,
                    &pending_snapshot,
                    &mut vetoed,
                    cancel_at,
                    &other_veto,
                    &single(&other_veto, replaced, usize::from(role), NATIVE_TX_CONTEXT),
                    &fee_schedule,
                    1
                )
                .is_err());
            assert_eq!(vetoed, restored);
            let vetoed_outcome = registry
                .veto_recovery(
                    &provider,
                    &pending_snapshot,
                    &mut vetoed,
                    cancel_at,
                    &veto,
                    &veto_proof,
                    &fee_schedule,
                    1,
                )
                .unwrap();
            assert_eq!(vetoed_outcome.transition, due);
            assert_eq!(vetoed_outcome.kind, TransitionOutcomeKind::Vetoed);
            assert_eq!(vetoed_outcome.source_finalized_height, 11);
            assert_eq!(vetoed_outcome.included, cancel_at);
            assert_eq!(vetoed_outcome.old_policy_epoch, 0);
            assert_eq!(vetoed_outcome.resulting_policy_epoch, 0);
            assert_eq!(vetoed_outcome.old_policy_hash, initial_policy_hash);
            assert_eq!(vetoed_outcome.resulting_policy_hash, initial_policy_hash);
            assert_charge(&vetoed_outcome, &veto);
            assert!(observe_pending(&vetoed, cancel_at.consensus_time)
                .unwrap()
                .is_null());
            assert!(!vetoed.protocol.contains_key(&due.key()));
            assert!(!vetoed.protocol.contains_key(&pending_key));
            assert_eq!(vetoed.protocol[&policy_key], original_policy);
            assert_eq!(vetoed.accounts[&address].nonce, 11);
            assert_eq!(vetoed.accounts[&address].balance_nwei, 999_996);
            assert_eq!(vetoed.accounts[&fee_schedule.collector].balance_nwei, 4);
            let vetoed_copy = vetoed.clone();
            assert!(registry
                .veto_recovery(
                    &provider,
                    &pending_snapshot,
                    &mut vetoed,
                    cancel_at,
                    &veto,
                    &veto_proof,
                    &fee_schedule,
                    1
                )
                .is_err());
            assert_eq!(vetoed, vetoed_copy);
            let veto_path = scratch.0.join("veto-branch");
            std::fs::create_dir(&veto_path).unwrap();
            let (veto_tip, veto_finality) = durable_position(12, &vetoed);
            let mut veto_store = synergy_state::FinalizedStateStore::load(&veto_path).unwrap();
            veto_store
                .commit_verified_world_state(durable_position(11, &restored).0, &restored)
                .unwrap();
            veto_store
                .commit_verified_world_transition(veto_tip.clone(), &restored, &vetoed)
                .unwrap();
            drop(veto_store);
            let veto_store = synergy_state::FinalizedStateStore::load(&veto_path).unwrap();
            let reopened_vetoed = veto_store.current_world_state().unwrap().unwrap();
            assert_eq!(reopened_vetoed, vetoed);
            let veto_snapshot = registry
                .finalized_snapshot(
                    &reopened_vetoed,
                    &veto_tip,
                    &veto_finality,
                    cancel_at.consensus_time,
                )
                .unwrap();
            assert_paid_settlement(&veto_snapshot, "vetoed_candidate", &veto);
            drop(veto_store);
            // Native policy effects only: the staged key7 continuity is still
            // synthetic, so this fixture cannot authorize real recovery activation.
            let mut activated = restored.clone();
            assert!(registry
                .activate_recovery_fixture(
                    &pending_snapshot,
                    &mut activated,
                    Position {
                        height: 12,
                        consensus_time: at - 1
                    },
                    account
                )
                .is_err());
            assert_eq!(activated, restored);
            let rotated = registry
                .apply_due_transitions_fixture(
                    &pending_snapshot,
                    &mut activated,
                    Position {
                        height: 12,
                        consensus_time: at,
                    },
                    1,
                )
                .unwrap();
            assert_eq!(rotated.len(), 1);
            assert_eq!(rotated[0].transition, due);
            assert_eq!(rotated[0].kind, TransitionOutcomeKind::Activated);
            assert_eq!(rotated[0].source_finalized_height, 11);
            assert_eq!(
                rotated[0].included,
                Position {
                    height: 12,
                    consensus_time: at
                }
            );
            assert_eq!(rotated[0].old_policy_epoch, 0);
            assert_eq!(rotated[0].resulting_policy_epoch, 1);
            assert_eq!(rotated[0].old_policy_hash, initial_policy_hash);
            assert_eq!(rotated[0].resulting_policy_hash, new_hash);
            assert!(rotated[0].signed_charge.is_none());
            assert!(observe_pending(&activated, at).unwrap().is_null());
            assert!(!activated
                .protocol
                .contains_key(&rotated[0].transition.key()));
            assert!(!activated.protocol.contains_key(&pending_key));
            assert_eq!(activated.accounts, restored.accounts); // No activation fee or second nonce.
            let active_record = registry.read_policy(&activated, account).unwrap();
            let initial_record = registry.read_policy(&world, account).unwrap();
            assert_eq!(active_record.account, *account.as_bytes());
            assert_eq!(active_record.network, initial_record.network);
            assert_eq!(active_record.enrollment, initial_record.enrollment);
            assert_eq!(
                active_record.registered_height,
                initial_record.registered_height
            );
            assert_eq!(active_record.policy_epoch, 1);
            assert_eq!(active_record.policy_hash, new_hash);
            let active_policy = CanonicalPublicPolicy::decode(
                active_record.replacement_policy.as_ref().unwrap(),
                &wire,
            )
            .unwrap();
            assert_eq!(active_policy.policy().account, account);
            assert_eq!(active_policy.policy().evm_public_key, policy.evm_public_key);
            assert_eq!(
                active_policy.policy().roles[usize::from(role)].auth_public_key,
                keys[3].0.as_bytes()
            );
            use super::super::super::protected_action_wire::{decode_transfer, TRANSFER};
            let recipient = AccountIdentifier::from_bytes([55; 20]);
            let mut transfer = vec![0xa3, 0, 1, 1, 0x54];
            transfer.extend_from_slice(recipient.as_bytes());
            transfer.extend_from_slice(&[2, 0x58, 32]);
            transfer.extend_from_slice(&[0; 31]);
            transfer.push(1);
            let spend = |epoch| {
                NativeIntentBody {
                    policy_epoch: epoch,
                    transaction_nonce: 10,
                    action_type: TRANSFER,
                    action_payload: &transfer,
                    valid_until_finalized_height: 12,
                    ..paid_body
                }
                .encode(60)
                .unwrap()
            };
            let old_intent = spend(0);
            let new_intent = spend(1);
            let old_roles = [(Role::D, 0), (Role::P, 1)];
            let mut new_roles = old_roles;
            new_roles[usize::from(role)].1 = 3;
            let (active_tip, active_finality) = durable_position(12, &activated);
            let activation_path = scratch.0.join("activation-branch");
            std::fs::create_dir(&activation_path).unwrap();
            let mut activation_store =
                synergy_state::FinalizedStateStore::load(&activation_path).unwrap();
            activation_store
                .commit_verified_world_state(durable_position(11, &restored).0, &restored)
                .unwrap();
            activation_store
                .commit_verified_world_transition(active_tip.clone(), &restored, &activated)
                .unwrap();
            drop(activation_store);
            let activation_store =
                synergy_state::FinalizedStateStore::load(&activation_path).unwrap();
            let reopened_active = activation_store.current_world_state().unwrap().unwrap();
            assert_eq!(reopened_active, activated);
            let active_snapshot = registry
                .finalized_snapshot(&reopened_active, &active_tip, &active_finality, at)
                .unwrap();
            let activation_settlement = transition_settlement::inspect_transition_settlement(
                &active_snapshot,
                account,
                reference,
                None,
            )
            .unwrap();
            assert_eq!(activation_settlement["status"], "activated_candidate");
            assert!(activation_settlement["signed_charge"].is_null());
            assert!(transition_settlement::inspect_transition_settlement(
                &active_snapshot,
                account,
                reference,
                Some(&"ff".repeat(64)),
            )
            .is_err());
            let check_spend = |snapshot: &FinalizedSnapshot<'_>, intent: &[u8], roles| {
                registry.verify_spend(
                    &provider,
                    snapshot,
                    snapshot.world,
                    intent,
                    60,
                    decode_transfer,
                    &sign(intent, roles),
                )
            };
            assert!(check_spend(&pending_snapshot, &old_intent, old_roles).is_ok());
            assert!(check_spend(&active_snapshot, &old_intent, old_roles).is_err());
            assert!(check_spend(&active_snapshot, &new_intent, old_roles).is_err());
            assert!(check_spend(&active_snapshot, &new_intent, new_roles).is_ok());
            for terminated in [&mut cancelled, &mut vetoed] {
                let before = terminated.clone();
                assert!(registry
                    .apply_due_transitions_fixture(
                        &pending_snapshot,
                        terminated,
                        Position {
                            height: 12,
                            consensus_time: at
                        },
                        1,
                    )
                    .unwrap()
                    .is_empty());
                assert!(registry
                    .activate_recovery_fixture(
                        &pending_snapshot,
                        terminated,
                        Position {
                            height: 12,
                            consensus_time: at
                        },
                        account,
                    )
                    .is_err());
                assert_eq!(*terminated, before);
            }
            let activated_copy = activated.clone();
            assert!(registry
                .cancel_recovery(
                    &provider,
                    &pending_snapshot,
                    &mut activated,
                    cancel_at,
                    &cancellation,
                    &cancel_proofs,
                    &fee_schedule,
                    1
                )
                .is_err());
            assert_eq!(activated, activated_copy);
            assert!(registry
                .veto_recovery(
                    &provider,
                    &pending_snapshot,
                    &mut activated,
                    cancel_at,
                    &veto,
                    &veto_proof,
                    &fee_schedule,
                    1
                )
                .is_err());
            assert_eq!(activated, activated_copy);
            assert!(registry
                .activate_recovery_fixture(
                    &pending_snapshot,
                    &mut activated,
                    Position {
                        height: 12,
                        consensus_time: at
                    },
                    account
                )
                .is_err());
            assert_eq!(activated, activated_copy);
            assert_eq!(world, original);
        }
    }
}
