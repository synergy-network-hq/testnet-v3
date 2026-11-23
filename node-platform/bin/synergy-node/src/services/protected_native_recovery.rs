//! Candidate lifecycle for adding a native ML-DSA recovery device to a DP account.
use super::policy_variant::{CurrentPolicy, InitialEnrollment};
use super::*;
use synergy_address_engine::apqe::enrollment::native_recovery::{
    CanonicalNativeRecoveryPublicPolicy, CurrentNativeRecoveryPolicy, NativeRecoveryApproval,
    NativeRecoveryCheckpoint, NativeRecoveryOperation, NativeRecoveryProofs,
    verify_native_recovery_approval,
};

const PENDING_PREFIX: &str = "apqe-protected-account-candidate/v1/native-recovery-pending/";
const RECEIPT_PREFIX: &str = "apqe-protected-account-candidate/v1/native-recovery-receipt/";
const MAX_PENDING_BYTES: usize = 48 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingAttachment {
    approval: Vec<u8>,
    proposed_policy: Vec<u8>,
    scheduled_height: u64,
    scheduled_time: u64,
}

fn state_key(account: AccountIdentifier) -> String {
    format!("{PENDING_PREFIX}{}", account.lowercase_hex())
}

fn receipt_key(account: AccountIdentifier, id: &[u8; 32]) -> String {
    format!(
        "{RECEIPT_PREFIX}{}/{}",
        account.lowercase_hex(),
        inspection::hex_bytes(id)
    )
}

fn check_slot(finalized: &FinalizedSnapshot<'_>, inclusion: Position) -> Result<(), String> {
    if inclusion.height <= finalized.position.height
        || inclusion.consensus_time < finalized.position.consensus_time
    {
        return Err("native recovery requires a later candidate over verified finality".into());
    }
    Ok(())
}

impl CandidateProtectedAccounts<'_> {
    fn native_recovery_checkpoint(
        &self,
        finalized: &FinalizedSnapshot<'_>,
        finality: &FinalizedBlockRecord,
        account: AccountIdentifier,
        enrollment_hash: [u8; 32],
    ) -> Result<NativeRecoveryCheckpoint, String> {
        if !std::ptr::eq(self, finalized.registry)
            || finalized.position.height != finality.height
            || crate::services::authority::processing_finality_root(finality)?
                != finalized.processing_finality_root
        {
            return Err("native recovery proof names another finalized checkpoint".into());
        }
        let address = account.to_native(&Primitives).map_err(display)?;
        let ledger = finalized
            .world
            .accounts
            .get(&address)
            .filter(|ledger| ledger.code_hash.is_none())
            .ok_or("native recovery approval lacks an authenticated ledger account")?;
        Ok(NativeRecoveryCheckpoint {
            account: NativeAccountCoordinate {
                chain_id: ChainId::from_be_bytes(self.network.native_chain),
                genesis: self.chain.native_genesis(),
                account,
            },
            enrollment_hash,
            finalized_height: finality.height,
            finalized_block_id: synergy_posy::parse_hash_bytes(&finality.block_id)
                .map_err(debug)?,
            finalized_state_root: synergy_posy::parse_hash_bytes(
                &state_root(finalized.world).map_err(debug)?,
            )
            .map_err(debug)?,
            finality_certificate_id: synergy_posy::parse_hash_bytes(
                &finality.finality_certificate_id,
            )
            .map_err(debug)?,
            consensus_time: finalized.position.consensus_time,
            balance_nwei: ledger.balance_nwei,
            next_nonce: ledger.nonce,
        })
    }

    /// The original consent state and the current proposal source must each
    /// be independently verified. This prepares a candidate World change only.
    #[allow(clippy::too_many_arguments)]
    fn prepare_native_recovery_attachment(
        &self,
        provider: &PqProvider<Mldsa87>,
        selected: &FinalizedSnapshot<'_>,
        proof: &FinalizedBlockRecord,
        finalized: &FinalizedSnapshot<'_>,
        working: &WorldState,
        inclusion: Position,
        approval: &[u8],
        proposed_policy: &[u8],
        consent: &[EnrollmentSignature; 2],
        possession: &EnrollmentSignature,
    ) -> Result<StateDiff, String> {
        check_slot(finalized, inclusion)?;
        let request = NativeRecoveryApproval::decode(approval).map_err(display)?;
        if !std::ptr::eq(self, finalized.registry)
            || request.operation != NativeRecoveryOperation::AttachRecoveryDevice
            || selected.position.height > finalized.position.height
            || selected.position.consensus_time > finalized.position.consensus_time
            || inclusion.height > request.valid_until_finalized_height
            || inclusion
                .consensus_time
                .checked_add(request.operation.delay_seconds())
                .is_none_or(|eligible| eligible > request.earliest_activation_time)
        {
            return Err(
                "native recovery attachment is outside its exact scope, lease or delay".into(),
            );
        }
        let account = request.checkpoint.account.account;
        let original = self.read_policy(selected.world, account)?;
        if original != self.read_policy(finalized.world, account)?
            || original != self.read_policy(working, account)?
            || original.registered_height > selected.position.height
        {
            return Err("native recovery attachment no longer matches the finalized policy".into());
        }
        let InitialEnrollment::PrimaryCompanion(enrollment) =
            InitialEnrollment::decode(&original.enrollment, self.wire)?
        else {
            return Err("native recovery attachment requires an original D/P enrollment".into());
        };
        let checkpoint = self.native_recovery_checkpoint(
            selected,
            proof,
            account,
            enrollment
                .binding_fields()
                .map_err(display)?
                .enrollment_hash,
        )?;
        let address = account.to_native(&Primitives).map_err(display)?;
        let same_reviewed_ledger = |world: &WorldState| {
            world.accounts.get(&address).is_some_and(|ledger| {
                ledger.code_hash.is_none()
                    && ledger.nonce == checkpoint.next_nonce
                    && ledger.balance_nwei == checkpoint.balance_nwei
            })
        };
        if !same_reviewed_ledger(finalized.world) || !same_reviewed_ledger(working) {
            return Err("native recovery attachment differs from the reviewed ledger state".into());
        }
        let CurrentPolicy::PrimaryCompanion(current) = self.current_policy(&original)? else {
            return Err("native recovery already attached".into());
        };
        let next = CanonicalNativeRecoveryPublicPolicy::decode(proposed_policy, self.wire)
            .map_err(display)?;
        let verified = verify_native_recovery_approval(
            provider,
            &checkpoint,
            request,
            CurrentNativeRecoveryPolicy::Unset(&current),
            &next,
            self.wire,
            NativeRecoveryProofs {
                consent,
                possession,
            },
        )
        .map_err(display)?;
        let approved = verified.approval();
        let pending = state_key(account);
        let receipt = receipt_key(account, &approved.intent_id);
        let legacy = transition_key(account);
        if [finalized.world, working].iter().any(|world| {
            [&pending, &receipt, &legacy]
                .into_iter()
                .any(|key| world.protocol.contains_key(key))
        }) {
            return Err(
                "native recovery attachment conflicts with existing transition or receipt".into(),
            );
        }
        let value = encode(&PendingAttachment {
            approval: approved.encode().map_err(display)?,
            proposed_policy: proposed_policy.to_vec(),
            scheduled_height: inclusion.height,
            scheduled_time: inclusion.consensus_time,
        })?;
        if value.len() > MAX_PENDING_BYTES {
            return Err("native recovery attachment exceeds durable size".into());
        }
        Ok(StateDiff {
            protocol_changes: vec![ProtocolChange {
                key: pending,
                expected_value: None,
                value: Some(value),
            }],
            ..StateDiff::default()
        })
    }

    fn prepare_native_recovery_activation(
        &self,
        finalized: &FinalizedSnapshot<'_>,
        working: &WorldState,
        inclusion: Position,
        account: AccountIdentifier,
    ) -> Result<StateDiff, String> {
        check_slot(finalized, inclusion)?;
        if !std::ptr::eq(self, finalized.registry) {
            return Err("native recovery activation uses a different finalized registry".into());
        }
        let pending_key = state_key(account);
        let bytes = finalized
            .world
            .protocol
            .get(&pending_key)
            .ok_or("native recovery attachment has not finalized")?;
        let pending: PendingAttachment = decode(bytes, MAX_PENDING_BYTES)?;
        let approved = NativeRecoveryApproval::decode(&pending.approval).map_err(display)?;
        let coordinates = approved.checkpoint.account;
        let mut current = self.read_policy(finalized.world, account)?;
        let next = CanonicalNativeRecoveryPublicPolicy::decode(&pending.proposed_policy, self.wire)
            .map_err(display)?;
        let original = self.current_policy(&current)?;
        let terms = next.policy();
        let address = account.to_native(&Primitives).map_err(display)?;
        if encode(&pending)? != *bytes
            || working.protocol.get(&pending_key) != Some(bytes)
            || approved.operation != NativeRecoveryOperation::AttachRecoveryDevice
            || coordinates.chain_id.as_be_bytes() != &self.network.native_chain
            || coordinates.genesis != self.chain.native_genesis()
            || coordinates.account != account
            || pending.scheduled_height <= approved.checkpoint.finalized_height
            || pending.scheduled_height > finalized.position.height
            || pending.scheduled_height > approved.valid_until_finalized_height
            || pending.scheduled_time < approved.checkpoint.consensus_time
            || pending.scheduled_time > finalized.position.consensus_time
            || approved.earliest_activation_time > inclusion.consensus_time
            || pending
                .scheduled_time
                .checked_add(approved.operation.delay_seconds())
                .is_none_or(|earliest| earliest > approved.earliest_activation_time)
            || current != self.read_policy(working, account)?
            || current.policy_epoch != approved.current_policy_epoch
            || current.policy_hash != approved.current_policy_hash
            || !matches!(original, CurrentPolicy::PrimaryCompanion(_))
            || current.policy_epoch.checked_add(1) != Some(terms.policy_epoch)
            || next.hash().map_err(display)? != approved.new_policy_hash
            || terms.account != account
            || terms.genesis != coordinates.genesis
            || terms.provider_manifest_hash != original.terms().provider_manifest_hash
            || terms.evm_public_key != *original.terms().evm_public_key
            || terms.roles[..2] != *original.terms().roles
            || !working
                .accounts
                .get(&address)
                .is_some_and(|ledger| ledger.code_hash.is_none())
        {
            return Err(
                "native recovery attachment no longer eligible for exact activation".into(),
            );
        }
        current.policy_epoch = terms.policy_epoch;
        current.policy_hash = approved.new_policy_hash;
        current.replacement_policy = Some(pending.proposed_policy);
        current.native_recovery_since = Some(inclusion.height);
        let receipt = receipt_key(account, &approved.intent_id);
        let key = account_key(account);
        Ok(StateDiff {
            protocol_changes: vec![
                ProtocolChange {
                    key: pending_key,
                    expected_value: Some(bytes.clone()),
                    value: None,
                },
                ProtocolChange {
                    key: key.clone(),
                    expected_value: working.protocol.get(&key).cloned(),
                    value: Some(encode(&current)?),
                },
                ProtocolChange {
                    key: receipt,
                    expected_value: None,
                    value: Some(encode(&(
                        approved.current_policy_hash,
                        approved.new_policy_hash,
                        inclusion.height,
                    ))?),
                },
            ],
            ..StateDiff::default()
        })
    }
}

#[cfg(test)]
#[path = "protected_native_recovery_tests.rs"]
mod tests;
