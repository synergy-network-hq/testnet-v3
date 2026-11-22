//! Candidate terminal transition evidence in the same World as its effects.
//! No public event wire, system transaction, ratification or activation authority.
use super::*;
use serde_json::{json, Value};
use transition_queue::TransitionMode;

const PREFIX: &str = "apqe-protected-account-candidate/v1/transition-settlement/";
const MAX_RECORD_BYTES: usize = 8192;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Charge {
    action: u16,
    intent_id: [u8; 32],
    signed_intent_digest: String,
    gas_used: u64,
    fee_nwei: u128,
    nonce_before: u64,
    nonce_after: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    network: Network,
    account: [u8; 20],
    pending_reference: [u8; 32],
    mode: TransitionMode,
    kind: TransitionOutcomeKind,
    activation_timestamp_unix: u64,
    source_finalized_height: u64,
    source_finalized_time: u64,
    included_height: u64,
    consensus_time: u64,
    old_policy_epoch: u64,
    resulting_policy_epoch: u64,
    old_policy_hash: [u8; 32],
    resulting_policy_hash: [u8; 32],
    signed_charge: Option<Charge>,
}

pub(super) fn owns_key(key: &str) -> bool {
    key.starts_with(PREFIX)
}

fn key(account: AccountIdentifier, reference: &[u8; 32]) -> String {
    format!(
        "{PREFIX}{}/{}",
        account.lowercase_hex(),
        inspection::hex_bytes(reference)
    )
}

fn digest(value: &str) -> bool {
    value.len() == 128
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && value.bytes().any(|b| b != b'0')
}

fn validate(record: &Record) -> Result<(), String> {
    use super::super::protected_action_wire::{POLICY_CANCEL, RECOVERY_CANCEL, RECOVERY_VETO};
    use TransitionOutcomeKind::{Activated, Canceled, Vetoed};
    AccountIdentifier::from_bytes(record.account)
        .validate_spending_destination()
        .map_err(display)?;
    if record.version != 1
        || record.pending_reference == [0; 32]
        || record.activation_timestamp_unix == 0
        || record.source_finalized_height == 0
        || record.source_finalized_time == 0
        || record.included_height <= record.source_finalized_height
        || record.consensus_time < record.source_finalized_time
        || record.old_policy_hash == [0; 32]
        || record.resulting_policy_hash == [0; 32]
    {
        return Err("invalid candidate transition settlement position or identity".into());
    }
    match (&record.kind, &record.signed_charge) {
        (Activated, None) => {
            if record.consensus_time < record.activation_timestamp_unix
                || record.old_policy_epoch.checked_add(1) != Some(record.resulting_policy_epoch)
                || record.old_policy_hash == record.resulting_policy_hash
            {
                return Err("invalid candidate activation settlement".into());
            }
        }
        (Canceled | Vetoed, Some(charge)) => {
            let action = match (record.kind, record.mode) {
                (Canceled, TransitionMode::Ordinary) => POLICY_CANCEL,
                (Canceled, TransitionMode::Recovery) => RECOVERY_CANCEL,
                (Vetoed, TransitionMode::Recovery) => RECOVERY_VETO,
                _ => return Err("invalid candidate transition termination mode".into()),
            };
            if record.consensus_time >= record.activation_timestamp_unix
                || record.old_policy_epoch != record.resulting_policy_epoch
                || record.old_policy_hash != record.resulting_policy_hash
                || charge.action != action
                || charge.intent_id == [0; 32]
                || !digest(&charge.signed_intent_digest)
                || charge.gas_used == 0
                || charge.fee_nwei == 0
                || charge.nonce_before.checked_add(1) != Some(charge.nonce_after)
            {
                return Err("invalid candidate signed transition settlement".into());
            }
        }
        _ => return Err("candidate transition settlement has an impossible charge".into()),
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn prepare_transition_settlement(
    finalized: &FinalizedSnapshot<'_>,
    outcome: &TransitionExecutionOutcome,
) -> Result<ProtocolChange, String> {
    let entry = &outcome.transition;
    let record = Record {
        version: 1,
        network: finalized.registry.network,
        account: *entry.account.as_bytes(),
        pending_reference: entry.reference,
        mode: entry.mode,
        kind: outcome.kind,
        activation_timestamp_unix: entry.activation_at,
        source_finalized_height: outcome.source_finalized_height,
        source_finalized_time: finalized.position.consensus_time,
        included_height: outcome.included.height,
        consensus_time: outcome.included.consensus_time,
        old_policy_epoch: outcome.old_policy_epoch,
        resulting_policy_epoch: outcome.resulting_policy_epoch,
        old_policy_hash: outcome.old_policy_hash,
        resulting_policy_hash: outcome.resulting_policy_hash,
        signed_charge: outcome.signed_charge.as_ref().map(|charge| Charge {
            action: charge.action,
            intent_id: charge.intent_id,
            signed_intent_digest: inspection::hex_bytes(&charge.signed_digest),
            gas_used: charge.gas_used,
            fee_nwei: charge.fee_nwei,
            nonce_before: charge.nonce_before,
            nonce_after: charge.nonce_after,
        }),
    };
    validate(&record)?;
    entry.verify_index(finalized.world)?;
    let active = finalized
        .registry
        .read_policy(finalized.world, entry.account)?;
    if record.source_finalized_height != finalized.position.height
        || active.policy_epoch != record.old_policy_epoch
        || active.policy_hash != record.old_policy_hash
    {
        return Err("transition settlement differs from its source finalized policy".into());
    }
    let record_key = key(entry.account, &entry.reference);
    if finalized.world.protocol.contains_key(&record_key) {
        return Err("candidate transition already has a terminal settlement".into());
    }
    let bytes = encode(&record)?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err("candidate transition settlement exceeds bound".into());
    }
    // The caller pairs this with the exact policy/pending/index/fee changes in
    // one atomic write. Missing-only CAS also rejects an overlay duplicate.
    Ok(ProtocolChange {
        key: record_key,
        expected_value: None,
        value: Some(bytes),
    })
}

pub(super) fn inspect_transition_settlement(
    snapshot: &FinalizedSnapshot<'_>,
    account: AccountIdentifier,
    reference: [u8; 32],
    expected_signed_digest: Option<&str>,
) -> Result<Value, String> {
    account.validate_spending_destination().map_err(display)?;
    if reference == [0; 32] || expected_signed_digest.is_some_and(|value| !digest(value)) {
        return Err("invalid candidate transition settlement selector".into());
    }
    let Some(bytes) = snapshot.world.protocol.get(&key(account, &reference)) else {
        return Ok(json!({"status":"no_transition_settlement_in_snapshot",
            "account":account.to_native(&Primitives).map_err(display)?,
            "pending_reference":inspection::hex_bytes(&reference)}));
    };
    let record: Record = decode(bytes, MAX_RECORD_BYTES)?;
    validate(&record)?;
    if encode(&record)? != *bytes
        || record.network != snapshot.registry.network
        || record.account != *account.as_bytes()
        || record.pending_reference != reference
        || record.included_height > snapshot.position.height
        || record.consensus_time > snapshot.position.consensus_time
        || expected_signed_digest.is_some_and(|expected| {
            record
                .signed_charge
                .as_ref()
                .is_none_or(|charge| charge.signed_intent_digest != expected)
        })
    {
        return Err("candidate transition settlement differs from selected evidence".into());
    }
    let reference_hex = inspection::hex_bytes(&reference);
    let pending = inspect_pending_transition(snapshot, account)?;
    if pending["pending_reference"].as_str() == Some(reference_hex.as_str()) {
        return Err("candidate transition is both pending and terminal".into());
    }
    let status = match record.kind {
        TransitionOutcomeKind::Canceled => "canceled_candidate",
        TransitionOutcomeKind::Vetoed => "vetoed_candidate",
        TransitionOutcomeKind::Activated => "activated_candidate",
    };
    let charge = record.signed_charge.as_ref().map(|charge| {
        json!({
            "action":charge.action, "intent_id":inspection::hex_bytes(&charge.intent_id),
            "signed_intent_digest":charge.signed_intent_digest, "gas_used":charge.gas_used,
            "fee_nwei":charge.fee_nwei.to_string(), "nonce_before":charge.nonce_before,
            "nonce_after":charge.nonce_after,
        })
    });
    Ok(
        json!({"status":status,"account":account.to_native(&Primitives).map_err(display)?,
        "pending_reference":reference_hex,
        "mode":record.mode,"activation_timestamp_unix":record.activation_timestamp_unix,
        "source_finalized_height":record.source_finalized_height,
        "source_finalized_consensus_timestamp_unix":record.source_finalized_time,
        "included_height":record.included_height,"consensus_timestamp_unix":record.consensus_time,
        "old_policy_epoch":record.old_policy_epoch,"resulting_policy_epoch":record.resulting_policy_epoch,
        "old_policy_hash":inspection::hex_bytes(&record.old_policy_hash),
        "resulting_policy_hash":inspection::hex_bytes(&record.resulting_policy_hash),
        "signed_charge":charge}),
    )
}
