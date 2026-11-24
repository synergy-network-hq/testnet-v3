//! Lookup for the protected receipt produced by an exact selected READY record.
use super::super::{debug, decode, encode, processing_disposition, settlement, sponsor_settlement};
use crate::services::processing_store::PendingProcessingIdentity;
use serde::{Deserialize, Serialize};
use synergy_etdag::EtdagDigest;
use synergy_execution::ProcessingReadyRecord;
use synergy_state::{ProtocolChange, StateDiff, WorldState, world_resources::BudgetedWorld};

const PREFIX: &str = "apqe-protected-account-candidate/v1/processing-outcome/";
const MAX_INDEX_BYTES: usize = 1_024;
const MAX_RECEIPT_BYTES: usize = 8_192;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Outcome {
    height: u64,
    identity: EtdagDigest,
    ready: EtdagDigest,
    receipt_key: String,
    receipt: EtdagDigest,
}

fn key(envelope: &EtdagDigest) -> String {
    format!("{PREFIX}{}", envelope.0)
}

fn identity(
    envelope: &EtdagDigest,
    context: &EtdagDigest,
    sender: &str,
    nonce: u64,
) -> Result<EtdagDigest, String> {
    EtdagDigest::from_canonical(
        "SYNERGY_POSY_PW13_OUTCOME_IDENTITY_V1",
        &(envelope, context, sender, nonce),
    )
    .map_err(debug)
}

fn record_identity(record: &ProcessingReadyRecord) -> Result<EtdagDigest, String> {
    identity(
        &record.item.envelope_id,
        &record.processing_context_root,
        &record.sender_wallet,
        record.sender_nonce,
    )
}

fn receipt_digest(world: &WorldState, key: &str) -> Result<EtdagDigest, String> {
    if key.len() > 384
        || !(settlement::owns_key(key)
            || sponsor_settlement::owns_key(key)
            || processing_disposition::owns_key(key)
            || key.starts_with(synergy_etdag::admission::FEE_FREE_ENROLLMENT_SETTLEMENT_PREFIX)
            || key.starts_with(synergy_etdag::admission::FEE_FREE_SYNID_SETTLEMENT_PREFIX))
    {
        return Err("invalid protected processing receipt key".into());
    }
    let bytes = world
        .protocol
        .get(key)
        .filter(|bytes| !bytes.is_empty() && bytes.len() <= MAX_RECEIPT_BYTES)
        .ok_or("protected processing outcome lacks its receipt")?;
    Ok(EtdagDigest::from_domain_bytes(
        "SYNERGY_POSY_PW13_OUTCOME_RECEIPT_V1",
        bytes,
    ))
}

fn lookup(world: &WorldState, envelope: &EtdagDigest) -> Result<Option<Outcome>, String> {
    let Some(bytes) = world.protocol.get(&key(envelope)) else {
        return Ok(None);
    };
    let index: Outcome = decode(bytes, MAX_INDEX_BYTES)?;
    if index.height == 0 || encode(&index)? != *bytes {
        return Err("invalid canonical protected processing outcome".into());
    }
    Ok(Some(index))
}

pub(in crate::services::protected_accounts) fn validate_public_record(
    world: &WorldState, key: &str, bytes: &[u8], height: u64,
) -> Result<bool, String> {
    let Some(envelope) = key.strip_prefix(PREFIX) else { return Ok(false); };
    let envelope = EtdagDigest(envelope.to_owned());
    let record: Outcome = decode(bytes, MAX_INDEX_BYTES)?;
    for digest in [&envelope, &record.identity, &record.ready, &record.receipt] {
        digest.validate().map_err(debug)?;
        if digest.is_zero() { return Err("invalid public protected processing outcome digest".into()); }
    }
    if record.height == 0 || record.height > height
        || record.receipt != receipt_digest(world, &record.receipt_key)?
        || encode(&record)? != bytes
    {
        return Err("invalid public protected processing outcome record".into());
    }
    Ok(true)
}

pub(super) fn record_outcome(
    candidate: &mut BudgetedWorld,
    height: u64,
    record: &ProcessingReadyRecord,
    receipt_key: String,
) -> Result<(), String> {
    let index = Outcome {
        height,
        identity: record_identity(record)?,
        ready: record.item.readiness_root.clone(),
        receipt: receipt_digest(candidate.as_ref(), &receipt_key)?,
        receipt_key,
    };
    let value = encode(&index)?;
    if value.len() > MAX_INDEX_BYTES {
        return Err("protected processing index exceeds its bound".into());
    }
    // The exact verified business outcome and its index join one speculative
    // World. No later finality or retirement operation can create an index.
    candidate
        .try_apply(&StateDiff {
            protocol_changes: vec![ProtocolChange {
                key: key(&record.item.envelope_id),
                expected_value: None,
                value: Some(value),
            }],
            ..StateDiff::default()
        })
        .map_err(debug)
}

/// Prefilter sparse authorization-only pins without reopening an unrelated
/// consumption parent. This grants no retirement authority.
pub(in crate::services) fn matches_pending(
    world: &WorldState,
    height: u64,
    pending: &PendingProcessingIdentity,
) -> Result<bool, String> {
    let Some(index) = lookup(world, &pending.envelope_id)? else {
        return Ok(false);
    };
    Ok(index.height == height
        && index.identity
            == identity(
                &pending.envelope_id,
                &pending.context_root,
                &pending.sender_wallet,
                pending.sender_nonce,
            )?)
}

pub(in crate::services) fn verify_selected(
    parent: &WorldState,
    candidate: &WorldState,
    height: u64,
    record: &ProcessingReadyRecord,
) -> Result<bool, String> {
    let Some(index) = lookup(candidate, &record.item.envelope_id)? else {
        return Ok(false);
    };
    if index.height != height
        || index.identity != record_identity(record)?
        || index.ready != record.item.readiness_root
        || parent.protocol.contains_key(&key(&record.item.envelope_id))
        || parent.protocol.contains_key(&index.receipt_key)
        || index.receipt != receipt_digest(candidate, &index.receipt_key)?
    {
        return Err(
            "protected processing receipt differs from the exact finalized selection".into(),
        );
    }
    Ok(true)
}

#[cfg(test)]
pub(in crate::services) fn selected_receipt_key(
    world: &WorldState,
    envelope: &EtdagDigest,
) -> Option<String> {
    lookup(world, envelope)
        .expect("known test outcome")
        .map(|index| index.receipt_key)
}
