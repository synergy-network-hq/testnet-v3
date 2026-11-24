//! Finalized processing metadata contains commitments and public routing terms
//! only. Original envelopes, authentication proofs and plaintext stay outside World.
use serde::{de::DeserializeOwned, Serialize};
use synergy_etdag::EtdagDigest;
use synergy_execution::{ProcessingGroupState, ProcessingMemberClaim, ProcessingReadyRecord};

const GROUP: &str = "etdag-processing-groups-v1/group/";
const CLAIM: &str = "etdag-processing-groups-v1/claim/";
const READY: &str = "etdag-processing-ready-v1/item/";
const MAX_METADATA_BYTES: usize = 16 * 1024;

// Public metadata is not spending authority. External account identifiers are
// admitted only by the independently signed EIP155 processing owner.
fn valid_processing_sender(value:&str)->bool {
    synergy_address::is_valid_address(value) || value.strip_prefix("0x")
        .is_some_and(|text|text.len()==40&&text.bytes().all(|byte|byte.is_ascii_digit()||(b'a'..=b'f').contains(&byte)))
}

pub(super) fn validate_record(key: &str, bytes: &[u8]) -> Result<bool, String> {
    let invalid = || "invalid public processing metadata".to_owned();
    if let Some(number) = key.strip_prefix(GROUP) {
        let record: ProcessingGroupState = decode(bytes)?;
        if record.group_number == 0
            || number != format!("{:020}", record.group_number)
            || record.remaining > 4096
            || record.next_position > 4096
        {
            return Err(invalid());
        }
        roots([&record.namespace_root, &record.group_root])?;
        roots(record.closed_by_successor.iter())?;
    } else if let Some(digest) = key.strip_prefix(CLAIM) {
        let record: ProcessingMemberClaim = decode(bytes)?;
        let envelope = &record.member.envelope;
        if record.group_number == 0
            || record.order_position >= 4096
            || envelope.nonce_slot == u64::MAX
            || envelope.protocol_dependencies.len() > 64
            || !valid_processing_sender(&envelope.sender_id)
            || EtdagDigest::from_canonical(
                "SYNERGY_ETDAG_PROCESSING_NONCE_CLAIM_V1",
                &(&envelope.sender_id, envelope.nonce_slot),
            )
            .map_err(|_| invalid())?
            .0 != digest
        {
            return Err(invalid());
        }
        envelope.validate().map_err(|_| invalid())?;
        roots([
            &record.group_root,
            &record.member.processing_context_root,
            &record.member.authorization_root,
            &envelope.tx_commitment,
        ])?;
        roots(&envelope.protocol_dependencies)?;
    } else if let Some(digest) = key.strip_prefix(READY) {
        let record: ProcessingReadyRecord = decode(bytes)?;
        let item = &record.item;
        if item.envelope_id.0 != digest
            || item.group_number == 0
            || item.order_position >= 4096
            || item.gas_class_units == 0
            || item.encoded_bytes == 0
            || item.remaining_dependencies.len() > 64
            || record.sender_nonce == u64::MAX
            || !valid_processing_sender(&record.sender_wallet)
        {
            return Err(invalid());
        }
        roots([
            &record.processing_context_root,
            &record.authorization_root,
            &item.group_root,
            &item.envelope_id,
            &item.payload_root,
            &item.readiness_root,
        ])?;
        roots(&item.remaining_dependencies)?;
    } else {
        return Ok(false);
    }
    Ok(true)
}

fn decode<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T, String> {
    let error = || "expected exact bounded canonical public processing metadata".to_owned();
    if bytes.is_empty() || bytes.len() > MAX_METADATA_BYTES {
        return Err(error());
    }
    let value = serde_json::from_slice(bytes).map_err(|_| error())?;
    if serde_json::to_vec(&value).map_err(|_| error())? != bytes {
        return Err(error());
    }
    Ok(value)
}

fn roots<'a>(digests: impl IntoIterator<Item = &'a EtdagDigest>) -> Result<(), String> {
    for digest in digests {
        digest
            .validate()
            .map_err(|_| "invalid public processing digest")?;
        if digest.is_zero() {
            return Err("invalid public processing digest".into());
        }
    }
    Ok(())
}
