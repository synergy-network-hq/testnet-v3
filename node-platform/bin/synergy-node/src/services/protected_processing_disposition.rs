//! Zero-effect terminal results for the unactivated PW13 processing profile.
use super::{
    debug, decode, encode, inspection, settlement::EngineeringEtdagOpening, FinalizedSnapshot,
    Network, Position,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use synergy_etdag::EtdagDigest;
use synergy_execution::ProcessingReadyRecord;
use synergy_state::{ProtocolChange, WorldState};

const PREFIX: &str = "apqe-protected-account-candidate/v1/processing-disposition/";
const MAX_BYTES: usize = 8192;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Disposition {
    Expired,
    NonceSuperseded {
        finalized_nonce: u64,
    },
    PolicySuperseded {
        signed_policy_epoch: u64,
        finalized_policy_epoch: u64,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    version: u8,
    network: Network,
    opening: EngineeringEtdagOpening,
    authorization_root: EtdagDigest,
    signed_intent_digest: String,
    payer: String,
    request_nonce: u64,
    source_finalized_height: u64,
    valid_until_finalized_height: u64,
    deciding_finalized_height: u64,
    deciding_finality_root: EtdagDigest,
    included_height: u64,
    consensus_time: u64,
    disposition: Disposition,
}

impl Receipt {
    fn validate(&self) -> Result<(), String> {
        self.opening.validate()?;
        self.authorization_root.validate().map_err(debug)?;
        self.deciding_finality_root.validate().map_err(debug)?;
        validate_intent_digest(&self.signed_intent_digest)?;
        let expired = self.deciding_finalized_height > self.valid_until_finalized_height;
        let coherent = match self.disposition {
            Disposition::Expired => expired,
            Disposition::NonceSuperseded { finalized_nonce } => {
                !expired && finalized_nonce > self.request_nonce
            }
            Disposition::PolicySuperseded {
                signed_policy_epoch,
                finalized_policy_epoch,
            } => !expired && finalized_policy_epoch > signed_policy_epoch,
        };
        if self.version != 1
            || !coherent
            || self.authorization_root.is_zero()
            || self.deciding_finality_root.is_zero()
            || self.payer.is_empty()
            || self.payer.len() > 256
            || self.payer.chars().any(char::is_control)
            || self.request_nonce == u64::MAX
            || self.source_finalized_height == 0
            || self.source_finalized_height >= self.opening.authorization_height
            || self.source_finalized_height > self.deciding_finalized_height
            || self.valid_until_finalized_height < self.source_finalized_height
            || self.included_height < self.opening.authorization_height
            || self.included_height <= self.deciding_finalized_height
            || self.consensus_time == 0
        {
            return Err("invalid protected processing disposition".into());
        }
        Ok(())
    }
}

fn validate_intent_digest(digest: &str) -> Result<(), String> {
    if digest.len() != 128
        || !digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("disposition requires the original lower-hex signed intent digest".into());
    }
    Ok(())
}

fn key(envelope: &EtdagDigest) -> String {
    format!("{PREFIX}{}", envelope.0)
}

pub(super) fn owns_key(key: &str) -> bool {
    key.starts_with(PREFIX)
}

pub(super) fn validate_public_record(scope: &super::PublicWalletRecords, stored_key: &str, bytes: &[u8]) -> Result<(), String> {
    let receipt: Receipt = decode(bytes, MAX_BYTES)?;
    receipt.validate()?;
    if !scope.matches(&receipt.network, receipt.included_height)
        || !synergy_address::is_valid_address(&receipt.payer)
        || stored_key != key(&receipt.opening.envelope_id)
        || encode(&receipt)? != bytes
    {
        return Err("invalid public protected processing disposition".into());
    }
    Ok(())
}

pub(super) struct DispositionSlot<'a> {
    pub(super) source_finalized_height: u64,
    pub(super) finalized: &'a FinalizedSnapshot<'a>,
    pub(super) inclusion: Position,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn prepare(
    world: &WorldState,
    record: &ProcessingReadyRecord,
    authorization_height: u64,
    signed_intent_digest: &[u8],
    valid_until_finalized_height: u64,
    slot: DispositionSlot<'_>,
    disposition: Disposition,
) -> Result<ProtocolChange, String> {
    let key = key(&record.item.envelope_id);
    if world.protocol.contains_key(&key) || slot.finalized.world.protocol.contains_key(&key) {
        return Err("protected envelope already has a terminal disposition".into());
    }
    let receipt = Receipt {
        version: 1,
        network: slot.finalized.registry.network,
        opening: EngineeringEtdagOpening {
            envelope_id: record.item.envelope_id.clone(),
            processing_context_root: record.processing_context_root.clone(),
            authorization_height,
            payload_root: record.item.payload_root.clone(),
        },
        authorization_root: record.authorization_root.clone(),
        signed_intent_digest: inspection::hex_bytes(signed_intent_digest),
        payer: record.sender_wallet.clone(),
        request_nonce: record.sender_nonce,
        source_finalized_height: slot.source_finalized_height,
        valid_until_finalized_height,
        deciding_finalized_height: slot.finalized.position.height,
        deciding_finality_root: slot.finalized.processing_finality_root.clone(),
        included_height: slot.inclusion.height,
        consensus_time: slot.inclusion.consensus_time,
        disposition,
    };
    receipt.validate()?;
    let bytes = encode(&receipt)?;
    if bytes.len() > MAX_BYTES {
        return Err("protected processing disposition exceeds storage bound".into());
    }
    Ok(ProtocolChange {
        key,
        expected_value: None,
        value: Some(bytes),
    })
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DispositionQuery {
    pub(super) opening: EngineeringEtdagOpening,
    pub(super) authorization_root: EtdagDigest,
    pub(super) signed_intent_digest: String,
}

pub(super) fn inspect(
    snapshot: &FinalizedSnapshot<'_>,
    query: &DispositionQuery,
) -> Result<Value, String> {
    query.opening.validate()?;
    query.authorization_root.validate().map_err(debug)?;
    validate_intent_digest(&query.signed_intent_digest)?;
    if query.authorization_root.is_zero() {
        return Err("disposition query requires a nonzero authorization commitment".into());
    }
    let Some(bytes) = snapshot
        .world
        .protocol
        .get(&key(&query.opening.envelope_id))
    else {
        return Ok(json!({
            "envelope_id": query.opening.envelope_id,
            "status": "no_disposition_in_snapshot",
        }));
    };
    let record: Receipt = decode(bytes, MAX_BYTES)?;
    record.validate()?;
    if encode(&record)? != *bytes
        || record.network != snapshot.registry.network
        || record.opening != query.opening
        || record.authorization_root != query.authorization_root
        || record.signed_intent_digest != query.signed_intent_digest
        || record.included_height > snapshot.position.height
        || record.consensus_time > snapshot.position.consensus_time
    {
        return Err(
            "protected processing disposition differs from the exact intent or snapshot".into(),
        );
    }
    Ok(json!({
        "status": match record.disposition {
            Disposition::Expired => "expired_candidate",
            Disposition::NonceSuperseded { .. } | Disposition::PolicySuperseded { .. } => "superseded_candidate",
        },
        "disposition": record.disposition,
        "engineering_etdag_opening": record.opening,
        "authorization_root": record.authorization_root,
        "signed_intent_digest": record.signed_intent_digest,
        "payer": record.payer,
        "request_nonce": record.request_nonce,
        "source_finalized_height": record.source_finalized_height,
        "valid_until_finalized_height": record.valid_until_finalized_height,
        "deciding_finalized_height": record.deciding_finalized_height,
        "deciding_finality_root": record.deciding_finality_root,
        "included_height": record.included_height,
        "inclusion_consensus_timestamp_unix": record.consensus_time,
        "nonce_consumed": false,
        "gas_used": 0,
        "fee_nwei": "0",
    }))
}
