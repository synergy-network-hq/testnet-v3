//! Candidate transfer settlement stored in the same World as its ledger effects.
//! An optional local ETDAG opening binds exact bytes, without asserting ingress
//! admission, reveal authorization, or another processing lifecycle outcome.
use super::*;
use serde_json::{json, Value};
use synergy_etdag::EtdagDigest;

const INTENT_PREFIX: &str = "apqe-protected-account-candidate/v1/settled-intent/";
const MAX_STORED_RECEIPT_BYTES: usize = 8192;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum TransferRevertReason {
    RecipientBalanceOverflow,
    InsufficientTransferBalance,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TransferSettlement {
    version: u8,
    network: Network,
    intent_id: [u8; 32],
    signed_intent_digest: String,
    decrypted_content_sha3_256: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    engineering_etdag_opening: Option<EngineeringEtdagOpening>,
    sender: [u8; 20],
    recipient: [u8; 20],
    source_finalized_height: u64,
    included_height: u64,
    consensus_time: u64,
    policy_epoch: u64,
    nonce_before: u64,
    nonce_after: u64,
    amount_nwei: u128,
    gas_used: u64,
    fee_nwei: u128,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    revert_reason: Option<TransferRevertReason>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EngineeringEtdagOpening {
    pub(super) envelope_id: EtdagDigest,
    pub(super) processing_context_root: EtdagDigest,
    pub(super) authorization_height: u64,
    pub(super) payload_root: EtdagDigest,
}

impl EngineeringEtdagOpening {
    fn validate(&self) -> Result<(), String> {
        for digest in [
            &self.envelope_id,
            &self.processing_context_root,
            &self.payload_root,
        ] {
            digest.validate().map_err(debug)?;
            if digest.is_zero() {
                return Err("zero digest in candidate ETDAG opening".into());
            }
        }
        if self.authorization_height == 0 {
            return Err("zero authorization height in candidate ETDAG opening".into());
        }
        Ok(())
    }
}

pub(super) fn owns_key(key: &str) -> bool {
    key.starts_with(INTENT_PREFIX)
}

fn receipt_key(account: AccountIdentifier, intent: &[u8; 32]) -> String {
    format!(
        "{INTENT_PREFIX}{}/{}",
        account.lowercase_hex(),
        inspection::hex_bytes(intent)
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(super) fn prepare_transfer_settlement(
    finalized: &FinalizedSnapshot<'_>,
    world: &WorldState,
    intent: &CanonicalNativeIntent<'_>,
    decrypted_content: &[u8],
    opened_envelope: Option<&synergy_etdag::ProcessingEnvelope>,
    recipient: AccountIdentifier,
    amount_nwei: u128,
    gas_used: u64,
    fee_nwei: u128,
    inclusion: Position,
    revert_reason: Option<TransferRevertReason>,
) -> Result<ProtocolChange, String> {
    let body = intent.body();
    if inclusion.height <= finalized.position.height
        || inclusion.consensus_time < finalized.position.consensus_time
    {
        return Err("candidate settlement requires a later execution position".into());
    }
    let key = receipt_key(body.account, &body.intent_id);
    if finalized.world.protocol.contains_key(&key) || world.protocol.contains_key(&key) {
        return Err("protected intent already has a candidate settlement".into());
    }
    let signature_digest = intent.digest().map_err(display)?;
    let content_hash = Primitives
        .hash(HashAlgorithm::Sha3256, decrypted_content)
        .map_err(debug)?;
    let engineering_etdag_opening = opened_envelope
        .map(|envelope| {
            let opening = EngineeringEtdagOpening {
                envelope_id: envelope.envelope_id.clone(),
                processing_context_root: envelope.aad.processing_context_root.clone(),
                authorization_height: envelope.aad.authorization_height,
                payload_root: synergy_execution::processing_payload_root(
                    &envelope.aad.processing_context_root,
                    &envelope.envelope_id,
                    decrypted_content,
                )
                .map_err(debug)?,
            };
            opening.validate()?;
            Ok::<_, String>(opening)
        })
        .transpose()?;
    let value = TransferSettlement {
        version: 1,
        network: finalized.registry.network,
        intent_id: body.intent_id,
        signed_intent_digest: inspection::hex_bytes(signature_digest.as_bytes()),
        decrypted_content_sha3_256: content_hash
            .try_into()
            .map_err(|_| "invalid content digest")?,
        engineering_etdag_opening,
        sender: *body.account.as_bytes(),
        recipient: *recipient.as_bytes(),
        source_finalized_height: finalized.position.height,
        included_height: inclusion.height,
        consensus_time: inclusion.consensus_time,
        policy_epoch: body.policy_epoch,
        nonce_before: body.transaction_nonce,
        nonce_after: body
            .transaction_nonce
            .checked_add(1)
            .ok_or("protected nonce exhausted")?,
        amount_nwei,
        gas_used,
        fee_nwei,
        revert_reason,
    };
    Ok(ProtocolChange {
        key,
        expected_value: None,
        value: Some(encode(&value)?),
    })
}

pub(super) fn inspect_transfer_settlement(
    snapshot: &FinalizedSnapshot<'_>,
    account: AccountIdentifier,
    intent_id: [u8; 32],
    expected_digest: &str,
    expected_opening: Option<&EngineeringEtdagOpening>,
) -> Result<Value, String> {
    if let Some(expected) = expected_opening {
        expected.validate()?;
    }
    let Some(bytes) = snapshot
        .world
        .protocol
        .get(&receipt_key(account, &intent_id))
    else {
        return Ok(json!({
            "sender": account.to_native(&Primitives).map_err(display)?,
            "intent_id": inspection::hex_bytes(&intent_id),
            "status": "no_settlement_in_snapshot",
        }));
    };
    let record: TransferSettlement = decode(bytes, MAX_STORED_RECEIPT_BYTES)?;
    if let Some(opening) = record.engineering_etdag_opening.as_ref() {
        opening.validate()?;
        if opening.authorization_height <= record.source_finalized_height {
            return Err("candidate ETDAG opening has a different authorization height".into());
        }
    }
    if let Some(expected) = expected_opening {
        if record.engineering_etdag_opening.as_ref() != Some(expected) {
            return Err("requested ETDAG opening differs from candidate settlement".into());
        }
    }
    if encode(&record)? != *bytes
        || record.version != 1
        || record.network != snapshot.registry.network
        || record.intent_id != intent_id
        || record.sender != *account.as_bytes()
        || record.signed_intent_digest != expected_digest
        || record.recipient == record.sender
        || record.recipient == [0; 20]
        || record.source_finalized_height == 0
        || record.source_finalized_height >= record.included_height
        || record.included_height > snapshot.position.height
        || !(1..=snapshot.position.consensus_time).contains(&record.consensus_time)
        || record.nonce_before.checked_add(1) != Some(record.nonce_after)
        || record.amount_nwei == 0
        || record.gas_used == 0
        || record.amount_nwei.checked_add(record.fee_nwei).is_none()
    {
        return Err("candidate transfer receipt disagrees with selected intent or snapshot".into());
    }
    let mut observed = json!({
        "sender": account.to_native(&Primitives).map_err(display)?,
        "recipient": AccountIdentifier::from_bytes(record.recipient).to_native(&Primitives).map_err(display)?,
        "intent_id": inspection::hex_bytes(&intent_id),
        "signed_intent_digest": record.signed_intent_digest,
        "decrypted_content_sha3_256": inspection::hex_bytes(&record.decrypted_content_sha3_256),
        "engineering_etdag_opening": record.engineering_etdag_opening,
        "status": if record.revert_reason.is_some() { "reverted_candidate" } else { "applied_candidate" },
        "source_finalized_height": record.source_finalized_height,
        "included_height": record.included_height,
        "inclusion_consensus_timestamp_unix": record.consensus_time,
        "policy_epoch": record.policy_epoch,
        "nonce_before": record.nonce_before,
        "nonce_after": record.nonce_after,
        "amount_nwei": record.amount_nwei.to_string(),
        "credited_nwei": if record.revert_reason.is_some() { "0".to_owned() } else { record.amount_nwei.to_string() },
        "gas_used": record.gas_used,
        "fee_nwei": record.fee_nwei.to_string(),
    });
    if let Some(reason) = record.revert_reason {
        observed["revert_reason"] = serde_json::to_value(reason).map_err(display)?;
    }
    Ok(observed)
}
