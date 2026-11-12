//! Versioned unsigned observations around unchanged protected signing bytes.
use serde_json::{json, Value};
use synergy_etdag::{EtdagDigest, WalletAdmissionContext};
use synergy_posy::{SimplifiedFinalityParent, ThreeQcFinality};

use super::{authority::VerifiedAuthority, ingress::AuthenticatedIngress};

pub(super) fn context_response(
    authority: &VerifiedAuthority,
    ingress: &AuthenticatedIngress,
    signing_context: &WalletAdmissionContext,
) -> Result<Value, String> {
    signing_context
        .validate()
        .map_err(|e| format!("v2 signing context: {e:?}"))?;
    let source_height = signing_context.context.source_finalized_height;
    let binding: Option<Value> = if authority.binding_bytes().is_empty() {
        None
    } else {
        Some(
            serde_json::from_slice(authority.binding_bytes())
                .map_err(|e| format!("encode verified source authority binding: {e}"))?,
        )
    };
    let evidence = if source_height == 0 {
        if !matches!(
            authority.anchor_parent,
            SimplifiedFinalityParent::Genesis { .. }
        ) {
            return Err("zero-height context lacks governed Genesis authority".into());
        }
        let (expected, _) =
            authority.protected_target(None, signing_context.context.target_height)?;
        if expected != signing_context.context {
            return Err("Genesis source does not authorize the exact signing context".into());
        }
        json!({"kind":"genesis", "genesis_reference":authority.anchor_parent,
            "source_finality_context_root":expected.source_finality_context_root,
            "signed_authority_binding":binding,"authority_binding_present":binding.is_some()})
    } else {
        // PoSy publishes its witness only after durable QC/finality commit.
        // Snapshot that bounded pair for the exact live source instead of
        // reopening four files and verifying the same three QCs twice. This
        // is still untrusted evidence here: every QC and the resulting record
        // are checked against this authority below. Historical sources retain
        // the authenticated durable reader; a malformed live pair never falls
        // back to a different proof.
        let (record, witness) = match ingress.latest_finality_with_witness()? {
            Some((record, bytes)) if record.height == source_height => {
                let witness: [synergy_posy::SimplifiedQuorumCertificate; 3] =
                    serde_json::from_slice(&bytes)
                        .map_err(|e| format!("decode live v2 source witness: {e}"))?;
                (record, witness)
            }
            _ => ingress
                .finalized_record_with_witness(source_height)?
                .ok_or("exact durable source finality witness is unavailable")?,
        };
        // Rebind evidence to this authority, independently of the ingress
        // history's authority. Never publish foreign epoch evidence.
        let mut finality = ThreeQcFinality::default();
        for qc in &witness {
            qc.verify(&authority.epoch, &authority.registry, authority)
                .map_err(|e| format!("verify v2 source QC authority: {e}"))?;
            finality
                .accept(qc.clone())
                .map_err(|e| format!("verify v2 source ancestry: {e}"))?;
        }
        if finality.last_finalized() != Some(&record) {
            return Err("v2 source witness and record disagree".into());
        }
        let root = EtdagDigest::from_canonical("SYNERGY_ETDAG_FINALIZED_SOURCE_V1", &record)
            .map_err(|e| format!("recompute v2 source root: {e:?}"))?;
        let (expected, _) =
            authority.protected_target(Some(&record), signing_context.context.target_height)?;
        if root.0 != signing_context.context.source_finality_context_root
            || expected != signing_context.context
        {
            return Err("source evidence does not authorize the exact signing context".into());
        }
        json!({"kind":"three_qc","record":record,"quorum_certificates":witness,
            "source_finality_context_root":root.0,"signed_authority_binding":binding,
            "authority_binding_present":binding.is_some()})
    };
    let observed_at_unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "v2 observation clock precedes epoch")?
        .as_millis();
    let latest = ingress.latest_finality()?;
    let cutoff_height = signing_context
        .context
        .target_height
        .checked_sub(2)
        .ok_or("v2 context target precedes protected cutoff")?;
    let epoch_root = authority.epoch.root().map_err(|e| e.to_string())?;
    let slot = ingress.consensus_observation()?.filter(|value| {
        value.get("epoch_context_root").and_then(Value::as_str) == Some(epoch_root.as_str())
    });
    let consensus_height = slot
        .as_ref()
        .and_then(|value| value.get("height"))
        .and_then(Value::as_u64);
    let consensus_round = slot
        .as_ref()
        .and_then(|value| value.get("round"))
        .and_then(Value::as_u64);
    let remaining_height_distance =
        consensus_height.map(|height| cutoff_height.saturating_sub(height));
    Ok(json!({
        "schema_version":2,
        "signing_context":signing_context,
        "source_finality_evidence":evidence,
        "observation":{
            "observed_at_unix_ms":observed_at_unix_ms,
            "finalized_height":latest.as_ref().map(|record|record.height),
            "finalized_block_id":latest.as_ref().map(|record|&record.block_id),
            "target_height":signing_context.context.target_height,
            "cutoff_height":cutoff_height,
            "cutoff_relationship":"vc_event_context_v1",
            "admission_closed":ingress.protected_cutoff_authority(signing_context.context.target_height)?.is_some(),
            "consensus_height":consensus_height,"consensus_round":consensus_round,
            "remaining_height_distance":remaining_height_distance,"remaining_time_ms":null,
            "slot_observed_at_unix_ms":slot.as_ref().and_then(|value|value.get("observed_at_unix_ms")),
            "reservation":false,
            "freshness_basis":"publication_time; recheck current receipt and cutoff at submission",
        }
    }))
}
