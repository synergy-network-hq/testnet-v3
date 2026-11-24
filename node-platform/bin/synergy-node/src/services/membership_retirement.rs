//! Consensus-owned future-epoch retirement. Local lifecycle scheduling has no
//! authority here; the current committee remains frozen until its QC closure.
use super::authority::VerifiedAuthority;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use synergy_genesis::membership::VerifiedMembershipRetirement;
use synergy_governance::{GovernanceExecution, MembershipRetirementSpec};
use synergy_state::{ProtocolChange, StateDiff, WorldState};

pub(super) const ACTION: &str = synergy_governance::MEMBERSHIP_RETIREMENT_ACTION_V1;
const OUTCOME: &str = "governance/posy-membership-outcome-v1/";
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RetirementOutcome {
    Expired,
    AlreadyDecided,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetirementDecision {
    version: u8,
    authorization_root: String,
    decided_at_finalized_height: u64,
    outcome: RetirementOutcome,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FinalizedMembershipEffect {
    pub schema_version: u8,
    pub installed_at_finalized_height: u64,
    pub execution: GovernanceExecution,
}
pub(super) fn genesis(authority: &VerifiedAuthority) -> Result<&str, String> {
    let synergy_posy::SimplifiedFinalityParent::Genesis { genesis_hash, .. } =
        &authority.autonomous_processing_origin().anchor_parent
    else {
        return Err("membership retirement lacks its authenticated Genesis origin".into());
    };
    Ok(genesis_hash)
}
pub(super) fn authorize_request(
    authority: &VerifiedAuthority,
    execution: &GovernanceExecution,
) -> Result<VerifiedMembershipRetirement, String> {
    if execution.mutation.action_kind != ACTION || execution.mutation.value.len() > 4096 {
        return Err("unsupported membership authorization".into());
    }
    let spec: MembershipRetirementSpec =
        serde_json::from_slice(&execution.mutation.value).map_err(|e| e.to_string())?;
    let original = authority
        .autonomous_authority_at(spec.install_not_before_finalized_height)
        .ok_or("membership retirement original frozen authority absent")?;
    VerifiedMembershipRetirement::verify(
        execution,
        genesis(authority)?,
        &original.epoch,
        &original.registry,
        original,
    )
}
pub(super) fn dispatch(
    authority: &VerifiedAuthority,
    execution: &GovernanceExecution,
    height: u64,
    world: &WorldState,
) -> Result<StateDiff, String> {
    let verified = authorize_request(authority, execution)?;
    let spec = verified.spec();
    if height < spec.install_not_before_finalized_height {
        return Err("membership retirement precedes its signed finalized-height window".into());
    }
    let key = spec.record_key();
    let expired = height > execution.proposal.expires_at_height;
    let already = world.protocol.contains_key(&key);
    let (key, value) = if expired || already {
        (
            format!("{OUTCOME}{}", execution.authorization_root),
            serde_json::to_vec(&RetirementDecision {
                version: 1,
                authorization_root: execution.authorization_root.clone(),
                decided_at_finalized_height: height,
                outcome: if expired {
                    RetirementOutcome::Expired
                } else {
                    RetirementOutcome::AlreadyDecided
                },
            })
            .map_err(|e| e.to_string())?,
        )
    } else {
        (
            key,
            serde_json::to_vec(&FinalizedMembershipEffect {
                schema_version: 1,
                installed_at_finalized_height: height,
                execution: execution.clone(),
            })
            .map_err(|e| e.to_string())?,
        )
    };
    if value.len() > 128 * 1024 {
        return Err("membership effect exceeds bounded protocol record".into());
    }
    Ok(StateDiff {
        changes: vec![],
        protocol_changes: vec![ProtocolChange {
            expected_value: world.protocol.get(&key).cloned(),
            key,
            value: Some(value),
        }],
    })
}

/// Disclosure is limited to the exact public governance effect or terminal
/// decision. This is a schema check; successor authentication verifies votes.
pub(super) fn validate_public_record(key: &str, bytes: &[u8]) -> Result<bool, String> {
    if key.starts_with(&format!("governance/{ACTION}/")) {
        if bytes.is_empty() || bytes.len() > 128 * 1024 {
            return Err("membership public record exceeds bound".into());
        }
        let record: FinalizedMembershipEffect =
            serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        let spec: MembershipRetirementSpec =
            serde_json::from_slice(&record.execution.mutation.value).map_err(|e| e.to_string())?;
        if record.schema_version != 1
            || record.installed_at_finalized_height < spec.install_not_before_finalized_height
            || record.installed_at_finalized_height > record.execution.proposal.expires_at_height
            || record.execution.mutation != spec.mutation()?
            || key != spec.record_key()
            || record.execution.votes.len() > 4096
            || record.execution.proposal.actions.len() != 1
            || !synergy_posy::is_hash(&record.execution.authorization_root)
            || serde_json::to_vec(&record).map_err(|e| e.to_string())? != bytes
        {
            return Err("invalid public membership effect".into());
        }
        return Ok(true);
    }
    if let Some(root) = key.strip_prefix(OUTCOME) {
        if bytes.len() > 1024 {
            return Err("membership decision exceeds bound".into());
        }
        let record: RetirementDecision =
            serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        if record.version != 1
            || record.decided_at_finalized_height == 0
            || !synergy_posy::is_hash(root)
            || record.authorization_root != root
            || serde_json::to_vec(&record).map_err(|e| e.to_string())? != bytes
        {
            return Err("invalid public membership decision".into());
        }
        return Ok(true);
    }
    Ok(false)
}

/// Called only by the finalized-World publisher. It cannot convert a locally
/// staged governance request or an administrative record into authority.
pub(super) fn refresh_finalized(
    authority: &VerifiedAuthority,
    height: u64,
    world: &WorldState,
) -> Result<(), String> {
    if !authority.epoch.contains_height(height) {
        return Ok(());
    }
    let target = authority
        .epoch
        .epoch
        .checked_add(1)
        .ok_or("membership epoch overflow")?;
    let key = format!("governance/{ACTION}/epoch-{target:020}");
    let Some(bytes) = world.protocol.get(&key) else {
        return Ok(());
    };
    if bytes.len() > 128 * 1024 {
        return Err("membership record exceeds source bound".into());
    }
    let record: FinalizedMembershipEffect =
        serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    if record.schema_version != 1
        || record.installed_at_finalized_height > height
        || record.installed_at_finalized_height > record.execution.proposal.expires_at_height
        || serde_json::to_vec(&record).map_err(|e| e.to_string())? != *bytes
    {
        return Err("membership source is not an exact finalized effect".into());
    }
    let verified = authorize_request(authority, &record.execution)?;
    if record.installed_at_finalized_height < verified.spec().install_not_before_finalized_height
        || verified.spec().record_key() != key
    {
        return Err("membership source differs from its installed window".into());
    }
    let mut cached = authority
        .membership_retirement
        .lock()
        .map_err(|_| "membership cache poisoned")?;
    if cached
        .as_ref()
        .is_some_and(|old| old.execution() != verified.execution())
    {
        return Err("conflicting finalized membership effect".into());
    }
    *cached = Some(Arc::new(verified));
    Ok(())
}
