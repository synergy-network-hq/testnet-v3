use std::path::Path;

use serde::{Deserialize, Serialize};
use synergy_aegis::KeyState;
use synergy_identity::NodeAddress;

use crate::aegis_keys::{read_metadata, write_public_json, KeyMetadata};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotationPlan {
    pub format_version: u32,
    #[serde(alias = "node_id")]
    pub node_address: NodeAddress,
    pub purpose: String,
    pub current_key_id: String,
    pub next_key_id: String,
    pub activation_epoch: u64,
    pub current_public_key_fingerprint: String,
    pub next_public_key_fingerprint: String,
}

impl RotationPlan {
    pub fn validate(&self) -> Result<(), String> {
        if self.format_version != 1
            || self.current_key_id == self.next_key_id
            || self.activation_epoch == 0
            || self.current_public_key_fingerprint == self.next_public_key_fingerprint
        {
            return Err("invalid key rotation plan".into());
        }
        Ok(())
    }
}

pub fn plan(
    current_path: &Path,
    next_path: &Path,
    activation_epoch: u64,
    output_path: &Path,
) -> Result<RotationPlan, String> {
    let current = read_metadata(current_path)?;
    let next = read_metadata(next_path)?;
    validate_transition(&current, &next, activation_epoch)?;
    let plan = RotationPlan {
        format_version: 1,
        node_address: current.node_address,
        purpose: format!("{:?}", current.record.purpose),
        current_key_id: current.record.id.as_str().into(),
        next_key_id: next.record.id.as_str().into(),
        activation_epoch,
        current_public_key_fingerprint: current.public_key_fingerprint,
        next_public_key_fingerprint: next.public_key_fingerprint,
    };
    plan.validate()?;
    write_public_json(output_path, &plan)?;
    Ok(plan)
}

fn validate_transition(
    current: &KeyMetadata,
    next: &KeyMetadata,
    activation_epoch: u64,
) -> Result<(), String> {
    if activation_epoch == 0
        || current.node_address != next.node_address
        || current.record.purpose != next.record.purpose
        || current.record.id == next.record.id
        || current.record.public_key == next.record.public_key
        || current.record.state != KeyState::Active
        || next.record.state != KeyState::Generated
    {
        return Err(
            "rotation requires same-node/same-purpose active-to-generated distinct keys".into(),
        );
    }
    Ok(())
}
