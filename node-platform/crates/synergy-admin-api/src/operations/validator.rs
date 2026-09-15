use serde::{Deserialize, Serialize};
use synergy_protocol_types::NodeAddress;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ValidatorOperation {
    Inspect {
        node_address: NodeAddress,
    },
    Onboard {
        node_address: NodeAddress,
        consensus_key_id: String,
        operator_identity: String,
        target_epoch: u64,
        authorization_root: String,
        required_shadow_blocks: u64,
    },
    Authorize {
        node_address: NodeAddress,
    },
    BeginSynchronization {
        node_address: NodeAddress,
    },
    EnterShadow {
        node_address: NodeAddress,
        change_set_root: String,
        frozen_voting_weight: u128,
    },
    RecordShadowProgress {
        node_address: NodeAddress,
        verified_blocks: u64,
    },
    MarkReady {
        node_address: NodeAddress,
    },
    RequestActivation {
        node_address: NodeAddress,
        change_set_root: String,
    },
    ConfirmFrozenAuthority {
        node_address: NodeAddress,
    },
    ScheduleJailing {
        node_address: NodeAddress,
        evidence_root: String,
        effective_epoch: u64,
        release_epoch: Option<u64>,
        authorization_root: String,
    },
    ScheduleDeactivation {
        node_address: NodeAddress,
        effective_epoch: u64,
        authorization_root: String,
    },
    ScheduleExpulsion {
        node_address: NodeAddress,
        evidence_root: String,
        effective_epoch: u64,
        authorization_root: String,
    },
    ScheduleSlashing {
        node_address: NodeAddress,
        evidence_root: String,
        penalty_units: u128,
        effective_epoch: u64,
        authorization_root: String,
    },
}

impl ValidatorOperation {
    pub fn is_mutating(&self) -> bool {
        !matches!(self, Self::Inspect { .. })
    }

    pub fn validate(&self) -> Result<(), crate::AdminError> {
        let node_address = match self {
            Self::Inspect { node_address }
            | Self::Onboard { node_address, .. }
            | Self::Authorize { node_address }
            | Self::BeginSynchronization { node_address }
            | Self::EnterShadow { node_address, .. }
            | Self::RecordShadowProgress { node_address, .. }
            | Self::MarkReady { node_address }
            | Self::RequestActivation { node_address, .. }
            | Self::ConfirmFrozenAuthority { node_address }
            | Self::ScheduleJailing { node_address, .. }
            | Self::ScheduleDeactivation { node_address, .. }
            | Self::ScheduleExpulsion { node_address, .. }
            | Self::ScheduleSlashing { node_address, .. } => node_address,
        };
        NodeAddress::parse(node_address.to_string())
            .map_err(|error| crate::AdminError::invalid_request(error.to_string()))?;
        match self {
            Self::Onboard {
                consensus_key_id,
                operator_identity,
                target_epoch,
                authorization_root,
                required_shadow_blocks,
                ..
            } => {
                require_identifier(consensus_key_id, "consensus key ID")?;
                require_identifier(operator_identity, "operator identity")?;
                require_hash(authorization_root, "onboarding authorization root")?;
                if *target_epoch == 0 || *required_shadow_blocks == 0 {
                    return Err(crate::AdminError::invalid_request(
                        "onboarding epoch and shadow requirement must be nonzero",
                    ));
                }
            }
            Self::EnterShadow {
                change_set_root,
                frozen_voting_weight,
                ..
            } => {
                require_hash(change_set_root, "membership change-set root")?;
                if *frozen_voting_weight == 0 {
                    return Err(crate::AdminError::invalid_request(
                        "frozen voting weight must be nonzero",
                    ));
                }
            }
            Self::RecordShadowProgress {
                verified_blocks, ..
            } if *verified_blocks == 0 => {
                return Err(crate::AdminError::invalid_request(
                    "verified shadow progress must be nonzero",
                ));
            }
            Self::RequestActivation {
                change_set_root, ..
            } => require_hash(change_set_root, "membership change-set root")?,
            Self::ScheduleJailing {
                evidence_root,
                effective_epoch,
                release_epoch,
                authorization_root,
                ..
            } => {
                require_hash(evidence_root, "jailing evidence root")?;
                require_hash(authorization_root, "jailing authorization root")?;
                require_future_epoch(*effective_epoch)?;
                if release_epoch.is_some_and(|release| release <= *effective_epoch) {
                    return Err(crate::AdminError::invalid_request(
                        "jailing release epoch must follow its effective epoch",
                    ));
                }
            }
            Self::ScheduleDeactivation {
                effective_epoch,
                authorization_root,
                ..
            } => {
                require_hash(authorization_root, "deactivation authorization root")?;
                require_future_epoch(*effective_epoch)?;
            }
            Self::ScheduleExpulsion {
                evidence_root,
                effective_epoch,
                authorization_root,
                ..
            } => {
                require_hash(evidence_root, "expulsion evidence root")?;
                require_hash(authorization_root, "expulsion authorization root")?;
                require_future_epoch(*effective_epoch)?;
            }
            Self::ScheduleSlashing {
                evidence_root,
                penalty_units,
                effective_epoch,
                authorization_root,
                ..
            } => {
                require_hash(evidence_root, "slashing evidence root")?;
                require_hash(authorization_root, "slashing authorization root")?;
                require_future_epoch(*effective_epoch)?;
                if *penalty_units == 0 {
                    return Err(crate::AdminError::invalid_request(
                        "slashing penalty must be nonzero",
                    ));
                }
            }
            _ => {}
        }
        Ok(())
    }
}

fn require_identifier(value: &str, label: &str) -> Result<(), crate::AdminError> {
    if value.trim().is_empty() || value.len() > 256 || value.contains(char::is_control) {
        return Err(crate::AdminError::invalid_request(format!(
            "{label} must contain 1..=256 safe characters"
        )));
    }
    Ok(())
}

fn require_hash(value: &str, label: &str) -> Result<(), crate::AdminError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(crate::AdminError::invalid_request(format!(
            "{label} must be a 64-character hexadecimal hash"
        )));
    }
    Ok(())
}

fn require_future_epoch(epoch: u64) -> Result<(), crate::AdminError> {
    if epoch == 0 {
        return Err(crate::AdminError::invalid_request(
            "validator lifecycle epoch must be nonzero",
        ));
    }
    Ok(())
}
