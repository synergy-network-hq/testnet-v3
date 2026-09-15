use serde::{Deserialize, Serialize};

use crate::{require_nonempty, KeyId, PosyError, PosyResult, ValidatorId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidatorStatus {
    Shadow,
    Active,
    Jailed,
    Removed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorRecord {
    pub validator_id: ValidatorId,
    pub consensus_key_id: KeyId,
    pub frozen_voting_weight: u128,
    pub status: ValidatorStatus,
}

impl ValidatorRecord {
    pub fn validate(&self) -> PosyResult<()> {
        require_nonempty(&self.validator_id, "validator id")?;
        require_nonempty(&self.consensus_key_id, "validator consensus key")?;
        if self.frozen_voting_weight == 0 {
            return Err(PosyError::invalid("validator frozen voting weight is zero"));
        }
        Ok(())
    }

    pub const fn may_sign_consensus(&self) -> bool {
        matches!(self.status, ValidatorStatus::Active)
    }
}
