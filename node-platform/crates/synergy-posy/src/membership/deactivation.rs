use serde::{Deserialize, Serialize};

use crate::{require_nonempty, PosyError, PosyResult, ValidatorId};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduledDeactivation {
    pub validator_id: ValidatorId,
    pub effective_epoch: u64,
    pub authorization_root: String,
}

impl ScheduledDeactivation {
    /// Validates a future-epoch membership transition. The current frozen epoch
    /// is intentionally immutable.
    pub fn validate(&self, current_epoch: u64) -> PosyResult<()> {
        require_nonempty(&self.validator_id, "deactivation validator id")?;
        require_nonempty(&self.authorization_root, "deactivation authorization root")?;
        if self.effective_epoch <= current_epoch {
            return Err(PosyError::invalid(
                "validator deactivation must target a future epoch",
            ));
        }
        Ok(())
    }
}
