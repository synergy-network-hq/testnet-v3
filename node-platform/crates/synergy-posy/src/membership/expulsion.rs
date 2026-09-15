use serde::{Deserialize, Serialize};

use crate::{is_hash, require_nonempty, PosyError, PosyResult, ValidatorId};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduledExpulsion {
    pub validator_id: ValidatorId,
    pub evidence_root: String,
    pub effective_epoch: u64,
    pub authorization_root: String,
}

impl ScheduledExpulsion {
    /// Expulsion is a governed future-epoch membership effect; it never edits
    /// the validator set frozen for the active epoch.
    pub fn validate(&self, current_epoch: u64) -> PosyResult<()> {
        require_nonempty(&self.validator_id, "expulsion validator id")?;
        require_nonempty(&self.authorization_root, "expulsion authorization root")?;
        if !is_hash(&self.evidence_root) || self.effective_epoch <= current_epoch {
            return Err(PosyError::invalid(
                "invalid expulsion evidence or effective epoch",
            ));
        }
        Ok(())
    }
}
