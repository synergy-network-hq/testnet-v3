use serde::{Deserialize, Serialize};

use crate::{is_hash, require_nonempty, PosyError, PosyResult, ValidatorId};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduledJailing {
    pub validator_id: ValidatorId,
    pub evidence_root: String,
    pub effective_epoch: u64,
    pub release_epoch: Option<u64>,
    pub authorization_root: String,
}

impl ScheduledJailing {
    /// Jailing changes eligibility only at an epoch transition. It does not
    /// alter votes, quorum certificates, or finality.
    pub fn validate(&self, current_epoch: u64) -> PosyResult<()> {
        require_nonempty(&self.validator_id, "jailed validator id")?;
        require_nonempty(&self.authorization_root, "jailing authorization root")?;
        if !is_hash(&self.evidence_root) || self.effective_epoch <= current_epoch {
            return Err(PosyError::invalid(
                "invalid jailing evidence or effective epoch",
            ));
        }
        if self
            .release_epoch
            .is_some_and(|release| release <= self.effective_epoch)
        {
            return Err(PosyError::invalid(
                "jailing release epoch must follow the effective epoch",
            ));
        }
        Ok(())
    }
}
