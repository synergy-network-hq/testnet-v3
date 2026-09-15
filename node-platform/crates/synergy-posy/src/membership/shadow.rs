use serde::{Deserialize, Serialize};

use crate::{require_nonempty, PosyError, PosyResult, ValidatorId};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowAdmission {
    pub validator_id: ValidatorId,
    pub admitted_epoch: u64,
    pub earliest_activation_epoch: u64,
    pub authorization_root: String,
}

impl ShadowAdmission {
    /// Shadow admission is explicitly non-consensus authority.
    pub fn validate(&self, current_epoch: u64) -> PosyResult<()> {
        require_nonempty(&self.validator_id, "shadow validator id")?;
        require_nonempty(
            &self.authorization_root,
            "shadow admission authorization root",
        )?;
        if self.admitted_epoch <= current_epoch
            || self.earliest_activation_epoch <= self.admitted_epoch
        {
            return Err(PosyError::invalid(
                "shadow admission and activation must target ordered future epochs",
            ));
        }
        Ok(())
    }
}
