use serde::{Deserialize, Serialize};

use crate::{is_hash, require_nonempty, PosyError, PosyResult, ValidatorId};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingDecision {
    pub validator_id: ValidatorId,
    pub evidence_root: String,
    pub penalty_units: u128,
    pub effective_epoch: u64,
    pub authorization_root: String,
}

impl SlashingDecision {
    /// Slashing is an accountability/economic record only. It contributes no
    /// voting weight and cannot create PoSy authority or finality.
    pub fn validate(&self, current_epoch: u64) -> PosyResult<()> {
        require_nonempty(&self.validator_id, "slashed validator id")?;
        require_nonempty(&self.authorization_root, "slashing authorization root")?;
        if !is_hash(&self.evidence_root)
            || self.penalty_units == 0
            || self.effective_epoch <= current_epoch
        {
            return Err(PosyError::invalid(
                "invalid slashing evidence, penalty, or effective epoch",
            ));
        }
        Ok(())
    }
}
