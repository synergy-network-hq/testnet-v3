use serde::{Deserialize, Serialize};
use synergy_posy::{is_hash, ValidatorId};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorHealthObservation {
    pub validator_id: ValidatorId,
    pub observed_height: u64,
    pub consecutive_failures: u32,
    pub evidence_root: String,
}

impl ValidatorHealthObservation {
    /// Health is operational evidence only and never changes frozen PoSy
    /// membership or voting weight by itself.
    pub fn validate(&self) -> Result<(), String> {
        if self.validator_id.trim().is_empty() || !is_hash(&self.evidence_root) {
            return Err("invalid validator health observation".into());
        }
        Ok(())
    }
}
