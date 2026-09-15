use serde::{Deserialize, Serialize};
use synergy_posy::{is_hash, KeyId, ValidatorId};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorApplication {
    pub validator_id: ValidatorId,
    pub consensus_key_id: KeyId,
    pub operator_identity: String,
    pub target_epoch: u64,
    pub authorization_root: String,
}

impl ValidatorApplication {
    pub fn validate(&self, current_epoch: u64) -> Result<(), String> {
        if self.validator_id.trim().is_empty()
            || self.consensus_key_id.trim().is_empty()
            || self.operator_identity.trim().is_empty()
            || self.operator_identity.len() > 256
            || !is_hash(&self.authorization_root)
            || self.target_epoch <= current_epoch
        {
            return Err("invalid validator application".into());
        }
        Ok(())
    }
}
