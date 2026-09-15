use crate::valid;
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderReputation {
    pub provider_id: String,
    pub successes: u64,
    pub failures: u64,
    pub evidence_root: String,
}
impl ProviderReputation {
    pub fn validate(&self) -> Result<(), String> {
        if !valid(&self.provider_id)
            || !valid(&self.evidence_root)
            || self.successes.saturating_add(self.failures) == 0
        {
            return Err("invalid reputation".into());
        }
        Ok(())
    }
}
