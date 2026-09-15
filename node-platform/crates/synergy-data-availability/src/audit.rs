use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvailabilityAudit {
    pub sequence: u64,
    pub object_root: String,
    pub shard_index: u32,
    pub action: String,
    pub outcome: String,
    pub timestamp_ms: u64,
}
impl AvailabilityAudit {
    pub fn validate(&self) -> Result<(), String> {
        if self.sequence == 0
            || self.object_root.trim().is_empty()
            || self.action.trim().is_empty()
            || self.outcome.trim().is_empty()
            || self.timestamp_ms == 0
        {
            return Err("invalid availability audit record".into());
        }
        Ok(())
    }
}
