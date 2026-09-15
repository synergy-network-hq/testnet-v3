use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleAction {
    Start,
    Stop,
    Restart,
    Drain,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleOperation {
    pub action: LifecycleAction,
    pub timeout_ms: u64,
}

impl LifecycleOperation {
    pub fn validate(&self) -> Result<(), crate::AdminError> {
        if self.timeout_ms == 0 || self.timeout_ms > 300_000 {
            return Err(crate::AdminError::invalid_request(
                "lifecycle timeout must be within 1..=300000 ms",
            ));
        }
        Ok(())
    }
}
