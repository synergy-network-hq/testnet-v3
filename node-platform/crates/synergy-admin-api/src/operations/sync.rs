use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum SyncOperation {
    Pause,
    Resume,
    RetrySource { peer_id: String },
}

impl SyncOperation {
    pub fn validate(&self) -> Result<(), crate::AdminError> {
        if let Self::RetrySource { peer_id } = self {
            if peer_id.trim().is_empty() {
                return Err(crate::AdminError::invalid_request("invalid sync source"));
            }
        }
        Ok(())
    }
}
