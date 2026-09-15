use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum StorageOperation {
    CreateSnapshot { finalized_height: u64 },
    Prune { retain_from_height: u64 },
    Verify,
}

impl StorageOperation {
    pub fn validate(&self) -> Result<(), crate::AdminError> {
        match self {
            Self::CreateSnapshot {
                finalized_height: 0,
            }
            | Self::Prune {
                retain_from_height: 0,
            } => Err(crate::AdminError::invalid_request(
                "storage height must be nonzero",
            )),
            _ => Ok(()),
        }
    }
}
