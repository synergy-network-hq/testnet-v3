use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum UpgradeOperation {
    Stage {
        release_id: String,
        metadata_path: String,
        artifact_path: String,
    },
    Apply {
        release_id: String,
    },
    Rollback {
        release_id: String,
    },
}

impl UpgradeOperation {
    pub fn validate(&self) -> Result<(), crate::AdminError> {
        let release_id = match self {
            Self::Stage {
                release_id,
                metadata_path,
                artifact_path,
            } => {
                if !std::path::Path::new(metadata_path).is_absolute()
                    || !std::path::Path::new(artifact_path).is_absolute()
                {
                    return Err(crate::AdminError::invalid_request(
                        "upgrade metadata and artifact paths must be absolute",
                    ));
                }
                release_id
            }
            Self::Apply { release_id } | Self::Rollback { release_id } => release_id,
        };
        if release_id.trim().is_empty() || release_id.len() > 256 {
            return Err(crate::AdminError::invalid_request("invalid release ID"));
        }
        Ok(())
    }
}
