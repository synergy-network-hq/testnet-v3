use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum EtdagOperation {
    PauseIngress,
    ResumeIngress,
    RecoverArtifact { artifact_id: String },
}

impl EtdagOperation {
    pub fn validate(&self) -> Result<(), crate::AdminError> {
        if let Self::RecoverArtifact { artifact_id } = self {
            if artifact_id.trim().is_empty() || artifact_id.len() > 256 {
                return Err(crate::AdminError::invalid_request(
                    "invalid ETDAG artifact ID",
                ));
            }
        }
        Ok(())
    }
}
