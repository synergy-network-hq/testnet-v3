use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum SentryOperation {
    DrainPublic,
    ResumePublic,
    ReconnectValidator { validator_id: String },
}

impl SentryOperation {
    pub fn validate(&self) -> Result<(), crate::AdminError> {
        if let Self::ReconnectValidator { validator_id } = self {
            if validator_id.trim().is_empty() {
                return Err(crate::AdminError::invalid_request(
                    "invalid validator identity",
                ));
            }
        }
        Ok(())
    }
}
