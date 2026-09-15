use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum CrossChainOperation {
    Pause,
    Resume,
    RetryPackage { package_id: String },
}

impl CrossChainOperation {
    pub fn validate(&self) -> Result<(), crate::AdminError> {
        if let Self::RetryPackage { package_id } = self {
            if package_id.trim().is_empty() {
                return Err(crate::AdminError::invalid_request(
                    "invalid cross-chain package ID",
                ));
            }
        }
        Ok(())
    }
}
