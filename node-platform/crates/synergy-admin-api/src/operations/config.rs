use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ConfigOperation {
    Validate { path: String },
    Reload { path: String },
}

impl ConfigOperation {
    pub fn validate(&self) -> Result<(), crate::AdminError> {
        let path = match self {
            Self::Validate { path } | Self::Reload { path } => path,
        };
        if !std::path::Path::new(path).is_absolute() {
            return Err(crate::AdminError::invalid_request(
                "configuration path must be absolute",
            ));
        }
        Ok(())
    }
}
