use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum IdentityOperation {
    Rotate { next_key_id: String },
    Retire { key_id: String },
}

impl IdentityOperation {
    pub fn validate(&self) -> Result<(), crate::AdminError> {
        let key_id = match self {
            Self::Rotate { next_key_id } => next_key_id,
            Self::Retire { key_id } => key_id,
        };
        if key_id.trim().is_empty() || key_id.len() > 256 {
            return Err(crate::AdminError::invalid_request(
                "invalid identity key ID",
            ));
        }
        Ok(())
    }
}
