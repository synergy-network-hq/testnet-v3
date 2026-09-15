use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PosyOperation {
    DrainSigning,
    ResumeSigning { recovery_reference: String },
}

impl PosyOperation {
    pub fn validate(&self) -> Result<(), crate::AdminError> {
        if let Self::ResumeSigning { recovery_reference } = self {
            if recovery_reference.trim().is_empty() {
                return Err(crate::AdminError::invalid_request(
                    "PoSy resume requires recovery evidence",
                ));
            }
        }
        Ok(())
    }
}
