use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum TelemetryOperation {
    Snapshot,
    SetFilter { filter: String },
}

impl TelemetryOperation {
    pub fn validate(&self) -> Result<(), crate::AdminError> {
        if let Self::SetFilter { filter } = self {
            if filter.trim().is_empty() || filter.len() > 1024 {
                return Err(crate::AdminError::invalid_request(
                    "invalid telemetry filter",
                ));
            }
        }
        Ok(())
    }
}
