use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum AiOperation {
    PauseWorkloads,
    ResumeWorkloads,
    CancelWorkload { workload_id: String },
}

impl AiOperation {
    pub fn validate(&self) -> Result<(), crate::AdminError> {
        if let Self::CancelWorkload { workload_id } = self {
            if workload_id.trim().is_empty() {
                return Err(crate::AdminError::invalid_request("invalid AI workload ID"));
            }
        }
        Ok(())
    }
}
