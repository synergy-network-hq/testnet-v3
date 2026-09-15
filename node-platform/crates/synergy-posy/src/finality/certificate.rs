use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalizedBlockRecord {
    pub height: u64,
    pub block_id: String,
    pub finality_certificate_id: String,
    pub protected_execution_root: String,
}
