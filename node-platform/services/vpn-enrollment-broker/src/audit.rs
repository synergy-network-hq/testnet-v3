use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub timestamp: u64,
    pub operation: String,
    pub node_address: String,
    pub outcome: String,
}
