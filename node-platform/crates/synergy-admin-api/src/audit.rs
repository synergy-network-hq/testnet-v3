use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminAuditRecord {
    pub sequence: u64,
    pub timestamp_ms: u64,
    pub request_id: String,
    pub principal: String,
    pub operation: String,
    pub outcome: String,
    pub detail: String,
}

impl AdminAuditRecord {
    pub fn validate(&self) -> Result<(), crate::AdminError> {
        if self.sequence == 0
            || self.request_id.trim().is_empty()
            || self.principal.trim().is_empty()
            || self.operation.trim().is_empty()
            || self.outcome.trim().is_empty()
            || self.detail.len() > 4096
        {
            return Err(crate::AdminError::invalid_request(
                "invalid Admin API audit record",
            ));
        }
        Ok(())
    }
}

pub trait AdminAuditSink: Send + Sync {
    fn append(&self, record: &AdminAuditRecord) -> Result<(), crate::AdminError>;
}
