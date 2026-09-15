use serde::{Deserialize, Serialize};

use crate::bounded;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceAuditRecord {
    pub sequence: u64,
    pub proposal_root: String,
    pub operation: String,
    pub outcome: String,
    pub evidence_root: String,
    pub timestamp_ms: u64,
}

impl GovernanceAuditRecord {
    pub fn validate(&self) -> Result<(), String> {
        if self.sequence == 0
            || !bounded(&self.proposal_root, 256)
            || !bounded(&self.operation, 128)
            || !bounded(&self.outcome, 128)
            || !bounded(&self.evidence_root, 256)
            || self.timestamp_ms == 0
        {
            return Err("invalid governance audit record".into());
        }
        Ok(())
    }
}

pub trait GovernanceAuditSink {
    fn append(&self, record: &GovernanceAuditRecord) -> Result<(), String>;
}
