use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdatePhase {
    Discovered,
    Verified,
    Staged,
    Drained,
    Installed,
    Healthy,
    RolledBack,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Succeeded,
    Failed { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEvent {
    pub sequence: u64,
    pub release_id: String,
    pub phase: UpdatePhase,
    pub outcome: AuditOutcome,
    pub timestamp_unix_seconds: u64,
}

pub trait AuditSink: Send + Sync {
    fn record(&self, event: &AuditEvent) -> Result<(), String>;
}
