//! Secret-free audit events for Aegis operations.

use serde::{Deserialize, Serialize};

use crate::{KeyId, SignatureAlgorithm};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOperation {
    Generate,
    Activate,
    Sign,
    Verify,
    Retire,
    Revoke,
    Attest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Succeeded,
    Refused,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp_unix_millis: u64,
    pub operation: AuditOperation,
    pub outcome: AuditOutcome,
    pub key_id: Option<KeyId>,
    pub algorithm: Option<SignatureAlgorithm>,
    pub context_commitment: Option<[u8; 32]>,
    pub error_code: Option<String>,
}

pub trait AuditSink: Send + Sync {
    fn record(&self, event: &AuditEvent) -> Result<(), String>;
}
