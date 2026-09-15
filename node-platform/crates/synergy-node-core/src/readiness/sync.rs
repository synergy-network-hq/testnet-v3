use serde::{Deserialize, Serialize};

use crate::DiagnosticCheck;

/// Synchronization evidence derived from verified finality rather than advertisements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncReadiness {
    pub local_finalized_height: u64,
    pub verified_target_height: u64,
    pub finality_evidence_verified: bool,
    pub import_idle: bool,
}

impl SyncReadiness {
    pub fn check(self) -> DiagnosticCheck {
        if self.finality_evidence_verified
            && self.import_idle
            && self.local_finalized_height >= self.verified_target_height
        {
            DiagnosticCheck::passed(
                "sync.finalized_head",
                "sync",
                "local finalized state matches the verified target",
            )
        } else {
            DiagnosticCheck::failed(
                "sync.finalized_head",
                "sync",
                "local finalized state is not synchronized",
                "complete verified block/state import before enabling authoritative work",
            )
        }
    }
}
