use serde::{Deserialize, Serialize};

use crate::DiagnosticCheck;

/// Durable storage evidence required before authoritative work begins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageReadiness {
    pub opened: bool,
    pub integrity_verified: bool,
    pub writable: bool,
    pub available_bytes: u64,
    pub required_bytes: u64,
}

impl StorageReadiness {
    pub fn check(self) -> DiagnosticCheck {
        if self.opened
            && self.integrity_verified
            && self.writable
            && self.available_bytes >= self.required_bytes
        {
            DiagnosticCheck::passed("storage.durable", "storage", "durable storage is ready")
        } else {
            DiagnosticCheck::failed(
                "storage.durable",
                "storage",
                "durable storage is not ready",
                "restore integrity, writability, and configured free-space headroom",
            )
        }
    }
}
