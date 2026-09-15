use serde::{Deserialize, Serialize};

use crate::supervisor::ServiceId;

/// Cause that prevents a node from remaining ready or active.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum DegradedReason {
    ServiceUnhealthy {
        service: ServiceId,
        reason: String,
    },
    SynchronizationLost {
        local: u64,
        verified_target: u64,
    },
    StoragePressure {
        available_bytes: u64,
        required_bytes: u64,
    },
    NetworkIsolation {
        authenticated_peers: usize,
        required_peers: usize,
    },
    AuthorityUnavailable {
        reason: String,
    },
}

/// Current degradation plus whether the role must fail closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DegradedCondition {
    pub reason: DegradedReason,
    pub blocks_authoritative_work: bool,
}
