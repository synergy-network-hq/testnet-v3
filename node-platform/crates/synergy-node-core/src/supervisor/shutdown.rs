use serde::{Deserialize, Serialize};

use super::ServiceId;

/// Exact result of a reverse-dependency-order shutdown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShutdownReport {
    pub stopped: Vec<ServiceId>,
    pub failed: Vec<(ServiceId, String)>,
}

impl ShutdownReport {
    pub fn clean(&self) -> bool {
        self.failed.is_empty()
    }
}
