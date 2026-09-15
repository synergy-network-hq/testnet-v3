use serde::{Deserialize, Serialize};

use crate::supervisor::ShutdownReport;

/// Final lifecycle result after supervisor shutdown completes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShutdownOutcome {
    pub drained: bool,
    pub services: ShutdownReport,
}

impl ShutdownOutcome {
    pub fn clean(&self) -> bool {
        self.drained && self.services.clean()
    }
}
