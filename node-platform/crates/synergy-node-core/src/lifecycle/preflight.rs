use serde::{Deserialize, Serialize};

use crate::DiagnosticCheck;

/// Complete preflight decision made before any node service starts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreflightReport {
    pub checks: Vec<DiagnosticCheck>,
}

impl PreflightReport {
    pub fn passed(&self) -> bool {
        !self.checks.iter().any(|check| check.state.is_blocking())
    }

    pub fn blocking_check_ids(&self) -> Vec<&str> {
        self.checks
            .iter()
            .filter(|check| check.state.is_blocking())
            .map(|check| check.id.as_str())
            .collect()
    }
}
