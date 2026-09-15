use serde::{Deserialize, Serialize};

use crate::{CheckState, DiagnosticCheck, NodeLifecycleState};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessReport {
    pub ready: bool,
    pub lifecycle: NodeLifecycleState,
    pub blocking_checks: Vec<String>,
    pub checks: Vec<DiagnosticCheck>,
}

impl ReadinessReport {
    pub fn evaluate(lifecycle: NodeLifecycleState, checks: Vec<DiagnosticCheck>) -> Self {
        let blocking_checks = checks
            .iter()
            .filter(|check| matches!(check.state, CheckState::Fail | CheckState::Unknown))
            .map(|check| check.id.clone())
            .collect::<Vec<_>>();
        let lifecycle_ready = matches!(
            lifecycle,
            NodeLifecycleState::Ready | NodeLifecycleState::Active
        );
        Self {
            ready: lifecycle_ready && blocking_checks.is_empty(),
            lifecycle,
            blocking_checks,
            checks,
        }
    }
}
