//! Deterministic aggregation of health findings.

use crate::{HealthCheck, HealthSeverity, Readiness};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthReport {
    pub checks: Vec<HealthCheck>,
}

impl HealthReport {
    pub fn new(mut checks: Vec<HealthCheck>) -> Self {
        checks.sort_by(|left, right| {
            left.subsystem
                .cmp(&right.subsystem)
                .then(left.severity.cmp(&right.severity))
                .then(left.detail.cmp(&right.detail))
        });
        Self { checks }
    }

    pub fn readiness(&self) -> Readiness {
        if self
            .checks
            .iter()
            .any(|check| check.severity == HealthSeverity::Critical)
        {
            Readiness::NotReady
        } else {
            Readiness::Ready
        }
    }

    pub fn critical_findings(&self) -> Vec<&HealthCheck> {
        self.checks
            .iter()
            .filter(|check| check.severity == HealthSeverity::Critical)
            .collect()
    }

    pub fn diagnostic_summary(&self) -> String {
        self.checks
            .iter()
            .map(|check| format!("{}:{:?}:{}", check.subsystem, check.severity, check.detail))
            .collect::<Vec<_>>()
            .join("; ")
    }
}
