//! Stable, authority-neutral types shared by node management clients.
//!
//! This crate deliberately contains no consensus voting, validator weighting,
//! or transport authority. PoSy authority remains Genesis-bound and runtime
//! owned; management only observes and asks the runtime to perform safe work.

use serde::{Deserialize, Serialize};

pub const MANAGEMENT_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeLifecycleState {
    Uninitialized,
    Configured,
    Starting,
    Shadowing,
    Ready,
    Active,
    Stopping,
    Stopped,
    Degraded,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagementOperation {
    NodeStatus,
    Health,
    Readiness,
    Diagnostics,
    ConfigurationValidation,
    RoleInspection,
    CapabilityDiscovery,
}

impl ManagementOperation {
    pub const ALL: [Self; 7] = [
        Self::NodeStatus,
        Self::Health,
        Self::Readiness,
        Self::Diagnostics,
        Self::ConfigurationValidation,
        Self::RoleInspection,
        Self::CapabilityDiscovery,
    ];

    pub fn is_read_only(self) -> bool {
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckState {
    Pass,
    Warn,
    Fail,
    Unknown,
}

impl CheckState {
    pub fn is_blocking(self) -> bool {
        matches!(self, Self::Fail)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticCheck {
    pub id: String,
    pub subsystem: String,
    pub severity: CheckSeverity,
    pub state: CheckState,
    pub summary: String,
    pub remediation: Option<String>,
}

impl DiagnosticCheck {
    pub fn passed(
        id: impl Into<String>,
        subsystem: impl Into<String>,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            subsystem: subsystem.into(),
            severity: CheckSeverity::Info,
            state: CheckState::Pass,
            summary: summary.into(),
            remediation: None,
        }
    }

    pub fn warning(
        id: impl Into<String>,
        subsystem: impl Into<String>,
        summary: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            subsystem: subsystem.into(),
            severity: CheckSeverity::Warning,
            state: CheckState::Warn,
            summary: summary.into(),
            remediation: Some(remediation.into()),
        }
    }

    pub fn failed(
        id: impl Into<String>,
        subsystem: impl Into<String>,
        summary: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            subsystem: subsystem.into(),
            severity: CheckSeverity::Error,
            state: CheckState::Fail,
            summary: summary.into(),
            remediation: Some(remediation.into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessReport {
    pub ready: bool,
    pub lifecycle: NodeLifecycleState,
    pub blocking_checks: Vec<String>,
    pub checks: Vec<DiagnosticCheck>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn management_surface_is_read_only_until_a_mutating_operation_is_implemented() {
        assert!(ManagementOperation::ALL
            .into_iter()
            .all(ManagementOperation::is_read_only));
    }

    #[test]
    fn only_failed_checks_block_readiness() {
        assert!(CheckState::Fail.is_blocking());
        assert!(!CheckState::Warn.is_blocking());
    }
}
