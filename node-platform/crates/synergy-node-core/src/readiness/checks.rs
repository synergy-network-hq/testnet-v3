use serde::{Deserialize, Serialize};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_failed_checks_block_readiness() {
        assert!(CheckState::Fail.is_blocking());
        assert!(!CheckState::Warn.is_blocking());
    }
}
