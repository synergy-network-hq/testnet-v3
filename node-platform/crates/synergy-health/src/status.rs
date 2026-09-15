//! One structured subsystem health finding.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HealthSeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthCheck {
    pub subsystem: String,
    pub severity: HealthSeverity,
    pub detail: String,
}

impl HealthCheck {
    pub fn new(
        subsystem: impl Into<String>,
        severity: HealthSeverity,
        detail: impl Into<String>,
    ) -> Result<Self, &'static str> {
        let subsystem = subsystem.into();
        let detail = detail.into();
        if subsystem.trim().is_empty() {
            return Err("health-check subsystem must not be empty");
        }
        if detail.trim().is_empty() {
            return Err("health-check detail must not be empty");
        }
        Ok(Self {
            subsystem,
            severity,
            detail,
        })
    }
}
