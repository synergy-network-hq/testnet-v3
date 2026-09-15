//! Explicit health of a required service dependency.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyStatus {
    Healthy,
    Degraded,
    Unavailable,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyHealth {
    pub service: String,
    pub status: DependencyStatus,
    pub detail: String,
}

impl DependencyHealth {
    pub const fn blocks_readiness(&self) -> bool {
        matches!(
            self.status,
            DependencyStatus::Unavailable | DependencyStatus::Unknown
        )
    }
}
