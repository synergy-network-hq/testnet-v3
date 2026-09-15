//! Typed health, readiness, liveness, dependency, and stall diagnostics.

mod checks;
mod dependency;
mod liveness;
mod readiness;
mod stall;
mod status;

pub use checks::HealthReport;
pub use dependency::{DependencyHealth, DependencyStatus};
pub use liveness::Liveness;
pub use readiness::Readiness;
pub use stall::{ProgressSample, StallAssessment, StallPolicy};
pub use status::{HealthCheck, HealthSeverity};
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_critical_findings_block_readiness() {
        let r = HealthReport::new(vec![HealthCheck {
            subsystem: "p2p".into(),
            severity: HealthSeverity::Warning,
            detail: "one peer slow".into(),
        }]);
        assert_eq!(r.readiness(), Readiness::Ready);
        let r = HealthReport::new(vec![HealthCheck {
            subsystem: "sync".into(),
            severity: HealthSeverity::Critical,
            detail: "behind verified head".into(),
        }]);
        assert_eq!(r.readiness(), Readiness::NotReady);
    }
    #[test]
    fn diagnostics_preserve_actionable_subsystem_context() {
        let r = HealthReport::new(vec![HealthCheck {
            subsystem: "posy".into(),
            severity: HealthSeverity::Critical,
            detail: "missing recovery state".into(),
        }]);
        assert!(r.diagnostic_summary().contains("posy"));
        assert!(r.diagnostic_summary().contains("missing recovery state"));
    }
}
