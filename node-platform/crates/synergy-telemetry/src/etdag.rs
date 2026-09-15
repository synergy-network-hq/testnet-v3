use crate::{TelemetryError, TelemetryRegistry};

pub fn record_admission(
    registry: &mut TelemetryRegistry,
    accepted: bool,
) -> Result<(), TelemetryError> {
    registry.increment(if accepted {
        "etdag_admissions_total"
    } else {
        "etdag_rejections_total"
    })
}

pub fn record_reveal(registry: &mut TelemetryRegistry) -> Result<(), TelemetryError> {
    registry.increment("etdag_reveals_total")
}

pub fn record_recovery(registry: &mut TelemetryRegistry) -> Result<(), TelemetryError> {
    registry.increment("etdag_recovery_requests_total")
}
