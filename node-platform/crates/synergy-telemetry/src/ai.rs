use crate::{TelemetryError, TelemetryRegistry};

pub fn record_workload_started(registry: &mut TelemetryRegistry) -> Result<(), TelemetryError> {
    registry.increment("ai_workloads_started_total")
}

pub fn record_workload_completed(
    registry: &mut TelemetryRegistry,
    accepted: bool,
) -> Result<(), TelemetryError> {
    registry.increment(if accepted {
        "ai_workloads_completed_total"
    } else {
        "ai_workloads_failed_total"
    })
}
