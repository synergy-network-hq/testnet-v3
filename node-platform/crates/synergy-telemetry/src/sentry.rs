use crate::{TelemetryError, TelemetryRegistry};

pub fn record_forward(registry: &mut TelemetryRegistry) -> Result<(), TelemetryError> {
    registry.increment("sentry_forwarded_total")
}

pub fn record_drop(registry: &mut TelemetryRegistry) -> Result<(), TelemetryError> {
    registry.increment("sentry_dropped_total")
}

pub fn record_failover(registry: &mut TelemetryRegistry) -> Result<(), TelemetryError> {
    registry.increment("sentry_failovers_total")
}
