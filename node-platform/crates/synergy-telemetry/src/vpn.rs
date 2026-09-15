use crate::{TelemetryError, TelemetryRegistry};

pub fn record_reconnect(registry: &mut TelemetryRegistry) -> Result<(), TelemetryError> {
    registry.increment("vpn_reconnects_total")
}

pub fn record_lease_failure(registry: &mut TelemetryRegistry) -> Result<(), TelemetryError> {
    registry.increment("vpn_lease_failures_total")
}
