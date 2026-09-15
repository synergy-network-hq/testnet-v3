use crate::{TelemetryError, TelemetryRegistry};

pub fn record_write(registry: &mut TelemetryRegistry, bytes: u64) -> Result<(), TelemetryError> {
    registry.add("storage_bytes_written_total", bytes)
}

pub fn record_failure(registry: &mut TelemetryRegistry) -> Result<(), TelemetryError> {
    registry.increment("storage_failures_total")
}
