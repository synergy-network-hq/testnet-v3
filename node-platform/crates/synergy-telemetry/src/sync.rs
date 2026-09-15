use crate::{TelemetryError, TelemetryRegistry};

pub fn record_import(registry: &mut TelemetryRegistry) -> Result<(), TelemetryError> {
    registry.increment("sync_imported_blocks_total")
}

pub fn record_failover(registry: &mut TelemetryRegistry) -> Result<(), TelemetryError> {
    registry.increment("sync_failovers_total")
}
