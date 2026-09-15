use crate::{TelemetryError, TelemetryRegistry};

pub fn record_relay(registry: &mut TelemetryRegistry) -> Result<(), TelemetryError> {
    registry.increment("cross_chain_relays_total")
}

pub fn record_verification(
    registry: &mut TelemetryRegistry,
    accepted: bool,
) -> Result<(), TelemetryError> {
    registry.increment(if accepted {
        "cross_chain_verified_total"
    } else {
        "cross_chain_rejected_total"
    })
}
