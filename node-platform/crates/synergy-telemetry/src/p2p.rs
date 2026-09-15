use crate::{TelemetryError, TelemetryRegistry};

pub fn record_frame(
    registry: &mut TelemetryRegistry,
    accepted: bool,
) -> Result<(), TelemetryError> {
    registry.increment(if accepted {
        "p2p_frames_accepted_total"
    } else {
        "p2p_frames_rejected_total"
    })
}

pub fn record_reconnect(registry: &mut TelemetryRegistry) -> Result<(), TelemetryError> {
    registry.increment("p2p_reconnects_total")
}
