use crate::{TelemetryError, TelemetryRegistry};

pub fn record_proposal(registry: &mut TelemetryRegistry) -> Result<(), TelemetryError> {
    registry.increment("posy_proposals_total")
}

pub fn record_vote(registry: &mut TelemetryRegistry) -> Result<(), TelemetryError> {
    registry.increment("posy_votes_total")
}

pub fn record_finality(registry: &mut TelemetryRegistry) -> Result<(), TelemetryError> {
    registry.increment("posy_finalized_total")
}

pub fn record_safety_refusal(registry: &mut TelemetryRegistry) -> Result<(), TelemetryError> {
    registry.increment("posy_safety_refusals_total")
}
