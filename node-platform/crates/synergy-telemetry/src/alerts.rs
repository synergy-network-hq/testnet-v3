use crate::TelemetrySnapshot;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlertSeverity {
    Warning,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetryAlert {
    pub severity: AlertSeverity,
    pub subsystem: String,
    pub detail: String,
}

pub fn evaluate(snapshot: &TelemetrySnapshot) -> Vec<TelemetryAlert> {
    let mut alerts = Vec::new();
    if snapshot
        .counters
        .get("node_service_failures_total")
        .copied()
        .unwrap_or(0)
        > 0
    {
        alerts.push(TelemetryAlert {
            severity: AlertSeverity::Critical,
            subsystem: "node".into(),
            detail: "one or more supervised services failed".into(),
        });
    }
    if snapshot
        .counters
        .get("posy_safety_refusals_total")
        .copied()
        .unwrap_or(0)
        > 0
    {
        alerts.push(TelemetryAlert {
            severity: AlertSeverity::Warning,
            subsystem: "posy".into(),
            detail: "PoSy safety refusal recorded".into(),
        });
    }
    alerts
}
