#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TelemetryReadiness {
    Ready,
    NotReady(String),
}

pub fn evaluate(exporter_configured: bool, exporter_running: bool) -> TelemetryReadiness {
    if !exporter_configured || exporter_running {
        TelemetryReadiness::Ready
    } else {
        TelemetryReadiness::NotReady("configured telemetry exporter is not running".into())
    }
}
