use crate::TelemetrySnapshot;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetryHealth {
    pub series: usize,
    pub ready: bool,
    pub detail: String,
}

pub fn assess(snapshot: &TelemetrySnapshot, max_series: usize) -> TelemetryHealth {
    let ready = max_series > 0 && snapshot.counters.len() <= max_series;
    TelemetryHealth {
        series: snapshot.counters.len(),
        ready,
        detail: if ready {
            "telemetry registry within configured bounds".into()
        } else {
            "telemetry registry exceeds configured bounds".into()
        },
    }
}
