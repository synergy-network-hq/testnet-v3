use crate::{TelemetryError, TelemetryRegistry, TelemetrySnapshot};

pub trait MetricsRegistry {
    fn increment_counter(&mut self, name: &str) -> Result<(), TelemetryError>;
    fn add_counter(&mut self, name: &str, value: u64) -> Result<(), TelemetryError>;
    fn snapshot_metrics(&self) -> TelemetrySnapshot;
}

impl MetricsRegistry for TelemetryRegistry {
    fn increment_counter(&mut self, name: &str) -> Result<(), TelemetryError> {
        self.increment(name)
    }

    fn add_counter(&mut self, name: &str, value: u64) -> Result<(), TelemetryError> {
        self.add(name, value)
    }

    fn snapshot_metrics(&self) -> TelemetrySnapshot {
        self.snapshot()
    }
}
