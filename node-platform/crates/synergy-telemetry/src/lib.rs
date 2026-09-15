//! Bounded in-process telemetry counters for structured node diagnostics.

use std::collections::BTreeMap;

pub mod ai;
pub mod alerts;
pub mod consensus;
pub mod cross_chain;
pub mod etdag;
pub mod health;
pub mod metrics;
pub mod p2p;
pub mod prometheus;
pub mod readiness;
pub mod registry;
pub mod sentry;
pub mod storage;
pub mod structured_log;
pub mod sync;
pub mod tracing;
pub mod vpn;
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TelemetrySnapshot {
    pub counters: BTreeMap<String, u64>,
}
#[derive(Debug, Default)]
pub struct TelemetryRegistry {
    counters: BTreeMap<String, u64>,
    max_series: usize,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetryError {
    SeriesLimit,
    InvalidKey,
}
impl TelemetryRegistry {
    pub fn new(max_series: usize) -> Self {
        assert!(max_series > 0);
        Self {
            counters: BTreeMap::new(),
            max_series,
        }
    }
    pub fn increment(&mut self, key: &str) -> Result<(), TelemetryError> {
        validate_key(key)?;
        if !self.counters.contains_key(key) && self.counters.len() >= self.max_series {
            return Err(TelemetryError::SeriesLimit);
        }
        let counter = self.counters.entry(key.into()).or_default();
        *counter = counter.saturating_add(1);
        Ok(())
    }
    pub fn add(&mut self, key: &str, value: u64) -> Result<(), TelemetryError> {
        validate_key(key)?;
        if !self.counters.contains_key(key) && self.counters.len() >= self.max_series {
            return Err(TelemetryError::SeriesLimit);
        }
        *self.counters.entry(key.into()).or_default() = self
            .counters
            .get(key)
            .copied()
            .unwrap_or(0)
            .saturating_add(value);
        Ok(())
    }
    pub fn snapshot(&self) -> TelemetrySnapshot {
        TelemetrySnapshot {
            counters: self.counters.clone(),
        }
    }
}

fn validate_key(key: &str) -> Result<(), TelemetryError> {
    if key.is_empty()
        || key.len() > 128
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(TelemetryError::InvalidKey);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_series_prevent_telemetry_cardinality_growth() {
        let mut t = TelemetryRegistry::new(1);
        t.increment("p2p_router_rejected").unwrap();
        assert_eq!(
            t.increment("unbounded_peer_label"),
            Err(TelemetryError::SeriesLimit)
        );
        assert_eq!(t.snapshot().counters["p2p_router_rejected"], 1);
    }
    #[test]
    fn counters_are_monotonic() {
        let mut t = TelemetryRegistry::new(2);
        t.add("sync_failover", 2).unwrap();
        t.increment("sync_failover").unwrap();
        assert_eq!(t.snapshot().counters["sync_failover"], 3);
    }
}
