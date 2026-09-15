#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SentryMetrics {
    pub public_connections: usize,
    pub validator_links: usize,
    pub forwarded_frames: u64,
    pub denied_frames: u64,
    pub overloaded_frames: u64,
    pub failovers: u64,
}

impl SentryMetrics {
    pub fn record_forwarded(&mut self) {
        self.forwarded_frames = self.forwarded_frames.saturating_add(1);
    }

    pub fn record_denied(&mut self) {
        self.denied_frames = self.denied_frames.saturating_add(1);
    }

    pub fn record_overloaded(&mut self) {
        self.overloaded_frames = self.overloaded_frames.saturating_add(1);
    }

    pub fn record_failover(&mut self) {
        self.failovers = self.failovers.saturating_add(1);
    }
}
