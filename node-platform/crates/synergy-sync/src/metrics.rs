use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct SyncMetrics {
    verified_blocks: AtomicU64,
    verified_chunks: AtomicU64,
    source_failovers: AtomicU64,
    rejected_responses: AtomicU64,
}

impl SyncMetrics {
    pub fn record_verified_blocks(&self, count: u64) {
        self.verified_blocks.fetch_add(count, Ordering::Relaxed);
    }
    pub fn record_verified_chunks(&self, count: u64) {
        self.verified_chunks.fetch_add(count, Ordering::Relaxed);
    }
    pub fn record_failover(&self) {
        self.source_failovers.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_rejection(&self) {
        self.rejected_responses.fetch_add(1, Ordering::Relaxed);
    }
    pub fn snapshot(&self) -> SyncMetricsSnapshot {
        SyncMetricsSnapshot {
            verified_blocks: self.verified_blocks.load(Ordering::Relaxed),
            verified_chunks: self.verified_chunks.load(Ordering::Relaxed),
            source_failovers: self.source_failovers.load(Ordering::Relaxed),
            rejected_responses: self.rejected_responses.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncMetricsSnapshot {
    pub verified_blocks: u64,
    pub verified_chunks: u64,
    pub source_failovers: u64,
    pub rejected_responses: u64,
}
