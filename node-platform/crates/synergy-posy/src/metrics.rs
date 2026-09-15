use std::sync::atomic::{AtomicU64, Ordering};

/// Observability counters only; metrics never influence PoSy decisions.
#[derive(Debug, Default)]
pub struct PosyMetrics {
    proposals_received: AtomicU64,
    votes_received: AtomicU64,
    quorum_certificates_verified: AtomicU64,
    finalized_blocks: AtomicU64,
    rejected_messages: AtomicU64,
}

impl PosyMetrics {
    pub fn record_proposal(&self) {
        self.proposals_received.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_vote(&self) {
        self.votes_received.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_verified_qc(&self) {
        self.quorum_certificates_verified
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_finality(&self) {
        self.finalized_blocks.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_rejection(&self) {
        self.rejected_messages.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> PosyMetricsSnapshot {
        PosyMetricsSnapshot {
            proposals_received: self.proposals_received.load(Ordering::Relaxed),
            votes_received: self.votes_received.load(Ordering::Relaxed),
            quorum_certificates_verified: self.quorum_certificates_verified.load(Ordering::Relaxed),
            finalized_blocks: self.finalized_blocks.load(Ordering::Relaxed),
            rejected_messages: self.rejected_messages.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PosyMetricsSnapshot {
    pub proposals_received: u64,
    pub votes_received: u64,
    pub quorum_certificates_verified: u64,
    pub finalized_blocks: u64,
    pub rejected_messages: u64,
}
