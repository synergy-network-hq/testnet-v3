use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SimplifiedEtdagTrafficMetrics {
    pub target_admission_unique_packages: u64,
    pub target_admission_broadcast_attempts: u64,
    pub target_admission_rebroadcasts: u64,
    pub target_admission_duplicate_suppressions: u64,
    pub target_admission_cache_entries: usize,
    pub p2p_outbound_queue_depth: usize,
    pub dcc_messages_sent: u64,
    pub dcc_messages_received: u64,
    pub bvc_messages_enqueued: u64,
    pub bvc_messages_sent: u64,
    pub bvc_messages_received: u64,
    pub boc_messages_enqueued: u64,
    pub boc_messages_sent: u64,
    pub boc_messages_received: u64,
    pub certified_protected_inputs_completed: u64,
}

static TARGET_ADMISSION_UNIQUE_PACKAGES: AtomicU64 = AtomicU64::new(0);
static TARGET_ADMISSION_BROADCAST_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static TARGET_ADMISSION_REBROADCASTS: AtomicU64 = AtomicU64::new(0);
static TARGET_ADMISSION_DUPLICATE_SUPPRESSIONS: AtomicU64 = AtomicU64::new(0);
static TARGET_ADMISSION_CACHE_ENTRIES: AtomicUsize = AtomicUsize::new(0);
static P2P_OUTBOUND_QUEUE_DEPTH: AtomicUsize = AtomicUsize::new(0);
static DCC_MESSAGES_SENT: AtomicU64 = AtomicU64::new(0);
static DCC_MESSAGES_RECEIVED: AtomicU64 = AtomicU64::new(0);
static BVC_MESSAGES_ENQUEUED: AtomicU64 = AtomicU64::new(0);
static BVC_MESSAGES_SENT: AtomicU64 = AtomicU64::new(0);
static BVC_MESSAGES_RECEIVED: AtomicU64 = AtomicU64::new(0);
static BOC_MESSAGES_ENQUEUED: AtomicU64 = AtomicU64::new(0);
static BOC_MESSAGES_SENT: AtomicU64 = AtomicU64::new(0);
static BOC_MESSAGES_RECEIVED: AtomicU64 = AtomicU64::new(0);
static CERTIFIED_PROTECTED_INPUTS_COMPLETED: AtomicU64 = AtomicU64::new(0);

pub fn record_target_admission_unique_package() {
    TARGET_ADMISSION_UNIQUE_PACKAGES.fetch_add(1, Ordering::Relaxed);
}

pub fn record_target_admission_broadcast_attempt(rebroadcast: bool) {
    TARGET_ADMISSION_BROADCAST_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
    if rebroadcast {
        TARGET_ADMISSION_REBROADCASTS.fetch_add(1, Ordering::Relaxed);
    }
}

pub fn record_target_admission_duplicate_suppression() {
    TARGET_ADMISSION_DUPLICATE_SUPPRESSIONS.fetch_add(1, Ordering::Relaxed);
}

pub fn set_target_admission_cache_entries(entries: usize) {
    TARGET_ADMISSION_CACHE_ENTRIES.store(entries, Ordering::Relaxed);
}

pub fn enter_p2p_outbound_queue() {
    P2P_OUTBOUND_QUEUE_DEPTH.fetch_add(1, Ordering::Relaxed);
}

pub fn leave_p2p_outbound_queue() {
    let _ = P2P_OUTBOUND_QUEUE_DEPTH.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |depth| {
        Some(depth.saturating_sub(1))
    });
}

pub fn record_empty_etdag_enqueued(message: &super::SimplifiedEmptyEtdagMessage) {
    match message {
        super::SimplifiedEmptyEtdagMessage::BvcCandidate { .. }
        | super::SimplifiedEmptyEtdagMessage::BvcVote { .. } => {
            BVC_MESSAGES_ENQUEUED.fetch_add(1, Ordering::Relaxed);
        }
        super::SimplifiedEmptyEtdagMessage::BocCandidate { .. }
        | super::SimplifiedEmptyEtdagMessage::BocVote { .. } => {
            BOC_MESSAGES_ENQUEUED.fetch_add(1, Ordering::Relaxed);
        }
        _ => {}
    }
}

pub fn record_empty_etdag_sent(message: &super::SimplifiedEmptyEtdagMessage) {
    match message {
        super::SimplifiedEmptyEtdagMessage::DccCandidate { .. }
        | super::SimplifiedEmptyEtdagMessage::DccVote { .. } => {
            DCC_MESSAGES_SENT.fetch_add(1, Ordering::Relaxed);
        }
        super::SimplifiedEmptyEtdagMessage::BvcCandidate { .. }
        | super::SimplifiedEmptyEtdagMessage::BvcVote { .. } => {
            BVC_MESSAGES_SENT.fetch_add(1, Ordering::Relaxed);
        }
        super::SimplifiedEmptyEtdagMessage::BocCandidate { .. }
        | super::SimplifiedEmptyEtdagMessage::BocVote { .. } => {
            BOC_MESSAGES_SENT.fetch_add(1, Ordering::Relaxed);
        }
        _ => {}
    }
}

pub fn record_empty_etdag_received(message: &super::SimplifiedEmptyEtdagMessage) {
    match message {
        super::SimplifiedEmptyEtdagMessage::DccCandidate { .. }
        | super::SimplifiedEmptyEtdagMessage::DccVote { .. } => {
            DCC_MESSAGES_RECEIVED.fetch_add(1, Ordering::Relaxed);
        }
        super::SimplifiedEmptyEtdagMessage::BvcCandidate { .. }
        | super::SimplifiedEmptyEtdagMessage::BvcVote { .. } => {
            BVC_MESSAGES_RECEIVED.fetch_add(1, Ordering::Relaxed);
        }
        super::SimplifiedEmptyEtdagMessage::BocCandidate { .. }
        | super::SimplifiedEmptyEtdagMessage::BocVote { .. } => {
            BOC_MESSAGES_RECEIVED.fetch_add(1, Ordering::Relaxed);
        }
        _ => {}
    }
}

pub fn record_certified_protected_input_completed() {
    CERTIFIED_PROTECTED_INPUTS_COMPLETED.fetch_add(1, Ordering::Relaxed);
}

pub fn simplified_etdag_traffic_metrics_snapshot() -> SimplifiedEtdagTrafficMetrics {
    SimplifiedEtdagTrafficMetrics {
        target_admission_unique_packages: TARGET_ADMISSION_UNIQUE_PACKAGES.load(Ordering::Relaxed),
        target_admission_broadcast_attempts: TARGET_ADMISSION_BROADCAST_ATTEMPTS
            .load(Ordering::Relaxed),
        target_admission_rebroadcasts: TARGET_ADMISSION_REBROADCASTS.load(Ordering::Relaxed),
        target_admission_duplicate_suppressions: TARGET_ADMISSION_DUPLICATE_SUPPRESSIONS
            .load(Ordering::Relaxed),
        target_admission_cache_entries: TARGET_ADMISSION_CACHE_ENTRIES.load(Ordering::Relaxed),
        p2p_outbound_queue_depth: P2P_OUTBOUND_QUEUE_DEPTH.load(Ordering::Relaxed),
        dcc_messages_sent: DCC_MESSAGES_SENT.load(Ordering::Relaxed),
        dcc_messages_received: DCC_MESSAGES_RECEIVED.load(Ordering::Relaxed),
        bvc_messages_enqueued: BVC_MESSAGES_ENQUEUED.load(Ordering::Relaxed),
        bvc_messages_sent: BVC_MESSAGES_SENT.load(Ordering::Relaxed),
        bvc_messages_received: BVC_MESSAGES_RECEIVED.load(Ordering::Relaxed),
        boc_messages_enqueued: BOC_MESSAGES_ENQUEUED.load(Ordering::Relaxed),
        boc_messages_sent: BOC_MESSAGES_SENT.load(Ordering::Relaxed),
        boc_messages_received: BOC_MESSAGES_RECEIVED.load(Ordering::Relaxed),
        certified_protected_inputs_completed: CERTIFIED_PROTECTED_INPUTS_COMPLETED
            .load(Ordering::Relaxed),
    }
}

pub const POSY_SIMPLIFIED_METRIC_SAMPLE_CAPACITY: usize = 4_096;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SimplifiedMetricKind {
    ProposalLatencyMicros,
    VotePropagationMicros,
    QuorumCertificateFormationMicros,
    ChainedFinalityMicros,
    TimeoutCertificateRecoveryMicros,
    LeaderTakeoverMicros,
    PqcVerificationMicros,
    CertificateSizeBytes,
    RestartRejoinMicros,
}

impl SimplifiedMetricKind {
    pub const fn name(self) -> &'static str {
        match self {
            Self::ProposalLatencyMicros => "posy_v3_proposal_latency_us",
            Self::VotePropagationMicros => "posy_v3_vote_propagation_us",
            Self::QuorumCertificateFormationMicros => "posy_v3_qc_formation_latency_us",
            Self::ChainedFinalityMicros => "posy_v3_chained_finality_latency_us",
            Self::TimeoutCertificateRecoveryMicros => "posy_v3_tc_recovery_latency_us",
            Self::LeaderTakeoverMicros => "posy_v3_leader_takeover_latency_us",
            Self::PqcVerificationMicros => "posy_v3_pqc_verification_us",
            Self::CertificateSizeBytes => "posy_v3_certificate_size_bytes",
            Self::RestartRejoinMicros => "posy_v3_restart_rejoin_time_us",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MetricSummary {
    pub name: String,
    pub count: u64,
    pub min: u64,
    pub max: u64,
    pub average: u64,
    pub p50: u64,
    pub p95: u64,
    pub p99: u64,
}

#[derive(Debug, Clone, Default)]
pub struct SimplifiedConsensusMetrics {
    samples: BTreeMap<SimplifiedMetricKind, Vec<u64>>,
}

impl SimplifiedConsensusMetrics {
    pub fn record_duration(&mut self, kind: SimplifiedMetricKind, duration: Duration) {
        let micros = duration.as_micros().min(u128::from(u64::MAX)) as u64;
        self.record_value(kind, micros);
    }

    pub fn record_value(&mut self, kind: SimplifiedMetricKind, value: u64) {
        let samples = self.samples.entry(kind).or_default();
        if samples.len() == POSY_SIMPLIFIED_METRIC_SAMPLE_CAPACITY {
            samples.remove(0);
        }
        samples.push(value);
    }

    pub fn summaries(&self) -> Vec<MetricSummary> {
        self.samples
            .iter()
            .filter_map(|(kind, samples)| summarize(*kind, samples))
            .collect()
    }
}

fn summarize(kind: SimplifiedMetricKind, samples: &[u64]) -> Option<MetricSummary> {
    if samples.is_empty() {
        return None;
    }
    let mut ordered = samples.to_vec();
    ordered.sort_unstable();
    let total = ordered
        .iter()
        .fold(0u128, |sum, value| sum.saturating_add(u128::from(*value)));
    Some(MetricSummary {
        name: kind.name().to_string(),
        count: ordered.len() as u64,
        min: ordered[0],
        max: ordered[ordered.len() - 1],
        average: (total / ordered.len() as u128).min(u128::from(u64::MAX)) as u64,
        p50: percentile(&ordered, 50),
        p95: percentile(&ordered, 95),
        p99: percentile(&ordered, 99),
    })
}

fn percentile(ordered: &[u64], percentile: usize) -> u64 {
    let rank = ordered.len().saturating_mul(percentile).saturating_add(99) / 100;
    ordered[rank.saturating_sub(1).min(ordered.len() - 1)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summaries_are_integer_bounded_and_deterministic() {
        let mut metrics = SimplifiedConsensusMetrics::default();
        for sample in 1..=100 {
            metrics.record_value(SimplifiedMetricKind::PqcVerificationMicros, sample);
        }
        let summary = &metrics.summaries()[0];
        assert_eq!(summary.average, 50);
        assert_eq!(summary.p50, 50);
        assert_eq!(summary.p95, 95);
        assert_eq!(summary.p99, 99);
    }
}
