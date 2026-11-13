use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Duration;

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
