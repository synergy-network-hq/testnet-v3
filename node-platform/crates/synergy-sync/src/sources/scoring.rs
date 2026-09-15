#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceObservation {
    pub successful_verified_responses: u64,
    pub rejected_responses: u64,
    pub median_latency_millis: u64,
}

pub fn support_source_score(observation: SourceObservation) -> i128 {
    let success = i128::from(observation.successful_verified_responses).saturating_mul(1_000);
    let rejection = i128::from(observation.rejected_responses).saturating_mul(10_000);
    let latency = i128::from(observation.median_latency_millis.min(60_000));
    success.saturating_sub(rejection).saturating_sub(latency)
}
