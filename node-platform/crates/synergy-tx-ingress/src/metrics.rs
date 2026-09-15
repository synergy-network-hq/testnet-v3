#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct IngressMetrics {
    pub admitted: u64,
    pub rejected_capacity: u64,
    pub rejected_duplicate: u64,
    pub rejected_invalid: u64,
}
