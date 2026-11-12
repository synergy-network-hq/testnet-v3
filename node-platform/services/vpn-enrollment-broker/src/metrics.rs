#[derive(Debug, Default, Clone, Copy)]
pub struct BrokerMetrics {
    pub accepted: u64,
    pub rejected: u64,
    pub replayed: u64,
    pub revoked: u64,
}
