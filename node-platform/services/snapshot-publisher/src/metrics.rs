#[derive(Debug, Default, Clone, Copy)]
pub struct PublisherMetrics {
    pub published: u64,
    pub rejected: u64,
    pub retained: u64,
}
