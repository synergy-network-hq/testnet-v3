#[derive(Debug, Default, Clone, Copy)]
pub struct RegistryMetrics {
    pub accepted: u64,
    pub rejected: u64,
    pub expired: u64,
}
