use super::StorageColumn;

#[derive(Debug, Clone, Copy, Default)]
pub struct PeersColumn;

impl StorageColumn for PeersColumn {
    const NAME: &'static str = "peers";
}
