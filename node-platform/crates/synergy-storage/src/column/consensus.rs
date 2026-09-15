use super::StorageColumn;

#[derive(Debug, Clone, Copy, Default)]
pub struct ConsensusColumn;

impl StorageColumn for ConsensusColumn {
    const NAME: &'static str = "consensus";
}
