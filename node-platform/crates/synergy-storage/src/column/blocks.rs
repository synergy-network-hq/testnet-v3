use super::StorageColumn;

#[derive(Debug, Clone, Copy, Default)]
pub struct BlocksColumn;

impl StorageColumn for BlocksColumn {
    const NAME: &'static str = "blocks";
}
