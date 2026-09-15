use super::StorageColumn;

#[derive(Debug, Clone, Copy, Default)]
pub struct MetadataColumn;

impl StorageColumn for MetadataColumn {
    const NAME: &'static str = "metadata";
}
