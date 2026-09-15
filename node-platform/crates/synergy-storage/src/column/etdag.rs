use super::StorageColumn;

#[derive(Debug, Clone, Copy, Default)]
pub struct EtdagColumn;

impl StorageColumn for EtdagColumn {
    const NAME: &'static str = "etdag";
}
