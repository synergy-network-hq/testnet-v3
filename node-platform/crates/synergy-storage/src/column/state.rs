use super::StorageColumn;

#[derive(Debug, Clone, Copy, Default)]
pub struct StateColumn;

impl StorageColumn for StateColumn {
    const NAME: &'static str = "state";
}
