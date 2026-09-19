#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackReceipt {
    pub restored_release_id: String,
}

pub trait RollbackCoordinator: Send + Sync {
    fn rollback(&self, install: &crate::InstallReceipt) -> Result<RollbackReceipt, String>;
}
