#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrainReceipt {
    pub final_height: u64,
    pub outstanding_work: u64,
}

pub trait DrainCoordinator: Send + Sync {
    fn drain(&self) -> Result<DrainReceipt, String>;
}
