#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskBudget {
    pub capacity: u64,
    pub used: u64,
}
impl DiskBudget {
    pub fn write(&mut self, bytes: u64) -> Result<(), String> {
        if bytes > self.capacity.saturating_sub(self.used) {
            return Err("simulated disk full".into());
        }
        self.used += bytes;
        Ok(())
    }
}
