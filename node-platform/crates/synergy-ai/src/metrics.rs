#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AiMetrics {
    pub admitted: u64,
    pub completed: u64,
    pub failed: u64,
    pub rejected: u64,
}
impl AiMetrics {
    pub fn admit(&mut self) {
        self.admitted = self.admitted.saturating_add(1)
    }
    pub fn reject(&mut self) {
        self.rejected = self.rejected.saturating_add(1)
    }
}
