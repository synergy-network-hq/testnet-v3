#[derive(Debug, Default, Clone, Copy)]
pub struct VirtualClock {
    now_ms: u64,
}
impl VirtualClock {
    pub fn now_ms(&self) -> u64 {
        self.now_ms
    }
    pub fn advance(&mut self, delta: u64) -> Result<u64, String> {
        self.now_ms = self
            .now_ms
            .checked_add(delta)
            .ok_or_else(|| "virtual clock overflow".to_string())?;
        Ok(self.now_ms)
    }
}
