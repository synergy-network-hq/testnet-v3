#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrashState {
    pub persisted_height: u64,
    pub volatile_height: u64,
}
impl CrashState {
    pub fn crash(&mut self) {
        self.volatile_height = self.persisted_height;
    }
    pub fn persist(&mut self, height: u64) -> Result<(), String> {
        if height < self.persisted_height {
            return Err("persistence regression".into());
        }
        self.persisted_height = height;
        self.volatile_height = height;
        Ok(())
    }
}
