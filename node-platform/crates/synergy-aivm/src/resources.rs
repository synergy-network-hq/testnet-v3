use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceBudget {
    pub fuel: u64,
    pub memory_bytes: u64,
    pub output_bytes: u64,
    pub wall_time_ms: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub fuel: u64,
    pub peak_memory_bytes: u64,
    pub output_bytes: u64,
}
impl ResourceBudget {
    pub fn validate(self) -> Result<(), String> {
        if self.fuel == 0
            || self.memory_bytes == 0
            || self.output_bytes == 0
            || self.wall_time_ms == 0
        {
            return Err("AIVM resource budget must be nonzero".into());
        }
        Ok(())
    }
    pub fn accepts(self, u: ResourceUsage) -> bool {
        u.fuel <= self.fuel
            && u.peak_memory_bytes <= self.memory_bytes
            && u.output_bytes <= self.output_bytes
    }
}
