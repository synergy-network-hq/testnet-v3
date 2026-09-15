use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionPolicy {
    pub retain_from_height: u64,
    pub retain_through_height: u64,
    pub maximum_bytes: u64,
}
impl RetentionPolicy {
    pub fn validate(self) -> Result<(), String> {
        if self.retain_from_height == 0
            || self.retain_through_height < self.retain_from_height
            || self.maximum_bytes == 0
        {
            return Err("invalid data-availability retention policy".into());
        }
        Ok(())
    }
    pub fn retains(self, height: u64) -> bool {
        height >= self.retain_from_height && height <= self.retain_through_height
    }
}
