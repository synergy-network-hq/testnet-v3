use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportBinding {
    pub registry_generation: u64,
    pub registry_hash: String,
}
impl TransportBinding {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.registry_generation > 0 && crate::hash::hex64(&self.registry_hash) {
            Ok(())
        } else {
            Err("invalid transport binding")
        }
    }
}
