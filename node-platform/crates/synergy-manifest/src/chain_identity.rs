use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainIdentityBinding {
    pub chain_id: u64,
    pub network_id: String,
}
impl ChainIdentityBinding {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.chain_id == 0 || self.network_id.trim().is_empty() {
            Err("invalid chain identity")
        } else {
            Ok(())
        }
    }
}
