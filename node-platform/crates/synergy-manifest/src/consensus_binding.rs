use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusBinding {
    pub protocol: String,
    pub authority_root: String,
    pub activation_epoch: u64,
}
impl ConsensusBinding {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.protocol.trim().is_empty()
            || !crate::hash::hex64(&self.authority_root)
            || self.activation_epoch == 0
        {
            Err("invalid consensus binding")
        } else {
            Ok(())
        }
    }
}
