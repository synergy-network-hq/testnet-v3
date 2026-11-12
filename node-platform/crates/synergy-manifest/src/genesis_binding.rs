use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisBinding {
    pub genesis_hash: String,
}
impl GenesisBinding {
    pub fn validate(&self) -> Result<(), &'static str> {
        if crate::hash::hex64(&self.genesis_hash) {
            Ok(())
        } else {
            Err("invalid Genesis hash")
        }
    }
}
