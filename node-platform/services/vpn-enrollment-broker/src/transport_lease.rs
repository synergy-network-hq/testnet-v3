use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportLease {
    pub node_address: String,
    pub endpoint: String,
    pub generation: u64,
    pub expires_at: u64,
    pub signature: Vec<u8>,
}
impl TransportLease {
    pub fn validate(&self, now: u64) -> Result<(), String> {
        if self.node_address.is_empty()
            || self.endpoint.is_empty()
            || self.generation == 0
            || self.expires_at <= now
            || self.signature.is_empty()
        {
            Err("invalid transport lease".into())
        } else {
            Ok(())
        }
    }
}
