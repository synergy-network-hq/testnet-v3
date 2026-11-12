use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootseedRecord {
    pub node_address: String,
    pub endpoints: Vec<String>,
    pub expires_at: u64,
    pub generation: u64,
    pub signature: Vec<u8>,
}
impl BootseedRecord {
    pub fn signing_bytes(&self) -> Vec<u8> {
        format!(
            "bootseed/v1|{}|{}|{}|{}",
            self.node_address,
            self.endpoints.join(","),
            self.expires_at,
            self.generation
        )
        .into_bytes()
    }
    pub fn validate_shape(&self) -> Result<(), &'static str> {
        if self.node_address.trim().is_empty()
            || self.endpoints.is_empty()
            || self.endpoints.iter().any(|e| e.trim().is_empty())
            || self.expires_at == 0
            || self.generation == 0
            || self.signature.is_empty()
        {
            Err("invalid bootseed record")
        } else {
            Ok(())
        }
    }
}
