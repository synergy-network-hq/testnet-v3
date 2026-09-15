use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedEnvelope {
    pub envelope_id: String,
    pub target_height: u64,
    pub ciphertext: Vec<u8>,
    pub content_blind_order_key: String,
}
