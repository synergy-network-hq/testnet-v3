use serde::{Deserialize, Serialize};
use synergy_crypto::{sha3_256_segments, AegisSha3_256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataShard {
    pub object_root: String,
    pub index: u32,
    pub total: u32,
    pub payload: Vec<u8>,
    pub payload_root: String,
}

impl DataShard {
    pub fn validate(&self, maximum: usize) -> Result<(), String> {
        if self.object_root.trim().is_empty()
            || self.index >= self.total
            || self.total == 0
            || self.payload.is_empty()
            || self.payload.len() > maximum
            || self.payload_root != root(&self.payload)?
        {
            return Err("invalid availability shard".into());
        }
        Ok(())
    }
}

pub fn root(bytes: &[u8]) -> Result<String, String> {
    let length = (bytes.len() as u64).to_be_bytes();
    let root = sha3_256_segments(&AegisSha3_256, &[b"SYNERGY_DA_SHARD_V1", &length, bytes])?;
    Ok(root.0.iter().map(|byte| format!("{byte:02x}")).collect())
}
