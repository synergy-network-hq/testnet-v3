use sha3::{Digest, Sha3_256};

use crate::SnapshotValidationError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateChunk {
    pub index: u64,
    pub bytes: Vec<u8>,
    pub digest: String,
}

impl StateChunk {
    pub fn from_bytes(index: u64, bytes: Vec<u8>) -> Self {
        let digest = digest(index, &bytes);
        Self {
            index,
            bytes,
            digest,
        }
    }

    pub fn validate(&self) -> Result<(), SnapshotValidationError> {
        if self.bytes.is_empty() || self.digest != digest(self.index, &self.bytes) {
            return Err(SnapshotValidationError::InvalidChunk(self.index));
        }
        Ok(())
    }
}

pub(crate) fn digest(index: u64, bytes: &[u8]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(b"SYNERGY_STATE_SNAPSHOT_CHUNK_V1");
    hasher.update(index.to_be_bytes());
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}
