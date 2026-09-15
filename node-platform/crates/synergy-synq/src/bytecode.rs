use sha3::{Digest, Sha3_256};

use crate::SynqError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SynqArtifact {
    pub bytes: Vec<u8>,
    pub code_hash: String,
}

impl SynqArtifact {
    pub fn new(bytes: Vec<u8>) -> Result<Self, SynqError> {
        if bytes.is_empty() {
            return Err(SynqError::EmptyArtifact);
        }
        let code_hash = hash(&bytes);
        Ok(Self { bytes, code_hash })
    }

    pub fn validate(&self) -> Result<(), SynqError> {
        (!self.bytes.is_empty() && self.code_hash == hash(&self.bytes))
            .then_some(())
            .ok_or(SynqError::ArtifactHashMismatch)
    }
}

pub(crate) fn hash(bytes: &[u8]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(b"SYNERGY_SYNQ_ARTIFACT_V1");
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}
