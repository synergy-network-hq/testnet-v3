use serde::{Deserialize, Serialize};
use synergy_crypto::{sha3_256, AegisDigest, CryptoDomain, Hash32};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotChunk {
    pub index: u64,
    pub hash: Hash32,
    pub bytes: Vec<u8>,
}

impl SnapshotChunk {
    pub fn new(
        provider: &impl AegisDigest,
        domain: &CryptoDomain,
        index: u64,
        bytes: Vec<u8>,
    ) -> Result<Self, String> {
        if bytes.is_empty() {
            return Err("snapshot chunk is empty".into());
        }
        let mut transcript = index.to_be_bytes().to_vec();
        transcript.extend_from_slice(&bytes);
        let hash = sha3_256(provider, domain, &transcript)?;
        Ok(Self { index, hash, bytes })
    }

    pub fn verify(&self, provider: &impl AegisDigest, domain: &CryptoDomain) -> Result<(), String> {
        let expected = Self::new(provider, domain, self.index, self.bytes.clone())?;
        if expected.hash != self.hash {
            return Err("snapshot chunk hash mismatch".into());
        }
        Ok(())
    }
}
