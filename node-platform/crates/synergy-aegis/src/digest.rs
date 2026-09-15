//! Canonical Aegis digest-provider boundary.
use sha3::{Digest, Sha3_256, Sha3_512};

pub trait AegisDigest: Send + Sync {
    fn digest(&self, domain: &[u8], message: &[u8]) -> Result<[u8; 32], DigestError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct AegisSha3_256;

impl AegisDigest for AegisSha3_256 {
    fn digest(&self, domain: &[u8], message: &[u8]) -> Result<[u8; 32], DigestError> {
        if domain.is_empty() || domain.len() > 1024 {
            return Err(DigestError::InvalidDomain);
        }
        let mut hasher = Sha3_256::new();
        hasher.update((domain.len() as u64).to_be_bytes());
        hasher.update(domain);
        hasher.update((message.len() as u64).to_be_bytes());
        hasher.update(message);
        Ok(hasher.finalize().into())
    }
}

/// Primitive hash provider for versioned protocols whose existing transcript
/// framing must remain byte-for-byte stable during caller migration.
pub trait AegisHashEngine: Send + Sync {
    fn sha3_256_segments(&self, segments: &[&[u8]]) -> Result<[u8; 32], DigestError>;
    fn sha3_512_segments(&self, segments: &[&[u8]]) -> Result<[u8; 64], DigestError>;
}

impl AegisHashEngine for AegisSha3_256 {
    fn sha3_256_segments(&self, segments: &[&[u8]]) -> Result<[u8; 32], DigestError> {
        let mut hasher = Sha3_256::new();
        for segment in segments {
            hasher.update(segment);
        }
        Ok(hasher.finalize().into())
    }

    fn sha3_512_segments(&self, segments: &[&[u8]]) -> Result<[u8; 64], DigestError> {
        let mut hasher = Sha3_512::new();
        for segment in segments {
            hasher.update(segment);
        }
        Ok(hasher.finalize().into())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestError {
    InvalidDomain,
    ProviderUnavailable,
}
