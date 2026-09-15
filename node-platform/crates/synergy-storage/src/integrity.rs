use sha3::{Digest, Sha3_256};

use crate::StorageError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityDigest(pub String);

impl IntegrityDigest {
    pub fn of(domain: &str, bytes: &[u8]) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(domain.as_bytes());
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
        Self(format!("{:x}", hasher.finalize()))
    }

    pub fn verify(&self, domain: &str, bytes: &[u8]) -> Result<(), StorageError> {
        (self == &Self::of(domain, bytes))
            .then_some(())
            .ok_or(StorageError::IntegrityMismatch)
    }
}
