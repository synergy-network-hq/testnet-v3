use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KemEncapsulation {
    pub algorithm: String,
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

pub trait KemProvider: Send + Sync {
    fn encapsulate(&self, algorithm: &str, public_key: &[u8])
        -> Result<KemEncapsulation, KemError>;

    fn decapsulate(
        &self,
        key_id: &str,
        algorithm: &str,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, KemError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KemError {
    InvalidPublicKey,
    InvalidCiphertext,
    KeyUnavailable(String),
    UnsupportedAlgorithm(String),
    Provider(String),
}

impl std::fmt::Display for KemError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "ETDAG KEM failure: {self:?}")
    }
}

impl std::error::Error for KemError {}
