use serde::{Deserialize, Serialize};

use super::EnvelopeNonce;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AeadCiphertext {
    pub algorithm: String,
    pub nonce: EnvelopeNonce,
    pub ciphertext: Vec<u8>,
}

pub trait AeadProvider: Send + Sync {
    fn seal(
        &self,
        key: &[u8],
        nonce: &EnvelopeNonce,
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<AeadCiphertext, AeadError>;

    fn open(
        &self,
        key: &[u8],
        associated_data: &[u8],
        ciphertext: &AeadCiphertext,
    ) -> Result<Vec<u8>, AeadError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AeadError {
    InvalidKey,
    AuthenticationFailed,
    UnsupportedAlgorithm(String),
    Provider(String),
}

impl std::fmt::Display for AeadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "ETDAG AEAD failure: {self:?}")
    }
}

impl std::error::Error for AeadError {}
