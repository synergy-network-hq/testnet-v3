use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EnvelopeNonce([u8; 12]);

impl EnvelopeNonce {
    pub const LENGTH: usize = 12;

    pub fn new(bytes: [u8; Self::LENGTH]) -> Result<Self, NonceError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(NonceError::AllZero);
        }
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceError {
    AllZero,
}

impl std::fmt::Display for NonceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ETDAG envelope nonce must not be all zero")
    }
}

impl std::error::Error for NonceError {}
