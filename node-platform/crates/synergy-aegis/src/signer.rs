//! Signing request boundary that never exports private key material.

use serde::{Deserialize, Serialize};

use crate::{KeyId, PolicyError, SignatureAlgorithm};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningContext {
    pub domain: String,
    pub chain_id: u64,
    pub epoch: Option<u64>,
    pub height: Option<u64>,
}

impl SigningContext {
    pub fn validate(&self) -> Result<(), SigningError> {
        if self.domain.is_empty() || self.domain.len() > 128 || self.chain_id == 0 {
            return Err(SigningError::InvalidContext);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub algorithm: SignatureAlgorithm,
    pub key_id: KeyId,
    pub bytes: Vec<u8>,
}

pub trait AegisSigner: Send + Sync {
    fn sign(
        &self,
        key_id: &KeyId,
        context: &SigningContext,
        message: &[u8],
    ) -> Result<Signature, SigningError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningError {
    InvalidContext,
    KeyUnavailable,
    KeyNotActive,
    Policy(PolicyError),
    Provider(String),
}

impl std::fmt::Display for SigningError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidContext => formatter.write_str("signing context is invalid"),
            Self::KeyUnavailable => formatter.write_str("signing key is unavailable"),
            Self::KeyNotActive => formatter.write_str("signing key is not active"),
            Self::Policy(error) => write!(formatter, "Aegis policy refused signing: {error}"),
            Self::Provider(message) => {
                write!(formatter, "Aegis signing provider failed: {message}")
            }
        }
    }
}

impl std::error::Error for SigningError {}

impl<T: AegisSigner + ?Sized> AegisSigner for std::sync::Arc<T> {
    fn sign(
        &self,
        key_id: &KeyId,
        context: &SigningContext,
        message: &[u8],
    ) -> Result<Signature, SigningError> {
        (**self).sign(key_id, context, message)
    }
}
