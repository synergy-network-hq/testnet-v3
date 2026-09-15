//! Custody-provider bridge. Operations refer to key IDs, never raw secrets.

use crate::{KeyId, KeyPurpose, SignatureAlgorithm};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderHealth {
    Healthy,
    Degraded(String),
    Unavailable(String),
}

pub trait KmsBridge: Send + Sync {
    fn provider_id(&self) -> &str;
    fn health(&self) -> ProviderHealth;
    fn generate_key(
        &self,
        purpose: KeyPurpose,
        algorithm: SignatureAlgorithm,
    ) -> Result<KeyId, KmsError>;
    fn public_key(&self, key_id: &KeyId) -> Result<Vec<u8>, KmsError>;
    fn destroy_key(&self, key_id: &KeyId) -> Result<(), KmsError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KmsError {
    Unavailable(String),
    Unauthorized,
    NotFound(KeyId),
    Provider(String),
}

impl std::fmt::Display for KmsError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(message) => write!(formatter, "key provider unavailable: {message}"),
            Self::Unauthorized => formatter.write_str("key provider operation is unauthorized"),
            Self::NotFound(key) => write!(formatter, "key {} was not found", key.as_str()),
            Self::Provider(message) => write!(formatter, "key provider failed: {message}"),
        }
    }
}

impl std::error::Error for KmsError {}
