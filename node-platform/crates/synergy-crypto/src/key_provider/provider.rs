use synergy_aegis::{Signature, SigningContext};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderKeyReference {
    pub provider: String,
    pub key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderError {
    InvalidReference,
    Unavailable,
    PermissionDenied,
    InvalidMaterial,
    OperationFailed(String),
}

pub trait KeyProvider: Send + Sync {
    fn sign(
        &self,
        key: &ProviderKeyReference,
        context: &SigningContext,
        message: &[u8],
    ) -> Result<Signature, ProviderError>;

    fn public_key(&self, key: &ProviderKeyReference) -> Result<Vec<u8>, ProviderError>;

    fn health(&self) -> Result<(), ProviderError>;
}
