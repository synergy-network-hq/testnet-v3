use crate::key_provider::ProviderError;

pub trait TpmClient: Send + Sync {
    fn quote(&self, nonce: &[u8]) -> Result<Vec<u8>, ProviderError>;
    fn sign(&self, handle: &str, message: &[u8]) -> Result<Vec<u8>, ProviderError>;
    fn public_key(&self, handle: &str) -> Result<Vec<u8>, ProviderError>;
}
