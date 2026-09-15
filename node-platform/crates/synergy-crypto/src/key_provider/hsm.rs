use crate::key_provider::ProviderError;

pub trait HsmClient: Send + Sync {
    fn sign(&self, slot: &str, message: &[u8]) -> Result<Vec<u8>, ProviderError>;
    fn public_key(&self, slot: &str) -> Result<Vec<u8>, ProviderError>;
    fn health(&self) -> Result<(), ProviderError>;
}
