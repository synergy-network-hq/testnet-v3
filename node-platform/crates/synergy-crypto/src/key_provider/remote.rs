use crate::key_provider::ProviderError;

pub trait RemoteKmsClient: Send + Sync {
    fn sign(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, ProviderError>;
    fn public_key(&self, key_id: &str) -> Result<Vec<u8>, ProviderError>;
    fn attest(&self) -> Result<Vec<u8>, ProviderError>;
}
