#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AeadError {
    InvalidKey,
    InvalidNonce,
    PayloadTooLarge,
    AuthenticationFailed,
    Provider(String),
}

pub trait Aes256GcmProvider: Send + Sync {
    fn seal(
        &self,
        key_reference: &str,
        nonce: &[u8; 12],
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, AeadError>;

    fn open(
        &self,
        key_reference: &str,
        nonce: &[u8; 12],
        associated_data: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, AeadError>;
}
