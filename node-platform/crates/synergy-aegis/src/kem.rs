//! Aegis-owned post-quantum KEM boundary and PQVM implementation.
use aegis_pqvm::pqc::kem::mlkem::mlkem768;
use pqrust_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};

pub trait AegisKem: Send + Sync {
    fn algorithm(&self) -> &'static str;
    fn encapsulate(&self, public_key: &[u8]) -> Result<KemEncapsulation, KemError>;
    fn decapsulate(&self, ciphertext: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, KemError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KemEncapsulation {
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PqvmMlKem768;

impl AegisKem for PqvmMlKem768 {
    fn algorithm(&self) -> &'static str {
        "ML-KEM-768"
    }

    fn encapsulate(&self, public_key: &[u8]) -> Result<KemEncapsulation, KemError> {
        let public_key =
            mlkem768::PublicKey::from_bytes(public_key).map_err(|_| KemError::InvalidPublicKey)?;
        let (shared_secret, ciphertext) = mlkem768::encapsulate(&public_key);
        Ok(KemEncapsulation {
            ciphertext: ciphertext.as_bytes().to_vec(),
            shared_secret: shared_secret.as_bytes().to_vec(),
        })
    }

    fn decapsulate(&self, ciphertext: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, KemError> {
        let ciphertext = mlkem768::Ciphertext::from_bytes(ciphertext)
            .map_err(|_| KemError::InvalidCiphertext)?;
        let secret_key =
            mlkem768::SecretKey::from_bytes(secret_key).map_err(|_| KemError::InvalidSecretKey)?;
        Ok(mlkem768::decapsulate(&ciphertext, &secret_key)
            .as_bytes()
            .to_vec())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KemError {
    InvalidPublicKey,
    InvalidSecretKey,
    InvalidCiphertext,
    ProviderUnavailable,
}
