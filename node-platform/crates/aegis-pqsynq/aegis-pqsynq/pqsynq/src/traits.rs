//! Common traits for PQC algorithms

use crate::error::PqcError;
use alloc::vec::Vec;

/// Trait for Key Encapsulation Mechanisms (KEM)
pub trait KeyEncapsulation {
    /// Generate a key pair
    fn keygen(&self) -> Result<(Vec<u8>, Vec<u8>), PqcError>;

    /// Encapsulate a shared secret
    fn encapsulate(&self, public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), PqcError>;

    /// Decapsulate a shared secret
    fn decapsulate(&self, ciphertext: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, PqcError>;

    /// Get the public key size in bytes
    fn public_key_size(&self) -> usize;

    /// Get the secret key size in bytes
    fn secret_key_size(&self) -> usize;

    /// Get the ciphertext size in bytes
    fn ciphertext_size(&self) -> usize;

    /// Get the shared secret size in bytes
    fn shared_secret_size(&self) -> usize;
}

/// Trait for Digital Signature Schemes
pub trait DigitalSignature {
    /// Generate a key pair
    fn keygen(&self) -> Result<(Vec<u8>, Vec<u8>), PqcError>;

    /// Sign a message
    fn sign(&self, message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, PqcError>;

    /// Verify a signature
    fn verify(&self, message: &[u8], signature: &[u8], public_key: &[u8])
        -> Result<bool, PqcError>;

    /// Get the public key size in bytes
    fn public_key_size(&self) -> usize;

    /// Get the secret key size in bytes
    fn secret_key_size(&self) -> usize;

    /// Get the signature size in bytes
    fn signature_size(&self) -> usize;
}

/// Trait for algorithms that support detached signatures
pub trait DetachedSignature: DigitalSignature {
    /// Create a detached signature
    fn detached_sign(&self, message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, PqcError>;

    /// Verify a detached signature
    fn verify_detached(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool, PqcError>;
}

/// Trait for algorithms that support context-based operations
pub trait Contextual {
    /// Sign with context
    fn sign_ctx(
        &self,
        message: &[u8],
        secret_key: &[u8],
        context: &[u8],
    ) -> Result<Vec<u8>, PqcError>;

    /// Verify with context
    fn verify_ctx(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
        context: &[u8],
    ) -> Result<bool, PqcError>;
}
