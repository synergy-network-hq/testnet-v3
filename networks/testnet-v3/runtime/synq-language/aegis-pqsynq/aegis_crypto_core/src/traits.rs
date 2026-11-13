//! Trait definitions for unified algorithm interfaces.

use zeroize::Zeroize;

/// Key Encapsulation Mechanism trait.
pub trait Kem: Algorithm {
    type PublicKey: AsRef<[u8]> + Clone;
    type SecretKey: AsRef<[u8]> + Clone + Zeroize;
    type Ciphertext: AsRef<[u8]> + Clone;
    type SharedSecret: AsRef<[u8]> + Clone + Zeroize;

    /// Generate a new key pair.
    fn keygen() -> Result<(Self::PublicKey, Self::SecretKey), KemError>;

    /// Encapsulate a shared secret using the public key.
    fn encapsulate(
        public_key: &Self::PublicKey,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), KemError>;

    /// Decapsulate a shared secret using the secret key and ciphertext.
    fn decapsulate(
        secret_key: &Self::SecretKey,
        ciphertext: &[u8],
    ) -> Result<Self::SharedSecret, KemError>;
}

/// Digital Signature trait.
pub trait Signature: Algorithm {
    type PublicKey: AsRef<[u8]> + Clone;
    type SecretKey: AsRef<[u8]> + Clone + Zeroize;
    type Signature: AsRef<[u8]> + Clone;

    /// Generate a new key pair.
    fn keygen() -> Result<(Self::PublicKey, Self::SecretKey), SignatureError>;

    /// Sign a message using the secret key.
    fn sign(
        secret_key: &Self::SecretKey,
        message: &[u8],
    ) -> Result<Self::Signature, SignatureError>;

    /// Verify a signature using the public key and message.
    fn verify(
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, SignatureError>;
}

/// Base algorithm trait.
pub trait Algorithm {
    /// Get the name of the algorithm.
    fn name() -> &'static str;

    /// Get the security level in bits.
    fn security_level() -> usize;
}

/// KEM-specific error type.
#[derive(Debug, Clone)]
pub enum KemError {
    InvalidKey,
    InvalidCiphertext,
    EncapsulationFailed,
    DecapsulationFailed,
    InternalError,
}

impl std::fmt::Display for KemError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KemError::InvalidKey => write!(f, "Invalid key"),
            KemError::InvalidCiphertext => write!(f, "Invalid ciphertext"),
            KemError::EncapsulationFailed => write!(f, "Encapsulation failed"),
            KemError::DecapsulationFailed => write!(f, "Decapsulation failed"),
            KemError::InternalError => write!(f, "Internal error"),
        }
    }
}

impl std::error::Error for KemError {}

/// Signature-specific error type.
#[derive(Debug, Clone)]
pub enum SignatureError {
    InvalidKey,
    InvalidSignature,
    SigningFailed,
    VerificationFailed,
    InternalError,
}

impl std::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignatureError::InvalidKey => write!(f, "Invalid key"),
            SignatureError::InvalidSignature => write!(f, "Invalid signature"),
            SignatureError::SigningFailed => write!(f, "Signing failed"),
            SignatureError::VerificationFailed => write!(f, "Verification failed"),
            SignatureError::InternalError => write!(f, "Internal error"),
        }
    }
}

impl std::error::Error for SignatureError {}
