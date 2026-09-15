//! Error types for PQSynQ

use alloc::string::String;
use core::fmt;

/// Errors that can occur during PQC operations
#[derive(Debug, Clone, PartialEq)]
pub enum PqcError {
    /// Invalid key size
    InvalidKeySize,
    /// Invalid ciphertext size
    InvalidCiphertextSize,
    /// Invalid signature size
    InvalidSignatureSize,
    /// Invalid message size
    InvalidMessageSize,
    /// Key generation failed
    KeyGenerationFailed,
    /// Encryption/encapsulation failed
    EncryptionFailed,
    /// Decryption/decapsulation failed
    DecryptionFailed,
    /// Signature generation failed
    SignatureFailed,
    /// Signature verification failed
    VerificationFailed,
    /// Invalid algorithm
    InvalidAlgorithm,
    /// Buffer too small
    BufferTooSmall,
    /// Internal error
    InternalError,
    /// Cryptographic error with message
    CryptoError(String),
}

impl fmt::Display for PqcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PqcError::InvalidKeySize => write!(f, "Invalid key size"),
            PqcError::InvalidCiphertextSize => write!(f, "Invalid ciphertext size"),
            PqcError::InvalidSignatureSize => write!(f, "Invalid signature size"),
            PqcError::InvalidMessageSize => write!(f, "Invalid message size"),
            PqcError::KeyGenerationFailed => write!(f, "Key generation failed"),
            PqcError::EncryptionFailed => write!(f, "Encryption/encapsulation failed"),
            PqcError::DecryptionFailed => write!(f, "Decryption/decapsulation failed"),
            PqcError::SignatureFailed => write!(f, "Signature generation failed"),
            PqcError::VerificationFailed => write!(f, "Signature verification failed"),
            PqcError::InvalidAlgorithm => write!(f, "Invalid algorithm"),
            PqcError::BufferTooSmall => write!(f, "Buffer too small"),
            PqcError::InternalError => write!(f, "Internal error"),
            PqcError::CryptoError(msg) => write!(f, "Cryptographic error: {}", msg),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PqcError {}

/// SynQ-specific policy and verification errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AegisSynQError {
    UnsupportedAlgorithm,
    AlgorithmBelowSecurityLevel,
    UnsupportedPurpose,
    WrongChain,
    WrongNetwork,
    WrongDomain,
    MissingNonce,
    MissingExpiration,
    PayloadNotYetValid,
    ExpiredPayload,
    NonCanonicalPayload,
    PayloadHashMismatch,
    MalformedPublicKey,
    OversizedPublicKey,
    MalformedSignature,
    OversizedSignature,
    InvalidSignature,
    SignerAddressMismatch,
    InvalidNetwork,
}

impl AegisSynQError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedAlgorithm | Self::AlgorithmBelowSecurityLevel => "AEGIS-ALG",
            Self::UnsupportedPurpose => "AEGIS-PURPOSE",
            Self::WrongChain => "AEGIS-CHAIN",
            Self::WrongNetwork | Self::InvalidNetwork => "AEGIS-NETWORK",
            Self::WrongDomain => "AEGIS-DOMAIN",
            Self::MissingNonce => "AEGIS-NONCE",
            Self::MissingExpiration | Self::PayloadNotYetValid | Self::ExpiredPayload => {
                "AEGIS-EXPIRY"
            }
            Self::NonCanonicalPayload | Self::PayloadHashMismatch => "AEGIS-CANON",
            Self::MalformedPublicKey | Self::OversizedPublicKey => "AEGIS-KEY",
            Self::MalformedSignature | Self::OversizedSignature | Self::InvalidSignature => {
                "AEGIS-SIG"
            }
            Self::SignerAddressMismatch => "AEGIS-ADDRESS",
        }
    }
}

impl fmt::Display for AegisSynQError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UnsupportedAlgorithm => "unsupported algorithm",
            Self::AlgorithmBelowSecurityLevel => "algorithm below required security level",
            Self::UnsupportedPurpose => "unsupported signature purpose",
            Self::WrongChain => "wrong chain id",
            Self::WrongNetwork => "wrong network id",
            Self::WrongDomain => "wrong domain tag",
            Self::MissingNonce => "missing nonce",
            Self::MissingExpiration => "missing expiration",
            Self::PayloadNotYetValid => "payload is not yet valid",
            Self::ExpiredPayload => "expired payload",
            Self::NonCanonicalPayload => "non-canonical payload",
            Self::PayloadHashMismatch => "payload hash mismatch",
            Self::MalformedPublicKey => "malformed public key",
            Self::OversizedPublicKey => "oversized public key",
            Self::MalformedSignature => "malformed signature",
            Self::OversizedSignature => "oversized signature",
            Self::InvalidSignature => "invalid signature",
            Self::SignerAddressMismatch => "signer address mismatch",
            Self::InvalidNetwork => "invalid network id",
        };
        write!(f, "{}: {}", self.code(), message)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AegisSynQError {}
