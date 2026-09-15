//! Verification provider boundary with explicit context and key selection.

use crate::{PolicyError, Signature, SigningContext};

pub trait AegisVerifier: Send + Sync {
    fn verify(
        &self,
        context: &SigningContext,
        message: &[u8],
        signature: &Signature,
        public_key: &[u8],
    ) -> Result<(), VerificationError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationError {
    InvalidContext,
    InvalidPublicKey,
    InvalidSignature,
    Policy(PolicyError),
    Provider(String),
}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidContext => formatter.write_str("verification context is invalid"),
            Self::InvalidPublicKey => formatter.write_str("public key is invalid"),
            Self::InvalidSignature => formatter.write_str("signature is invalid"),
            Self::Policy(error) => write!(formatter, "Aegis policy refused verification: {error}"),
            Self::Provider(message) => {
                write!(formatter, "Aegis verification provider failed: {message}")
            }
        }
    }
}

impl std::error::Error for VerificationError {}
