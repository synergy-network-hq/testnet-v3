//! Explicit algorithm and payload policy for Aegis operations.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureAlgorithm {
    MlDsa65,
    MlDsa87,
    FnDsa512,
    SphincsSha2128s,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AegisPolicy {
    pub allowed_algorithms: Vec<SignatureAlgorithm>,
    pub maximum_message_bytes: usize,
    pub maximum_signature_bytes: usize,
}

impl AegisPolicy {
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.allowed_algorithms.is_empty() {
            return Err(PolicyError::NoAllowedAlgorithms);
        }
        if self.maximum_message_bytes == 0 || self.maximum_signature_bytes == 0 {
            return Err(PolicyError::ZeroLimit);
        }
        Ok(())
    }

    pub fn authorize(
        &self,
        algorithm: SignatureAlgorithm,
        message_bytes: usize,
        signature_bytes: usize,
    ) -> Result<(), PolicyError> {
        self.validate()?;
        if !self.allowed_algorithms.contains(&algorithm) {
            return Err(PolicyError::AlgorithmDenied(algorithm));
        }
        if message_bytes > self.maximum_message_bytes {
            return Err(PolicyError::MessageTooLarge);
        }
        if signature_bytes > self.maximum_signature_bytes {
            return Err(PolicyError::SignatureTooLarge);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyError {
    NoAllowedAlgorithms,
    ZeroLimit,
    AlgorithmDenied(SignatureAlgorithm),
    MessageTooLarge,
    SignatureTooLarge,
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoAllowedAlgorithms => formatter.write_str("Aegis policy permits no algorithms"),
            Self::ZeroLimit => formatter.write_str("Aegis policy limits must be nonzero"),
            Self::AlgorithmDenied(algorithm) => {
                write!(formatter, "Aegis algorithm {algorithm:?} is not permitted")
            }
            Self::MessageTooLarge => formatter.write_str("message exceeds the Aegis policy limit"),
            Self::SignatureTooLarge => {
                formatter.write_str("signature exceeds the Aegis policy limit")
            }
        }
    }
}

impl std::error::Error for PolicyError {}
