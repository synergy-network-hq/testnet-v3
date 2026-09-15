//! Canonical cross-component transaction reference.

use serde::{Deserialize, Serialize};

use crate::ProtocolHash;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionReference {
    pub transaction_hash: ProtocolHash,
    pub nonce: u64,
}

impl TransactionReference {
    pub fn new(
        transaction_hash: ProtocolHash,
        nonce: u64,
    ) -> Result<Self, TransactionReferenceError> {
        if transaction_hash.is_zero() {
            return Err(TransactionReferenceError::ZeroHash);
        }
        Ok(Self {
            transaction_hash,
            nonce,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionReferenceError {
    ZeroHash,
}

impl std::fmt::Display for TransactionReferenceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("transaction hash must be nonzero")
    }
}

impl std::error::Error for TransactionReferenceError {}
