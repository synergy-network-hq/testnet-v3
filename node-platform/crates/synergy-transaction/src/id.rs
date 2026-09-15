use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::{TransactionError, UnsignedTransaction};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TransactionId(pub String);

impl TransactionId {
    pub fn from_unsigned(transaction: &UnsignedTransaction) -> Result<Self, TransactionError> {
        transaction.validate_structure()?;
        let bytes = transaction.signing_bytes()?;
        let mut hasher = Sha3_256::new();
        hasher.update(b"SYNERGY_TRANSACTION_ID_V1");
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
        Ok(Self(hex(&hasher.finalize())))
    }

    pub fn validate(&self) -> Result<(), TransactionError> {
        if self.0.len() != 64
            || self
                .0
                .bytes()
                .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
        {
            return Err(TransactionError::InvalidTransactionId);
        }
        Ok(())
    }
}

pub(crate) fn hex(bytes: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = bytes.as_ref();
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}
