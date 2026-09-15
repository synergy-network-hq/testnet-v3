use serde::{Deserialize, Serialize};

use sha3::{Digest, Sha3_256};

use crate::{id::hex, TransactionId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Applied,
    Reverted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionReceipt {
    pub transaction_id: TransactionId,
    pub status: ReceiptStatus,
    pub gas_used: u64,
    pub state_root_after: String,
    pub error_code: Option<String>,
}

impl TransactionReceipt {
    pub fn validate(&self) -> bool {
        self.transaction_id.validate().is_ok()
            && !self.state_root_after.trim().is_empty()
            && match self.status {
                ReceiptStatus::Applied => self.error_code.is_none(),
                ReceiptStatus::Reverted => self
                    .error_code
                    .as_deref()
                    .is_some_and(|code| !code.is_empty()),
            }
    }

    pub fn commitment(&self) -> Option<String> {
        self.validate().then(|| {
            let mut hasher = Sha3_256::new();
            hasher.update(b"SYNERGY_TRANSACTION_RECEIPT_V1");
            hasher.update(self.transaction_id.0.as_bytes());
            hasher.update([match self.status {
                ReceiptStatus::Applied => 0,
                ReceiptStatus::Reverted => 1,
            }]);
            hasher.update(self.gas_used.to_be_bytes());
            hasher.update((self.state_root_after.len() as u64).to_be_bytes());
            hasher.update(self.state_root_after.as_bytes());
            if let Some(error) = &self.error_code {
                hasher.update((error.len() as u64).to_be_bytes());
                hasher.update(error.as_bytes());
            } else {
                hasher.update(0_u64.to_be_bytes());
            }
            hex(hasher.finalize())
        })
    }
}
