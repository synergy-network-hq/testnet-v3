//! Compact execution-owned observations, committed atomically with finalized state.
//! These are not standalone inclusion proofs and confer no consensus authority.
use serde::{Deserialize, Serialize};
/// Storage projection only; execution's existing receipt remains the authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalizedReceiptStatus {
    Applied,
    Reverted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizedPublicReceipt {
    pub transaction_id: String,
    pub status: FinalizedReceiptStatus,
    pub gas_used: u64,
    pub state_root_after: String,
    pub error_code: Option<String>,
}
use crate::{FinalizedState, StateError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizedReceiptEntry {
    pub sender: String,
    pub receiver: String,
    pub amount_nwei: u128,
    pub nonce: u64,
    pub gas_limit: u64,
    pub max_fee_per_gas_nwei: u64,
    pub receipt: FinalizedPublicReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizedReceiptBatch {
    pub schema_version: u32,
    pub finalized: FinalizedState,
    pub protected_execution_root: String,
    pub finality_certificate_id: String,
    pub transactions: Vec<FinalizedReceiptEntry>,
}

impl FinalizedReceiptBatch {
    pub(crate) fn validate(&self, next: &FinalizedState) -> Result<(), StateError> {
        let hash = |s: &str| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if self.schema_version != 1
            || &self.finalized != next
            || next.finalized_height == 0
            || !hash(&next.finalized_block_id)
            || !hash(&next.state_root)
            || !hash(&self.protected_execution_root)
            || !hash(&self.finality_certificate_id)
            || self.transactions.is_empty()
            || self.transactions.iter().any(|row| {
                row.gas_limit == 0
                    || row.max_fee_per_gas_nwei == 0
                    || row
                        .gas_limit
                        .checked_mul(row.max_fee_per_gas_nwei)
                        .is_none()
                    || !hash(&row.receipt.transaction_id)
                    || match row.receipt.status {
                        FinalizedReceiptStatus::Applied => row.receipt.error_code.is_some(),
                        FinalizedReceiptStatus::Reverted => {
                            row.receipt.error_code.as_ref().is_none_or(|v| v.is_empty())
                        }
                    }
                    || !hash(&row.receipt.state_root_after)
                    || [&row.sender, &row.receiver].iter().any(|v| {
                        v.is_empty()
                            || v.len() > 256
                            || !v.bytes().all(|b| b.is_ascii_alphanumeric())
                    })
            })
        {
            return Err(StateError::InvalidCommitment);
        }
        Ok(())
    }
}
