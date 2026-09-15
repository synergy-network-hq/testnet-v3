use serde::{Deserialize, Serialize};

use synergy_transaction::{SignedTransaction, TransactionId};

use crate::{transaction_root, BlockError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockBody {
    pub transactions: Vec<SignedTransaction>,
}

impl BlockBody {
    pub fn transaction_ids(&self) -> Result<Vec<TransactionId>, BlockError> {
        self.transactions
            .iter()
            .map(|transaction| transaction.id().map_err(BlockError::Transaction))
            .collect()
    }

    pub fn transaction_root(&self) -> Result<String, BlockError> {
        transaction_root(&self.transaction_ids()?)
    }

    pub fn validate_structure(&self) -> Result<(), BlockError> {
        let ids = self.transaction_ids()?;
        let mut sorted = ids.clone();
        sorted.sort();
        sorted.dedup();
        if sorted.len() != ids.len() {
            return Err(BlockError::DuplicateTransaction);
        }
        Ok(())
    }
}
