use serde::{Deserialize, Serialize};

use crate::StateError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AccountState {
    pub balance_nwei: u128,
    pub nonce: u64,
    pub code_hash: Option<String>,
}

impl AccountState {
    pub fn debit(&mut self, amount: u128) -> Result<(), StateError> {
        self.balance_nwei = self
            .balance_nwei
            .checked_sub(amount)
            .ok_or(StateError::InsufficientBalance)?;
        Ok(())
    }

    pub fn credit(&mut self, amount: u128) -> Result<(), StateError> {
        self.balance_nwei = self
            .balance_nwei
            .checked_add(amount)
            .ok_or(StateError::BalanceOverflow)?;
        Ok(())
    }

    pub fn consume_nonce(&mut self, expected: u64) -> Result<(), StateError> {
        if self.nonce != expected {
            return Err(StateError::NonceMismatch {
                expected: self.nonce,
                supplied: expected,
            });
        }
        self.nonce = self.nonce.checked_add(1).ok_or(StateError::NonceOverflow)?;
        Ok(())
    }
}
