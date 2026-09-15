use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::TransactionError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonceWindow {
    next: u64,
    reserved: BTreeSet<u64>,
    maximum_gap: u64,
}

impl NonceWindow {
    pub fn new(next: u64, maximum_gap: u64) -> Result<Self, TransactionError> {
        if maximum_gap == 0 {
            return Err(TransactionError::InvalidNonceWindow);
        }
        Ok(Self {
            next,
            reserved: BTreeSet::new(),
            maximum_gap,
        })
    }

    pub fn reserve(&mut self, nonce: u64) -> Result<(), TransactionError> {
        if nonce < self.next || nonce.saturating_sub(self.next) > self.maximum_gap {
            return Err(TransactionError::NonceOutOfWindow);
        }
        if !self.reserved.insert(nonce) {
            return Err(TransactionError::DuplicateNonce);
        }
        Ok(())
    }

    pub fn commit(&mut self, nonce: u64) -> Result<(), TransactionError> {
        if nonce != self.next || !self.reserved.remove(&nonce) {
            return Err(TransactionError::NonceNotReady);
        }
        self.next = self
            .next
            .checked_add(1)
            .ok_or(TransactionError::NonceOverflow)?;
        Ok(())
    }

    pub fn release(&mut self, nonce: u64) -> bool {
        self.reserved.remove(&nonce)
    }

    pub fn is_reserved(&self, nonce: u64) -> bool {
        self.reserved.contains(&nonce)
    }

    pub fn next(&self) -> u64 {
        self.next
    }
}
