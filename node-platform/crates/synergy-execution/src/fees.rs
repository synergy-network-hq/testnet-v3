use synergy_state::{AccountChange, StateDiff};
use synergy_transaction::SignedTransaction;

use crate::BlockExecutionError;

/// Network-selected execution fee schedule. The fee cap remains signed by the
/// sender; this schedule selects the deterministic price actually charged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeeSchedule {
    pub base_fee_per_gas_nwei: u64,
    pub collector: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeSettlement {
    pub gas_used: u64,
    pub fee_nwei: u128,
}

impl FeeSchedule {
    pub fn validate(&self) -> Result<(), BlockExecutionError> {
        if self.base_fee_per_gas_nwei == 0 || self.collector.trim().is_empty() {
            return Err(BlockExecutionError::InvalidFeeSchedule);
        }
        Ok(())
    }

    pub fn settle(
        &self,
        transaction: &SignedTransaction,
        gas_used: u64,
        transaction_index: usize,
    ) -> Result<(FeeSettlement, StateDiff), BlockExecutionError> {
        self.validate()?;
        let limit = transaction.unsigned.fee_limit;
        if gas_used > limit.gas_limit {
            return Err(BlockExecutionError::GasLimitExceeded {
                transaction_index,
                used: gas_used,
                limit: limit.gas_limit,
            });
        }
        if limit.max_fee_per_gas_nwei < self.base_fee_per_gas_nwei {
            return Err(BlockExecutionError::FeeCapTooLow {
                transaction_index,
                cap: limit.max_fee_per_gas_nwei,
                required: self.base_fee_per_gas_nwei,
            });
        }
        if transaction.unsigned.sender == self.collector {
            return Err(BlockExecutionError::FeeCollectorIsSender { transaction_index });
        }
        let fee_nwei = u128::from(gas_used)
            .checked_mul(u128::from(self.base_fee_per_gas_nwei))
            .ok_or(BlockExecutionError::FeeOverflow { transaction_index })?;
        let diff = StateDiff {
            changes: vec![
                AccountChange {
                    account: transaction.unsigned.sender.clone(),
                    debit_nwei: fee_nwei,
                    credit_nwei: 0,
                    expected_nonce: None,
                    code_hash: None,
                },
                AccountChange {
                    account: self.collector.clone(),
                    debit_nwei: 0,
                    credit_nwei: fee_nwei,
                    expected_nonce: None,
                    code_hash: None,
                },
            ],
            protocol_changes: Vec::new(),
        };
        Ok((FeeSettlement { gas_used, fee_nwei }, diff))
    }
}
