use serde::{Deserialize, Serialize};

use crate::TransactionError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeLimit {
    pub gas_limit: u64,
    pub max_fee_per_gas_nwei: u64,
}

impl FeeLimit {
    pub fn validate(self) -> Result<(), TransactionError> {
        if self.gas_limit == 0 || self.max_fee_per_gas_nwei == 0 {
            return Err(TransactionError::InvalidFeeLimit);
        }
        self.gas_limit
            .checked_mul(self.max_fee_per_gas_nwei)
            .ok_or(TransactionError::FeeOverflow)?;
        Ok(())
    }

    pub fn maximum_fee_nwei(self) -> Result<u64, TransactionError> {
        self.validate()?;
        self.gas_limit
            .checked_mul(self.max_fee_per_gas_nwei)
            .ok_or(TransactionError::FeeOverflow)
    }
}
