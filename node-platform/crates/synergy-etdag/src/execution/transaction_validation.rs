use crate::{execution::PreparedTransaction, EtdagError};

pub trait PlaintextTransactionValidator {
    fn validate_transaction(&self, transaction: &[u8]) -> Result<(), EtdagError>;
}

pub fn validate_prepared_transactions(
    transactions: &[PreparedTransaction],
    max_transaction_bytes: usize,
    validator: &impl PlaintextTransactionValidator,
) -> Result<(), EtdagError> {
    if max_transaction_bytes == 0 || transactions.is_empty() {
        return Err(EtdagError::InvalidCapacity);
    }
    for transaction in transactions {
        transaction.vertex_id.validate()?;
        transaction.envelope_id.validate()?;
        if transaction.plaintext.is_empty() || transaction.plaintext.len() > max_transaction_bytes {
            return Err(EtdagError::InvalidExecutionInput);
        }
        validator.validate_transaction(&transaction.plaintext)?;
    }
    Ok(())
}
