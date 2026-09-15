use serde::{Deserialize, Serialize};

pub const TRANSACTION_GET: &str = "synergy_getTransaction";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionQuery {
    pub transaction_id: String,
}

impl TransactionQuery {
    pub fn validate(&self) -> Result<(), crate::RpcError> {
        if self.transaction_id.len() != 64
            || self
                .transaction_id
                .bytes()
                .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
        {
            return Err(crate::RpcError::invalid_params(
                "transaction identifier must be a canonical lowercase hash",
            ));
        }
        Ok(())
    }
}
