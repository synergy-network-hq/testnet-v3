use serde::{Deserialize, Serialize};

pub const ACCOUNT_GET: &str = "synergy_getAccount";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountQuery {
    pub address: String,
    pub at_height: Option<u64>,
}

impl AccountQuery {
    pub fn validate(&self) -> Result<(), crate::RpcError> {
        if self.address.trim().is_empty() || self.address.len() > 256 {
            return Err(crate::RpcError::invalid_params("invalid account address"));
        }
        if self.at_height == Some(0) {
            return Err(crate::RpcError::invalid_params(
                "account height must be greater than zero",
            ));
        }
        Ok(())
    }
}
