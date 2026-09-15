use serde::{Deserialize, Serialize};

pub const BLOCK_GET: &str = "synergy_getBlock";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockQuery {
    pub height: Option<u64>,
    pub hash: Option<String>,
}

impl BlockQuery {
    pub fn validate(&self) -> Result<(), crate::RpcError> {
        if self.height.is_some() == self.hash.is_some() {
            return Err(crate::RpcError::invalid_params(
                "provide exactly one block height or hash",
            ));
        }
        Ok(())
    }
}
