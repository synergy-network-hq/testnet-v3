use serde::{Deserialize, Serialize};

pub const BLOCK_GET: &str = "synergy_getBlock";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
        if self.hash.as_ref().is_some_and(|hash| {
            hash.len() != 64
                || !hash.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }) {
            return Err(crate::RpcError::invalid_params(
                "block hash must be a canonical lowercase historical hash",
            ));
        }
        Ok(())
    }
}
