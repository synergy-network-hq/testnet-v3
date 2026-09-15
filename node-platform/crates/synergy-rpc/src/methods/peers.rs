use serde::{Deserialize, Serialize};

pub const PEERS_LIST: &str = "synergy_listPeers";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerQuery {
    pub limit: usize,
}

impl PeerQuery {
    pub fn validate(&self) -> Result<(), crate::RpcError> {
        if self.limit == 0 || self.limit > 1_000 {
            return Err(crate::RpcError::invalid_params("invalid peer limit"));
        }
        Ok(())
    }
}
