use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum PeerOperation {
    Disconnect { peer_id: String },
    Quarantine { peer_id: String, until: u64 },
    Ban { peer_id: String, until: Option<u64> },
    Unban { peer_id: String },
}

impl PeerOperation {
    pub fn validate(&self) -> Result<(), crate::AdminError> {
        let peer_id = match self {
            Self::Disconnect { peer_id }
            | Self::Quarantine { peer_id, .. }
            | Self::Ban { peer_id, .. }
            | Self::Unban { peer_id } => peer_id,
        };
        if peer_id.trim().is_empty() || peer_id.len() > 256 {
            return Err(crate::AdminError::invalid_request("invalid peer ID"));
        }
        Ok(())
    }
}
