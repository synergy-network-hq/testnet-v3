use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminEventKind {
    Lifecycle,
    Health,
    Peer,
    Sync,
    Validator,
    Vpn,
    Posy,
    Etdag,
    Storage,
    Upgrade,
    Audit,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdminEvent {
    pub sequence: u64,
    pub timestamp_ms: u64,
    pub kind: AdminEventKind,
    pub payload: Value,
}

impl AdminEvent {
    pub fn validate(&self, max_payload_bytes: usize) -> Result<(), crate::AdminError> {
        if self.sequence == 0 || max_payload_bytes == 0 {
            return Err(crate::AdminError::invalid_request("invalid Admin event"));
        }
        let bytes = serde_json::to_vec(&self.payload)
            .map_err(|error| crate::AdminError::internal(error.to_string()))?;
        if bytes.len() > max_payload_bytes {
            return Err(crate::AdminError::invalid_request(
                "Admin event payload exceeds limit",
            ));
        }
        Ok(())
    }
}
