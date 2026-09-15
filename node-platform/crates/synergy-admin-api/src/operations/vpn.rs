use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum VpnOperation {
    Enroll { authorization_id: String },
    RefreshLease,
    Revoke { authorization_id: String },
}

impl VpnOperation {
    pub fn validate(&self) -> Result<(), crate::AdminError> {
        match self {
            Self::Enroll { authorization_id } | Self::Revoke { authorization_id }
                if authorization_id.trim().is_empty() =>
            {
                Err(crate::AdminError::invalid_request(
                    "VPN operation requires authorization ID",
                ))
            }
            _ => Ok(()),
        }
    }
}
