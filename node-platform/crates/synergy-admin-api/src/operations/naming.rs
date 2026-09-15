use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum NamingOperation {
    Resolve {
        node_id: String,
    },
    ReverseResolve {
        node_address: String,
    },
    Availability {
        node_id: String,
    },
    PrepareRegister {
        node_id: String,
        node_address: String,
        nonce: u64,
    },
    PrepareRename {
        current_node_id: String,
        replacement_node_id: String,
        node_address: String,
        nonce: u64,
    },
}

impl NamingOperation {
    pub const fn is_mutating(&self) -> bool {
        false
    }

    pub fn validate(&self) -> Result<(), crate::AdminError> {
        match self {
            Self::Resolve { node_id } | Self::Availability { node_id } => require_node_id(node_id),
            Self::ReverseResolve { node_address } => require_address(node_address),
            Self::PrepareRegister {
                node_id,
                node_address,
                nonce,
            } => {
                require_node_id(node_id)?;
                require_address(node_address)?;
                require_nonce(*nonce)
            }
            Self::PrepareRename {
                current_node_id,
                replacement_node_id,
                node_address,
                nonce,
            } => {
                require_node_id(current_node_id)?;
                require_node_id(replacement_node_id)?;
                require_address(node_address)?;
                require_nonce(*nonce)
            }
        }
    }
}

fn require_node_id(value: &str) -> Result<(), crate::AdminError> {
    if value.trim().is_empty() || value.len() > 68 || value.contains(char::is_control) {
        return Err(crate::AdminError::invalid_request("invalid NodeID"));
    }
    Ok(())
}

fn require_address(value: &str) -> Result<(), crate::AdminError> {
    if value.trim().is_empty() || value.len() > 256 || value.contains(char::is_control) {
        return Err(crate::AdminError::invalid_request("invalid NodeAddress"));
    }
    Ok(())
}

fn require_nonce(nonce: u64) -> Result<(), crate::AdminError> {
    if nonce == 0 {
        return Err(crate::AdminError::invalid_request("nonce must be nonzero"));
    }
    Ok(())
}
