use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum OwnershipOperation {
    Inspect {
        node_address: String,
    },
    PrepareClaim {
        node_address: String,
        nonce: u64,
        node_possession_proof: Vec<u8>,
    },
    PrepareTransfer {
        node_address: String,
        new_owner_wallet: String,
        nonce: u64,
        new_owner_acceptance_proof: Vec<u8>,
    },
}

impl OwnershipOperation {
    pub const fn is_mutating(&self) -> bool {
        false
    }

    pub fn validate(&self) -> Result<(), crate::AdminError> {
        let (node_address, nonce, proof) = match self {
            Self::Inspect { node_address } => (node_address, None, None),
            Self::PrepareClaim {
                node_address,
                nonce,
                node_possession_proof,
            } => (node_address, Some(*nonce), Some(node_possession_proof)),
            Self::PrepareTransfer {
                node_address,
                new_owner_wallet,
                nonce,
                new_owner_acceptance_proof,
            } => {
                require_address(new_owner_wallet, "new owner wallet")?;
                (node_address, Some(*nonce), Some(new_owner_acceptance_proof))
            }
        };
        require_address(node_address, "NodeAddress")?;
        if nonce.is_some_and(|value| value == 0)
            || proof.is_some_and(|value| value.is_empty() || value.len() > 65_536)
        {
            return Err(crate::AdminError::invalid_request(
                "authorization nonce and proof must be present and bounded",
            ));
        }
        Ok(())
    }
}

fn require_address(value: &str, label: &str) -> Result<(), crate::AdminError> {
    if value.trim().is_empty() || value.len() > 256 || value.contains(char::is_control) {
        return Err(crate::AdminError::invalid_request(format!(
            "invalid {label}"
        )));
    }
    Ok(())
}
