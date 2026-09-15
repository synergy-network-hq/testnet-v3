use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum RewardOperation {
    InspectAccount {
        node_address: String,
    },
    InspectWithdrawal {
        withdrawal_id: String,
    },
    PrepareWithdrawal {
        withdrawal_id: String,
        node_address: String,
        destination_wallet: String,
        amount_nwei: u128,
        nonce: u64,
    },
}

impl RewardOperation {
    pub const fn is_mutating(&self) -> bool {
        false
    }

    pub fn validate(&self) -> Result<(), crate::AdminError> {
        match self {
            Self::InspectAccount { node_address } => require_text(node_address, "NodeAddress", 256),
            Self::InspectWithdrawal { withdrawal_id } => {
                require_text(withdrawal_id, "withdrawal ID", 128)
            }
            Self::PrepareWithdrawal {
                withdrawal_id,
                node_address,
                destination_wallet,
                amount_nwei,
                nonce,
            } => {
                require_text(withdrawal_id, "withdrawal ID", 128)?;
                require_text(node_address, "NodeAddress", 256)?;
                require_text(destination_wallet, "destination wallet", 256)?;
                if *amount_nwei == 0 || *nonce == 0 {
                    return Err(crate::AdminError::invalid_request(
                        "withdrawal amount and nonce must be nonzero",
                    ));
                }
                Ok(())
            }
        }
    }
}

fn require_text(value: &str, label: &str, maximum: usize) -> Result<(), crate::AdminError> {
    if value.trim().is_empty() || value.len() > maximum || value.contains(char::is_control) {
        return Err(crate::AdminError::invalid_request(format!(
            "invalid {label}"
        )));
    }
    Ok(())
}
