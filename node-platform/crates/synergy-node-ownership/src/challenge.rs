use serde::{Deserialize, Serialize};
use synergy_protocol_types::NodeAddress;

use crate::OwnershipError;

const CLAIM_DOMAIN: &[u8] = b"SYNERGY_NODE_OWNERSHIP_CLAIM_V1";
const TRANSFER_DOMAIN: &[u8] = b"SYNERGY_NODE_OWNERSHIP_TRANSFER_V1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum OwnershipAction {
    Claim {
        node_address: NodeAddress,
        owner_wallet: String,
        nonce: u64,
    },
    Transfer {
        node_address: NodeAddress,
        current_owner_wallet: String,
        new_owner_wallet: String,
        nonce: u64,
    },
}

impl OwnershipAction {
    pub fn signing_payload(&self) -> Result<Vec<u8>, OwnershipError> {
        let mut bytes = Vec::with_capacity(256);
        match self {
            Self::Claim {
                node_address,
                owner_wallet,
                nonce,
            } => {
                append_field(&mut bytes, CLAIM_DOMAIN)?;
                append_field(&mut bytes, node_address.as_str().as_bytes())?;
                append_field(&mut bytes, owner_wallet.as_bytes())?;
                bytes.extend_from_slice(&nonce.to_be_bytes());
            }
            Self::Transfer {
                node_address,
                current_owner_wallet,
                new_owner_wallet,
                nonce,
            } => {
                append_field(&mut bytes, TRANSFER_DOMAIN)?;
                append_field(&mut bytes, node_address.as_str().as_bytes())?;
                append_field(&mut bytes, current_owner_wallet.as_bytes())?;
                append_field(&mut bytes, new_owner_wallet.as_bytes())?;
                bytes.extend_from_slice(&nonce.to_be_bytes());
            }
        }
        Ok(bytes)
    }

    pub fn node_address(&self) -> &NodeAddress {
        match self {
            Self::Claim { node_address, .. } | Self::Transfer { node_address, .. } => node_address,
        }
    }

    pub const fn nonce(&self) -> u64 {
        match self {
            Self::Claim { nonce, .. } | Self::Transfer { nonce, .. } => *nonce,
        }
    }
}

fn append_field(target: &mut Vec<u8>, value: &[u8]) -> Result<(), OwnershipError> {
    let length = u32::try_from(value.len())
        .map_err(|_| OwnershipError::Serialization("challenge field exceeds u32".into()))?;
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(value);
    Ok(())
}
