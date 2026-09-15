use serde::{Deserialize, Serialize};
use synergy_protocol_types::{NodeAddress, NodeClass};

use crate::{NamingError, NodeId};

const REGISTER_DOMAIN: &[u8] = b"SYNERGY_NODEID_REGISTER_V1";
const RENAME_DOMAIN: &[u8] = b"SYNERGY_NODEID_RENAME_V1";

/// Maximum external owner-wallet proof accepted by the naming boundary.
pub const MAX_AUTHORIZATION_PROOF_BYTES: usize = 65_536;

/// Owner-wallet proof presented for a naming transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamingAuthorization {
    pub owner_wallet: String,
    pub nonce: u64,
    pub proof: Vec<u8>,
}

impl NamingAuthorization {
    pub(crate) fn validate(&self) -> Result<(), NamingError> {
        if synergy_address::address_kind(&self.owner_wallet) != synergy_address::AddressKind::Wallet
        {
            return Err(NamingError::InvalidOwnerWallet);
        }
        if self.nonce == 0 {
            return Err(NamingError::InvalidNonce);
        }
        if self.proof.is_empty() {
            return Err(NamingError::MissingAuthorizationProof);
        }
        if self.proof.len() > MAX_AUTHORIZATION_PROOF_BYTES {
            return Err(NamingError::AuthorizationProofTooLarge);
        }
        Ok(())
    }
}

/// Canonical owner-authorized action whose bytes are signed outside the node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum NamingAction {
    Register {
        node_id: NodeId,
        node_address: NodeAddress,
        owner_wallet: String,
        nonce: u64,
    },
    Rename {
        current_node_id: NodeId,
        replacement_node_id: NodeId,
        node_address: NodeAddress,
        owner_wallet: String,
        nonce: u64,
    },
}

impl NamingAction {
    /// Produces deterministic domain-separated bytes for owner-wallet signing.
    ///
    /// # Errors
    /// Returns NamingError if a field cannot fit the bounded encoding.
    pub fn signing_payload(&self) -> Result<Vec<u8>, NamingError> {
        let mut bytes = Vec::with_capacity(256);
        match self {
            Self::Register {
                node_id,
                node_address,
                owner_wallet,
                nonce,
            } => {
                append_field(&mut bytes, REGISTER_DOMAIN)?;
                append_field(&mut bytes, node_id.as_str().as_bytes())?;
                append_field(&mut bytes, node_address.as_str().as_bytes())?;
                append_field(&mut bytes, owner_wallet.as_bytes())?;
                bytes.extend_from_slice(&nonce.to_be_bytes());
                bytes.push(node_address.class().digit());
            }
            Self::Rename {
                current_node_id,
                replacement_node_id,
                node_address,
                owner_wallet,
                nonce,
            } => {
                append_field(&mut bytes, RENAME_DOMAIN)?;
                append_field(&mut bytes, current_node_id.as_str().as_bytes())?;
                append_field(&mut bytes, replacement_node_id.as_str().as_bytes())?;
                append_field(&mut bytes, node_address.as_str().as_bytes())?;
                append_field(&mut bytes, owner_wallet.as_bytes())?;
                bytes.extend_from_slice(&nonce.to_be_bytes());
                bytes.push(node_address.class().digit());
            }
        }
        Ok(bytes)
    }

    /// Returns the canonical address that remains authoritative for this action.
    pub fn node_address(&self) -> &NodeAddress {
        match self {
            Self::Register { node_address, .. } | Self::Rename { node_address, .. } => node_address,
        }
    }

    /// Returns the owner wallet claimed by the action.
    pub fn owner_wallet(&self) -> &str {
        match self {
            Self::Register { owner_wallet, .. } | Self::Rename { owner_wallet, .. } => owner_wallet,
        }
    }

    /// Returns the monotonic replay-protection nonce.
    pub const fn nonce(&self) -> u64 {
        match self {
            Self::Register { nonce, .. } | Self::Rename { nonce, .. } => *nonce,
        }
    }

    /// Naming never changes the canonical node class.
    pub fn node_class(&self) -> NodeClass {
        self.node_address().class()
    }
}

fn append_field(target: &mut Vec<u8>, value: &[u8]) -> Result<(), NamingError> {
    let length = u32::try_from(value.len())
        .map_err(|_| NamingError::Serialization("signing field exceeds u32".into()))?;
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(value);
    Ok(())
}

/// Boundary implemented by the canonical node-owner wallet verifier.
///
/// Implementations verify the action payload with the linked owner wallet.
/// This crate never stores or handles an owner private key.
pub trait NamingAuthorizationVerifier {
    fn verify(
        &self,
        action: &NamingAction,
        authorization: &NamingAuthorization,
    ) -> Result<(), String>;
}
