//! Canonical finalized NodeAddress-to-wallet ownership state.
//!
//! Ownership is independent of the Synergy Naming System. A node can be owned,
//! earn rewards, and authorize withdrawals without ever registering a NodeID.
//! This crate never stores wallet or node private keys.

mod authorization;
mod binding;
mod challenge;
mod store;
mod transfer;

use std::fmt;

/// Canonical WorldState.protocol key for node ownership.
pub const PROTOCOL_STATE_KEY: &str = "synergy/node-ownership/v1";

pub use authorization::{
    OwnershipAuthorization, OwnershipAuthorizationVerifier, MAX_OWNERSHIP_PROOF_BYTES,
};
pub use binding::{NodeOwnerResolver, NodeOwnershipBinding};
pub use challenge::OwnershipAction;
pub use store::{AtomicOwnershipCache, OwnershipCache, OwnershipRegistrySnapshot};
pub use transfer::{
    FinalizedOwnershipBatch, OwnershipClaimRequest, OwnershipEngine, OwnershipTransferRequest,
    OwnershipTransition,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnershipError {
    InvalidWallet,
    InvalidNonce,
    MissingProof,
    ProofTooLarge,
    NodeAlreadyOwned,
    NodeNotOwned,
    OwnerMismatch,
    UnchangedOwner,
    InvalidVersion,
    InvalidFinalizedOrder,
    ConflictingFinalizedState,
    EmptyFinalizedBatch,
    CorruptState,
    Authorization(String),
    Serialization(String),
    Cache(String),
}

impl fmt::Display for OwnershipError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidWallet => {
                formatter.write_str("ownership requires a canonical Synergy wallet")
            }
            Self::InvalidNonce => {
                formatter.write_str("ownership authorization nonce must increase")
            }
            Self::MissingProof => formatter.write_str("ownership proof is empty"),
            Self::ProofTooLarge => formatter.write_str("ownership proof exceeds protocol bound"),
            Self::NodeAlreadyOwned => formatter.write_str("NodeAddress already has an owner"),
            Self::NodeNotOwned => formatter.write_str("NodeAddress has no current owner"),
            Self::OwnerMismatch => formatter.write_str("wallet is not the current node owner"),
            Self::UnchangedOwner => formatter.write_str("replacement owner is unchanged"),
            Self::InvalidVersion => formatter.write_str("unsupported ownership state version"),
            Self::InvalidFinalizedOrder => {
                formatter.write_str("ownership update is not after cached finalized state")
            }
            Self::ConflictingFinalizedState => {
                formatter.write_str("conflicting ownership state at one finalized block")
            }
            Self::EmptyFinalizedBatch => formatter.write_str("finalized ownership batch is empty"),
            Self::CorruptState => formatter.write_str("ownership state invariants are corrupt"),
            Self::Authorization(message) => {
                write!(formatter, "ownership authorization failed: {message}")
            }
            Self::Serialization(message) => {
                write!(formatter, "ownership serialization failed: {message}")
            }
            Self::Cache(message) => write!(formatter, "ownership cache failed: {message}"),
        }
    }
}

impl std::error::Error for OwnershipError {}

pub(crate) fn validate_wallet(wallet: &str) -> Result<(), OwnershipError> {
    if synergy_address::address_kind(wallet) == synergy_address::AddressKind::Wallet {
        Ok(())
    } else {
        Err(OwnershipError::InvalidWallet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use synergy_protocol_types::{BlockReference, Height, NodeAddress, ProtocolHash};

    const NODE: &str = "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn";

    #[derive(Clone, Copy)]
    struct Verifier;

    impl OwnershipAuthorizationVerifier for Verifier {
        fn verify_wallet_proof(
            &self,
            _wallet: &str,
            _payload: &[u8],
            proof: &[u8],
        ) -> Result<(), String> {
            (proof == b"wallet-proof")
                .then_some(())
                .ok_or_else(|| "bad wallet proof".into())
        }

        fn verify_node_possession(
            &self,
            _node_address: &NodeAddress,
            _payload: &[u8],
            proof: &[u8],
        ) -> Result<(), String> {
            (proof == b"node-proof")
                .then_some(())
                .ok_or_else(|| "bad node proof".into())
        }
    }

    fn wallet(seed: u8) -> String {
        synergy_address::generate_wallet_address(&format!("{seed:02x}").repeat(1_793)).unwrap()
    }

    fn finalized(height: u64) -> BlockReference {
        BlockReference::new(
            Height::new(height),
            ProtocolHash::new([(height + 1) as u8; 32]),
            ProtocolHash::new([height as u8; 32]),
        )
        .unwrap()
    }

    #[test]
    fn claim_requires_wallet_and_node_control_proofs() {
        let engine = OwnershipEngine::new(Verifier);
        let request = OwnershipClaimRequest {
            node_address: NodeAddress::parse(NODE).unwrap(),
            owner_wallet: wallet(1),
            nonce: 1,
            wallet_proof: b"wallet-proof".to_vec(),
            node_possession_proof: Vec::new(),
        };
        assert_eq!(
            engine
                .prepare_claim(&OwnershipRegistrySnapshot::default(), request)
                .unwrap_err(),
            OwnershipError::MissingProof
        );
    }

    #[test]
    fn finalized_transfer_changes_owner_without_changing_node_address() {
        let node_address = NodeAddress::parse(NODE).unwrap();
        let first = wallet(1);
        let second = wallet(2);
        let engine = OwnershipEngine::new(Verifier);
        let mut state = OwnershipRegistrySnapshot::default();
        let claim = engine
            .prepare_claim(
                &state,
                OwnershipClaimRequest {
                    node_address: node_address.clone(),
                    owner_wallet: first.clone(),
                    nonce: 1,
                    wallet_proof: b"wallet-proof".to_vec(),
                    node_possession_proof: b"node-proof".to_vec(),
                },
            )
            .unwrap();
        state
            .apply_finalized(FinalizedOwnershipBatch {
                finalized_at: finalized(1),
                transitions: vec![claim],
            })
            .unwrap();
        let transfer = engine
            .prepare_transfer(
                &state,
                OwnershipTransferRequest {
                    node_address: node_address.clone(),
                    current_owner_wallet: first,
                    new_owner_wallet: second.clone(),
                    nonce: 2,
                    current_owner_proof: b"wallet-proof".to_vec(),
                    new_owner_acceptance_proof: b"wallet-proof".to_vec(),
                },
            )
            .unwrap();
        state
            .apply_finalized(FinalizedOwnershipBatch {
                finalized_at: finalized(2),
                transitions: vec![transfer],
            })
            .unwrap();
        assert_eq!(state.current_owner(&node_address), Some(second.as_str()));
    }
}
