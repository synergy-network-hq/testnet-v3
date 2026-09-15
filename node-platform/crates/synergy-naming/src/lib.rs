//! Canonical Synergy Naming System for human-readable NodeID aliases.
//!
//! Finalized network state is authoritative. Local persistence is a rebuildable
//! cache only. Ownership is resolved through synergy-node-ownership and is
//! never inferred from a naming record.

mod authorization;
mod availability;
mod nodeid;
mod normalization;
mod registration;
mod resolution;
mod reverse_resolution;
mod store;

use std::fmt;

/// Canonical WorldState.protocol key for Synergy Naming System state.
pub const PROTOCOL_STATE_KEY: &str = "synergy/naming/v1";

pub use authorization::{
    NamingAction, NamingAuthorization, NamingAuthorizationVerifier, MAX_AUTHORIZATION_PROOF_BYTES,
};
pub use availability::{ensure_available, is_available};
pub use nodeid::{NodeId, NodeIdError};
pub use normalization::normalize_node_id;
pub use registration::{
    FinalizedNamingBatch, NamingEngine, NamingRecord, NamingRecordStatus, NamingTransition,
    RegistrationRequest, RenameRequest,
};
pub use resolution::resolve;
pub use reverse_resolution::reverse_resolve;
pub use store::{AtomicNamingCache, NamingCache, NamingRegistrySnapshot};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NamingError {
    InvalidNodeId(NodeIdError),
    InvalidOwnerWallet,
    InvalidNonce,
    MissingAuthorizationProof,
    AuthorizationProofTooLarge,
    DuplicateNodeId,
    NodeAddressAlreadyNamed,
    NodeIdNotFound,
    NodeAddressMismatch,
    OwnerWalletMismatch,
    UnchangedNodeId,
    InvalidRegistryVersion,
    InvalidFinalizedOrder,
    ConflictingFinalizedState,
    EmptyFinalizedBatch,
    CorruptRegistry,
    Ownership(String),
    Authorization(String),
    Serialization(String),
    Cache(String),
}

impl From<NodeIdError> for NamingError {
    fn from(error: NodeIdError) -> Self {
        Self::InvalidNodeId(error)
    }
}

impl fmt::Display for NamingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidNodeId(error) => write!(formatter, "invalid NodeID: {error}"),
            Self::InvalidOwnerWallet => {
                formatter.write_str("naming authorization requires a canonical wallet address")
            }
            Self::InvalidNonce => formatter.write_str("naming authorization nonce must increase"),
            Self::MissingAuthorizationProof => {
                formatter.write_str("naming authorization proof is empty")
            }
            Self::AuthorizationProofTooLarge => {
                formatter.write_str("naming authorization proof exceeds the protocol bound")
            }
            Self::DuplicateNodeId => formatter.write_str("NodeID is already registered"),
            Self::NodeAddressAlreadyNamed => {
                formatter.write_str("NodeAddress already has a registered NodeID")
            }
            Self::NodeIdNotFound => formatter.write_str("NodeID is not registered"),
            Self::NodeAddressMismatch => {
                formatter.write_str("naming request does not match the registered NodeAddress")
            }
            Self::OwnerWalletMismatch => {
                formatter.write_str("wallet is not the current canonical node owner")
            }
            Self::UnchangedNodeId => formatter.write_str("replacement NodeID is unchanged"),
            Self::InvalidRegistryVersion => {
                formatter.write_str("unsupported naming registry version")
            }
            Self::InvalidFinalizedOrder => {
                formatter.write_str("naming update is not after cached finalized state")
            }
            Self::ConflictingFinalizedState => {
                formatter.write_str("conflicting naming state at one finalized block")
            }
            Self::EmptyFinalizedBatch => formatter.write_str("finalized naming batch is empty"),
            Self::CorruptRegistry => formatter.write_str("naming registry invariants are corrupt"),
            Self::Ownership(message) => write!(formatter, "ownership lookup failed: {message}"),
            Self::Authorization(message) => {
                write!(formatter, "naming authorization failed: {message}")
            }
            Self::Serialization(message) => {
                write!(formatter, "naming serialization failed: {message}")
            }
            Self::Cache(message) => write!(formatter, "naming cache failed: {message}"),
        }
    }
}

impl std::error::Error for NamingError {}

#[cfg(test)]
mod tests;
