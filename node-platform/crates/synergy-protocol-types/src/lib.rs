//! Authority-neutral wire and session types shared by the node platform.
//!
//! These values identify a transport route only. They never grant validator
//! authority, calculate quorum, or determine PoSy finality.

use serde::{Deserialize, Serialize};

/// Existing network validator bond, in the canonical nine-decimal native unit.
pub const VALIDATOR_MINIMUM_BOND_NWEI:u128=50_000_000_000_000;

mod block;
mod certificate;
mod chain;
mod cluster;
mod epoch;
mod hash;
mod height;
mod node_address;
mod network_r1;
mod r1_public_node;
mod role;
mod serialization;
mod transaction;
mod validator;
pub mod bounded_document;
pub mod r1_rpc_response;

pub use block::{BlockReference, BlockReferenceError};
pub use certificate::{CertificateKind, CertificateReference};
pub use chain::{ChainContext, ChainId, ChainIdError};
pub use cluster::{ClusterId, ClusterIdError};
pub use epoch::{Epoch, EpochOverflow};
pub use hash::ProtocolHash;
pub use height::{Height, HeightOverflow};
pub use node_address::{NodeAddress, NodeAddressError, NodeClass};
pub use network_r1::{R1ContextError,R1ProfileRef,R1NetworkRef,R1GenesisReference,R1ProfileSetReference,R1NetworkCoordinate};
pub use r1_public_node::R1NodePresentation;
pub use role::NodeRole;
pub use serialization::{FrameDescriptor, FrameDescriptorError, WireVersion};
pub use transaction::{TransactionReference, TransactionReferenceError};
pub use validator::{ValidatorId, ValidatorIdError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolKind {
    Status,
    Discovery,
    Sync,
    Posy,
    Etdag,
    Transaction,
    Snapshot,
    Observer,
    Sxcp,
}

impl ProtocolKind {
    /// Routing metadata is never a consensus decision.
    pub const fn may_determine_finality(self) -> bool {
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedPeer {
    pub node_address: NodeAddress,
    pub session_id: SessionId,
    pub capabilities: Vec<String>,
}

impl AuthenticatedPeer {
    /// Builds a route value from the explicit current R1 presentation profile.
    /// The native session owner must separately verify network, key possession,
    /// session establishment and current capabilities; syntax grants no authority.
    pub fn new_current(
        node_address: impl Into<String>,
        expected_class: NodeClass,
        session_id: SessionId,
        capabilities: Vec<String>,
    ) -> Result<Self, PeerIdentityError> {
        let node_address = NodeAddress::parse_current(node_address, expected_class)
            .map_err(PeerIdentityError::InvalidNodeAddress)?;
        Ok(Self { node_address, session_id, capabilities })
    }

    pub fn new(
        node_address: impl Into<String>,
        session_id: SessionId,
        capabilities: Vec<String>,
    ) -> Result<Self, PeerIdentityError> {
        let node_address = NodeAddress::parse(node_address.into())
            .map_err(PeerIdentityError::InvalidNodeAddress)?;
        Ok(Self {
            node_address,
            session_id,
            capabilities,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerIdentityError {
    InvalidNodeAddress(NodeAddressError),
}

impl std::fmt::Display for PeerIdentityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidNodeAddress(error) => {
                write!(formatter, "invalid authenticated node address: {error}")
            }
        }
    }
}

impl std::error::Error for PeerIdentityError {}

#[cfg(test)]
mod tests {
    use super::{AuthenticatedPeer, NodeClass, ProtocolKind, SessionId};

    #[test]
    fn protocol_classification_never_grants_finality_authority() {
        assert!(!ProtocolKind::Posy.may_determine_finality());
        assert!(!ProtocolKind::Etdag.may_determine_finality());
        assert!(!ProtocolKind::Sync.may_determine_finality());
    }

    #[test]
    fn current_peer_preserves_full_identifier_and_requires_selected_class() {
        let text = format!("synv5.2.{}", "A".repeat(64));
        let peer = AuthenticatedPeer::new_current(&text, NodeClass::ServiceAndAccess,
                                                SessionId(7), vec![]).unwrap();
        assert_eq!(peer.node_address.as_str(), text);
        assert_eq!(peer.session_id, SessionId(7));
        assert!(AuthenticatedPeer::new_current(text, NodeClass::ConsensusAndChainIntegrity,
                                               SessionId(7), vec![]).is_err());
    }

    #[test]
    fn current_peer_existing_constructor_and_serde_preserve_full_case_sensitive_text() {
        for digit in 1..=5 {
            let text=format!("synv{digit}.2.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v");
            let peer=AuthenticatedPeer::new(&text,SessionId(7),vec!["status".into()]).unwrap();
            assert_eq!(peer.node_address.as_str(),text);
            let encoded=serde_json::to_string(&peer).unwrap();
            let decoded:AuthenticatedPeer=serde_json::from_str(&encoded).unwrap();
            assert_eq!(decoded,peer);
            assert!(super::NodeAddress::parse_historical(text).is_err());
        }
    }

    #[test]
    fn current_peer_rejects_historical_identity_without_changing_old_constructor() {
        let historical = "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn";
        assert!(AuthenticatedPeer::new_current(historical, NodeClass::ConsensusAndChainIntegrity,
                                              SessionId(7), vec![]).is_err());
        assert!(AuthenticatedPeer::new(historical, SessionId(7), vec![]).is_ok());
    }

    #[test]
    fn authenticated_peer_requires_a_nonempty_transport_identity() {
        assert!(AuthenticatedPeer::new("", SessionId(1), Vec::new()).is_err());
    }
}

pub mod canonical_bytes;

pub mod c14n02;
