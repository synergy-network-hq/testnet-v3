//! Authority-neutral wire and session types shared by the node platform.
//!
//! These values identify a transport route only. They never grant validator
//! authority, calculate quorum, or determine PoSy finality.

use serde::{Deserialize, Serialize};

mod block;
mod certificate;
mod chain;
mod cluster;
mod epoch;
mod hash;
mod height;
mod node_address;
mod role;
mod serialization;
mod transaction;
mod validator;

pub use block::{BlockReference, BlockReferenceError};
pub use certificate::{CertificateKind, CertificateReference};
pub use chain::{ChainContext, ChainId, ChainIdError};
pub use cluster::{ClusterId, ClusterIdError};
pub use epoch::{Epoch, EpochOverflow};
pub use hash::ProtocolHash;
pub use height::{Height, HeightOverflow};
pub use node_address::{NodeAddress, NodeAddressError, NodeClass};
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
    use super::{AuthenticatedPeer, ProtocolKind, SessionId};

    #[test]
    fn protocol_classification_never_grants_finality_authority() {
        assert!(!ProtocolKind::Posy.may_determine_finality());
        assert!(!ProtocolKind::Etdag.may_determine_finality());
        assert!(!ProtocolKind::Sync.may_determine_finality());
    }

    #[test]
    fn authenticated_peer_requires_a_nonempty_transport_identity() {
        assert!(AuthenticatedPeer::new("", SessionId(1), Vec::new()).is_err());
    }
}
