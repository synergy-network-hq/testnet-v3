//! Optional transport-admission policy applied after handshake identity binding.
//! It is deliberately distinct from PoSy membership and authority.

use synergy_protocol_types::AuthenticatedPeer;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerAdmissionPolicyError {
    Denied(String),
}
impl std::fmt::Display for PeerAdmissionPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Denied(reason) => write!(f, "transport admission denied: {reason}"),
        }
    }
}
impl std::error::Error for PeerAdmissionPolicyError {}

pub trait AuthenticatedTransportAdmissionPolicy {
    fn permit(&self, peer: &AuthenticatedPeer) -> Result<(), PeerAdmissionPolicyError>;
}
