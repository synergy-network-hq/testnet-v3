//! Typed messages for the challenge-response handshake.

use synergy_protocol_types::SessionId;

use super::{HandshakeChallenge, HandshakeMetadata, TransportIdentity};

/// Invalid relationship between handshake offer fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfferError {
    IdentityMismatch,
}

impl std::fmt::Display for OfferError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("handshake metadata and transport identity do not match")
    }
}

impl std::error::Error for OfferError {}

/// Remote identity, compatibility metadata, and fresh replay challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeOffer {
    pub metadata: HandshakeMetadata,
    pub identity: TransportIdentity,
    pub challenge: HandshakeChallenge,
}

impl HandshakeOffer {
    /// Creates a coherent handshake offer.
    ///
    /// # Errors
    /// Returns [`OfferError`] if metadata and authenticated identity disagree.
    pub fn new(
        metadata: HandshakeMetadata,
        identity: TransportIdentity,
        challenge: HandshakeChallenge,
    ) -> Result<Self, OfferError> {
        if &metadata.node_address != identity.node_address() {
            return Err(OfferError::IdentityMismatch);
        }
        Ok(Self {
            metadata,
            identity,
            challenge,
        })
    }
}

/// Signature over both challenges, compatibility metadata, and exact session ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeProof {
    pub session_id: SessionId,
    pub offer_nonce: [u8; 32],
    pub answer_nonce: [u8; 32],
    pub signature: Vec<u8>,
}
