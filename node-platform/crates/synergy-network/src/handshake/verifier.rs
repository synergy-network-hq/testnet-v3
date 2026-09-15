//! Fail-closed conversion from a signed proof to transport authentication.

use synergy_protocol_types::{AuthenticatedPeer, PeerIdentityError, SessionId};

use super::{
    signing::{handshake_transcript, MAX_HANDSHAKE_SIGNATURE_BYTES},
    ChallengeError, HandshakeError, HandshakeMetadata, HandshakeOffer, HandshakeProof,
    HandshakeTranscriptError, OfferError, PeerKeyAlgorithm,
};

/// Verifies the offered peer identity's signature using static dispatch.
pub trait HandshakeSignatureVerifier {
    type Error;

    /// Verifies an exact canonical transcript for `peer_id` and `algorithm`.
    fn verify_handshake_signature(
        &self,
        peer_id: &str,
        algorithm: PeerKeyAlgorithm,
        transcript: &[u8],
        signature: &[u8],
    ) -> Result<(), Self::Error>;
}

/// Verified transport result. Role and capabilities remain authority-neutral.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedHandshake {
    peer: AuthenticatedPeer,
    role: synergy_protocol_types::NodeRole,
}

impl VerifiedHandshake {
    /// Authenticated transport peer produced by the verified proof.
    pub fn peer(&self) -> &AuthenticatedPeer {
        &self.peer
    }

    /// Advertised role; callers must not treat it as PoSy membership authority.
    pub const fn role(&self) -> synergy_protocol_types::NodeRole {
        self.role
    }

    /// Consumes the result and returns the authenticated peer for admission.
    pub fn into_peer(self) -> AuthenticatedPeer {
        self.peer
    }

    /// A verified transport handshake never determines PoSy finality.
    pub const fn may_determine_finality(&self) -> bool {
        false
    }
}

/// Error detected before a peer may enter the authenticated lifecycle state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeVerificationError<E> {
    Offer(OfferError),
    Challenge(ChallengeError),
    Compatibility(HandshakeError),
    SessionMismatch,
    NonceMismatch,
    InvalidSignatureLength,
    Transcript(HandshakeTranscriptError),
    Signature(E),
    Identity(PeerIdentityError),
}

/// Verifies freshness, session binding, compatibility, identity, and signature.
///
/// Successful verification authenticates transport only. The caller must use a
/// separate membership authority before any PoSy participation decision.
///
/// # Errors
/// Returns [`HandshakeVerificationError`] on any failed binding or verifier error.
pub fn verify_handshake<V: HandshakeSignatureVerifier>(
    offer: &HandshakeOffer,
    proof: &HandshakeProof,
    answer: &super::HandshakeChallenge,
    expected_metadata: &HandshakeMetadata,
    expected_session: SessionId,
    now: u64,
    verifier: &V,
) -> Result<VerifiedHandshake, HandshakeVerificationError<V::Error>> {
    if &offer.metadata.node_address != offer.identity.node_address() {
        return Err(HandshakeVerificationError::Offer(
            OfferError::IdentityMismatch,
        ));
    }
    offer
        .challenge
        .validate_at(now)
        .map_err(HandshakeVerificationError::Challenge)?;
    answer
        .validate_at(now)
        .map_err(HandshakeVerificationError::Challenge)?;
    offer
        .metadata
        .validate_against(expected_metadata)
        .map_err(HandshakeVerificationError::Compatibility)?;
    if proof.session_id != expected_session || proof.session_id.0 == 0 {
        return Err(HandshakeVerificationError::SessionMismatch);
    }
    if &proof.offer_nonce != offer.challenge.nonce() || &proof.answer_nonce != answer.nonce() {
        return Err(HandshakeVerificationError::NonceMismatch);
    }
    if proof.signature.is_empty() || proof.signature.len() > MAX_HANDSHAKE_SIGNATURE_BYTES {
        return Err(HandshakeVerificationError::InvalidSignatureLength);
    }
    let transcript = handshake_transcript(offer, proof.session_id, answer.nonce())
        .map_err(HandshakeVerificationError::Transcript)?;
    verifier
        .verify_handshake_signature(
            offer.identity.node_address().as_str(),
            offer.metadata.key_algorithm,
            &transcript,
            &proof.signature,
        )
        .map_err(HandshakeVerificationError::Signature)?;
    let peer = AuthenticatedPeer::new(
        offer.identity.node_address().as_str(),
        proof.session_id,
        offer.identity.capabilities().to_vec(),
    )
    .map_err(HandshakeVerificationError::Identity)?;
    Ok(VerifiedHandshake {
        peer,
        role: offer.identity.role(),
    })
}
