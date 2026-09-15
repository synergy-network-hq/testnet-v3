//! Canonical handshake transcript construction and proof signing.

use synergy_protocol_types::{NodeRole, SessionId};

use super::{HandshakeChallenge, HandshakeOffer, HandshakeProof, PeerKeyAlgorithm};

const HANDSHAKE_DOMAIN: &[u8] = b"SYNERGY-P2P-HANDSHAKE-V1";
const MAX_TRANSCRIPT_FIELD_BYTES: usize = u16::MAX as usize;
pub(crate) const MAX_HANDSHAKE_SIGNATURE_BYTES: usize = 16_384;

/// Signs a canonical handshake transcript with the offered peer identity key.
pub trait HandshakeSigner {
    type Error;

    /// Signs the exact domain-separated transcript using `algorithm`.
    fn sign_handshake(
        &self,
        algorithm: PeerKeyAlgorithm,
        transcript: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;
}

/// Canonical transcript construction failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeTranscriptError {
    InvalidSession,
    FieldTooLong,
    LengthOverflow,
    InvalidSignatureLength,
}

/// Error while constructing a signed handshake proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeSignError<E> {
    Transcript(HandshakeTranscriptError),
    Signer(E),
}

/// Builds a nonce- and session-bound proof using static signer dispatch.
///
/// # Errors
/// Returns transcript construction errors or the signer implementation's error.
pub fn build_handshake_proof<S: HandshakeSigner>(
    offer: &HandshakeOffer,
    session_id: SessionId,
    answer: &HandshakeChallenge,
    signer: &S,
) -> Result<HandshakeProof, HandshakeSignError<S::Error>> {
    let transcript = handshake_transcript(offer, session_id, answer.nonce())
        .map_err(HandshakeSignError::Transcript)?;
    let signature = signer
        .sign_handshake(offer.metadata.key_algorithm, &transcript)
        .map_err(HandshakeSignError::Signer)?;
    if signature.is_empty() || signature.len() > MAX_HANDSHAKE_SIGNATURE_BYTES {
        return Err(HandshakeSignError::Transcript(
            HandshakeTranscriptError::InvalidSignatureLength,
        ));
    }
    Ok(HandshakeProof {
        session_id,
        offer_nonce: *offer.challenge.nonce(),
        answer_nonce: *answer.nonce(),
        signature,
    })
}

pub(crate) fn handshake_transcript(
    offer: &HandshakeOffer,
    session_id: SessionId,
    answer_nonce: &[u8; 32],
) -> Result<Vec<u8>, HandshakeTranscriptError> {
    if session_id.0 == 0 {
        return Err(HandshakeTranscriptError::InvalidSession);
    }
    let mut transcript = Vec::with_capacity(512);
    transcript.extend_from_slice(HANDSHAKE_DOMAIN);
    transcript.extend_from_slice(&session_id.0.to_be_bytes());
    transcript.extend_from_slice(offer.challenge.nonce());
    transcript.extend_from_slice(answer_nonce);
    push_field(
        &mut transcript,
        offer.metadata.node_address.as_str().as_bytes(),
    )?;
    push_field(&mut transcript, offer.metadata.network_id.as_bytes())?;
    push_field(&mut transcript, offer.metadata.genesis_hash.as_bytes())?;
    push_field(&mut transcript, offer.metadata.protocol_version.as_bytes())?;
    transcript.push(key_algorithm_id(offer.metadata.key_algorithm));
    transcript.push(role_id(offer.identity.role()));
    let capability_count = u16::try_from(offer.identity.capabilities().len())
        .map_err(|_| HandshakeTranscriptError::LengthOverflow)?;
    transcript.extend_from_slice(&capability_count.to_be_bytes());
    for capability in offer.identity.capabilities() {
        push_field(&mut transcript, capability.as_bytes())?;
    }
    Ok(transcript)
}

fn push_field(target: &mut Vec<u8>, value: &[u8]) -> Result<(), HandshakeTranscriptError> {
    if value.len() > MAX_TRANSCRIPT_FIELD_BYTES {
        return Err(HandshakeTranscriptError::FieldTooLong);
    }
    let length = u16::try_from(value.len()).map_err(|_| HandshakeTranscriptError::FieldTooLong)?;
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(value);
    Ok(())
}

const fn key_algorithm_id(algorithm: PeerKeyAlgorithm) -> u8 {
    match algorithm {
        PeerKeyAlgorithm::Fndsa => 1,
        PeerKeyAlgorithm::Mldsa65 => 2,
        PeerKeyAlgorithm::Mldsa87 => 3,
    }
}

const fn role_id(role: NodeRole) -> u8 {
    match role {
        NodeRole::Validator => 1,
        NodeRole::Sentry => 2,
        NodeRole::Archive => 3,
        NodeRole::ConsensusAudit => 4,
        NodeRole::CrossChain => 5,
        NodeRole::Witness => 6,
        NodeRole::Oracle => 7,
        NodeRole::UmaCoordinator => 8,
        NodeRole::SynqExecution => 9,
        NodeRole::NetworkAnalytics => 10,
        NodeRole::AegisCryptography => 11,
        NodeRole::DataAvailability => 12,
        NodeRole::AiCompute => 13,
        NodeRole::AiCoordination => 14,
        NodeRole::AiData => 15,
        NodeRole::AiAssurance => 16,
        NodeRole::RpcGateway => 17,
        NodeRole::Indexer => 18,
        NodeRole::ObserverLight => 19,
        NodeRole::Bootseed => 20,
    }
}
