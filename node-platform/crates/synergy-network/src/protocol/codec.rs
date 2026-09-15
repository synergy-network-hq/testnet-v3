//! Statically dispatched frame authentication at the socket/codec boundary.

use super::{
    framing::{authentication_transcript, encode_wire, parse_wire},
    DecodedEnvelope, FrameError, FrameLimits, OutboundEnvelope,
};

/// Produces an authenticator for one canonical frame transcript.
pub trait FrameSigner {
    type Error;

    /// Signs or authenticates exactly the supplied domain-separated transcript.
    fn sign_frame(&self, transcript: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

/// Verifies an authenticator for one canonical frame transcript.
pub trait FrameVerifier {
    type Error;

    /// Verifies `authenticator` against exactly `transcript`.
    fn verify_frame(&self, transcript: &[u8], authenticator: &[u8]) -> Result<(), Self::Error>;
}

/// Error while producing an authenticated wire frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameEncodeError<E> {
    Frame(FrameError),
    Authentication(E),
}

/// Error while structurally decoding and authenticating a wire frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameDecodeError<E> {
    Frame(FrameError),
    Authentication(E),
}

/// Encodes and authenticates one session-bound envelope.
///
/// # Errors
/// Returns a structural frame error or the signer implementation's error.
pub fn encode_authenticated<S: FrameSigner>(
    envelope: OutboundEnvelope<'_>,
    limits: FrameLimits,
    signer: &S,
) -> Result<Vec<u8>, FrameEncodeError<S::Error>> {
    let transcript =
        authentication_transcript(envelope, limits).map_err(FrameEncodeError::Frame)?;
    let authenticator = signer
        .sign_frame(&transcript)
        .map_err(FrameEncodeError::Authentication)?;
    encode_wire(envelope, &authenticator, limits).map_err(FrameEncodeError::Frame)
}

/// Parses and authenticates one complete wire frame before allocating payload output.
///
/// # Errors
/// Returns a structural frame error or the verifier implementation's error.
pub fn decode_authenticated<V: FrameVerifier>(
    wire: &[u8],
    limits: FrameLimits,
    verifier: &V,
) -> Result<DecodedEnvelope, FrameDecodeError<V::Error>> {
    let parsed = parse_wire(wire, limits).map_err(FrameDecodeError::Frame)?;
    let unsigned = OutboundEnvelope::new(
        parsed.protocol,
        parsed.session_id,
        parsed.sequence,
        parsed.payload,
    )
    .map_err(FrameDecodeError::Frame)?;
    let transcript =
        authentication_transcript(unsigned, limits).map_err(FrameDecodeError::Frame)?;
    verifier
        .verify_frame(&transcript, parsed.authenticator)
        .map_err(FrameDecodeError::Authentication)?;
    Ok(DecodedEnvelope::authenticated(
        parsed.protocol,
        parsed.session_id,
        parsed.sequence,
        parsed.payload.to_vec(),
    ))
}
