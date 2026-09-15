//! Canonical binary frame layout and structural parsing.

use synergy_protocol_types::{ProtocolKind, SessionId};

use super::{protocol_id, protocol_kind, FrameLimits, OutboundEnvelope};

/// Wire prefix for the new Synergy authenticated P2P frame format.
pub const FRAME_MAGIC: [u8; 4] = *b"SNPF";
/// Current canonical frame version.
pub const FRAME_VERSION: u16 = 1;
/// Bytes in the fixed frame header.
pub const FRAME_HEADER_BYTES: usize = 30;
const AUTHENTICATION_DOMAIN: &[u8] = b"SYNERGY-P2P-FRAME-AUTH-V1";

/// Structural frame error detected before protocol delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    EmptyPayload,
    Oversize { received: usize, maximum: usize },
    AuthenticatorRequired,
    AuthenticatorOversize { received: usize, maximum: usize },
    Truncated,
    TrailingBytes,
    InvalidMagic,
    UnsupportedVersion(u16),
    UnknownProtocol(u8),
    ReservedFlags(u8),
    InvalidSession,
    InvalidSequence,
    SessionMismatch,
    LengthOverflow,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "invalid authenticated P2P frame: {self:?}")
    }
}

impl std::error::Error for FrameError {}

pub(crate) struct ParsedFrame<'a> {
    pub protocol: ProtocolKind,
    pub session_id: SessionId,
    pub sequence: u64,
    pub payload: &'a [u8],
    pub authenticator: &'a [u8],
}

pub(crate) fn authentication_transcript(
    envelope: OutboundEnvelope<'_>,
    limits: FrameLimits,
) -> Result<Vec<u8>, FrameError> {
    validate_session(envelope.session_id, envelope.sequence)?;
    validate_payload(envelope.payload, limits)?;
    let payload_length =
        u32::try_from(envelope.payload.len()).map_err(|_| FrameError::LengthOverflow)?;
    let capacity = AUTHENTICATION_DOMAIN
        .len()
        .checked_add(2 + 1 + 8 + 8 + 4)
        .and_then(|length| length.checked_add(envelope.payload.len()))
        .ok_or(FrameError::LengthOverflow)?;
    let mut transcript = Vec::with_capacity(capacity);
    transcript.extend_from_slice(AUTHENTICATION_DOMAIN);
    transcript.extend_from_slice(&FRAME_VERSION.to_be_bytes());
    transcript.push(protocol_id(envelope.protocol));
    transcript.extend_from_slice(&envelope.session_id.0.to_be_bytes());
    transcript.extend_from_slice(&envelope.sequence.to_be_bytes());
    transcript.extend_from_slice(&payload_length.to_be_bytes());
    transcript.extend_from_slice(envelope.payload);
    Ok(transcript)
}

pub(crate) fn encode_wire(
    envelope: OutboundEnvelope<'_>,
    authenticator: &[u8],
    limits: FrameLimits,
) -> Result<Vec<u8>, FrameError> {
    validate_session(envelope.session_id, envelope.sequence)?;
    validate_payload(envelope.payload, limits)?;
    validate_authenticator(authenticator, limits)?;
    let payload_length =
        u32::try_from(envelope.payload.len()).map_err(|_| FrameError::LengthOverflow)?;
    let authenticator_length =
        u16::try_from(authenticator.len()).map_err(|_| FrameError::LengthOverflow)?;
    let capacity = FRAME_HEADER_BYTES
        .checked_add(envelope.payload.len())
        .and_then(|length| length.checked_add(authenticator.len()))
        .ok_or(FrameError::LengthOverflow)?;
    let mut wire = Vec::with_capacity(capacity);
    wire.extend_from_slice(&FRAME_MAGIC);
    wire.extend_from_slice(&FRAME_VERSION.to_be_bytes());
    wire.push(protocol_id(envelope.protocol));
    wire.push(0);
    wire.extend_from_slice(&envelope.session_id.0.to_be_bytes());
    wire.extend_from_slice(&envelope.sequence.to_be_bytes());
    wire.extend_from_slice(&payload_length.to_be_bytes());
    wire.extend_from_slice(&authenticator_length.to_be_bytes());
    wire.extend_from_slice(envelope.payload);
    wire.extend_from_slice(authenticator);
    Ok(wire)
}

pub(crate) fn parse_wire<'a>(
    wire: &'a [u8],
    limits: FrameLimits,
) -> Result<ParsedFrame<'a>, FrameError> {
    if wire.len() < FRAME_HEADER_BYTES {
        return Err(FrameError::Truncated);
    }
    if wire.get(0..4) != Some(FRAME_MAGIC.as_slice()) {
        return Err(FrameError::InvalidMagic);
    }
    let version = read_u16(&wire[4..6])?;
    if version != FRAME_VERSION {
        return Err(FrameError::UnsupportedVersion(version));
    }
    let protocol_identifier = wire[6];
    let protocol = protocol_kind(protocol_identifier)
        .map_err(|_| FrameError::UnknownProtocol(protocol_identifier))?;
    if wire[7] != 0 {
        return Err(FrameError::ReservedFlags(wire[7]));
    }
    let session_id = SessionId(read_u64(&wire[8..16])?);
    let sequence = read_u64(&wire[16..24])?;
    if session_id.0 == 0 {
        return Err(FrameError::InvalidSession);
    }
    if sequence == 0 {
        return Err(FrameError::InvalidSequence);
    }
    let payload_length = read_u32(&wire[24..28])? as usize;
    let authenticator_length = read_u16(&wire[28..30])? as usize;
    if payload_length > limits.max_payload_bytes() {
        return Err(FrameError::Oversize {
            received: payload_length,
            maximum: limits.max_payload_bytes(),
        });
    }
    if authenticator_length > limits.max_authenticator_bytes() {
        return Err(FrameError::AuthenticatorOversize {
            received: authenticator_length,
            maximum: limits.max_authenticator_bytes(),
        });
    }
    let total_length = FRAME_HEADER_BYTES
        .checked_add(payload_length)
        .and_then(|length| length.checked_add(authenticator_length))
        .ok_or(FrameError::LengthOverflow)?;
    if wire.len() < total_length {
        return Err(FrameError::Truncated);
    }
    if wire.len() != total_length {
        return Err(FrameError::TrailingBytes);
    }
    let payload_end = FRAME_HEADER_BYTES + payload_length;
    let payload = &wire[FRAME_HEADER_BYTES..payload_end];
    let authenticator = &wire[payload_end..total_length];
    validate_payload(payload, limits)?;
    validate_authenticator(authenticator, limits)?;
    Ok(ParsedFrame {
        protocol,
        session_id,
        sequence,
        payload,
        authenticator,
    })
}

fn validate_payload(payload: &[u8], limits: FrameLimits) -> Result<(), FrameError> {
    if payload.is_empty() {
        return Err(FrameError::EmptyPayload);
    }
    if payload.len() > limits.max_payload_bytes() {
        return Err(FrameError::Oversize {
            received: payload.len(),
            maximum: limits.max_payload_bytes(),
        });
    }
    Ok(())
}

fn validate_session(session_id: SessionId, sequence: u64) -> Result<(), FrameError> {
    if session_id.0 == 0 {
        return Err(FrameError::InvalidSession);
    }
    if sequence == 0 {
        return Err(FrameError::InvalidSequence);
    }
    Ok(())
}

fn validate_authenticator(authenticator: &[u8], limits: FrameLimits) -> Result<(), FrameError> {
    if authenticator.is_empty() {
        return Err(FrameError::AuthenticatorRequired);
    }
    if authenticator.len() > limits.max_authenticator_bytes() {
        return Err(FrameError::AuthenticatorOversize {
            received: authenticator.len(),
            maximum: limits.max_authenticator_bytes(),
        });
    }
    Ok(())
}

fn read_u16(bytes: &[u8]) -> Result<u16, FrameError> {
    let value: [u8; 2] = bytes.try_into().map_err(|_| FrameError::Truncated)?;
    Ok(u16::from_be_bytes(value))
}

fn read_u32(bytes: &[u8]) -> Result<u32, FrameError> {
    let value: [u8; 4] = bytes.try_into().map_err(|_| FrameError::Truncated)?;
    Ok(u32::from_be_bytes(value))
}

fn read_u64(bytes: &[u8]) -> Result<u64, FrameError> {
    let value: [u8; 8] = bytes.try_into().map_err(|_| FrameError::Truncated)?;
    Ok(u64::from_be_bytes(value))
}
