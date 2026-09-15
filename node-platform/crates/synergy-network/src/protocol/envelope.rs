//! Session-bound envelope types on either side of frame authentication.

use synergy_protocol_types::{AuthenticatedPeer, ProtocolKind, SessionId};

use super::{FrameError, InboundFrame};

/// Borrowed outbound payload bound to one authenticated session and sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutboundEnvelope<'a> {
    pub protocol: ProtocolKind,
    pub session_id: SessionId,
    pub sequence: u64,
    pub payload: &'a [u8],
}

impl<'a> OutboundEnvelope<'a> {
    /// Creates a session-bound outbound envelope.
    ///
    /// # Errors
    /// Returns [`FrameError`] when the session, sequence, or payload is invalid.
    pub fn new(
        protocol: ProtocolKind,
        session_id: SessionId,
        sequence: u64,
        payload: &'a [u8],
    ) -> Result<Self, FrameError> {
        if session_id.0 == 0 {
            return Err(FrameError::InvalidSession);
        }
        if sequence == 0 {
            return Err(FrameError::InvalidSequence);
        }
        if payload.is_empty() {
            return Err(FrameError::EmptyPayload);
        }
        Ok(Self {
            protocol,
            session_id,
            sequence,
            payload,
        })
    }
}

/// Structurally decoded envelope whose authenticator has been verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedEnvelope {
    protocol: ProtocolKind,
    session_id: SessionId,
    sequence: u64,
    payload: Vec<u8>,
}

impl DecodedEnvelope {
    pub(crate) fn authenticated(
        protocol: ProtocolKind,
        session_id: SessionId,
        sequence: u64,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            protocol,
            session_id,
            sequence,
            payload,
        }
    }

    /// Authenticated authority-neutral protocol route.
    pub const fn protocol(&self) -> ProtocolKind {
        self.protocol
    }

    /// Exact authenticated session carried by the frame.
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Caller-managed monotonically increasing replay sequence.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Opaque authenticated protocol payload.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Converts verified bytes to router input for the exact authenticated peer.
    ///
    /// # Errors
    /// Returns [`FrameError::SessionMismatch`] if the authenticated peer belongs
    /// to a different connection, or an oversize error if `maximum` is smaller.
    pub fn into_inbound(
        self,
        peer: AuthenticatedPeer,
        maximum: usize,
    ) -> Result<InboundFrame, FrameError> {
        if peer.session_id != self.session_id {
            return Err(FrameError::SessionMismatch);
        }
        InboundFrame::new(peer, self.protocol, self.payload, maximum)
    }
}
