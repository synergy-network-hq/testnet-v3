//! Canonical authenticated framing for bounded Synergy P2P sessions.

mod aegis;
mod codec;
mod compatibility;
mod envelope;
mod framing;
mod id;
mod registry;
mod size_limits;
mod version;

pub use aegis::{AegisFrameSigner, AegisFrameVerifier};
pub use codec::{
    decode_authenticated, encode_authenticated, FrameDecodeError, FrameEncodeError, FrameSigner,
    FrameVerifier,
};
pub use compatibility::{check_protocol_compatibility, ProtocolCompatibilityError};
pub use envelope::{DecodedEnvelope, OutboundEnvelope};
pub use framing::{FrameError, FRAME_HEADER_BYTES, FRAME_MAGIC, FRAME_VERSION};
pub use id::{protocol_id, protocol_kind, ProtocolIdError};
pub use registry::{ProtocolRegistration, ProtocolRegistry, ProtocolRegistryError};
pub use size_limits::{FrameLimitError, FrameLimits};
pub use version::ProtocolVersion;

use synergy_protocol_types::{AuthenticatedPeer, ProtocolKind};

/// Default maximum opaque protocol payload size.
pub const DEFAULT_MAX_FRAME_BYTES: usize = 1_048_576;

/// An authenticated, bounded transport frame. Its payload remains opaque to
/// networking; the destination adapter owns validation and interpretation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundFrame {
    pub peer: AuthenticatedPeer,
    pub protocol: ProtocolKind,
    pub payload: Vec<u8>,
}

impl InboundFrame {
    /// Creates a bounded frame after session authentication has completed.
    ///
    /// # Errors
    /// Returns [`FrameError::Oversize`] when `payload` exceeds `maximum`.
    pub fn new(
        peer: AuthenticatedPeer,
        protocol: ProtocolKind,
        payload: Vec<u8>,
        maximum: usize,
    ) -> Result<Self, FrameError> {
        if payload.len() > maximum {
            return Err(FrameError::Oversize {
                received: payload.len(),
                maximum,
            });
        }
        Ok(Self {
            peer,
            protocol,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use synergy_protocol_types::SessionId;
    #[test]
    fn rejects_oversize_frame_before_protocol_delivery() {
        let peer = AuthenticatedPeer::new(
            "synv51lrh6jcxaejkj4zv994j7qwn2rk6u38z5nwn",
            SessionId(1),
            vec![],
        )
        .unwrap();
        assert_eq!(
            InboundFrame::new(peer, ProtocolKind::Posy, vec![0; 3], 2),
            Err(FrameError::Oversize {
                received: 3,
                maximum: 2
            })
        );
    }
}
