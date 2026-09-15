use synergy_protocol_types::{AuthenticatedPeer, ProtocolKind};

use crate::{AdapterEnvelope, AdapterError, ProtocolAdapter};

/// PoSy transport adapter. The sink owns decoding, signature checks, quorum,
/// membership, safety state, and finality; this type performs none of them.
pub trait PosyMessageSink {
    fn receive_posy(&mut self, peer: AuthenticatedPeer, payload: Vec<u8>) -> Result<(), String>;
}

#[derive(Debug, Default)]
pub struct PosyAdapter;

impl ProtocolAdapter for PosyAdapter {
    fn protocol(&self) -> ProtocolKind {
        ProtocolKind::Posy
    }
}

impl PosyAdapter {
    pub fn deliver<S: PosyMessageSink>(
        &self,
        envelope: AdapterEnvelope,
        sink: &mut S,
    ) -> Result<(), AdapterError> {
        let envelope = self.accept(envelope)?;
        if envelope.payload.is_empty() {
            return Err(AdapterError::EmptyPayload);
        }
        sink.receive_posy(envelope.peer, envelope.payload)
            .map_err(AdapterError::Consumer)
    }
}
