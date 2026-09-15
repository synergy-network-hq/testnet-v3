use synergy_protocol_types::{AuthenticatedPeer, ProtocolKind};

use crate::{AdapterEnvelope, AdapterError, ProtocolAdapter};

pub trait SxcpMessageSink {
    fn receive_sxcp(&mut self, peer: AuthenticatedPeer, payload: Vec<u8>) -> Result<(), String>;
}

#[derive(Debug, Default)]
pub struct SxcpAdapter;

impl ProtocolAdapter for SxcpAdapter {
    fn protocol(&self) -> ProtocolKind {
        ProtocolKind::Sxcp
    }
}

impl SxcpAdapter {
    pub fn deliver(
        &self,
        envelope: AdapterEnvelope,
        sink: &mut impl SxcpMessageSink,
    ) -> Result<(), AdapterError> {
        let envelope = self.accept(envelope)?;
        if envelope.payload.is_empty() {
            return Err(AdapterError::EmptyPayload);
        }
        sink.receive_sxcp(envelope.peer, envelope.payload)
            .map_err(AdapterError::Consumer)
    }
}
