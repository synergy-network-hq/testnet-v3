use synergy_protocol_types::{AuthenticatedPeer, ProtocolKind};

use crate::{AdapterEnvelope, AdapterError, ProtocolAdapter};

pub trait ObserverMessageSink {
    fn receive_observer(&mut self, peer: AuthenticatedPeer, payload: Vec<u8>)
        -> Result<(), String>;
}

#[derive(Debug, Default)]
pub struct ObserverAdapter;

impl ProtocolAdapter for ObserverAdapter {
    fn protocol(&self) -> ProtocolKind {
        ProtocolKind::Observer
    }
}

impl ObserverAdapter {
    pub fn deliver(
        &self,
        envelope: AdapterEnvelope,
        sink: &mut impl ObserverMessageSink,
    ) -> Result<(), AdapterError> {
        let envelope = self.accept(envelope)?;
        if envelope.payload.is_empty() {
            return Err(AdapterError::EmptyPayload);
        }
        sink.receive_observer(envelope.peer, envelope.payload)
            .map_err(AdapterError::Consumer)
    }
}
