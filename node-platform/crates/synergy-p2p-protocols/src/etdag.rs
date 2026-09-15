use synergy_protocol_types::{AuthenticatedPeer, ProtocolKind};

use crate::{AdapterEnvelope, AdapterError, ProtocolAdapter};

/// ETDAG transport adapter. ETDAG owns encrypted admission, DAG validation,
/// certification, protected ordering, reveal, decrypt shares, and recovery.
pub trait EtdagMessageSink {
    fn receive_etdag(&mut self, peer: AuthenticatedPeer, payload: Vec<u8>) -> Result<(), String>;
}

#[derive(Debug, Default)]
pub struct EtdagAdapter;

impl ProtocolAdapter for EtdagAdapter {
    fn protocol(&self) -> ProtocolKind {
        ProtocolKind::Etdag
    }
}

impl EtdagAdapter {
    pub fn deliver<S: EtdagMessageSink>(
        &self,
        envelope: AdapterEnvelope,
        sink: &mut S,
    ) -> Result<(), AdapterError> {
        let envelope = self.accept(envelope)?;
        if envelope.payload.is_empty() {
            return Err(AdapterError::EmptyPayload);
        }
        sink.receive_etdag(envelope.peer, envelope.payload)
            .map_err(AdapterError::Consumer)
    }
}
