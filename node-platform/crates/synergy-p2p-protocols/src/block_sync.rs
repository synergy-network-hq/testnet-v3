use synergy_protocol_types::{AuthenticatedPeer, ProtocolKind};

use crate::{AdapterEnvelope, AdapterError, ProtocolAdapter};

/// Verified Sync owns evidence and source trust. This adapter cannot promote an
/// advertised head, import a block, or authorize a validator to sign.
pub trait SyncMessageSink {
    fn receive_sync(&mut self, peer: AuthenticatedPeer, payload: Vec<u8>) -> Result<(), String>;
}

#[derive(Debug, Default)]
pub struct SyncAdapter;

impl ProtocolAdapter for SyncAdapter {
    fn protocol(&self) -> ProtocolKind {
        ProtocolKind::Sync
    }
}

impl SyncAdapter {
    pub fn deliver<S: SyncMessageSink>(
        &self,
        envelope: AdapterEnvelope,
        sink: &mut S,
    ) -> Result<(), AdapterError> {
        let envelope = self.accept(envelope)?;
        if envelope.payload.is_empty() {
            return Err(AdapterError::EmptyPayload);
        }
        sink.receive_sync(envelope.peer, envelope.payload)
            .map_err(AdapterError::Consumer)
    }
}
