use synergy_protocol_types::{AuthenticatedPeer, ProtocolKind};

use crate::{AdapterEnvelope, AdapterError, ProtocolAdapter};

/// Verified Sync owns head evidence, block continuity, checkpoint validation,
/// and state import. This adapter only delivers authenticated bounded Sync
/// payloads and never treats an advertised head as finality evidence.
pub trait StateSyncMessageSink {
    fn receive_state_sync(
        &mut self,
        peer: AuthenticatedPeer,
        payload: Vec<u8>,
    ) -> Result<(), String>;
}

/// Explicit authenticated delivery boundary for head, block, and state-sync
/// messages. Semantic decoding stays with the verified Sync owner.
#[derive(Debug, Default)]
pub struct StateSyncAdapter;

impl ProtocolAdapter for StateSyncAdapter {
    fn protocol(&self) -> ProtocolKind {
        ProtocolKind::Sync
    }
}

impl StateSyncAdapter {
    pub fn deliver<S: StateSyncMessageSink>(
        &self,
        envelope: AdapterEnvelope,
        sink: &mut S,
    ) -> Result<(), AdapterError> {
        let envelope = self.accept(envelope)?;
        if envelope.payload.is_empty() {
            return Err(AdapterError::EmptyPayload);
        }
        sink.receive_state_sync(envelope.peer, envelope.payload)
            .map_err(AdapterError::Consumer)
    }
}
