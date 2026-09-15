use synergy_protocol_types::ProtocolKind;

use crate::{AdapterEnvelope, AdapterError, ProtocolAdapter};

/// Discovery candidates remain untrusted until handshake and peer policy admit
/// them. Peer exchange cannot grant any consensus capability.
#[derive(Debug, Default)]
pub struct PeerExchangeAdapter;

impl ProtocolAdapter for PeerExchangeAdapter {
    fn protocol(&self) -> ProtocolKind {
        ProtocolKind::Discovery
    }
}

impl PeerExchangeAdapter {
    pub fn accept_candidate(
        &self,
        envelope: AdapterEnvelope,
    ) -> Result<AdapterEnvelope, AdapterError> {
        self.accept(envelope)
    }
}
