use synergy_protocol_types::ProtocolKind;

use crate::{AdapterEnvelope, AdapterError, ProtocolAdapter};

#[derive(Debug, Default)]
pub struct StatusAdapter;

impl ProtocolAdapter for StatusAdapter {
    fn protocol(&self) -> ProtocolKind {
        ProtocolKind::Status
    }
}

impl StatusAdapter {
    pub fn accept_status(
        &self,
        envelope: AdapterEnvelope,
    ) -> Result<AdapterEnvelope, AdapterError> {
        self.accept(envelope)
    }
}
