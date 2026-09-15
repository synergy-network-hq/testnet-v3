use synergy_protocol_types::ProtocolKind;

use crate::{AdapterEnvelope, AdapterError, ProtocolAdapter};

#[derive(Debug, Default)]
pub struct TransactionAdapter;

impl ProtocolAdapter for TransactionAdapter {
    fn protocol(&self) -> ProtocolKind {
        ProtocolKind::Transaction
    }
}

impl TransactionAdapter {
    pub fn accept_transaction(
        &self,
        envelope: AdapterEnvelope,
    ) -> Result<AdapterEnvelope, AdapterError> {
        self.accept(envelope)
    }
}
