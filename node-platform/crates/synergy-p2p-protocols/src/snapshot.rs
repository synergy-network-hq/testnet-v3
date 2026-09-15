use synergy_protocol_types::ProtocolKind;

use crate::{AdapterEnvelope, AdapterError, ProtocolAdapter};

#[derive(Debug, Default)]
pub struct SnapshotAdapter;

impl ProtocolAdapter for SnapshotAdapter {
    fn protocol(&self) -> ProtocolKind {
        ProtocolKind::Snapshot
    }
}

impl SnapshotAdapter {
    pub fn accept_snapshot(
        &self,
        envelope: AdapterEnvelope,
    ) -> Result<AdapterEnvelope, AdapterError> {
        self.accept(envelope)
    }
}
