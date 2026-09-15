use std::collections::BTreeMap;

use synergy_protocol_types::ProtocolKind;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkMetrics {
    pub inbound_connections: usize,
    pub outbound_connections: usize,
    pub authenticated_peers: usize,
    pub ready_peers: usize,
    pub received_frames: u64,
    pub sent_frames: u64,
    pub rejected_frames: u64,
    pub reconnect_attempts: u64,
    pub frames_by_protocol: BTreeMap<ProtocolKind, u64>,
}

impl NetworkMetrics {
    pub fn record_received(&mut self, protocol: ProtocolKind) {
        self.received_frames = self.received_frames.saturating_add(1);
        let counter = self.frames_by_protocol.entry(protocol).or_default();
        *counter = counter.saturating_add(1);
    }

    pub fn record_sent(&mut self) {
        self.sent_frames = self.sent_frames.saturating_add(1);
    }

    pub fn record_rejected(&mut self) {
        self.rejected_frames = self.rejected_frames.saturating_add(1);
    }

    pub fn record_reconnect(&mut self) {
        self.reconnect_attempts = self.reconnect_attempts.saturating_add(1);
    }
}
