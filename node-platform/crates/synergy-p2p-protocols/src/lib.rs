//! Authenticated protocol adapters downstream of the bounded P2P router.
//!
//! Adapters route opaque authenticated envelopes to the owning subsystem. They
//! never grant authority, calculate quorum, decide finality, alter membership,
//! validate PoSy/ETDAG semantics, or own raw sockets.

mod block_sync;
mod errors;
mod etdag;
mod observer;
mod peer_exchange;
mod posy;
mod snapshot;
mod state_sync;
mod status;
mod sxcp;
mod transaction;

use synergy_network::protocol::InboundFrame;
use synergy_protocol_types::{AuthenticatedPeer, ProtocolKind};

pub use block_sync::{SyncAdapter, SyncMessageSink};
pub use errors::AdapterError;
pub use etdag::{EtdagAdapter, EtdagMessageSink};
pub use observer::{ObserverAdapter, ObserverMessageSink};
pub use peer_exchange::PeerExchangeAdapter;
pub use posy::{PosyAdapter, PosyMessageSink};
pub use snapshot::SnapshotAdapter;
pub use state_sync::{StateSyncAdapter, StateSyncMessageSink};
pub use status::StatusAdapter;
pub use sxcp::{SxcpAdapter, SxcpMessageSink};
pub use transaction::TransactionAdapter;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterEnvelope {
    pub peer: AuthenticatedPeer,
    pub protocol: ProtocolKind,
    pub payload: Vec<u8>,
}

impl From<InboundFrame> for AdapterEnvelope {
    fn from(frame: InboundFrame) -> Self {
        Self {
            peer: frame.peer,
            protocol: frame.protocol,
            payload: frame.payload,
        }
    }
}

pub trait ProtocolAdapter {
    fn protocol(&self) -> ProtocolKind;

    fn accept(&self, envelope: AdapterEnvelope) -> Result<AdapterEnvelope, AdapterError> {
        (envelope.protocol == self.protocol())
            .then_some(envelope)
            .ok_or(AdapterError::WrongProtocol)
    }

    fn may_determine_finality(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use synergy_protocol_types::SessionId;

    fn envelope(protocol: ProtocolKind) -> AdapterEnvelope {
        AdapterEnvelope {
            peer: AuthenticatedPeer::new(
                "synv51lrh6jcxaejkj4zv994j7qwn2rk6u38z5nwn",
                SessionId(1),
                vec!["v1".into()],
            )
            .unwrap(),
            protocol,
            payload: vec![7],
        }
    }

    struct RecordingPosy(Vec<u8>);
    impl PosyMessageSink for RecordingPosy {
        fn receive_posy(&mut self, _: AuthenticatedPeer, payload: Vec<u8>) -> Result<(), String> {
            self.0 = payload;
            Ok(())
        }
    }

    #[test]
    fn adapters_route_only_their_own_protocol() {
        assert!(PosyAdapter.accept(envelope(ProtocolKind::Posy)).is_ok());
        assert!(EtdagAdapter.accept(envelope(ProtocolKind::Etdag)).is_ok());
        assert!(SyncAdapter.accept(envelope(ProtocolKind::Sync)).is_ok());
        assert_eq!(
            PosyAdapter.accept(envelope(ProtocolKind::Sync)),
            Err(AdapterError::WrongProtocol)
        );
    }

    #[test]
    fn adapter_delivers_opaque_posy_bytes_without_consensus_authority() {
        let mut sink = RecordingPosy(Vec::new());
        PosyAdapter
            .deliver(envelope(ProtocolKind::Posy), &mut sink)
            .unwrap();
        assert_eq!(sink.0, vec![7]);
        assert!(!PosyAdapter.may_determine_finality());
    }

    #[test]
    fn empty_payload_is_rejected_before_consumer_delivery() {
        let mut sink = RecordingPosy(Vec::new());
        let mut message = envelope(ProtocolKind::Posy);
        message.payload.clear();
        assert_eq!(
            PosyAdapter.deliver(message, &mut sink),
            Err(AdapterError::EmptyPayload)
        );
    }
}
