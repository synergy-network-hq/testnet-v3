use super::SentryCapabilities;
use crate::{
    protocol::InboundFrame,
    router::{BoundedPeerRouter, RouterAdmissionError},
};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SentryForwardError {
    ProtocolDenied,
    Overloaded(RouterAdmissionError),
}
/// Bounded forwarding queue shared by the Sentry's permitted public/overlay
/// paths. Payload semantics remain opaque to this perimeter component.
#[derive(Debug)]
pub struct SentryForwarder {
    capabilities: SentryCapabilities,
    router: BoundedPeerRouter,
}
impl SentryForwarder {
    pub fn new(capacity: usize, per_peer_capacity: usize) -> Self {
        Self {
            capabilities: SentryCapabilities::default(),
            router: BoundedPeerRouter::new(capacity, per_peer_capacity),
        }
    }
    pub fn forward(&mut self, frame: InboundFrame) -> Result<(), SentryForwardError> {
        if !self.capabilities.allows(frame.protocol) {
            return Err(SentryForwardError::ProtocolDenied);
        }
        self.router
            .try_admit(frame)
            .map_err(SentryForwardError::Overloaded)
    }
    pub fn try_next(&mut self) -> Option<InboundFrame> {
        self.router.try_next()
    }
    pub fn capabilities(&self) -> SentryCapabilities {
        self.capabilities
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use synergy_protocol_types::{AuthenticatedPeer, ProtocolKind, SessionId};
    fn frame(protocol: ProtocolKind) -> InboundFrame {
        InboundFrame::new(
            AuthenticatedPeer::new(
                "synv51lrh6jcxaejkj4zv994j7qwn2rk6u38z5nwn",
                SessionId(1),
                vec![],
            )
            .unwrap(),
            protocol,
            vec![1],
            8,
        )
        .unwrap()
    }
    #[test]
    fn forwards_only_permitted_opaque_protocol_traffic() {
        let mut f = SentryForwarder::new(2, 2);
        assert!(f.forward(frame(ProtocolKind::Posy)).is_ok());
        assert_eq!(
            f.forward(frame(ProtocolKind::Snapshot)),
            Err(SentryForwardError::ProtocolDenied)
        );
        assert_eq!(f.try_next().unwrap().protocol, ProtocolKind::Posy)
    }
    #[test]
    fn overload_is_contained_to_admission() {
        let mut f = SentryForwarder::new(1, 1);
        f.forward(frame(ProtocolKind::Sync)).unwrap();
        assert_eq!(
            f.forward(frame(ProtocolKind::Sync)),
            Err(SentryForwardError::Overloaded(
                RouterAdmissionError::GlobalCapacity
            ))
        );
    }
}
