use super::{SentryCapabilities, SentryFilter, SentryFilterError};
use crate::{
    protocol::{decode_session_payload, FrameError, InboundFrame},
    router::{BoundedPeerRouter, RouterAdmissionError},
};
use synergy_protocol_types::{AuthenticatedPeer, SessionId};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SentryForwardError {
    ProtocolDenied,
    Overloaded(RouterAdmissionError),
}
/// Failure before an authenticated session payload enters the forwarding queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SentryIngressError {
    Payload(&'static str),
    Frame(FrameError),
    Policy(SentryFilterError),
    Forward(SentryForwardError),
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
    /// Admits the existing APQE routing payload after the native session owner
    /// has authenticated the peer, confirmed keys, and checked current authority.
    ///
    /// This adapter does not authenticate raw socket bytes or qualify a session
    /// profile. The caller must bind `peer` to that established session and pass
    /// only its authenticated plaintext. Replay checks remain session-owned.
    /// Queue admission grants no destination, private route, or finality authority;
    /// the dispatch owner must separately resolve an authorized validator link.
    pub fn forward_session_payload(
        &mut self,
        peer: AuthenticatedPeer,
        authenticated_plaintext: &[u8],
        maximum: usize,
        policy: &SentryFilter,
    ) -> Result<(), SentryIngressError> {
        if peer.session_id.0 == 0 {
            return Err(SentryIngressError::Frame(FrameError::InvalidSession));
        }
        let (protocol, payload) = decode_session_payload(authenticated_plaintext, maximum)
            .map_err(SentryIngressError::Payload)?;
        let frame = InboundFrame::new(peer, protocol, payload.to_vec(), maximum)
            .map_err(SentryIngressError::Frame)?;
        policy.permit(&frame).map_err(SentryIngressError::Policy)?;
        self.forward(frame).map_err(SentryIngressError::Forward)
    }
    pub fn try_next(&mut self) -> Option<InboundFrame> {
        self.router.try_next()
    }
    /// Drops only queued frames from this exact closed or retired session.
    /// Persistent node membership and any replacement session remain unchanged.
    pub fn discard_session(&mut self, node_address: &str, session: SessionId) -> usize {
        self.router.discard_session(node_address, session)
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

    fn sync_policy(maximum: usize) -> SentryFilter {
        SentryFilter::new([ProtocolKind::Sync].into_iter().collect(), maximum).unwrap()
    }

    // These are post-authentication routing tests, not cryptographic or live
    // session qualification. The real APQE payload codec is exercised directly.
    #[test]
    fn session_payload_preserves_authenticated_peer_protocol_and_exact_bytes() {
        let peer = frame(ProtocolKind::Sync).peer;
        let payload = b"opaque signed owner payload";
        let wire =
            crate::protocol::encode_session_payload(ProtocolKind::Sync, payload, 64).unwrap();
        let mut forwarder = SentryForwarder::new(2, 2);
        forwarder
            .forward_session_payload(peer.clone(), &wire, 64, &sync_policy(64))
            .unwrap();
        let delivered = forwarder.try_next().unwrap();
        assert_eq!(delivered.peer, peer);
        assert_eq!(delivered.protocol, ProtocolKind::Sync);
        assert_eq!(delivered.payload, payload);
        assert!(forwarder.try_next().is_none());
    }

    #[test]
    fn session_payload_policy_rejection_never_enters_queue() {
        let peer = frame(ProtocolKind::Posy).peer;
        let wire = crate::protocol::encode_session_payload(ProtocolKind::Posy, b"owner bytes", 64)
            .unwrap();
        let mut forwarder = SentryForwarder::new(2, 2);
        assert_eq!(
            forwarder.forward_session_payload(peer, &wire, 64, &sync_policy(64)),
            Err(SentryIngressError::Policy(SentryFilterError::Denied))
        );
        assert!(forwarder.try_next().is_none());
    }

    #[test]
    fn malformed_or_oversized_session_payload_never_enters_queue() {
        let peer = frame(ProtocolKind::Sync).peer;
        let wire = crate::protocol::encode_session_payload(ProtocolKind::Sync, b"owner bytes", 64)
            .unwrap();
        let mut forwarder = SentryForwarder::new(2, 2);
        assert!(matches!(
            forwarder.forward_session_payload(peer.clone(), &wire, 2, &sync_policy(64)),
            Err(SentryIngressError::Payload(_))
        ));
        let mut malformed = wire;
        malformed[0] = 2;
        assert!(matches!(
            forwarder.forward_session_payload(peer, &malformed, 64, &sync_policy(64)),
            Err(SentryIngressError::Payload(_))
        ));
        assert!(forwarder.try_next().is_none());
    }

    #[test]
    fn session_payload_requires_nonzero_authenticated_session() {
        let mut peer = frame(ProtocolKind::Sync).peer;
        peer.session_id = SessionId(0);
        let wire = crate::protocol::encode_session_payload(ProtocolKind::Sync, b"owner bytes", 64)
            .unwrap();
        let mut forwarder = SentryForwarder::new(2, 2);
        assert_eq!(
            forwarder.forward_session_payload(peer, &wire, 64, &sync_policy(64)),
            Err(SentryIngressError::Frame(FrameError::InvalidSession))
        );
        assert!(forwarder.try_next().is_none());
    }

    #[test]
    fn session_payload_policy_cannot_expand_sentry_protocol_capabilities() {
        let peer = frame(ProtocolKind::Snapshot).peer;
        let wire =
            crate::protocol::encode_session_payload(ProtocolKind::Snapshot, b"owner bytes", 64)
                .unwrap();
        let policy = SentryFilter::new([ProtocolKind::Snapshot].into_iter().collect(), 64).unwrap();
        let mut forwarder = SentryForwarder::new(2, 2);
        assert_eq!(
            forwarder.forward_session_payload(peer, &wire, 64, &policy),
            Err(SentryIngressError::Forward(
                SentryForwardError::ProtocolDenied
            ))
        );
        assert!(forwarder.try_next().is_none());
    }

    #[test]
    fn session_payload_overload_preserves_previously_admitted_frame() {
        let peer = frame(ProtocolKind::Sync).peer;
        let first =
            crate::protocol::encode_session_payload(ProtocolKind::Sync, b"first", 64).unwrap();
        let second =
            crate::protocol::encode_session_payload(ProtocolKind::Sync, b"second", 64).unwrap();
        let mut forwarder = SentryForwarder::new(1, 1);
        forwarder
            .forward_session_payload(peer.clone(), &first, 64, &sync_policy(64))
            .unwrap();
        assert_eq!(
            forwarder.forward_session_payload(peer, &second, 64, &sync_policy(64)),
            Err(SentryIngressError::Forward(SentryForwardError::Overloaded(
                RouterAdmissionError::GlobalCapacity
            )))
        );
        assert_eq!(forwarder.try_next().unwrap().payload, b"first");
        assert!(forwarder.try_next().is_none());
    }

    #[test]
    fn retired_session_cleanup_preserves_replacement_session_work() {
        let old_peer = frame(ProtocolKind::Sync).peer;
        let mut replacement = old_peer.clone();
        replacement.session_id = SessionId(2);
        let wire = crate::protocol::encode_session_payload(ProtocolKind::Sync, b"owner bytes", 64)
            .unwrap();
        let mut forwarder = SentryForwarder::new(2, 2);
        forwarder
            .forward_session_payload(old_peer.clone(), &wire, 64, &sync_policy(64))
            .unwrap();
        forwarder
            .forward_session_payload(replacement.clone(), &wire, 64, &sync_policy(64))
            .unwrap();
        assert_eq!(
            forwarder.discard_session(old_peer.node_address.as_str(), old_peer.session_id),
            1
        );
        assert_eq!(forwarder.try_next().unwrap().peer, replacement);
        assert!(forwarder.try_next().is_none());
    }
}
