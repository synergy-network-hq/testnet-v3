use crate::protocol::InboundFrame;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use synergy_protocol_types::{ProtocolKind, SessionId};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouterAdmissionError {
    GlobalCapacity,
    PeerCapacity,
}
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouterTelemetry {
    pub queue_depth: usize,
    pub queue_high_water_mark: usize,
    pub admitted: u64,
    pub dispatched: u64,
    pub rejected_global_capacity: u64,
    pub rejected_peer_capacity: u64,
    pub discarded_disconnected: u64,
    pub by_protocol: BTreeMap<ProtocolKind, usize>,
}

/// Bounded round-robin mailbox. Full admission rejects only the incoming
/// frame; it never blocks unrelated peers nor interprets protocol semantics.
#[derive(Debug)]
pub struct BoundedPeerRouter {
    capacity: usize,
    per_peer_capacity: usize,
    queues: BTreeMap<String, VecDeque<InboundFrame>>,
    ready_peers: VecDeque<String>,
    ready_set: BTreeSet<String>,
    telemetry: RouterTelemetry,
}
impl BoundedPeerRouter {
    pub fn new(capacity: usize, per_peer_capacity: usize) -> Self {
        assert!(capacity > 0);
        assert!(per_peer_capacity > 0);
        Self {
            capacity,
            per_peer_capacity,
            queues: BTreeMap::new(),
            ready_peers: VecDeque::new(),
            ready_set: BTreeSet::new(),
            telemetry: RouterTelemetry::default(),
        }
    }
    pub fn try_admit(&mut self, frame: InboundFrame) -> Result<(), RouterAdmissionError> {
        if self.telemetry.queue_depth >= self.capacity {
            self.telemetry.rejected_global_capacity =
                self.telemetry.rejected_global_capacity.saturating_add(1);
            return Err(RouterAdmissionError::GlobalCapacity);
        }
        let peer = frame.peer.node_address.to_string();
        let queue = self.queues.entry(peer.clone()).or_default();
        if queue.len() >= self.per_peer_capacity {
            self.telemetry.rejected_peer_capacity =
                self.telemetry.rejected_peer_capacity.saturating_add(1);
            return Err(RouterAdmissionError::PeerCapacity);
        }
        let protocol = frame.protocol;
        queue.push_back(frame);
        if self.ready_set.insert(peer.clone()) {
            self.ready_peers.push_back(peer)
        }
        self.telemetry.queue_depth += 1;
        *self.telemetry.by_protocol.entry(protocol).or_default() += 1;
        self.telemetry.queue_high_water_mark = self
            .telemetry
            .queue_high_water_mark
            .max(self.telemetry.queue_depth);
        self.telemetry.admitted = self.telemetry.admitted.saturating_add(1);
        Ok(())
    }
    /// Non-blocking fair drain: one frame per peer per turn.
    pub fn try_next(&mut self) -> Option<InboundFrame> {
        let peer = self.ready_peers.pop_front()?;
        let queue = self.queues.get_mut(&peer)?;
        let frame = queue.pop_front()?;
        if queue.is_empty() {
            self.queues.remove(&peer);
            self.ready_set.remove(&peer);
        } else {
            self.ready_peers.push_back(peer)
        }
        self.telemetry.queue_depth = self.telemetry.queue_depth.saturating_sub(1);
        decrement(&mut self.telemetry.by_protocol, frame.protocol);
        self.telemetry.dispatched = self.telemetry.dispatched.saturating_add(1);
        Some(frame)
    }
    /// Drops queued work belonging only to the replaced/closed exact session.
    pub fn discard_session(&mut self, peer: &str, session: SessionId) -> usize {
        let Some(queue) = self.queues.get_mut(peer) else {
            return 0;
        };
        let discarded: Vec<ProtocolKind> = queue
            .iter()
            .filter(|f| f.peer.session_id == session)
            .map(|f| f.protocol)
            .collect();
        queue.retain(|f| f.peer.session_id != session);
        if queue.is_empty() {
            self.queues.remove(peer);
            self.ready_set.remove(peer);
            self.ready_peers.retain(|p| p != peer)
        }
        self.telemetry.queue_depth = self.telemetry.queue_depth.saturating_sub(discarded.len());
        self.telemetry.discarded_disconnected = self
            .telemetry
            .discarded_disconnected
            .saturating_add(discarded.len() as u64);
        for protocol in discarded.iter().copied() {
            decrement(&mut self.telemetry.by_protocol, protocol)
        }
        discarded.len()
    }
    pub fn telemetry(&self) -> RouterTelemetry {
        self.telemetry.clone()
    }
}
fn decrement(depths: &mut BTreeMap<ProtocolKind, usize>, protocol: ProtocolKind) {
    let Some(depth) = depths.get_mut(&protocol) else {
        return;
    };
    *depth = depth.saturating_sub(1);
    if *depth == 0 {
        depths.remove(&protocol);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use synergy_protocol_types::AuthenticatedPeer;
    fn frame(peer: &str, session: u64, protocol: ProtocolKind) -> InboundFrame {
        InboundFrame::new(
            AuthenticatedPeer::new(peer, SessionId(session), vec![]).unwrap(),
            protocol,
            vec![1],
            8,
        )
        .unwrap()
    }
    #[test]
    fn capacity_is_bounded_and_rejection_is_deterministic() {
        let mut r = BoundedPeerRouter::new(2, 2);
        r.try_admit(frame(
            "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn",
            1,
            ProtocolKind::Posy,
        ))
        .unwrap();
        r.try_admit(frame(
            "synv21lrh6jcxaejkj4zv994j7qwn2rk6u3zat22n",
            1,
            ProtocolKind::Sync,
        ))
        .unwrap();
        assert_eq!(
            r.try_admit(frame(
                "synv31lrh6jcxaejkj4zv994j7qwn2rk6u3shpu9n",
                1,
                ProtocolKind::Etdag
            )),
            Err(RouterAdmissionError::GlobalCapacity)
        );
        assert_eq!(r.telemetry().queue_depth, 2);
        assert_eq!(r.telemetry().rejected_global_capacity, 1)
    }
    #[test]
    fn one_peer_cannot_monopolize_admission_or_drain() {
        let mut r = BoundedPeerRouter::new(8, 2);
        r.try_admit(frame(
            "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn",
            1,
            ProtocolKind::Posy,
        ))
        .unwrap();
        r.try_admit(frame(
            "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn",
            1,
            ProtocolKind::Posy,
        ))
        .unwrap();
        assert_eq!(
            r.try_admit(frame(
                "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn",
                1,
                ProtocolKind::Posy
            )),
            Err(RouterAdmissionError::PeerCapacity)
        );
        r.try_admit(frame(
            "synv21lrh6jcxaejkj4zv994j7qwn2rk6u3zat22n",
            1,
            ProtocolKind::Sync,
        ))
        .unwrap();
        assert_eq!(
            r.try_next().unwrap().peer.node_address.as_str(),
            "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn"
        );
        assert_eq!(
            r.try_next().unwrap().peer.node_address.as_str(),
            "synv21lrh6jcxaejkj4zv994j7qwn2rk6u3zat22n"
        )
    }
    #[test]
    fn exact_session_cleanup_preserves_replacement_work() {
        let mut r = BoundedPeerRouter::new(8, 8);
        r.try_admit(frame(
            "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn",
            1,
            ProtocolKind::Posy,
        ))
        .unwrap();
        r.try_admit(frame(
            "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn",
            2,
            ProtocolKind::Etdag,
        ))
        .unwrap();
        assert_eq!(
            r.discard_session("synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn", SessionId(1)),
            1
        );
        let left = r.try_next().unwrap();
        assert_eq!(left.peer.session_id, SessionId(2));
        assert_eq!(left.protocol, ProtocolKind::Etdag)
    }
    #[test]
    fn normal_protocol_categories_route_without_semantic_interpretation() {
        let mut r = BoundedPeerRouter::new(8, 8);
        for p in [ProtocolKind::Posy, ProtocolKind::Etdag, ProtocolKind::Sync] {
            r.try_admit(frame("synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn", 1, p))
                .unwrap()
        }
        let mut got = vec![];
        while let Some(m) = r.try_next() {
            got.push(m.protocol)
        }
        assert_eq!(
            got,
            vec![ProtocolKind::Posy, ProtocolKind::Etdag, ProtocolKind::Sync]
        )
    }
}
