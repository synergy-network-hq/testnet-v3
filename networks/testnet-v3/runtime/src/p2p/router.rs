//! Bounded, fair admission for authenticated P2P frames.
//!
//! This module intentionally does not validate protocol semantics.  It bounds
//! transport work and schedules authenticated frames fairly before the existing
//! PoSy, ETDAG, sync, and control handlers make their own decisions.

use super::messages::NetworkMessage;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Condvar, Mutex, MutexGuard};

pub(crate) const DEFAULT_ROUTER_CAPACITY: usize = 1_024;
pub(crate) const DEFAULT_ROUTER_PER_PEER_CAPACITY: usize = 64;

/// The downstream protocol owner for a frame.
///
/// Classification is observability and scheduling metadata only.  In
/// particular, it does not establish validator authority or interpret PoSy
/// finality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProtocolRoute {
    Posy,
    Etdag,
    Sync,
    DiscoveryControl,
}

impl ProtocolRoute {
    fn classify(message: &NetworkMessage) -> Self {
        match message {
            NetworkMessage::VoteRequest { .. }
            | NetworkMessage::Vote { .. }
            | NetworkMessage::TypedConsensus { .. }
            | NetworkMessage::CoordinatedConsensus { .. }
            | NetworkMessage::SimplifiedConsensus { .. } => Self::Posy,
            NetworkMessage::SimplifiedTargetAdmission { .. }
            | NetworkMessage::ProtectedPipelineEvidence { .. }
            | NetworkMessage::EtdagCertifiedInput { .. }
            | NetworkMessage::Transaction { .. } => Self::Etdag,
            NetworkMessage::Block { .. }
            | NetworkMessage::Blocks { .. }
            | NetworkMessage::GetBlocks { .. }
            | NetworkMessage::GetBlockHeaders { .. }
            | NetworkMessage::BlockHeaders { .. }
            | NetworkMessage::GetBlockBodies { .. }
            | NetworkMessage::BlockBodies { .. }
            | NetworkMessage::TypedFinalityObserver { .. }
            | NetworkMessage::CoordinatedFinalityObserver { .. } => Self::Sync,
            NetworkMessage::Handshake { .. }
            | NetworkMessage::GetPeers
            | NetworkMessage::Peers { .. }
            | NetworkMessage::Ping
            | NetworkMessage::Pong
            | NetworkMessage::Error { .. }
            | NetworkMessage::GetStatus
            | NetworkMessage::Status { .. } => Self::DiscoveryControl,
        }
    }
}

/// A frame admitted by the router for one downstream protocol consumer.
#[derive(Debug, Clone)]
pub(crate) struct RoutedPeerMessage {
    pub(crate) peer_address: String,
    pub(crate) session_id: u64,
    pub(crate) route: ProtocolRoute,
    pub(crate) message: NetworkMessage,
}

/// Admission failures are intentionally scoped to one connection/frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouterAdmissionError {
    GlobalCapacity,
    PeerCapacity,
}

/// Read-only router pressure telemetry for health and operator diagnostics.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RouterTelemetry {
    pub(crate) queue_depth: usize,
    pub(crate) queue_high_water_mark: usize,
    pub(crate) posy_queue_depth: usize,
    pub(crate) etdag_queue_depth: usize,
    pub(crate) sync_queue_depth: usize,
    pub(crate) discovery_control_queue_depth: usize,
    pub(crate) admitted: u64,
    pub(crate) dispatched: u64,
    pub(crate) rejected_global_capacity: u64,
    pub(crate) rejected_peer_capacity: u64,
    pub(crate) slow_consumer_rejections: u64,
    pub(crate) discarded_disconnected: u64,
    pub(crate) waiting_consumers: u64,
}

#[derive(Default)]
struct RouterState {
    queues: HashMap<String, VecDeque<RoutedPeerMessage>>,
    ready_peers: VecDeque<String>,
    ready_set: HashSet<String>,
    telemetry: RouterTelemetry,
}

/// A process-wide bounded mailbox with per-peer quotas and round-robin drain.
///
/// A full queue rejects the incoming frame immediately.  Connection handlers
/// close the offending connection, containing overload to that peer rather
/// than blocking unrelated authenticated sessions.
pub(crate) struct BoundedPeerRouter {
    capacity: usize,
    per_peer_capacity: usize,
    state: Mutex<RouterState>,
    message_available: Condvar,
}

impl BoundedPeerRouter {
    pub(crate) fn new(capacity: usize, per_peer_capacity: usize) -> Self {
        assert!(capacity > 0, "router capacity must be non-zero");
        assert!(
            per_peer_capacity > 0,
            "router per-peer capacity must be non-zero"
        );
        Self {
            capacity,
            per_peer_capacity,
            state: Mutex::new(RouterState::default()),
            message_available: Condvar::new(),
        }
    }

    pub(crate) fn production() -> Self {
        Self::new(DEFAULT_ROUTER_CAPACITY, DEFAULT_ROUTER_PER_PEER_CAPACITY)
    }

    /// Attempts immediate admission without blocking a transport reader.
    pub(crate) fn try_admit(
        &self,
        peer_address: &str,
        session_id: u64,
        message: NetworkMessage,
    ) -> Result<(), RouterAdmissionError> {
        let mut state = self.lock_state();
        if state.telemetry.queue_depth >= self.capacity {
            state.telemetry.rejected_global_capacity =
                state.telemetry.rejected_global_capacity.saturating_add(1);
            return Err(RouterAdmissionError::GlobalCapacity);
        }

        let route = ProtocolRoute::classify(&message);
        let peer_queue = state.queues.entry(peer_address.to_string()).or_default();
        if peer_queue.len() >= self.per_peer_capacity {
            state.telemetry.rejected_peer_capacity =
                state.telemetry.rejected_peer_capacity.saturating_add(1);
            state.telemetry.slow_consumer_rejections =
                state.telemetry.slow_consumer_rejections.saturating_add(1);
            return Err(RouterAdmissionError::PeerCapacity);
        }

        peer_queue.push_back(RoutedPeerMessage {
            peer_address: peer_address.to_string(),
            session_id,
            route,
            message,
        });
        if state.ready_set.insert(peer_address.to_string()) {
            state.ready_peers.push_back(peer_address.to_string());
        }
        state.telemetry.queue_depth = state.telemetry.queue_depth.saturating_add(1);
        increment_route_depth(&mut state.telemetry, route);
        state.telemetry.queue_high_water_mark = state
            .telemetry
            .queue_high_water_mark
            .max(state.telemetry.queue_depth);
        state.telemetry.admitted = state.telemetry.admitted.saturating_add(1);
        self.message_available.notify_one();
        Ok(())
    }

    /// Waits for the next frame, draining one frame per peer in round-robin order.
    pub(crate) fn receive(&self) -> RoutedPeerMessage {
        let mut state = self.lock_state();
        loop {
            if let Some(message) = Self::pop_next(&mut state) {
                return message;
            }
            state.telemetry.waiting_consumers = state.telemetry.waiting_consumers.saturating_add(1);
            state = self
                .message_available
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    }

    /// Drops queued work for a connection that has already closed or been replaced.
    pub(crate) fn discard_session(&self, peer_address: &str, session_id: u64) -> usize {
        let mut state = self.lock_state();
        let (discarded_routes, queue_empty) = {
            let Some(queue) = state.queues.get_mut(peer_address) else {
                return 0;
            };
            let discarded_routes = queue
                .iter()
                .filter(|queued| queued.session_id == session_id)
                .map(|queued| queued.route)
                .collect::<Vec<_>>();
            queue.retain(|queued| queued.session_id != session_id);
            (discarded_routes, queue.is_empty())
        };
        let discarded = discarded_routes.len();
        if queue_empty {
            state.queues.remove(peer_address);
            state.ready_set.remove(peer_address);
            state.ready_peers.retain(|ready| ready != peer_address);
        }
        state.telemetry.queue_depth = state.telemetry.queue_depth.saturating_sub(discarded);
        state.telemetry.discarded_disconnected = state
            .telemetry
            .discarded_disconnected
            .saturating_add(discarded as u64);
        for route in discarded_routes {
            decrement_route_depth(&mut state.telemetry, route);
        }
        discarded
    }

    pub(crate) fn telemetry(&self) -> RouterTelemetry {
        self.lock_state().telemetry.clone()
    }

    fn pop_next(state: &mut RouterState) -> Option<RoutedPeerMessage> {
        let peer_address = state.ready_peers.pop_front()?;
        let queue = state.queues.get_mut(&peer_address)?;
        let message = queue.pop_front()?;
        if queue.is_empty() {
            state.queues.remove(&peer_address);
            state.ready_set.remove(&peer_address);
        } else {
            state.ready_peers.push_back(peer_address);
        }
        state.telemetry.queue_depth = state.telemetry.queue_depth.saturating_sub(1);
        decrement_route_depth(&mut state.telemetry, message.route);
        state.telemetry.dispatched = state.telemetry.dispatched.saturating_add(1);
        Some(message)
    }

    fn lock_state(&self) -> MutexGuard<'_, RouterState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn increment_route_depth(telemetry: &mut RouterTelemetry, route: ProtocolRoute) {
    match route {
        ProtocolRoute::Posy => {
            telemetry.posy_queue_depth = telemetry.posy_queue_depth.saturating_add(1)
        }
        ProtocolRoute::Etdag => {
            telemetry.etdag_queue_depth = telemetry.etdag_queue_depth.saturating_add(1)
        }
        ProtocolRoute::Sync => {
            telemetry.sync_queue_depth = telemetry.sync_queue_depth.saturating_add(1)
        }
        ProtocolRoute::DiscoveryControl => {
            telemetry.discovery_control_queue_depth =
                telemetry.discovery_control_queue_depth.saturating_add(1)
        }
    }
}

fn decrement_route_depth(telemetry: &mut RouterTelemetry, route: ProtocolRoute) {
    match route {
        ProtocolRoute::Posy => {
            telemetry.posy_queue_depth = telemetry.posy_queue_depth.saturating_sub(1)
        }
        ProtocolRoute::Etdag => {
            telemetry.etdag_queue_depth = telemetry.etdag_queue_depth.saturating_sub(1)
        }
        ProtocolRoute::Sync => {
            telemetry.sync_queue_depth = telemetry.sync_queue_depth.saturating_sub(1)
        }
        ProtocolRoute::DiscoveryControl => {
            telemetry.discovery_control_queue_depth =
                telemetry.discovery_control_queue_depth.saturating_sub(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::dual_quorum::Vote;
    use crate::crypto::pqc::{PQCAlgorithm, PQCSignature};
    use crate::transaction::Transaction;

    fn ping() -> NetworkMessage {
        NetworkMessage::Ping
    }

    fn posy_vote() -> NetworkMessage {
        NetworkMessage::Vote {
            vote: Vote {
                validator_address: "synv1router-test".to_string(),
                block_hash: "router-test-block".to_string(),
                block_index: 1,
                epoch_number: 0,
                round_number: 0,
                signature: PQCSignature {
                    algorithm: PQCAlgorithm::FNDSA,
                    signature_data: vec![1],
                    message_hash: vec![2],
                    public_key_id: "router-test".to_string(),
                    created_at: 0,
                },
                signer_public_key: vec![3],
                timestamp: 0,
            },
        }
    }

    fn etdag_transaction() -> NetworkMessage {
        NetworkMessage::Transaction {
            transaction_data: Transaction {
                chain_id: 1266,
                network_id: "testnet".to_string(),
                sender: "sender".to_string(),
                receiver: "receiver".to_string(),
                amount: 0,
                nonce: 0,
                signature: Vec::new(),
                signer_public_key: Vec::new(),
                timestamp: 0,
                gas_price: 0,
                gas_limit: 0,
                data: None,
                signature_algorithm: "test".to_string(),
            },
        }
    }

    #[test]
    fn capacity_is_bounded_and_overload_is_deterministic() {
        let router = BoundedPeerRouter::new(2, 2);
        assert!(router.try_admit("peer-a", 1, ping()).is_ok());
        assert!(router.try_admit("peer-b", 1, ping()).is_ok());
        assert_eq!(
            router.try_admit("peer-c", 1, ping()),
            Err(RouterAdmissionError::GlobalCapacity)
        );
        let telemetry = router.telemetry();
        assert_eq!(telemetry.queue_depth, 2);
        assert_eq!(telemetry.rejected_global_capacity, 1);
    }

    #[test]
    fn one_peer_cannot_monopolize_admission() {
        let router = BoundedPeerRouter::new(4, 1);
        assert!(router.try_admit("peer-a", 1, ping()).is_ok());
        assert_eq!(
            router.try_admit("peer-a", 1, ping()),
            Err(RouterAdmissionError::PeerCapacity)
        );
        assert!(router.try_admit("peer-b", 1, ping()).is_ok());
        assert_eq!(router.telemetry().rejected_peer_capacity, 1);
    }

    #[test]
    fn overload_does_not_evict_previously_admitted_work() {
        let router = BoundedPeerRouter::new(1, 1);
        assert!(router.try_admit("peer-a", 1, ping()).is_ok());
        assert_eq!(
            router.try_admit("peer-b", 1, ping()),
            Err(RouterAdmissionError::GlobalCapacity)
        );
        assert_eq!(router.receive().peer_address, "peer-a");
    }

    #[test]
    fn round_robin_drain_does_not_block_an_unrelated_peer_behind_a_slow_consumer() {
        let router = BoundedPeerRouter::new(4, 2);
        assert!(router.try_admit("peer-a", 1, ping()).is_ok());
        assert!(router.try_admit("peer-a", 1, ping()).is_ok());
        assert!(router.try_admit("peer-b", 1, ping()).is_ok());
        assert_eq!(router.receive().peer_address, "peer-a");
        assert_eq!(router.receive().peer_address, "peer-b");
    }

    #[test]
    fn closed_connection_discards_only_its_queued_work() {
        let router = BoundedPeerRouter::new(4, 2);
        assert!(router.try_admit("peer-a", 7, ping()).is_ok());
        assert!(router.try_admit("peer-b", 8, ping()).is_ok());
        assert_eq!(router.discard_session("peer-a", 7), 1);
        assert_eq!(router.receive().peer_address, "peer-b");
        assert_eq!(router.telemetry().discarded_disconnected, 1);
    }

    #[test]
    fn telemetry_reports_route_depth_and_slow_consumer_pressure() {
        let router = BoundedPeerRouter::new(3, 1);
        assert!(router.try_admit("posy", 1, posy_vote()).is_ok());
        assert_eq!(
            router.try_admit("posy", 1, ping()),
            Err(RouterAdmissionError::PeerCapacity)
        );
        let telemetry = router.telemetry();
        assert_eq!(telemetry.posy_queue_depth, 1);
        assert_eq!(telemetry.slow_consumer_rejections, 1);
    }

    #[test]
    fn routes_posy_etdag_and_sync_frames_without_interpreting_their_semantics() {
        let router = BoundedPeerRouter::new(4, 2);
        assert!(router.try_admit("posy", 1, posy_vote()).is_ok());
        assert!(router.try_admit("etdag", 1, etdag_transaction()).is_ok());
        assert!(router
            .try_admit(
                "sync",
                1,
                NetworkMessage::GetBlocks {
                    from_height: 1,
                    count: 1,
                },
            )
            .is_ok());
        assert_eq!(router.receive().route, ProtocolRoute::Posy);
        assert_eq!(router.receive().route, ProtocolRoute::Etdag);
        assert_eq!(router.receive().route, ProtocolRoute::Sync);
    }

    #[test]
    fn preserves_posy_payload_without_applying_validator_or_finality_logic() {
        let router = BoundedPeerRouter::new(1, 1);
        assert!(router.try_admit("peer-a", 9, posy_vote()).is_ok());
        let routed = router.receive();
        assert_eq!(routed.route, ProtocolRoute::Posy);
        let NetworkMessage::Vote { vote } = routed.message else {
            panic!("router changed the PoSy frame family");
        };
        assert_eq!(vote.validator_address, "synv1router-test");
    }
}
