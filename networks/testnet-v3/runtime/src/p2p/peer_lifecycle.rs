//! Authenticated peer lifecycle policy.
//!
//! This module owns connection admission and lifecycle state. Transport code
//! owns sockets; it reports lifecycle events here after a socket is accepted
//! or a dial finishes. A peer address is only a transport key until the
//! handshake layer binds an authenticated identity.

use crate::consensus::typed_coordinator::AuthenticatedTypedConsensusPeer;
use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

const MAX_TYPED_CONSENSUS_PEER_SESSIONS: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PeerDirection {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PeerLifecycleState {
    Connecting,
    Connected,
    Authenticated,
    Ready,
    Degraded,
    Stale,
    Disconnecting,
    Disconnected,
    Quarantined,
    Banned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PeerDisconnectReason {
    RemoteClosed,
    DialFailure,
    ProtocolViolation,
    Overloaded,
    Stale,
    Quarantined,
    Banned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdmissionError {
    ConnectionLimit,
    Duplicate,
    Backoff { retry_at: u64 },
    Quarantined { retry_at: u64 },
    Banned { until: Option<u64> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PeerLifecycleSnapshot {
    pub peer: String,
    pub direction: PeerDirection,
    pub state: PeerLifecycleState,
    pub authenticated: bool,
    pub node_id: Option<String>,
    pub capabilities: Vec<String>,
    pub connected_at: Option<u64>,
    pub last_seen_at: Option<u64>,
    pub failures: u32,
    pub retry_at: Option<u64>,
    pub quarantine_until: Option<u64>,
    pub ban_until: Option<u64>,
    pub disconnect_reason: Option<PeerDisconnectReason>,
}

#[derive(Debug, Clone)]
struct PeerLifecycleRecord {
    direction: PeerDirection,
    state: PeerLifecycleState,
    authenticated: bool,
    node_id: Option<String>,
    capabilities: Vec<String>,
    connected_at: Option<u64>,
    last_seen_at: Option<u64>,
    failures: u32,
    retry_at: Option<u64>,
    quarantine_until: Option<u64>,
    ban_until: Option<u64>,
    disconnect_reason: Option<PeerDisconnectReason>,
}

impl PeerLifecycleRecord {
    fn connecting(direction: PeerDirection, now: u64) -> Self {
        Self {
            direction,
            state: PeerLifecycleState::Connecting,
            authenticated: false,
            node_id: None,
            capabilities: Vec::new(),
            connected_at: None,
            last_seen_at: Some(now),
            failures: 0,
            retry_at: None,
            quarantine_until: None,
            ban_until: None,
            disconnect_reason: None,
        }
    }

    fn snapshot(&self, peer: String) -> PeerLifecycleSnapshot {
        PeerLifecycleSnapshot {
            peer,
            direction: self.direction,
            state: self.state,
            authenticated: self.authenticated,
            node_id: self.node_id.clone(),
            capabilities: self.capabilities.clone(),
            connected_at: self.connected_at,
            last_seen_at: self.last_seen_at,
            failures: self.failures,
            retry_at: self.retry_at,
            quarantine_until: self.quarantine_until,
            ban_until: self.ban_until,
            disconnect_reason: self.disconnect_reason,
        }
    }
}

/// Session identity belongs to peer management rather than protocol handlers.
///
/// A transport address may be reused after reconnect. The monotonically assigned
/// session id lets routing, synchronization, and protocol adapters discard work
/// queued for the displaced connection. The typed PoSy identity is deliberately
/// an opaque authenticated binding here: this registry does not validate votes,
/// grant validator authority, or decide finality.
#[derive(Default)]
struct PeerSessionRegistry {
    next_session_id: u64,
    current_sessions: BTreeMap<String, u64>,
    typed_consensus_peers: BTreeMap<(String, u64), AuthenticatedTypedConsensusPeer>,
}

impl PeerSessionRegistry {
    fn begin(&mut self, peer: &str) -> u64 {
        let session_id = self.next_session_id.max(1);
        self.next_session_id = session_id.saturating_add(1);
        self.current_sessions.insert(peer.to_string(), session_id);
        self.typed_consensus_peers
            .retain(|(address, _), _| address != peer);
        session_id
    }

    fn current(&self, peer: &str) -> Option<u64> {
        self.current_sessions.get(peer).copied()
    }

    fn is_current(&self, peer: &str, session_id: u64) -> bool {
        self.current(peer) == Some(session_id)
    }

    fn clear(&mut self, peer: &str) -> Option<u64> {
        let removed = self.current_sessions.remove(peer);
        self.typed_consensus_peers
            .retain(|(address, _), _| address != peer);
        removed
    }

    fn bind_typed_consensus_peer(
        &mut self,
        peer: &str,
        session_id: u64,
        identity: AuthenticatedTypedConsensusPeer,
    ) -> Result<(), String> {
        if !self.is_current(peer, session_id) {
            return Err(
                "cannot bind typed consensus identity to a replaced peer session".to_string(),
            );
        }
        let key = (peer.to_string(), session_id);
        if !self.typed_consensus_peers.contains_key(&key)
            && self.typed_consensus_peers.len() >= MAX_TYPED_CONSENSUS_PEER_SESSIONS
        {
            return Err("typed consensus peer-session registry capacity is exhausted".to_string());
        }
        self.typed_consensus_peers.insert(key, identity);
        Ok(())
    }

    fn typed_consensus_peer(
        &self,
        peer: &str,
        session_id: u64,
    ) -> Option<AuthenticatedTypedConsensusPeer> {
        self.is_current(peer, session_id)
            .then(|| {
                self.typed_consensus_peers
                    .get(&(peer.to_string(), session_id))
                    .cloned()
            })
            .flatten()
    }
}

fn peer_sessions() -> &'static Mutex<PeerSessionRegistry> {
    static PEER_SESSIONS: OnceLock<Mutex<PeerSessionRegistry>> = OnceLock::new();
    PEER_SESSIONS.get_or_init(|| Mutex::new(PeerSessionRegistry::default()))
}

pub(crate) fn begin_peer_session(peer: &str) -> u64 {
    peer_sessions().lock().unwrap().begin(peer)
}

pub(crate) fn current_peer_session_id(peer: &str) -> Option<u64> {
    peer_sessions().lock().unwrap().current(peer)
}

pub(crate) fn peer_session_is_current(peer: &str, session_id: u64) -> bool {
    peer_sessions().lock().unwrap().is_current(peer, session_id)
}

pub(crate) fn clear_peer_session(peer: &str) -> Option<u64> {
    peer_sessions().lock().unwrap().clear(peer)
}

#[cfg(test)]
pub(crate) fn clear_peer_sessions_for_tests() {
    let mut sessions = peer_sessions().lock().unwrap();
    sessions.current_sessions.clear();
    sessions.typed_consensus_peers.clear();
}

pub(crate) fn register_typed_consensus_peer_session(
    peer: &str,
    session_id: u64,
    identity: AuthenticatedTypedConsensusPeer,
) -> Result<(), String> {
    peer_sessions()
        .lock()
        .unwrap()
        .bind_typed_consensus_peer(peer, session_id, identity)
}

pub(crate) fn typed_consensus_peer_for_session(
    peer: &str,
    session_id: u64,
) -> Option<AuthenticatedTypedConsensusPeer> {
    peer_sessions()
        .lock()
        .unwrap()
        .typed_consensus_peer(peer, session_id)
}

/// A bounded, deterministic reconnect policy. Jitter is derived from the
/// transport key so all scheduling is local and never enters consensus.
#[derive(Debug, Clone)]
pub(crate) struct PeerLifecycle {
    max_connections: usize,
    base_backoff_secs: u64,
    max_backoff_secs: u64,
    records: BTreeMap<String, PeerLifecycleRecord>,
}

impl PeerLifecycle {
    pub(crate) fn new(max_connections: usize) -> Self {
        Self {
            max_connections: max_connections.max(1),
            base_backoff_secs: 3,
            max_backoff_secs: 300,
            records: BTreeMap::new(),
        }
    }

    pub(crate) fn begin_outbound(&mut self, peer: &str, now: u64) -> Result<(), AdmissionError> {
        self.begin(peer, PeerDirection::Outbound, now)
    }

    pub(crate) fn begin_inbound(&mut self, peer: &str, now: u64) -> Result<(), AdmissionError> {
        self.begin(peer, PeerDirection::Inbound, now)
    }

    fn begin(
        &mut self,
        peer: &str,
        direction: PeerDirection,
        now: u64,
    ) -> Result<(), AdmissionError> {
        let peer = peer.trim();
        if peer.is_empty() {
            return Err(AdmissionError::Duplicate);
        }
        if let Some(record) = self.records.get(peer) {
            if record.state == PeerLifecycleState::Banned {
                if record.ban_until.is_none_or(|until| until > now) {
                    return Err(AdmissionError::Banned {
                        until: record.ban_until,
                    });
                }
            }
            if record.state == PeerLifecycleState::Quarantined {
                if let Some(until) = record.quarantine_until.filter(|until| *until > now) {
                    return Err(AdmissionError::Quarantined { retry_at: until });
                }
            }
            if matches!(
                record.state,
                PeerLifecycleState::Connecting | PeerLifecycleState::Connected
            ) {
                return Err(AdmissionError::Duplicate);
            }
            if let Some(retry_at) = record.retry_at.filter(|retry_at| *retry_at > now) {
                return Err(AdmissionError::Backoff { retry_at });
            }
        }
        if self.active_connection_count() >= self.max_connections {
            return Err(AdmissionError::ConnectionLimit);
        }

        let record = self
            .records
            .entry(peer.to_string())
            .or_insert_with(|| PeerLifecycleRecord::connecting(direction, now));
        record.direction = direction;
        record.state = PeerLifecycleState::Connecting;
        record.authenticated = false;
        record.node_id = None;
        record.capabilities.clear();
        record.disconnect_reason = None;
        record.last_seen_at = Some(now);
        record.retry_at = None;
        record.quarantine_until = None;
        Ok(())
    }

    pub(crate) fn mark_connected(&mut self, peer: &str, now: u64) {
        if let Some(record) = self.records.get_mut(peer.trim()) {
            record.state = PeerLifecycleState::Connected;
            record.connected_at = Some(now);
            record.last_seen_at = Some(now);
            record.retry_at = None;
        }
    }

    pub(crate) fn mark_authenticated(&mut self, peer: &str, now: u64) {
        self.mark_authenticated_with_metadata(peer, now, None, &[]);
    }

    pub(crate) fn mark_authenticated_with_metadata(
        &mut self,
        peer: &str,
        now: u64,
        node_id: Option<&str>,
        capabilities: &[String],
    ) {
        if let Some(record) = self.records.get_mut(peer.trim()) {
            record.state = PeerLifecycleState::Authenticated;
            record.authenticated = true;
            record.node_id = node_id
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned);
            record.capabilities = capabilities.to_vec();
            record.last_seen_at = Some(now);
        }
    }

    pub(crate) fn mark_ready(&mut self, peer: &str, now: u64) {
        if let Some(record) = self.records.get_mut(peer.trim()) {
            if record.authenticated {
                record.state = PeerLifecycleState::Ready;
                record.last_seen_at = Some(now);
            }
        }
    }

    pub(crate) fn mark_degraded(&mut self, peer: &str, now: u64) {
        if let Some(record) = self.records.get_mut(peer.trim()) {
            if record.authenticated {
                record.state = PeerLifecycleState::Degraded;
                record.last_seen_at = Some(now);
            }
        }
    }

    pub(crate) fn mark_stale(&mut self, peer: &str, now: u64) {
        if let Some(record) = self.records.get_mut(peer.trim()) {
            if record.authenticated {
                record.state = PeerLifecycleState::Stale;
                record.last_seen_at = Some(now);
            }
        }
    }

    pub(crate) fn mark_disconnecting(&mut self, peer: &str) {
        if let Some(record) = self.records.get_mut(peer.trim()) {
            record.state = PeerLifecycleState::Disconnecting;
        }
    }

    pub(crate) fn mark_activity(&mut self, peer: &str, now: u64) {
        if let Some(record) = self.records.get_mut(peer.trim()) {
            record.last_seen_at = Some(now);
        }
    }

    pub(crate) fn mark_disconnected(&mut self, peer: &str, now: u64, failed: bool) {
        let reason = if failed {
            PeerDisconnectReason::DialFailure
        } else {
            PeerDisconnectReason::RemoteClosed
        };
        self.mark_disconnected_with_reason(peer, now, failed, reason);
    }

    pub(crate) fn mark_disconnected_with_reason(
        &mut self,
        peer: &str,
        now: u64,
        failed: bool,
        reason: PeerDisconnectReason,
    ) {
        let base_backoff_secs = self.base_backoff_secs;
        let max_backoff_secs = self.max_backoff_secs;
        let Some(record) = self.records.get_mut(peer.trim()) else {
            return;
        };
        if record.state == PeerLifecycleState::Banned {
            return;
        }
        record.authenticated = false;
        record.connected_at = None;
        record.last_seen_at = Some(now);
        record.state = PeerLifecycleState::Disconnected;
        record.disconnect_reason = Some(reason);
        if failed {
            record.failures = record.failures.saturating_add(1);
            record.retry_at = Some(now.saturating_add(backoff_with_jitter(
                peer,
                record.failures,
                base_backoff_secs,
                max_backoff_secs,
            )));
        } else {
            record.failures = 0;
            record.retry_at = None;
        }
    }

    pub(crate) fn quarantine(&mut self, peer: &str, now: u64, duration_secs: u64) {
        if let Some(record) = self.records.get_mut(peer.trim()) {
            record.state = PeerLifecycleState::Quarantined;
            record.authenticated = false;
            record.connected_at = None;
            record.quarantine_until = Some(now.saturating_add(duration_secs.max(1)));
            record.retry_at = record.quarantine_until;
            record.disconnect_reason = Some(PeerDisconnectReason::Quarantined);
        }
    }

    pub(crate) fn ban(&mut self, peer: &str, until: Option<u64>) {
        if let Some(record) = self.records.get_mut(peer.trim()) {
            record.state = PeerLifecycleState::Banned;
            record.authenticated = false;
            record.connected_at = None;
            record.ban_until = until;
            record.retry_at = until;
            record.disconnect_reason = Some(PeerDisconnectReason::Banned);
        }
    }

    pub(crate) fn stale_peers(&self, now: u64, stale_after_secs: u64) -> Vec<String> {
        self.records
            .iter()
            .filter_map(|(peer, record)| {
                (matches!(
                    record.state,
                    PeerLifecycleState::Connected
                        | PeerLifecycleState::Authenticated
                        | PeerLifecycleState::Ready
                        | PeerLifecycleState::Degraded
                ) && record
                    .last_seen_at
                    .is_some_and(|seen| now.saturating_sub(seen) >= stale_after_secs))
                .then(|| peer.clone())
            })
            .collect()
    }

    pub(crate) fn snapshot(&self) -> Vec<PeerLifecycleSnapshot> {
        self.records
            .iter()
            .map(|(peer, record)| record.snapshot(peer.clone()))
            .collect()
    }

    fn active_connection_count(&self) -> usize {
        self.records
            .values()
            .filter(|record| {
                matches!(
                    record.state,
                    PeerLifecycleState::Connecting
                        | PeerLifecycleState::Connected
                        | PeerLifecycleState::Authenticated
                        | PeerLifecycleState::Ready
                        | PeerLifecycleState::Degraded
                        | PeerLifecycleState::Stale
                        | PeerLifecycleState::Disconnecting
                )
            })
            .count()
    }
}

fn backoff_with_jitter(
    peer: &str,
    failures: u32,
    base_backoff_secs: u64,
    max_backoff_secs: u64,
) -> u64 {
    let exponent = failures.saturating_sub(1).min(16);
    let base = base_backoff_secs
        .saturating_mul(1_u64.checked_shl(exponent).unwrap_or(u64::MAX))
        .min(max_backoff_secs);
    let jitter = stable_jitter(peer, base_backoff_secs.max(1));
    base.saturating_add(jitter).min(max_backoff_secs)
}

fn stable_jitter(peer: &str, bound: u64) -> u64 {
    peer.as_bytes()
        .iter()
        .fold(0xcbf29ce484222325_u64, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
        })
        % bound
}

#[cfg(test)]
mod tests {
    use super::{AdmissionError, PeerLifecycle, PeerLifecycleState};

    #[test]
    fn rejects_duplicate_connections_and_enforces_limit() {
        let mut peers = PeerLifecycle::new(1);
        peers.begin_outbound("peer-a", 10).unwrap();
        assert_eq!(
            peers.begin_outbound("peer-a", 10),
            Err(AdmissionError::Duplicate)
        );
        assert_eq!(
            peers.begin_inbound("peer-b", 10),
            Err(AdmissionError::ConnectionLimit)
        );
    }

    #[test]
    fn failed_dial_uses_deterministic_backoff_then_recovers() {
        let mut peers = PeerLifecycle::new(2);
        peers.begin_outbound("peer-a", 10).unwrap();
        peers.mark_disconnected("peer-a", 11, true);
        let retry_at = match peers.begin_outbound("peer-a", 12) {
            Err(AdmissionError::Backoff { retry_at }) => retry_at,
            other => panic!("expected backoff, got {other:?}"),
        };
        peers.begin_outbound("peer-a", retry_at).unwrap();
        peers.mark_connected("peer-a", retry_at);
        peers.mark_authenticated("peer-a", retry_at);
        assert_eq!(peers.snapshot()[0].state, PeerLifecycleState::Connected);
        assert!(peers.snapshot()[0].authenticated);
    }

    #[test]
    fn quarantine_and_ban_are_admission_boundaries() {
        let mut peers = PeerLifecycle::new(2);
        peers.begin_outbound("peer-a", 10).unwrap();
        peers.quarantine("peer-a", 11, 30);
        assert_eq!(
            peers.begin_outbound("peer-a", 20),
            Err(AdmissionError::Quarantined { retry_at: 41 })
        );
        peers.ban("peer-a", Some(90));
        assert_eq!(
            peers.begin_outbound("peer-a", 50),
            Err(AdmissionError::Banned { until: Some(90) })
        );
    }

    #[test]
    fn replaced_session_is_rejected_and_cleanup_is_peer_scoped() {
        let peer = format!("peer-session-test-{}", std::process::id());
        let first = super::begin_peer_session(&peer);
        let replacement = super::begin_peer_session(&peer);

        assert_ne!(first, replacement);
        assert!(!super::peer_session_is_current(&peer, first));
        assert!(super::peer_session_is_current(&peer, replacement));
        assert_eq!(super::clear_peer_session(&peer), Some(replacement));
        assert_eq!(super::current_peer_session_id(&peer), None);
    }
}
