use super::{AuthenticatedTransportAdmissionPolicy, PeerAdmissionPolicyError};
use std::collections::BTreeMap;
use synergy_protocol_types::{AuthenticatedPeer, SessionId};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerDirection {
    Inbound,
    Outbound,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
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
pub enum DisconnectReason {
    RemoteClosed,
    DialFailure,
    ProtocolViolation,
    Overloaded,
    Stale,
    Quarantined,
    Banned,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionError {
    ConnectionLimit,
    InvalidSession,
    Duplicate { retained: SessionId },
    Backoff { retry_at: u64 },
    Quarantined { retry_at: u64 },
    Banned { until: Option<u64> },
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportAuthenticationError {
    Policy(PeerAdmissionPolicyError),
    StaleOrUnknownSession,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionAdmission {
    pub session_id: SessionId,
    pub displaced_session: Option<SessionId>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSnapshot {
    pub peer_id: String,
    pub session_id: SessionId,
    pub direction: PeerDirection,
    pub state: PeerState,
    pub authenticated: bool,
    pub capabilities: Vec<String>,
    pub last_seen_at: u64,
    pub retry_at: Option<u64>,
    pub disconnect_reason: Option<DisconnectReason>,
}
#[derive(Debug, Clone)]
struct PeerRecord {
    session_id: SessionId,
    direction: PeerDirection,
    state: PeerState,
    authenticated: bool,
    capabilities: Vec<String>,
    last_seen_at: u64,
    retry_at: Option<u64>,
    quarantine_until: Option<u64>,
    ban_until: Option<u64>,
    disconnect_reason: Option<DisconnectReason>,
}

/// Sole owner of peer lifecycle state. Exact SessionId ownership ensures a
/// delayed socket cleanup cannot affect a newer authenticated replacement.
/// It stores handshake facts only; it never grants validator authority or
/// interprets PoSy/ETDAG semantics.
#[derive(Debug)]
pub struct PeerManager {
    local_peer_id: String,
    max_connections: usize,
    next_session_id: u64,
    peers: BTreeMap<String, PeerRecord>,
}
impl PeerManager {
    pub fn new(local_peer_id: impl Into<String>, max_connections: usize) -> Self {
        assert!(max_connections > 0);
        Self {
            local_peer_id: local_peer_id.into(),
            max_connections,
            next_session_id: 1,
            peers: BTreeMap::new(),
        }
    }
    pub fn admit(
        &mut self,
        peer_id: impl Into<String>,
        direction: PeerDirection,
        now: u64,
    ) -> Result<ConnectionAdmission, AdmissionError> {
        let peer_id = peer_id.into();
        if let Some(existing) = self.peers.get(&peer_id) {
            if let Some(until) = existing.ban_until.filter(|until| *until > now) {
                return Err(AdmissionError::Banned { until: Some(until) });
            }
            if existing.state == PeerState::Banned && existing.ban_until.is_none() {
                return Err(AdmissionError::Banned { until: None });
            }
            if let Some(until) = existing.quarantine_until.filter(|until| *until > now) {
                return Err(AdmissionError::Quarantined { retry_at: until });
            }
            if let Some(retry_at) = existing.retry_at.filter(|retry_at| *retry_at > now) {
                return Err(AdmissionError::Backoff { retry_at });
            }
            if active(existing.state)
                && !self.candidate_wins(&peer_id, existing.direction, direction)
            {
                return Err(AdmissionError::Duplicate {
                    retained: existing.session_id,
                });
            }
        }
        if !self.peers.contains_key(&peer_id) && self.active_count() >= self.max_connections {
            return Err(AdmissionError::ConnectionLimit);
        }
        let session_id = self.next_session();
        let displaced_session = self
            .peers
            .get(&peer_id)
            .and_then(|p| active(p.state).then_some(p.session_id));
        self.peers.insert(
            peer_id,
            PeerRecord {
                session_id,
                direction,
                state: PeerState::Connecting,
                authenticated: false,
                capabilities: vec![],
                last_seen_at: now,
                retry_at: None,
                quarantine_until: None,
                ban_until: None,
                disconnect_reason: None,
            },
        );
        Ok(ConnectionAdmission {
            session_id,
            displaced_session,
        })
    }
    /// Registers a session identifier assigned by the authenticated remote
    /// responder. The caller still must verify the signed handshake before
    /// invoking authenticate.
    pub fn admit_with_session(
        &mut self,
        peer_id: impl Into<String>,
        direction: PeerDirection,
        session_id: SessionId,
        now: u64,
    ) -> Result<ConnectionAdmission, AdmissionError> {
        let peer_id = peer_id.into();
        if session_id.0 == 0 {
            return Err(AdmissionError::InvalidSession);
        }
        if self
            .peers
            .get(&peer_id)
            .is_some_and(|record| record.session_id == session_id)
        {
            return Err(AdmissionError::Duplicate {
                retained: session_id,
            });
        }
        let admission = self.admit(peer_id.clone(), direction, now)?;
        if let Some(record) = self.peers.get_mut(&peer_id) {
            record.session_id = session_id;
        }
        Ok(ConnectionAdmission {
            session_id,
            displaced_session: admission.displaced_session,
        })
    }
    pub fn authenticate(
        &mut self,
        peer: &str,
        session: SessionId,
        capabilities: Vec<String>,
        now: u64,
    ) -> bool {
        let Some(r) = self.current_mut(peer, session) else {
            return false;
        };
        r.authenticated = true;
        r.capabilities = capabilities;
        r.state = PeerState::Authenticated;
        r.last_seen_at = now;
        true
    }
    /// Applies an optional transport policy after identity binding. The policy
    /// can fail closed for a private overlay but never grants PoSy authority.
    pub fn authenticate_with_transport_policy<P: AuthenticatedTransportAdmissionPolicy>(
        &mut self,
        peer: AuthenticatedPeer,
        policy: &P,
        now: u64,
    ) -> Result<(), TransportAuthenticationError> {
        policy
            .permit(&peer)
            .map_err(TransportAuthenticationError::Policy)?;
        self.authenticate(
            peer.node_address.as_str(),
            peer.session_id,
            peer.capabilities,
            now,
        )
        .then_some(())
        .ok_or(TransportAuthenticationError::StaleOrUnknownSession)
    }
    pub fn mark_ready(&mut self, peer: &str, session: SessionId, now: u64) -> bool {
        let Some(r) = self.current_mut(peer, session) else {
            return false;
        };
        if !r.authenticated {
            return false;
        }
        r.state = PeerState::Ready;
        r.last_seen_at = now;
        true
    }
    pub fn mark_stale_before(&mut self, cutoff: u64) -> usize {
        let mut count = 0;
        for r in self.peers.values_mut() {
            if active(r.state) && r.last_seen_at < cutoff {
                r.state = PeerState::Stale;
                r.disconnect_reason = Some(DisconnectReason::Stale);
                count += 1
            }
        }
        count
    }
    pub fn disconnect_exact(
        &mut self,
        peer: &str,
        session: SessionId,
        reason: DisconnectReason,
        now: u64,
    ) -> bool {
        let delay = 1 + (session.0 % 3);
        let Some(r) = self.current_mut(peer, session) else {
            return false;
        };
        r.state = PeerState::Disconnected;
        r.authenticated = false;
        r.capabilities.clear();
        r.disconnect_reason = Some(reason);
        r.last_seen_at = now;
        r.retry_at = matches!(
            reason,
            DisconnectReason::DialFailure | DisconnectReason::RemoteClosed
        )
        .then_some(now.saturating_add(delay));
        true
    }
    pub fn quarantine_exact(&mut self, peer: &str, session: SessionId, until: u64) -> bool {
        let Some(r) = self.current_mut(peer, session) else {
            return false;
        };
        r.state = PeerState::Quarantined;
        r.authenticated = false;
        r.capabilities.clear();
        r.quarantine_until = Some(until);
        r.disconnect_reason = Some(DisconnectReason::Quarantined);
        true
    }
    pub fn ban_exact(&mut self, peer: &str, session: SessionId, until: Option<u64>) -> bool {
        let Some(r) = self.current_mut(peer, session) else {
            return false;
        };
        r.state = PeerState::Banned;
        r.authenticated = false;
        r.capabilities.clear();
        r.ban_until = until;
        r.disconnect_reason = Some(DisconnectReason::Banned);
        true
    }
    pub fn snapshot(&self, peer: &str) -> Option<PeerSnapshot> {
        self.peers.get(peer).map(|r| PeerSnapshot {
            peer_id: peer.into(),
            session_id: r.session_id,
            direction: r.direction,
            state: r.state,
            authenticated: r.authenticated,
            capabilities: r.capabilities.clone(),
            last_seen_at: r.last_seen_at,
            retry_at: r.retry_at,
            disconnect_reason: r.disconnect_reason,
        })
    }
    pub fn is_current(&self, peer: &str, session: SessionId) -> bool {
        self.peers
            .get(peer)
            .is_some_and(|r| r.session_id == session && active(r.state))
    }
    fn candidate_wins(
        &self,
        remote: &str,
        existing: PeerDirection,
        candidate: PeerDirection,
    ) -> bool {
        if existing == candidate {
            return false;
        };
        let desired = if self.local_peer_id.as_str() < remote {
            PeerDirection::Outbound
        } else {
            PeerDirection::Inbound
        };
        candidate == desired && existing != desired
    }
    fn active_count(&self) -> usize {
        self.peers.values().filter(|r| active(r.state)).count()
    }
    fn next_session(&mut self) -> SessionId {
        let s = SessionId(self.next_session_id.max(1));
        self.next_session_id = self.next_session_id.saturating_add(1);
        s
    }
    fn current_mut(&mut self, peer: &str, session: SessionId) -> Option<&mut PeerRecord> {
        self.peers.get_mut(peer).filter(|r| r.session_id == session)
    }
}
fn active(state: PeerState) -> bool {
    matches!(
        state,
        PeerState::Connecting
            | PeerState::Connected
            | PeerState::Authenticated
            | PeerState::Ready
            | PeerState::Degraded
            | PeerState::Stale
            | PeerState::Disconnecting
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn delayed_old_session_cleanup_cannot_remove_new_authenticated_session() {
        let mut p = PeerManager::new("a", 2);
        let first = p.admit("b", PeerDirection::Outbound, 1).unwrap().session_id;
        assert!(p.disconnect_exact("b", first, DisconnectReason::RemoteClosed, 2));
        let second = p.admit("b", PeerDirection::Outbound, 4).unwrap().session_id;
        assert!(p.authenticate("b", second, vec!["posy".into()], 5));
        assert!(p.mark_ready("b", second, 6));
        assert!(!p.disconnect_exact("b", first, DisconnectReason::RemoteClosed, 7));
        let s = p.snapshot("b").unwrap();
        assert_eq!(s.session_id, second);
        assert_eq!(s.state, PeerState::Ready);
        assert!(s.authenticated)
    }
    #[test]
    fn reciprocal_dials_choose_one_deterministic_direction() {
        let mut a = PeerManager::new("a", 2);
        let mut b = PeerManager::new("b", 2);
        let aout = a.admit("b", PeerDirection::Outbound, 1).unwrap().session_id;
        let bin = b.admit("a", PeerDirection::Inbound, 1).unwrap().session_id;
        assert!(
            matches!(a.admit("b",PeerDirection::Inbound,2),Err(AdmissionError::Duplicate{retained})if retained==aout)
        );
        assert!(
            matches!(b.admit("a",PeerDirection::Outbound,2),Err(AdmissionError::Duplicate{retained})if retained==bin)
        );
    }
    #[test]
    fn quarantine_and_ban_prevent_reentry() {
        let mut p = PeerManager::new("a", 2);
        let s = p.admit("b", PeerDirection::Outbound, 1).unwrap().session_id;
        assert!(p.quarantine_exact("b", s, 10));
        assert_eq!(
            p.admit("b", PeerDirection::Outbound, 2),
            Err(AdmissionError::Quarantined { retry_at: 10 })
        );
        let s = p
            .admit("b", PeerDirection::Outbound, 10)
            .unwrap()
            .session_id;
        assert!(p.ban_exact("b", s, None));
        assert_eq!(
            p.admit("b", PeerDirection::Outbound, 99),
            Err(AdmissionError::Banned { until: None })
        );
    }
    #[test]
    fn stale_detection_is_local_lifecycle_not_consensus() {
        let mut p = PeerManager::new("a", 2);
        let s = p.admit("b", PeerDirection::Outbound, 1).unwrap().session_id;
        assert!(p.authenticate("b", s, vec![], 2));
        assert_eq!(p.mark_stale_before(3), 1);
        assert_eq!(p.snapshot("b").unwrap().state, PeerState::Stale);
    }
}
