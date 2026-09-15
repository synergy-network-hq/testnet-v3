use super::PeerState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerTransitionError {
    pub from: PeerState,
    pub to: PeerState,
}

pub fn validate_peer_transition(from: PeerState, to: PeerState) -> Result<(), PeerTransitionError> {
    let allowed = matches!(
        (from, to),
        (PeerState::Connecting, PeerState::Connected)
            | (PeerState::Connected, PeerState::Authenticated)
            | (PeerState::Authenticated, PeerState::Ready)
            | (PeerState::Ready, PeerState::Degraded)
            | (PeerState::Degraded, PeerState::Ready)
            | (PeerState::Ready | PeerState::Degraded, PeerState::Stale)
            | (_, PeerState::Disconnecting)
            | (PeerState::Disconnecting, PeerState::Disconnected)
            | (_, PeerState::Quarantined)
            | (_, PeerState::Banned)
    );
    allowed
        .then_some(())
        .ok_or(PeerTransitionError { from, to })
}
