use synergy_protocol_types::{AuthenticatedPeer, SessionId};

use super::PeerDirection;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSession {
    pub peer: AuthenticatedPeer,
    pub direction: PeerDirection,
    pub established_at: u64,
    pub last_sequence: u64,
}

impl PeerSession {
    pub fn accept_sequence(&mut self, session_id: SessionId, sequence: u64) -> bool {
        if session_id != self.peer.session_id || sequence <= self.last_sequence {
            return false;
        }
        self.last_sequence = sequence;
        true
    }
}
