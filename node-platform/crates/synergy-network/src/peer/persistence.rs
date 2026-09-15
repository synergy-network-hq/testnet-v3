use synergy_protocol_types::SessionId;

use super::{DisconnectReason, PeerDirection, PeerState};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedPeerState {
    pub peer_id: String,
    pub last_session_id: SessionId,
    pub direction: PeerDirection,
    pub state: PeerState,
    pub last_seen_at: u64,
    pub retry_at: Option<u64>,
    pub disconnect_reason: Option<DisconnectReason>,
}

/// Persistence is injected by the node storage owner. Live authenticated
/// session state is never restored as authority after restart.
pub trait PeerSnapshotStore {
    fn load(&self) -> Result<Vec<PersistedPeerState>, String>;
    fn save(&mut self, states: &[PersistedPeerState]) -> Result<(), String>;
}
