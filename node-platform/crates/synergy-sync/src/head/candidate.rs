#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncPeerCandidate {
    pub peer_id: String,
    pub authenticated: bool,
    pub protocol_compatible: bool,
    pub genesis_hash: String,
    pub quarantined: bool,
    pub consensus_duties_disabled: bool,
    pub designated_support: bool,
    pub advertised_height: u64,
}
