use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct P2pConfiguration {
    pub max_authenticated_peers: usize,
    pub max_pending_handshakes: usize,
    pub max_frame_bytes: usize,
    pub gossip_fanout: usize,
}

impl Default for P2pConfiguration {
    fn default() -> Self {
        Self {
            max_authenticated_peers: 256,
            max_pending_handshakes: 64,
            max_frame_bytes: 4 * 1024 * 1024,
            gossip_fanout: 8,
        }
    }
}
