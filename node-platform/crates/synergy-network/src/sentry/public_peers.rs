use std::collections::BTreeSet;

use synergy_protocol_types::AuthenticatedPeer;

#[derive(Debug)]
pub struct PublicPeerSet {
    capacity: usize,
    peers: BTreeSet<String>,
}

impl PublicPeerSet {
    pub fn new(capacity: usize) -> Result<Self, String> {
        if capacity == 0 {
            return Err("public peer capacity must be nonzero".into());
        }
        Ok(Self {
            capacity,
            peers: BTreeSet::new(),
        })
    }

    pub fn admit(&mut self, peer: &AuthenticatedPeer) -> Result<bool, String> {
        if self.peers.contains(peer.node_address.as_str()) {
            return Ok(false);
        }
        if self.peers.len() >= self.capacity {
            return Err("public peer capacity reached".into());
        }
        self.peers.insert(peer.node_address.to_string());
        Ok(true)
    }

    pub fn remove(&mut self, peer_id: &str) -> bool {
        self.peers.remove(peer_id)
    }
}
