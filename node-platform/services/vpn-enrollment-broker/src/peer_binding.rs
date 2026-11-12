use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerBinding {
    pub node_address: String,
    pub netbird_peer_id: String,
    pub overlay_address: String,
}
impl PeerBinding {
    pub fn validate(&self) -> Result<(), String> {
        if self.node_address.is_empty()
            || self.netbird_peer_id.is_empty()
            || self.overlay_address.is_empty()
        {
            Err("incomplete peer binding".into())
        } else {
            Ok(())
        }
    }
}
