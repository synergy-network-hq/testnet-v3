use serde::{Deserialize, Serialize};
use synergy_protocol_types::AuthenticatedPeer;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PosyEnvelope {
    pub peer_id: String,
    pub session_id: u64,
    pub payload: Vec<u8>,
}

impl PosyEnvelope {
    pub fn authenticated_peer(&self) -> Result<AuthenticatedPeer, String> {
        AuthenticatedPeer::new(
            self.peer_id.clone(),
            synergy_protocol_types::SessionId(self.session_id),
            vec!["posy".into()],
        )
        .map_err(|error| error.to_string())
    }
}
