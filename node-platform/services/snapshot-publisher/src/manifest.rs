use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedSnapshotManifest {
    pub snapshot_id: String,
    pub height: u64,
    pub state_root: String,
    pub chunks: Vec<String>,
    pub finality_proof: Vec<u8>,
    pub signature: Vec<u8>,
}
impl PublishedSnapshotManifest {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.snapshot_id.is_empty()
            || self.height == 0
            || self.state_root.len() != 64
            || self.chunks.is_empty()
            || self.finality_proof.is_empty()
            || self.signature.is_empty()
        {
            Err("invalid snapshot manifest")
        } else {
            Ok(())
        }
    }
}
