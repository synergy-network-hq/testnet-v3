use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockRequest {
    pub from_height: u64,
    pub through_height: u64,
    pub expected_parent_id: String,
}

impl BlockRequest {
    pub fn validate(&self) -> bool {
        self.from_height > 0
            && self.from_height <= self.through_height
            && !self.expected_parent_id.trim().is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncBlock {
    pub height: u64,
    pub block_id: String,
    pub parent_id: String,
    pub finality_evidence_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockResponse {
    pub request: BlockRequest,
    pub blocks: Vec<SyncBlock>,
}
