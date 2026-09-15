#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedHead {
    pub peer_id: String,
    pub finalized_height: u64,
    pub finalized_hash: String,
    pub finality_evidence_id: String,
}
