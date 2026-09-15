use serde::{Deserialize, Serialize};
use synergy_crypto::Hash32;
use synergy_execution::ExecutionCandidate;

use crate::HeadClaim;

/// One-block bounded request anchored to the caller's local finalized tip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizedCandidateRequest {
    pub height: u64,
    pub expected_parent_id: String,
}

impl FinalizedCandidateRequest {
    pub fn validate(&self) -> bool {
        self.height > 0 && !self.expected_parent_id.trim().is_empty()
    }
}

/// Complete candidate data plus the three-QC witness that finalized it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizedCandidateResponse {
    pub request: FinalizedCandidateRequest,
    pub candidate: ExecutionCandidate,
    pub finality_witness: Vec<u8>,
}

/// Bounded request for one authenticated snapshot chunk. The first request
/// identifies a PoSy-verified finalized block; subsequent requests also pin the
/// signed snapshot root learned from the verified manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotChunkRequest {
    pub epoch: u64,
    pub height: u64,
    pub finalized_block_id: String,
    pub finality_evidence_id: String,
    pub expected_snapshot_root: Option<Hash32>,
    pub index: u64,
}

impl SnapshotChunkRequest {
    pub fn validate(&self) -> bool {
        self.epoch > 0
            && self.height > 0
            && !self.finalized_block_id.trim().is_empty()
            && self.finalized_block_id.len() <= 256
            && !self.finality_evidence_id.trim().is_empty()
            && self.finality_evidence_id.len() <= 256
    }
}

/// One authenticated snapshot chunk response. The complete manifest is
/// repeated on every response so a resumed transfer can validate its finalized
/// authority anchor before accepting any chunk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotChunkResponse {
    pub request: SnapshotChunkRequest,
    pub manifest: synergy_snapshot::SnapshotManifest,
    pub chunk: synergy_snapshot::SnapshotChunk,
}

impl SnapshotChunkResponse {
    pub fn validate(&self) -> Result<(), String> {
        if !self.request.validate()
            || self.manifest.epoch != self.request.epoch
            || self.manifest.height != self.request.height
            || self.manifest.finalized_block_id != self.request.finalized_block_id
            || self.manifest.finality_evidence_id != self.request.finality_evidence_id
            || self
                .request
                .expected_snapshot_root
                .is_some_and(|root| root != self.manifest.state_root)
            || self.chunk.index != self.request.index
            || self.chunk.index >= self.manifest.chunk_hashes.len() as u64
            || self.chunk.bytes.is_empty()
            || self.chunk.bytes.len() > self.manifest.chunk_size as usize
            || self.chunk.hash != self.manifest.chunk_hashes[self.chunk.index as usize]
        {
            return Err("snapshot chunk response is not bound to its request".into());
        }
        self.manifest.validate_shape()
    }
}

/// Request for the trust-root-signed authority binding that immediately follows
/// the caller's locally verified, epoch-closing PoSy finality record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpochAuthorityRequest {
    pub current_epoch: u64,
    pub current_epoch_context_root: String,
    pub finalized_height: u64,
    pub finalized_block_id: String,
    pub finality_evidence_id: String,
}

impl EpochAuthorityRequest {
    pub fn validate(&self) -> bool {
        self.current_epoch > 0
            && self.current_epoch_context_root.len() == 128
            && self
                .current_epoch_context_root
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            && self.finalized_height > 0
            && !self.finalized_block_id.trim().is_empty()
            && self.finalized_block_id.len() <= 256
            && self.finality_evidence_id.len() == 128
            && self
                .finality_evidence_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }
}

/// The next frozen authority binding. The authenticated transport identifies
/// the source; the binding still requires the configured Aegis trust-root
/// signature and an exact match to local epoch-closing PoSy finality.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpochAuthorityResponse {
    pub request: EpochAuthorityRequest,
    pub next_authority_binding: Vec<u8>,
}

impl EpochAuthorityResponse {
    pub fn validate(&self) -> bool {
        self.request.validate()
            && !self.next_authority_binding.is_empty()
            && self.next_authority_binding.len() <= 1024 * 1024
    }
}

/// Authenticated Sync protocol messages. Semantic verification remains with
/// Sync, PoSy, and Execution owners rather than the transport adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "body", rename_all = "snake_case")]
pub enum SyncWireMessage {
    Head(HeadClaim),
    FinalizedCandidateRequest(FinalizedCandidateRequest),
    FinalizedCandidateResponse(FinalizedCandidateResponse),
    SnapshotChunkRequest(SnapshotChunkRequest),
    SnapshotChunkResponse(SnapshotChunkResponse),
    EpochAuthorityRequest(EpochAuthorityRequest),
    EpochAuthorityResponse(EpochAuthorityResponse),
}
