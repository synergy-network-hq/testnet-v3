use sha3::{Digest, Sha3_256};

use crate::StateChunk;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotManifest {
    pub chain_id: u64,
    pub genesis_hash: String,
    pub finalized_height: u64,
    pub finalized_block_id: String,
    pub state_root: String,
    pub chunks_root: String,
    pub chunk_count: u64,
    pub finality_evidence_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotValidationError {
    InvalidManifest,
    InvalidChunk(u64),
    ChunkCount,
    ChunkOrder,
    ChunksRoot,
}

impl SnapshotManifest {
    pub fn validate_structure(&self) -> Result<(), SnapshotValidationError> {
        if self.chain_id != 1266
            || self.genesis_hash.trim().is_empty()
            || self.finalized_height == 0
            || self.finalized_block_id.trim().is_empty()
            || self.state_root.trim().is_empty()
            || self.chunks_root.len() != 64
            || self.chunk_count == 0
            || self.finality_evidence_id.trim().is_empty()
        {
            return Err(SnapshotValidationError::InvalidManifest);
        }
        Ok(())
    }

    pub fn validate_chunks(&self, chunks: &[StateChunk]) -> Result<(), SnapshotValidationError> {
        self.validate_structure()?;
        if chunks.len() != self.chunk_count as usize {
            return Err(SnapshotValidationError::ChunkCount);
        }
        for (index, chunk) in chunks.iter().enumerate() {
            if chunk.index != index as u64 {
                return Err(SnapshotValidationError::ChunkOrder);
            }
            chunk.validate()?;
        }
        let actual = chunks_root(chunks);
        if actual != self.chunks_root {
            return Err(SnapshotValidationError::ChunksRoot);
        }
        Ok(())
    }

    pub const fn may_determine_finality(&self) -> bool {
        false
    }
}

pub fn chunks_root(chunks: &[StateChunk]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(b"SYNERGY_STATE_SNAPSHOT_ROOT_V1");
    for chunk in chunks {
        hasher.update(chunk.index.to_be_bytes());
        hasher.update(chunk.digest.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}
