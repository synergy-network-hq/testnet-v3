use sha3::{Digest, Sha3_256};

use crate::{SnapshotManifest, SnapshotValidationError, VerifiedHead};

/// Stable new-format anchor for a resumable state download.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateCheckpoint {
    pub checkpoint_id: String,
    pub chain_id: u64,
    pub genesis_hash: String,
    pub finalized_height: u64,
    pub finalized_block_id: String,
    pub state_root: String,
    pub chunks_root: String,
    pub chunk_count: u64,
}

/// Failure while binding a manifest to caller-verified finality.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointError {
    Manifest(SnapshotValidationError),
    ChainMismatch,
    GenesisMismatch,
    FinalizedHeadMismatch,
    FinalityEvidenceMismatch,
}

impl StateCheckpoint {
    /// Builds a checkpoint only when the manifest matches the selected verified head.
    ///
    /// # Errors
    /// Rejects malformed manifests or mismatched chain, Genesis, block, or
    /// caller-verified finality evidence bindings.
    pub fn from_manifest(
        manifest: &SnapshotManifest,
        expected_chain_id: u64,
        expected_genesis_hash: &str,
        verified_head: &VerifiedHead,
    ) -> Result<Self, CheckpointError> {
        manifest
            .validate_structure()
            .map_err(CheckpointError::Manifest)?;
        if manifest.chain_id != expected_chain_id {
            return Err(CheckpointError::ChainMismatch);
        }
        if manifest.genesis_hash != expected_genesis_hash {
            return Err(CheckpointError::GenesisMismatch);
        }
        if manifest.finalized_height != verified_head.finalized_height
            || manifest.finalized_block_id != verified_head.finalized_hash
        {
            return Err(CheckpointError::FinalizedHeadMismatch);
        }
        if manifest.finality_evidence_id != verified_head.finality_evidence_id {
            return Err(CheckpointError::FinalityEvidenceMismatch);
        }
        Ok(Self {
            checkpoint_id: checkpoint_id(manifest),
            chain_id: manifest.chain_id,
            genesis_hash: manifest.genesis_hash.clone(),
            finalized_height: manifest.finalized_height,
            finalized_block_id: manifest.finalized_block_id.clone(),
            state_root: manifest.state_root.clone(),
            chunks_root: manifest.chunks_root.clone(),
            chunk_count: manifest.chunk_count,
        })
    }

    /// Sync checkpoints consume finality and never determine it.
    pub const fn may_determine_finality(&self) -> bool {
        false
    }
}

fn checkpoint_id(manifest: &SnapshotManifest) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(b"SYNERGY_STATE_CHECKPOINT_V1");
    hasher.update(manifest.chain_id.to_be_bytes());
    hash_field(&mut hasher, manifest.genesis_hash.as_bytes());
    hasher.update(manifest.finalized_height.to_be_bytes());
    hash_field(&mut hasher, manifest.finalized_block_id.as_bytes());
    hash_field(&mut hasher, manifest.state_root.as_bytes());
    hash_field(&mut hasher, manifest.chunks_root.as_bytes());
    hasher.update(manifest.chunk_count.to_be_bytes());
    hash_field(&mut hasher, manifest.finality_evidence_id.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn hash_field(hasher: &mut Sha3_256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}
