use crate::{
    CheckpointError, SnapshotManifest, SnapshotValidationError, StateCheckpoint, StateChunk,
    VerifiedHead,
};

/// Snapshot package whose manifest, chunks, and finality anchor are verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSnapshot {
    pub(super) checkpoint: StateCheckpoint,
    pub(super) manifest: SnapshotManifest,
    pub(super) chunks: Vec<StateChunk>,
}

/// Failure while verifying a complete state snapshot package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotVerifyError {
    Checkpoint(CheckpointError),
    Chunks(SnapshotValidationError),
}

/// Verifies new-format state packages against caller-verified PoSy finality.
#[derive(Debug, Clone)]
pub struct StateSnapshotVerifier {
    chain_id: u64,
    genesis_hash: String,
}

impl StateSnapshotVerifier {
    /// Pins snapshot verification to one chain incarnation.
    pub fn new(chain_id: u64, genesis_hash: impl Into<String>) -> Self {
        Self {
            chain_id,
            genesis_hash: genesis_hash.into(),
        }
    }

    /// Verifies a complete package without importing state.
    ///
    /// # Errors
    /// Rejects any manifest/finality mismatch, missing or reordered chunk, or
    /// chunk/root integrity failure.
    pub fn verify(
        &self,
        manifest: SnapshotManifest,
        chunks: Vec<StateChunk>,
        verified_head: &VerifiedHead,
    ) -> Result<VerifiedSnapshot, SnapshotVerifyError> {
        let checkpoint = StateCheckpoint::from_manifest(
            &manifest,
            self.chain_id,
            &self.genesis_hash,
            verified_head,
        )
        .map_err(SnapshotVerifyError::Checkpoint)?;
        manifest
            .validate_chunks(&chunks)
            .map_err(SnapshotVerifyError::Chunks)?;
        Ok(VerifiedSnapshot {
            checkpoint,
            manifest,
            chunks,
        })
    }

    /// Sync snapshot verification never establishes PoSy finality.
    pub const fn may_determine_finality(&self) -> bool {
        false
    }
}

impl VerifiedSnapshot {
    /// Returns the immutable finalized checkpoint binding.
    pub const fn checkpoint(&self) -> &StateCheckpoint {
        &self.checkpoint
    }

    /// Returns the verified snapshot manifest.
    pub const fn manifest(&self) -> &SnapshotManifest {
        &self.manifest
    }

    /// Returns integrity-checked chunks in manifest order.
    pub fn chunks(&self) -> &[StateChunk] {
        &self.chunks
    }
}
