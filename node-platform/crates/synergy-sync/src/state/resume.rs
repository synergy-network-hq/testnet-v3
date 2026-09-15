use std::collections::{BTreeMap, BTreeSet};

use crate::{DownloadError, SnapshotDownload, SnapshotDownloadLimits, StateCheckpoint, StateChunk};

/// Integrity metadata for one durably staged state chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedChunk {
    pub index: u64,
    pub byte_len: u64,
    pub digest: String,
}

/// New-format resume token for one immutable checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeToken {
    checkpoint_id: String,
    chunks: Vec<ReceivedChunk>,
}

/// Failure while validating or restoring resumable state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResumeError {
    InvalidCheckpointId,
    InvalidChunkMetadata(u64),
    DuplicateChunk(u64),
    CheckpointMismatch,
    ChunkOutOfRange(u64),
    MissingStagedChunk(u64),
    UnexpectedStagedChunk(u64),
    StagedChunkMismatch(u64),
    Download(DownloadError),
}

impl ResumeToken {
    /// Creates a validated token from decoded new-format metadata.
    ///
    /// # Errors
    /// Rejects malformed checkpoint IDs, duplicate indexes, empty digests, or
    /// zero-sized chunks.
    pub fn new(
        checkpoint_id: impl Into<String>,
        mut chunks: Vec<ReceivedChunk>,
    ) -> Result<Self, ResumeError> {
        let checkpoint_id = checkpoint_id.into();
        if !is_lower_hex_digest(&checkpoint_id) {
            return Err(ResumeError::InvalidCheckpointId);
        }
        chunks.sort_by_key(|chunk| chunk.index);
        let mut seen = BTreeSet::new();
        for chunk in &chunks {
            if chunk.byte_len == 0 || !is_lower_hex_digest(&chunk.digest) {
                return Err(ResumeError::InvalidChunkMetadata(chunk.index));
            }
            if !seen.insert(chunk.index) {
                return Err(ResumeError::DuplicateChunk(chunk.index));
            }
        }
        Ok(Self {
            checkpoint_id,
            chunks,
        })
    }

    /// Captures metadata from chunks already retained by a download.
    pub fn from_download(download: &SnapshotDownload) -> Self {
        let chunks = download
            .received_chunks()
            .map(|chunk| ReceivedChunk {
                index: chunk.index,
                byte_len: chunk.bytes.len() as u64,
                digest: chunk.digest.clone(),
            })
            .collect();
        Self {
            checkpoint_id: download.checkpoint().checkpoint_id.clone(),
            chunks,
        }
    }

    /// Restores a bounded download from separately staged chunk bytes.
    ///
    /// # Errors
    /// Rejects a different checkpoint, incomplete/extra staged data, metadata
    /// mismatch, or any normal download validation failure.
    pub fn restore(
        &self,
        checkpoint: StateCheckpoint,
        limits: SnapshotDownloadLimits,
        staged: Vec<StateChunk>,
    ) -> Result<SnapshotDownload, ResumeError> {
        if checkpoint.checkpoint_id != self.checkpoint_id {
            return Err(ResumeError::CheckpointMismatch);
        }
        let expected = self
            .chunks
            .iter()
            .map(|chunk| (chunk.index, chunk))
            .collect::<BTreeMap<_, _>>();
        for index in expected.keys() {
            if *index >= checkpoint.chunk_count {
                return Err(ResumeError::ChunkOutOfRange(*index));
            }
        }
        let mut found = BTreeSet::new();
        let mut download =
            SnapshotDownload::new(checkpoint, limits).map_err(ResumeError::Download)?;
        for chunk in staged {
            let Some(metadata) = expected.get(&chunk.index) else {
                return Err(ResumeError::UnexpectedStagedChunk(chunk.index));
            };
            if metadata.byte_len != chunk.bytes.len() as u64 || metadata.digest != chunk.digest {
                return Err(ResumeError::StagedChunkMismatch(chunk.index));
            }
            found.insert(chunk.index);
            download.accept(chunk).map_err(ResumeError::Download)?;
        }
        if let Some(missing) = expected.keys().find(|index| !found.contains(index)) {
            return Err(ResumeError::MissingStagedChunk(*missing));
        }
        Ok(download)
    }

    /// Returns the checkpoint identifier encoded by the token.
    pub fn checkpoint_id(&self) -> &str {
        &self.checkpoint_id
    }

    /// Returns chunk metadata in ascending index order.
    pub fn chunks(&self) -> &[ReceivedChunk] {
        &self.chunks
    }
}

fn is_lower_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
