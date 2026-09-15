use std::collections::BTreeMap;

use crate::{SnapshotValidationError, StateCheckpoint, StateChunk};

/// Hard limits applied before retaining snapshot bytes in memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotDownloadLimits {
    pub max_chunk_bytes: usize,
    pub max_total_bytes: usize,
}

/// Failure while accepting or completing a bounded state download.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DownloadError {
    InvalidLimits,
    ChunkOutOfRange(u64),
    ChunkTooLarge(u64),
    TotalTooLarge,
    InvalidChunk(SnapshotValidationError),
    ConflictingChunk(u64),
    Incomplete { received: u64, expected: u64 },
}

/// Owns chunks for one immutable checkpoint and supports deterministic resume.
#[derive(Debug, Clone)]
pub struct SnapshotDownload {
    checkpoint: StateCheckpoint,
    limits: SnapshotDownloadLimits,
    received_bytes: usize,
    chunks: BTreeMap<u64, StateChunk>,
}

impl SnapshotDownload {
    /// Starts a bounded download for one checkpoint.
    ///
    /// # Errors
    /// Rejects zero limits or a per-chunk limit larger than the total limit.
    pub fn new(
        checkpoint: StateCheckpoint,
        limits: SnapshotDownloadLimits,
    ) -> Result<Self, DownloadError> {
        if limits.max_chunk_bytes == 0
            || limits.max_total_bytes == 0
            || limits.max_chunk_bytes > limits.max_total_bytes
        {
            return Err(DownloadError::InvalidLimits);
        }
        Ok(Self {
            checkpoint,
            limits,
            received_bytes: 0,
            chunks: BTreeMap::new(),
        })
    }

    /// Accepts one integrity-checked chunk, taking ownership after validation.
    ///
    /// Duplicate identical chunks are idempotent; conflicting duplicates fail.
    ///
    /// # Errors
    /// Rejects out-of-range, oversized, malformed, or conflicting chunks.
    pub fn accept(&mut self, chunk: StateChunk) -> Result<bool, DownloadError> {
        if chunk.index >= self.checkpoint.chunk_count {
            return Err(DownloadError::ChunkOutOfRange(chunk.index));
        }
        if chunk.bytes.len() > self.limits.max_chunk_bytes {
            return Err(DownloadError::ChunkTooLarge(chunk.index));
        }
        chunk.validate().map_err(DownloadError::InvalidChunk)?;
        if let Some(existing) = self.chunks.get(&chunk.index) {
            if existing == &chunk {
                return Ok(false);
            }
            return Err(DownloadError::ConflictingChunk(chunk.index));
        }
        let received_bytes = self
            .received_bytes
            .checked_add(chunk.bytes.len())
            .ok_or(DownloadError::TotalTooLarge)?;
        if received_bytes > self.limits.max_total_bytes {
            return Err(DownloadError::TotalTooLarge);
        }
        self.received_bytes = received_bytes;
        self.chunks.insert(chunk.index, chunk);
        Ok(true)
    }

    /// Returns up to `limit` missing indexes in ascending order.
    pub fn missing_indices(&self, limit: usize) -> Vec<u64> {
        (0..self.checkpoint.chunk_count)
            .filter(|index| !self.chunks.contains_key(index))
            .take(limit)
            .collect()
    }

    /// Consumes a complete download and returns chunks in manifest order.
    ///
    /// # Errors
    /// Returns [`DownloadError::Incomplete`] until every chunk is present.
    pub fn complete(self) -> Result<Vec<StateChunk>, DownloadError> {
        if self.chunks.len() as u64 != self.checkpoint.chunk_count {
            return Err(DownloadError::Incomplete {
                received: self.chunks.len() as u64,
                expected: self.checkpoint.chunk_count,
            });
        }
        Ok(self.chunks.into_values().collect())
    }

    /// Returns the immutable checkpoint for this download.
    pub const fn checkpoint(&self) -> &StateCheckpoint {
        &self.checkpoint
    }

    /// Returns retained chunks in ascending index order.
    pub fn received_chunks(&self) -> impl ExactSizeIterator<Item = &StateChunk> {
        self.chunks.values()
    }

    /// Returns the retained byte count.
    pub const fn received_bytes(&self) -> usize {
        self.received_bytes
    }
}
