use std::path::PathBuf;

use super::CanonicalObjectStore;
use crate::{is_hash, FinalizedBlockRecord, PosyError, PosyResult};

#[derive(Debug)]
/// Durable exactly-once storage for verified three-QC finality records.
pub struct FinalityStore(CanonicalObjectStore<FinalizedBlockRecord>);

impl FinalityStore {
    /// Opens the finality namespace beneath `root`.
    pub fn new(root: impl Into<PathBuf>) -> PosyResult<Self> {
        CanonicalObjectStore::new(root, "finality").map(Self)
    }

    /// Persists one contiguous finalized record without overwriting conflicts.
    pub fn commit_exactly_once(
        &self,
        record: &FinalizedBlockRecord,
        previous: Option<&FinalizedBlockRecord>,
    ) -> PosyResult<bool> {
        self.validate_contiguous(record, previous)?;
        self.0.put_once(&format!("h{}", record.height), record)
    }

    pub(super) fn prepared_write(
        &self,
        record: &FinalizedBlockRecord,
        previous: Option<&FinalizedBlockRecord>,
    ) -> PosyResult<synergy_storage::StorageWrite> {
        self.validate_contiguous(record, previous)?;
        self.0.storage_write(&format!("h{}", record.height), record)
    }

    fn validate_contiguous(
        &self,
        record: &FinalizedBlockRecord,
        previous: Option<&FinalizedBlockRecord>,
    ) -> PosyResult<()> {
        if record.height == 0
            || record.block_id.trim().is_empty()
            || !is_hash(&record.finality_certificate_id)
            || !is_hash(&record.protected_execution_root)
        {
            return Err(PosyError::invalid("invalid finalized record"));
        }
        if record.height > 1 && previous.is_none() {
            return Err(PosyError::NotReady(
                "previous finalized record is required for contiguous persistence".into(),
            ));
        }
        if let Some(previous) = previous {
            if record.height
                != previous
                    .height
                    .checked_add(1)
                    .ok_or_else(|| PosyError::invalid("finalized height overflow"))?
            {
                return Err(PosyError::Conflict(
                    "finalized persistence skipped a height".into(),
                ));
            }
        }
        Ok(())
    }

    /// Loads the finalized record at `height`, when present.
    pub fn get(&self, height: u64) -> PosyResult<Option<FinalizedBlockRecord>> {
        self.0.get(&format!("h{height}"))
    }
}
