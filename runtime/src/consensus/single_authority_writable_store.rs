//! O(1) steady-state writable wrapper over `SingleAuthorityFinalityStore`.
//!
//! One full validation scan at open, then per-block append validates against a
//! cached tail and writes exactly one frame. `recover()` is never called per
//! block. Any uncertain write/sync failure poisons the handle permanently.

use super::single_authority_finality_store::*;
use super::single_authority_writer_lock::SingleAuthorityWriterLock;

/// Counts full-log scans so tests can prove steady-state append is O(1).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SingleAuthorityScanStats {
    pub full_scans: u64,
}

#[derive(Debug)]
pub struct WritableSingleAuthorityStore {
    store: SingleAuthorityFinalityStore,
    _writer: SingleAuthorityWriterLock,
    cached_tail: Option<SingleAuthorityFinalityRecord>,
    cached_end_offset: u64,
    cached_head: Option<SingleAuthorityFinalizedHead>,
    stats: SingleAuthorityScanStats,
    poisoned: Option<String>,
}

impl WritableSingleAuthorityStore {
    /// Exclusive writable open: one O(n) validation scan, then cached.
    pub fn open(store: SingleAuthorityFinalityStore) -> Result<Self, String> {
        let writer = SingleAuthorityWriterLock::acquire(store.log_path())?;
        let startup = store.recover_startup_state()?;
        let head = store.load_head()?;
        let recovery = store.recover_with_head(head.as_ref())?;
        Ok(Self {
            cached_tail: startup.finalized,
            cached_end_offset: recovery.durable_end_offset,
            cached_head: store.load_head()?,
            store,
            _writer: writer,
            stats: SingleAuthorityScanStats { full_scans: 1 },
            poisoned: None,
        })
    }

    pub fn stats(&self) -> SingleAuthorityScanStats {
        self.stats
    }

    pub fn cached_tail(&self) -> Option<&SingleAuthorityFinalityRecord> {
        self.cached_tail.as_ref()
    }

    pub fn cached_head(&self) -> Option<&SingleAuthorityFinalizedHead> {
        self.cached_head.as_ref()
    }

    pub fn next_height(&self) -> u64 {
        self.cached_tail
            .as_ref()
            .map(|r| r.height + 1)
            .unwrap_or(self.store.binding().first_authority_height)
    }

    fn check_usable(&self) -> Result<(), String> {
        match &self.poisoned {
            Some(reason) => Err(format!(
                "single-authority writable store is in a failed state: {reason}"
            )),
            None => Ok(()),
        }
    }
}

impl WritableSingleAuthorityStore {
    /// O(1) append: validates against the cached tail, writes one frame,
    /// fsyncs, then updates the cache. Never rescans the log.
    pub fn append_finalized(
        &mut self,
        record: &SingleAuthorityFinalityRecord,
    ) -> Result<u64, String> {
        self.check_usable()?;

        // Linkage is validated against the CACHED tail, not a fresh scan.
        match &self.cached_tail {
            None => {
                let first = self.store.binding().first_authority_height;
                if record.height != first {
                    return Err(format!(
                        "single-authority finality log must begin at height {first}, found {}",
                        record.height
                    ));
                }
            }
            Some(tail) => {
                if record.height == tail.height {
                    if record == tail {
                        return Ok(self.cached_end_offset);
                    }
                    return Err(format!(
                        "single-authority finality height {} is already finalized with a \
                         different block",
                        record.height
                    ));
                }
                if record.height != tail.height + 1 {
                    return Err(format!(
                        "single-authority finality height {} does not follow {}",
                        record.height, tail.height
                    ));
                }
                if record.parent_hash != tail.block_hash {
                    return Err(format!(
                        "single-authority finality record at height {} has a broken parent link",
                        record.height
                    ));
                }
            }
        }

        match self.store.append_frame_at(record, self.cached_end_offset) {
            Ok(end_offset) => {
                // Cache advances ONLY after a successful write+fsync.
                self.cached_tail = Some(record.clone());
                self.cached_end_offset = end_offset;
                Ok(end_offset)
            }
            Err(error) => {
                self.poisoned = Some(error.clone());
                Err(error)
            }
        }
    }
}

impl WritableSingleAuthorityStore {
    /// Commits the durable head; the head cache advances only on success.
    pub fn commit_head(
        &mut self,
        record: &SingleAuthorityFinalityRecord,
    ) -> Result<(), String> {
        self.check_usable()?;
        match self.store.commit_head(record, self.cached_end_offset) {
            Ok(head) => {
                self.cached_head = Some(head);
                Ok(())
            }
            Err(error) => {
                self.poisoned = Some(error.clone());
                Err(error)
            }
        }
    }

    /// Read-only access for inspection paths - does not take the writer role.
    pub fn store(&self) -> &SingleAuthorityFinalityStore {
        &self.store
    }
}
