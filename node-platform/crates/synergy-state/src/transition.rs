use std::path::Path;

use synergy_storage::{
    AtomicStore, PruneBoundary, PruneReport, RequiredRecord, StoragePrecondition,
    StorageTransaction,
};

use crate::state::{history_record, validate, DurableState, STATE_FORMAT, STATE_RECORD};
use crate::{state_root, FinalizedState, WorldState};

const MAX_STATE_TRANSACTION_BYTES: usize = 80 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateError {
    Storage(String),
    Corrupt(String),
    InvalidCommitment,
    HeightGap { current: u64, requested: u64 },
    ConflictingReplay,
    InsufficientBalance,
    BalanceOverflow,
    NonceMismatch { expected: u64, supplied: u64 },
    NonceOverflow,
    InvalidDiff,
    ProtocolValueMismatch(String),
    InvalidPruneRequest,
}

/// Durable state owner. The caller supplies a PoSy-verified finalization; this
/// type does not expose any method that computes votes, quorum, or finality.
#[derive(Debug)]
pub struct FinalizedStateStore {
    store: AtomicStore,
    world_store: AtomicStore,
    current: Option<FinalizedState>,
}

impl FinalizedStateStore {
    pub fn load(root: impl AsRef<Path>) -> Result<Self, StateError> {
        let store = AtomicStore::new(root.as_ref(), 4 * 1024 * 1024).map_err(storage_error)?;
        let world_store =
            AtomicStore::new(root.as_ref(), 64 * 1024 * 1024).map_err(storage_error)?;
        let current = if store.exists(STATE_RECORD).map_err(storage_error)? {
            let bytes = store.read_bounded(STATE_RECORD).map_err(storage_error)?;
            Some(decode_record(&bytes)?.state)
        } else {
            None
        };
        let result = Self {
            store,
            world_store,
            current,
        };
        // New-format commits have an immutable per-height record. A missing
        // record is tolerated for the pre-migration latest-only format.
        if let Some(latest) = result.current() {
            if let Some(archived) = result.history_at(latest.finalized_height)? {
                if archived != *latest {
                    return Err(StateError::ConflictingReplay);
                }
            }
        }
        Ok(result)
    }

    pub fn current(&self) -> Option<&FinalizedState> {
        self.current.as_ref()
    }

    /// Loads the exact account state for the current durable finality pointer.
    /// A commitment without account data is not usable for execution restart.
    pub fn current_world_state(&self) -> Result<Option<WorldState>, StateError> {
        let Some(current) = self.current() else {
            return Ok(None);
        };
        self.world_state_at(current.finalized_height)
    }

    /// Loads account state for an exact durable finality height.
    ///
    /// Historical reads remain bound to the immutable finalized commitment.
    /// A legacy latest-only commitment is accepted only when it is also the
    /// current pointer; it cannot authorize arbitrary historical state.
    pub fn world_state_at(&self, height: u64) -> Result<Option<WorldState>, StateError> {
        let commitment = match self.history_at(height)? {
            Some(commitment) => commitment,
            None => match self.current() {
                Some(current) if current.finalized_height == height => current.clone(),
                _ => return Ok(None),
            },
        };
        let path = world_record(height);
        if !self.world_store.exists(&path).map_err(storage_error)? {
            return Ok(None);
        }
        let bytes = self
            .world_store
            .read_bounded(&path)
            .map_err(storage_error)?;
        let world: WorldState = serde_json::from_slice(&bytes)
            .map_err(|error| StateError::Corrupt(error.to_string()))?;
        if state_root(&world)? != commitment.state_root {
            return Err(StateError::Corrupt(
                "durable account state root differs from finality".into(),
            ));
        }
        Ok(Some(world))
    }

    /// Persists account bytes before the finalized commitment. Only the
    /// PoSy-verified caller may supply the finality record.
    pub fn commit_verified_world_state(
        &mut self,
        next: FinalizedState,
        world: &WorldState,
    ) -> Result<bool, StateError> {
        validate(&next)?;
        if state_root(world)? != next.state_root {
            return Err(StateError::InvalidCommitment);
        }
        let replay = if let Some(current) = self.current() {
            if next.finalized_height == current.finalized_height {
                if next != *current {
                    return Err(StateError::ConflictingReplay);
                }
                true
            } else {
                if next.finalized_height != current.finalized_height.saturating_add(1) {
                    return Err(StateError::HeightGap {
                        current: current.finalized_height,
                        requested: next.finalized_height,
                    });
                }
                false
            }
        } else {
            false
        };
        let world_path = world_record(next.finalized_height);
        let history_path = history_record(next.finalized_height);
        let world_bytes =
            serde_json::to_vec(world).map_err(|error| StateError::Corrupt(error.to_string()))?;
        let durable = durable_bytes(&next)?;
        let preconditions = [
            self.current_precondition()?,
            StoragePrecondition {
                relative_path: world_path.clone().into(),
                required: RequiredRecord::MissingOrExact(world_bytes.clone()),
            },
            StoragePrecondition {
                relative_path: history_path.clone().into(),
                required: RequiredRecord::MissingOrExact(durable.clone()),
            },
        ];
        let mut transaction =
            StorageTransaction::new(MAX_STATE_TRANSACTION_BYTES).map_err(storage_error)?;
        transaction
            .put(world_path, world_bytes)
            .and_then(|()| transaction.put(history_path, durable.clone()))
            .and_then(|()| transaction.put(STATE_RECORD, durable))
            .map_err(storage_error)?;
        transaction
            .commit_guarded(&mut self.world_store, &preconditions)
            .map_err(storage_error)?;
        self.current = Some(next);
        Ok(!replay)
    }

    /// Commits a finalized snapshot supplied by the authenticated Sync
    /// restore path. Unlike sequential block commits, a snapshot may advance
    /// over an unavailable height range; it can never regress or overwrite a
    /// conflicting durable commitment.
    pub fn commit_verified_snapshot(
        &mut self,
        next: FinalizedState,
        world: &WorldState,
    ) -> Result<bool, StateError> {
        validate(&next)?;
        if state_root(world)? != next.state_root {
            return Err(StateError::InvalidCommitment);
        }
        if let Some(current) = self.current() {
            if next.finalized_height < current.finalized_height {
                return Err(StateError::HeightGap {
                    current: current.finalized_height,
                    requested: next.finalized_height,
                });
            }
            if next.finalized_height == current.finalized_height {
                return if next == *current {
                    Ok(false)
                } else {
                    Err(StateError::ConflictingReplay)
                };
            }
        }
        let world_path = world_record(next.finalized_height);
        let history_path = history_record(next.finalized_height);
        let world_bytes =
            serde_json::to_vec(world).map_err(|error| StateError::Corrupt(error.to_string()))?;
        let durable = durable_bytes(&next)?;
        let preconditions = [
            self.current_precondition()?,
            StoragePrecondition {
                relative_path: world_path.clone().into(),
                required: RequiredRecord::MissingOrExact(world_bytes.clone()),
            },
            StoragePrecondition {
                relative_path: history_path.clone().into(),
                required: RequiredRecord::MissingOrExact(durable.clone()),
            },
        ];
        let mut transaction =
            StorageTransaction::new(MAX_STATE_TRANSACTION_BYTES).map_err(storage_error)?;
        transaction
            .put(world_path, world_bytes)
            .and_then(|()| transaction.put(history_path, durable.clone()))
            .and_then(|()| transaction.put(STATE_RECORD, durable))
            .map_err(storage_error)?;
        transaction
            .commit_guarded(&mut self.world_store, &preconditions)
            .map_err(storage_error)?;
        self.current = Some(next);
        Ok(true)
    }

    /// Retrieve a finalized block/state commitment for verified historical
    /// replay. Legacy latest-only records may have no archived entry.
    pub fn history_at(&self, height: u64) -> Result<Option<FinalizedState>, StateError> {
        let path = history_record(height);
        if !self.store.exists(&path).map_err(storage_error)? {
            return Ok(None);
        }
        let bytes = self.store.read_bounded(&path).map_err(storage_error)?;
        let record = decode_record(&bytes)?;
        if record.state.finalized_height != height {
            return Err(StateError::Corrupt("history height mismatch".into()));
        }
        Ok(Some(record.state))
    }

    pub fn commit_verified_finalization(
        &mut self,
        next: FinalizedState,
    ) -> Result<bool, StateError> {
        validate(&next)?;
        if let Some(current) = &self.current {
            if next.finalized_height == current.finalized_height {
                return if next == *current {
                    Ok(false)
                } else {
                    Err(StateError::ConflictingReplay)
                };
            }
            if next.finalized_height != current.finalized_height.saturating_add(1) {
                return Err(StateError::HeightGap {
                    current: current.finalized_height,
                    requested: next.finalized_height,
                });
            }
        }
        let history_path = history_record(next.finalized_height);
        let durable = durable_bytes(&next)?;
        let preconditions = [
            self.current_precondition()?,
            StoragePrecondition {
                relative_path: history_path.clone().into(),
                required: RequiredRecord::MissingOrExact(durable.clone()),
            },
        ];
        let mut transaction =
            StorageTransaction::new(MAX_STATE_TRANSACTION_BYTES).map_err(storage_error)?;
        transaction
            .put(history_path, durable.clone())
            .and_then(|()| transaction.put(STATE_RECORD, durable))
            .map_err(storage_error)?;
        transaction
            .commit_guarded(&mut self.store, &preconditions)
            .map_err(storage_error)?;
        self.current = Some(next);
        Ok(true)
    }

    /// Removes finalized account-state and commitment history only below the
    /// caller-supplied finalized retention boundary. The current pointer and
    /// every retained height remain untouched; PoSy remains the sole source of
    /// the finalized height used to derive this boundary.
    pub fn prune_finalized_history(
        &self,
        finalized_height: u64,
        retain_blocks: u64,
    ) -> Result<PruneReport, StateError> {
        let Some(through_height) = (PruneBoundary {
            finalized_height,
            retain_from_height: retain_blocks,
        })
        .oldest_prunable_height()
        .map_err(storage_error)?
        else {
            return Ok(PruneReport::default());
        };
        let world = self
            .world_store
            .prune_height_records_through("finalized-world", through_height)
            .map_err(storage_error)?;
        let history = self
            .store
            .prune_height_records_through("finalized-history", through_height)
            .map_err(storage_error)?;
        Ok(PruneReport {
            examined_records: world
                .examined_records
                .saturating_add(history.examined_records),
            removed_records: world
                .removed_records
                .saturating_add(history.removed_records),
        })
    }

    fn current_precondition(&self) -> Result<StoragePrecondition, StateError> {
        Ok(StoragePrecondition {
            relative_path: STATE_RECORD.into(),
            required: match self.current.as_ref() {
                Some(current) => RequiredRecord::Exact(durable_bytes(current)?),
                None => RequiredRecord::Missing,
            },
        })
    }

    pub const fn may_determine_finality(&self) -> bool {
        false
    }
}

fn durable_bytes(state: &FinalizedState) -> Result<Vec<u8>, StateError> {
    serde_json::to_vec(&DurableState {
        format: STATE_FORMAT.into(),
        state: state.clone(),
    })
    .map_err(|error| StateError::Corrupt(error.to_string()))
}

fn world_record(height: u64) -> String {
    format!("finalized-world/{height:020}.json")
}

fn storage_error(error: synergy_storage::StorageError) -> StateError {
    match error {
        synergy_storage::StorageError::ConflictingWrite => StateError::ConflictingReplay,
        error => StateError::Storage(error.to_string()),
    }
}

fn decode_record(bytes: &[u8]) -> Result<DurableState, StateError> {
    let record: DurableState =
        serde_json::from_slice(bytes).map_err(|error| StateError::Corrupt(error.to_string()))?;
    if record.format != STATE_FORMAT {
        return Err(StateError::Corrupt(
            "unsupported finalized-state format".into(),
        ));
    }
    validate(&record.state)?;
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn root() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "synergy-state-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn state(height: u64, block: &str) -> FinalizedState {
        FinalizedState {
            finalized_height: height,
            finalized_block_id: block.into(),
            state_root: format!("root-{height}"),
        }
    }

    #[test]
    fn persists_verified_commit_and_allows_only_identical_replay() {
        let root = root();
        let mut store = FinalizedStateStore::load(&root).unwrap();
        assert!(store.commit_verified_finalization(state(1, "one")).unwrap());
        assert_eq!(store.history_at(1).unwrap(), Some(state(1, "one")));
        assert!(!store.commit_verified_finalization(state(1, "one")).unwrap());
        drop(store);
        let store = FinalizedStateStore::load(&root).unwrap();
        assert_eq!(store.current(), Some(&state(1, "one")));
        assert_eq!(store.history_at(1).unwrap(), Some(state(1, "one")));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_conflicting_or_non_contiguous_finalized_history() {
        let root = root();
        let mut store = FinalizedStateStore::load(&root).unwrap();
        store.commit_verified_finalization(state(1, "one")).unwrap();
        assert_eq!(
            store.commit_verified_finalization(state(1, "other")),
            Err(StateError::ConflictingReplay)
        );
        assert!(matches!(
            store.commit_verified_finalization(state(3, "three")),
            Err(StateError::HeightGap { .. })
        ));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn preserves_earlier_history_after_later_finalization() {
        let root = root();
        let mut store = FinalizedStateStore::load(&root).unwrap();
        store.commit_verified_finalization(state(1, "one")).unwrap();
        store.commit_verified_finalization(state(2, "two")).unwrap();
        drop(store);
        let store = FinalizedStateStore::load(&root).unwrap();
        assert_eq!(store.current(), Some(&state(2, "two")));
        assert_eq!(store.history_at(1).unwrap(), Some(state(1, "one")));
        assert_eq!(store.history_at(2).unwrap(), Some(state(2, "two")));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn interrupted_pointer_write_cannot_replace_a_record_with_a_conflict() {
        let root = root();
        let mut store = FinalizedStateStore::load(&root).unwrap();
        store.commit_verified_finalization(state(1, "one")).unwrap();
        let archived = DurableState {
            format: STATE_FORMAT.into(),
            state: state(2, "two"),
        };
        store
            .store
            .write_atomic(history_record(2), &serde_json::to_vec(&archived).unwrap())
            .unwrap();
        assert_eq!(
            store.commit_verified_finalization(state(2, "conflict")),
            Err(StateError::ConflictingReplay)
        );
        assert_eq!(store.current(), Some(&state(1, "one")));
        assert_eq!(store.history_at(2).unwrap(), Some(state(2, "two")));
        assert!(store.commit_verified_finalization(state(2, "two")).unwrap());
        std::fs::remove_dir_all(root).unwrap();
    }
}
