use std::{cell::RefCell, path::Path, sync::Arc};

use synergy_storage::{
    AtomicStore, PruneBoundary, PruneReport, RequiredRecord, StoragePrecondition,
    StorageTransaction,
};

use crate::state::{history_record, validate, DurableState, STATE_FORMAT, STATE_RECORD};
use crate::world_history::{self, world_record, WorldHistoryTip};
use crate::world_resources::{BudgetedWorld, WorldResourceBudget};
use crate::{state_root, FinalizedReceiptBatch, FinalizedReceiptEntry, FinalizedState, WorldState};

#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReceiptPointer { height: u64, block_id: String, batch_digest: String, row: usize }

struct EncodedSize(usize);
impl std::io::Write for EncodedSize {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.checked_add(bytes.len()).ok_or_else(|| std::io::Error::other("receipt size overflow"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}

type ReceiptBatchRead = (FinalizedReceiptBatch, Option<crate::world_resources::WorldResourcePermit>);
pub type FinalizedTransactionLookup = (FinalizedReceiptBatch, FinalizedReceiptEntry, Option<crate::world_resources::WorldResourcePermit>);

const MAX_COMMITMENT_BYTES: usize = 64 * 1024;

const MAX_STATE_TRANSACTION_BYTES: usize = 80 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateError {
    ResourcePressure { requested: usize, limit: usize },
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
    current: Option<FinalizedState>,
    world_tip: RefCell<Option<WorldHistoryTip>>,
    budget: Option<Arc<WorldResourceBudget>>,
}

impl FinalizedStateStore {
    pub fn load(root: impl AsRef<Path>) -> Result<Self, StateError> {
        Self::load_internal(root, None)
    }
    pub fn load_budgeted(
        root: impl AsRef<Path>,
        budget: Arc<WorldResourceBudget>,
    ) -> Result<Self, StateError> {
        Self::load_internal(root, Some(budget))
    }
    fn load_internal(
        root: impl AsRef<Path>,
        budget: Option<Arc<WorldResourceBudget>>,
    ) -> Result<Self, StateError> {
        // One transaction namespace must have one record limit during writes
        // and crash recovery, including a staged full world above 4 MiB.
        let store = AtomicStore::new(root.as_ref(), 64 * 1024 * 1024).map_err(storage_error)?;
        let current = if store.exists(STATE_RECORD).map_err(storage_error)? {
            let bytes = store
                .inspect_consistent(|reader| {
                    reader
                        .with_maximum_bytes(MAX_COMMITMENT_BYTES)
                        .read_optional_bounded(STATE_RECORD)
                })
                .map_err(storage_error)?
                .map_err(storage_error)?
                .ok_or_else(|| StateError::Corrupt("finalized pointer disappeared".into()))?;
            Some(decode_record(&bytes)?.state)
        } else {
            None
        };
        let result = Self {
            store,
            current,
            world_tip: RefCell::new(None),
            budget,
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
        self.verified_world_at(height)
    }

    /// Snapshot consumers receive canonical full-world JSON even when the
    /// durable representation is a checkpoint followed by bounded deltas.
    pub fn world_state_bytes_at(&self, height: u64) -> Result<Option<Vec<u8>>, StateError> {
        self.verified_world_at(height)?
            .map(|world| {
                serde_json::to_vec(&world).map_err(|error| StateError::Corrupt(error.to_string()))
            })
            .transpose()
    }

    pub fn current_world_state_budgeted(
        &self,
        budget: &Arc<WorldResourceBudget>,
    ) -> Result<Option<BudgetedWorld>, StateError> {
        let Some(current) = self.current() else {
            return Ok(None);
        };
        self.world_state_at_budgeted(current.finalized_height, budget)
    }
    pub fn world_state_at_budgeted(
        &self,
        height: u64,
        budget: &Arc<WorldResourceBudget>,
    ) -> Result<Option<BudgetedWorld>, StateError> {
        self.verified_world_at_with(height, |reader, height, root| {
            world_history::read_world_records_budgeted(
                reader,
                height,
                root,
                world_record,
                None,
                budget,
            )
        })
    }
    fn verified_world_at(&self, height: u64) -> Result<Option<WorldState>, StateError> {
        self.verified_world_at_with(height, world_history::read_world)
    }
    fn verified_world_at_with<T>(
        &self,
        height: u64,
        read: impl FnOnce(
            &synergy_storage::AtomicStoreReader<'_>,
            u64,
            &str,
        ) -> Result<Option<(T, WorldHistoryTip)>, StateError>,
    ) -> Result<Option<T>, StateError> {
        let result = self
            .store
            .inspect_consistent(|reader| {
                let commitment = match reader
                    .with_maximum_bytes(MAX_COMMITMENT_BYTES)
                    .read_optional_bounded(history_record(height))
                    .map_err(storage_error)?
                {
                    Some(bytes) => {
                        let record = decode_record(&bytes)?.state;
                        if record.finalized_height != height {
                            return Err(StateError::Corrupt("history height mismatch".into()));
                        }
                        record
                    }
                    None => match self.current() {
                        Some(current) if current.finalized_height == height => current.clone(),
                        _ => return Ok(None),
                    },
                };
                read(reader, height, &commitment.state_root)
            })
            .map_err(storage_error)??;
        if let Some((_, tip)) = &result {
            if self
                .current()
                .is_some_and(|current| current.finalized_height == height)
            {
                *self.world_tip.borrow_mut() = Some(*tip);
            }
        }
        Ok(result.map(|(world, _)| world))
    }

    /// Sequential PoSy-authorized transition. Reuses the execution owner's
    /// finalized parent; no durable parent reload is needed after restart setup.
    pub fn commit_verified_world_transition(
        &mut self,
        next: FinalizedState,
        base: &WorldState,
        world: &WorldState,
    ) -> Result<bool, StateError> {
        self.commit_verified_world_transition_with_receipts(next, base, world, None)
    }

    /// Execution supplies only the exact PoSy-verified candidate's public rows.
    /// One nonempty batch joins the SAME guarded transaction as the World/tip.
    pub fn commit_verified_world_transition_with_receipts(
        &mut self,
        next: FinalizedState,
        base: &WorldState,
        world: &WorldState,
        receipts: Option<&FinalizedReceiptBatch>,
    ) -> Result<bool, StateError> {
        if let Some(batch) = receipts { batch.validate(&next)?; }
        let _write_scratch = self.reserve_write(world, Some(base))?;
        if self.check_world_commit(&next, world)? {
            if let Some(batch) = receipts {
                if self.finalized_receipts_at(next.finalized_height)?.as_ref().map(|(value, _)| value) != Some(batch) {
                    return Err(StateError::ConflictingReplay);
                }
            }
            return Ok(false);
        }
        let encoded = if let Some(current) = self.current() {
            if state_root(base)? != current.state_root {
                return Err(StateError::InvalidCommitment);
            }
            let needs_tip = self.world_tip.borrow().is_none();
            if needs_tip && !self.verify_current_world(None)? {
                return Err(StateError::Corrupt("missing finalized world parent".into()));
            }
            world_history::encode_transition(
                next.finalized_height,
                &next.state_root,
                &current.state_root,
                base,
                world,
                self.world_tip.borrow().expect("verified parent tip"),
            )?
        } else {
            world_history::checkpoint(next.finalized_height, world)?
        };
        self.commit_world_record_with_receipts(next, encoded, receipts)
    }

    fn reserve_write(
        &self,
        world: &WorldState,
        base: Option<&WorldState>,
    ) -> Result<Option<crate::world_resources::WorldResourcePermit>, StateError> {
        self.budget
            .as_ref()
            .map(|budget| {
                crate::world_resources::reserve_world_write(world, base, budget)
                    .map_err(crate::world_resources::resource_state_error)
            })
            .transpose()
    }
    fn verify_current_world(&self, expected: Option<&WorldState>) -> Result<bool, StateError> {
        match &self.budget {
            Some(budget) => Ok(self
                .current_world_state_budgeted(budget)?
                .as_ref()
                .is_some_and(|world| expected.is_none_or(|value| world.as_ref() == value))),
            None => Ok(self
                .current_world_state()?
                .as_ref()
                .is_some_and(|world| expected.is_none_or(|value| world == value))),
        }
    }

    fn check_world_commit(
        &self,
        next: &FinalizedState,
        world: &WorldState,
    ) -> Result<bool, StateError> {
        validate(next)?;
        if state_root(world)? != next.state_root {
            return Err(StateError::InvalidCommitment);
        }
        if let Some(current) = self.current() {
            if next.finalized_height == current.finalized_height {
                if next != current {
                    return Err(StateError::ConflictingReplay);
                }
                if !self.verify_current_world(Some(world))? {
                    return Err(StateError::ConflictingReplay);
                }
                return Ok(true);
            }
            if next.finalized_height != current.finalized_height.saturating_add(1) {
                return Err(StateError::HeightGap {
                    current: current.finalized_height,
                    requested: next.finalized_height,
                });
            }
        }
        Ok(false)
    }

    /// Persists account bytes before the finalized commitment. Only the
    /// PoSy-verified caller may supply the finality record.
    pub fn commit_verified_world_state(
        &mut self,
        next: FinalizedState,
        world: &WorldState,
    ) -> Result<bool, StateError> {
        let _write_scratch = self.reserve_write(world, None)?;
        if self.check_world_commit(&next, world)? {
            return Ok(false);
        }
        let encoded = world_history::checkpoint(next.finalized_height, world)?;
        self.commit_world_record(next, encoded)
    }

    fn commit_world_record(
        &mut self,
        next: FinalizedState,
        (world_bytes, tip): (Vec<u8>, WorldHistoryTip),
    ) -> Result<bool, StateError> {
        self.commit_world_record_with_receipts(next, (world_bytes, tip), None)
    }

    fn commit_world_record_with_receipts(
        &mut self,
        next: FinalizedState,
        (world_bytes, tip): (Vec<u8>, WorldHistoryTip),
        receipts: Option<&FinalizedReceiptBatch>,
    ) -> Result<bool, StateError> {
        let mut measured = EncodedSize(0);
        if let Some(batch) = receipts { serde_json::to_writer(&mut measured, batch).map_err(|e| StateError::Corrupt(e.to_string()))?; }
        // Same fixed record ceiling as existing candidate/World storage. A
        // pressure refusal is not a new transaction/consensus validity rule.
        if measured.0 > 64 * 1024 * 1024 { return Err(StateError::ResourcePressure { requested: measured.0, limit: 64 * 1024 * 1024 }); }
        let _receipt_scratch = self.budget.as_ref().map(|budget| budget.reserve(measured.0.saturating_mul(4)))
            .transpose().map_err(crate::world_resources::resource_state_error)?;
        let receipt_bytes = receipts.map(serde_json::to_vec).transpose().map_err(|e| StateError::Corrupt(e.to_string()))?;
        if let (Some(batch), Some(bytes)) = (receipts, receipt_bytes.as_ref()) {
            self.prepare_receipt_pointers(batch, &synergy_storage::IntegrityDigest::of("SYNERGY_FINALIZED_RECEIPTS_V1", bytes).0)?;
        }
        let world_path = world_record(next.finalized_height);
        let history_path = history_record(next.finalized_height);
        let durable = durable_bytes(&next)?;
        let mut preconditions = vec![
            self.current_precondition()?,
            StoragePrecondition {
                relative_path: world_path.clone().into(),
                required: RequiredRecord::MissingOrSameWrite,
            },
            StoragePrecondition {
                relative_path: history_path.clone().into(),
                required: RequiredRecord::MissingOrExact(durable.clone()),
            },
        ];
        let mut transaction =
            StorageTransaction::new(MAX_STATE_TRANSACTION_BYTES + receipt_bytes.as_ref().map_or(0, Vec::len)).map_err(storage_error)?;
        if let Some(bytes) = receipt_bytes {
            let path = finalized_receipts_record(next.finalized_height);
            preconditions.push(StoragePrecondition { relative_path: path.clone().into(), required: RequiredRecord::MissingOrSameWrite });
            transaction.put(path, bytes).map_err(storage_error)?;
        }
        transaction
            .put(world_path, world_bytes)
            .and_then(|()| transaction.put(history_path, durable.clone()))
            .and_then(|()| transaction.put(STATE_RECORD, durable))
            .map_err(storage_error)?;
        transaction
            .commit_guarded(&mut self.store, &preconditions)
            .map_err(storage_error)?;
        self.current = Some(next);
        *self.world_tip.borrow_mut() = Some(tip);
        Ok(true)
    }

    fn receipt_pointer(&self, transaction_id: &str) -> Result<Option<ReceiptPointer>, StateError> {
        if transaction_id.len() != 64 || !transaction_id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err(StateError::InvalidCommitment);
        }
        self.store.inspect_consistent(|reader| reader.with_maximum_bytes(1024).read_optional_bounded(receipt_pointer_record(transaction_id)))
            .map_err(storage_error)?.map_err(storage_error)?
            .map(|bytes| serde_json::from_slice(&bytes).map_err(|e| StateError::Corrupt(e.to_string()))).transpose()
    }

    // Publish bounded lookup pointers first. They NEVER attest execution. A
    // crash here leaves a detectable provisional pointer; sequential replay
    // completes the authoritative batch+World transaction before exposing it.
    fn prepare_receipt_pointers(&mut self, batch: &FinalizedReceiptBatch, batch_digest: &str) -> Result<(), StateError> {
        fn flush(store: &mut AtomicStore, writes: &mut Vec<(String, Vec<u8>)>) -> Result<(), StateError> {
            if writes.is_empty() { return Ok(()); }
            let mut transaction = StorageTransaction::new(1024 * 1024).map_err(storage_error)?;
            let mut guards = Vec::with_capacity(writes.len());
            for (path, bytes) in writes.drain(..) {
                guards.push(StoragePrecondition { relative_path: path.clone().into(), required: RequiredRecord::MissingOrSameWrite });
                transaction.put(path, bytes).map_err(storage_error)?;
            }
            transaction.commit_guarded(store, &guards).map_err(storage_error)
        }
        let mut writes = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for (row, entry) in batch.transactions.iter().enumerate() {
            let id = &entry.receipt.transaction_id;
            if !seen.insert(id) { continue; }
            let pointer = ReceiptPointer { height: batch.finalized.finalized_height, block_id: batch.finalized.finalized_block_id.clone(), batch_digest: batch_digest.into(), row };
            if let Some(old) = self.receipt_pointer(id)? {
                if old == pointer { continue; }
                if old.height < pointer.height {
                    self.finalized_transaction(id)?.ok_or(StateError::ConflictingReplay)?;
                    continue; // A later replay cannot overwrite the first outcome.
                }
                return Err(StateError::ConflictingReplay);
            }
            writes.push((receipt_pointer_record(id), serde_json::to_vec(&pointer).map_err(|e| StateError::Corrupt(e.to_string()))?));
            // Bound each auxiliary write set, never the number of transactions
            // in a consensus block. All chunks precede the atomic state commit.
            if writes.len() == 512 { flush(&mut self.store, &mut writes)?; }
        }
        flush(&mut self.store, &mut writes)
    }

    /// Direct bounded lookup. The pointer alone is not a receipt: it must name
    /// an exact row in the batch atomically committed with executed state.
    pub fn finalized_transaction(&self, transaction_id: &str) -> Result<Option<FinalizedTransactionLookup>, StateError> {
        let Some(pointer) = self.receipt_pointer(transaction_id)? else { return Ok(None) };
        let (batch, permit) = self.finalized_receipts_at(pointer.height)?.ok_or_else(|| StateError::Corrupt("transaction index is not committed".into()))?;
        if batch.finalized.finalized_block_id != pointer.block_id { return Err(StateError::ConflictingReplay); }
        synergy_storage::IntegrityDigest(pointer.batch_digest).verify("SYNERGY_FINALIZED_RECEIPTS_V1", &serde_json::to_vec(&batch).map_err(|e| StateError::Corrupt(e.to_string()))?).map_err(storage_error)?;
        let entry = batch.transactions.get(pointer.row).filter(|entry| entry.receipt.transaction_id == transaction_id)
            .ok_or(StateError::ConflictingReplay)?.clone();
        Ok(Some((batch, entry, permit)))
    }

    /// Missing means unobserved: old software/snapshot restores may not have
    /// receipts. No backfill, negative inclusion claim or World reconstruction.
    fn finalized_receipts_at(&self, height: u64) -> Result<Option<ReceiptBatchRead>, StateError> {
        let (bytes, scratch) = self.store.inspect_consistent(|reader| -> Result<_, StateError> {
            let path = finalized_receipts_record(height);
            let length = reader.optional_record_bytes(&path).map_err(storage_error)?.unwrap_or(0);
            let scratch = self.budget.as_ref().map(|budget| budget.reserve(length.saturating_mul(4)))
                .transpose().map_err(crate::world_resources::resource_state_error)?;
            Ok((reader.read_optional_bounded(&path).map_err(storage_error)?, scratch))
        }).map_err(storage_error)??;
        let Some(bytes) = bytes else { return Ok(None) };
        let batch: FinalizedReceiptBatch = serde_json::from_slice(&bytes).map_err(|e| StateError::Corrupt(e.to_string()))?;
        batch.validate(&batch.finalized)?;
        if batch.finalized.finalized_height != height
            || self.current().is_none_or(|tip| tip.finalized_height < height
                || (tip.finalized_height == height && tip != &batch.finalized)) {
            return Err(StateError::ConflictingReplay);
        }
        Ok(Some((batch, scratch)))
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
        let _write_scratch = self.reserve_write(world, None)?;
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
        let encoded = world_history::checkpoint(next.finalized_height, world)?;
        self.commit_world_record(next, encoded)
    }

    /// Retrieve a finalized block/state commitment for verified historical
    /// replay. Legacy latest-only records may have no archived entry.
    pub fn history_at(&self, height: u64) -> Result<Option<FinalizedState>, StateError> {
        let path = history_record(height);
        let Some(bytes) = self
            .store
            .inspect_consistent(|reader| {
                reader
                    .with_maximum_bytes(MAX_COMMITMENT_BYTES)
                    .read_optional_bounded(&path)
                    .and_then(|record| match record {
                        Some(bytes) => Ok(Some(bytes)),
                        None => reader
                            .with_maximum_bytes(MAX_COMMITMENT_BYTES)
                            .read_optional_bounded(processing_history_pin(height))
                            .map(|record| record.filter(|bytes| bytes != b"null")),
                    })
            })
            .map_err(storage_error)?
            .map_err(storage_error)?
        else {
            return Ok(None);
        };
        let record = decode_record(&bytes)?;
        if record.state.finalized_height != height {
            return Err(StateError::Corrupt("history height mismatch".into()));
        }
        Ok(Some(record.state))
    }

    /// Preserve only the exact durable execution commitment needed by a
    /// pending processing proof. No World copy or finality authority is added.
    /// The execution owner coordinates these sparse records with its bounded
    /// candidate pins before the ordinary history pruner runs.
    pub fn pin_processing_history(&mut self, height: u64) -> Result<(), StateError> {
        let state = self
            .history_at(height)?
            .ok_or(StateError::InvalidCommitment)?;
        self.write_processing_history_pin(&state)
    }

    /// Restore an exact historical commitment after the stopped recovery owner
    /// verifies its native finality and full candidate. Never changes the tip.
    pub fn pin_verified_processing_history(
        &mut self,
        state: &FinalizedState,
    ) -> Result<(), StateError> {
        validate(state)?;
        if self
            .history_at(state.finalized_height)?
            .is_some_and(|existing| &existing != state)
        {
            return Err(StateError::ConflictingReplay);
        }
        self.write_processing_history_pin(state)
    }

    fn write_processing_history_pin(&mut self, state: &FinalizedState) -> Result<(), StateError> {
        let _scratch = self
            .budget
            .as_ref()
            .map(|budget| budget.reserve(4 * MAX_COMMITMENT_BYTES))
            .transpose()
            .map_err(crate::world_resources::resource_state_error)?;
        let height = state.finalized_height;
        if self.current().is_none_or(|tip| {
            tip.finalized_height < height || (tip.finalized_height == height && tip != state)
        }) {
            return Err(StateError::InvalidCommitment);
        }
        let bytes = durable_bytes(state)?;
        let path = processing_history_pin(height);
        let old = self
            .store
            .inspect_consistent(|reader| {
                reader
                    .with_maximum_bytes(MAX_COMMITMENT_BYTES)
                    .read_optional_bounded(&path)
            })
            .map_err(storage_error)?
            .map_err(storage_error)?;
        if let Some(old) = old.as_ref().filter(|value| value.as_slice() != b"null") {
            return if old == &bytes {
                Ok(())
            } else {
                Err(StateError::ConflictingReplay)
            };
        }
        let mut transaction =
            StorageTransaction::new(2 * MAX_COMMITMENT_BYTES).map_err(storage_error)?;
        transaction.put(&path, bytes).map_err(storage_error)?;
        transaction
            .commit_guarded(
                &mut self.store,
                &[StoragePrecondition {
                    relative_path: path.into(),
                    required: match old {
                        Some(bytes) => RequiredRecord::Exact(bytes),
                        None => RequiredRecord::Missing,
                    },
                }],
            )
            .map_err(storage_error)?;
        Ok(())
    }

    pub fn unpin_processing_history(&mut self, height: u64) -> Result<(), StateError> {
        let _scratch = self
            .budget
            .as_ref()
            .map(|budget| budget.reserve(4 * MAX_COMMITMENT_BYTES))
            .transpose()
            .map_err(crate::world_resources::resource_state_error)?;
        let path = processing_history_pin(height);
        let old = self
            .store
            .inspect_consistent(|reader| {
                reader
                    .with_maximum_bytes(MAX_COMMITMENT_BYTES)
                    .read_optional_bounded(&path)
            })
            .map_err(storage_error)?
            .map_err(storage_error)?;
        let Some(old) = old else { return Ok(()) };
        if old == b"null" {
            self.store
                .remove_cache_records(&[path.into()])
                .map_err(storage_error)?;
            return Ok(());
        }
        let mut transaction =
            StorageTransaction::new(2 * MAX_COMMITMENT_BYTES).map_err(storage_error)?;
        transaction
            .put(&path, b"null".to_vec())
            .map_err(storage_error)?;
        transaction
            .commit_guarded(
                &mut self.store,
                &[StoragePrecondition {
                    relative_path: path.into(),
                    required: RequiredRecord::Exact(old),
                }],
            )
            .map_err(storage_error)?;
        self.store
            .remove_cache_records(&[processing_history_pin(height).into()])
            .map_err(storage_error)?;
        Ok(())
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
        *self.world_tip.borrow_mut() = None;
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
        if self
            .current()
            .is_none_or(|current| finalized_height > current.finalized_height)
        {
            return Err(StateError::InvalidPruneRequest);
        }
        let Some(through_height) = (PruneBoundary {
            finalized_height,
            retain_from_height: retain_blocks,
        })
        .oldest_prunable_height()
        .map_err(storage_error)?
        else {
            return Ok(PruneReport::default());
        };
        self.store
            .prune_dependent_height_records_incremental(
                "finalized-history",
                "finalized-world",
                through_height,
                world_history::world_prune_through,
            )
            .map_err(storage_error)
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

fn receipt_pointer_record(id: &str) -> String {
    format!("finalized-transaction-index/{id}.json")
}

fn finalized_receipts_record(height: u64) -> String {
    format!("finalized-receipts/{height:020}.json")
}

fn processing_history_pin(height: u64) -> String {
    format!("processing-pinned-history/{height:020}.json")
}

fn durable_bytes(state: &FinalizedState) -> Result<Vec<u8>, StateError> {
    serde_json::to_vec(&DurableState {
        format: STATE_FORMAT.into(),
        state: state.clone(),
    })
    .map_err(|error| StateError::Corrupt(error.to_string()))
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

    fn receipt_batch(height: u64, world: &WorldState) -> FinalizedReceiptBatch {
        FinalizedReceiptBatch {
            schema_version: 1,
            finalized: FinalizedState { finalized_height: height, finalized_block_id: format!("{height:064x}"), state_root: state_root(world).unwrap() },
            protected_execution_root: "c".repeat(64), finality_certificate_id: "d".repeat(64),
            transactions: vec![FinalizedReceiptEntry { sender: "syna1sender".into(), receiver: "syna1receiver".into(), amount_nwei: 1000, nonce: 0, gas_limit: 100, max_fee_per_gas_nwei: 1, receipt: crate::FinalizedPublicReceipt {
                transaction_id: "a".repeat(64), status: crate::FinalizedReceiptStatus::Applied,
                gas_used: 21, state_root_after: state_root(world).unwrap(), error_code: None,
            }}],
        }
    }

    #[test]
    fn durable_receipt_survives_64_block_pruning_restart_and_later_replay() {
        let root = root(); let world = WorldState::default(); let original = receipt_batch(1, &world);
        let mut store = FinalizedStateStore::load(&root).unwrap();
        for height in 1..=66 {
            let mut batch = receipt_batch(height, &world);
            if height == 66 { batch.transactions[0].receipt.status = crate::FinalizedReceiptStatus::Reverted; batch.transactions[0].receipt.error_code = Some("nonce_mismatch".into()); }
            store.commit_verified_world_transition_with_receipts(batch.finalized.clone(), &world, &world, if height == 1 || height == 66 { Some(&batch) } else { None }).unwrap();
            store.prune_finalized_history(height, 64).unwrap();
        }
        assert!(store.history_at(1).unwrap().is_none());
        assert!(store.world_state_at(1).unwrap().is_none());
        drop(store);
        let store = FinalizedStateStore::load(&root).unwrap();
        let (batch, row, _permit) = store.finalized_transaction(&"a".repeat(64)).unwrap().unwrap();
        assert_eq!(batch, original); assert_eq!(row, original.transactions[0]);
        assert!(store.finalized_transaction(&"b".repeat(64)).unwrap().is_none());
        let bytes = std::fs::read(root.join(finalized_receipts_record(1))).unwrap();
        assert!(!String::from_utf8(bytes).unwrap().contains("payload"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn durable_receipt_batch_exceeds_storage_write_count_without_transaction_limit() {
        let root = root(); let world = WorldState::default(); let mut batch = receipt_batch(1, &world);
        let row = batch.transactions[0].clone();
        batch.transactions = (0..1025).map(|n| { let mut row = row.clone(); row.receipt.transaction_id = format!("{n:064x}"); row }).collect();
        let mut store = FinalizedStateStore::load(&root).unwrap();
        store.commit_verified_world_transition_with_receipts(batch.finalized.clone(), &world, &world, Some(&batch)).unwrap();
        drop(store);
        let store = FinalizedStateStore::load(&root).unwrap();
        assert_eq!(store.finalized_transaction(&format!("{:064x}",1024)).unwrap().unwrap().1, batch.transactions[1024]);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn provisional_receipt_pointer_never_exposes_pre_state_crash_and_resumes() {
        let root = root(); let world = WorldState::default(); let batch = receipt_batch(1, &world);
        let mut store = FinalizedStateStore::load(&root).unwrap();
        store.prepare_receipt_pointers(&batch, &synergy_storage::IntegrityDigest::of("SYNERGY_FINALIZED_RECEIPTS_V1", &serde_json::to_vec(&batch).unwrap()).0).unwrap(); // Deterministic crash seam before atomic state/batch.
        assert!(store.finalized_transaction(&"a".repeat(64)).is_err());
        assert!(store.current().is_none()); drop(store);
        let mut store = FinalizedStateStore::load(&root).unwrap();
        assert!(store.finalized_transaction(&"a".repeat(64)).is_err());
        store.commit_verified_world_transition_with_receipts(batch.finalized.clone(), &world, &world, Some(&batch)).unwrap();
        assert_eq!(store.finalized_transaction(&"a".repeat(64)).unwrap().unwrap().0, batch);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn durable_receipt_conflict_and_invalid_world_do_not_publish_or_overwrite() {
        let root = root(); let world = WorldState::default(); let batch = receipt_batch(1, &world);
        let mut store = FinalizedStateStore::load(&root).unwrap();
        let mut wrong = batch.clone(); wrong.finalized.state_root = "b".repeat(64);
        assert!(store.commit_verified_world_transition_with_receipts(wrong.finalized.clone(), &world, &world, Some(&wrong)).is_err());
        assert!(store.receipt_pointer(&"a".repeat(64)).unwrap().is_none());
        store.commit_verified_world_transition_with_receipts(batch.finalized.clone(), &world, &world, Some(&batch)).unwrap();
        assert!(!store.commit_verified_world_transition_with_receipts(batch.finalized.clone(), &world, &world, Some(&batch)).unwrap());
        let bytes = std::fs::read(root.join(finalized_receipts_record(1))).unwrap();
        let mut conflict = batch.clone(); conflict.transactions[0].receipt.gas_used += 1;
        assert_eq!(store.commit_verified_world_transition_with_receipts(batch.finalized.clone(), &world, &world, Some(&conflict)), Err(StateError::ConflictingReplay));
        assert_eq!(std::fs::read(root.join(finalized_receipts_record(1))).unwrap(), bytes);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn processing_commitment_pin_survives_pruning_and_releases_after_restart() {
        let root = root();
        let budget = WorldResourceBudget::new(1024 * 1024);
        let mut store = FinalizedStateStore::load_budgeted(&root, budget.clone()).unwrap();
        store.commit_verified_finalization(state(1, "one")).unwrap();
        store.pin_processing_history(1).unwrap();
        let bytes = std::fs::read(root.join(processing_history_pin(1))).unwrap();
        store.pin_processing_history(1).unwrap();
        assert_eq!(
            std::fs::read(root.join(processing_history_pin(1))).unwrap(),
            bytes
        );
        store.commit_verified_finalization(state(2, "two")).unwrap();
        store.prune_finalized_history(2, 1).unwrap();
        assert!(!root.join(history_record(1)).exists());
        assert_eq!(store.history_at(1).unwrap(), Some(state(1, "one")));
        drop(store);
        let mut store = FinalizedStateStore::load_budgeted(&root, budget.clone()).unwrap();
        assert_eq!(store.history_at(1).unwrap(), Some(state(1, "one")));
        store.unpin_processing_history(1).unwrap();
        assert_eq!(store.history_at(1).unwrap(), None);
        drop(store);
        assert_eq!(budget.used(), 0);
        let store = FinalizedStateStore::load(&root).unwrap();
        assert_eq!(store.history_at(1).unwrap(), None);
        std::fs::remove_dir_all(root).unwrap();
    }

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

    fn commitment(height: u64, world: &WorldState) -> FinalizedState {
        FinalizedState {
            finalized_height: height,
            finalized_block_id: format!("delta-block-{height}"),
            state_root: state_root(world).unwrap(),
        }
    }

    #[test]
    fn budgeted_snapshot_pressure_preserves_durable_tip_and_retries() {
        let root = root();
        let budget = WorldResourceBudget::new(1024 * 1024);
        let mut store = FinalizedStateStore::load_budgeted(&root, Arc::clone(&budget)).unwrap();
        let first = WorldState::default();
        store
            .commit_verified_snapshot(commitment(1, &first), &first)
            .unwrap();
        let original = std::fs::read(root.join(STATE_RECORD)).unwrap();
        let mut next = first.clone();
        next.protocol
            .insert("snapshot-change".into(), vec![7; 4096]);
        let pressure = budget.reserve(budget.available()).unwrap();
        assert!(matches!(
            store.commit_verified_snapshot(commitment(2, &next), &next),
            Err(StateError::ResourcePressure { .. })
        ));
        assert_eq!(store.current().unwrap().finalized_height, 1);
        assert_eq!(std::fs::read(root.join(STATE_RECORD)).unwrap(), original);
        assert!(!root.join(world_record(2)).exists());
        drop(pressure);
        store
            .commit_verified_snapshot(commitment(2, &next), &next)
            .unwrap();
        drop(store);
        let store = FinalizedStateStore::load_budgeted(&root, Arc::clone(&budget)).unwrap();
        let restored = store
            .current_world_state_budgeted(&budget)
            .unwrap()
            .unwrap();
        assert_eq!(restored.as_ref(), &next);
        drop(restored);
        assert_eq!(budget.used(), 0);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn budgeted_write_pressure_preserves_original_and_unblocks_after_release() {
        let root = root();
        let budget = WorldResourceBudget::new(1024 * 1024);
        let mut store = FinalizedStateStore::load_budgeted(&root, Arc::clone(&budget)).unwrap();
        let base = WorldState::default();
        let mut world = base.clone();
        world.protocol.insert("changed".into(), vec![7; 4096]);
        let pressure = budget.reserve(budget.available()).unwrap();
        assert!(matches!(
            store.commit_verified_world_transition(commitment(1, &world), &base, &world),
            Err(StateError::ResourcePressure { .. })
        ));
        assert!(store.current().is_none());
        assert!(!root.join(world_record(1)).exists());
        assert!(!root.join(STATE_RECORD).exists());
        assert_eq!(budget.used(), pressure.bytes());
        drop(pressure);
        assert!(store
            .commit_verified_world_transition(commitment(1, &world), &base, &world)
            .unwrap());
        assert_eq!(budget.used(), 0);
        drop(store);
        let store = FinalizedStateStore::load_budgeted(&root, Arc::clone(&budget)).unwrap();
        let restored = store
            .current_world_state_budgeted(&budget)
            .unwrap()
            .unwrap();
        assert_eq!(restored.as_ref(), &world);
        drop(restored);
        assert_eq!(budget.used(), 0);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn world_resources_state_store_budgeted_read_keeps_retained_charge() {
        let root = root();
        let mut store = FinalizedStateStore::load(&root).unwrap();
        let base = WorldState::default();
        let mut world = base.clone();
        world.protocol.insert("value".into(), vec![7; 4096]);
        store
            .commit_verified_world_transition(commitment(1, &world), &base, &world)
            .unwrap();
        let budget = WorldResourceBudget::new(1024 * 1024);
        let restored = store
            .current_world_state_budgeted(&budget)
            .unwrap()
            .unwrap();
        assert_eq!(restored.as_ref(), &world);
        assert_eq!(budget.used(), restored.charged_bytes());
        assert!(store.world_state_at_budgeted(2, &budget).unwrap().is_none());
        drop(restored);
        assert_eq!(budget.used(), 0);
        let small = WorldResourceBudget::new(1);
        assert!(matches!(
            store.world_state_at_budgeted(1, &small),
            Err(StateError::ResourcePressure { .. })
        ));
        assert_eq!(small.used(), 0);
        assert_eq!(store.current_world_state().unwrap().unwrap(), world);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn incremental_world_replays_across_checkpoints_restart_and_pruning() {
        let root = root();
        let mut store = FinalizedStateStore::load(&root).unwrap();
        let mut world = WorldState::default();
        world
            .protocol
            .insert("unchanged-large-payload".into(), vec![7; 32 * 1024]);
        let mut height_69 = None;
        let mut repeated_full_bytes = 0u64;
        for height in 1..=70 {
            let base = world.clone();
            world.accounts.insert(
                "sender".into(),
                crate::AccountState {
                    balance_nwei: 1000 - u128::from(height),
                    nonce: height,
                    code_hash: None,
                },
            );
            world.protocol.insert("changed".into(), vec![height as u8]);
            if height == 2 {
                world.protocol.insert("removed".into(), vec![1, 2]);
            }
            if height == 3 {
                world.protocol.remove("removed");
            }
            repeated_full_bytes += serde_json::to_vec(&world).unwrap().len() as u64;
            store
                .commit_verified_world_transition(commitment(height, &world), &base, &world)
                .unwrap();
            if height == 69 {
                height_69 = Some(world.clone());
            }
            if height == 35 {
                drop(store);
                store = FinalizedStateStore::load(&root).unwrap();
                // Transition after restart also initializes the replay budget
                // when the caller has not explicitly read current_world_state.
            }
        }
        let stored_bytes: u64 = (1..=70)
            .map(|height| {
                std::fs::metadata(root.join(world_record(height)))
                    .unwrap()
                    .len()
            })
            .sum();
        assert!(stored_bytes < repeated_full_bytes / 10);
        eprintln!("70-height world history: {stored_bytes} stored bytes versus {repeated_full_bytes} repeated full-world bytes");
        assert!(
            std::fs::metadata(root.join(world_record(63)))
                .unwrap()
                .len()
                < 1024
        );
        assert!(
            std::fs::metadata(root.join(world_record(64)))
                .unwrap()
                .len()
                > 32 * 1024
        );
        assert_eq!(store.world_state_at(69).unwrap(), height_69);
        assert_eq!(store.current_world_state().unwrap(), Some(world.clone()));
        assert_eq!(
            serde_json::from_slice::<WorldState>(&store.world_state_bytes_at(70).unwrap().unwrap())
                .unwrap(),
            world
        );
        let before = std::fs::read(root.join(world_record(70))).unwrap();
        assert!(!store
            .commit_verified_world_state(commitment(70, &world), &world)
            .unwrap());
        assert_eq!(std::fs::read(root.join(world_record(70))).unwrap(), before);
        store.prune_finalized_history(70, 2).unwrap();
        assert!(!root.join(world_record(63)).exists());
        assert!(root.join(world_record(64)).exists());
        assert!(store.world_state_at(68).unwrap().is_none());
        assert_eq!(store.world_state_at(69).unwrap(), height_69);
        drop(store);
        let mut store = FinalizedStateStore::load(&root).unwrap();
        assert_eq!(store.current_world_state().unwrap(), Some(world.clone()));
        let base = world.clone();
        world.accounts.remove("sender");
        store
            .commit_verified_world_transition(commitment(71, &world), &base, &world)
            .unwrap();
        assert_eq!(store.current_world_state().unwrap(), Some(world.clone()));
        // A missing or corrupted dependency cannot silently produce state.
        let parent_path = root.join(world_record(70));
        let parent = std::fs::read(&parent_path).unwrap();
        std::fs::remove_file(&parent_path).unwrap();
        assert!(matches!(
            store.current_world_state(),
            Err(StateError::Corrupt(_))
        ));
        std::fs::write(&parent_path, parent).unwrap();
        let delta_path = root.join(world_record(71));
        let bytes = std::fs::read(&delta_path).unwrap();
        let mut delta: serde_json::Value = serde_json::from_slice(&bytes[8..]).unwrap();
        delta["protocol"]["forged"] = serde_json::json!([1]);
        let mut corrupt = bytes[..8].to_vec();
        corrupt.extend(serde_json::to_vec(&delta).unwrap());
        std::fs::write(delta_path, corrupt).unwrap();
        assert!(matches!(
            store.current_world_state(),
            Err(StateError::Corrupt(_))
        ));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn interrupted_delta_commit_recovers_atomic_pointer_and_legacy_parent() {
        let root = root();
        let mut store = FinalizedStateStore::load(&root).unwrap();
        let base = WorldState::default();
        store
            .commit_verified_world_state(commitment(1, &base), &base)
            .unwrap();
        let mut world = base.clone();
        world.protocol.insert("new".into(), vec![1, 2, 3]);
        let finalized = commitment(2, &world);
        let (delta, _) = world_history::encode_transition(
            2,
            &finalized.state_root,
            &state_root(&base).unwrap(),
            &base,
            &world,
            WorldHistoryTip {
                checkpoint_height: 1,
                delta_bytes: 0,
            },
        )
        .unwrap();
        let durable = durable_bytes(&finalized).unwrap();
        drop(store);
        let transaction = root.join(".transactions/interrupted-delta");
        std::fs::create_dir_all(transaction.join("staged")).unwrap();
        let writes = [
            (world_record(2), delta),
            (history_record(2), durable.clone()),
            (STATE_RECORD.into(), durable),
        ];
        let manifest: Vec<_> = writes.iter().enumerate().map(|(index, (path, bytes))| {
            std::fs::write(transaction.join("staged").join(format!("{index:020}")), bytes).unwrap();
            serde_json::json!({ "relative_path": path, "length": bytes.len(),
                "digest": synergy_storage::IntegrityDigest::of("SYNERGY_STORAGE_TRANSACTION_WRITE_V1", bytes).0 })
        }).collect();
        std::fs::write(
            transaction.join("manifest.json"),
            serde_json::to_vec(&serde_json::json!({"version": 1, "writes": manifest})).unwrap(),
        )
        .unwrap();
        std::fs::write(transaction.join("intent"), b"commit").unwrap();
        // Crash after installing the delta, before the history/pointer records.
        std::fs::rename(
            transaction.join("staged/00000000000000000000"),
            root.join(world_record(2)),
        )
        .unwrap();
        let mut store = FinalizedStateStore::load(&root).unwrap();
        assert_eq!(store.current(), Some(&finalized));
        assert_eq!(store.current_world_state().unwrap(), Some(world.clone()));
        assert_eq!(store.world_state_at(1).unwrap(), Some(base));
        assert!(!transaction.exists());
        // An authenticated snapshot jump starts a new full checkpoint.
        store
            .commit_verified_snapshot(commitment(100, &world), &world)
            .unwrap();
        let base = world.clone();
        world.protocol.remove("new");
        store
            .commit_verified_world_transition(commitment(101, &world), &base, &world)
            .unwrap();
        store.prune_finalized_history(101, 1).unwrap();
        drop(store);
        assert_eq!(
            FinalizedStateStore::load(&root)
                .unwrap()
                .current_world_state()
                .unwrap(),
            Some(world)
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn incremental_world_rejects_wrong_parent_without_advancing_durability() {
        let root = root();
        let mut store = FinalizedStateStore::load(&root).unwrap();
        let world = WorldState::default();
        store
            .commit_verified_world_state(commitment(1, &world), &world)
            .unwrap();
        let mut wrong = world.clone();
        wrong.protocol.insert("wrong-parent".into(), vec![1]);
        assert_eq!(
            store.commit_verified_world_transition(commitment(2, &world), &wrong, &world),
            Err(StateError::InvalidCommitment)
        );
        assert_eq!(store.current().unwrap().finalized_height, 1);
        assert!(!root.join(world_record(2)).exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn snapshot_bytes_remain_bound_to_exact_durable_world_across_restart() {
        let root = root();
        let world = WorldState::default();
        let mut store = FinalizedStateStore::load(&root).unwrap();
        let finalized = FinalizedState {
            finalized_height: 1,
            finalized_block_id: "block-one".into(),
            state_root: state_root(&world).unwrap(),
        };
        store
            .commit_verified_world_state(finalized.clone(), &world)
            .unwrap();
        assert!(!store
            .commit_verified_world_state(finalized, &world)
            .unwrap());
        drop(store);
        let store = FinalizedStateStore::load(&root).unwrap();
        let expected = serde_json::to_vec(&world).unwrap();
        assert_eq!(store.world_state_bytes_at(1).unwrap(), Some(expected));
        assert!(store.world_state_bytes_at(2).unwrap().is_none());
        let mut changed = world;
        changed
            .accounts
            .insert("unexpected".into(), crate::AccountState::default());
        std::fs::write(
            root.join(world_record(1)),
            serde_json::to_vec(&changed).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            store.world_state_bytes_at(1),
            Err(StateError::Corrupt(_))
        ));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn startup_replays_interrupted_world_transaction_above_metadata_record_limit() {
        let root = root();
        let mut world = WorldState::default();
        world
            .protocol
            .insert("large-value".into(), vec![7; 3 * 1024 * 1024]);
        let finalized = FinalizedState {
            finalized_height: 1,
            finalized_block_id: "large-world".into(),
            state_root: state_root(&world).unwrap(),
        };
        let world_bytes = serde_json::to_vec(&world).unwrap();
        assert!(world_bytes.len() > 4 * 1024 * 1024);
        let durable = durable_bytes(&finalized).unwrap();
        // An acknowledged commit intent survived a crash before its staged
        // records were renamed into the canonical namespace.
        let transaction = root.join(".transactions/interrupted");
        std::fs::create_dir_all(transaction.join("staged")).unwrap();
        let writes = [
            (world_record(1), world_bytes),
            (history_record(1), durable.clone()),
            (STATE_RECORD.into(), durable),
        ];
        let manifest: Vec<_> = writes.iter().enumerate().map(|(index, (path, bytes))| {
            std::fs::write(transaction.join("staged").join(format!("{index:020}")), bytes).unwrap();
            serde_json::json!({
                "relative_path": path,
                "length": bytes.len(),
                "digest": synergy_storage::IntegrityDigest::of("SYNERGY_STORAGE_TRANSACTION_WRITE_V1", bytes).0,
            })
        }).collect();
        std::fs::write(
            transaction.join("manifest.json"),
            serde_json::to_vec(&serde_json::json!({"version": 1, "writes": manifest})).unwrap(),
        )
        .unwrap();
        std::fs::write(transaction.join("intent"), b"commit").unwrap();
        let store = FinalizedStateStore::load(&root).unwrap();
        assert_eq!(store.current(), Some(&finalized));
        assert_eq!(store.current_world_state().unwrap(), Some(world));
        assert!(!transaction.exists());
        drop(store);
        assert_eq!(
            FinalizedStateStore::load(&root).unwrap().current(),
            Some(&finalized)
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn retention_never_uses_an_ahead_of_commit_finality_or_removes_current_state() {
        let root = root();
        let world = WorldState::default();
        let mut store = FinalizedStateStore::load(&root).unwrap();
        assert_eq!(
            store.prune_finalized_history(10, 1),
            Err(StateError::InvalidPruneRequest)
        );
        for height in 1..=4 {
            store
                .commit_verified_world_state(
                    FinalizedState {
                        finalized_height: height,
                        finalized_block_id: format!("block-{height}"),
                        state_root: state_root(&world).unwrap(),
                    },
                    &world,
                )
                .unwrap();
        }
        assert_eq!(
            store.prune_finalized_history(5, 1),
            Err(StateError::InvalidPruneRequest)
        );
        assert!(store.world_state_at(1).unwrap().is_some());
        let report = store.prune_finalized_history(4, 2).unwrap();
        assert_eq!(report.examined_records, 2);
        assert_eq!(report.removed_records, 2);
        assert!(store.world_state_at(2).unwrap().is_none());
        assert_eq!(store.world_state_at(4).unwrap(), Some(world));
        assert_eq!(
            store
                .prune_finalized_history(4, 2)
                .unwrap()
                .examined_records,
            0
        );
        drop(store);
        let store = FinalizedStateStore::load(&root).unwrap();
        assert_eq!(
            store
                .prune_finalized_history(4, 2)
                .unwrap()
                .examined_records,
            0
        );
        assert_eq!(store.current().unwrap().finalized_height, 4);
        std::fs::remove_dir_all(root).unwrap();
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
