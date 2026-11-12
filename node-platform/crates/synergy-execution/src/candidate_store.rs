//! Durable speculative material. Storage integrity grants no QC or finality authority.
use std::{
    cell::RefCell,
    path::Path,
    sync::{Arc, Weak},
};

use serde::{Deserialize, Serialize};
use synergy_state::{
    state_root,
    world_history::{self, WorldHistoryBase, WorldHistoryTip},
    world_resources::{BudgetedWorld, WorldResourceBudget, WorldResourcePermit},
    WorldState,
};
use synergy_storage::{
    AtomicStore, AtomicStoreReader, PruneBoundary, PruneReport, RequiredRecord,
    StoragePrecondition, StorageTransaction,
};

use crate::{
    decode_budgeted_candidate, BudgetedExecutionCandidate, CandidateResourceError,
    ExecutionCandidate,
};

struct JsonCounter(usize);
impl std::io::Write for JsonCounter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .ok_or_else(|| std::io::Error::other("JSON length overflow"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

const MAGIC: &[u8; 8] = b"SNCDV001";
const MAX_RECORD_BYTES: usize = 64 * 1024 * 1024;
const PIN_INDEX: &str = "candidate-pins/index-v1.json";
// At most closure, consumption parent, and consumption per bounded pending
// slot, plus the existing active speculation allowance. No height-range pin.
const MAX_PINS: usize = 3 * 4096 + 16;
const MAX_PIN_INDEX_BYTES: usize = 4 * 1024 * 1024;

/// Exact sparse recovery dependency. This descriptor grants no QC authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidatePin {
    pub height: u64,
    pub block_id: String,
    slot: usize,
    bytes: usize,
    root: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidatePins {
    version: u32,
    generation: u64,
    pins: Vec<CandidatePin>,
}
fn pin_path(slot: usize) -> String {
    format!("candidate-pins/payload/{slot:04}.json")
}
fn pin_charge(bytes: usize) -> Result<usize, CandidateResourceError> {
    bytes
        .checked_mul(32)
        .and_then(|n| n.checked_add(64 * 1024))
        .ok_or_else(|| {
            synergy_state::world_resources::WorldResourceError::ArithmeticOverflow.into()
        })
}

// Canonical descriptors contain two fixed 64-byte hashes and scalar fields.
// Eight encoded index lengths cover the retained raw bytes/native graph,
// replacement graph, encoder growth, CAS original, transaction copy, and
// duplicate-height/slot validation trees. Large World payloads retain their
// separate conservative charge; this index bound never decodes a World.
fn pin_index_charge(bytes: usize) -> Result<usize, CandidateResourceError> {
    bytes
        .checked_mul(8)
        .and_then(|n| n.checked_add(64 * 1024))
        .ok_or_else(|| {
            synergy_state::world_resources::WorldResourceError::ArithmeticOverflow.into()
        })
}

/// The existing Execution owner persists candidates before publication. Peers
/// still receive the complete unchanged ExecutionCandidate; disk records split
/// its metadata from a bounded checkpoint/delta world representation.
pub struct CandidateStore<W = WorldState> {
    store: AtomicStore,
    cached: RefCell<Option<CachedWorld<W>>>,
    write_tip: Option<CachedWorld<W>>,
    budget: Option<Arc<WorldResourceBudget>>,
    pins: CandidatePins,
    pin_index_bytes: Option<Vec<u8>>,
    _pin_index_permit: Option<WorldResourcePermit>,
}

struct CachedWorld<W> {
    height: u64,
    block_id: String,
    state_root: String,
    tip: WorldHistoryTip,
    world: Weak<W>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateMetadata {
    height: u64,
    block_id: String,
    parent_block_id: String,
    protected_execution_root: String,
    protected_material: synergy_etdag::execution::CandidateProtectedMaterial,
    state_root: String,
    transactions: Vec<synergy_transaction::SignedTransaction>,
    receipts: Vec<synergy_transaction::TransactionReceipt>,
}

#[derive(Serialize)]
struct CandidateMetadataRef<'a> {
    height: u64,
    block_id: &'a str,
    parent_block_id: &'a str,
    protected_execution_root: &'a str,
    protected_material: &'a synergy_etdag::execution::CandidateProtectedMaterial,
    state_root: &'a str,
    transactions: &'a [synergy_transaction::SignedTransaction],
    receipts: &'a [synergy_transaction::TransactionReceipt],
}

/// Validated block commitments; this does not attest archived world readability.
#[derive(Debug, PartialEq, Eq)]
pub struct CandidateCommitment {
    pub height: u64,
    pub block_id: String,
    pub protected_execution_root: String,
    pub state_root: String,
    pub transaction_count: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyCommitmentMetadata {
    height: u64,
    block_id: String,
    parent_block_id: String,
    protected_execution_root: String,
    protected_material: synergy_etdag::execution::CandidateProtectedMaterial,
    state_root: String,
    transactions: Vec<synergy_transaction::SignedTransaction>,
    receipts: Vec<synergy_transaction::TransactionReceipt>,
    state: serde::de::IgnoredAny,
}

impl CandidateMetadata {
    fn with_world<W>(self, state: Arc<W>) -> ExecutionCandidate<W> {
        ExecutionCandidate {
            resource_permit: None,
            height: self.height,
            block_id: self.block_id,
            parent_block_id: self.parent_block_id,
            protected_execution_root: self.protected_execution_root,
            protected_material: self.protected_material,
            state_root: self.state_root,
            transactions: self.transactions,
            receipts: self.receipts,
            state,
        }
    }
}

impl<W> Clone for CachedWorld<W> {
    fn clone(&self) -> Self {
        Self {
            height: self.height,
            block_id: self.block_id.clone(),
            state_root: self.state_root.clone(),
            tip: self.tip,
            world: self.world.clone(),
        }
    }
}
mod sealed {
    pub trait Sealed {}
    impl Sealed for synergy_state::WorldState {}
    impl Sealed for synergy_state::world_resources::BudgetedWorld {}
}
/// Sealed storage strategy; public only to expose the generic store's bounds.
#[doc(hidden)]
pub trait CandidateWorldStorage: sealed::Sealed + AsRef<WorldState> + PartialEq + Sized {
    fn read_world(
        reader: &synergy_storage::AtomicStoreReader<'_>,
        height: u64,
        root: &str,
        base: Option<(u64, &str, &Self, WorldHistoryTip)>,
        budget: Option<&Arc<WorldResourceBudget>>,
    ) -> Result<Option<(Self, WorldHistoryTip)>, CandidateResourceError>;
    fn decode_legacy(
        bytes: &[u8],
        budget: Option<&Arc<WorldResourceBudget>>,
    ) -> Result<ExecutionCandidate<Self>, CandidateResourceError>;
    fn matches_budget(&self, budget: Option<&Arc<WorldResourceBudget>>) -> bool;
}
impl CandidateWorldStorage for WorldState {
    fn read_world(
        reader: &synergy_storage::AtomicStoreReader<'_>,
        height: u64,
        root: &str,
        base: Option<(u64, &str, &Self, WorldHistoryTip)>,
        _budget: Option<&Arc<WorldResourceBudget>>,
    ) -> Result<Option<(Self, WorldHistoryTip)>, CandidateResourceError> {
        world_history::read_world_records(
            reader,
            height,
            root,
            world_record,
            base.map(|(height, state_root, world, tip)| WorldHistoryBase {
                height,
                state_root,
                world,
                tip,
            }),
        )
        .map_err(|e| {
            CandidateResourceError::Storage(format!("reconstruct candidate H{height}: {e:?}"))
        })
    }
    fn decode_legacy(
        bytes: &[u8],
        _budget: Option<&Arc<WorldResourceBudget>>,
    ) -> Result<ExecutionCandidate<Self>, CandidateResourceError> {
        let candidate: ExecutionCandidate<Self> = serde_json::from_slice(bytes)
            .map_err(|e| CandidateResourceError::Decode(e.to_string()))?;
        candidate
            .validate()
            .map_err(CandidateResourceError::Invalid)?;
        Ok(candidate)
    }
    fn matches_budget(&self, _budget: Option<&Arc<WorldResourceBudget>>) -> bool {
        true
    }
}
impl CandidateWorldStorage for BudgetedWorld {
    fn read_world(
        reader: &synergy_storage::AtomicStoreReader<'_>,
        height: u64,
        root: &str,
        base: Option<(u64, &str, &Self, WorldHistoryTip)>,
        budget: Option<&Arc<WorldResourceBudget>>,
    ) -> Result<Option<(Self, WorldHistoryTip)>, CandidateResourceError> {
        world_history::read_world_records_budgeted(
            reader,
            height,
            root,
            world_record,
            base.map(
                |(height, state_root, world, tip)| world_history::BudgetedWorldHistoryBase {
                    height,
                    state_root,
                    world,
                    tip,
                },
            ),
            budget.expect("budgeted store always has explicit pool"),
        )
        .map_err(|e| match e {
            synergy_state::StateError::ResourcePressure { requested, limit } => {
                CandidateResourceError::Resource(
                    synergy_state::world_resources::WorldResourceError::Capacity {
                        requested,
                        limit,
                    },
                )
            }
            other => CandidateResourceError::Storage(format!(
                "reconstruct candidate H{height}: {other:?}"
            )),
        })
    }
    fn decode_legacy(
        bytes: &[u8],
        budget: Option<&Arc<WorldResourceBudget>>,
    ) -> Result<ExecutionCandidate<Self>, CandidateResourceError> {
        decode_budgeted_candidate(
            bytes,
            budget.expect("budgeted store always has explicit pool"),
        )
    }
    fn matches_budget(&self, budget: Option<&Arc<WorldResourceBudget>>) -> bool {
        budget.is_some_and(|budget| Arc::ptr_eq(self.budget(), budget))
    }
}
pub type BudgetedCandidateStore = CandidateStore<BudgetedWorld>;
impl CandidateStore<WorldState> {
    pub fn new(root: impl AsRef<Path>) -> Result<Self, String> {
        Self::open(root, None)
    }
}
impl CandidateStore<BudgetedWorld> {
    pub fn new_budgeted(
        root: impl AsRef<Path>,
        budget: Arc<WorldResourceBudget>,
    ) -> Result<Self, String> {
        Self::open(root, Some(budget))
    }
    /// Retain one immutable complete checkpoint for an exact native-QC-selected
    /// dependency. The caller owns consensus authority and release lifetime.
    pub fn pin_budgeted(
        &mut self,
        candidate: &BudgetedExecutionCandidate,
    ) -> Result<(), CandidateResourceError> {
        if !candidate.state.matches_budget(self.budget.as_ref()) {
            return Err("pinned World belongs to a different resource pool".into());
        }
        if let Some(pin) = self
            .pins
            .pins
            .iter()
            .find(|pin| pin.height == candidate.height)
        {
            if pin.block_id != candidate.block_id {
                return Err("conflicting exact candidate pin at same height".into());
            }
            return Ok(());
        }
        if self.pins.pins.len() >= MAX_PINS {
            return Err(
                synergy_state::world_resources::WorldResourceError::Capacity {
                    requested: self.pins.pins.len() + 1,
                    limit: MAX_PINS,
                }
                .into(),
            );
        }
        let mut counter = JsonCounter(0);
        serde_json::to_writer(&mut counter, candidate).map_err(|e| e.to_string())?;
        if counter.0 > MAX_RECORD_BYTES {
            return Err("candidate pin exceeds full-wire bound".into());
        }
        let _payload = self
            .budget
            .as_ref()
            .unwrap()
            .reserve(pin_charge(counter.0)?)?;
        candidate.validate()?;
        if let Some(original) = self.get_budgeted(candidate.height)? {
            if original != *candidate {
                return Err("candidate pin conflicts with durable history".into());
            }
        }
        let bytes = serde_json::to_vec(candidate).map_err(|e| e.to_string())?;
        let slot = (0..MAX_PINS)
            .find(|slot| !self.pins.pins.iter().any(|pin| pin.slot == *slot))
            .ok_or("candidate proof pin capacity exhausted")?;
        let pin = CandidatePin {
            height: candidate.height,
            block_id: candidate.block_id.clone(),
            slot,
            bytes: bytes.len(),
            root: synergy_block::hash_block_bytes(&bytes),
        };
        self.replace_pin_index(Some(pin), None, pin_path(slot), bytes)
    }

    pub fn get_budgeted(
        &self,
        height: u64,
    ) -> Result<Option<BudgetedExecutionCandidate>, CandidateResourceError> {
        self.read_internal(height, MAX_RECORD_BYTES)
    }
    pub fn put_budgeted(
        &mut self,
        candidate: &BudgetedExecutionCandidate,
        parent: &WorldState,
    ) -> Result<(), CandidateResourceError> {
        self.put_internal(candidate, parent)
    }
    pub fn get_budgeted_bounded(
        &self,
        height: u64,
        maximum_bytes: usize,
    ) -> Result<Option<BudgetedExecutionCandidate>, CandidateResourceError> {
        self.read_internal(height, maximum_bytes)
    }
}
impl<W: CandidateWorldStorage> CandidateStore<W> {
    fn open(
        root: impl AsRef<Path>,
        budget: Option<Arc<WorldResourceBudget>>,
    ) -> Result<Self, String> {
        let store = AtomicStore::new(root.as_ref(), MAX_RECORD_BYTES)
            .map_err(|error| format!("open execution candidate store: {error}"))?;
        let (pins, pin_index_bytes, pin_index_permit) = store
            .inspect_consistent(|reader| -> Result<_, String> {
                let reader = reader.with_maximum_bytes(MAX_PIN_INDEX_BYTES);
                let Some(length) = reader
                    .optional_record_bytes(PIN_INDEX)
                    .map_err(storage_error)?
                else {
                    return Ok((
                        CandidatePins {
                            version: 1,
                            generation: 0,
                            pins: Vec::new(),
                        },
                        None,
                        None,
                    ));
                };
                let permit = budget
                    .as_ref()
                    .map(|pool| -> Result<_, String> {
                        pool.reserve(pin_index_charge(length).map_err(|e| e.to_string())?)
                            .map_err(|e| e.to_string())
                    })
                    .transpose()?;
                let bytes = reader
                    .read_optional_bounded(PIN_INDEX)
                    .map_err(storage_error)?
                    .ok_or("candidate pin index disappeared")?;
                let pins: CandidatePins =
                    serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
                validate_pins(&pins)?;
                Ok((pins, Some(bytes), permit))
            })
            .map_err(storage_error)??;
        Ok(Self {
            store,
            cached: RefCell::new(None),
            write_tip: None,
            budget,
            pins,
            pin_index_bytes,
            _pin_index_permit: pin_index_permit,
        })
    }

    // Independent read owners must not use the mutation owner's startup snapshot:
    // processing pins can be added, retired and their slots reused after open.
    // Read the bounded index and payload under the same storage lock.
    fn current_pin(
        &self,
        reader: &AtomicStoreReader<'_>,
        height: u64,
    ) -> Result<(Option<CandidatePin>, Option<WorldResourcePermit>), CandidateResourceError> {
        let reader = reader.with_maximum_bytes(MAX_PIN_INDEX_BYTES);
        let Some(length) = reader
            .optional_record_bytes(PIN_INDEX)
            .map_err(storage_error)?
        else {
            return Ok((None, None));
        };
        if length == 0 || length > MAX_PIN_INDEX_BYTES {
            return Err("candidate pin index exceeds bound".into());
        }
        let permit = self
            .budget
            .as_ref()
            .map(|budget| {
                budget
                    .reserve(pin_index_charge(length)?)
                    .map_err(CandidateResourceError::from)
            })
            .transpose()?;
        let bytes = reader
            .read_optional_bounded(PIN_INDEX)
            .map_err(storage_error)?
            .ok_or("candidate pin index disappeared")?;
        let pins: CandidatePins =
            serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        validate_pins(&pins)?;
        Ok((
            pins.pins.into_iter().find(|pin| pin.height == height),
            permit,
        ))
    }

    /// Reads canonical candidate metadata without reconstructing account state.
    /// Finality authority must still be supplied by the caller's durable PoSy
    /// and finalized-state commitments. Execution/import use `get` instead.
    pub fn commitment(&self, height: u64) -> Result<Option<CandidateCommitment>, String> {
        self.store
            .inspect_consistent(|reader| -> Result<_, String> {
                let normal = candidate_record(height);
                let (pin, _pin_index) = self
                    .current_pin(reader, height)
                    .map_err(|error| error.to_string())?;
                let (path, length, pinned) = match reader
                    .optional_record_bytes(&normal)
                    .map_err(storage_error)?
                {
                    Some(length) => (normal, length, false),
                    None => {
                        let Some(pin) = pin.as_ref() else {
                            return Ok(None);
                        };
                        let path = pin_path(pin.slot);
                        let length = reader
                            .optional_record_bytes(&path)
                            .map_err(storage_error)?
                            .ok_or("missing exact candidate pin payload")?;
                        if length != pin.bytes {
                            return Err("candidate pin payload length mismatch".into());
                        }
                        (path, length, true)
                    }
                };
                let _encoded = self
                    .budget
                    .as_ref()
                    .map(|budget| budget.reserve(length))
                    .transpose()
                    .map_err(|e| e.to_string())?;
                let Some(bytes) = reader
                    .with_maximum_bytes(length)
                    .read_optional_bounded(&path)
                    .map_err(storage_error)?
                else {
                    return Ok(None);
                };
                if pinned && synergy_block::hash_block_bytes(&bytes) != pin.as_ref().unwrap().root {
                    return Err("candidate pin payload digest mismatch".into());
                }
                let _metadata = self
                    .budget
                    .as_ref()
                    .map(|budget| -> Result<_, String> {
                        let scratch = bytes
                            .len()
                            .checked_mul(3)
                            .and_then(|n| n.checked_add(8192))
                            .ok_or("candidate commitment resource overflow")?;
                        let mut permit = budget.reserve(scratch).map_err(|e| e.to_string())?;
                        let metadata = if bytes.starts_with(MAGIC) {
                            &bytes[MAGIC.len()..]
                        } else {
                            &bytes
                        };
                        permit
                            .grow(
                                crate::candidate::candidate_metadata_charge(metadata)
                                    .map_err(|e| e.to_string())?,
                            )
                            .map_err(|e| e.to_string())?;
                        Ok(permit)
                    })
                    .transpose()?;
                let metadata: CandidateMetadata = if bytes.starts_with(MAGIC) {
                    serde_json::from_slice(&bytes[MAGIC.len()..]).map_err(|e| e.to_string())?
                } else {
                    let legacy: LegacyCommitmentMetadata =
                        serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
                    let _ = legacy.state;
                    CandidateMetadata {
                        height: legacy.height,
                        block_id: legacy.block_id,
                        parent_block_id: legacy.parent_block_id,
                        protected_execution_root: legacy.protected_execution_root,
                        protected_material: legacy.protected_material,
                        state_root: legacy.state_root,
                        transactions: legacy.transactions,
                        receipts: legacy.receipts,
                    }
                };
                metadata
                    .protected_material
                    .validate()
                    .map_err(|e| format!("invalid protected material: {e:?}"))?;
                let protected = synergy_block::hash_block_bytes(
                    &metadata
                        .protected_material
                        .commitment_bytes()
                        .map_err(|e| format!("encode protected material: {e:?}"))?,
                );
                let canonical = serde_json::to_vec(&(
                    metadata.height,
                    &metadata.parent_block_id,
                    &metadata.protected_execution_root,
                    &metadata.state_root,
                    &metadata.transactions,
                    &metadata.receipts,
                ))
                .map_err(|e| e.to_string())?;
                if height == 0
                    || metadata.height != height
                    || metadata.protected_material.height() != height
                    || metadata.parent_block_id.trim().is_empty()
                    || metadata.state_root.trim().is_empty()
                    || metadata.protected_execution_root != protected
                    || metadata.transactions.len() != metadata.receipts.len()
                    || metadata.block_id != synergy_block::hash_block_bytes(&canonical)
                {
                    return Err("invalid canonical candidate commitment metadata".into());
                }
                for (transaction, receipt) in metadata.transactions.iter().zip(&metadata.receipts) {
                    let id = transaction
                        .id()
                        .map_err(|e| format!("verify transaction: {e:?}"))?;
                    if receipt.transaction_id != id || !receipt.validate() {
                        return Err("invalid candidate transaction receipt".into());
                    }
                }
                if pin
                    .as_ref()
                    .is_some_and(|pin| pin.block_id != metadata.block_id)
                {
                    return Err("candidate commitment conflicts with exact pin".into());
                }
                Ok(Some(CandidateCommitment {
                    height,
                    block_id: metadata.block_id,
                    protected_execution_root: metadata.protected_execution_root,
                    state_root: metadata.state_root,
                    transaction_count: metadata.transactions.len(),
                }))
            })
            .map_err(storage_error)?
    }

    pub fn get(&self, height: u64) -> Result<Option<ExecutionCandidate<W>>, String> {
        self.get_bounded(height, MAX_RECORD_BYTES)
    }

    /// Enforces a caller's existing full-wire limit for both disk formats.
    pub fn get_bounded(
        &self,
        height: u64,
        maximum_bytes: usize,
    ) -> Result<Option<ExecutionCandidate<W>>, String> {
        self.read_internal(height, maximum_bytes)
            .map_err(|e| e.to_string())
    }
    fn read_internal(
        &self,
        height: u64,
        maximum_bytes: usize,
    ) -> Result<Option<ExecutionCandidate<W>>, CandidateResourceError> {
        let maximum_bytes = maximum_bytes.min(MAX_RECORD_BYTES);
        let cached = self.cached.borrow().clone();
        let result = self
            .store
            .inspect_consistent(|reader| -> Result<_, CandidateResourceError> {
                let metadata_reader = reader.with_maximum_bytes(maximum_bytes);
                let normal = candidate_record(height);
                let (pin, _pin_index) = self.current_pin(reader, height)?;
                let (path, length, pinned) = match metadata_reader.optional_record_bytes(&normal).map_err(storage_error)? {
                    Some(length) => (normal, length, false),
                    None => {
                        let Some(pin) = pin.as_ref() else { return Ok(None); };
                        let path = pin_path(pin.slot);
                        let length = metadata_reader.optional_record_bytes(&path).map_err(storage_error)?
                            .ok_or("missing exact candidate pin payload")?;
                        if length != pin.bytes { return Err("candidate pin payload length mismatch".into()); }
                        (path, length, true)
                    }
                };
                let _encoded = self.budget.as_ref().map(|budget| budget.reserve(length)).transpose()?;
                let Some(bytes) = metadata_reader.with_maximum_bytes(length)
                    .read_optional_bounded(&path)
                    .map_err(storage_error)?
                else {
                    return Ok(None);
                };
                if pinned && synergy_block::hash_block_bytes(&bytes) != pin.as_ref().unwrap().root {
                    return Err("candidate pin payload digest mismatch".into());
                }
                let record_bytes = bytes.len();
                let split = bytes.starts_with(MAGIC);
                // Metadata still allocates native transaction/receipt vectors.
                // Reserve scanner scratch before walking, then native decode
                // capacity before serde; the World follows its own replay permit.
                let mut metadata_permit = if split {
                    if let Some(budget) = &self.budget {
                        let scratch=bytes.len().checked_mul(3).and_then(|n|n.checked_add(4096))
                            .ok_or(synergy_state::world_resources::WorldResourceError::ArithmeticOverflow)?;
                        let mut permit=budget.reserve(scratch)?;
                        let owned=crate::candidate::candidate_metadata_charge(&bytes[MAGIC.len()..])?;
                        permit.grow(owned)?;
                        Some(permit)
                    } else {None}
                } else {None};
                if !split && record_bytes > maximum_bytes {
                    return Err("execution candidate exceeds caller full-wire bound".into());
                }
                let (mut candidate, tip) = if split {
                    let metadata: CandidateMetadata = serde_json::from_slice(&bytes[MAGIC.len()..])
                        .map_err(|error| error.to_string())?;
                    if metadata.height != height {
                        return Err("execution candidate record height mismatch".into());
                    }
                    drop(bytes);
                    let world = cached
                        .as_ref()
                        .and_then(|cache| cache.world.upgrade())
                        .filter(|world| world.matches_budget(self.budget.as_ref()));
                    if let Some((cache, world)) =
                        cached.as_ref().zip(world.as_ref()).filter(|(cache, _)| {
                            cache.height == height
                                && cache.block_id == metadata.block_id
                                && cache.state_root == metadata.state_root
                        })
                    {
                        (metadata.with_world(Arc::clone(world)), Some(cache.tip))
                    } else {
                        let base = cached
                            .as_ref()
                            .zip(world.as_ref())
                            .filter(|(cache, _)| {
                                cache.height.checked_add(1) == Some(height)
                                    && cache.block_id == metadata.parent_block_id
                            })
                            .map(|(cache, world)| {
                                (
                                    cache.height,
                                    cache.state_root.as_str(),
                                    world.as_ref(),
                                    cache.tip,
                                )
                            });
                        let (world, tip) = W::read_world(
                            reader,
                            height,
                            &metadata.state_root,
                            base,
                            self.budget.as_ref(),
                        )?
                        .ok_or_else(|| format!("missing execution candidate world at H{height}"))?;
                        (metadata.with_world(Arc::new(world)), Some(tip))
                    }
                } else {
                    // Older candidates contain their full world inline. The first
                    // new write after such a record seeds an independent checkpoint.
                    (W::decode_legacy(&bytes, self.budget.as_ref())?, None)
                };
                if split {
                    if let Some(mut permit) = metadata_permit.take() {
                        // Drop input/parser scratch; the metadata's preflighted
                        // owned graph remains charged until the last Arc owner.
                        let metadata_bytes = permit.bytes().saturating_sub(record_bytes.saturating_mul(3).saturating_add(4096));
                        permit.shrink(metadata_bytes)?;
                        candidate.resource_permit = Some(Arc::new(permit));
                    }
                }
                if candidate.height != height {
                    return Err("execution candidate record height mismatch".into());
                }
                if pin.as_ref().is_some_and(|pin| pin.block_id != candidate.block_id) {
                    return Err("candidate history conflicts with exact pin".into());
                }
                if split {
                    let world_size = candidate.validate_with_world_size().map_err(CandidateResourceError::Invalid)?;
                    check_candidate_size(record_bytes, world_size, maximum_bytes)?;
                }
                // Both sealed legacy strategies already validate the native
                // World/root/block tuple; do not hash that World a second time.
                Ok(Some((candidate, tip)))
            })
            .map_err(storage_error)??;
        Ok(result.map(|(candidate, tip)| {
            self.remember(&candidate, tip);
            candidate
        }))
    }

    /// Parent bytes come from the existing deterministic execution owner. A
    /// cached root/tip links sequential deltas; cache misses seed checkpoints,
    /// rather than reloading an entire parent world on every write.
    pub fn put_once(
        &mut self,
        candidate: &ExecutionCandidate<W>,
        parent: &WorldState,
    ) -> Result<(), String> {
        self.put_internal(candidate, parent)
            .map_err(|e| e.to_string())
    }
    fn put_internal(
        &mut self,
        candidate: &ExecutionCandidate<W>,
        parent: &WorldState,
    ) -> Result<(), CandidateResourceError> {
        if !candidate.state.matches_budget(self.budget.as_ref()) {
            return Err("candidate World belongs to a different resource pool".into());
        }
        let _write_scratch = self
            .budget
            .as_ref()
            .map(|budget| {
                synergy_state::world_resources::reserve_world_write(
                    candidate.state.as_ref().as_ref(),
                    Some(parent),
                    budget,
                )
            })
            .transpose()?;
        let world_size = candidate.validate_with_world_size()?;
        if let Some(existing) = self.read_internal(candidate.height, MAX_RECORD_BYTES)? {
            return if existing == *candidate {
                Ok(())
            } else {
                Err(CandidateResourceError::Invalid(format!(
                    "conflicting durable execution candidate at H{}",
                    candidate.height
                )))
            };
        }
        let _metadata_write =
            self.budget
                .as_ref()
                .map(|budget| -> Result<_, CandidateResourceError> {
                    let mut counter = JsonCounter(0);
                    serde_json::to_writer(
                        &mut counter,
                        &CandidateMetadataRef {
                            height: candidate.height,
                            block_id: &candidate.block_id,
                            parent_block_id: &candidate.parent_block_id,
                            protected_execution_root: &candidate.protected_execution_root,
                            protected_material: &candidate.protected_material,
                            state_root: &candidate.state_root,
                            transactions: &candidate.transactions,
                            receipts: &candidate.receipts,
                        },
                    )
                    .map_err(|e| CandidateResourceError::Invalid(e.to_string()))?;
                    budget.reserve(counter.0.checked_mul(2).and_then(|n| n.checked_add(4096))
                .ok_or(synergy_state::world_resources::WorldResourceError::ArithmeticOverflow)?)
                .map_err(Into::into)
                })
                .transpose()?;
        let bytes = metadata_bytes(candidate)?;
        check_full_candidate_size(bytes.len(), world_size)?;
        // Historical provider reads cannot displace the writer's sequential tip.
        let cached = self
            .write_tip
            .clone()
            .or_else(|| self.cached.borrow().clone());
        let encoded = if let Some(cache) = cached.as_ref().filter(|cache| {
            cache.height.checked_add(1) == Some(candidate.height)
                && cache.block_id == candidate.parent_block_id
        }) {
            if state_root(parent).map_err(|error| format!("root candidate parent: {error:?}"))?
                != cache.state_root
            {
                return Err("candidate delta parent differs from verified cached world".into());
            }
            world_history::encode_transition(
                candidate.height,
                &candidate.state_root,
                &cache.state_root,
                parent,
                candidate.state.as_ref().as_ref(),
                cache.tip,
            )
        } else {
            world_history::checkpoint(candidate.height, candidate.state.as_ref().as_ref())
        }
        .map_err(|error| format!("encode candidate world: {error:?}"))?;
        let (world_bytes, tip) = encoded;
        let path = candidate_record(candidate.height);
        let world_path = world_record(candidate.height);
        let guards = [
            StoragePrecondition {
                relative_path: path.clone().into(),
                required: RequiredRecord::MissingOrSameWrite,
            },
            StoragePrecondition {
                relative_path: world_path.clone().into(),
                required: RequiredRecord::MissingOrSameWrite,
            },
        ];
        let mut transaction =
            StorageTransaction::new(2 * MAX_RECORD_BYTES).map_err(storage_error)?;
        transaction
            .put(world_path, world_bytes)
            .and_then(|()| transaction.put(path, bytes))
            .map_err(storage_error)?;
        // AtomicStore's lock is shared by reads, commits and retirement. No
        // split metadata/world visibility or compare-then-overwrite race.
        if let Err(error) = transaction.commit_guarded(&mut self.store, &guards) {
            if error == synergy_storage::StorageError::ConflictingWrite
                && self
                    .read_internal(candidate.height, MAX_RECORD_BYTES)?
                    .as_ref()
                    == Some(candidate)
            {
                // Concurrent identical semantic commits may choose different
                // checkpoint representations. Verify the winning durable one.
                self.write_tip = self.cached.borrow().clone();
                return Ok(());
            }
            return Err(CandidateResourceError::Storage(storage_error(error)));
        }
        self.remember(candidate, Some(tip));
        self.write_tip = self.cached.borrow().clone();
        Ok(())
    }

    /// Only the Execution owner supplies its already durable PoSy finality and
    /// existing configured horizon. Speculative heights are never selected.
    pub fn prune_finalized_history(
        &self,
        finalized_height: u64,
        retain_blocks: u64,
    ) -> Result<PruneReport, String> {
        let Some(through) = (PruneBoundary {
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
                "candidate",
                "candidate-world",
                through,
                world_history::world_prune_through,
            )
            .map_err(storage_error)
    }

    /// Bounded borrowed descriptors; storage provenance is not consensus authority.
    pub fn pinned_descriptors(&self) -> &[CandidatePin] {
        &self.pins.pins
    }
    pub fn remaining_pin_capacity(&self) -> usize {
        MAX_PINS - self.pins.pins.len()
    }

    /// Release only the exact dependency named by its native owner. Durable
    /// index and fixed payload retirement are one atomic transaction.
    pub fn unpin(&mut self, height: u64, block_id: &str) -> Result<(), CandidateResourceError> {
        let Some(pin) = self.pins.pins.iter().find(|pin| pin.height == height) else {
            return Ok(());
        };
        if pin.block_id != block_id {
            return Err("candidate unpin identity mismatch".into());
        }
        self.replace_pin_index(None, Some(height), pin_path(pin.slot), b"null".to_vec())
    }

    fn replace_pin_index(
        &mut self,
        add: Option<CandidatePin>,
        remove: Option<u64>,
        payload_path: String,
        payload: Vec<u8>,
    ) -> Result<(), CandidateResourceError> {
        // Bound and reserve the next owned descriptor graph and encoding before
        // cloning any original state. Failed commits preserve both old owners.
        let estimate = self
            .pin_index_bytes
            .as_ref()
            .map_or(0, Vec::len)
            .checked_add(1024)
            .ok_or(synergy_state::world_resources::WorldResourceError::ArithmeticOverflow)?;
        let release_only = remove.is_some() && add.is_none();
        let permit = if release_only {
            None
        } else {
            self.budget
                .as_ref()
                .map(|pool| -> Result<_, CandidateResourceError> {
                    Ok(pool.reserve(pin_index_charge(estimate)?)?)
                })
                .transpose()?
        };
        let mut pins = CandidatePins {
            version: 1,
            generation: self
                .pins
                .generation
                .checked_add(1)
                .ok_or("candidate pin generation overflow")?,
            pins: self.pins.pins.clone(),
        };
        if let Some(height) = remove {
            pins.pins.retain(|pin| pin.height != height);
        }
        if let Some(pin) = add {
            pins.pins.push(pin);
        }
        validate_pins(&pins)?;
        let encoded = serde_json::to_vec(&pins).map_err(|e| e.to_string())?;
        if encoded.len() > MAX_PIN_INDEX_BYTES {
            return Err("candidate pin index exceeds bound".into());
        }
        let required = self
            .pin_index_bytes
            .as_ref()
            .map_or(RequiredRecord::Missing, |bytes| {
                RequiredRecord::Exact(bytes.clone())
            });
        let mut transaction =
            StorageTransaction::new(2 * MAX_RECORD_BYTES).map_err(storage_error)?;
        transaction
            .put(payload_path, payload)
            .map_err(storage_error)?;
        transaction
            .put(PIN_INDEX, encoded.clone())
            .map_err(storage_error)?;
        transaction
            .commit_guarded(
                &mut self.store,
                &[StoragePrecondition {
                    relative_path: PIN_INDEX.into(),
                    required,
                }],
            )
            .map_err(storage_error)?;
        let retained = if release_only {
            // The existing conservative reservation covers the old and smaller
            // replacement index plus encoding/CAS scratch. Releasing a pin
            // cannot become blocked by its own reservation at full capacity.
            if let Some(mut old) = self._pin_index_permit.take() {
                old.shrink(pin_index_charge(encoded.len())?.min(old.bytes()))?;
                Some(old)
            } else {
                None
            }
        } else {
            permit
        };
        self.pins = pins;
        self.pin_index_bytes = Some(encoded);
        self._pin_index_permit = retained;
        Ok(())
    }

    fn remember(&self, candidate: &ExecutionCandidate<W>, tip: Option<WorldHistoryTip>) {
        *self.cached.borrow_mut() = tip.map(|tip| CachedWorld {
            height: candidate.height,
            block_id: candidate.block_id.clone(),
            state_root: candidate.state_root.clone(),
            tip,
            world: Arc::downgrade(&candidate.state),
        });
    }
}

fn validate_pins(index: &CandidatePins) -> Result<(), String> {
    if index.version != 1 || index.pins.len() > MAX_PINS {
        return Err("invalid candidate pin index shape".into());
    }
    let mut heights = std::collections::BTreeSet::new();
    let mut slots = std::collections::BTreeSet::new();
    for pin in &index.pins {
        if pin.height == 0
            || pin.slot >= MAX_PINS
            || pin.bytes == 0
            || pin.bytes > MAX_RECORD_BYTES
            || !valid_pin_hash(&pin.block_id)
            || !valid_pin_hash(&pin.root)
            || !heights.insert(pin.height)
            || !slots.insert(pin.slot)
        {
            return Err("invalid or conflicting candidate pin descriptor".into());
        }
    }
    Ok(())
}
fn valid_pin_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn check_full_candidate_size(metadata_bytes: usize, world_bytes: usize) -> Result<(), String> {
    check_candidate_size(metadata_bytes, world_bytes, MAX_RECORD_BYTES)
}

fn check_candidate_size(
    metadata_bytes: usize,
    world_bytes: usize,
    maximum_bytes: usize,
) -> Result<(), String> {
    // The split metadata has every original field except the final state field.
    let full = metadata_bytes
        .saturating_sub(MAGIC.len())
        .saturating_add(b",\"state\":".len())
        .saturating_add(world_bytes);
    if full > maximum_bytes {
        return Err("execution candidate exceeds full-wire bound".into());
    }
    Ok(())
}

fn metadata_bytes<W>(candidate: &ExecutionCandidate<W>) -> Result<Vec<u8>, String> {
    let metadata = CandidateMetadataRef {
        height: candidate.height,
        block_id: &candidate.block_id,
        parent_block_id: &candidate.parent_block_id,
        protected_execution_root: &candidate.protected_execution_root,
        protected_material: &candidate.protected_material,
        state_root: &candidate.state_root,
        transactions: &candidate.transactions,
        receipts: &candidate.receipts,
    };
    let mut bytes = MAGIC.to_vec();
    serde_json::to_writer(&mut bytes, &metadata).map_err(|error| error.to_string())?;
    Ok(bytes)
}

fn candidate_record(height: u64) -> String {
    format!("candidate/{height:020}.json")
}
fn world_record(height: u64) -> String {
    format!("candidate-world/{height:020}.json")
}
fn storage_error(error: synergy_storage::StorageError) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    fn root() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "synergy-candidate-delta-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ))
    }
    fn candidate(height: u64, parent: &str, world: WorldState) -> ExecutionCandidate {
        let material = synergy_etdag::execution::ProtectedProposalMaterial {
            material_version: 2,
            height,
            execution_root: synergy_etdag::EtdagDigest::from_domain_bytes("test", b"execution"),
            next_batch_root: synergy_etdag::EtdagDigest::from_domain_bytes("test", b"batch"),
            cutoff_boundary_root: synergy_etdag::EtdagDigest::from_domain_bytes("test", b"cutoff"),
        };
        let mut candidate = ExecutionCandidate {
            resource_permit: None,
            height,
            block_id: String::new(),
            parent_block_id: parent.into(),
            protected_execution_root: synergy_block::hash_block_bytes(
                &material.commitment_bytes().unwrap(),
            ),
            protected_material: material.into(),
            state_root: state_root(&world).unwrap(),
            transactions: vec![],
            receipts: vec![],
            state: Arc::new(world),
        };
        candidate.block_id = candidate.commitment_id().unwrap();
        candidate.validate().unwrap();
        candidate
    }

    #[test]
    fn maximum_sparse_pin_descriptor_index_is_bounded_before_decode() {
        let root = root();
        let index = CandidatePins {
            version: 1,
            generation: 1,
            pins: (0..MAX_PINS)
                .map(|slot| CandidatePin {
                    height: slot as u64 + 1,
                    block_id: "a".repeat(64),
                    slot,
                    bytes: 1024,
                    root: "b".repeat(64),
                })
                .collect(),
        };
        validate_pins(&index).unwrap();
        let bytes = serde_json::to_vec(&index).unwrap();
        assert!(bytes.len() < MAX_PIN_INDEX_BYTES);
        let amount = pin_index_charge(bytes.len()).unwrap();
        eprintln!(
            "{MAX_PINS} exact pin descriptors: {} encoded bytes, {amount} prepaid index bytes",
            bytes.len()
        );
        std::fs::create_dir_all(root.join("candidate-pins")).unwrap();
        std::fs::write(root.join(PIN_INDEX), &bytes).unwrap();
        let pressure = WorldResourceBudget::new(amount - 1);
        assert!(BudgetedCandidateStore::new_budgeted(&root, Arc::clone(&pressure)).is_err());
        assert_eq!(pressure.used(), 0);
        assert_eq!(std::fs::read(root.join(PIN_INDEX)).unwrap(), bytes);
        let exact = WorldResourceBudget::new(amount);
        let store = BudgetedCandidateStore::new_budgeted(&root, Arc::clone(&exact)).unwrap();
        assert_eq!(store.pinned_descriptors().len(), MAX_PINS);
        assert_eq!(store.remaining_pin_capacity(), 0);
        assert_eq!(exact.used(), amount);
        drop(store);
        assert_eq!(exact.used(), 0);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn independent_readers_follow_sparse_pin_add_release_and_slot_reuse() {
        let root = root();
        let budget = WorldResourceBudget::new(32 * 1024 * 1024);
        let mut owner = BudgetedCandidateStore::new_budgeted(&root, Arc::clone(&budget)).unwrap();
        let before_add = BudgetedCandidateStore::new_budgeted(&root, Arc::clone(&budget)).unwrap();
        let mut parent = "genesis".to_string();
        let mut first = None;
        let mut second = None;
        for height in 1..=70 {
            let next = candidate(height, &parent, WorldState::default());
            let next =
                decode_budgeted_candidate(&serde_json::to_vec(&next).unwrap(), &budget).unwrap();
            owner.put_budgeted(&next, &WorldState::default()).unwrap();
            parent = next.block_id.clone();
            if height == 1 {
                first = Some(next);
            } else if height == 2 {
                second = Some(next);
            }
        }
        let first = first.unwrap();
        let second = second.unwrap();
        owner.pin_budgeted(&first).unwrap();
        let before_release =
            BudgetedCandidateStore::new_budgeted(&root, Arc::clone(&budget)).unwrap();
        owner.prune_finalized_history(70, 2).unwrap();
        assert!(!root.join(candidate_record(1)).exists());
        assert!(!root.join(candidate_record(2)).exists());
        for reader in [&before_add, &before_release] {
            assert_eq!(reader.get_budgeted(1).unwrap().unwrap(), first);
            assert_eq!(
                reader.commitment(1).unwrap().unwrap().block_id,
                first.block_id
            );
        }
        let slot = owner.pinned_descriptors()[0].slot;
        owner.unpin(1, &first.block_id).unwrap();
        owner.pin_budgeted(&second).unwrap();
        assert_eq!(owner.pinned_descriptors()[0].slot, slot);
        for reader in [&before_add, &before_release] {
            assert!(reader.get_budgeted(1).unwrap().is_none());
            assert!(reader.commitment(1).unwrap().is_none());
            assert_eq!(reader.get_budgeted(2).unwrap().unwrap(), second);
            assert_eq!(
                reader.commitment(2).unwrap().unwrap().block_id,
                second.block_id
            );
        }
        // Live descriptors retain exact payload integrity; refresh is not a
        // reason to accept a missing or corrupted dependency.
        std::fs::write(root.join(pin_path(slot)), b"tampered").unwrap();
        for reader in [&before_add, &before_release] {
            assert!(reader.get_budgeted(2).is_err());
            assert!(reader.commitment(2).is_err());
        }
        drop((owner, before_add, before_release, first, second));
        assert_eq!(budget.used(), 0);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn exact_sparse_pin_survives_pruning_restart_and_releases_without_rewrite() {
        let root = root();
        let budget = WorldResourceBudget::new(32 * 1024 * 1024);
        let original = candidate(1, "genesis", WorldState::default());
        let encoded = serde_json::to_vec(&original).unwrap();
        let pinned = decode_budgeted_candidate(&encoded, &budget).unwrap();
        let mut store = BudgetedCandidateStore::new_budgeted(&root, Arc::clone(&budget)).unwrap();
        store.put_budgeted(&pinned, &WorldState::default()).unwrap();
        store.pin_budgeted(&pinned).unwrap();
        let descriptor = store.pinned_descriptors()[0].clone();
        let index = std::fs::read(root.join(PIN_INDEX)).unwrap();
        let payload = std::fs::read(root.join(pin_path(descriptor.slot))).unwrap();
        store.pin_budgeted(&pinned).unwrap();
        assert_eq!(std::fs::read(root.join(PIN_INDEX)).unwrap(), index);
        assert_eq!(
            std::fs::read(root.join(pin_path(descriptor.slot))).unwrap(),
            payload
        );
        let mut parent = pinned.block_id.clone();
        for height in 2..=70 {
            let next = candidate(height, &parent, WorldState::default());
            let next =
                decode_budgeted_candidate(&serde_json::to_vec(&next).unwrap(), &budget).unwrap();
            store.put_budgeted(&next, &WorldState::default()).unwrap();
            parent = next.block_id.clone();
        }
        store.prune_finalized_history(70, 2).unwrap();
        assert!(!root.join(candidate_record(1)).exists());
        assert!(!root.join(world_record(1)).exists());
        assert_eq!(store.get_budgeted(1).unwrap().unwrap(), pinned);
        assert_eq!(
            store.commitment(1).unwrap().unwrap().block_id,
            pinned.block_id
        );
        drop(store);
        let mut store = BudgetedCandidateStore::new_budgeted(&root, Arc::clone(&budget)).unwrap();
        assert_eq!(store.pinned_descriptors(), &[descriptor]);
        assert_eq!(store.get_budgeted(1).unwrap().unwrap(), pinned);
        assert!(store.unpin(1, "wrong").is_err());
        assert_eq!(std::fs::read(root.join(PIN_INDEX)).unwrap(), index);
        let mut altered = WorldState::default();
        altered.protocol.insert("conflict".into(), vec![1]);
        let conflicting = candidate(1, "genesis", altered);
        let conflicting =
            decode_budgeted_candidate(&serde_json::to_vec(&conflicting).unwrap(), &budget).unwrap();
        assert!(store.pin_budgeted(&conflicting).is_err());
        assert_eq!(std::fs::read(root.join(PIN_INDEX)).unwrap(), index);
        assert_eq!(std::fs::read(root.join(pin_path(0))).unwrap(), payload);
        let occupied = budget.reserve(budget.available()).unwrap();
        store.unpin(1, &pinned.block_id).unwrap();
        drop(occupied);
        assert!(store.get_budgeted(1).unwrap().is_none());
        assert!(store.commitment(1).unwrap().is_none());
        drop(store);
        let store = BudgetedCandidateStore::new_budgeted(&root, Arc::clone(&budget)).unwrap();
        assert!(store.pinned_descriptors().is_empty());
        assert!(store.get_budgeted(1).unwrap().is_none());
        drop((store, pinned, conflicting));
        assert_eq!(budget.used(), 0);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pin_pressure_and_corruption_preserve_original_records_and_reservations() {
        let root = root();
        let budget = WorldResourceBudget::new(16 * 1024 * 1024);
        let original = candidate(1, "genesis", WorldState::default());
        let candidate =
            decode_budgeted_candidate(&serde_json::to_vec(&original).unwrap(), &budget).unwrap();
        let mut store = BudgetedCandidateStore::new_budgeted(&root, Arc::clone(&budget)).unwrap();
        let occupied = budget.reserve(budget.available()).unwrap();
        let used = budget.used();
        assert!(matches!(
            store.pin_budgeted(&candidate),
            Err(CandidateResourceError::Resource(_))
        ));
        assert_eq!(budget.used(), used);
        assert!(store.pinned_descriptors().is_empty());
        assert!(!root.join(PIN_INDEX).exists());
        assert!(!root.join(pin_path(0)).exists());
        drop(occupied);
        store.pin_budgeted(&candidate).unwrap();
        let index = std::fs::read(root.join(PIN_INDEX)).unwrap();
        let path = root.join(pin_path(0));
        let mut corrupt = std::fs::read(&path).unwrap();
        corrupt[0] ^= 1;
        std::fs::write(&path, &corrupt).unwrap();
        let used = budget.used();
        assert!(store.get_budgeted(1).is_err());
        assert_eq!(budget.used(), used);
        assert_eq!(std::fs::read(root.join(PIN_INDEX)).unwrap(), index);
        assert_eq!(std::fs::read(path).unwrap(), corrupt);
        drop((store, candidate));
        assert_eq!(budget.used(), 0);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn budgeted_candidates_share_pool_cache_and_preserve_legacy_split_reads() {
        let root = root();
        let legacy_root = root.with_extension("legacy");
        let mut world = WorldState::default();
        world.protocol.insert("large".into(), vec![7; 64 * 1024]);
        let original = candidate(1, "genesis", world);
        let encoded = serde_json::to_vec(&original).unwrap();
        let budget = WorldResourceBudget::new(16 * 1024 * 1024);
        let budgeted = Arc::new(decode_budgeted_candidate(&encoded, &budget).unwrap());
        assert_eq!(serde_json::to_vec(&budgeted).unwrap(), encoded);
        let used = budget.used();
        let clone = budgeted.clone();
        assert!(Arc::ptr_eq(&budgeted.state, &clone.state));
        assert_eq!(used, budget.used());
        let mut store = BudgetedCandidateStore::new_budgeted(&root, Arc::clone(&budget)).unwrap();
        store
            .put_budgeted(&budgeted, &WorldState::default())
            .unwrap();
        let cached = store.get_budgeted(1).unwrap().unwrap();
        assert!(Arc::ptr_eq(&cached.state, &budgeted.state));
        let cached_metadata_charge = cached.resource_permit.as_ref().unwrap().bytes();
        assert_eq!(used + cached_metadata_charge, budget.used());
        let other_pool = WorldResourceBudget::new(16 * 1024 * 1024);
        let mut wrong =
            BudgetedCandidateStore::new_budgeted(root.with_extension("wrong"), other_pool).unwrap();
        assert!(wrong
            .put_budgeted(&budgeted, &WorldState::default())
            .is_err());
        assert_eq!(used + cached_metadata_charge, budget.used());
        let mut legacy = AtomicStore::new(&legacy_root, MAX_RECORD_BYTES).unwrap();
        let mut tx = StorageTransaction::new(MAX_RECORD_BYTES).unwrap();
        tx.put(candidate_record(1), encoded.clone()).unwrap();
        tx.commit(&mut legacy).unwrap();
        let reader =
            BudgetedCandidateStore::new_budgeted(&legacy_root, Arc::clone(&budget)).unwrap();
        let occupied = budget.reserve(budget.available() - 1).unwrap();
        assert!(matches!(
            reader.get_budgeted(1),
            Err(CandidateResourceError::Resource(_))
        ));
        assert_eq!(budget.available(), 1);
        drop(occupied);
        let cold = reader.get_budgeted(1).unwrap().unwrap();
        assert_eq!(serde_json::to_vec(&cold).unwrap(), encoded);
        drop((cold, cached, clone, budgeted));
        assert_eq!(budget.used(), 0);
        let cold_split = store.get_budgeted(1).unwrap().unwrap();
        assert_eq!(serde_json::to_vec(&cold_split).unwrap(), encoded);
        drop(cold_split);
        assert_eq!(budget.used(), 0);
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(legacy_root).unwrap();
    }

    #[test]
    fn commitment_reads_skip_world_reconstruction_but_reject_changed_metadata() {
        let root = root();
        let mut store = CandidateStore::new(&root).unwrap();
        let mut world = WorldState::default();
        world.protocol.insert("large".into(), vec![7; 1024 * 1024]);
        let candidate = candidate(1, "genesis", world);
        store.put_once(&candidate, &WorldState::default()).unwrap();
        let expected = store.commitment(1).unwrap().unwrap();
        assert_eq!(expected.block_id, candidate.block_id);
        drop(candidate);
        // Remove the archived world: metadata must remain readable without
        // accidentally satisfying execution/account-state availability checks.
        std::fs::remove_file(root.join(world_record(1))).unwrap();
        for _ in 0..32 {
            assert_eq!(store.commitment(1).unwrap().unwrap(), expected);
            assert!(store
                .cached
                .borrow()
                .as_ref()
                .is_none_or(|cache| cache.world.upgrade().is_none()));
        }
        assert!(store.get(1).is_err());
        let path = root.join(candidate_record(1));
        let bytes = std::fs::read(&path).unwrap();
        let mut metadata: serde_json::Value =
            serde_json::from_slice(&bytes[MAGIC.len()..]).unwrap();
        metadata["state_root"] = "corrupt".into();
        let mut corrupt = MAGIC.to_vec();
        corrupt.extend(serde_json::to_vec(&metadata).unwrap());
        std::fs::write(path, corrupt).unwrap();
        assert!(store.commitment(1).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn legacy_commitment_reads_skip_inline_world_without_changing_full_validation() {
        let root = root();
        let store = CandidateStore::new(&root).unwrap();
        let candidate = candidate(1, "genesis", WorldState::default());
        let mut legacy = serde_json::to_value(&candidate).unwrap();
        legacy["state"] = serde_json::json!({"not_a_world": [1, 2, 3]});
        std::fs::create_dir_all(root.join("candidate")).unwrap();
        std::fs::write(
            root.join(candidate_record(1)),
            serde_json::to_vec(&legacy).unwrap(),
        )
        .unwrap();
        assert_eq!(
            store.commitment(1).unwrap().unwrap().block_id,
            candidate.block_id
        );
        assert!(store.get(1).is_err());
        legacy["protected_execution_root"] = "wrong".into();
        std::fs::write(
            root.join(candidate_record(1)),
            serde_json::to_vec(&legacy).unwrap(),
        )
        .unwrap();
        assert!(store.commitment(1).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn candidate_history_is_incremental_restartable_and_checkpoint_safe_to_prune() {
        let root = root();
        let mut store = CandidateStore::new(&root).unwrap();
        let mut world = WorldState::default();
        world
            .protocol
            .insert("large-unchanged".into(), vec![7; 32 * 1024]);
        let mut parent = "genesis".to_owned();
        let mut previous = Arc::new(world);
        let mut full_bytes = 0u64;
        let mut last = None;
        for height in 1..=70 {
            let mut world = previous.as_ref().clone();
            world.accounts.insert(
                "sender".into(),
                synergy_state::AccountState {
                    balance_nwei: 1000 - u128::from(height),
                    nonce: height,
                    code_hash: None,
                },
            );
            if height == 2 {
                world.protocol.insert("deleted".into(), vec![1]);
            }
            if height == 3 {
                world.protocol.remove("deleted");
            }
            let next = candidate(height, &parent, world);
            let canonical = serde_json::to_vec(&next).unwrap();
            let metadata_size = metadata_bytes(&next).unwrap().len();
            assert_eq!(
                metadata_size - MAGIC.len()
                    + b",\"state\":".len()
                    + serde_json::to_vec(next.state.as_ref()).unwrap().len(),
                canonical.len()
            );
            full_bytes += canonical.len() as u64;
            store.put_once(&next, &previous).unwrap();
            // A provider request must not turn the next write into a checkpoint.
            if height == 50 {
                assert!(store.get(1).unwrap().is_some());
            }
            previous = Arc::clone(&next.state);
            parent = next.block_id.clone();
            last = Some(next);
            if height == 35 {
                drop(store);
                store = CandidateStore::new(&root).unwrap();
                assert_eq!(store.get(35).unwrap(), last);
            }
        }
        let last = last.unwrap();
        assert!(
            std::fs::metadata(root.join(world_record(51)))
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
        let stored: u64 = (1..=70)
            .map(|height| {
                std::fs::metadata(root.join(world_record(height)))
                    .unwrap()
                    .len()
                    + std::fs::metadata(root.join(candidate_record(height)))
                        .unwrap()
                        .len()
            })
            .sum();
        assert!(stored < full_bytes / 10);
        eprintln!("70-height candidate history: {stored} stored payload bytes versus {full_bytes} inline full candidate bytes");
        let bytes = std::fs::read(root.join(world_record(70))).unwrap();
        store.put_once(&last, &previous).unwrap();
        assert_eq!(std::fs::read(root.join(world_record(70))).unwrap(), bytes);
        let restored = store.get(70).unwrap().unwrap();
        assert!(Arc::ptr_eq(&restored.state, &last.state));
        assert_eq!(
            serde_json::to_vec(&restored).unwrap(),
            serde_json::to_vec(&last).unwrap()
        );
        store.prune_finalized_history(70, 2).unwrap();
        assert!(store.get(68).unwrap().is_none());
        assert!(!root.join(world_record(63)).exists());
        assert!(root.join(world_record(64)).exists());
        assert_eq!(
            store
                .prune_finalized_history(70, 2)
                .unwrap()
                .examined_records,
            0
        );
        drop(store);
        let store = CandidateStore::new(&root).unwrap();
        let retained_parent = store.get(69).unwrap().unwrap();
        assert_eq!(store.get(70).unwrap(), Some(last.clone()));
        assert_eq!(retained_parent.block_id, last.parent_block_id);
        drop(retained_parent);
        drop(restored);
        drop(last);
        drop(previous);
        assert!(store
            .cached
            .borrow()
            .as_ref()
            .unwrap()
            .world
            .upgrade()
            .is_none());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn retirement_backlog_preserves_checkpoint_for_the_first_surviving_index() {
        let root = root();
        let mut store = CandidateStore::new(&root).unwrap();
        let checkpoint = candidate(256, "earlier-parent", WorldState::default());
        store.put_once(&checkpoint, &WorldState::default()).unwrap();
        let next = candidate(257, &checkpoint.block_id, WorldState::default());
        store.put_once(&next, &checkpoint.state).unwrap();
        let current = candidate(300, "later-parent", WorldState::default());
        store.put_once(&current, &WorldState::default()).unwrap();
        store.prune_finalized_history(300, 1).unwrap();
        assert!(store.get(256).unwrap().is_none());
        assert!(root.join(world_record(256)).exists());
        drop(store);
        let store = CandidateStore::new(&root).unwrap();
        assert_eq!(store.get(257).unwrap(), Some(next));
        store.prune_finalized_history(300, 1).unwrap();
        assert!(store.get(257).unwrap().is_none());
        assert_eq!(store.get(300).unwrap(), Some(current));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn split_storage_keeps_the_existing_full_candidate_wire_limit() {
        let root = root();
        let mut world = WorldState::default();
        world
            .protocol
            .insert("large".into(), vec![0; 32 * 1024 * 1024]);
        let oversized = candidate(1, "genesis", world);
        let mut store = CandidateStore::new(&root).unwrap();
        let error = store
            .put_once(&oversized, &WorldState::default())
            .unwrap_err();
        assert!(error.contains("full-wire bound"));
        assert!(!root.join(candidate_record(1)).exists());
        assert!(!root.join(world_record(1)).exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bounded_current_candidate_can_replay_a_larger_checkpoint() {
        let root = root();
        let mut world = WorldState::default();
        world.protocol.insert("removed".into(), vec![7; 4096]);
        let one = candidate(1, "genesis", world);
        let two = candidate(2, &one.block_id, WorldState::default());
        let limit = serde_json::to_vec(&two).unwrap().len();
        let mut store = CandidateStore::new(&root).unwrap();
        store.put_once(&one, &WorldState::default()).unwrap();
        store.put_once(&two, &one.state).unwrap();
        assert!(std::fs::metadata(root.join(world_record(1))).unwrap().len() > limit as u64);
        drop(store);
        let store = CandidateStore::new(&root).unwrap();
        assert_eq!(store.get_bounded(2, limit).unwrap(), Some(two));
        assert!(store.get_bounded(2, limit - 1).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn legacy_candidate_replay_is_unchanged_and_new_successor_seeds_checkpoint() {
        let root = root();
        let one = candidate(1, "genesis", WorldState::default());
        std::fs::create_dir_all(root.join("candidate")).unwrap();
        let legacy = serde_json::to_vec(&one).unwrap();
        std::fs::write(root.join(candidate_record(1)), &legacy).unwrap();
        let mut store = CandidateStore::new(&root).unwrap();
        assert_eq!(store.get(1).unwrap(), Some(one.clone()));
        assert!(store.get_bounded(1, legacy.len() - 1).is_err());
        assert_eq!(
            store.get_bounded(1, legacy.len()).unwrap(),
            Some(one.clone())
        );
        store.put_once(&one, &WorldState::default()).unwrap();
        assert_eq!(
            std::fs::read(root.join(candidate_record(1))).unwrap(),
            legacy
        );
        assert!(!root.join(world_record(1)).exists());
        let two = candidate(2, &one.block_id, one.state.as_ref().clone());
        store.put_once(&two, &one.state).unwrap();
        let two_size = serde_json::to_vec(&two).unwrap().len();
        assert!(store.get_bounded(2, two_size - 1).is_err());
        assert_eq!(store.get_bounded(2, two_size).unwrap(), Some(two.clone()));
        assert!(!std::fs::read(root.join(world_record(2)))
            .unwrap()
            .starts_with(b"SNWDV001"));
        let three = candidate(3, &two.block_id, two.state.as_ref().clone());
        store.put_once(&three, &two.state).unwrap();
        assert!(std::fs::read(root.join(world_record(3)))
            .unwrap()
            .starts_with(b"SNWDV001"));
        drop(store);
        assert_eq!(
            CandidateStore::new(&root).unwrap().get(3).unwrap(),
            Some(three)
        );
        // A writer without a verified in-memory tip starts a full checkpoint.
        let mut store = CandidateStore::new(&root).unwrap();
        let jumped = candidate(100, "snapshot-parent", WorldState::default());
        store.put_once(&jumped, &WorldState::default()).unwrap();
        assert_eq!(store.get(100).unwrap(), Some(jumped));
        assert!(!std::fs::read(root.join(world_record(100)))
            .unwrap()
            .starts_with(b"SNWDV001"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn candidate_conflicts_wrong_parents_and_corrupt_dependencies_fail_closed() {
        let root = root();
        let mut store = CandidateStore::new(&root).unwrap();
        let one = candidate(1, "genesis", WorldState::default());
        store.put_once(&one, &WorldState::default()).unwrap();
        let mut changed = one.state.as_ref().clone();
        changed.protocol.insert("changed".into(), vec![1]);
        let two = candidate(2, &one.block_id, changed.clone());
        assert!(store.put_once(&two, &changed).is_err());
        assert!(!root.join(candidate_record(2)).exists());
        store.put_once(&two, &one.state).unwrap();
        let metadata = std::fs::read(root.join(candidate_record(2))).unwrap();
        let world = std::fs::read(root.join(world_record(2))).unwrap();
        let conflicting = candidate(2, &one.block_id, WorldState::default());
        assert!(store.put_once(&conflicting, &one.state).is_err());
        assert_eq!(
            std::fs::read(root.join(candidate_record(2))).unwrap(),
            metadata
        );
        assert_eq!(std::fs::read(root.join(world_record(2))).unwrap(), world);
        drop(store);
        std::fs::remove_file(root.join(world_record(1))).unwrap();
        assert!(CandidateStore::new(&root).unwrap().get(2).is_err());
        std::fs::write(
            root.join(world_record(1)),
            serde_json::to_vec(&changed).unwrap(),
        )
        .unwrap();
        assert!(CandidateStore::new(&root).unwrap().get(2).is_err());
        std::fs::write(
            root.join(world_record(1)),
            serde_json::to_vec(one.state.as_ref()).unwrap(),
        )
        .unwrap();
        let mut delta: serde_json::Value = serde_json::from_slice(&world[8..]).unwrap();
        delta["protocol"]["forged"] = serde_json::json!([2]);
        let mut bad = world[..8].to_vec();
        bad.extend(serde_json::to_vec(&delta).unwrap());
        std::fs::write(root.join(world_record(2)), bad).unwrap();
        assert!(CandidateStore::new(&root).unwrap().get(2).is_err());
        std::fs::write(root.join(world_record(2)), world).unwrap();
        let mut invalid: serde_json::Value = serde_json::from_slice(&metadata[8..]).unwrap();
        invalid["height"] = serde_json::json!(3);
        let mut bad = metadata[..8].to_vec();
        bad.extend(serde_json::to_vec(&invalid).unwrap());
        std::fs::write(root.join(candidate_record(2)), bad).unwrap();
        assert!(CandidateStore::new(&root).unwrap().get(2).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn interrupted_candidate_delta_transaction_recovers_after_partial_install() {
        let root = root();
        let one = candidate(1, "genesis", WorldState::default());
        let mut store = CandidateStore::new(&root).unwrap();
        store.put_once(&one, &WorldState::default()).unwrap();
        let mut world = one.state.as_ref().clone();
        world.protocol.insert("new".into(), vec![1, 2, 3]);
        let two = candidate(2, &one.block_id, world);
        let (_, tip) = world_history::checkpoint(1, &one.state).unwrap();
        let (delta, _) = world_history::encode_transition(
            2,
            &two.state_root,
            &one.state_root,
            &one.state,
            &two.state,
            tip,
        )
        .unwrap();
        drop(store);
        let transaction = root.join(".transactions/interrupted-candidate");
        std::fs::create_dir_all(transaction.join("staged")).unwrap();
        let writes = [
            (world_record(2), delta),
            (candidate_record(2), metadata_bytes(&two).unwrap()),
        ];
        let manifest: Vec<_> = writes.iter().enumerate().map(|(index, (path, bytes))| {
            std::fs::write(transaction.join("staged").join(format!("{index:020}")), bytes).unwrap();
            serde_json::json!({"relative_path": path, "length": bytes.len(),
                "digest": synergy_storage::IntegrityDigest::of("SYNERGY_STORAGE_TRANSACTION_WRITE_V1", bytes).0})
        }).collect();
        std::fs::write(
            transaction.join("manifest.json"),
            serde_json::to_vec(&serde_json::json!({"version": 1, "writes": manifest})).unwrap(),
        )
        .unwrap();
        std::fs::write(transaction.join("intent"), b"commit").unwrap();
        std::fs::rename(
            transaction.join("staged/00000000000000000000"),
            root.join(world_record(2)),
        )
        .unwrap();
        let store = CandidateStore::new(&root).unwrap();
        assert_eq!(store.get(2).unwrap(), Some(two));
        assert!(!transaction.exists());
        assert_eq!(store.get(1).unwrap(), Some(one));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn identical_writers_allow_checkpoint_or_delta_without_conflicting_replay() {
        let root = root();
        let one = candidate(1, "genesis", WorldState::default());
        let two = candidate(2, &one.block_id, WorldState::default());
        let mut warm = CandidateStore::new(&root).unwrap();
        warm.put_once(&one, &WorldState::default()).unwrap();
        let mut cold = CandidateStore::new(&root).unwrap();
        let barrier = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            let first = scope.spawn(|| {
                barrier.wait();
                warm.put_once(&two, &one.state)
            });
            let second = scope.spawn(|| {
                barrier.wait();
                cold.put_once(&two, &one.state)
            });
            first.join().unwrap().unwrap();
            second.join().unwrap().unwrap();
        });
        assert_eq!(
            CandidateStore::new(&root).unwrap().get(2).unwrap(),
            Some(two)
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn competing_candidate_writers_cannot_overwrite_an_immutable_height() {
        let root = root();
        let one = candidate(1, "genesis", WorldState::default());
        let mut changed = WorldState::default();
        changed.protocol.insert("different".into(), vec![1]);
        let other = candidate(1, "genesis", changed);
        let barrier = std::sync::Barrier::new(2);
        let results = std::thread::scope(|scope| {
            let first = scope.spawn(|| {
                let mut store = CandidateStore::new(&root).unwrap();
                barrier.wait();
                store.put_once(&one, &WorldState::default())
            });
            let second = scope.spawn(|| {
                let mut store = CandidateStore::new(&root).unwrap();
                barrier.wait();
                store.put_once(&other, &WorldState::default())
            });
            (first.join().unwrap(), second.join().unwrap())
        });
        assert_ne!(results.0.is_ok(), results.1.is_ok());
        let recovered = CandidateStore::new(&root).unwrap().get(1).unwrap().unwrap();
        assert!(recovered == one || recovered == other);
        std::fs::remove_dir_all(root).unwrap();
    }
}
