use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use synergy_protocol_types::{BlockReference, NodeAddress};
use synergy_storage::{AtomicStore, RequiredRecord, StoragePrecondition, StorageTransaction};

use crate::{NamingError, NamingRecord, NodeId};

const STATE_VERSION: u32 = 1;
const CACHE_PATH: &str = "cache/naming-finalized-v1.json";
const MAX_CACHE_BYTES: usize = 4 * 1024 * 1024;

/// Rebuildable view of authoritative finalized Synergy Naming System state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamingRegistrySnapshot {
    version: u32,
    pub(crate) finalized_at: Option<BlockReference>,
    records: BTreeMap<NodeId, NamingRecord>,
    reverse: BTreeMap<NodeAddress, NodeId>,
    last_nonce_by_node: BTreeMap<NodeAddress, u64>,
}

impl Default for NamingRegistrySnapshot {
    fn default() -> Self {
        Self {
            version: STATE_VERSION,
            finalized_at: None,
            records: BTreeMap::new(),
            reverse: BTreeMap::new(),
            last_nonce_by_node: BTreeMap::new(),
        }
    }
}

impl NamingRegistrySnapshot {
    pub const fn version(&self) -> u32 {
        self.version
    }

    pub const fn finalized_at(&self) -> Option<BlockReference> {
        self.finalized_at
    }

    pub fn record(&self, node_id: &NodeId) -> Option<&NamingRecord> {
        self.records.get(node_id)
    }

    pub fn node_id(&self, node_address: &NodeAddress) -> Option<&NodeId> {
        self.reverse.get(node_address)
    }

    pub(crate) fn last_nonce(&self, node_address: &NodeAddress) -> u64 {
        self.last_nonce_by_node
            .get(node_address)
            .copied()
            .unwrap_or_default()
    }

    pub(crate) fn insert(&mut self, record: NamingRecord, nonce: u64) -> Result<(), NamingError> {
        if nonce == 0 || nonce <= self.last_nonce(&record.node_address) {
            return Err(NamingError::InvalidNonce);
        }
        self.reverse
            .insert(record.node_address.clone(), record.node_id.clone());
        self.last_nonce_by_node
            .insert(record.node_address.clone(), nonce);
        self.records.insert(record.node_id.clone(), record);
        Ok(())
    }

    pub(crate) fn rename(
        &mut self,
        current_node_id: &NodeId,
        replacement: NamingRecord,
        nonce: u64,
    ) -> Result<(), NamingError> {
        let previous = self
            .records
            .remove(current_node_id)
            .ok_or(NamingError::NodeIdNotFound)?;
        self.reverse.remove(&previous.node_address);
        self.insert(replacement, nonce)
    }

    pub(crate) fn ensure_next_finalized(&self, next: &BlockReference) -> Result<(), NamingError> {
        if let Some(current) = self.finalized_at {
            if next.height <= current.height {
                return Err(if next == &current {
                    NamingError::ConflictingFinalizedState
                } else {
                    NamingError::InvalidFinalizedOrder
                });
            }
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), NamingError> {
        if self.version != STATE_VERSION {
            return Err(NamingError::InvalidRegistryVersion);
        }
        if self.records.len() != self.reverse.len() {
            return Err(NamingError::CorruptRegistry);
        }
        for (node_id, record) in &self.records {
            if node_id != &record.node_id
                || record.record_version != 1
                || record.sequence == 0
                || self.reverse.get(&record.node_address) != Some(node_id)
                || self.last_nonce(&record.node_address) == 0
            {
                return Err(NamingError::CorruptRegistry);
            }
        }
        for (node_address, node_id) in &self.reverse {
            if self
                .records
                .get(node_id)
                .is_none_or(|record| &record.node_address != node_address)
            {
                return Err(NamingError::CorruptRegistry);
            }
        }
        Ok(())
    }
}

/// Rebuildable local cache; it cannot register, rename, or arbitrate a NodeID.
pub trait NamingCache {
    fn load_finalized(&self) -> Result<Option<NamingRegistrySnapshot>, NamingError>;

    fn replace_finalized(
        &mut self,
        expected: Option<&NamingRegistrySnapshot>,
        replacement: &NamingRegistrySnapshot,
    ) -> Result<(), NamingError>;
}

#[derive(Debug, Clone)]
pub struct AtomicNamingCache {
    store: AtomicStore,
}

impl AtomicNamingCache {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, NamingError> {
        AtomicStore::new(root.as_ref(), MAX_CACHE_BYTES)
            .map(|store| Self { store })
            .map_err(|error| NamingError::Cache(error.to_string()))
    }

    fn load_bytes(&self) -> Result<Option<Vec<u8>>, NamingError> {
        if !self
            .store
            .exists(CACHE_PATH)
            .map_err(|error| NamingError::Cache(error.to_string()))?
        {
            return Ok(None);
        }
        self.store
            .read_bounded(CACHE_PATH)
            .map(Some)
            .map_err(|error| NamingError::Cache(error.to_string()))
    }
}

impl NamingCache for AtomicNamingCache {
    fn load_finalized(&self) -> Result<Option<NamingRegistrySnapshot>, NamingError> {
        let snapshot: Option<NamingRegistrySnapshot> = self
            .load_bytes()?
            .as_deref()
            .map(serde_json::from_slice)
            .transpose()
            .map_err(|error| NamingError::Serialization(error.to_string()))?;
        if let Some(value) = &snapshot {
            value.validate()?;
            if value.finalized_at().is_none() {
                return Err(NamingError::CorruptRegistry);
            }
        }
        Ok(snapshot)
    }

    fn replace_finalized(
        &mut self,
        expected: Option<&NamingRegistrySnapshot>,
        replacement: &NamingRegistrySnapshot,
    ) -> Result<(), NamingError> {
        replacement.validate()?;
        let replacement_finalized = replacement
            .finalized_at()
            .ok_or(NamingError::CorruptRegistry)?;
        if let Some(current) = expected {
            let current_finalized = current.finalized_at().ok_or(NamingError::CorruptRegistry)?;
            if replacement_finalized.height <= current_finalized.height {
                return Err(NamingError::InvalidFinalizedOrder);
            }
        }
        let expected_bytes = expected
            .map(serde_json::to_vec)
            .transpose()
            .map_err(|error| NamingError::Serialization(error.to_string()))?;
        let replacement_bytes = serde_json::to_vec(replacement)
            .map_err(|error| NamingError::Serialization(error.to_string()))?;
        let required = expected_bytes.map_or(RequiredRecord::Missing, RequiredRecord::Exact);
        let preconditions = [StoragePrecondition {
            relative_path: PathBuf::from(CACHE_PATH),
            required,
        }];
        let mut transaction = StorageTransaction::new(MAX_CACHE_BYTES)
            .map_err(|error| NamingError::Cache(error.to_string()))?;
        transaction
            .put(CACHE_PATH, replacement_bytes)
            .map_err(|error| NamingError::Cache(error.to_string()))?;
        transaction
            .commit_guarded(&mut self.store, &preconditions)
            .map_err(|error| NamingError::Cache(error.to_string()))
    }
}
