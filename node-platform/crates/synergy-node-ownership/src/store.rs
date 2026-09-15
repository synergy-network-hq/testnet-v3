use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use synergy_protocol_types::{BlockReference, NodeAddress};
use synergy_storage::{AtomicStore, RequiredRecord, StoragePrecondition, StorageTransaction};

use crate::{NodeOwnershipBinding, OwnershipError};

const STATE_VERSION: u32 = 1;
const CACHE_PATH: &str = "cache/node-ownership-finalized-v1.json";
const MAX_CACHE_BYTES: usize = 8 * 1024 * 1024;

/// Rebuildable snapshot of canonical finalized ownership state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnershipRegistrySnapshot {
    version: u32,
    pub(crate) finalized_at: Option<BlockReference>,
    bindings: BTreeMap<NodeAddress, NodeOwnershipBinding>,
    history: BTreeMap<NodeAddress, Vec<NodeOwnershipBinding>>,
    last_nonce_by_node: BTreeMap<NodeAddress, u64>,
}

impl Default for OwnershipRegistrySnapshot {
    fn default() -> Self {
        Self {
            version: STATE_VERSION,
            finalized_at: None,
            bindings: BTreeMap::new(),
            history: BTreeMap::new(),
            last_nonce_by_node: BTreeMap::new(),
        }
    }
}

impl OwnershipRegistrySnapshot {
    pub const fn version(&self) -> u32 {
        self.version
    }

    pub const fn finalized_at(&self) -> Option<BlockReference> {
        self.finalized_at
    }

    pub fn binding(&self, node_address: &NodeAddress) -> Option<&NodeOwnershipBinding> {
        self.bindings.get(node_address)
    }

    pub fn current_owner(&self, node_address: &NodeAddress) -> Option<&str> {
        self.binding(node_address)
            .map(|binding| binding.owner_wallet.as_str())
    }

    pub fn history(&self, node_address: &NodeAddress) -> &[NodeOwnershipBinding] {
        self.history
            .get(node_address)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    pub(crate) fn last_nonce(&self, node_address: &NodeAddress) -> u64 {
        self.last_nonce_by_node
            .get(node_address)
            .copied()
            .unwrap_or_default()
    }

    pub(crate) fn install_binding(
        &mut self,
        binding: NodeOwnershipBinding,
        nonce: u64,
    ) -> Result<(), OwnershipError> {
        binding.validate()?;
        if nonce == 0 || nonce <= self.last_nonce(&binding.node_address) {
            return Err(OwnershipError::InvalidNonce);
        }
        self.history
            .entry(binding.node_address.clone())
            .or_default()
            .push(binding.clone());
        self.last_nonce_by_node
            .insert(binding.node_address.clone(), nonce);
        self.bindings.insert(binding.node_address.clone(), binding);
        Ok(())
    }

    pub(crate) fn ensure_next_finalized(
        &self,
        next: &BlockReference,
    ) -> Result<(), OwnershipError> {
        if let Some(current) = self.finalized_at {
            if next.height <= current.height {
                return Err(if next == &current {
                    OwnershipError::ConflictingFinalizedState
                } else {
                    OwnershipError::InvalidFinalizedOrder
                });
            }
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), OwnershipError> {
        if self.version != STATE_VERSION {
            return Err(OwnershipError::InvalidVersion);
        }
        for (node_address, binding) in &self.bindings {
            binding.validate()?;
            if &binding.node_address != node_address
                || self
                    .history
                    .get(node_address)
                    .and_then(|entries| entries.last())
                    != Some(binding)
                || self.last_nonce(node_address) == 0
            {
                return Err(OwnershipError::CorruptState);
            }
        }
        for (node_address, entries) in &self.history {
            if entries.is_empty() || !self.bindings.contains_key(node_address) {
                return Err(OwnershipError::CorruptState);
            }
            for (index, binding) in entries.iter().enumerate() {
                binding.validate()?;
                if &binding.node_address != node_address
                    || binding.sequence != (index as u64).saturating_add(1)
                {
                    return Err(OwnershipError::CorruptState);
                }
            }
        }
        Ok(())
    }
}

/// Rebuildable local cache for finalized state; never an ownership authority.
pub trait OwnershipCache {
    fn load_finalized(&self) -> Result<Option<OwnershipRegistrySnapshot>, OwnershipError>;

    fn replace_finalized(
        &mut self,
        expected: Option<&OwnershipRegistrySnapshot>,
        replacement: &OwnershipRegistrySnapshot,
    ) -> Result<(), OwnershipError>;
}

#[derive(Debug, Clone)]
pub struct AtomicOwnershipCache {
    store: AtomicStore,
}

impl AtomicOwnershipCache {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, OwnershipError> {
        AtomicStore::new(root.as_ref(), MAX_CACHE_BYTES)
            .map(|store| Self { store })
            .map_err(|error| OwnershipError::Cache(error.to_string()))
    }

    fn load_bytes(&self) -> Result<Option<Vec<u8>>, OwnershipError> {
        if !self
            .store
            .exists(CACHE_PATH)
            .map_err(|error| OwnershipError::Cache(error.to_string()))?
        {
            return Ok(None);
        }
        self.store
            .read_bounded(CACHE_PATH)
            .map(Some)
            .map_err(|error| OwnershipError::Cache(error.to_string()))
    }
}

impl OwnershipCache for AtomicOwnershipCache {
    fn load_finalized(&self) -> Result<Option<OwnershipRegistrySnapshot>, OwnershipError> {
        let snapshot: Option<OwnershipRegistrySnapshot> = self
            .load_bytes()?
            .as_deref()
            .map(serde_json::from_slice)
            .transpose()
            .map_err(|error| OwnershipError::Serialization(error.to_string()))?;
        if let Some(value) = &snapshot {
            value.validate()?;
            if value.finalized_at().is_none() {
                return Err(OwnershipError::CorruptState);
            }
        }
        Ok(snapshot)
    }

    fn replace_finalized(
        &mut self,
        expected: Option<&OwnershipRegistrySnapshot>,
        replacement: &OwnershipRegistrySnapshot,
    ) -> Result<(), OwnershipError> {
        replacement.validate()?;
        let replacement_finalized = replacement
            .finalized_at()
            .ok_or(OwnershipError::CorruptState)?;
        if let Some(current) = expected {
            let current_finalized = current.finalized_at().ok_or(OwnershipError::CorruptState)?;
            if replacement_finalized.height <= current_finalized.height {
                return Err(OwnershipError::InvalidFinalizedOrder);
            }
        }
        let expected_bytes = expected
            .map(serde_json::to_vec)
            .transpose()
            .map_err(|error| OwnershipError::Serialization(error.to_string()))?;
        let replacement_bytes = serde_json::to_vec(replacement)
            .map_err(|error| OwnershipError::Serialization(error.to_string()))?;
        let required = expected_bytes.map_or(RequiredRecord::Missing, RequiredRecord::Exact);
        let preconditions = [StoragePrecondition {
            relative_path: PathBuf::from(CACHE_PATH),
            required,
        }];
        let mut transaction = StorageTransaction::new(MAX_CACHE_BYTES)
            .map_err(|error| OwnershipError::Cache(error.to_string()))?;
        transaction
            .put(CACHE_PATH, replacement_bytes)
            .map_err(|error| OwnershipError::Cache(error.to_string()))?;
        transaction
            .commit_guarded(&mut self.store, &preconditions)
            .map_err(|error| OwnershipError::Cache(error.to_string()))
    }
}
