use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use synergy_protocol_types::{BlockReference, NodeAddress};
use synergy_storage::{AtomicStore, RequiredRecord, StoragePrecondition, StorageTransaction};

use crate::{RewardAccount, RewardError, WithdrawalRecord};

const STATE_VERSION: u32 = 1;
const CACHE_PATH: &str = "cache/rewards-finalized-v1.json";
const MAX_CACHE_BYTES: usize = 16 * 1024 * 1024;

/// Rebuildable snapshot of finalized reward and withdrawal state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RewardLedgerSnapshot {
    version: u32,
    pub(crate) finalized_at: Option<BlockReference>,
    pub(crate) accounts: BTreeMap<NodeAddress, RewardAccount>,
    pub(crate) withdrawals: BTreeMap<String, WithdrawalRecord>,
    pub(crate) credit_sources: BTreeSet<String>,
    pub(crate) last_nonce_by_node: BTreeMap<NodeAddress, u64>,
}

impl Default for RewardLedgerSnapshot {
    fn default() -> Self {
        Self {
            version: STATE_VERSION,
            finalized_at: None,
            accounts: BTreeMap::new(),
            withdrawals: BTreeMap::new(),
            credit_sources: BTreeSet::new(),
            last_nonce_by_node: BTreeMap::new(),
        }
    }
}

impl RewardLedgerSnapshot {
    pub const fn finalized_at(&self) -> Option<BlockReference> {
        self.finalized_at
    }

    pub fn account(&self, node_address: &NodeAddress) -> Option<&RewardAccount> {
        self.accounts.get(node_address)
    }

    pub fn withdrawal(&self, withdrawal_id: &str) -> Option<&WithdrawalRecord> {
        self.withdrawals.get(withdrawal_id)
    }

    pub(crate) fn last_nonce(&self, node_address: &NodeAddress) -> u64 {
        self.last_nonce_by_node
            .get(node_address)
            .copied()
            .unwrap_or_default()
    }

    pub(crate) fn ensure_next_finalized(&self, next: &BlockReference) -> Result<(), RewardError> {
        if let Some(current) = self.finalized_at {
            if next.height <= current.height {
                return Err(if next == &current {
                    RewardError::ConflictingFinalizedState
                } else {
                    RewardError::InvalidFinalizedOrder
                });
            }
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), RewardError> {
        if self.version != STATE_VERSION {
            return Err(RewardError::InvalidVersion);
        }
        for (node_address, account) in &self.accounts {
            account.validate()?;
            if &account.node_address != node_address {
                return Err(RewardError::CorruptState);
            }
        }
        for (id, withdrawal) in &self.withdrawals {
            if id != &withdrawal.withdrawal_id
                || withdrawal.record_version != 1
                || withdrawal.amount_nwei == 0
                || !self.accounts.contains_key(&withdrawal.node_address)
            {
                return Err(RewardError::CorruptState);
            }
        }
        Ok(())
    }
}

/// Rebuildable cache only; finalized chain state remains authoritative.
pub trait RewardCache {
    fn load_finalized(&self) -> Result<Option<RewardLedgerSnapshot>, RewardError>;

    fn replace_finalized(
        &mut self,
        expected: Option<&RewardLedgerSnapshot>,
        replacement: &RewardLedgerSnapshot,
    ) -> Result<(), RewardError>;
}

#[derive(Debug, Clone)]
pub struct AtomicRewardCache {
    store: AtomicStore,
}

impl AtomicRewardCache {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, RewardError> {
        AtomicStore::new(root.as_ref(), MAX_CACHE_BYTES)
            .map(|store| Self { store })
            .map_err(|error| RewardError::Cache(error.to_string()))
    }

    fn load_bytes(&self) -> Result<Option<Vec<u8>>, RewardError> {
        if !self
            .store
            .exists(CACHE_PATH)
            .map_err(|error| RewardError::Cache(error.to_string()))?
        {
            return Ok(None);
        }
        self.store
            .read_bounded(CACHE_PATH)
            .map(Some)
            .map_err(|error| RewardError::Cache(error.to_string()))
    }
}

impl RewardCache for AtomicRewardCache {
    fn load_finalized(&self) -> Result<Option<RewardLedgerSnapshot>, RewardError> {
        let state: Option<RewardLedgerSnapshot> = self
            .load_bytes()?
            .as_deref()
            .map(serde_json::from_slice)
            .transpose()
            .map_err(|error| RewardError::Serialization(error.to_string()))?;
        if let Some(value) = &state {
            value.validate()?;
            if value.finalized_at().is_none() {
                return Err(RewardError::CorruptState);
            }
        }
        Ok(state)
    }

    fn replace_finalized(
        &mut self,
        expected: Option<&RewardLedgerSnapshot>,
        replacement: &RewardLedgerSnapshot,
    ) -> Result<(), RewardError> {
        replacement.validate()?;
        let replacement_finalized = replacement
            .finalized_at()
            .ok_or(RewardError::CorruptState)?;
        if let Some(current) = expected {
            let current_finalized = current.finalized_at().ok_or(RewardError::CorruptState)?;
            if replacement_finalized.height <= current_finalized.height {
                return Err(RewardError::InvalidFinalizedOrder);
            }
        }
        let expected_bytes = expected
            .map(serde_json::to_vec)
            .transpose()
            .map_err(|error| RewardError::Serialization(error.to_string()))?;
        let replacement_bytes = serde_json::to_vec(replacement)
            .map_err(|error| RewardError::Serialization(error.to_string()))?;
        let required = expected_bytes.map_or(RequiredRecord::Missing, RequiredRecord::Exact);
        let preconditions = [StoragePrecondition {
            relative_path: PathBuf::from(CACHE_PATH),
            required,
        }];
        let mut transaction = StorageTransaction::new(MAX_CACHE_BYTES)
            .map_err(|error| RewardError::Cache(error.to_string()))?;
        transaction
            .put(CACHE_PATH, replacement_bytes)
            .map_err(|error| RewardError::Cache(error.to_string()))?;
        transaction
            .commit_guarded(&mut self.store, &preconditions)
            .map_err(|error| RewardError::Cache(error.to_string()))
    }
}
