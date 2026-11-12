use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalSyncPolicy {
    EveryCommit,
    BoundedBatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfiguration {
    pub data_directory: PathBuf,
    pub wal_sync: WalSyncPolicy,
    pub max_open_files: u32,
    /// Local capacity for retained World graphs and concurrent decode/clone scratch.
    /// This is backpressure capacity, never a signed state-validity limit.
    #[serde(default = "default_world_memory_budget_bytes")]
    pub world_memory_budget_bytes: usize,
    #[serde(default = "default_minimum_free_bytes")]
    pub minimum_free_bytes: u64,
    pub prune_finalized_history_after_blocks: Option<u64>,
}

pub const fn default_minimum_free_bytes() -> u64 {
    2 * 1024 * 1024 * 1024
}

/// Shared per-node World allocation pool; operators may size it for their host.
pub const fn default_world_memory_budget_bytes() -> usize {
    64 * 1024 * 1024
}
