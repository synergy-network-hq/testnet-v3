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
    #[serde(default = "default_minimum_free_bytes")]
    pub minimum_free_bytes: u64,
    pub prune_finalized_history_after_blocks: Option<u64>,
}

pub const fn default_minimum_free_bytes() -> u64 {
    2 * 1024 * 1024 * 1024
}
