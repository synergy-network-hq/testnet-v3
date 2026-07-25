use crate::synq_execution::{SynQArtifactKey, SynQContractArtifact, SynQDeploymentRecord};
use aivm_core::state::ContractState;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const SYNQ_RECEIPT_INDEX_VERSION: u16 = 1;
pub const SYNQ_RECEIPT_INDEX_PATH_ENV: &str = "SYNERGY_SYNQ_RECEIPT_INDEX_PATH";
pub const DEFAULT_SYNQ_RECEIPT_INDEX_PATH: &str = "data/synq_receipts.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynQReceiptIndex {
    pub version: u16,
    pub receipts_by_tx_hash: BTreeMap<String, SynQIndexedReceipt>,
    pub tx_hash_aliases: BTreeMap<String, String>,
    pub tx_hashes_by_block: BTreeMap<u64, Vec<String>>,
    pub checkpoint: SynQExecutionCheckpoint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynQExecutionCheckpoint {
    pub first_materialized_block: Option<u64>,
    pub latest_materialized_block: Option<u64>,
    pub aivm_state_root: String,
    pub aivm_state: ContractState,
    pub artifacts: Vec<SynQStoredArtifact>,
    pub deployments: BTreeMap<String, SynQDeploymentRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynQStoredArtifact {
    pub key: SynQArtifactKey,
    pub artifact: SynQContractArtifact,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynQIndexedReceipt {
    pub legacy_tx_hash: String,
    pub legacy_raw_tx_hash: String,
    pub block_hash: String,
    pub block_number: u64,
    pub transaction_index: usize,
    pub synq_receipt_hash: Option<String>,
    pub receipt: Value,
}

impl Default for SynQReceiptIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl SynQReceiptIndex {
    pub fn new() -> Self {
        Self {
            version: SYNQ_RECEIPT_INDEX_VERSION,
            receipts_by_tx_hash: BTreeMap::new(),
            tx_hash_aliases: BTreeMap::new(),
            tx_hashes_by_block: BTreeMap::new(),
            checkpoint: SynQExecutionCheckpoint::new(),
        }
    }

    pub fn load_from_path(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let file = File::open(path)
            .map_err(|error| format!("open SynQ receipt index {}: {error}", path.display()))?;
        let reader = BufReader::new(file);
        let mut deserializer = serde_json::Deserializer::from_reader(reader);
        let index = Self::deserialize(&mut deserializer)
            .map_err(|error| format!("decode SynQ receipt index {}: {error}", path.display()))?;
        deserializer.end().map_err(|error| {
            format!(
                "decode SynQ receipt index {}: trailing bytes after JSON: {error}",
                path.display()
            )
        })?;
        if index.version != SYNQ_RECEIPT_INDEX_VERSION {
            return Err(format!(
                "unsupported SynQ receipt index version {} in {}",
                index.version,
                path.display()
            ));
        }
        Ok(index)
    }

    pub fn save_to_path_atomic(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "create SynQ receipt index directory {}: {error}",
                    parent.display()
                )
            })?;
        }

        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| format!("invalid SynQ receipt index path: {}", path.display()))?;
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        let temp_path =
            path.with_file_name(format!("{file_name}.tmp-{}-{suffix}", std::process::id()));

        {
            let file = File::create(&temp_path).map_err(|error| {
                format!(
                    "create temp SynQ receipt index {}: {error}",
                    temp_path.display()
                )
            })?;
            let mut writer = BufWriter::new(file);
            serde_json::to_writer_pretty(&mut writer, self).map_err(|error| {
                format!(
                    "write temp SynQ receipt index {}: {error}",
                    temp_path.display()
                )
            })?;
            writer.flush().map_err(|error| {
                format!(
                    "flush temp SynQ receipt index {}: {error}",
                    temp_path.display()
                )
            })?;
            writer.get_ref().sync_all().map_err(|error| {
                format!(
                    "sync temp SynQ receipt index {}: {error}",
                    temp_path.display()
                )
            })?;
        }

        fs::rename(&temp_path, path).map_err(|error| {
            let _ = fs::remove_file(&temp_path);
            format!(
                "replace SynQ receipt index {} with {}: {error}",
                path.display(),
                temp_path.display()
            )
        })?;
        Ok(())
    }

    pub fn upsert_receipt(&mut self, receipt: SynQIndexedReceipt) {
        let canonical = normalize_tx_hash(&receipt.legacy_tx_hash);
        self.insert_alias(&canonical, &canonical);
        self.insert_alias(&receipt.legacy_tx_hash, &canonical);
        self.insert_alias(&receipt.legacy_raw_tx_hash, &canonical);
        if let Some(raw) = strip_synergy_tx_prefix(&receipt.legacy_raw_tx_hash) {
            self.insert_alias(raw, &canonical);
        }
        if let Some(raw) = strip_synergy_tx_prefix(&receipt.legacy_tx_hash) {
            self.insert_alias(raw, &canonical);
        }

        let txs = self
            .tx_hashes_by_block
            .entry(receipt.block_number)
            .or_default();
        if !txs.iter().any(|tx_hash| tx_hash == &canonical) {
            txs.push(canonical.clone());
        }
        self.receipts_by_tx_hash.insert(canonical, receipt);
    }

    pub fn receipt_by_query(&self, query: &str) -> Option<&SynQIndexedReceipt> {
        let normalized = normalize_tx_hash(query);
        self.tx_hash_aliases
            .get(&normalized)
            .and_then(|canonical| self.receipts_by_tx_hash.get(canonical))
            .or_else(|| self.receipts_by_tx_hash.get(&normalized))
    }

    pub fn receipt_for_position(
        &self,
        block_number: u64,
        transaction_index: usize,
    ) -> Option<&SynQIndexedReceipt> {
        self.tx_hashes_by_block
            .get(&block_number)?
            .iter()
            .filter_map(|tx_hash| self.receipts_by_tx_hash.get(tx_hash))
            .find(|receipt| receipt.transaction_index == transaction_index)
    }

    pub fn record_checkpoint(
        &mut self,
        block_number: u64,
        first_materialized_block: Option<u64>,
        aivm_state: &ContractState,
        artifacts: &BTreeMap<SynQArtifactKey, SynQContractArtifact>,
        deployments: &BTreeMap<String, SynQDeploymentRecord>,
    ) {
        self.checkpoint.first_materialized_block = self
            .checkpoint
            .first_materialized_block
            .or(first_materialized_block);
        self.checkpoint.latest_materialized_block = Some(block_number);
        self.checkpoint.aivm_state_root = hex::encode(aivm_state.state_root());
        self.checkpoint.aivm_state = aivm_state.clone();
        self.checkpoint.artifacts = artifacts
            .iter()
            .map(|(key, artifact)| SynQStoredArtifact {
                key: key.clone(),
                artifact: artifact.clone(),
            })
            .collect();
        self.checkpoint.deployments = deployments.clone();
    }

    fn insert_alias(&mut self, alias: &str, canonical: &str) {
        let normalized = normalize_tx_hash(alias);
        if !normalized.is_empty() {
            self.tx_hash_aliases
                .insert(normalized, canonical.to_string());
        }
    }
}

impl SynQExecutionCheckpoint {
    pub fn new() -> Self {
        let aivm_state = ContractState::default();
        Self {
            first_materialized_block: None,
            latest_materialized_block: None,
            aivm_state_root: hex::encode(aivm_state.state_root()),
            aivm_state,
            artifacts: Vec::new(),
            deployments: BTreeMap::new(),
        }
    }

    pub fn artifact_map(&self) -> BTreeMap<SynQArtifactKey, SynQContractArtifact> {
        self.artifacts
            .iter()
            .map(|entry| (entry.key.clone(), entry.artifact.clone()))
            .collect()
    }
}

impl SynQIndexedReceipt {
    pub fn new(
        legacy_tx_hash: String,
        legacy_raw_tx_hash: String,
        block_hash: String,
        block_number: u64,
        transaction_index: usize,
        receipt: Value,
    ) -> Self {
        let synq_receipt_hash = receipt
            .get("synq_receipt_hash")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        Self {
            legacy_tx_hash,
            legacy_raw_tx_hash,
            block_hash,
            block_number,
            transaction_index,
            synq_receipt_hash,
            receipt,
        }
    }
}

pub fn configured_synq_receipt_index_path() -> PathBuf {
    std::env::var_os(SYNQ_RECEIPT_INDEX_PATH_ENV)
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SYNQ_RECEIPT_INDEX_PATH))
}

fn normalize_tx_hash(hash: &str) -> String {
    hash.trim()
        .strip_prefix("0x")
        .unwrap_or_else(|| hash.trim())
        .to_lowercase()
}

fn strip_synergy_tx_prefix(hash: &str) -> Option<&str> {
    let normalized = hash
        .trim()
        .strip_prefix("0x")
        .unwrap_or_else(|| hash.trim());
    normalized
        .strip_prefix("syntxn-")
        .or_else(|| normalized.strip_prefix("synxxn-"))
}
