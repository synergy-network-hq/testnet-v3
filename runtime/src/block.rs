use crate::transaction::Transaction;
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::consensus::consensus_fork::validate_consensus_key_algorithm_for_height;
use crate::consensus::validator_keys::block_signature_algorithm;
use crate::crypto::pqc::{PQCManager, PQCPublicKey, PQCSignature};
use crate::genesis::canonical_genesis;

pub const HOT_CHAIN_RETENTION_BLOCKS_ENV: &str = "SYNERGY_HOT_CHAIN_RETENTION_BLOCKS";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub block_index: u64,
    #[serde(default)]
    pub timestamp: u64,
    pub transactions: Vec<Transaction>,
    pub previous_hash: String,
    pub validator_id: String,
    pub nonce: u64,
    pub hash: String,
    #[serde(default)]
    pub transactions_root: String,
    #[serde(default)]
    pub proposer_public_key: Vec<u8>,
    #[serde(default)]
    pub block_signature: Vec<u8>,
    #[serde(default)]
    pub block_signature_algorithm: String,
}

impl Block {
    pub fn new(
        block_index: u64,
        transactions: Vec<Transaction>,
        previous_hash: String,
        validator_id: String,
        nonce: u64,
    ) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self::new_with_timestamp(
            block_index,
            transactions,
            previous_hash,
            validator_id,
            nonce,
            timestamp,
        )
    }

    pub fn new_with_timestamp(
        block_index: u64,
        transactions: Vec<Transaction>,
        previous_hash: String,
        validator_id: String,
        nonce: u64,
        timestamp: u64,
    ) -> Self {
        let transactions_root = compute_merkle_root(&transactions);

        let data = format!(
            "{:?}{}{}{}{}{}",
            block_index, previous_hash, validator_id, nonce, timestamp, transactions_root
        );
        let hash = blake3::hash(data.as_bytes()).to_hex().to_string();
        Block {
            block_index,
            timestamp,
            transactions,
            previous_hash,
            validator_id,
            nonce,
            hash,
            transactions_root,
            proposer_public_key: Vec::new(),
            block_signature: Vec::new(),
            block_signature_algorithm: String::new(),
        }
    }

    pub fn validate(&self) -> bool {
        if self.block_index == 0 {
            return self.hash
                == canonical_genesis()
                    .map(|genesis| genesis.hash().to_string())
                    .unwrap_or_default()
                && self.transactions.is_empty()
                && self.transactions_root == compute_merkle_root(&[]);
        }

        if self.hash.is_empty()
            || self.previous_hash.is_empty()
            || self.validator_id.is_empty()
            || self.transactions_root.is_empty()
        {
            return false;
        }

        if self.block_signature.is_empty()
            || self.proposer_public_key.is_empty()
            || self.block_signature_algorithm.trim().is_empty()
        {
            return false;
        }

        self.transactions_root == compute_merkle_root(&self.transactions)
            && self.hash == self.recompute_hash()
    }

    pub fn verify_proposer_signature(&self) -> Result<(), String> {
        if self.block_index == 0 {
            return if self.validate() {
                Ok(())
            } else {
                Err("genesis block does not match canonical genesis".to_string())
            };
        }

        if !self.validate() {
            return Err(
                "block header, transaction root, or signature metadata is invalid".to_string(),
            );
        }

        let algorithm = block_signature_algorithm(&self.block_signature_algorithm)
            .map_err(|error| format!("unsupported Aegis PQC block signature algorithm: {error}"))?;
        validate_consensus_key_algorithm_for_height(self.block_index, &algorithm)?;

        let public_key = PQCPublicKey {
            algorithm: algorithm.clone(),
            key_data: self.proposer_public_key.clone(),
            key_id: format!("block-proposer:{}", self.validator_id),
            created_at: self.timestamp,
        };
        let signature = PQCSignature {
            algorithm,
            signature_data: self.block_signature.clone(),
            message_hash: self.hash.as_bytes().to_vec(),
            public_key_id: public_key.key_id.clone(),
            created_at: self.timestamp,
        };

        let manager = PQCManager::new();
        match manager.verify(&public_key, &signature, self.hash.as_bytes()) {
            Ok(true) => Ok(()),
            Ok(false) => Err("Aegis PQC block signature verification failed".to_string()),
            Err(error) => Err(format!(
                "Aegis PQC block signature verification failed: {error}"
            )),
        }
    }

    pub fn recompute_hash(&self) -> String {
        let data = format!(
            "{:?}{}{}{}{}{}",
            self.block_index,
            self.previous_hash,
            self.validator_id,
            self.nonce,
            self.timestamp,
            self.transactions_root
        );
        blake3::hash(data.as_bytes()).to_hex().to_string()
    }

    pub fn header(&self) -> BlockHeader {
        BlockHeader {
            number: self.block_index,
            timestamp: self.timestamp,
            parent_hash: self.previous_hash.clone(),
            hash: self.hash.clone(),
            validator_id: self.validator_id.clone(),
            transactions_root: self.transactions_root.clone(),
        }
    }
}

pub fn compute_merkle_root(transactions: &[Transaction]) -> String {
    if transactions.is_empty() {
        return blake3::hash(&[]).to_hex().to_string();
    }

    let mut hashes: Vec<String> = transactions.iter().map(|tx| tx.raw_hash()).collect();
    while hashes.len() > 1 {
        let mut next = Vec::new();
        for chunk in hashes.chunks(2) {
            if chunk.len() == 2 {
                let pair = format!("{}{}", chunk[0], chunk[1]);
                next.push(blake3::hash(pair.as_bytes()).to_hex().to_string());
            } else {
                next.push(chunk[0].clone());
            }
        }
        hashes = next;
    }

    hashes
        .first()
        .cloned()
        .unwrap_or_else(|| blake3::hash(&[]).to_hex().to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    pub number: u64,
    pub timestamp: u64,
    pub parent_hash: String,
    pub hash: String,
    pub validator_id: String,
    pub transactions_root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockChain {
    pub chain: Vec<Block>,
}

impl BlockChain {
    pub fn new() -> Self {
        BlockChain { chain: vec![] }
    }

    pub fn add_block(&mut self, block: Block) {
        self.chain.push(block);
    }

    pub fn add_block_extending_tip(&mut self, block: Block) -> Result<bool, String> {
        if let Some(tip) = self.chain.last() {
            if tip.block_index == block.block_index && tip.hash == block.hash {
                return Ok(false);
            }

            let expected_height = tip.block_index.saturating_add(1);
            if block.block_index != expected_height {
                return Err(format!(
                    "block height {} does not extend local tip {}",
                    block.block_index, tip.block_index
                ));
            }

            if block.previous_hash != tip.hash {
                return Err(format!(
                    "block parent {} does not match local tip hash {} at height {}",
                    block.previous_hash, tip.hash, tip.block_index
                ));
            }
        }

        self.chain.push(block);
        Ok(true)
    }

    pub fn last(&self) -> Option<&Block> {
        self.chain.last()
    }

    pub fn block_at_height(&self, height: u64) -> Option<&Block> {
        self.chain.iter().find(|block| block.block_index == height)
    }

    pub fn truncate_to_height(&mut self, height: u64) {
        if let Some(position) = self
            .chain
            .iter()
            .rposition(|block| block.block_index <= height)
        {
            self.chain.truncate(position + 1);
        } else {
            self.chain.clear();
        }
    }

    pub fn compact_to_recent_blocks(&mut self, retain_recent_blocks: u64) -> usize {
        if retain_recent_blocks == 0 {
            return 0;
        }

        let Some(tip_height) = self.last().map(|block| block.block_index) else {
            return 0;
        };
        if tip_height < retain_recent_blocks {
            return 0;
        }

        let first_retained_height = tip_height
            .saturating_sub(retain_recent_blocks)
            .saturating_add(1);
        let prune_count = self
            .chain
            .iter()
            .take_while(|block| block.block_index < first_retained_height)
            .count();
        if prune_count == 0 {
            return 0;
        }

        self.chain.drain(0..prune_count);
        self.chain.shrink_to_fit();
        prune_count
    }

    pub fn compact_from_env(&mut self) -> Option<(u64, usize)> {
        let retain_recent_blocks = configured_hot_chain_retention_blocks()?;
        let removed = self.compact_to_recent_blocks(retain_recent_blocks);
        Some((retain_recent_blocks, removed))
    }

    pub fn genesis(&mut self) -> Result<(), String> {
        let genesis = canonical_genesis()?;
        let genesis_block = Block {
            block_index: 0,
            timestamp: genesis.timestamp(),
            transactions: Vec::new(),
            previous_hash: genesis
                .value()
                .get("header")
                .and_then(|header| header.get("parent_hash"))
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_string(),
            validator_id: "genesis".to_string(),
            nonce: 0,
            hash: genesis.hash().to_string(),
            transactions_root: compute_merkle_root(&[]),
            proposer_public_key: Vec::new(),
            block_signature: Vec::new(),
            block_signature_algorithm: String::new(),
        };
        self.chain.clear();
        self.chain.push(genesis_block);
        Ok(())
    }

    pub fn get_genesis_hash(&self) -> Option<String> {
        self.chain.first().map(|b| b.hash.clone())
    }

    pub fn ensure_expected_genesis_hash(&self, expected: &str) -> Result<(), String> {
        let actual = self
            .get_genesis_hash()
            .ok_or_else(|| "blockchain has no genesis block".to_string())?;
        if actual != expected {
            return Err(format!(
                "genesis hash mismatch: expected {expected}, found {actual}"
            ));
        }
        Ok(())
    }

    pub fn save_to_file(&self, path: &str) {
        if let Err(error) = self.save_to_file_atomic(path) {
            eprintln!("failed to save blockchain state to {path}: {error}");
        }
    }

    pub fn save_to_file_result(&self, path: &str) -> Result<(), String> {
        self.save_to_file_atomic(path)
    }

    fn save_to_file_atomic(&self, path: &str) -> Result<(), String> {
        let target = Path::new(path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                format!("create chain state directory {}: {error}", parent.display())
            })?;
        }

        let file_name = target
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| format!("invalid chain state path: {}", target.display()))?;
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        let temp_path =
            target.with_file_name(format!("{file_name}.tmp-{}-{suffix}", std::process::id()));

        {
            let file = File::create(&temp_path).map_err(|error| {
                format!("create temp chain state {}: {error}", temp_path.display())
            })?;
            let mut writer = BufWriter::new(file);
            serde_json::to_writer(&mut writer, &self.chain).map_err(|error| {
                format!("write temp chain state {}: {error}", temp_path.display())
            })?;
            writer.flush().map_err(|error| {
                format!("flush temp chain state {}: {error}", temp_path.display())
            })?;
            writer.get_ref().sync_all().map_err(|error| {
                format!("sync temp chain state {}: {error}", temp_path.display())
            })?;
        }

        fs::rename(&temp_path, target).map_err(|error| {
            let _ = fs::remove_file(&temp_path);
            format!(
                "replace chain state {} with {}: {error}",
                target.display(),
                temp_path.display()
            )
        })?;
        Ok(())
    }

    pub fn load_from_file(path: &str) -> Option<Self> {
        if Path::new(path).exists() {
            if let Ok(file) = File::open(path) {
                let reader = BufReader::new(file);
                let mut deserializer = serde_json::Deserializer::from_reader(reader);
                if let Ok(blocks) = Vec::<Block>::deserialize(&mut deserializer) {
                    if deserializer.end().is_ok() {
                        return Some(BlockChain { chain: blocks });
                    }
                }
            }
        }
        None
    }

    pub fn load_last_from_file(path: &str) -> Option<Block> {
        struct LastBlockVisitor;

        impl<'de> Visitor<'de> for LastBlockVisitor {
            type Value = Option<Block>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON array of blocks")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut last = None;
                while let Some(block) = sequence.next_element::<Block>()? {
                    last = Some(block);
                }
                Ok(last)
            }
        }

        let file = File::open(path).ok()?;
        let reader = BufReader::new(file);
        let mut deserializer = serde_json::Deserializer::from_reader(reader);
        let last = deserializer.deserialize_seq(LastBlockVisitor).ok()?;
        deserializer.end().ok()?;
        last
    }
}

pub fn configured_hot_chain_retention_blocks() -> Option<u64> {
    std::env::var(HOT_CHAIN_RETENTION_BLOCKS_ENV)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
}

#[cfg(test)]
mod tests {
    use super::{Block, BlockChain};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn block(height: u64, previous_hash: String, validator: &str) -> Block {
        Block::new_with_timestamp(
            height,
            Vec::new(),
            previous_hash,
            validator.to_string(),
            height,
            100 + height,
        )
    }

    #[test]
    fn add_block_extending_tip_accepts_next_child() {
        let genesis = block(0, "genesis".to_string(), "validator-1");
        let child = block(1, genesis.hash.clone(), "validator-2");
        let mut chain = BlockChain {
            chain: vec![genesis],
        };

        assert_eq!(chain.add_block_extending_tip(child.clone()), Ok(true));
        assert_eq!(
            chain.last().map(|block| block.hash.as_str()),
            Some(child.hash.as_str())
        );
    }

    #[test]
    fn add_block_extending_tip_skips_exact_duplicate_tip() {
        let genesis = block(0, "genesis".to_string(), "validator-1");
        let mut chain = BlockChain {
            chain: vec![genesis.clone()],
        };

        assert_eq!(chain.add_block_extending_tip(genesis), Ok(false));
        assert_eq!(chain.chain.len(), 1);
    }

    #[test]
    fn load_from_file_rejects_stale_bytes_after_valid_chain_array() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = crate::utils::test_temp_root(format!(
            "synergy-chain-load-stale-tail-{}-{nonce}.json",
            std::process::id()
        ));
        let genesis = block(0, "genesis".to_string(), "validator-1");
        let child = block(1, genesis.hash.clone(), "validator-2");
        let mut bytes = serde_json::to_vec(&vec![genesis, child.clone()]).unwrap();
        bytes.extend_from_slice(b"{\"stale_tail\":true}");
        fs::write(&path, bytes).unwrap();

        assert!(BlockChain::load_from_file(path.to_str().unwrap()).is_none());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn load_last_from_file_returns_only_tip() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = crate::utils::test_temp_root(format!(
            "synergy-chain-load-tip-{}-{nonce}.json",
            std::process::id()
        ));
        let genesis = block(0, "genesis".to_string(), "validator-1");
        let child = block(1, genesis.hash.clone(), "validator-2");
        fs::write(
            &path,
            serde_json::to_vec(&vec![genesis, child.clone()]).unwrap(),
        )
        .unwrap();

        assert_eq!(
            BlockChain::load_last_from_file(path.to_str().unwrap()).map(|block| block.hash),
            Some(child.hash)
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn add_block_extending_tip_rejects_same_height_fork() {
        let genesis = block(0, "genesis".to_string(), "validator-1");
        let canonical = block(1, genesis.hash.clone(), "validator-2");
        let fork = block(1, genesis.hash.clone(), "validator-3");
        let mut chain = BlockChain {
            chain: vec![genesis, canonical],
        };

        let error = chain
            .add_block_extending_tip(fork)
            .expect_err("same-height fork rejected");
        assert!(error.contains("does not extend local tip"));
        assert_eq!(chain.chain.len(), 2);
    }

    #[test]
    fn add_block_extending_tip_rejects_wrong_parent() {
        let genesis = block(0, "genesis".to_string(), "validator-1");
        let mut chain = BlockChain {
            chain: vec![genesis],
        };
        let wrong_parent = block(1, "other-parent".to_string(), "validator-2");

        let error = chain
            .add_block_extending_tip(wrong_parent)
            .expect_err("wrong-parent child rejected");
        assert!(error.contains("does not match local tip hash"));
        assert_eq!(chain.chain.len(), 1);
    }

    #[test]
    fn compact_to_recent_blocks_keeps_contiguous_tip_window() {
        let genesis = block(0, "genesis".to_string(), "validator-1");
        let mut chain = BlockChain {
            chain: vec![genesis.clone()],
        };
        let mut previous = genesis;
        for height in 1..=10 {
            let next = block(height, previous.hash.clone(), "validator-1");
            chain.add_block_extending_tip(next.clone()).unwrap();
            previous = next;
        }

        let removed = chain.compact_to_recent_blocks(4);

        assert_eq!(removed, 7);
        assert_eq!(
            chain
                .chain
                .iter()
                .map(|block| block.block_index)
                .collect::<Vec<_>>(),
            vec![7, 8, 9, 10]
        );
        let next = block(11, previous.hash.clone(), "validator-1");
        assert_eq!(chain.add_block_extending_tip(next), Ok(true));
    }
}
