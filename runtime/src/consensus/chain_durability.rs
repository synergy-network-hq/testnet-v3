use crate::block::{Block, BlockChain};
use crate::consensus::legacy_canonical_lock::latest_legacy_canonical_commit_record;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

const COMMITTED_BLOCK_LOG_FILE: &str = "data/committed_blocks.jsonl";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommittedBlockLogEntry {
    pub height: u64,
    pub hash: String,
    pub previous_hash: String,
    pub block: Block,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainBodyCanonicalGap {
    pub reason: String,
    pub chain_tip_height: u64,
    pub chain_tip_hash: String,
    pub canonical_lock_height: u64,
    pub canonical_lock_hash: String,
    pub missing_from_height: u64,
    pub missing_to_height: u64,
}

pub fn committed_block_log_path() -> PathBuf {
    if let Ok(path) = std::env::var("SYNERGY_COMMITTED_BLOCK_LOG_FILE") {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }

    #[cfg(test)]
    {
        if let Some(test_name) = std::thread::current().name() {
            let sanitized = test_name
                .chars()
                .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
                .collect::<String>();
            return std::env::temp_dir().join(format!(
                "synergy-test-committed-blocks-{}-{sanitized}.jsonl",
                std::process::id()
            ));
        }
    }

    crate::utils::resolve_data_path(COMMITTED_BLOCK_LOG_FILE)
}

pub fn append_committed_block_body(block: &Block) -> Result<(), String> {
    append_committed_block_bodies_at(std::slice::from_ref(block), &committed_block_log_path())
}

pub fn append_committed_block_body_at(block: &Block, path: &Path) -> Result<(), String> {
    append_committed_block_bodies_at(std::slice::from_ref(block), path)
}

pub fn append_committed_block_bodies(blocks: &[Block]) -> Result<(), String> {
    append_committed_block_bodies_at(blocks, &committed_block_log_path())
}

pub fn append_committed_block_bodies_at(blocks: &[Block], path: &Path) -> Result<(), String> {
    if blocks.is_empty() {
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create committed block log directory: {error}"))?;
    }

    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path).map_err(|error| {
        format!(
            "failed to open committed block log {}: {error}",
            path.display()
        )
    })?;
    for block in blocks {
        let entry = CommittedBlockLogEntry {
            height: block.block_index,
            hash: block.hash.clone(),
            previous_hash: block.previous_hash.clone(),
            block: block.clone(),
        };
        let serialized = serde_json::to_vec(&entry)
            .map_err(|error| format!("failed to encode committed block log entry: {error}"))?;
        file.write_all(&serialized)
            .map_err(|error| format!("failed to write committed block log entry: {error}"))?;
        file.write_all(b"\n")
            .map_err(|error| format!("failed to write committed block log newline: {error}"))?;
    }
    file.sync_all().map_err(|error| {
        format!(
            "failed to sync committed block log {}: {error}",
            path.display()
        )
    })
}

pub fn recover_chain_from_committed_block_log(chain: &mut BlockChain) -> Result<u64, String> {
    recover_chain_from_committed_block_log_at(chain, &committed_block_log_path())
}

pub fn recover_chain_from_committed_block_log_at(
    chain: &mut BlockChain,
    path: &Path,
) -> Result<u64, String> {
    if !path.exists() {
        return Ok(0);
    }

    let file = fs::File::open(path).map_err(|error| {
        format!(
            "failed to open committed block log {}: {error}",
            path.display()
        )
    })?;
    let mut entries = BTreeMap::<u64, CommittedBlockLogEntry>::new();
    for (line_number, line) in BufReader::new(file).lines().enumerate() {
        let line = line.map_err(|error| {
            format!(
                "failed to read committed block log {} line {}: {error}",
                path.display(),
                line_number + 1
            )
        })?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let entry = match serde_json::from_str::<CommittedBlockLogEntry>(trimmed) {
            Ok(entry) => entry,
            Err(_) => {
                // Older runtimes could leave torn append-log lines after abrupt
                // stops. Valid entries still fail closed on conflicting data.
                continue;
            }
        };
        if entry.height != entry.block.block_index || entry.hash != entry.block.hash {
            return Err(format!(
                "committed block log entry at line {} has inconsistent height/hash",
                line_number + 1
            ));
        }
        entries.entry(entry.height).or_insert(entry);
    }

    let mut recovered = 0;
    for entry in entries.into_values() {
        let Some(tip) = chain.last().cloned() else {
            if entry.height != 0 {
                continue;
            }
            chain.add_block(entry.block);
            recovered += 1;
            continue;
        };

        if entry.height <= tip.block_index {
            if entry.height == tip.block_index && entry.hash != tip.hash {
                return Err(format!(
                    "committed block log conflicts with persisted chain at height {}: chain_hash={} log_hash={}",
                    entry.height, tip.hash, entry.hash
                ));
            }
            continue;
        }

        if entry.height != tip.block_index.saturating_add(1) {
            break;
        }
        if entry.previous_hash != tip.hash || entry.block.previous_hash != tip.hash {
            return Err(format!(
                "committed block log entry at height {} does not extend persisted tip {}:{}",
                entry.height, tip.block_index, tip.hash
            ));
        }
        chain.add_block_extending_tip(entry.block)?;
        recovered += 1;
    }

    Ok(recovered)
}

pub fn recover_chain_and_validate_canonical(
    chain: &mut BlockChain,
    chain_path: &Path,
) -> Result<u64, String> {
    let recovered = recover_chain_from_committed_block_log(chain)?;
    if recovered > 0 {
        chain.save_to_file_result(
            chain_path
                .to_str()
                .ok_or_else(|| format!("invalid chain path {}", chain_path.display()))?,
        )?;
    }
    validate_chain_body_covers_canonical_lock(chain)?;
    Ok(recovered)
}

pub fn validate_chain_body_covers_canonical_lock(chain: &BlockChain) -> Result<(), String> {
    let Some(canonical) = latest_legacy_canonical_commit_record()? else {
        return Ok(());
    };
    let Some(tip) = chain.last() else {
        return Err(format!(
            "CHAIN_BODY_BEHIND_CANONICAL_LOCK: empty chain body while canonical lock is at h{} {}",
            canonical.height, canonical.block_hash
        ));
    };

    if canonical.height > tip.block_index {
        let gap = ChainBodyCanonicalGap {
            reason: "CHAIN_BODY_BEHIND_CANONICAL_LOCK".to_string(),
            chain_tip_height: tip.block_index,
            chain_tip_hash: tip.hash.clone(),
            canonical_lock_height: canonical.height,
            canonical_lock_hash: canonical.block_hash,
            missing_from_height: tip.block_index.saturating_add(1),
            missing_to_height: canonical.height,
        };
        let encoded = serde_json::to_string(&gap)
            .unwrap_or_else(|_| "CHAIN_BODY_BEHIND_CANONICAL_LOCK".to_string());
        return Err(encoded);
    }

    if let Some(block) = chain.block_at_height(canonical.height) {
        if block.hash != canonical.block_hash {
            return Err(format!(
                "CHAIN_BODY_CANONICAL_LOCK_HASH_MISMATCH: chain h{} hash {} does not match canonical lock {}",
                canonical.height, block.hash, canonical.block_hash
            ));
        }
    } else {
        return Err(format!(
            "CHAIN_BODY_MISSING_CANONICAL_LOCK_HEIGHT: chain is missing h{} required by canonical lock {}",
            canonical.height, canonical.block_hash
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::Block;
    use crate::consensus::dual_quorum::QuorumCertificate;
    use crate::consensus::legacy_canonical_lock::write_legacy_canonical_lock;
    use std::fs;

    fn block(height: u64, previous_hash: String) -> Block {
        Block::new_with_timestamp(
            height,
            Vec::new(),
            previous_hash,
            "validator-1".to_string(),
            height,
            100 + height,
        )
    }

    fn qc(hash: &str) -> QuorumCertificate {
        QuorumCertificate {
            block_hash: hash.to_string(),
            cluster_id: None,
            epoch_number: 1,
            round_number: 1,
            aggregate_signature: Vec::new(),
            participant_bitmap: Vec::new(),
            cumulative_weight: 4.0,
            validation_quorum_met: true,
            cooperation_quorum_met: true,
            timestamp: 1,
            votes: Vec::new(),
        }
    }

    #[test]
    fn committed_block_log_replays_chain_body_after_stale_snapshot() {
        let root = std::env::temp_dir().join(format!(
            "synergy-chain-durability-replay-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let log_path = root.join("committed_blocks.jsonl");

        let genesis = block(0, "genesis".to_string());
        let one = block(1, genesis.hash.clone());
        let two = block(2, one.hash.clone());
        append_committed_block_body_at(&one, &log_path).unwrap();
        append_committed_block_body_at(&two, &log_path).unwrap();

        let mut chain = BlockChain {
            chain: vec![genesis],
        };
        let recovered = recover_chain_from_committed_block_log_at(&mut chain, &log_path).unwrap();
        assert_eq!(recovered, 2);
        assert_eq!(chain.last().map(|block| block.block_index), Some(2));
        assert_eq!(chain.last().map(|block| block.hash.clone()), Some(two.hash));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn committed_block_log_recovery_skips_malformed_lines() {
        let root = std::env::temp_dir().join(format!(
            "synergy-chain-durability-malformed-log-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let log_path = root.join("committed_blocks.jsonl");

        let genesis = block(0, "genesis".to_string());
        let one = block(1, genesis.hash.clone());
        fs::write(
            &log_path,
            format!(
                "{{\"height\":1,\"hash\"\n{}\n",
                serde_json::to_string(&CommittedBlockLogEntry {
                    height: one.block_index,
                    hash: one.hash.clone(),
                    previous_hash: one.previous_hash.clone(),
                    block: one.clone(),
                })
                .unwrap()
            ),
        )
        .unwrap();

        let mut chain = BlockChain {
            chain: vec![genesis],
        };
        let recovered = recover_chain_from_committed_block_log_at(&mut chain, &log_path).unwrap();
        assert_eq!(recovered, 1);
        assert_eq!(chain.last().map(|block| block.block_index), Some(1));
        assert_eq!(chain.last().map(|block| block.hash.clone()), Some(one.hash));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn startup_validation_rejects_canonical_lock_ahead_of_chain_body() {
        let root = std::env::temp_dir().join(format!(
            "synergy-chain-durability-gap-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let canonical_path = root.join("canonical-locks.json");
        std::env::set_var("SYNERGY_CANONICAL_LOCK_FILE", &canonical_path);

        let genesis = block(0, "genesis".to_string());
        let one = block(1, genesis.hash.clone());
        write_legacy_canonical_lock(&one, &qc(&one.hash)).unwrap();

        let chain = BlockChain {
            chain: vec![genesis],
        };
        let error = validate_chain_body_covers_canonical_lock(&chain).unwrap_err();
        assert!(error.contains("CHAIN_BODY_BEHIND_CANONICAL_LOCK"));
        assert!(error.contains("\"missing_from_height\":1"));

        std::env::remove_var("SYNERGY_CANONICAL_LOCK_FILE");
        let _ = fs::remove_dir_all(&root);
    }
}
