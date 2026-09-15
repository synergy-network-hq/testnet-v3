use crate::block::Block;
use crate::consensus::dual_quorum::QuorumCertificate;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Cursor, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyCanonicalCommitRecord {
    pub height: u64,
    pub block_hash: String,
    pub parent_hash: String,
    pub validator_id: String,
    pub transactions_root: String,
    pub qc_block_hash: String,
    pub qc_hash: String,
    pub written_at_unix_secs: u64,
}

pub fn verify_legacy_canonical_lock(block: &Block) -> Result<(), String> {
    verify_legacy_canonical_locks(std::slice::from_ref(&block))
}

pub fn verify_legacy_canonical_locks(blocks: &[&Block]) -> Result<(), String> {
    if blocks.is_empty() {
        return Ok(());
    }

    let locks = load_legacy_canonical_locks()?;
    for block in blocks {
        let Some(existing) = locks.get(&block.block_index) else {
            continue;
        };
        if existing.block_hash != block.hash {
            return Err(format!(
                "canonical lock at height {} already binds block {}; refusing conflicting block {}",
                block.block_index, existing.block_hash, block.hash
            ));
        }
    }
    Ok(())
}

pub fn write_legacy_canonical_lock(block: &Block, qc: &QuorumCertificate) -> Result<(), String> {
    write_legacy_canonical_locks(&[(block, qc)])
}

pub fn write_legacy_canonical_locks(
    entries: &[(&Block, &QuorumCertificate)],
) -> Result<(), String> {
    if entries.is_empty() {
        return Ok(());
    }

    let mut locks = load_legacy_canonical_locks()?;
    let mut changed = false;
    for (block, qc) in entries {
        if qc.block_hash != block.hash {
            return Err("cannot write canonical lock with QC for a different block".to_string());
        }

        if let Some(existing) = locks.get(&block.block_index) {
            if existing.block_hash == block.hash {
                continue;
            }
            return Err(format!(
                "canonical lock at height {} already binds block {}; refusing conflicting block {}",
                block.block_index, existing.block_hash, block.hash
            ));
        }

        locks.insert(
            block.block_index,
            LegacyCanonicalCommitRecord {
                height: block.block_index,
                block_hash: block.hash.clone(),
                parent_hash: block.previous_hash.clone(),
                validator_id: block.validator_id.clone(),
                transactions_root: block.transactions_root.clone(),
                qc_block_hash: qc.block_hash.clone(),
                qc_hash: legacy_qc_hash(qc)?,
                written_at_unix_secs: current_unix_secs(),
            },
        );
        changed = true;
    }

    if !changed {
        return Ok(());
    }
    prune_canonical_locks_for_hot_path(&mut locks);
    persist_legacy_canonical_locks(&locks)
}

pub fn legacy_canonical_commit_record(
    height: u64,
) -> Result<Option<LegacyCanonicalCommitRecord>, String> {
    Ok(load_legacy_canonical_locks()?.get(&height).cloned())
}

pub fn latest_legacy_canonical_commit_record() -> Result<Option<LegacyCanonicalCommitRecord>, String>
{
    Ok(load_legacy_canonical_locks()?
        .iter()
        .next_back()
        .map(|(_, record)| record.clone()))
}

/// Remove only the untrusted lock suffix after a verified source-majority
/// branch has identified a common ancestor. The caller must establish the
/// durable recovery duty fence before allowing consensus duties to resume.
pub fn quarantine_legacy_canonical_locks_above(
    common_height: u64,
) -> Result<Vec<LegacyCanonicalCommitRecord>, String> {
    let mut locks = load_legacy_canonical_locks()?;
    let quarantined = locks
        .range((common_height.saturating_add(1))..)
        .map(|(_, record)| record.clone())
        .collect::<Vec<_>>();
    if quarantined.is_empty() {
        return Ok(quarantined);
    }

    locks.retain(|height, _| *height <= common_height);
    persist_legacy_canonical_locks(&locks)?;
    Ok(quarantined)
}

fn load_legacy_canonical_locks() -> Result<BTreeMap<u64, LegacyCanonicalCommitRecord>, String> {
    let path = legacy_canonical_lock_path();
    if !path.exists() {
        return Ok(BTreeMap::new());
    }

    let bytes = fs::read(&path)
        .map_err(|error| format!("failed to read canonical lock store {:?}: {error}", path))?;
    if bytes.is_empty() {
        return Ok(BTreeMap::new());
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("failed to parse canonical lock store {:?}: {error}", path))
}

fn persist_legacy_canonical_locks(
    locks: &BTreeMap<u64, LegacyCanonicalCommitRecord>,
) -> Result<(), String> {
    let path = legacy_canonical_lock_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create canonical lock directory: {error}"))?;
    }

    let tmp_path = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(locks)
        .map_err(|error| format!("failed to encode canonical locks: {error}"))?;
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(&tmp_path)
        .map_err(|error| format!("failed to open canonical lock temp file: {error}"))?;
    file.write_all(&bytes)
        .map_err(|error| format!("failed to write canonical lock temp file: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("failed to sync canonical lock temp file: {error}"))?;
    drop(file);
    fs::rename(&tmp_path, &path)
        .map_err(|error| format!("failed to replace canonical lock store: {error}"))
}

fn prune_canonical_locks_for_hot_path(locks: &mut BTreeMap<u64, LegacyCanonicalCommitRecord>) {
    let Some(retain) = canonical_lock_retain_entries() else {
        return;
    };
    let protected_height = compact_chain_boundary_height();
    prune_canonical_locks_for_hot_path_with_protected_height(locks, retain, protected_height);
}

fn prune_canonical_locks_for_hot_path_with_protected_height(
    locks: &mut BTreeMap<u64, LegacyCanonicalCommitRecord>,
    retain: usize,
    protected_height: Option<u64>,
) {
    while locks.len() > retain {
        let Some(height) = locks
            .keys()
            .copied()
            .find(|height| Some(*height) != protected_height)
        else {
            break;
        };
        locks.remove(&height);
    }
}

fn compact_chain_boundary_height() -> Option<u64> {
    let path = crate::utils::resolve_data_path("data/chain.json");
    compact_chain_boundary_height_from_path(&path)
}

fn compact_chain_boundary_height_from_path(path: &Path) -> Option<u64> {
    let file = File::open(path).ok()?;
    let mut reader = BufReader::new(file);
    if next_non_whitespace_byte(&mut reader)? != b'[' {
        return None;
    }
    let first_value_start = next_non_whitespace_byte(&mut reader)?;
    if first_value_start == b']' {
        return None;
    }
    let first_value_reader = Cursor::new(vec![first_value_start]).chain(reader);
    let block = serde_json::Deserializer::from_reader(first_value_reader)
        .into_iter::<Block>()
        .next()?
        .ok()?;
    (block.block_index > 0).then_some(block.block_index)
}

fn next_non_whitespace_byte<R: BufRead>(reader: &mut R) -> Option<u8> {
    loop {
        let buf = reader.fill_buf().ok()?;
        if buf.is_empty() {
            return None;
        }
        if let Some(index) = buf.iter().position(|byte| !byte.is_ascii_whitespace()) {
            let byte = buf[index];
            reader.consume(index + 1);
            return Some(byte);
        }
        let len = buf.len();
        reader.consume(len);
    }
}

fn canonical_lock_retain_entries() -> Option<usize> {
    std::env::var("SYNERGY_CANONICAL_LOCK_RETAIN_ENTRIES")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
}

fn legacy_qc_hash(qc: &QuorumCertificate) -> Result<String, String> {
    let bytes = serde_json::to_vec(qc).map_err(|error| format!("failed to encode QC: {error}"))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

fn legacy_canonical_lock_path() -> PathBuf {
    if let Ok(path) = std::env::var("SYNERGY_CANONICAL_LOCK_FILE") {
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
            return crate::utils::test_temp_root(format!(
                "synergy-test-canonical-locks-{}-{sanitized}.json",
                std::process::id()
            ));
        }
        return crate::utils::test_temp_root(format!(
            "synergy-test-canonical-locks-{}.json",
            std::process::id()
        ));
    }

    #[cfg(not(test))]
    {
        crate::utils::resolve_data_path("data/canonical_locks.json")
    }
}

fn current_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
pub(crate) fn clear_legacy_canonical_locks_for_tests() {
    let path = legacy_canonical_lock_path();
    let _ = fs::remove_file(path.with_extension("json.tmp"));
    let _ = fs::remove_file(path);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(height: u64, hash_suffix: &str) -> Block {
        let mut block = Block::new_with_timestamp(
            height,
            Vec::new(),
            "parent".to_string(),
            "validator".to_string(),
            height,
            1_700_000_000 + height,
        );
        block.hash = format!("block-{height}-{hash_suffix}");
        block.transactions_root = "root".to_string();
        block
    }

    fn qc(block_hash: &str) -> QuorumCertificate {
        QuorumCertificate {
            block_hash: block_hash.to_string(),
            cluster_id: None,
            epoch_number: 0,
            round_number: 1,
            aggregate_signature: vec![1],
            participant_bitmap: vec![1],
            cumulative_weight: 4.0,
            validation_quorum_met: true,
            cooperation_quorum_met: true,
            timestamp: 1,
            votes: Vec::new(),
        }
    }

    fn canonical_record(height: u64) -> LegacyCanonicalCommitRecord {
        LegacyCanonicalCommitRecord {
            height,
            block_hash: format!("block-{height}"),
            parent_hash: format!("parent-{height}"),
            validator_id: "validator".to_string(),
            transactions_root: "root".to_string(),
            qc_block_hash: format!("block-{height}"),
            qc_hash: format!("qc-{height}"),
            written_at_unix_secs: height,
        }
    }

    #[test]
    fn canonical_lock_rejects_conflicting_same_height_block() {
        clear_legacy_canonical_locks_for_tests();
        let block_a = block(7, "a");
        let block_b = block(7, "b");
        write_legacy_canonical_lock(&block_a, &qc(&block_a.hash)).unwrap();

        verify_legacy_canonical_lock(&block_a).unwrap();
        assert!(verify_legacy_canonical_lock(&block_b)
            .unwrap_err()
            .contains("already binds block"));
    }

    #[test]
    fn canonical_lock_prune_preserves_compact_chain_boundary_height() {
        let mut locks = BTreeMap::new();
        locks.insert(175_518, canonical_record(175_518));
        locks.insert(200_001, canonical_record(200_001));
        locks.insert(200_002, canonical_record(200_002));

        prune_canonical_locks_for_hot_path_with_protected_height(&mut locks, 2, Some(175_518));

        assert!(locks.contains_key(&175_518));
        assert!(!locks.contains_key(&200_001));
        assert!(locks.contains_key(&200_002));
    }

    #[test]
    fn compact_chain_boundary_height_reads_first_pruned_block() {
        let path = crate::utils::test_temp_root(format!(
            "synergy-test-chain-boundary-{}-{}.json",
            std::process::id(),
            current_unix_secs()
        ));
        fs::write(
            &path,
            serde_json::to_vec(&vec![block(42, "a"), block(43, "b")]).unwrap(),
        )
        .unwrap();

        assert_eq!(compact_chain_boundary_height_from_path(&path), Some(42));

        let _ = fs::remove_file(path);
    }
}
