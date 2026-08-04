//! Track A durability tests for `SingleAuthorityFinalityStore`.
//!
//! Every test uses a real temporary directory and reopens the store from disk
//! so recovery is exercised against actual filesystem state, not in-memory
//! objects. No `Vote`, `QuorumCertificate`, or quorum type is constructed
//! anywhere in this module - that is asserted structurally by this file
//! importing none of them.

use super::single_authority_finality_store::*;
use crate::synergy_types::Hash;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

const TEST_CHAIN_ID: u64 = 1266;
const TEST_INCARNATION: u64 = 5;
const TEST_AUTHORITY: &str = "authority-node-01";
const TEST_FINGERPRINT: &str = "sha256:testauthorityfingerprint";

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "sa-finality-{tag}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&path).expect("create temp dir");
        Self(path)
    }
    fn log(&self) -> PathBuf {
        self.0.join("finality.log")
    }
    fn head(&self) -> PathBuf {
        self.0.join("finality.head.json")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn binding() -> SingleAuthorityChainBinding {
    SingleAuthorityChainBinding {
        chain_id: TEST_CHAIN_ID,
        chain_incarnation: TEST_INCARNATION,
        authority_id: TEST_AUTHORITY.to_string(),
        authority_public_key_fingerprint: TEST_FINGERPRINT.to_string(),
    }
}

/// Reopens the store from disk - all recovery assertions go through this.
fn open_store(dir: &TempDir) -> SingleAuthorityFinalityStore {
    SingleAuthorityFinalityStore::at_paths(dir.log(), dir.head(), binding()).expect("open store")
}

fn hash_of(seed: u8) -> Hash {
    Hash([seed; 32])
}

fn record_at(height: u64, parent: Hash, block: Hash) -> SingleAuthorityFinalityRecord {
    SingleAuthorityFinalityRecord {
        schema_version: SINGLE_AUTHORITY_FINALITY_SCHEMA_VERSION,
        chain_id: TEST_CHAIN_ID,
        chain_incarnation: TEST_INCARNATION,
        consensus_protocol: SINGLE_AUTHORITY_CONSENSUS_PROTOCOL.to_string(),
        release_id: "chain1266-single-authority-rc1".to_string(),
        height,
        block_hash: block,
        parent_hash: parent,
        state_root: hash_of(100u8.wrapping_add(height as u8)),
        transaction_root: hash_of(150u8.wrapping_add(height as u8)),
        receipt_root: hash_of(200u8.wrapping_add(height as u8)),
        authority_id: TEST_AUTHORITY.to_string(),
        authority_public_key_fingerprint: TEST_FINGERPRINT.to_string(),
        authority_signature_base64: "dGVzdC1zaWduYXR1cmU=".to_string(),
        finalized_timestamp_ms: 1_700_000_000_000 + height * 2_000,
    }
}

/// Appends a chain 0..=n and commits the head after each, like the driver does.
fn seed_chain(store: &SingleAuthorityFinalityStore, count: u64) -> Vec<SingleAuthorityFinalityRecord> {
    let mut out = Vec::new();
    let mut parent = Hash::zero();
    for height in 0..count {
        let block = hash_of(1u8.wrapping_add(height as u8));
        let record = record_at(height, parent, block);
        let end = store.append_finalized(&record).expect("append");
        store.commit_head(&record, end).expect("commit head");
        parent = block;
        out.push(record);
    }
    out
}

#[test]
fn t01_first_record_appends_and_recovers() {
    let dir = TempDir::new("t01");
    let store = open_store(&dir);
    let record = record_at(0, Hash::zero(), hash_of(1));
    let end = store.append_finalized(&record).expect("append");
    store.commit_head(&record, end).expect("head");

    let reopened = open_store(&dir);
    let recovery = reopened.recover().expect("recover");
    assert_eq!(recovery.records.len(), 1);
    assert_eq!(recovery.records[0], record);
    assert_eq!(recovery.next_height(), 1);
    assert!(!recovery.truncated_trailing_frame);
}

#[test]
fn t02_consecutive_records_recover_in_order() {
    let dir = TempDir::new("t02");
    let store = open_store(&dir);
    let seeded = seed_chain(&store, 5);

    let recovery = open_store(&dir).recover().expect("recover");
    assert_eq!(recovery.records, seeded);
    assert_eq!(recovery.next_height(), 5);
}

#[test]
fn t03_exact_duplicate_append_is_idempotent() {
    let dir = TempDir::new("t03");
    let store = open_store(&dir);
    let record = record_at(0, Hash::zero(), hash_of(1));
    let first = store.append_finalized(&record).expect("append");
    let size_after_first = fs::metadata(dir.log()).unwrap().len();

    let second = store.append_finalized(&record).expect("idempotent replay");
    assert_eq!(first, second);
    assert_eq!(fs::metadata(dir.log()).unwrap().len(), size_after_first);
    assert_eq!(open_store(&dir).recover().unwrap().records.len(), 1);
}

#[test]
fn t04_conflicting_duplicate_height_fails() {
    let dir = TempDir::new("t04");
    let store = open_store(&dir);
    let record = record_at(0, Hash::zero(), hash_of(1));
    store.append_finalized(&record).expect("append");

    let conflicting = record_at(0, Hash::zero(), hash_of(9));
    let error = store.append_finalized(&conflicting).unwrap_err();
    assert!(error.contains("already finalized with a different block"), "{error}");
}

#[test]
fn t05_height_gap_fails() {
    let dir = TempDir::new("t05");
    let store = open_store(&dir);
    seed_chain(&store, 1);
    let gapped = record_at(2, hash_of(1), hash_of(3));
    let error = store.append_finalized(&gapped).unwrap_err();
    assert!(error.contains("does not follow"), "{error}");
}

#[test]
fn t06_parent_mismatch_fails() {
    let dir = TempDir::new("t06");
    let store = open_store(&dir);
    seed_chain(&store, 1);
    let bad_parent = record_at(1, hash_of(77), hash_of(2));
    let error = store.append_finalized(&bad_parent).unwrap_err();
    assert!(error.contains("broken parent link"), "{error}");
}

#[test]
fn t07_wrong_chain_id_fails() {
    let dir = TempDir::new("t07");
    let store = open_store(&dir);
    let mut record = record_at(0, Hash::zero(), hash_of(1));
    record.chain_id = 1264;
    let error = store.append_finalized(&record).unwrap_err();
    assert!(error.contains("chain id"), "{error}");
}

#[test]
fn t08_wrong_incarnation_fails() {
    let dir = TempDir::new("t08");
    let store = open_store(&dir);
    let mut record = record_at(0, Hash::zero(), hash_of(1));
    record.chain_incarnation = 4;
    let error = store.append_finalized(&record).unwrap_err();
    assert!(error.contains("incarnation"), "{error}");
}

#[test]
fn t09_wrong_consensus_protocol_fails() {
    let dir = TempDir::new("t09");
    let store = open_store(&dir);
    let mut record = record_at(0, Hash::zero(), hash_of(1));
    record.consensus_protocol = "coordinated_round_robin_v1".to_string();
    let error = store.append_finalized(&record).unwrap_err();
    assert!(error.contains("consensus protocol"), "{error}");
}

#[test]
fn t10_wrong_authority_id_fails() {
    let dir = TempDir::new("t10");
    let store = open_store(&dir);
    let mut record = record_at(0, Hash::zero(), hash_of(1));
    record.authority_id = "validator-node-03".to_string();
    let error = store.append_finalized(&record).unwrap_err();
    assert!(error.contains("foreign authority id"), "{error}");
}

#[test]
fn t11_wrong_authority_fingerprint_fails() {
    let dir = TempDir::new("t11");
    let store = open_store(&dir);
    let mut record = record_at(0, Hash::zero(), hash_of(1));
    record.authority_public_key_fingerprint = "sha256:someoneelse".to_string();
    let error = store.append_finalized(&record).unwrap_err();
    assert!(error.contains("foreign authority key fingerprint"), "{error}");
}

#[test]
fn t13_zero_block_hash_fails() {
    let dir = TempDir::new("t13");
    let store = open_store(&dir);
    let record = record_at(0, Hash::zero(), Hash::zero());
    let error = store.append_finalized(&record).unwrap_err();
    assert!(error.contains("zero block hash"), "{error}");
}

#[test]
fn t14_missing_signature_fails() {
    let dir = TempDir::new("t14");
    let store = open_store(&dir);
    let mut record = record_at(0, Hash::zero(), hash_of(1));
    record.authority_signature_base64.clear();
    let error = store.append_finalized(&record).unwrap_err();
    assert!(error.contains("unsigned"), "{error}");
}

#[test]
fn t28_no_quorum_types_are_reachable_from_this_store() {
    // Structural assertion: the record type carries no certificate/vote field.
    // If a QC were reintroduced this would fail to compile with a missing field.
    let record = record_at(0, Hash::zero(), hash_of(1));
    let encoded = serde_json::to_string(&record).expect("encode");
    assert!(!encoded.contains("quorum"), "{encoded}");
    assert!(!encoded.contains("certificate"), "{encoded}");
    assert!(!encoded.contains("vote"), "{encoded}");
}

/// Appends raw bytes past the end of a healthy, head-committed log.
fn append_raw(dir: &TempDir, bytes: &[u8]) {
    let mut file = OpenOptions::new().append(true).open(dir.log()).expect("open log");
    file.write_all(bytes).expect("write raw");
    file.sync_all().expect("sync");
}

#[test]
fn t15_short_frame_prefix_after_head_is_recoverable() {
    let dir = TempDir::new("t15");
    let store = open_store(&dir);
    let seeded = seed_chain(&store, 2);
    let committed_len = fs::metadata(dir.log()).unwrap().len();

    append_raw(&dir, b"S1FR\x00\x00");

    let recovery = open_store(&dir).recover().expect("torn prefix is recoverable");
    assert_eq!(recovery.records, seeded);
    assert!(recovery.truncated_trailing_frame);
    assert_eq!(recovery.durable_end_offset, committed_len);
}

#[test]
fn t16_short_payload_after_head_is_recoverable() {
    let dir = TempDir::new("t16");
    let store = open_store(&dir);
    let seeded = seed_chain(&store, 2);

    // valid prefix claiming 4096 payload bytes, but only 10 supplied
    let mut torn = Vec::new();
    torn.extend_from_slice(b"S1FR");
    torn.extend_from_slice(&1u32.to_be_bytes());
    torn.extend_from_slice(&4096u64.to_be_bytes());
    torn.extend_from_slice(&[0u8; 10]);
    append_raw(&dir, &torn);

    let recovery = open_store(&dir).recover().expect("torn payload is recoverable");
    assert_eq!(recovery.records, seeded);
    assert!(recovery.truncated_trailing_frame);
}

#[test]
fn t17_short_checksum_after_head_is_recoverable() {
    let dir = TempDir::new("t17");
    let store = open_store(&dir);
    let seeded = seed_chain(&store, 2);

    // complete payload, checksum cut short (only 8 of 32 bytes)
    let payload = b"{}";
    let mut torn = Vec::new();
    torn.extend_from_slice(b"S1FR");
    torn.extend_from_slice(&1u32.to_be_bytes());
    torn.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    torn.extend_from_slice(payload);
    torn.extend_from_slice(&[0u8; 8]);
    append_raw(&dir, &torn);

    let recovery = open_store(&dir).recover().expect("torn checksum is recoverable");
    assert_eq!(recovery.records, seeded);
    assert!(recovery.truncated_trailing_frame);
}

#[test]
fn t18_short_frame_referenced_by_durable_head_fails_closed() {
    let dir = TempDir::new("t18");
    let store = open_store(&dir);
    seed_chain(&store, 2);
    let committed_len = fs::metadata(dir.log()).unwrap().len();

    // Truncate INTO the last committed frame, so the head still commits to
    // bytes that no longer exist. This must never be silently accepted.
    let file = OpenOptions::new().write(true).open(dir.log()).unwrap();
    file.set_len(committed_len - 20).unwrap();
    file.sync_all().unwrap();

    let error = open_store(&dir).recover().unwrap_err();
    assert!(
        error.contains("truncated inside committed history"),
        "{error}"
    );
}

#[test]
fn t19_complete_frame_with_bad_checksum_fails_closed() {
    let dir = TempDir::new("t19");
    let store = open_store(&dir);
    seed_chain(&store, 2);

    // Corrupt the final byte of the last committed frame's checksum.
    let mut bytes = fs::read(dir.log()).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    fs::write(dir.log(), &bytes).unwrap();

    let error = open_store(&dir).recover().unwrap_err();
    assert!(error.contains("checksum mismatch"), "{error}");
}

#[test]
fn t20_bad_checksum_in_middle_of_log_fails_closed() {
    let dir = TempDir::new("t20");
    let store = open_store(&dir);
    seed_chain(&store, 4);

    // Corrupt a payload byte early in the log - interior corruption.
    let mut bytes = fs::read(dir.log()).unwrap();
    bytes[40] ^= 0xFF;
    fs::write(dir.log(), &bytes).unwrap();

    let error = open_store(&dir).recover().unwrap_err();
    assert!(
        error.contains("checksum mismatch") || error.contains("decode"),
        "{error}"
    );
}

#[test]
fn t21_malformed_frame_followed_by_more_bytes_fails_closed() {
    let dir = TempDir::new("t21");
    let store = open_store(&dir);
    seed_chain(&store, 2);

    // Garbage that is long enough to parse a prefix but has bad magic,
    // followed by further bytes - unambiguously interior corruption.
    append_raw(&dir, &[0xAAu8; 128]);

    let error = open_store(&dir).recover().unwrap_err();
    assert!(error.contains("magic mismatch"), "{error}");
}

#[test]
fn t22_log_durable_but_head_stale_rolls_forward() {
    let dir = TempDir::new("t22");
    let store = open_store(&dir);
    seed_chain(&store, 2);

    // Simulate a crash between log fsync and head commit: append height 2
    // durably, but never advance the head.
    let record = record_at(2, hash_of(2), hash_of(3));
    store.append_finalized(&record).expect("append h2");

    let startup = open_store(&dir)
        .recover_startup_state()
        .expect("stale head rolls forward");
    assert!(startup.head_advanced_during_recovery);
    assert_eq!(startup.next_height, 3);
    assert_eq!(startup.finalized.as_ref().unwrap().height, 2);

    let head = open_store(&dir).load_head().unwrap().expect("head present");
    assert_eq!(head.height, 2);
    assert_eq!(head.block_hash, hash_of(3));
}

#[test]
fn t23_head_ahead_of_durable_log_fails_closed() {
    let dir = TempDir::new("t23");
    let store = open_store(&dir);
    seed_chain(&store, 2);

    // Forge a head claiming a height the log never durably reached.
    let phantom = record_at(7, hash_of(6), hash_of(7));
    store.commit_head(&phantom, 999_999).expect("write forged head");

    let error = open_store(&dir).recover_startup_state().unwrap_err();
    assert!(error.contains("exceeds durable finality height"), "{error}");
}

#[test]
fn t24_head_and_log_disagree_at_same_height_fails_closed() {
    let dir = TempDir::new("t24");
    let store = open_store(&dir);
    seed_chain(&store, 2);
    let end = fs::metadata(dir.log()).unwrap().len();

    let impostor = record_at(1, hash_of(1), hash_of(200));
    store.commit_head(&impostor, end).expect("write divergent head");

    let error = open_store(&dir).recover_startup_state().unwrap_err();
    assert!(error.contains("head hash disagrees"), "{error}");
}

#[test]
fn t25_head_with_empty_log_fails_closed() {
    let dir = TempDir::new("t25");
    let store = open_store(&dir);
    let orphan = record_at(0, Hash::zero(), hash_of(1));
    store.commit_head(&orphan, 128).expect("write orphan head");

    let error = open_store(&dir).recover_startup_state().unwrap_err();
    assert!(error.contains("finality log is empty"), "{error}");
}

#[test]
fn t26_multiple_valid_records_after_stale_head_are_deterministic() {
    let dir = TempDir::new("t26");
    let store = open_store(&dir);
    seed_chain(&store, 1);

    // Three further durable appends with no head advance at all.
    let mut parent = hash_of(1);
    for height in 1..4u64 {
        let block = hash_of(1u8.wrapping_add(height as u8));
        let record = record_at(height, parent, block);
        store.append_finalized(&record).expect("append");
        parent = block;
    }

    let first = open_store(&dir).recover_startup_state().expect("recover once");
    assert_eq!(first.next_height, 4);
    assert!(first.head_advanced_during_recovery);

    // Second recovery must be stable and must not advance again.
    let second = open_store(&dir).recover_startup_state().expect("recover twice");
    assert_eq!(second.next_height, 4);
    assert!(!second.head_advanced_during_recovery);
    assert_eq!(first.finalized, second.finalized);
}

#[test]
fn t27_recovery_never_truncates_committed_history() {
    let dir = TempDir::new("t27");
    let store = open_store(&dir);
    seed_chain(&store, 3);
    let committed_len = fs::metadata(dir.log()).unwrap().len();

    append_raw(&dir, b"S1FR\x00\x00\x00");
    let _ = open_store(&dir).recover().expect("torn tail tolerated");
    // Recovery itself must not modify the file at all.
    assert_eq!(
        fs::metadata(dir.log()).unwrap().len(),
        committed_len + 7,
        "recover() must be read-only"
    );

    // Only a subsequent append may truncate the uncommitted tail.
    let next = record_at(3, hash_of(3), hash_of(4));
    let store = open_store(&dir);
    let end = store.append_finalized(&next).expect("append after torn tail");
    store.commit_head(&next, end).expect("head");

    let recovery = open_store(&dir).recover().expect("recover");
    assert_eq!(recovery.records.len(), 4);
    assert_eq!(recovery.records[3], next);
}
