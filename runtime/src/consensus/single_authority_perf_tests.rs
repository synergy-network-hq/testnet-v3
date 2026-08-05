//! Single-writer lock, cache-correctness, and O(1) steady-state proofs.

use super::single_authority_finality_store::*;
use super::single_authority_signing_journal::*;
use super::single_authority_writable_store::WritableSingleAuthorityStore;
use crate::synergy_types::Hash;
use std::fs;
use std::path::PathBuf;

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "sa-perf-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&path).expect("temp dir");
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
        first_authority_height: 0,
        chain_id: 1266,
        chain_incarnation: 5,
        authority_id: "authority-node-01".to_string(),
        authority_public_key_fingerprint: "sha256:authority".to_string(),
    }
}

fn store(dir: &TempDir) -> SingleAuthorityFinalityStore {
    SingleAuthorityFinalityStore::at_paths(dir.log(), dir.head(), binding()).expect("store")
}

fn hash_of(seed: u64) -> Hash {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&(seed + 1).to_be_bytes());
    Hash(bytes)
}

fn record_at(height: u64) -> SingleAuthorityFinalityRecord {
    SingleAuthorityFinalityRecord {
        schema_version: SINGLE_AUTHORITY_FINALITY_SCHEMA_VERSION,
        chain_id: 1266,
        chain_incarnation: 5,
        consensus_protocol: SINGLE_AUTHORITY_CONSENSUS_PROTOCOL.to_string(),
        release_id: "chain1266-single-authority-rc1".to_string(),
        height,
        block_hash: hash_of(height),
        parent_hash: if height == 0 { Hash::zero() } else { hash_of(height - 1) },
        state_root: hash_of(height + 1_000_000),
        transaction_root: hash_of(height + 2_000_000),
        receipt_root: hash_of(height + 3_000_000),
        authority_id: "authority-node-01".to_string(),
        authority_public_key_fingerprint: "sha256:authority".to_string(),
        authority_signature_base64: "dGVzdA==".to_string(),
        finalized_timestamp_ms: 1_700_000_000_000 + height * 2_000,
    }
}

#[test]
fn p01_second_writable_finality_store_is_rejected() {
    let dir = TempDir::new("p01");
    let _first = WritableSingleAuthorityStore::open(store(&dir)).expect("first writer");
    let error = WritableSingleAuthorityStore::open(store(&dir)).unwrap_err();
    assert!(error.contains("already open for writing"), "{error}");
}

#[test]
fn p03_read_only_inspection_does_not_take_the_writer_role() {
    let dir = TempDir::new("p03");
    // Read-only handles never acquire the lock, so a writer can still open.
    let readonly_a = store(&dir);
    let readonly_b = store(&dir);
    assert!(readonly_a.recover().is_ok());
    assert!(readonly_b.recover().is_ok());
    let _writer = WritableSingleAuthorityStore::open(store(&dir)).expect("writer still available");
}

#[test]
fn p02_writer_lock_is_released_on_drop() {
    let dir = TempDir::new("p02");
    {
        let _first = WritableSingleAuthorityStore::open(store(&dir)).expect("first");
    }
    let _second = WritableSingleAuthorityStore::open(store(&dir)).expect("reacquire after drop");
}

/// Steady-state O(1): 5,000 appends must perform exactly ONE full scan
/// (the one at open). Frames are generated directly - no block execution.
#[test]
fn p04_steady_state_append_performs_no_additional_full_scans() {
    let dir = TempDir::new("p04");
    let mut writable = WritableSingleAuthorityStore::open(store(&dir)).expect("open");
    assert_eq!(writable.stats().full_scans, 1);

    for height in 0..5_000u64 {
        let record = record_at(height);
        writable.append_finalized(&record).expect("append");
    }
    let record = record_at(5_000);
    writable.append_finalized(&record).expect("append 5001st");
    writable.commit_head(&record).expect("head");

    // Still exactly one scan: appends never call recover().
    assert_eq!(
        writable.stats().full_scans,
        1,
        "steady-state append must not rescan the log"
    );
    assert_eq!(writable.next_height(), 5_001);
}

#[test]
fn p06_cache_advances_only_after_successful_append() {
    let dir = TempDir::new("p06");
    let mut writable = WritableSingleAuthorityStore::open(store(&dir)).expect("open");
    writable.append_finalized(&record_at(0)).expect("h0");
    assert_eq!(writable.cached_tail().unwrap().height, 0);

    // Rejected append must leave the cached tail untouched.
    let mut wrong = record_at(5);
    wrong.parent_hash = hash_of(99);
    assert!(writable.append_finalized(&wrong).is_err());
    assert_eq!(writable.cached_tail().unwrap().height, 0);
    assert_eq!(writable.next_height(), 1);
}

#[test]
fn p07_head_cache_updates_only_after_commit() {
    let dir = TempDir::new("p07");
    let mut writable = WritableSingleAuthorityStore::open(store(&dir)).expect("open");
    let record = record_at(0);
    writable.append_finalized(&record).expect("append");
    assert!(writable.cached_head().is_none(), "no head before commit");
    writable.commit_head(&record).expect("commit");
    assert_eq!(writable.cached_head().unwrap().height, 0);
}

#[test]
fn p08_reopen_performs_full_validation_and_rebuilds_the_cache() {
    let dir = TempDir::new("p08");
    {
        let mut writable = WritableSingleAuthorityStore::open(store(&dir)).expect("open");
        for height in 0..25u64 {
            let record = record_at(height);
            writable.append_finalized(&record).expect("append");
            writable.commit_head(&record).expect("head");
        }
    }
    let reopened = WritableSingleAuthorityStore::open(store(&dir)).expect("reopen");
    assert_eq!(reopened.stats().full_scans, 1);
    assert_eq!(reopened.next_height(), 25);
    assert_eq!(reopened.cached_tail().unwrap().height, 24);
    assert_eq!(reopened.cached_head().unwrap().height, 24);
}

#[test]
fn p10_interior_corruption_still_fails_closed_on_reopen() {
    let dir = TempDir::new("p10");
    {
        let mut writable = WritableSingleAuthorityStore::open(store(&dir)).expect("open");
        for height in 0..4u64 {
            let record = record_at(height);
            writable.append_finalized(&record).expect("append");
            writable.commit_head(&record).expect("head");
        }
    }
    let mut bytes = fs::read(dir.log()).unwrap();
    bytes[40] ^= 0xFF;
    fs::write(dir.log(), &bytes).unwrap();

    assert!(WritableSingleAuthorityStore::open(store(&dir)).is_err());
}

fn namespace(incarnation: u64, release: &str) -> SingleAuthorityHaltNamespace {
    SingleAuthorityHaltNamespace {
        chain_id: 1266,
        chain_incarnation: incarnation,
        consensus_protocol: SINGLE_AUTHORITY_CONSENSUS_PROTOCOL.to_string(),
        authority_id: "authority-node-01".to_string(),
        release_id: release.to_string(),
    }
}

#[test]
fn p13_old_incarnation_halt_cannot_block_incarnation_five() {
    let dir = TempDir::new("p13");
    let journal = SingleAuthoritySigningJournal::at_path(dir.0.join("journal.json"));

    // A halt recorded against the abandoned incarnation-4 chain.
    journal
        .enter_safety_halt(&namespace(4, "chain1266-rc29"), 614, "incarnation-4 stall")
        .expect("record historical halt");

    // It stays visible for audit ...
    assert_eq!(journal.safety_halts().unwrap().len(), 1);
    // ... but must not gate the fresh incarnation-5 signer.
    journal
        .require_signing_allowed(&namespace(5, "chain1266-single-authority-rc1"))
        .expect("incarnation-5 signing must not be blocked by an incarnation-4 halt");
}

#[test]
fn p14_current_incarnation_halt_blocks_current_signing() {
    let dir = TempDir::new("p14");
    let journal = SingleAuthoritySigningJournal::at_path(dir.0.join("journal.json"));
    let active = namespace(5, "chain1266-single-authority-rc1");

    journal
        .enter_safety_halt(&active, 12, "uncertain signing window")
        .expect("halt");
    let error = journal.require_signing_allowed(&active).unwrap_err();
    assert!(error.contains("SINGLE_AUTHORITY_SAFETY_HALT"), "{error}");
    assert!(error.contains("incarnation 5"), "{error}");
}

#[test]
fn p15_a_different_release_halt_does_not_block_the_active_release() {
    let dir = TempDir::new("p15");
    let journal = SingleAuthoritySigningJournal::at_path(dir.0.join("journal.json"));
    journal
        .enter_safety_halt(&namespace(5, "chain1266-single-authority-rc0"), 3, "old release")
        .expect("halt");
    journal
        .require_signing_allowed(&namespace(5, "chain1266-single-authority-rc1"))
        .expect("a halt bound to another release must not block this one");
}
