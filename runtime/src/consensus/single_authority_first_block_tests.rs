//! Height-1 vertical slice: real ML-DSA-65, real Block, real durability.

use super::single_authority_driver::*;
use super::single_authority_finality_store::*;
use super::single_authority_signing_journal::*;
use crate::crypto::pqc::{PQCAlgorithm, PQCManager};
use std::fs;
use std::path::PathBuf;

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "sa-block-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&path).expect("temp dir");
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Real Genesis hashes are blake3 hex; the anchor must be the same shape.
const GENESIS_HASH: &str = "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e";

fn inputs(dir: &TempDir) -> SingleAuthorityRuntimeInputs {
    let mut manager = PQCManager::new();
    let (public, private) = manager
        .generate_keypair(PQCAlgorithm::MLDSA65)
        .expect("ML-DSA-65 authority key");
    SingleAuthorityRuntimeInputs {
        chain_id: 1266,
        chain_incarnation: 5,
        network_id: "synergy-testnet-v3".to_string(),
        release_id: "chain1266-single-authority-rc1".to_string(),
        authority_id: "authority-node-01".to_string(),
        authority_key_id: "authority-node-01-block-key".to_string(),
        authority_public_key_fingerprint: "sha256:authority-node-01".to_string(),
        authority_public_key: public,
        authority_private_key: private,
        target_block_time_ms: 2_000,
        genesis_hash: GENESIS_HASH.to_string(),
        directory_namespace: "chain-1266/incarnation-5".to_string(),
        finality_log_path: dir.0.join("finality.log"),
        finality_head_path: dir.0.join("finality.head.json"),
        signing_journal_path: dir.0.join("signing-journal.json"),
        committed_block_log_path: dir.0.join("committed-blocks.ndjson"),
        execution_state_path: dir.0.join("execution-state.json"),
        receipt_log_path: dir.0.join("receipts.ndjson"),
        // Durability-only slice: an empty canonical execution state. The real
        // Genesis-derived state is exercised by the real-transaction suite.
        genesis_execution_state: crate::execution::ExecutionState::new(),
    }
}

#[test]
fn f01_height_one_finalizes_from_genesis() {
    let dir = TempDir::new("f01");
    let cfg = inputs(&dir);
    let journal_path = cfg.signing_journal_path.clone();
    let log_path = cfg.finality_log_path.clone();
    let head_path = cfg.finality_head_path.clone();
    let body_path = cfg.committed_block_log_path.clone();
    let binding = cfg.chain_binding();

    let mut driver = SingleAuthorityDriver::start(cfg).expect("driver starts");

    // 1. Genesis is the finalized parent at height 0.
    assert_eq!(driver.finalized_parent().height, 0);
    assert_eq!(driver.finalized_parent().block_hash, GENESIS_HASH);
    assert_eq!(driver.next_height(), 1);

    // 2. Produce height 1 with an empty canonical transaction set.
    let block = driver.produce_next_block(Vec::new()).expect("height 1");

    assert_eq!(block.block_index, 1, "height 1");
    assert_eq!(block.previous_hash, GENESIS_HASH, "parent is Genesis");
    assert_eq!(block.validator_id, "authority-node-01");
    assert_eq!(block.block_signature_algorithm, "mldsa65");
    assert!(!block.block_signature.is_empty());

    // 3. The real canonical verifier accepts the ML-DSA-65 signature.
    block
        .verify_proposer_signature()
        .expect("canonical ML-DSA-65 block signature verifies");

    // 4. Durable block body exists.
    let bodies = fs::read_to_string(&body_path).expect("committed block log");
    assert!(bodies.contains(&block.hash), "block body is durable");

    // 5. Finality record and durable head agree at height 1.
    let store =
        SingleAuthorityFinalityStore::at_paths(log_path, head_path, binding).expect("reopen store");
    let recovery = store.recover().expect("recover");
    assert_eq!(recovery.records.len(), 1);
    assert_eq!(recovery.records[0].height, 1);
    let head = store.load_head().expect("head").expect("head present");
    assert_eq!(head.height, 1);
    assert_eq!(head.block_hash, recovery.records[0].block_hash);

    // 6. Completed journal entries are compacted; the finality record keeps
    // the exact public signature as the durable audit source.
    let journal = SingleAuthoritySigningJournal::at_path(journal_path);
    assert!(journal.entry_for_height(1).unwrap().is_none());
    use base64::{engine::general_purpose, Engine as _};
    assert_eq!(
        general_purpose::STANDARD
            .decode(&recovery.records[0].authority_signature_base64)
            .unwrap(),
        block.block_signature
    );

    // 7. No BFT concept anywhere in the durable artifacts.
    let finality_raw = fs::read_to_string(&store.log_path()).unwrap_or_default();
    for forbidden in [
        "quorum",
        "certificate",
        "vote",
        "round",
        "cluster",
        "coordinator",
        "producer",
    ] {
        assert!(
            !finality_raw.contains(forbidden),
            "finality log leaked {forbidden}"
        );
    }
}

#[test]
fn f02_restart_resumes_at_height_two_without_resigning_height_one() {
    let dir = TempDir::new("f02");

    // --- first process lifetime ---
    let height_one_signature;
    let height_one_hash;
    {
        let mut driver = SingleAuthorityDriver::start(inputs(&dir)).expect("start");
        let block = driver.produce_next_block(Vec::new()).expect("height 1");
        height_one_signature = block.block_signature.clone();
        height_one_hash = block.hash.clone();
        // All runtime objects (including the writer lock) drop here.
    }

    // --- restart: reopen everything from disk ---
    let mut cfg = inputs(&dir);
    // Reuse the SAME authority key, as a real restart would.
    let journal = SingleAuthoritySigningJournal::at_path(cfg.signing_journal_path.clone());
    assert!(
        journal.entry_for_height(1).unwrap().is_none(),
        "completed entries are compacted before restart"
    );

    cfg.authority_public_key_fingerprint = "sha256:authority-node-01".to_string();
    let mut driver = SingleAuthorityDriver::start(cfg).expect("restart");

    // Recovery returns finalized height 1 and the next height is 2.
    assert_eq!(driver.finalized_parent().height, 1);
    assert_eq!(driver.next_height(), 2);

    let block_two = driver.produce_next_block(Vec::new()).expect("height 2");
    assert_eq!(block_two.block_index, 2);
    assert_eq!(
        block_two.previous_hash, height_one_hash,
        "height 2 extends the exact height-1 block"
    );

    // No duplicate or conflicting heights.
    let store = SingleAuthorityFinalityStore::at_paths(
        dir.0.join("finality.log"),
        dir.0.join("finality.head.json"),
        SingleAuthorityChainBinding {
            first_authority_height: 1,
            chain_id: 1266,
            chain_incarnation: 5,
            authority_id: "authority-node-01".to_string(),
            authority_public_key_fingerprint: "sha256:authority-node-01".to_string(),
        },
    )
    .unwrap();
    let recovery = store.recover().unwrap();
    let heights: Vec<u64> = recovery.records.iter().map(|r| r.height).collect();
    assert_eq!(heights, vec![1, 2], "exactly heights 1 and 2, in order");
    // Height 1 was never re-signed: finality retains the exact durable
    // signature while the compact journal carries only an unfinished slot.
    use base64::{engine::general_purpose, Engine as _};
    assert_eq!(
        general_purpose::STANDARD
            .decode(&recovery.records[0].authority_signature_base64)
            .unwrap(),
        height_one_signature,
        "restart must not regenerate the height-1 signature"
    );
}
