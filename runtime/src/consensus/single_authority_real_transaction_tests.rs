//! One real, signed, native-token transaction finalized locally through the
//! canonical `single_authority_v1` path.
//!
//! Nothing here is mocked: real ML-DSA transaction signing, real Aegis
//! admission, the real DAG transaction pool, the real canonical state
//! transition, real on-disk durability, and real ML-DSA-65 block signing.
//!
//! The Genesis fixture is produced through the canonical Genesis builder
//! (`recompute_testnet_v3_candidate_integrity`) from the committed canonical
//! Genesis and is re-validated by the canonical loader before use.

use super::single_authority_driver::*;
use super::single_authority_execution::*;
use super::single_authority_finality_store::*;
use super::single_authority_signing_journal::*;
use crate::aegis_tx_tool::{
    sign_with_new_aegis_transaction_key, AegisSignedTxReport, AegisTxBuildOptions,
};
use crate::block::BlockChain;
use crate::crypto::aegis_pqvm::AegisPqvmVerifier;
use crate::crypto::pqc::{PQCAlgorithm, PQCManager, PQCPrivateKey, PQCPublicKey};
use crate::dag_mempool::{BlockSelectionLimits, DagMempool};
use crate::execution::{
    compute_state_root_after, execute_block_contents, ExecutionBlockContext, ExecutionState,
    GenesisExecutionSnapshot, ReceiptStatus,
};
use crate::synergy_types::{Epoch, Hash, Height};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

const CHAIN_ID: u64 = 1266;
const CHAIN_INCARNATION: u64 = 5;
const NETWORK_ID: &str = "synergy-testnet-v3";
const AUTHORITY_ID: &str = "authority-node-01";
const RELEASE_ID: &str = "chain1266-single-authority-rc1";
const TARGET_BLOCK_TIME_MS: u64 = 2_000;

const SENDER_GENESIS_BALANCE_NWEI: u128 = 5_000_000_000_000_000_000;
const TRANSFER_AMOUNT_NWEI: u128 = 1_000_000_000_000_000;
const TX_GAS_LIMIT: u64 = 21_000;
const TX_MAX_FEE_NWEI: u128 = 21_000_000_000;

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "sa-realtx-{tag}-{}-{}",
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

fn canonical_source_genesis() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("launch/production-node-configs/canonical-genesis/genesis.json")
}

/// A canonical Genesis fixture, built through the canonical Genesis path.
struct GenesisFixture {
    path: PathBuf,
    genesis_hash: String,
    execution_state: ExecutionState,
    execution_state_root: Hash,
}

/// Produces a temporary canonical Genesis that funds the real accounts this
/// test transacts between.
///
/// The funded balances are inserted into BOTH the Genesis balance table and the
/// embedded post-deployment execution snapshot, the snapshot digest and every
/// execution root are rebound, and all dependent integrity roots are recomputed
/// by the canonical builder. The result is then re-loaded by the canonical
/// loader, so nothing downstream consumes an unvalidated document.
fn build_canonical_genesis_fixture(dir: &Path, funded: &[(String, u128)]) -> GenesisFixture {
    let source = canonical_source_genesis();
    let base = crate::genesis::load_genesis_from_path(&source)
        .expect("committed canonical Genesis must validate");
    let mut state =
        crate::testnet_v3_execution_bootstrap::load_finalized_testnet_v3_genesis_execution_state(
            &base,
        )
        .expect("canonical Genesis must restore its finalized execution state");

    let mut value: Value =
        serde_json::from_slice(&fs::read(&source).expect("read Genesis")).expect("parse Genesis");
    let mut balances = value["balances"]
        .as_array()
        .expect("Genesis balances")
        .clone();
    for (index, (address, amount)) in funded.iter().enumerate() {
        assert!(
            !state.balances_nwei.contains_key(address),
            "fixture account must not already exist in canonical Genesis"
        );
        assert!(
            u64::try_from(*amount).is_ok(),
            "Genesis balances are canonically u64-bounded"
        );
        state.balances_nwei.insert(address.clone(), *amount);
        balances.push(json!({
            "account_id": format!("SA-TX-FIXTURE-{index:02}"),
            "address": address,
            "balance_nwei": amount.to_string(),
        }));
    }
    value["balances"] = Value::Array(balances);

    // Rebind the embedded post-deployment execution snapshot to the new state.
    let snapshot =
        GenesisExecutionSnapshot::capture_testnet_v3(&state).expect("capture Genesis snapshot");
    let snapshot_bytes = serde_json::to_vec(&snapshot).expect("encode Genesis snapshot");
    let snapshot_sha256 = hex::encode(Sha256::digest(&snapshot_bytes));
    value["genesis_deployment"]["execution_state"] =
        serde_json::to_value(&snapshot).expect("snapshot to value");
    value["genesis_deployment"]["execution_state_snapshot_canonical_sha256"] =
        Value::String(snapshot_sha256);
    value["genesis_deployment"]["post_deployment_execution_state_root"] =
        Value::String(snapshot.state_root.clone());
    value["integrity"]["post_deployment_execution_state_root"] =
        Value::String(snapshot.state_root.clone());
    value["execution"]["genesis_execution_state_root"] = Value::String(snapshot.state_root.clone());

    crate::genesis::recompute_testnet_v3_candidate_integrity(&mut value)
        .expect("canonical Genesis builder must recompute every dependent root");

    let path = dir.join("genesis.chain1266.single-authority-fixture.json");
    let mut bytes = serde_json::to_vec_pretty(&value).expect("encode fixture Genesis");
    bytes.push(b'\n');
    fs::write(&path, &bytes).expect("write fixture Genesis");

    // The canonical loader is the acceptance gate for this fixture.
    let document = crate::genesis::load_genesis_from_path(&path)
        .expect("fixture Genesis must validate through the canonical loader");
    assert_eq!(document.chain_id(), CHAIN_ID);
    let restored =
        crate::testnet_v3_execution_bootstrap::load_finalized_testnet_v3_genesis_execution_state(
            &document,
        )
        .expect("fixture Genesis must restore its finalized execution state");
    assert_eq!(restored, state, "fixture Genesis must round-trip its state");

    let execution_state_root =
        compute_state_root_after(&state).expect("Genesis execution state root");
    GenesisFixture {
        path,
        genesis_hash: document.hash().to_string(),
        execution_state: state,
        execution_state_root,
    }
}

fn sign_real_transaction(uma: &str, nonce: u64, amount_nwei: u128) -> AegisSignedTxReport {
    sign_with_new_aegis_transaction_key(AegisTxBuildOptions {
        signer_uma_id: uma.to_string(),
        nonce,
        amount_nwei,
        gas_limit: TX_GAS_LIMIT,
        max_fee_nwei: TX_MAX_FEE_NWEI,
        ttl_height: 10_000,
        epoch: 0,
        ..AegisTxBuildOptions::default()
    })
    .expect("real ML-DSA transaction signing must succeed")
}

fn verifier_for(report: &AegisSignedTxReport) -> AegisPqvmVerifier {
    AegisPqvmVerifier::initialize_required_for_public_key(
        report.submission_envelope.public_key.clone(),
        report.submission_envelope.lifecycle_record.clone(),
    )
    .expect("real Aegis verifier")
}

fn authority_keypair() -> (PQCPublicKey, PQCPrivateKey) {
    let mut manager = PQCManager::new();
    manager
        .generate_keypair(PQCAlgorithm::MLDSA65)
        .expect("real ML-DSA-65 authority key")
}

fn inputs(
    dir: &TempDir,
    fixture: &GenesisFixture,
    public: &PQCPublicKey,
    private: &PQCPrivateKey,
) -> SingleAuthorityRuntimeInputs {
    SingleAuthorityRuntimeInputs {
        chain_id: CHAIN_ID,
        chain_incarnation: CHAIN_INCARNATION,
        network_id: NETWORK_ID.to_string(),
        release_id: RELEASE_ID.to_string(),
        authority_id: AUTHORITY_ID.to_string(),
        authority_key_id: "authority-node-01-block-key".to_string(),
        authority_public_key_fingerprint: fingerprint(public),
        authority_public_key: public.clone(),
        authority_private_key: private.clone(),
        target_block_time_ms: TARGET_BLOCK_TIME_MS,
        genesis_hash: fixture.genesis_hash.clone(),
        directory_namespace: format!("chain-{CHAIN_ID}/incarnation-{CHAIN_INCARNATION}"),
        finality_log_path: dir.0.join("finality.log"),
        finality_head_path: dir.0.join("finality.head.json"),
        signing_journal_path: dir.0.join("signing-journal.json"),
        committed_block_log_path: dir.0.join("committed-blocks.ndjson"),
        execution_state_path: dir.0.join("execution-state.json"),
        receipt_log_path: dir.0.join("receipts.ndjson"),
        genesis_execution_state: fixture.execution_state.clone(),
    }
}

fn fingerprint(public: &PQCPublicKey) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(&public.key_data)))
}

fn binding(fingerprint: &str, incarnation: u64) -> SingleAuthorityChainBinding {
    SingleAuthorityChainBinding {
        first_authority_height: 1,
        chain_id: CHAIN_ID,
        chain_incarnation: incarnation,
        authority_id: AUTHORITY_ID.to_string(),
        authority_public_key_fingerprint: fingerprint.to_string(),
    }
}

fn balance(state: &ExecutionState, address: &str) -> u128 {
    state.balances_nwei.get(address).copied().unwrap_or(0)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn t01_real_signed_native_transfer_is_finalized_and_survives_restart() {
    let dir = TempDir::new("t01");

    // ---------------------------------------------------------------
    // 4-7. Real transaction: real key, real signing, real verification.
    // ---------------------------------------------------------------
    let report = sign_real_transaction("chain1266-single-authority-account", 0, TRANSFER_AMOUNT_NWEI);
    let typed_tx = report.transaction.clone();
    let sender = typed_tx.sender_uma_or_account.clone();
    let recipient = typed_tx.receiver_uma_or_account.clone();
    assert_ne!(sender, recipient);

    // The canonical transaction-signing algorithm, read from the artifact the
    // real signing API produced - not assumed.
    let signing_algorithm = typed_tx.aegis_pq_signature.algorithm.clone();
    assert_eq!(
        signing_algorithm, "mldsa65",
        "canonical Aegis transaction signing algorithm"
    );
    assert_eq!(
        report.submission_envelope.public_key.algorithm, signing_algorithm,
        "signing key algorithm must match the signature algorithm"
    );

    let verifier = verifier_for(&report);
    verifier
        .verify_transaction_signature_checked(&typed_tx)
        .expect("real transaction signature must verify");
    let mut tampered = typed_tx.clone();
    tampered.amount_nwei += 1;
    assert!(
        verifier
            .verify_transaction_signature_checked(&tampered)
            .is_err(),
        "tampering must invalidate the transaction signature"
    );

    // ---------------------------------------------------------------
    // 1-3. Canonical Genesis funding the real accounts.
    // ---------------------------------------------------------------
    let fixture = build_canonical_genesis_fixture(
        &dir.0,
        &[
            (sender.clone(), SENDER_GENESIS_BALANCE_NWEI),
            (recipient.clone(), 0),
        ],
    );
    let genesis_state = fixture.execution_state.clone();

    // Captured BEFORE execution.
    let sender_nonce_before = typed_tx.account_nonce_or_sequence;
    let sender_balance_before = balance(&genesis_state, &sender);
    let recipient_balance_before = balance(&genesis_state, &recipient);
    assert_eq!(sender_balance_before, SENDER_GENESIS_BALANCE_NWEI);
    assert_eq!(recipient_balance_before, 0);
    assert_eq!(sender_nonce_before, 0);

    // ---------------------------------------------------------------
    // 8. Canonical admission.
    // ---------------------------------------------------------------
    let empty_chain = BlockChain::new();
    let now = now_unix();
    let carrier =
        admit_single_authority_transaction(&report.submission_envelope, &empty_chain, &[], now)
            .expect("canonical admission must accept the real transaction");

    // Chain id and network id are enforced at admission.
    let mut foreign_chain = report.submission_envelope.clone();
    foreign_chain.transaction.chain_id = crate::synergy_types::ChainId(999);
    assert!(
        admit_single_authority_transaction(&foreign_chain, &empty_chain, &[], now).is_err(),
        "a foreign chain id must be rejected at admission"
    );
    let mut foreign_network = report.submission_envelope.clone();
    foreign_network.transaction.network_id =
        crate::synergy_types::NetworkId("synergy-testnet-v2".to_string());
    assert!(
        admit_single_authority_transaction(&foreign_network, &empty_chain, &[], now).is_err(),
        "a foreign network id must be rejected at admission"
    );

    // Correct nonce is enforced.
    let mut future_nonce = carrier.clone();
    future_nonce.nonce = 7;
    assert!(
        require_canonical_account_sequence(&future_nonce, &empty_chain, &[])
            .unwrap_err()
            .contains("future nonce gap"),
        "a nonce gap must be rejected"
    );

    // Balance and fee requirements are enforced by canonical execution.
    let overdraft = sign_real_transaction(
        "chain1266-single-authority-overdraft",
        0,
        SENDER_GENESIS_BALANCE_NWEI,
    );
    let mut overdraft_state = genesis_state.clone();
    overdraft_state
        .balances_nwei
        .insert(overdraft.transaction.sender_uma_or_account.clone(), 1);
    let overdraft_authorized = authorize_for_execution(
        &overdraft_state,
        std::slice::from_ref(&overdraft.transaction),
        now,
    )
    .expect("authorize overdraft");
    let overdraft_result = execute_block_contents(
        &ExecutionBlockContext {
            height: Height(1),
            timestamp_ms: now.saturating_mul(1_000),
        },
        std::slice::from_ref(&overdraft.transaction),
        &overdraft_authorized,
    )
    .expect("overdraft execution must produce a receipt");
    assert_eq!(overdraft_result.receipts.len(), 1);
    assert_eq!(overdraft_result.receipts[0].status, ReceiptStatus::Failed);
    assert_eq!(overdraft_result.receipts[0].error, "INSUFFICIENT_FUNDS");

    // ---------------------------------------------------------------
    // 9-10. Canonical transaction pool, then canonical selection.
    // ---------------------------------------------------------------
    let mut pool = DagMempool::new(&verifier, Epoch(0), Height(0));
    let admission = pool
        .admit_transaction(typed_tx.clone())
        .expect("the canonical pool must admit the real transaction");
    let tx_id = admission.tx_id.clone();
    assert!(admission.ready, "the transaction must be immediately ready");
    assert!(
        pool.transaction(&tx_id).is_some(),
        "pool must hold the transaction before block construction"
    );

    let frontier = pool.ready_frontier();
    assert_eq!(frontier, vec![tx_id.clone()]);
    let selected = pool
        .ancestor_closed_set(
            &frontier,
            BlockSelectionLimits {
                max_txs: 64,
                max_gas: 30_000_000,
            },
        )
        .expect("canonical selection");
    assert_eq!(selected, vec![tx_id.clone()], "selected exactly once");
    assert!(
        pool.admit_transaction(typed_tx.clone()).is_err(),
        "the pool must reject a replayed transaction"
    );

    // The pool id (`SYNERGY_TX_V1`) and the execution receipt id
    // (`SYNERGY_EXECUTION_TX_ID_V1`) are distinct canonical domains over the
    // SAME canonical transaction bytes. Bind both to this one transaction.
    let execution_context = crate::execution::verified_context_for_block(std::slice::from_ref(
        &typed_tx,
    ))
    .expect("canonical execution identity");
    assert_eq!(execution_context.len(), 1);
    let (execution_tx_id, execution_canonical_bytes_hash) = execution_context
        .iter()
        .next()
        .map(|(id, hash)| (id.clone(), *hash))
        .expect("execution identity");
    assert_eq!(
        execution_canonical_bytes_hash,
        typed_tx
            .canonical_tx_bytes_hash()
            .expect("canonical tx bytes hash"),
        "both id domains bind the same canonical transaction bytes"
    );
    assert_ne!(execution_tx_id, tx_id, "the two id domains are separated");

    // ---------------------------------------------------------------
    // 11-16. Production block production through the real driver.
    // ---------------------------------------------------------------
    let (public, private) = authority_keypair();
    let authority_fingerprint = fingerprint(&public);
    let block;
    let height_one_signature;
    let finalized_state_root;
    let finalized_receipt_root;
    let finalized_transaction_root;
    let receipt;
    {
        let mut driver = SingleAuthorityDriver::start(inputs(&dir, &fixture, &public, &private))
            .expect("driver starts on canonical Genesis");
        assert_eq!(driver.finalized_parent().height, 0);
        assert_eq!(driver.finalized_parent().block_hash, fixture.genesis_hash);
        assert_eq!(
            driver.finalized_parent().state_root,
            fixture.execution_state_root,
            "height 0 carries the canonical Genesis execution state root"
        );
        assert_eq!(driver.next_height(), 1);

        block = driver
            .produce_next_block(vec![carrier.clone()])
            .expect("height 1 with one real transaction");

        let frames =
            recover_receipt_frames(&dir.0.join("receipts.ndjson")).expect("durable receipts");
        let frame = frames.get(&1).expect("height 1 receipt frame");
        assert_eq!(frame.receipts.len(), 1, "executed exactly once");
        receipt = frame.receipts[0].clone();
        finalized_state_root = frame.state_root_after;
        finalized_receipt_root = frame.receipt_root;
        finalized_transaction_root =
            Hash::from_hex(&block.transactions_root).expect("canonical transactions root");
        height_one_signature = block.block_signature.clone();

        // The canonical ML-DSA-65 authority block signature verifies.
        assert_eq!(block.block_signature_algorithm, "mldsa65");
        block
            .verify_proposer_signature()
            .expect("ML-DSA-65 authority block signature must verify");

        // A successful canonical receipt was produced.
        assert_eq!(receipt.status, ReceiptStatus::Success);
        assert_eq!(receipt.tx_id, execution_tx_id);
        assert!(receipt.error.is_empty());

        // Balance, nonce, and fee accounting.
        let after = driver.execution_state().clone();
        let fee = receipt
            .fee_breakdown
            .clone()
            .expect("canonical receipt carries the fee breakdown");
        assert!(fee.total_network_fee_nwei > 0, "a real fee must be charged");
        assert_eq!(
            balance(&after, &sender),
            sender_balance_before - TRANSFER_AMOUNT_NWEI - fee.total_network_fee_nwei,
            "sender pays exactly transfer + canonical network fee"
        );
        assert_eq!(
            balance(&after, &recipient),
            recipient_balance_before + TRANSFER_AMOUNT_NWEI,
            "recipient receives exactly the transfer amount"
        );
        assert_eq!(
            balance(&after, &fee.fee_collector_address),
            balance(&genesis_state, &fee.fee_collector_address) + fee.total_network_fee_nwei,
            "the canonical fee collector receives exactly the network fee"
        );
        let fee_event = after
            .fee_events
            .iter()
            .find(|event| event.tx_id == execution_tx_id)
            .expect("canonical fee event");
        assert!(fee_event.success);
        assert_eq!(fee_event.payer, sender);
        assert_eq!(fee_event.block_height, 1);
        assert_eq!(fee_event.total_network_fee_nwei, fee.total_network_fee_nwei);
        assert_eq!(
            fee.gas_fee_nwei
                + fee.amount_protocol_fee_nwei
                + fee.storage_fee_nwei
                + fee.priority_fee_nwei,
            fee.total_network_fee_nwei,
            "fee components must sum to the canonical total"
        );

        // Sender nonce advanced exactly once.
        assert_eq!(
            committed_sender_nonces(driver.chain(), &sender),
            vec![sender_nonce_before],
            "exactly one committed nonce for the sender"
        );
        require_canonical_account_sequence(&carrier, driver.chain(), &[])
            .expect_err("the same nonce must not be admissible again");
        let mut next = carrier.clone();
        next.nonce = sender_nonce_before + 1;
        require_canonical_account_sequence(&next, driver.chain(), &[])
            .expect("the next sequential nonce is the only admissible one");

        // The finalized record binds the real execution roots.
        let store = SingleAuthorityFinalityStore::at_paths(
            dir.0.join("finality.log"),
            dir.0.join("finality.head.json"),
            binding(&authority_fingerprint, CHAIN_INCARNATION),
        )
        .expect("reopen finality store");
        let recovery = store.recover().expect("recover finality");
        assert_eq!(recovery.records.len(), 1);
        let record = &recovery.records[0];
        assert_eq!(record.height, 1);
        assert_eq!(record.chain_id, CHAIN_ID);
        assert_eq!(record.chain_incarnation, CHAIN_INCARNATION);
        assert_eq!(
            record.consensus_protocol,
            SINGLE_AUTHORITY_CONSENSUS_PROTOCOL
        );
        assert_eq!(record.state_root, finalized_state_root);
        assert_eq!(record.receipt_root, finalized_receipt_root);
        assert_eq!(record.transaction_root, finalized_transaction_root);
        assert_eq!(record.block_hash.to_hex(), block.hash);
        assert_eq!(
            record.parent_hash.to_hex(),
            fixture.genesis_hash,
            "height 1 extends the real canonical Genesis"
        );
        assert_ne!(
            record.state_root, fixture.execution_state_root,
            "the transfer must move the state root"
        );

        // Finality record and durable head reference the same block.
        let head = store.load_head().expect("head").expect("head present");
        assert_eq!(head.height, record.height);
        assert_eq!(head.block_hash, record.block_hash);
        assert_eq!(head.state_root, record.state_root);
        assert_eq!(head.chain_incarnation, CHAIN_INCARNATION);

        // A foreign incarnation cannot read this log.
        let foreign = SingleAuthorityFinalityStore::at_paths(
            dir.0.join("finality.log"),
            dir.0.join("finality.head.json"),
            binding(&authority_fingerprint, 4),
        )
        .expect("open with a foreign binding");
        assert!(
            foreign.recover().is_err(),
            "incarnation 4 must not be able to read an incarnation 5 finality log"
        );

        // Signing journal state is Finalized.
        let journal = SingleAuthoritySigningJournal::at_path(dir.0.join("signing-journal.json"));
        let entry = journal.entry_for_height(1).unwrap().expect("journal entry");
        assert_eq!(entry.state, SingleAuthorityJournalState::Finalized);
        assert!(entry.signature.is_some());
    }

    // 18. Replay from the same parent state reproduces every root.
    let replay_typed =
        typed_transactions_for_block(&block.transactions, &BlockChain::new(), block.timestamp)
            .expect("replay re-admits the body");
    let replay_authorized = authorize_for_execution(&genesis_state, &replay_typed, block.timestamp)
        .expect("replay authorization");
    let replay = execute_block_contents(
        &ExecutionBlockContext {
            height: Height(1),
            timestamp_ms: block.timestamp.saturating_mul(1_000),
        },
        &replay_typed,
        &replay_authorized,
    )
    .expect("replay execution");
    assert_eq!(replay.state_root_after, finalized_state_root);
    assert_eq!(replay.receipt_root, finalized_receipt_root);
    assert_eq!(replay.receipts, vec![receipt.clone()]);

    // 14. The receipt is durably persisted.
    let persisted = recover_receipt_frames(&dir.0.join("receipts.ndjson"))
        .expect("durable receipts")
        .get(&1)
        .cloned()
        .expect("height 1 frame");
    assert_eq!(persisted.receipts, vec![receipt.clone()]);
    assert_eq!(persisted.block_hash, block.hash);

    // 23. No BFT artifact exists in any durable single-authority file.
    for file in [
        "finality.log",
        "finality.head.json",
        "signing-journal.json",
    ] {
        let raw = fs::read_to_string(dir.0.join(file)).unwrap_or_default();
        for forbidden in [
            "quorum",
            "certificate",
            "vote",
            "round",
            "epoch",
            "cluster",
            "coordinator",
            "producer",
        ] {
            assert!(
                !raw.contains(forbidden),
                "durable file {file} leaked the concept {forbidden}"
            );
        }
    }

    // ---------------------------------------------------------------
    // Restart gate. Every runtime object above has been dropped, which
    // releases the single-writer lock.
    // ---------------------------------------------------------------
    let mut driver =
        SingleAuthorityDriver::start(inputs(&dir, &fixture, &public, &private)).expect("restart");

    assert_eq!(driver.finalized_parent().height, 1);
    assert_eq!(driver.finalized_parent().block_hash, block.hash);
    assert_eq!(driver.finalized_parent().state_root, finalized_state_root);
    assert_eq!(
        driver.chain().last().expect("recovered tip").hash,
        block.hash
    );
    assert_eq!(
        driver
            .chain()
            .last()
            .expect("recovered tip")
            .transactions
            .len(),
        1,
        "the committed block body survived restart"
    );

    // Balances, nonce, and the receipt survived restart.
    let recovered = driver.execution_state().clone();
    assert_eq!(
        compute_state_root_after(&recovered).expect("root"),
        finalized_state_root
    );
    let fee = receipt.fee_breakdown.clone().expect("fee");
    assert_eq!(
        balance(&recovered, &sender),
        sender_balance_before - TRANSFER_AMOUNT_NWEI - fee.total_network_fee_nwei
    );
    assert_eq!(balance(&recovered, &recipient), TRANSFER_AMOUNT_NWEI);
    assert_eq!(
        committed_sender_nonces(driver.chain(), &sender),
        vec![sender_nonce_before]
    );

    // The transaction is not pending and cannot execute again.
    let restart_pool = DagMempool::new(&verifier, Epoch(0), Height(1));
    assert!(
        restart_pool.transaction(&tx_id).is_none(),
        "a finalized transaction must not be pending after restart"
    );
    require_canonical_account_sequence(&carrier, driver.chain(), &[])
        .expect_err("a finalized nonce must not be re-admissible after restart");
    assert!(
        driver
            .execute_block_body(&crate::block::Block::new(
                2,
                vec![carrier.clone()],
                block.hash.clone(),
                AUTHORITY_ID.to_string(),
                0,
            ))
            .is_err(),
        "a replayed transaction must not be executable after restart"
    );

    // One additional empty block extends the transaction block.
    let block_two = driver
        .produce_next_block(Vec::new())
        .expect("height 2 after restart");
    assert_eq!(block_two.block_index, 2);
    assert_eq!(block_two.previous_hash, block.hash);
    assert_eq!(
        block_two.transactions_root,
        crate::block::compute_merkle_root(&[])
    );
    block_two
        .verify_proposer_signature()
        .expect("height 2 authority signature verifies");

    let journal = SingleAuthoritySigningJournal::at_path(dir.0.join("signing-journal.json"));
    let entry_one = journal.entry_for_height(1).unwrap().expect("entry");
    use base64::{engine::general_purpose, Engine as _};
    assert_eq!(
        general_purpose::STANDARD
            .decode(&entry_one.signature.expect("signature").signature_base64)
            .unwrap(),
        height_one_signature,
        "restart must not regenerate the height-1 signature"
    );

    // No duplicate or conflicting height.
    let store = SingleAuthorityFinalityStore::at_paths(
        dir.0.join("finality.log"),
        dir.0.join("finality.head.json"),
        binding(&authority_fingerprint, CHAIN_INCARNATION),
    )
    .expect("reopen store");
    let recovery = store.recover().expect("recover");
    let heights: Vec<u64> = recovery.records.iter().map(|r| r.height).collect();
    assert_eq!(heights, vec![1, 2], "exactly heights 1 and 2, in order");
    // An empty height-2 body leaves the post-transaction state unchanged.
    assert_eq!(recovery.records[1].state_root, finalized_state_root);

    assert!(fixture.path.exists(), "the fixture Genesis is on disk");

    // Evidence for the release record. Visible under `-- --nocapture`.
    println!("SINGLE_AUTHORITY_REAL_TRANSACTION_EVIDENCE");
    println!("  chain_id                 = {CHAIN_ID}");
    println!("  chain_incarnation        = {CHAIN_INCARNATION}");
    println!("  network_id               = {NETWORK_ID}");
    println!("  consensus_protocol       = {SINGLE_AUTHORITY_CONSENSUS_PROTOCOL}");
    println!("  genesis_hash             = {}", fixture.genesis_hash);
    println!(
        "  genesis_state_root       = {}",
        fixture.execution_state_root.to_hex()
    );
    println!("  tx_signing_algorithm     = {signing_algorithm}");
    println!("  tx_hash (carrier)        = {}", carrier.hash());
    println!("  tx_id (pool/SYNERGY_TX_V1)      = {}", tx_id.0);
    println!("  tx_id (execution)               = {}", execution_tx_id.0);
    println!("  sender                   = {sender}");
    println!("  recipient                = {recipient}");
    println!("  nonce_before             = {sender_nonce_before}");
    println!(
        "  nonce_after (committed)  = {:?}",
        committed_sender_nonces(driver.chain(), &sender)
    );
    println!("  sender_balance_before    = {sender_balance_before}");
    println!(
        "  sender_balance_after     = {}",
        balance(&recovered, &sender)
    );
    println!("  recipient_balance_before = {recipient_balance_before}");
    println!(
        "  recipient_balance_after  = {}",
        balance(&recovered, &recipient)
    );
    println!("  transfer_amount_nwei     = {TRANSFER_AMOUNT_NWEI}");
    println!("  fee_total_nwei           = {}", fee.total_network_fee_nwei);
    println!("  fee_gas_nwei             = {}", fee.gas_fee_nwei);
    println!(
        "  fee_amount_protocol_nwei = {}",
        fee.amount_protocol_fee_nwei
    );
    println!("  fee_storage_nwei         = {}", fee.storage_fee_nwei);
    println!("  fee_priority_nwei        = {}", fee.priority_fee_nwei);
    println!("  fee_collector            = {}", fee.fee_collector_address);
    println!("  block_height             = {}", block.block_index);
    println!("  block_hash               = {}", block.hash);
    println!("  block_signature_alg      = {}", block.block_signature_algorithm);
    println!(
        "  transaction_root         = {}",
        finalized_transaction_root.to_hex()
    );
    println!(
        "  receipt_root             = {}",
        finalized_receipt_root.to_hex()
    );
    println!(
        "  state_root               = {}",
        finalized_state_root.to_hex()
    );
    println!(
        "  replay_state_root        = {}",
        replay.state_root_after.to_hex()
    );
    println!(
        "  replay_receipt_root      = {}",
        replay.receipt_root.to_hex()
    );
    println!("  restart_recovered_height = {}", 1);
    println!("  next_finalized_height    = {}", block_two.block_index);
    println!("  next_block_hash          = {}", block_two.hash);
}

/// The Genesis fixture must resolve through `canonical_genesis()` when it is
/// the configured Genesis file. Isolated from the finalization test because it
/// mutates the process-wide `SYNERGY_GENESIS_FILE`.
#[test]
fn t02_fixture_genesis_resolves_through_canonical_genesis() {
    let dir = TempDir::new("t02");
    let report = sign_real_transaction("chain1266-single-authority-genesis-probe", 0, 1);
    let fixture = build_canonical_genesis_fixture(
        &dir.0,
        &[(
            report.transaction.sender_uma_or_account.clone(),
            SENDER_GENESIS_BALANCE_NWEI,
        )],
    );

    let previous = std::env::var("SYNERGY_GENESIS_FILE").ok();
    std::env::set_var("SYNERGY_GENESIS_FILE", &fixture.path);
    let resolved = crate::genesis::canonical_genesis()
        .expect("canonical_genesis must resolve the configured fixture")
        .hash()
        .to_string();
    match previous {
        Some(value) => std::env::set_var("SYNERGY_GENESIS_FILE", value),
        None => std::env::remove_var("SYNERGY_GENESIS_FILE"),
    }
    assert_eq!(resolved, fixture.genesis_hash);
}
