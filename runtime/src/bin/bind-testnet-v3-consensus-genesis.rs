//! Reconciles the pre-deployment Testnet-v3 Genesis and its explicit test
//! fixture to the one finalized consensus-parameter manifest.
//!
//! The operation is public-input-only. It preserves byte-for-byte backups,
//! validates each recomputed candidate before publication, and never touches
//! custody material or ceremony execution evidence.

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use synergy_testnet::consensus_parameters::load_finalized_consensus_parameters;
use synergy_testnet::genesis::{
    bind_testnet_v3_genesis_consensus_parameters, load_genesis_from_path,
};

const DECISION_ID: &str = "TV3-POSY-PARAMS-2026-07-28-01";
const DECISION_FILE: &str = "launch/TESTNET_V3_CONSENSUS_PARAMETER_RELEASE_DECISION.md";
const PARAMETERS_FILE: &str = "launch/TESTNET_V3_CONSENSUS_PARAMETERS.json";
const GENESIS_FILE: &str = "genesis.testnet-v3.identity-assigned.json";
const FIXTURE_FILE: &str = "runtime/config/genesis.testnet-v3.test-fixture.json";
const BACKUP_DIR: &str = "launch/production-genesis-ceremony/parameter-binding-backups";

fn fail(message: impl AsRef<str>) -> ! {
    eprintln!("bind-testnet-v3-consensus-genesis: {}", message.as_ref());
    std::process::exit(1);
}

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|error| fail(format!("read {}: {error}", path.display())))
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn pretty_json(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .unwrap_or_else(|error| fail(format!("encode JSON: {error}")));
    bytes.push(b'\n');
    bytes
}

fn bind_document(
    path: &Path,
    parameters: &synergy_testnet::consensus_parameters::LoadedConsensusParameters,
    decision_sha256: &str,
) -> (Value, Vec<u8>, Vec<u8>) {
    let original = read(path);
    let mut value: Value = serde_json::from_slice(&original)
        .unwrap_or_else(|error| fail(format!("parse {}: {error}", path.display())));
    bind_testnet_v3_genesis_consensus_parameters(&mut value, parameters, decision_sha256)
        .unwrap_or_else(|error| fail(format!("bind {}: {error}", path.display())));
    let bytes = pretty_json(&value);
    (value, bytes, original)
}

fn write_backup(path: &Path, bytes: &[u8]) {
    if path.exists() {
        return;
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .unwrap_or_else(|error| fail(format!("create {}: {error}", parent.display())));
    }
    fs::write(path, bytes)
        .unwrap_or_else(|error| fail(format!("write backup {}: {error}", path.display())));
}

fn publish(path: &Path, bytes: &[u8]) {
    let temporary = path.with_extension(format!("parameter-bound-{}", std::process::id()));
    fs::write(&temporary, bytes)
        .unwrap_or_else(|error| fail(format!("write {}: {error}", temporary.display())));
    fs::rename(&temporary, path)
        .unwrap_or_else(|error| fail(format!("publish {}: {error}", path.display())));
}

fn main() {
    let apply = match std::env::args().nth(1).as_deref() {
        Some("--check") => false,
        Some("--apply") => true,
        _ => fail("use exactly one of --check or --apply"),
    };
    if std::env::args().len() != 2 {
        fail("use exactly one of --check or --apply");
    }

    let root = repo();
    let parameters = load_finalized_consensus_parameters(root.join(PARAMETERS_FILE))
        .unwrap_or_else(|error| fail(format!("load finalized parameters: {error}")));
    if parameters.manifest.governance_approval_id != DECISION_ID
        || parameters.manifest.epoch_length_slots != Some(1_000)
        || parameters.manifest.target_block_time_ms != 2_000
        || parameters.manifest.proposal_timeout_ms != 1_500
        || parameters.manifest.prevote_timeout_ms != 1_500
        || parameters.manifest.precommit_timeout_ms != 1_500
        || parameters.manifest.max_round_timeout_ms != 10_000
    {
        fail("manifest does not match the approved Testnet-v3 launch timing profile");
    }

    let decision_bytes = read(&root.join(DECISION_FILE));
    let decision_marker = format!("Decision ID: `{DECISION_ID}`");
    if !decision_bytes
        .windows(decision_marker.len())
        .any(|window| window == decision_marker.as_bytes())
    {
        fail("release decision record is missing the exact approved Decision ID");
    }
    let decision_sha256 = sha256(&decision_bytes);

    let genesis_path = root.join(GENESIS_FILE);
    let fixture_path = root.join(FIXTURE_FILE);
    let (genesis, genesis_bytes, original_genesis) =
        bind_document(&genesis_path, &parameters, &decision_sha256);
    let (fixture, fixture_bytes, original_fixture) =
        bind_document(&fixture_path, &parameters, &decision_sha256);

    let check_path =
        root.join("launch/production-genesis-ceremony/genesis.parameter-bound.check.json");
    fs::write(&check_path, &genesis_bytes)
        .unwrap_or_else(|error| fail(format!("write {}: {error}", check_path.display())));
    load_genesis_from_path(&check_path)
        .unwrap_or_else(|error| fail(format!("runtime rejected parameter-bound Genesis: {error}")));
    fs::remove_file(&check_path)
        .unwrap_or_else(|error| fail(format!("remove {}: {error}", check_path.display())));

    if apply {
        let backup_dir = root.join(BACKUP_DIR);
        write_backup(
            &backup_dir.join("genesis.testnet-v3.identity-assigned.pre-parameter-binding.json"),
            &original_genesis,
        );
        write_backup(
            &backup_dir.join("genesis.testnet-v3.test-fixture.pre-parameter-binding.json"),
            &original_fixture,
        );
        publish(&genesis_path, &genesis_bytes);
        publish(&fixture_path, &fixture_bytes);
    }

    println!(
        "mode                  : {}",
        if apply { "APPLY" } else { "CHECK" }
    );
    println!("decision ID           : {DECISION_ID}");
    println!("decision sha256       : {decision_sha256}");
    println!(
        "manifest sha256       : {}",
        sha256(&parameters.canonical_bytes)
    );
    println!("parameter root        : {}", parameters.root.to_hex());
    println!("genesis sha256        : {}", sha256(&genesis_bytes));
    println!(
        "genesis hash          : {}",
        genesis["integrity"]["genesis_hash"].as_str().unwrap()
    );
    println!("fixture sha256        : {}", sha256(&fixture_bytes));
    println!(
        "fixture genesis hash  : {}",
        fixture["integrity"]["genesis_hash"].as_str().unwrap()
    );
}
