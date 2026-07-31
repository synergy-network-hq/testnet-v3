//! Produces one new Chain 1266 incarnation without changing allocations,
//! validator identities, custody material, or deployment execution state.
//!
//! The incarnation and state-schema fields are inserted into existing
//! Genesis-hash inputs before all dependent integrity roots are recomputed.

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use synergy_testnet::genesis::{load_genesis_from_path, recompute_testnet_v3_candidate_integrity};

const CHAIN_ID: u64 = 1266;
const NEW_INCARNATION: u64 = 4;
const CONSENSUS_STATE_SCHEMA_VERSION: u64 = 4;

fn fail(message: impl AsRef<str>) -> ! {
    eprintln!("advance-testnet-v3-chain-incarnation: {}", message.as_ref());
    std::process::exit(1);
}

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn encode(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .unwrap_or_else(|error| fail(format!("encode Genesis: {error}")));
    bytes.push(b'\n');
    bytes
}

fn transformed(path: &Path) -> (Value, Vec<u8>) {
    let bytes =
        fs::read(path).unwrap_or_else(|error| fail(format!("read {}: {error}", path.display())));
    let mut value: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| fail(format!("parse {}: {error}", path.display())));
    if value["network"]["chain_id"] != Value::from(CHAIN_ID) {
        fail(format!("{} is not Chain 1266", path.display()));
    }
    let prior = value["network"]["chain_incarnation"].as_u64().unwrap_or(0);
    if prior > NEW_INCARNATION {
        fail(format!(
            "{} has incarnation {prior}; refusing a non-incrementing transition to {NEW_INCARNATION}",
            path.display()
        ));
    }
    value["network"]["chain_incarnation"] = Value::from(NEW_INCARNATION);
    value["consensus"]["state_schema_version"] = Value::from(CONSENSUS_STATE_SCHEMA_VERSION);
    value["consensus"]["state_directory_namespace"] =
        Value::String(format!("chain-{CHAIN_ID}/incarnation-{NEW_INCARNATION}"));
    recompute_testnet_v3_candidate_integrity(&mut value)
        .unwrap_or_else(|error| fail(format!("recompute {}: {error}", path.display())));
    (value.clone(), encode(&value))
}

fn publish(path: &Path, bytes: &[u8], validate_runtime: bool) {
    let temporary = path.with_extension(format!("incarnation-4-{}", std::process::id()));
    fs::write(&temporary, bytes)
        .unwrap_or_else(|error| fail(format!("write {}: {error}", temporary.display())));
    if validate_runtime {
        load_genesis_from_path(&temporary)
            .unwrap_or_else(|error| fail(format!("runtime rejected {}: {error}", path.display())));
    }
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
    let relative_paths = [
        "genesis.testnet-v3.identity-assigned.json",
        "runtime/config/genesis.testnet-v3.test-fixture.json",
        "launch/production-genesis-ceremony/genesis.testnet-v3.final-candidate.json",
        "launch/production-node-configs/canonical-genesis/genesis.json",
    ];
    let mut canonical_hash = None;
    for relative in relative_paths {
        let path = root.join(relative);
        let (value, bytes) = transformed(&path);
        let hash = value["integrity"]["genesis_hash"]
            .as_str()
            .unwrap_or_else(|| fail(format!("{relative} lacks a Genesis hash")));
        if relative != "runtime/config/genesis.testnet-v3.test-fixture.json" {
            match canonical_hash.as_deref() {
                None => canonical_hash = Some(hash.to_string()),
                Some(expected) if expected == hash => {}
                Some(expected) => fail(format!(
                    "canonical Genesis copies diverge: expected {expected}, found {hash} in {relative}"
                )),
            }
        }
        if apply {
            publish(
                &path,
                &bytes,
                relative != "runtime/config/genesis.testnet-v3.test-fixture.json",
            );
        }
        println!(
            "{} mode={} incarnation={} state_schema={} genesis_hash={} file_sha256={}",
            relative,
            if apply { "APPLY" } else { "CHECK" },
            NEW_INCARNATION,
            CONSENSUS_STATE_SCHEMA_VERSION,
            hash,
            sha256(&bytes)
        );
    }
}
