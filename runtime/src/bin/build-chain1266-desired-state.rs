//! Deterministically builds the exact desired-state manifest later attested by
//! the tag-driven release workflow. This tool never signs or loads custody
//! material.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use synergy_testnet::consensus::testnet_v3_bootstrap::load_testnet_v3_genesis_bootstrap;
use synergy_testnet::genesis::load_genesis_from_path;
use synergy_testnet::synergy_types::{
    Epoch, SYNERGY_TESTNET_V3_CHAIN_ID, TESTNET_V3_CHAIN_INCARNATION,
    TESTNET_V3_CONSENSUS_STATE_SCHEMA_VERSION,
};

fn fail(message: impl AsRef<str>) -> ! {
    eprintln!("build-chain1266-desired-state: {}", message.as_ref());
    std::process::exit(1);
}

fn arg_value(args: &[String], flag: &str) -> String {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| pair[1].clone())
        .unwrap_or_else(|| fail(format!("missing {flag} <VALUE>")))
}

fn repeated_bindings(args: &[String], flag: &str) -> BTreeMap<String, PathBuf> {
    let mut bindings = BTreeMap::new();
    let mut index = 0usize;
    while index < args.len() {
        if args[index] != flag {
            index += 1;
            continue;
        }
        let value = args
            .get(index + 1)
            .unwrap_or_else(|| fail(format!("missing value after {flag}")));
        let (role, path) = value
            .split_once('=')
            .unwrap_or_else(|| fail(format!("{flag} requires ROLE=PATH")));
        if role.trim().is_empty()
            || bindings
                .insert(role.to_string(), PathBuf::from(path))
                .is_some()
        {
            fail(format!(
                "{flag} contains an empty or duplicate role: {role}"
            ));
        }
        index += 2;
    }
    if bindings.is_empty() {
        fail(format!("{flag} must be supplied at least once"));
    }
    bindings
}

fn sha256_file(path: &Path) -> String {
    let bytes =
        fs::read(path).unwrap_or_else(|error| fail(format!("read {}: {error}", path.display())));
    hex::encode(Sha256::digest(bytes))
}

fn require_revision(name: &str, value: &str) {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        fail(format!("{name} must be a full lowercase Git revision"));
    }
}

fn main() {
    let args = env::args().collect::<Vec<_>>();
    let release_id = arg_value(&args, "--release-id");
    let release_tag = arg_value(&args, "--release-tag");
    let testnet_revision = arg_value(&args, "--testnet-revision");
    let synq_revision = arg_value(&args, "--synq-revision");
    let aegis_revision = arg_value(&args, "--aegis-revision");
    let genesis_path = PathBuf::from(arg_value(&args, "--genesis"));
    let start_authority_path = PathBuf::from(arg_value(&args, "--start-authority"));
    let output_path = PathBuf::from(arg_value(&args, "--output"));
    let artifacts = repeated_bindings(&args, "--artifact");
    let configurations = repeated_bindings(&args, "--configuration");
    for (name, revision) in [
        ("Testnet-v3 revision", &testnet_revision),
        ("SynQ revision", &synq_revision),
        ("Aegis revision", &aegis_revision),
    ] {
        require_revision(name, revision);
    }

    let genesis = load_genesis_from_path(&genesis_path)
        .unwrap_or_else(|error| fail(format!("load canonical Genesis: {error}")));
    let bootstrap = load_testnet_v3_genesis_bootstrap(&genesis)
        .unwrap_or_else(|error| fail(format!("load Genesis validator set: {error}")));
    let validator_set_root = bootstrap
        .validator_set
        .active_for_epoch(Epoch(0))
        .hash()
        .unwrap_or_else(|error| fail(format!("derive active validator-set root: {error}")))
        .to_hex();
    let start_authority: Value =
        serde_json::from_slice(&fs::read(&start_authority_path).unwrap_or_else(|error| {
            fail(format!(
                "read start authority {}: {error}",
                start_authority_path.display()
            ))
        }))
        .unwrap_or_else(|error| fail(format!("parse start authority: {error}")));
    if start_authority["signature_algorithm"] != "ML-DSA-87"
        || start_authority["signature_domain"]
            != synergy_testnet::consensus_start::CHAIN1266_START_SIGNATURE_DOMAIN
        || !start_authority["public_key_fingerprint"]
            .as_str()
            .is_some_and(|value| value.starts_with("sha256:"))
        || !start_authority["public_key_base64"].is_string()
    {
        fail("start authority has an invalid ML-DSA-87 profile");
    }

    let artifact_hashes = artifacts
        .iter()
        .map(|(role, path)| (role.clone(), Value::String(sha256_file(path))))
        .collect::<serde_json::Map<_, _>>();
    let configuration_hashes = configurations
        .iter()
        .map(|(role, path)| (role.clone(), Value::String(sha256_file(path))))
        .collect::<serde_json::Map<_, _>>();
    let manifest = json!({
        "schema_version": 1,
        "release_id": release_id,
        "release_tag": release_tag,
        "chain": {
            "chain_id": SYNERGY_TESTNET_V3_CHAIN_ID,
            "incarnation": TESTNET_V3_CHAIN_INCARNATION,
            "genesis_hash": genesis.hash(),
            "validator_set_root": validator_set_root,
            "quorum": 5
        },
        "source": {
            "testnet_v3_revision": testnet_revision,
            "synq_revision": synq_revision,
            "aegis_revision": aegis_revision
        },
        "state": {
            "consensus_schema_version": TESTNET_V3_CONSENSUS_STATE_SCHEMA_VERSION,
            "directory_namespace": format!(
                "chain-{}/incarnation-{}",
                SYNERGY_TESTNET_V3_CHAIN_ID,
                TESTNET_V3_CHAIN_INCARNATION
            )
        },
        "start_authority": start_authority,
        "artifacts": artifact_hashes,
        "configuration": configuration_hashes
    });
    let mut encoded = serde_json::to_vec_pretty(&manifest)
        .unwrap_or_else(|error| fail(format!("serialize desired state: {error}")));
    encoded.push(b'\n');
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .unwrap_or_else(|error| fail(format!("create {}: {error}", parent.display())));
    }
    fs::write(&output_path, &encoded)
        .unwrap_or_else(|error| fail(format!("write {}: {error}", output_path.display())));
    println!(
        "{}  {}",
        hex::encode(Sha256::digest(&encoded)),
        output_path.display()
    );
}
