//! Assembles a public, unsigned fresh-P3 Genesis candidate.
//!
//! The command takes only public inputs. It never signs, decrypts, creates
//! keys, or deploys. It refuses to construct an intermediate candidate that
//! binds just consensus or just ETDAG: the finalized P3 manifest, exact
//! five-validator activation binding, and governed ETDAG policy must all be
//! supplied together before the candidate integrity roots are recomputed.

use serde::de::DeserializeOwned;
use sha2::{Digest as _, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use synergy_testnet::consensus::simplified_posy::GenesisBoundSimplifiedActivation;
use synergy_testnet::consensus_parameters::load_finalized_consensus_parameters;
use synergy_testnet::etdag_governance::EtdagGovernedGenesisBinding;
use synergy_testnet::genesis::{
    bind_testnet_v3_genesis_simplified_posy_authorities, load_genesis_from_path,
};

fn usage() -> ! {
    eprintln!(
        "usage: prepare-fresh-posy-v3-genesis --source-genesis PATH --consensus-manifest PATH --consensus-decision PATH --activation PATH --etdag-binding PATH --output PATH\n\nAll inputs are public. Output must be a new path. This command never signs, decrypts, creates keys, or deploys."
    );
    std::process::exit(2);
}

fn fail(message: impl AsRef<str>) -> ! {
    eprintln!("prepare-fresh-posy-v3-genesis: {}", message.as_ref());
    std::process::exit(1);
}

fn read_bytes(path: &Path, label: &str) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|error| fail(format!("read {label} {}: {error}", path.display())))
}

fn read_json<T: DeserializeOwned>(path: &Path, label: &str) -> T {
    serde_json::from_slice(&read_bytes(path, label))
        .unwrap_or_else(|error| fail(format!("decode {label} {}: {error}", path.display())))
}

fn required_string<'a>(value: &'a serde_json::Value, pointer: &str, label: &str) -> &'a str {
    value
        .pointer(pointer)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| fail(format!("fresh P3 source Genesis has no canonical {label}")))
}

fn contains_retired_value(value: &serde_json::Value, retired: &str) -> bool {
    match value {
        serde_json::Value::String(found) => found == retired,
        serde_json::Value::Array(values) => values
            .iter()
            .any(|entry| contains_retired_value(entry, retired)),
        serde_json::Value::Object(values) => values
            .values()
            .any(|entry| contains_retired_value(entry, retired)),
        _ => false,
    }
}

/// Rejects a staged record from the retired chain before it can reach the
/// atomic P3 binder.  The binder intentionally only owns the authority
/// subtrees; this guard establishes that the deployment and account state
/// were produced for the separate fresh chain rather than rebased from P2.
fn require_fresh_p3_source_genesis(value: &serde_json::Value) {
    let chain_id = value
        .pointer("/network/chain_id")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_else(|| fail("fresh P3 source Genesis has no numeric Chain ID"));
    if chain_id != 1266
        || required_string(value, "/network/network_id", "technical network ID") != "testnet"
        || required_string(value, "/network/consensus_version", "consensus version") != "posy/3.0"
        || required_string(
            value,
            "/genesis_deployment/network_id",
            "deployment technical network ID",
        ) != "testnet"
        || required_string(
            value,
            "/genesis_deployment/release_id",
            "deployment release ID",
        ) != "testnet-v3"
        || required_string(
            value,
            "/genesis_deployment/synq_network_id",
            "deployment SynQ network ID",
        ) != "synergy-testnet"
    {
        fail("source Genesis is not a fresh Chain-1266/Testnet-v3 PoSy P3 deployment record");
    }
    for retired in ["posy/2.2", "synergy-testnet-v3", "ProofOfSynergy"] {
        if contains_retired_value(value, retired) {
            fail(format!(
                "source Genesis contains retired chain value {retired:?}; create a new P3 deployment record"
            ));
        }
    }
}

fn arg_path(args: &[String], flag: &str) -> PathBuf {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| PathBuf::from(&pair[1]))
        .unwrap_or_else(|| usage())
}

fn require_exact_flags(args: &[String]) {
    const FLAGS: [&str; 6] = [
        "--source-genesis",
        "--consensus-manifest",
        "--consensus-decision",
        "--activation",
        "--etdag-binding",
        "--output",
    ];
    if args.len() != FLAGS.len() * 2 {
        usage();
    }
    for flag in FLAGS {
        if args.iter().filter(|value| value.as_str() == flag).count() != 1 {
            usage();
        }
    }
}

fn write_new(path: &Path, bytes: &[u8]) {
    if path.exists() {
        fail(format!(
            "refusing to overwrite existing output {}; choose a new candidate path",
            path.display()
        ));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .unwrap_or_else(|error| fail(format!("create {}: {error}", parent.display())));
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap_or_else(|error| fail(format!("create {}: {error}", path.display())));
    file.write_all(bytes)
        .unwrap_or_else(|error| fail(format!("write {}: {error}", path.display())));
    file.sync_all()
        .unwrap_or_else(|error| fail(format!("sync {}: {error}", path.display())));
}

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    require_exact_flags(&args);
    let source_genesis = arg_path(&args, "--source-genesis");
    let consensus_manifest = arg_path(&args, "--consensus-manifest");
    let consensus_decision = arg_path(&args, "--consensus-decision");
    let activation_path = arg_path(&args, "--activation");
    let etdag_binding_path = arg_path(&args, "--etdag-binding");
    let output = arg_path(&args, "--output");

    let loaded = load_finalized_consensus_parameters(&consensus_manifest)
        .unwrap_or_else(|error| fail(format!("load finalized P3 consensus manifest: {error}")));
    let activation: GenesisBoundSimplifiedActivation =
        read_json(&activation_path, "five-validator activation binding");
    let etdag_binding = EtdagGovernedGenesisBinding::from_canonical_bytes(&read_bytes(
        &etdag_binding_path,
        "ETDAG governed Genesis binding",
    ))
    .unwrap_or_else(|error| fail(format!("load governed ETDAG binding: {error}")));
    let decision_bytes = read_bytes(&consensus_decision, "consensus decision record");
    let decision_id = loaded
        .manifest
        .governance_approval_id()
        .unwrap_or_else(|error| fail(format!("read finalized P3 decision identifier: {error}")));
    let decision_marker = format!("Decision ID: `{decision_id}`");
    if !decision_bytes
        .windows(decision_marker.len())
        .any(|window| window == decision_marker.as_bytes())
    {
        fail("consensus decision record does not carry the exact finalized P3 Decision ID");
    }
    let decision_sha256 = hex::encode(Sha256::digest(decision_bytes));
    let mut candidate: serde_json::Value = read_json(&source_genesis, "source Genesis");
    require_fresh_p3_source_genesis(&candidate);
    bind_testnet_v3_genesis_simplified_posy_authorities(
        &mut candidate,
        &loaded,
        &decision_sha256,
        &activation,
        &etdag_binding,
    )
    .unwrap_or_else(|error| fail(format!("bind fresh P3 authorities: {error}")));

    let mut encoded = serde_json::to_vec_pretty(&candidate)
        .unwrap_or_else(|error| fail(format!("encode fresh P3 candidate: {error}")));
    encoded.push(b'\n');
    write_new(&output, &encoded);
    let checked = load_genesis_from_path(&output).unwrap_or_else(|error| {
        fail(format!(
            "runtime rejected emitted fresh P3 candidate: {error}"
        ))
    });
    println!(
        "{{\n  \"result\": \"UNSIGNED_FRESH_P3_GENESIS_CANDIDATE_WRITTEN\",\n  \"candidate\": \"{}\",\n  \"candidate_sha256\": \"{}\",\n  \"genesis_hash\": \"{}\",\n  \"consensus_parameter_root_sha3_512\": \"{}\",\n  \"etdag_parameter_root_sha3_512\": \"{}\",\n  \"etdag_fee_schedule_root_sha3_512\": \"{}\"\n}}",
        output.display(),
        hex::encode(Sha256::digest(&encoded)),
        checked.hash(),
        loaded.root.to_hex(),
        etdag_binding.parameter_artifact.etdag_parameter_root_sha3_512.to_hex(),
        etdag_binding.fee_schedule_artifact.etdag_fee_schedule_root_sha3_512.to_hex(),
    );
}
