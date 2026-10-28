//! Builds the unsigned immutable-Genesis P1 activation record.
//!
//! This is intentionally separate from Genesis tooling. The record is later
//! signed by the existing release/start Governance Authority; this command
//! never reads custody material.

use std::env;
use std::fs;
use std::path::PathBuf;
use synergy_testnet::consensus_activation::build_consensus_activation_manifest;
use synergy_testnet::genesis::load_genesis_from_path;

fn fail(message: impl AsRef<str>) -> ! {
    eprintln!("build-chain1266-consensus-activation: {}", message.as_ref());
    std::process::exit(1);
}

fn arg(args: &[String], flag: &str) -> String {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| pair[1].clone())
        .unwrap_or_else(|| fail(format!("missing {flag} <VALUE>")))
}

fn main() {
    let args = env::args().collect::<Vec<_>>();
    let desired_state = PathBuf::from(arg(&args, "--desired-state"));
    let genesis_path = PathBuf::from(arg(&args, "--genesis"));
    let output = PathBuf::from(arg(&args, "--output"));
    let genesis = load_genesis_from_path(genesis_path)
        .unwrap_or_else(|error| fail(format!("load immutable canonical Genesis: {error}")));
    let activation = build_consensus_activation_manifest(&desired_state, &genesis)
        .unwrap_or_else(|error| fail(error));
    let mut encoded = serde_json::to_vec_pretty(&activation)
        .unwrap_or_else(|error| fail(format!("encode consensus activation: {error}")));
    encoded.push(b'\n');
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .unwrap_or_else(|error| fail(format!("create {}: {error}", parent.display())));
    }
    fs::write(&output, encoded)
        .unwrap_or_else(|error| fail(format!("write {}: {error}", output.display())));
    println!("CHAIN1266_CONSENSUS_ACTIVATION_BUILT {}", output.display());
}
