//! Builds an isolated qualification Genesis and six disposable ML-DSA-65
//! signer keys. The public Genesis and production custody material are never
//! modified or read.

use base64::{engine::general_purpose, Engine as _};
use serde_json::{json, Value};
use sha2::Digest;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use synergy_testnet::crypto::pqc::{PQCAlgorithm, PQCManager};
use synergy_testnet::genesis::{load_genesis_from_path, recompute_testnet_v3_candidate_integrity};

fn fail(message: impl AsRef<str>) -> ! {
    eprintln!(
        "build-chain1266-private-ring-material: {}",
        message.as_ref()
    );
    std::process::exit(1);
}

fn arg(args: &[String], flag: &str) -> PathBuf {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| PathBuf::from(&pair[1]))
        .unwrap_or_else(|| fail(format!("missing {flag} <PATH>")))
}

fn replace_exact_strings(value: &mut Value, replacements: &BTreeMap<String, String>) {
    match value {
        Value::String(text) => {
            if let Some(replacement) = replacements.get(text) {
                *text = replacement.clone();
            }
        }
        Value::Array(items) => {
            for item in items {
                replace_exact_strings(item, replacements);
            }
        }
        Value::Object(fields) => {
            for field in fields.values_mut() {
                replace_exact_strings(field, replacements);
            }
        }
        _ => {}
    }
}

#[cfg(unix)]
fn restrict_private_key(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .unwrap_or_else(|error| fail(format!("protect {}: {error}", path.display())));
}

#[cfg(not(unix))]
fn restrict_private_key(_path: &Path) {}

fn main() {
    let args = env::args().collect::<Vec<_>>();
    let source_path = arg(&args, "--source-genesis");
    let output_path = arg(&args, "--output-genesis");
    let key_root = arg(&args, "--key-root");
    let bytes = fs::read(&source_path)
        .unwrap_or_else(|error| fail(format!("read {}: {error}", source_path.display())));
    let mut genesis: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| fail(format!("parse source Genesis: {error}")));

    let active = genesis
        .get("preconfigured_validators")
        .and_then(Value::as_array)
        .unwrap_or_else(|| fail("source Genesis omits preconfigured_validators"))
        .iter()
        .filter(|record| record.get("status").and_then(Value::as_str) == Some("active_at_genesis"))
        .map(|record| {
            let validator_id = record
                .get("validator_id")
                .and_then(Value::as_str)
                .unwrap_or_else(|| fail("active validator omits validator_id"))
                .to_string();
            let old_public_key = record
                .get("consensus_public_key")
                .and_then(Value::as_str)
                .unwrap_or_else(|| fail("active validator omits consensus_public_key"))
                .to_string();
            (validator_id, old_public_key)
        })
        .collect::<Vec<_>>();
    if active.len() != 6 {
        fail(format!(
            "qualification Genesis requires six active validators; found {}",
            active.len()
        ));
    }

    fs::create_dir_all(&key_root)
        .unwrap_or_else(|error| fail(format!("create {}: {error}", key_root.display())));
    let mut manager = PQCManager::new();
    let mut replacements = BTreeMap::new();
    let mut public_records = Vec::new();
    for (validator_id, old_public_key) in active {
        let (public_key, private_key) = manager
            .generate_keypair(PQCAlgorithm::MLDSA65)
            .unwrap_or_else(|error| {
                fail(format!("generate {validator_id} ML-DSA-65 key: {error}"))
            });
        let public_key_base64 = general_purpose::STANDARD.encode(&public_key.key_data);
        let private_key_base64 = general_purpose::STANDARD.encode(&private_key.key_data);
        replacements.insert(old_public_key, public_key_base64.clone());
        let validator_root = key_root.join(&validator_id);
        fs::create_dir_all(&validator_root)
            .unwrap_or_else(|error| fail(format!("create {}: {error}", validator_root.display())));
        let private_path = validator_root.join("mldsa65-consensus.private.key");
        fs::write(&private_path, format!("{private_key_base64}\n"))
            .unwrap_or_else(|error| fail(format!("write {}: {error}", private_path.display())));
        restrict_private_key(&private_path);
        public_records.push(json!({
            "validator_id": validator_id,
            "algorithm": "ML-DSA-65",
            "public_key_sha256": hex::encode(sha2::Sha256::digest(&public_key.key_data))
        }));
    }
    let (start_public_key, start_private_key) = manager
        .generate_keypair(PQCAlgorithm::MLDSA87)
        .unwrap_or_else(|error| fail(format!("generate qualification start authority: {error}")));
    let start_private_path = key_root.join("start-authority.private.key");
    fs::write(
        &start_private_path,
        format!(
            "{}\n",
            general_purpose::STANDARD.encode(&start_private_key.key_data)
        ),
    )
    .unwrap_or_else(|error| fail(format!("write {}: {error}", start_private_path.display())));
    restrict_private_key(&start_private_path);
    let start_public_path = key_root.join("start-authority.public.json");
    fs::write(
        &start_public_path,
        serde_json::to_vec_pretty(&json!({
            "signature_algorithm": "ML-DSA-87",
            "signature_domain": synergy_testnet::consensus_start::CHAIN1266_START_SIGNATURE_DOMAIN,
            "public_key_fingerprint": format!(
                "sha256:{}",
                hex::encode(sha2::Sha256::digest(&start_public_key.key_data))
            ),
            "public_key_base64": general_purpose::STANDARD.encode(&start_public_key.key_data)
        }))
        .unwrap(),
    )
    .unwrap_or_else(|error| fail(format!("write {}: {error}", start_public_path.display())));
    replace_exact_strings(&mut genesis, &replacements);
    genesis["env"] = Value::String("chain1266-private-qualification".to_string());
    recompute_testnet_v3_candidate_integrity(&mut genesis)
        .unwrap_or_else(|error| fail(format!("recompute qualification Genesis: {error}")));

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .unwrap_or_else(|error| fail(format!("create {}: {error}", parent.display())));
    }
    let mut encoded = serde_json::to_vec_pretty(&genesis)
        .unwrap_or_else(|error| fail(format!("serialize qualification Genesis: {error}")));
    encoded.push(b'\n');
    fs::write(&output_path, encoded)
        .unwrap_or_else(|error| fail(format!("write {}: {error}", output_path.display())));
    load_genesis_from_path(&output_path)
        .unwrap_or_else(|error| fail(format!("validate qualification Genesis: {error}")));
    let record_path = key_root.join("public-record.json");
    fs::write(
        &record_path,
        serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "purpose": "CHAIN1266_PRIVATE_QUALIFICATION_ONLY",
            "production_custody_material_used": false,
            "validators": public_records
        }))
        .unwrap(),
    )
    .unwrap_or_else(|error| fail(format!("write {}: {error}", record_path.display())));
    println!(
        "CHAIN1266_PRIVATE_RING_MATERIAL_READY genesis_hash={}",
        genesis["integrity"]["genesis_hash"]
            .as_str()
            .unwrap_or_default()
    );
}
