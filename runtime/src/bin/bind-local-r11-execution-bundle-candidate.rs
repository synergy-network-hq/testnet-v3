//! Binds one verified LOCAL_R11 execution envelope into a fresh P3 candidate.
//!
//! The template provides the already-governed consensus and ETDAG policy; this
//! tool refuses to copy its historical execution roots.  It validates the
//! supplied canonical Genesis and current bundle, replaces only execution
//! bindings, recomputes the membership anchor with the production type, and
//! publishes a new candidate without overwriting evidence.

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use synergy_testnet::etdag_governance::EtdagGovernedMembershipAnchor;
use synergy_testnet::execution::GenesisExecutionSnapshot;
use synergy_testnet::genesis::load_genesis_from_path;
use synergy_testnet::genesis_deployment::compute_genesis_receipt_root;
use synergy_testnet::testnet_v3_release_approval::{
    TestnetV3GenesisExecutionBundle, TESTNET_V3_GENESIS_EXECUTION_BUNDLE_ARTIFACT_TYPE,
    TESTNET_V3_GENESIS_EXECUTION_BUNDLE_SCHEMA_VERSION,
};

fn fail(message: impl AsRef<str>) -> ! {
    eprintln!(
        "bind-local-r11-execution-bundle-candidate: {}",
        message.as_ref()
    );
    std::process::exit(1);
}

fn usage() -> ! {
    fail("usage: bind-local-r11-execution-bundle-candidate --genesis PATH --template PATH --bundle PATH --authority-record PATH --output PATH")
}

fn path(args: &[String], name: &str) -> PathBuf {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| PathBuf::from(&pair[1]))
        .unwrap_or_else(|| usage())
}

fn read(path: &Path, label: &str) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|error| fail(format!("read {label} {}: {error}", path.display())))
}

fn json(path: &Path, label: &str) -> Value {
    serde_json::from_slice(&read(path, label))
        .unwrap_or_else(|error| fail(format!("parse {label} {}: {error}", path.display())))
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn require_string<'a>(value: &'a Value, pointer: &str, label: &str) -> &'a str {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| fail(format!("{label} is missing {pointer}")))
}

fn write_new(path: &Path, bytes: &[u8]) {
    let parent = path
        .parent()
        .unwrap_or_else(|| fail("output path has no parent"));
    fs::create_dir_all(parent)
        .unwrap_or_else(|error| fail(format!("create {}: {error}", parent.display())));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap_or_else(|error| fail(format!("create new output {}: {error}", path.display())));
    file.write_all(bytes)
        .unwrap_or_else(|error| fail(format!("write {}: {error}", path.display())));
    file.sync_all()
        .unwrap_or_else(|error| fail(format!("sync {}: {error}", path.display())));
}

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let flags = [
        "--genesis",
        "--template",
        "--bundle",
        "--authority-record",
        "--output",
    ];
    if args.len() != flags.len() * 2
        || flags
            .iter()
            .any(|flag| args.iter().filter(|arg| *arg == flag).count() != 1)
    {
        usage();
    }
    let genesis_path = path(&args, "--genesis");
    let template_path = path(&args, "--template");
    let bundle_path = path(&args, "--bundle");
    let authority_path = path(&args, "--authority-record");
    let output = path(&args, "--output");
    if output.exists() {
        fail(format!("output {} already exists", output.display()));
    }

    let genesis = load_genesis_from_path(&genesis_path)
        .unwrap_or_else(|error| fail(format!("load current canonical Genesis: {error}")));
    let bundle_bytes = read(&bundle_path, "execution bundle");
    let bundle: TestnetV3GenesisExecutionBundle = serde_json::from_slice(&bundle_bytes)
        .unwrap_or_else(|error| fail(format!("parse execution bundle: {error}")));
    if bundle.schema_version != TESTNET_V3_GENESIS_EXECUTION_BUNDLE_SCHEMA_VERSION
        || bundle.artifact_type != TESTNET_V3_GENESIS_EXECUTION_BUNDLE_ARTIFACT_TYPE
        || bundle.chain_id != 1266
        || bundle.network_id != "testnet"
        || bundle.release_id != "testnet-v3"
        || bundle.canonical_genesis_hash != genesis.hash().to_string()
        || bundle.deployment_count != 9
        || bundle.initialization_count != 27
        || bundle.deployment_receipts.len() != 9
        || bundle.initialization_receipts.len() != 27
    {
        fail("execution bundle has an invalid immutable binding or receipt cardinality");
    }
    let restored = bundle
        .execution_state
        .restore_testnet_v3()
        .unwrap_or_else(|error| fail(format!("restore execution bundle state: {error}")));
    let recaptured = GenesisExecutionSnapshot::capture_testnet_v3(&restored)
        .unwrap_or_else(|error| fail(format!("recapture execution bundle state: {error}")));
    if recaptured.state_root != bundle.execution_state_root
        || recaptured.aivm_state_root != bundle.aivm_state_root
        || compute_genesis_receipt_root(
            &bundle.deployment_receipts,
            &bundle.initialization_receipts,
        )
        .unwrap_or_else(|error| fail(format!("recompute bundle receipt root: {error}")))
        .to_hex()
            != bundle.receipt_root
    {
        fail("execution bundle roots do not recompute");
    }

    let mut candidate = json(&template_path, "candidate template");
    let mut comparable = candidate.clone();
    comparable
        .as_object_mut()
        .unwrap_or_else(|| fail("candidate template is not an object"))
        .remove("genesis_deployment");
    comparable
        .as_object_mut()
        .unwrap()
        .remove("etdag_membership_anchor");
    comparable
        .as_object_mut()
        .unwrap()
        .remove("genesis_execution_snapshot");
    if comparable != genesis.value().clone() {
        fail("candidate template differs from the supplied canonical Genesis outside binding overlays");
    }
    if require_string(&candidate, "/integrity/genesis_hash", "candidate template")
        != genesis.hash().to_string()
        || require_string(
            &candidate,
            "/genesis_deployment/network_id",
            "candidate template",
        ) != "testnet"
        || require_string(
            &candidate,
            "/genesis_deployment/release_id",
            "candidate template",
        ) != "testnet-v3"
        || require_string(
            &candidate,
            "/genesis_deployment/synq_network_id",
            "candidate template",
        ) != "synergy-testnet"
    {
        fail("candidate template has invalid immutable release identifiers");
    }
    candidate["genesis_deployment"]["candidate_input_id"] =
        Value::String(sha256(&read(&genesis_path, "canonical Genesis")));
    candidate["genesis_deployment"]["authority_record_sha256"] =
        Value::String(sha256(&read(&authority_path, "authority record")));
    candidate["genesis_deployment"]["post_deployment_execution_state_root"] =
        Value::String(bundle.execution_state_root.clone());
    candidate["genesis_deployment"]["post_deployment_aivm_state_root"] =
        Value::String(bundle.aivm_state_root.clone());
    candidate["genesis_deployment"]["receipt_root"] = Value::String(bundle.receipt_root.clone());
    candidate["execution"]["genesis_execution_state_root"] =
        Value::String(bundle.execution_state_root.clone());
    candidate["execution"]["genesis_aivm_state_root"] =
        Value::String(bundle.aivm_state_root.clone());
    candidate["execution"]["genesis_receipt_root"] = Value::String(bundle.receipt_root.clone());
    candidate["integrity"]["post_deployment_execution_state_root"] =
        Value::String(bundle.execution_state_root.clone());
    candidate["integrity"]["post_deployment_aivm_state_root"] =
        Value::String(bundle.aivm_state_root.clone());
    let mut anchor: EtdagGovernedMembershipAnchor = serde_json::from_value(
        candidate["etdag_membership_anchor"].clone(),
    )
    .unwrap_or_else(|error| fail(format!("parse governed ETDAG membership anchor: {error}")));
    anchor.deployed_execution_state_root = bundle.execution_state_root.clone();
    anchor.anchor_digest = anchor.expected_anchor_digest().unwrap_or_else(|error| {
        fail(format!(
            "recompute governed ETDAG membership anchor: {error}"
        ))
    });
    candidate["etdag_membership_anchor"] = serde_json::to_value(anchor)
        .unwrap_or_else(|error| fail(format!("encode governed ETDAG membership anchor: {error}")));
    candidate["genesis_execution_snapshot"] = serde_json::json!({
        "schema_version": TESTNET_V3_GENESIS_EXECUTION_BUNDLE_SCHEMA_VERSION,
        "artifact_type": TESTNET_V3_GENESIS_EXECUTION_BUNDLE_ARTIFACT_TYPE,
        "sha256": sha256(&bundle_bytes),
        "execution_state_canonical_sha256": sha256(&serde_json::to_vec(&bundle.execution_state)
            .unwrap_or_else(|error| fail(format!("canonicalize execution state: {error}")))),
    });
    let mut bytes = serde_json::to_vec_pretty(&candidate)
        .unwrap_or_else(|error| fail(format!("encode candidate: {error}")));
    bytes.push(b'\n');
    write_new(&output, &bytes);
    println!("GENESIS_EXECUTION_BUNDLE_VERIFIED=YES");
    println!("EXECUTION_STATE_ROOT_VERIFIED=YES");
    println!("AIVM_STATE_ROOT_VERIFIED=YES");
    println!("RECEIPT_ROOT_VERIFIED=YES");
    println!("LOCAL_R11_SNAPSHOT_BOUND_CANDIDATE_WRITTEN=YES");
    println!("CANDIDATE_SHA256={}", sha256(&bytes));
}
