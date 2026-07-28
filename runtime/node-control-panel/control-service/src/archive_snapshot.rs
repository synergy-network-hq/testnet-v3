use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};
use tar::Builder;
use uuid::Uuid;

pub const SNAPSHOT_CLASS_VALIDATOR_PRUNED: &str = "validator-pruned";
pub const SOURCE_ROLE_ARCHIVE_VALIDATOR: &str = "archive_validator";
const RUNTIME_SNAPSHOT_SOURCE_ROLE: &str = "VALIDATOR";
pub const CATALOG_SCHEMA: &str = "synergy-archive-snapshot-catalog-v1";
pub const DISTRIBUTION_SCHEMA: &str = "synergy-archive-snapshot-distribution-v1";
pub const DISTRIBUTION_DOMAIN: &str = "SYNERGY_ARCHIVE_SNAPSHOT_DISTRIBUTION_V1";
pub const CATALOG_DOMAIN: &str = "SYNERGY_ARCHIVE_SNAPSHOT_CATALOG_V1";
pub const PRODUCER_NODE_KIND: &str = "archive-validator";
pub const BINARY_COMPATIBILITY: &str = "synergy-testnet-v3-validator-pruned-v1";
pub const ARCHIVE_CHUNK_SIZE: u64 = 512 * 1024 * 1024;
pub const RETAIN_PER_CLASS: usize = 2;
const CANONICAL_TESTNET_CHAIN_ID: u64 = 1266;
const CANONICAL_TESTNET_NETWORK_ID: &str = "synergy-testnet-v3";
const CANONICAL_TESTNET_GENESIS_HASH: &str =
    "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789";

const ALLOWED_STATE_FILES: &[&str] = &[
    "account_state.json",
    "canonical_locks.json",
    "chain.json",
    "committed_blocks.jsonl",
    "committed_qcs.json",
    "committed_qcs.jsonl",
    "dag_state.json",
    "state_checkpoint.json",
    "token_state.json",
    "validator_registry.json",
];

const FORBIDDEN_PATH_FRAGMENTS: &[&str] = &[
    "config",
    "credential",
    "genesis",
    "identity",
    "key",
    "log",
    "password",
    "quorum",
    "secret",
    "wireguard",
    "wg0",
];

#[derive(Debug, Clone)]
pub struct ArchiveSnapshotCreateRequest {
    pub workspace: PathBuf,
    pub publish_root: PathBuf,
    pub source_node_id: String,
    pub chain_id: u64,
    pub network_id: String,
    pub genesis_hash: String,
    pub consensus_fork: Value,
    pub majority_proof_marker: PathBuf,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ArchiveSnapshotPublication {
    pub snapshot_id: String,
    pub snapshot_class: String,
    pub snapshot_path: String,
    pub archive_path: String,
    pub catalog_path: String,
    pub height: u64,
    pub block_hash: String,
    pub archive_sha256: String,
    pub manifest_sha256: String,
}

pub fn create_and_publish(
    request: ArchiveSnapshotCreateRequest,
) -> Result<ArchiveSnapshotPublication, String> {
    let majority_proof = validate_majority_proof(
        &request.majority_proof_marker,
        request.chain_id,
        &request.network_id,
        &request.genesis_hash,
    )?;

    let runtime = configured_runtime()?;
    let mut create = Command::new(&runtime);
    create
        .arg("create-snapshot")
        .arg("--chain-id")
        .arg(request.chain_id.to_string())
        .arg("--network-id")
        .arg(&request.network_id)
        .arg("--genesis-hash")
        .arg(&request.genesis_hash)
        .arg("--source-workspace")
        .arg(&request.workspace)
        .arg("--source-node-majority-branch-proven")
        .arg("--source-role")
        .arg(RUNTIME_SNAPSHOT_SOURCE_ROLE)
        .arg("--snapshot-class")
        .arg(SNAPSHOT_CLASS_VALIDATOR_PRUNED)
        .arg("--allowed-role")
        .arg("validator")
        .arg("--allowed-role")
        .arg("onboarding_validator")
        .arg("--allowed-role")
        .arg("quarantined_validator");
    let create_report = run_json_command(&mut create, "archive snapshot creation")?;
    if create_report.get("success").and_then(Value::as_bool) != Some(true) {
        return Err(format!(
            "Archive snapshot runtime refused creation: {create_report}"
        ));
    }
    require_runtime_snapshot_matches_marker(&majority_proof, &create_report)?;

    let snapshot_root = required_path(&create_report, "snapshot_path")?;
    let manifest_path = required_path(&create_report, "manifest_path")?;
    verify_with_runtime(&runtime, &request, &manifest_path, &snapshot_root)?;

    publish_preverified(&request, &snapshot_root, &manifest_path, &create_report)
}

pub fn import_and_publish(
    request: ArchiveSnapshotCreateRequest,
    snapshot_root: PathBuf,
    runtime_report_path: PathBuf,
) -> Result<ArchiveSnapshotPublication, String> {
    validate_canonical_testnet_request(&request)?;
    let majority_proof = validate_majority_proof(
        &request.majority_proof_marker,
        request.chain_id,
        &request.network_id,
        &request.genesis_hash,
    )?;
    let runtime_report = read_json(&runtime_report_path)?;
    let (manifest_path, _) = validate_imported_snapshot_source(
        &request,
        &majority_proof,
        &snapshot_root,
        &runtime_report,
    )?;
    let expected_manifest_hash = required_string(&runtime_report, "manifest_hash")?;

    let runtime = configured_runtime()?;
    let verified_report = verify_with_runtime(&runtime, &request, &manifest_path, &snapshot_root)?;
    validate_runtime_verification_report(
        &verified_report,
        &majority_proof,
        &expected_manifest_hash,
    )?;
    publish_preverified(&request, &snapshot_root, &manifest_path, &runtime_report)
}

fn validate_imported_snapshot_source(
    request: &ArchiveSnapshotCreateRequest,
    majority_proof: &MajorityProofMarker,
    snapshot_root: &Path,
    runtime_report: &Value,
) -> Result<(PathBuf, Value), String> {
    validate_import_runtime_report(runtime_report, majority_proof)?;
    validate_snapshot_root(snapshot_root)?;
    let manifest_name = required_string(runtime_report, "manifest_path")?;
    let manifest_name = Path::new(&manifest_name)
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "Runtime report manifest_path has no safe file name.".to_string())?;
    validate_relative_name(manifest_name)?;
    let manifest_path = snapshot_root.join(manifest_name);
    validate_regular_file(&manifest_path, "imported runtime snapshot manifest")?;
    let signed_manifest = read_json(&manifest_path)?;
    let manifest = signed_manifest.get("manifest").unwrap_or(&signed_manifest);
    validate_signed_manifest(
        manifest,
        request,
        snapshot_root,
        &manifest_path,
        &signed_manifest,
    )?;
    let expected_manifest_hash = required_string(runtime_report, "manifest_hash")?;
    validate_import_manifest(
        request,
        majority_proof,
        manifest,
        runtime_report,
        &expected_manifest_hash,
    )?;
    Ok((manifest_path, signed_manifest))
}

pub fn validate_catalog_for_consumer(
    catalog: &Value,
    expected_chain_id: u64,
    expected_network_id: &str,
    expected_genesis_hash: &str,
    expected_consensus_fork: &Value,
) -> Result<(), String> {
    if catalog.get("schema").and_then(Value::as_str) != Some(CATALOG_SCHEMA) {
        return Err("Archive snapshot catalog schema is missing or unsupported.".to_string());
    }
    if catalog.get("chain_id").and_then(Value::as_u64) != Some(expected_chain_id)
        || catalog.get("network_id").and_then(Value::as_str) != Some(expected_network_id)
        || catalog.get("genesis_hash").and_then(Value::as_str) != Some(expected_genesis_hash)
    {
        return Err(
            "Archive snapshot catalog chain, network, or genesis identity mismatch.".to_string(),
        );
    }
    if catalog
        .get("catalog_signature_status")
        .and_then(Value::as_str)
        != Some("AEGIS_PQC_VERIFIED")
    {
        return Err("Archive snapshot catalog signature is not verified.".to_string());
    }
    require_compatibility_metadata(catalog, "catalog")?;
    if catalog.get("signature_scheme").and_then(Value::as_str) != Some("aegis-pqc") {
        return Err("Archive snapshot catalog signature scheme is unsupported.".to_string());
    }
    if catalog.get("signature_domain").and_then(Value::as_str) != Some(CATALOG_DOMAIN) {
        return Err("Archive snapshot catalog signature domain is unsupported.".to_string());
    }
    if !is_sha256(catalog.get("catalog_content_root").and_then(Value::as_str)) {
        return Err("Archive snapshot catalog is missing catalog_content_root.".to_string());
    }

    let snapshots = catalog
        .get("snapshots")
        .and_then(Value::as_array)
        .ok_or_else(|| "Archive snapshot catalog is missing snapshots.".to_string())?;
    let active = snapshots
        .iter()
        .filter(|entry| {
            entry.get("snapshot_class").and_then(Value::as_str)
                == Some(SNAPSHOT_CLASS_VALIDATOR_PRUNED)
                && entry.get("status").and_then(Value::as_str) == Some("published")
        })
        .collect::<Vec<_>>();
    if active.is_empty() {
        return Err(
            "Archive snapshot catalog has no published validator-pruned snapshot.".to_string(),
        );
    }
    if active.len() > RETAIN_PER_CLASS {
        return Err(format!(
            "Archive snapshot catalog exposes more than {RETAIN_PER_CLASS} active validator-pruned snapshots."
        ));
    }
    let content_root = catalog_content_root(snapshots)?;
    if catalog.get("catalog_content_root").and_then(Value::as_str) != Some(content_root.as_str()) {
        return Err(
            "Archive snapshot catalog content root does not match its entries.".to_string(),
        );
    }

    let mut heights = BTreeMap::new();
    for snapshot in active {
        validate_catalog_entry(
            snapshot,
            expected_chain_id,
            expected_network_id,
            expected_genesis_hash,
            expected_consensus_fork,
        )?;
        let height = required_u64(snapshot, "height")?;
        let block_hash = required_string(snapshot, "hash")?;
        if let Some(previous_hash) = heights.insert(height, block_hash.clone()) {
            if previous_hash != block_hash {
                return Err(format!(
                    "Archive catalog contains conflicting validator-pruned snapshots at height {height}."
                ));
            }
        }
    }
    Ok(())
}

pub fn select_latest_validator_snapshot(catalog: &Value) -> Result<Value, String> {
    catalog
        .get("snapshots")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|entry| {
            entry.get("snapshot_class").and_then(Value::as_str)
                == Some(SNAPSHOT_CLASS_VALIDATOR_PRUNED)
                && entry.get("status").and_then(Value::as_str) == Some("published")
        })
        .max_by(|left, right| {
            let left_key = (
                left.get("height").and_then(Value::as_u64).unwrap_or(0),
                left.get("snapshot_id")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
            );
            let right_key = (
                right.get("height").and_then(Value::as_u64).unwrap_or(0),
                right
                    .get("snapshot_id")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
            );
            left_key.cmp(&right_key)
        })
        .cloned()
        .ok_or_else(|| "Archive catalog has no selectable validator-pruned snapshot.".to_string())
}

pub fn validate_distribution_manifest_for_consumer(
    manifest: &Value,
    expected_snapshot_id: &str,
    expected_height: u64,
    expected_block_hash: &str,
    expected_archive_sha256: &str,
    expected_chain_id: u64,
    expected_network_id: &str,
    expected_genesis_hash: &str,
    expected_consensus_fork: &Value,
) -> Result<(), String> {
    if manifest.get("schema").and_then(Value::as_str) != Some(DISTRIBUTION_SCHEMA)
        || manifest.get("snapshot_id").and_then(Value::as_str) != Some(expected_snapshot_id)
        || manifest.get("snapshot_class").and_then(Value::as_str)
            != Some(SNAPSHOT_CLASS_VALIDATOR_PRUNED)
    {
        return Err("Archive distribution manifest identity mismatch.".to_string());
    }
    if manifest.get("status").and_then(Value::as_str) != Some("published")
        || manifest.get("verification_status").and_then(Value::as_str) != Some("green")
    {
        return Err("Archive distribution manifest is not published and verified.".to_string());
    }
    require_compatibility_metadata(manifest, "distribution manifest")?;
    if manifest.get("signature_scheme").and_then(Value::as_str) != Some("aegis-pqc") {
        return Err("Archive distribution manifest signature scheme is unsupported.".to_string());
    }
    if manifest.get("signature_domain").and_then(Value::as_str) != Some(DISTRIBUTION_DOMAIN) {
        return Err("Archive distribution manifest signature domain is unsupported.".to_string());
    }
    if manifest.get("chain_id").and_then(Value::as_u64) != Some(expected_chain_id)
        || manifest.get("network_id").and_then(Value::as_str) != Some(expected_network_id)
        || manifest.get("genesis_hash").and_then(Value::as_str) != Some(expected_genesis_hash)
        || manifest.get("height").and_then(Value::as_u64) != Some(expected_height)
        || manifest.get("hash").and_then(Value::as_str) != Some(expected_block_hash)
        || manifest.get("archive_sha256").and_then(Value::as_str) != Some(expected_archive_sha256)
    {
        return Err("Archive distribution manifest does not match the catalog entry.".to_string());
    }
    if !matches_source_role(manifest.get("source_role").and_then(Value::as_str)) {
        return Err("Archive distribution manifest has an invalid source role.".to_string());
    }
    if manifest.get("consensus_fork") != Some(expected_consensus_fork) {
        return Err("Archive distribution manifest consensus fork mismatch.".to_string());
    }
    let roles = manifest
        .get("allowed_roles")
        .and_then(Value::as_array)
        .ok_or_else(|| "Archive distribution manifest is missing allowed_roles.".to_string())?;
    if !roles.iter().any(|role| role.as_str() == Some("validator")) {
        return Err("Archive distribution manifest is not allowed for validators.".to_string());
    }
    if manifest
        .get("receiver_format")
        .and_then(|value| value.get("compression"))
        .and_then(Value::as_str)
        != Some("zstd")
        || manifest
            .get("receiver_format")
            .and_then(|value| value.get("archive_container"))
            .and_then(Value::as_str)
            != Some("tar")
    {
        return Err("Archive distribution manifest receiver format is unsupported.".to_string());
    }
    let operating_systems = manifest
        .get("supported_receiver_operating_systems")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            "Archive distribution manifest is missing receiver operating systems.".to_string()
        })?;
    for operating_system in ["macos", "linux", "windows"] {
        if !operating_systems
            .iter()
            .any(|value| value.as_str() == Some(operating_system))
        {
            return Err(format!(
                "Archive distribution manifest does not support receiver OS {operating_system}."
            ));
        }
    }
    let archive_filename = required_string(manifest, "archive_filename")?;
    validate_relative_name(&archive_filename)?;
    let chunks = manifest
        .get("chunks")
        .and_then(Value::as_array)
        .ok_or_else(|| "Archive distribution manifest is missing chunks.".to_string())?;
    if chunks.is_empty() {
        return Err("Archive distribution manifest contains no archive chunks.".to_string());
    }
    for chunk in chunks {
        let name = required_string(chunk, "name")?;
        validate_relative_name(&name)?;
        if !is_sha256(chunk.get("sha256").and_then(Value::as_str)) {
            return Err(format!("Archive chunk {name} is missing a valid SHA-256."));
        }
        if chunk.get("size_bytes").and_then(Value::as_u64).unwrap_or(0) == 0 {
            return Err(format!("Archive chunk {name} has no positive size."));
        }
    }
    Ok(())
}

/// Verify a downloaded catalog using the same Aegis CLI contract used at publication.
/// The caller owns artifact retrieval; this function intentionally performs no network I/O.
pub fn verify_catalog_signature_for_consumer(
    catalog_path: &Path,
    signature_path: &Path,
) -> Result<(), String> {
    verify_signed_json_for_consumer(catalog_path, signature_path, CATALOG_DOMAIN, "catalog")
}

/// Verify a downloaded distribution manifest using the archive distribution domain.
/// A status marker in JSON is never accepted as a substitute for this verification.
pub fn verify_distribution_signature_for_consumer(
    manifest_path: &Path,
    signature_path: &Path,
) -> Result<(), String> {
    verify_signed_json_for_consumer(
        manifest_path,
        signature_path,
        DISTRIBUTION_DOMAIN,
        "distribution manifest",
    )
}

fn verify_signed_json_for_consumer(
    input: &Path,
    signature: &Path,
    domain: &str,
    label: &str,
) -> Result<(), String> {
    if !input.is_file() || !signature.is_file() {
        return Err(format!(
            "Archive {label} signature verification requires downloaded data and signature files."
        ));
    }
    let verifier = std::env::var_os("SYNERGY_AEGIS_CLI")
        .map(PathBuf::from)
        .filter(|path| path.is_file())
        .ok_or_else(|| {
            "Archive snapshot verification requires the packaged SYNERGY_AEGIS_CLI verifier."
                .to_string()
        })?;
    let expected_signer = expected_archive_signer_sha256()?;
    let output = Command::new(&verifier)
        .args(["verify-json", "--domain", domain, "--input"])
        .arg(input)
        .args(["--signature"])
        .arg(signature)
        .args(["--expected-signer-sha256", &expected_signer])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| format!("Failed to run archive {label} signature verifier: {error}"))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr)
            .trim()
            .chars()
            .take(1_000)
            .collect::<String>();
        return Err(format!(
            "Archive {label} Aegis signature verification failed closed.{}",
            if detail.is_empty() {
                String::new()
            } else {
                format!(" Verifier detail: {detail}")
            }
        ));
    }
    Ok(())
}

fn validate_catalog_entry(
    snapshot: &Value,
    expected_chain_id: u64,
    expected_network_id: &str,
    expected_genesis_hash: &str,
    expected_consensus_fork: &Value,
) -> Result<(), String> {
    if snapshot.get("chain_id").and_then(Value::as_u64) != Some(expected_chain_id)
        || snapshot.get("network_id").and_then(Value::as_str) != Some(expected_network_id)
        || snapshot.get("genesis_hash").and_then(Value::as_str) != Some(expected_genesis_hash)
    {
        return Err("Archive catalog entry identity mismatch.".to_string());
    }
    let snapshot_id = required_string(snapshot, "snapshot_id")?;
    validate_relative_name(&snapshot_id)?;
    if required_u64(snapshot, "height")? == 0 || required_string(snapshot, "hash")?.is_empty() {
        return Err("Archive catalog entry has no positive height or block hash.".to_string());
    }
    if !is_sha256(snapshot.get("archive_sha256").and_then(Value::as_str))
        || !is_sha256(snapshot.get("manifest_sha256").and_then(Value::as_str))
    {
        return Err(format!(
            "Archive catalog entry {snapshot_id} is missing immutable artifact digests."
        ));
    }
    if snapshot
        .get("manifest_signature_status")
        .and_then(Value::as_str)
        != Some("AEGIS_PQC_VERIFIED")
    {
        return Err(format!(
            "Archive catalog entry {snapshot_id} does not have a verified distribution signature."
        ));
    }
    if !matches_source_role(snapshot.get("source_role").and_then(Value::as_str)) {
        return Err(format!(
            "Archive catalog entry {snapshot_id} has an invalid source role."
        ));
    }
    if snapshot.get("producer_role").and_then(Value::as_str) != Some(SOURCE_ROLE_ARCHIVE_VALIDATOR)
        || snapshot.get("producer_node_kind").and_then(Value::as_str) != Some(PRODUCER_NODE_KIND)
    {
        return Err(format!(
            "Archive catalog entry {snapshot_id} does not identify archive_validator provenance."
        ));
    }
    require_compatibility_metadata(snapshot, &format!("catalog entry {snapshot_id}"))?;
    if snapshot.get("consensus_fork") != Some(expected_consensus_fork) {
        return Err(format!(
            "Archive catalog entry {snapshot_id} consensus fork mismatch."
        ));
    }
    let roles = snapshot
        .get("allowed_roles")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("Archive catalog entry {snapshot_id} is missing allowed_roles."))?;
    if !roles.iter().any(|role| role.as_str() == Some("validator")) {
        return Err(format!(
            "Archive catalog entry {snapshot_id} is not allowed for validators."
        ));
    }
    let archive_filename = required_string(snapshot, "archive_filename")?;
    validate_relative_name(&archive_filename)?;
    let receiver_format = snapshot.get("receiver_format").ok_or_else(|| {
        format!("Archive catalog entry {snapshot_id} is missing receiver_format.")
    })?;
    if receiver_format
        .get("archive_container")
        .and_then(Value::as_str)
        != Some("tar")
        || receiver_format.get("compression").and_then(Value::as_str) != Some("zstd")
    {
        return Err(format!(
            "Archive catalog entry {snapshot_id} has an unsupported receiver format."
        ));
    }
    let operating_systems = snapshot
        .get("supported_receiver_operating_systems")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            format!("Archive catalog entry {snapshot_id} is missing receiver operating systems.")
        })?;
    if ["macos", "linux", "windows"]
        .iter()
        .any(|operating_system| {
            !operating_systems
                .iter()
                .any(|value| value.as_str() == Some(*operating_system))
        })
    {
        return Err(format!(
            "Archive catalog entry {snapshot_id} does not declare all supported receiver operating systems."
        ));
    }
    validate_artifact_url(snapshot, "snapshot_url", "snapshot.tar.zst")?;
    validate_artifact_url(snapshot, "manifest_url", "distribution-manifest.json")?;
    validate_artifact_url(snapshot, "manifest_signature_url", "signature.sig")?;
    validate_artifact_url(snapshot, "checksums_url", "checksums.sha256")?;
    Ok(())
}

fn publish_preverified(
    request: &ArchiveSnapshotCreateRequest,
    snapshot_root: &Path,
    manifest_path: &Path,
    runtime_report: &Value,
) -> Result<ArchiveSnapshotPublication, String> {
    validate_snapshot_root(snapshot_root)?;
    validate_regular_file(manifest_path, "signed runtime snapshot manifest")?;
    let signed_manifest = read_json(manifest_path)?;
    let manifest = signed_manifest.get("manifest").unwrap_or(&signed_manifest);
    validate_signed_manifest(
        manifest,
        request,
        snapshot_root,
        manifest_path,
        &signed_manifest,
    )?;

    let height = required_u64(manifest, "snapshot_height")?;
    let block_hash = required_string(manifest, "snapshot_block_hash")?;
    let snapshot_id = immutable_snapshot_id(height, &block_hash);
    let stage_root = request.publish_root.join("staging");
    fs::create_dir_all(&stage_root)
        .map_err(|error| format!("Failed to create {}: {error}", stage_root.display()))?;
    let stage = stage_root.join(format!(
        "{snapshot_id}.building-{}-{}",
        std::process::id(),
        Uuid::new_v4().simple()
    ));
    fs::create_dir_all(&stage)
        .map_err(|error| format!("Failed to create {}: {error}", stage.display()))?;
    let staged_snapshot = stage.join(&snapshot_id);
    if let Err(error) = materialize_snapshot(snapshot_root, manifest_path, &staged_snapshot) {
        let _ = fs::remove_dir_all(&stage);
        return Err(error);
    }

    let archive_name = format!("{snapshot_id}.{SNAPSHOT_CLASS_VALIDATOR_PRUNED}.tar.zst");
    let staged_archive = stage.join(&archive_name);
    let archive_sha256 =
        match create_deterministic_archive(&staged_snapshot, &staged_archive, &snapshot_id) {
            Ok(value) => value,
            Err(error) => {
                let _ = fs::remove_dir_all(&stage);
                return Err(error);
            }
        };
    let chunks = write_chunks(&staged_archive, &stage, &archive_name)?;
    let source_manifest_sha256 = sha256_file(manifest_path)?;
    let created_at = manifest
        .get("created_at")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let distribution = build_distribution_manifest(
        request,
        &snapshot_id,
        height,
        &block_hash,
        &archive_name,
        &archive_sha256,
        source_manifest_sha256.as_str(),
        created_at,
        chunks,
        runtime_report,
    );
    let distribution_path = stage.join("distribution-manifest.json");
    write_canonical_json(&distribution_path, &distribution)?;
    sign_and_verify_json(
        &distribution_path,
        &stage.join("distribution-manifest.sig"),
        DISTRIBUTION_DOMAIN,
    )?;

    let verification_report = json!({
        "status": "green",
        "runtime": runtime_report,
        "distribution_signature_status": "AEGIS_PQC_VERIFIED",
        "archive_sha256": archive_sha256,
    });
    write_canonical_json(
        &stage.join("verification-report.json"),
        &verification_report,
    )?;

    let final_root = request
        .publish_root
        .join(format!("testnet-{}", request.chain_id))
        .join(SNAPSHOT_CLASS_VALIDATOR_PRUNED);
    fs::create_dir_all(&final_root)
        .map_err(|error| format!("Failed to create {}: {error}", final_root.display()))?;
    let final_snapshot = final_root.join(&snapshot_id);
    if final_snapshot.exists() {
        let existing_manifest = final_snapshot.join("distribution-manifest.json");
        let existing = read_json(&existing_manifest)?;
        if existing.get("archive_sha256").and_then(Value::as_str) != Some(&archive_sha256) {
            let _ = fs::remove_dir_all(&stage);
            return Err(format!(
                "Immutable snapshot id {snapshot_id} already exists with different content."
            ));
        }
        let _ = fs::remove_dir_all(&stage);
    } else {
        fs::rename(&stage, &final_snapshot).map_err(|error| {
            format!(
                "Failed to atomically publish immutable snapshot {}: {error}",
                final_snapshot.display()
            )
        })?;
    }
    let manifest_sha256 = sha256_file(&final_snapshot.join("distribution-manifest.json"))?;

    let catalog_path = request.publish_root.join("catalog.json");
    let catalog = update_catalog(
        &catalog_path,
        request,
        &snapshot_id,
        height,
        &block_hash,
        &archive_name,
        &archive_sha256,
        &manifest_sha256,
        created_at,
        &final_snapshot,
    )?;
    let published_archive = final_snapshot.join(&archive_name);
    let public_catalog_path = publish_to_r2(
        request,
        &catalog,
        &final_snapshot,
        &published_archive,
        height,
        &archive_sha256,
    )?;
    Ok(ArchiveSnapshotPublication {
        snapshot_id,
        snapshot_class: SNAPSHOT_CLASS_VALIDATOR_PRUNED.to_string(),
        snapshot_path: final_snapshot.to_string_lossy().to_string(),
        archive_path: published_archive.to_string_lossy().to_string(),
        catalog_path: public_catalog_path.to_string_lossy().to_string(),
        height,
        block_hash,
        archive_sha256,
        manifest_sha256,
    })
}

#[derive(Debug, Clone)]
struct R2Config {
    local_only: bool,
    endpoint: Option<String>,
    bucket: String,
    public_base_url: String,
    access_key_id: Option<String>,
    secret_access_key: Option<String>,
}

fn required_snapshot_env(name: &str) -> Result<String, String> {
    std::env::var(name)
        .map(|value| value.trim().to_string())
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{name} is required before archive snapshots may be published."))
}

fn r2_config() -> Result<R2Config, String> {
    let local_only = std::env::var("SYNERGY_SNAPSHOT_LOCAL_ONLY")
        .map(|value| value.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if local_only {
        return Ok(R2Config {
            local_only,
            endpoint: None,
            bucket: required_snapshot_env("SYNERGY_SNAPSHOT_R2_BUCKET")?,
            public_base_url: required_snapshot_env("SYNERGY_SNAPSHOT_PUBLIC_BASE_URL")?
                .trim_end_matches('/')
                .to_string(),
            access_key_id: None,
            secret_access_key: None,
        });
    }

    Ok(R2Config {
        local_only,
        endpoint: Some(required_snapshot_env("SYNERGY_SNAPSHOT_R2_ENDPOINT")?),
        bucket: required_snapshot_env("SYNERGY_SNAPSHOT_R2_BUCKET")?,
        public_base_url: required_snapshot_env("SYNERGY_SNAPSHOT_PUBLIC_BASE_URL")?
            .trim_end_matches('/')
            .to_string(),
        access_key_id: Some(required_snapshot_env("SYNERGY_SNAPSHOT_R2_ACCESS_KEY_ID")?),
        secret_access_key: Some(required_snapshot_env(
            "SYNERGY_SNAPSHOT_R2_SECRET_ACCESS_KEY",
        )?),
    })
}

fn r2_command(config: &R2Config) -> Result<Command, String> {
    let endpoint = config.endpoint.as_deref().ok_or_else(|| {
        "R2 commands are unavailable while SYNERGY_SNAPSHOT_LOCAL_ONLY=true.".to_string()
    })?;
    let access_key_id = config.access_key_id.as_deref().ok_or_else(|| {
        "R2 access credentials are unavailable while SYNERGY_SNAPSHOT_LOCAL_ONLY=true.".to_string()
    })?;
    let secret_access_key = config.secret_access_key.as_deref().ok_or_else(|| {
        "R2 access credentials are unavailable while SYNERGY_SNAPSHOT_LOCAL_ONLY=true.".to_string()
    })?;
    let mut command = Command::new("aws");
    command
        .env("AWS_ACCESS_KEY_ID", access_key_id)
        .env("AWS_SECRET_ACCESS_KEY", secret_access_key)
        .env("AWS_EC2_METADATA_DISABLED", "true")
        .arg("--endpoint-url")
        .arg(endpoint);
    Ok(command)
}

fn upload_and_verify_r2_object(
    config: &R2Config,
    local_path: &Path,
    object_key: &str,
) -> Result<(), String> {
    let destination = format!("s3://{}/{}", config.bucket, object_key);
    let expected_sha256 = sha256_file(local_path)?;
    let copy = r2_command(config)?
        .arg("s3")
        .arg("cp")
        .arg(local_path)
        .arg(&destination)
        .arg("--metadata")
        .arg(format!("sha256={expected_sha256}"))
        .arg("--only-show-errors")
        .output()
        .map_err(|error| format!("Failed to start aws CLI for R2 upload: {error}"))?;
    if !copy.status.success() {
        return Err(format!(
            "R2 upload failed for {object_key}: {}",
            String::from_utf8_lossy(&copy.stderr).trim()
        ));
    }
    let head = r2_command(config)?
        .arg("s3api")
        .arg("head-object")
        .arg("--bucket")
        .arg(&config.bucket)
        .arg("--key")
        .arg(object_key)
        .output()
        .map_err(|error| format!("Failed to start aws CLI for R2 verification: {error}"))?;
    if !head.status.success() {
        return Err(format!(
            "R2 verification failed for {object_key}: {}",
            String::from_utf8_lossy(&head.stderr).trim()
        ));
    }
    let head_value: Value = serde_json::from_slice(&head.stdout).map_err(|error| {
        format!("R2 verification returned invalid JSON for {object_key}: {error}")
    })?;
    let expected_size = fs::metadata(local_path)
        .map_err(|error| format!("Failed to stat {}: {error}", local_path.display()))?
        .len();
    let reported_size = head_value.get("ContentLength").and_then(Value::as_u64);
    if reported_size != Some(expected_size) {
        return Err(format!(
            "R2 object {object_key} size does not match the local artifact."
        ));
    }
    let reported_sha256 = head_value
        .get("Metadata")
        .and_then(|metadata| metadata.get("sha256"))
        .and_then(Value::as_str)
        .map(str::to_ascii_lowercase);
    if reported_sha256.as_deref() != Some(expected_sha256.as_str()) {
        return Err(format!(
            "R2 object {object_key} SHA-256 metadata does not match the local artifact."
        ));
    }

    let file_name = local_path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            format!(
                "R2 local artifact path has no valid file name: {}",
                local_path.display()
            )
        })?;
    let downloaded_path = local_path.with_file_name(format!(
        ".{file_name}.r2-verify-{}",
        Uuid::new_v4().simple()
    ));
    let downloaded = r2_command(config)?
        .arg("s3")
        .arg("cp")
        .arg(&destination)
        .arg(&downloaded_path)
        .arg("--only-show-errors")
        .output()
        .map_err(|error| {
            format!("Failed to start aws CLI for R2 read-back verification: {error}")
        })?;
    if !downloaded.status.success() {
        let _ = fs::remove_file(&downloaded_path);
        return Err(format!(
            "R2 read-back verification failed for {object_key}: {}",
            String::from_utf8_lossy(&downloaded.stderr).trim()
        ));
    }
    let downloaded_sha256 = sha256_file(&downloaded_path);
    let _ = fs::remove_file(&downloaded_path);
    if downloaded_sha256.as_ref().map(String::as_str).ok() != Some(expected_sha256.as_str()) {
        return Err(format!(
            "R2 read-back SHA-256 does not match the local artifact for {object_key}."
        ));
    }
    Ok(())
}

fn publish_to_r2(
    request: &ArchiveSnapshotCreateRequest,
    catalog: &Value,
    final_snapshot: &Path,
    archive_path: &Path,
    height: u64,
    archive_sha256: &str,
) -> Result<PathBuf, String> {
    let config = r2_config()?;
    let prefix = format!("snapshots/{height}");
    let archive_size = fs::metadata(archive_path)
        .map_err(|error| format!("Failed to stat {}: {error}", archive_path.display()))?
        .len();
    let checksum_path = final_snapshot.join("checksums.sha256");
    fs::write(
        &checksum_path,
        format!("{archive_sha256}  snapshot.tar.zst\n"),
    )
    .map_err(|error| format!("Failed to write {}: {error}", checksum_path.display()))?;
    let artifacts = r2_snapshot_artifacts(final_snapshot, archive_path, &checksum_path, &prefix)?;
    if !config.local_only {
        for (path, key) in &artifacts {
            upload_and_verify_r2_object(&config, path, key)?;
        }
    }

    let mut public_catalog = catalog.clone();
    let snapshots = public_catalog
        .get_mut("snapshots")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| {
            "Archive catalog is missing snapshots before public publication.".to_string()
        })?;
    for snapshot in &mut *snapshots {
        let Some(snapshot_height) = snapshot.get("height").and_then(Value::as_u64) else {
            continue;
        };
        let snapshot_prefix = format!("{}/snapshots/{snapshot_height}", config.public_base_url);
        snapshot["snapshot_url"] = Value::String(format!("{snapshot_prefix}/snapshot.tar.zst"));
        snapshot["manifest_url"] =
            Value::String(format!("{snapshot_prefix}/distribution-manifest.json"));
        snapshot["manifest_signature_url"] =
            Value::String(format!("{snapshot_prefix}/signature.sig"));
        snapshot["checksums_url"] = Value::String(format!("{snapshot_prefix}/checksums.sha256"));
        snapshot["producer_role"] = Value::String(SOURCE_ROLE_ARCHIVE_VALIDATOR.to_string());
        snapshot["producer_node_kind"] = Value::String(PRODUCER_NODE_KIND.to_string());
        snapshot["catalog_schema"] = Value::String(CATALOG_SCHEMA.to_string());
        snapshot["distribution_schema"] = Value::String(DISTRIBUTION_SCHEMA.to_string());
        snapshot["binary_compatibility"] = Value::String(BINARY_COMPATIBILITY.to_string());
        if snapshot_height == height {
            snapshot["compressed_size_bytes"] = Value::from(archive_size);
        }
    }
    public_catalog["catalog_content_root"] = Value::String(catalog_content_root(snapshots)?);
    let latest_local = request.publish_root.join("latest.json");
    write_signed_catalog_atomically(&latest_local, &public_catalog)?;
    let latest_signature = latest_local.with_file_name("latest.json.sig");
    if !config.local_only {
        upload_and_verify_r2_object(&config, &latest_signature, "snapshots/latest.json.sig")?;
        upload_and_verify_r2_object(&config, &latest_local, "snapshots/latest.json")?;
    }
    Ok(latest_local)
}

fn r2_snapshot_artifacts(
    final_snapshot: &Path,
    archive_path: &Path,
    checksum_path: &Path,
    prefix: &str,
) -> Result<Vec<(PathBuf, String)>, String> {
    let manifest_path = final_snapshot.join("distribution-manifest.json");
    let manifest = read_json(&manifest_path)?;
    let chunks = manifest
        .get("chunks")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            "Distribution manifest is missing chunks before R2 publication.".to_string()
        })?;
    if chunks.is_empty() {
        return Err("Distribution manifest has no chunks before R2 publication.".to_string());
    }

    let mut artifacts = vec![
        (
            archive_path.to_path_buf(),
            format!("{prefix}/snapshot.tar.zst"),
        ),
        (
            manifest_path,
            format!("{prefix}/distribution-manifest.json"),
        ),
        (
            final_snapshot.join("distribution-manifest.sig"),
            format!("{prefix}/signature.sig"),
        ),
        (
            checksum_path.to_path_buf(),
            format!("{prefix}/checksums.sha256"),
        ),
        (
            final_snapshot.join("verification-report.json"),
            format!("{prefix}/verification-report.json"),
        ),
    ];
    for chunk in chunks {
        let name = required_string(chunk, "name")?;
        validate_relative_name(&name)?;
        artifacts.push((final_snapshot.join(&name), format!("{prefix}/{name}")));
    }
    Ok(artifacts)
}

fn update_catalog(
    catalog_path: &Path,
    request: &ArchiveSnapshotCreateRequest,
    snapshot_id: &str,
    height: u64,
    block_hash: &str,
    archive_name: &str,
    archive_sha256: &str,
    manifest_sha256: &str,
    created_at: u64,
    final_snapshot: &Path,
) -> Result<Value, String> {
    let verified_at = current_unix_timestamp()?;
    let mut catalog = if catalog_path.is_file() {
        read_json(catalog_path)?
    } else {
        json!({
            "schema": CATALOG_SCHEMA,
            "chain_id": request.chain_id,
            "network_id": request.network_id,
            "genesis_hash": request.genesis_hash,
            "snapshots": []
        })
    };
    if catalog.get("schema").and_then(Value::as_str) != Some(CATALOG_SCHEMA)
        || catalog.get("chain_id").and_then(Value::as_u64) != Some(request.chain_id)
        || catalog.get("network_id").and_then(Value::as_str) != Some(&request.network_id)
        || catalog.get("genesis_hash").and_then(Value::as_str) != Some(&request.genesis_hash)
    {
        return Err(
            "Existing archive catalog identity does not match the active Testnet.".to_string(),
        );
    }
    let snapshots = catalog
        .get_mut("snapshots")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| "Existing archive catalog is missing snapshots.".to_string())?;
    if let Some(existing) = snapshots
        .iter()
        .find(|entry| entry.get("snapshot_id").and_then(Value::as_str) == Some(snapshot_id))
    {
        if existing.get("archive_sha256").and_then(Value::as_str) != Some(archive_sha256) {
            return Err(format!(
                "Catalog already contains immutable snapshot id {snapshot_id} with different content."
            ));
        }
    } else {
        snapshots.push(json!({
            "snapshot_id": snapshot_id,
            "snapshot_class": SNAPSHOT_CLASS_VALIDATOR_PRUNED,
            "allowed_roles": ["validator", "onboarding_validator", "quarantined_validator"],
            "chain_id": request.chain_id,
            "network_id": request.network_id,
            "genesis_hash": request.genesis_hash,
            "height": height,
            "hash": block_hash,
            "created_at": created_at,
            "producer": request.source_node_id,
            "source_role": SOURCE_ROLE_ARCHIVE_VALIDATOR,
            "producer_role": SOURCE_ROLE_ARCHIVE_VALIDATOR,
            "producer_node_kind": PRODUCER_NODE_KIND,
            "catalog_schema": CATALOG_SCHEMA,
            "distribution_schema": DISTRIBUTION_SCHEMA,
            "binary_compatibility": BINARY_COMPATIBILITY,
            "archive_filename": archive_name,
            "archive_sha256": archive_sha256,
            "manifest_sha256": manifest_sha256,
            "manifest_signature_status": "AEGIS_PQC_VERIFIED",
            "supported_receiver_operating_systems": ["macos", "linux", "windows"],
            "receiver_format": {"archive_container": "tar", "compression": "zstd", "chunk_size": ARCHIVE_CHUNK_SIZE},
            "consensus_fork": request.consensus_fork,
            "status": "published",
            "verification_status": "green",
            "local_path": final_snapshot.to_string_lossy().to_string(),
            "superseded_by": Value::Null
        }));
    }
    let mut active = snapshots
        .iter_mut()
        .filter(|entry| {
            entry.get("snapshot_class").and_then(Value::as_str)
                == Some(SNAPSHOT_CLASS_VALIDATOR_PRUNED)
                && entry.get("status").and_then(Value::as_str) == Some("published")
        })
        .collect::<Vec<_>>();
    active.sort_by(|left, right| {
        let left_key = (
            left.get("height").and_then(Value::as_u64).unwrap_or(0),
            left.get("snapshot_id")
                .and_then(Value::as_str)
                .unwrap_or(""),
        );
        let right_key = (
            right.get("height").and_then(Value::as_u64).unwrap_or(0),
            right
                .get("snapshot_id")
                .and_then(Value::as_str)
                .unwrap_or(""),
        );
        right_key.cmp(&left_key)
    });
    for stale in active.into_iter().skip(RETAIN_PER_CLASS) {
        stale["status"] = Value::String("retired".to_string());
        stale["superseded_by"] = Value::String(snapshot_id.to_string());
    }
    snapshots.sort_by(|left, right| {
        let left_key = (
            left.get("snapshot_class")
                .and_then(Value::as_str)
                .unwrap_or(""),
            left.get("height").and_then(Value::as_u64).unwrap_or(0),
            left.get("snapshot_id")
                .and_then(Value::as_str)
                .unwrap_or(""),
        );
        let right_key = (
            right
                .get("snapshot_class")
                .and_then(Value::as_str)
                .unwrap_or(""),
            right.get("height").and_then(Value::as_u64).unwrap_or(0),
            right
                .get("snapshot_id")
                .and_then(Value::as_str)
                .unwrap_or(""),
        );
        left_key.cmp(&right_key)
    });
    stamp_catalog_verification(&mut catalog, snapshot_id, verified_at)?;
    let snapshots = catalog
        .get("snapshots")
        .and_then(Value::as_array)
        .ok_or_else(|| "Existing archive catalog is missing snapshots.".to_string())?;
    let content_root = catalog_content_root(snapshots)?;
    catalog["consensus_fork"] = request.consensus_fork.clone();
    catalog["producer_role"] = Value::String(SOURCE_ROLE_ARCHIVE_VALIDATOR.to_string());
    catalog["producer_node_kind"] = Value::String(PRODUCER_NODE_KIND.to_string());
    catalog["catalog_schema"] = Value::String(CATALOG_SCHEMA.to_string());
    catalog["distribution_schema"] = Value::String(DISTRIBUTION_SCHEMA.to_string());
    catalog["binary_compatibility"] = Value::String(BINARY_COMPATIBILITY.to_string());
    catalog["catalog_signature_status"] = Value::String("AEGIS_PQC_VERIFIED".to_string());
    catalog["signature_scheme"] = Value::String("aegis-pqc".to_string());
    catalog["signature_domain"] = Value::String(CATALOG_DOMAIN.to_string());
    catalog["catalog_content_root"] = Value::String(content_root);
    write_signed_catalog_atomically(catalog_path, &catalog)?;
    Ok(catalog)
}

fn current_unix_timestamp() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| format!("System clock is before the Unix epoch: {error}"))
}

fn stamp_catalog_verification(
    catalog: &mut Value,
    snapshot_id: &str,
    verified_at: u64,
) -> Result<(), String> {
    catalog["updated_at"] = Value::from(verified_at);
    let snapshot = catalog
        .get_mut("snapshots")
        .and_then(Value::as_array_mut)
        .and_then(|snapshots| {
            snapshots
                .iter_mut()
                .find(|entry| entry.get("snapshot_id").and_then(Value::as_str) == Some(snapshot_id))
        })
        .ok_or_else(|| {
            format!("Archive catalog is missing newly verified snapshot {snapshot_id}.")
        })?;
    snapshot["last_verified_at"] = Value::from(verified_at);
    Ok(())
}

fn write_signed_catalog_atomically(path: &Path, catalog: &Value) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "Archive catalog has no parent directory.".to_string())?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("Failed to create {}: {error}", parent.display()))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("catalog.json");
    let temp = path.with_file_name(format!(".{file_name}.tmp-{}", Uuid::new_v4().simple()));
    let signature_path = path.with_file_name(format!("{file_name}.sig"));
    let signature_file_name = signature_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("catalog.json.sig");
    let signature_temp = signature_path.with_file_name(format!(
        ".{signature_file_name}.tmp-{}",
        Uuid::new_v4().simple()
    ));
    write_canonical_json(&temp, catalog)?;
    sign_and_verify_json(&temp, &signature_temp, CATALOG_DOMAIN)?;
    fs::rename(&signature_temp, &signature_path).map_err(|error| {
        format!(
            "Failed to publish archive catalog signature {}: {error}",
            signature_path.display()
        )
    })?;
    fs::rename(&temp, path).map_err(|error| {
        format!(
            "Failed to atomically publish current archive catalog {}: {error}",
            path.display()
        )
    })?;
    sync_directory(parent)
}

fn validate_signed_manifest(
    manifest: &Value,
    request: &ArchiveSnapshotCreateRequest,
    snapshot_root: &Path,
    manifest_path: &Path,
    signed_manifest: &Value,
) -> Result<(), String> {
    validate_snapshot_root(snapshot_root)?;
    validate_regular_file(manifest_path, "runtime snapshot manifest")?;
    if manifest
        .get("manifest_version")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        == 0
        || manifest.get("snapshot_class").and_then(Value::as_str)
            != Some(SNAPSHOT_CLASS_VALIDATOR_PRUNED)
        || manifest.get("chain_id").and_then(Value::as_u64) != Some(request.chain_id)
        || manifest.get("network_id").and_then(Value::as_str) != Some(&request.network_id)
        || manifest.get("genesis_hash").and_then(Value::as_str) != Some(&request.genesis_hash)
    {
        return Err(
            "Runtime snapshot manifest failed chain, class, or version validation.".to_string(),
        );
    }
    if signed_manifest
        .get("aegis_pq_signature")
        .and_then(Value::as_object)
        .is_none()
        || signed_manifest
            .get("signature_domain")
            .and_then(Value::as_str)
            != Some("SYNERGY_ARCHIVE_SNAPSHOT_MANIFEST_V1")
    {
        return Err("Runtime snapshot manifest is not Aegis-signed.".to_string());
    }
    if manifest
        .get("source_node_majority_branch")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err(
            "Runtime snapshot manifest does not prove the source majority branch.".to_string(),
        );
    }
    if !matches_source_role(manifest.get("source_role").and_then(Value::as_str)) {
        return Err("Runtime snapshot manifest has an invalid producer role.".to_string());
    }
    if manifest.get("consensus_fork") != Some(&request.consensus_fork) {
        return Err("Runtime snapshot manifest consensus fork mismatch.".to_string());
    }
    let files = manifest
        .get("files")
        .and_then(Value::as_array)
        .ok_or_else(|| "Runtime snapshot manifest is missing file checksums.".to_string())?;
    if files.is_empty() {
        return Err("Runtime snapshot manifest contains no state files.".to_string());
    }
    let mut manifest_paths = BTreeSet::new();
    for file in files {
        let relative = required_string(file, "relative_path")?;
        validate_state_relative_path(&relative)?;
        if !ALLOWED_STATE_FILES.contains(&relative.as_str()) {
            return Err(format!(
                "Runtime snapshot manifest contains non-approved state file {relative}."
            ));
        }
        if !manifest_paths.insert(relative.clone()) {
            return Err(format!(
                "Runtime snapshot manifest contains duplicate state file {relative}."
            ));
        }
        let path = snapshot_root.join(&relative);
        validate_regular_file(&path, &format!("runtime snapshot file {relative}"))?;
        let expected = required_string(file, "sha256")?;
        let actual = sha256_file(&path)?;
        if !actual.eq_ignore_ascii_case(&expected) {
            return Err(format!(
                "Runtime snapshot file checksum mismatch for {relative}."
            ));
        }
    }
    let manifest_name = manifest_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "Runtime snapshot manifest has no file name.".to_string())?;
    validate_relative_name(manifest_name)?;
    let materialized_files = collect_state_files(snapshot_root, manifest_name)?;
    for relative in materialized_files {
        if !manifest_paths.contains(&relative) {
            return Err(format!(
                "Runtime snapshot contains unmanifested state file {relative}."
            ));
        }
    }
    Ok(())
}

fn materialize_snapshot(
    source_root: &Path,
    manifest_path: &Path,
    destination: &Path,
) -> Result<(), String> {
    let manifest_name = manifest_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "Runtime snapshot manifest has no file name.".to_string())?;
    let files = collect_state_files(source_root, manifest_name)?;
    if files.is_empty() {
        return Err("Archive snapshot source contains no approved state files.".to_string());
    }
    fs::create_dir_all(destination)
        .map_err(|error| format!("Failed to create {}: {error}", destination.display()))?;
    for relative in files {
        let source = source_root.join(&relative);
        let target = destination.join(&relative);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("Failed to create {}: {error}", parent.display()))?;
        }
        fs::copy(&source, &target).map_err(|error| {
            format!("Failed to copy {} into snapshot: {error}", source.display())
        })?;
    }
    validate_relative_name(manifest_name)?;
    fs::copy(manifest_path, destination.join(manifest_name)).map_err(|error| {
        format!("Failed to copy signed snapshot manifest into publication: {error}")
    })?;
    Ok(())
}

fn collect_state_files(root: &Path, manifest_name: &str) -> Result<Vec<String>, String> {
    let mut files = Vec::new();
    for entry in fs::read_dir(root)
        .map_err(|error| format!("Failed to read snapshot root {}: {error}", root.display()))?
    {
        let entry = entry.map_err(|error| format!("Failed to inspect snapshot root: {error}"))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| format!("Failed to inspect {}: {error}", path.display()))?;
        if file_type.is_symlink() {
            return Err(format!(
                "Snapshot contains symlinked path {}; refusing import.",
                path.display()
            ));
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|error| format!("Failed to resolve snapshot path: {error}"))?
            .to_string_lossy()
            .replace('\\', "/");
        if path.is_dir()
            || (relative != manifest_name && !ALLOWED_STATE_FILES.contains(&relative.as_str()))
        {
            return Err(format!(
                "Snapshot contains non-approved state path {relative}."
            ));
        }
        if relative != manifest_name {
            validate_state_relative_path(&relative)?;
            files.push(relative);
        }
    }
    files.sort();
    Ok(files)
}

fn validate_snapshot_root(root: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(root).map_err(|error| {
        format!(
            "Failed to inspect snapshot root {}: {error}",
            root.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "Snapshot root {} is not a regular directory; refusing import.",
            root.display()
        ));
    }
    Ok(())
}

fn validate_regular_file(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("{label} {} is unavailable: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "{label} {} is not a regular file; refusing import.",
            path.display()
        ));
    }
    Ok(())
}

fn create_deterministic_archive(
    snapshot_root: &Path,
    archive_path: &Path,
    snapshot_id: &str,
) -> Result<String, String> {
    let output = File::create(archive_path)
        .map_err(|error| format!("Failed to create {}: {error}", archive_path.display()))?;
    let mut encoder = zstd::stream::write::Encoder::new(output, 3)
        .map_err(|error| format!("Failed to initialize zstd encoder: {error}"))?;
    encoder
        .include_checksum(false)
        .map_err(|error| format!("Failed to configure zstd encoder: {error}"))?;
    let mut builder = Builder::new(&mut encoder);
    let mut paths = fs::read_dir(snapshot_root)
        .map_err(|error| format!("Failed to read {}: {error}", snapshot_root.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("Failed to enumerate snapshot files: {error}"))?
        .into_iter()
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    paths.sort();
    for path in paths {
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| "Snapshot file has invalid UTF-8 name.".to_string())?;
        let bytes = fs::read(&path)
            .map_err(|error| format!("Failed to read {}: {error}", path.display()))?;
        let archive_name = format!("{snapshot_id}/{name}");
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_cksum();
        builder
            .append_data(&mut header, archive_name, bytes.as_slice())
            .map_err(|error| format!("Failed to append deterministic archive entry: {error}"))?;
    }
    builder
        .finish()
        .map_err(|error| format!("Failed to finish deterministic tar archive: {error}"))?;
    drop(builder);
    encoder
        .finish()
        .map_err(|error| format!("Failed to finish deterministic zstd archive: {error}"))?;
    sha256_file(archive_path)
}

fn write_chunks(
    archive_path: &Path,
    stage: &Path,
    archive_name: &str,
) -> Result<Vec<Value>, String> {
    let mut input = File::open(archive_path)
        .map_err(|error| format!("Failed to open {}: {error}", archive_path.display()))?;
    let mut chunks = Vec::new();
    let mut index = 0usize;
    loop {
        let mut bytes = vec![0u8; ARCHIVE_CHUNK_SIZE as usize];
        let count = input
            .read(&mut bytes)
            .map_err(|error| format!("Failed to read archive chunk: {error}"))?;
        if count == 0 {
            break;
        }
        bytes.truncate(count);
        let name = format!("{archive_name}.part-{index:06}");
        let path = stage.join(&name);
        fs::write(&path, &bytes)
            .map_err(|error| format!("Failed to write {}: {error}", path.display()))?;
        chunks.push(json!({
            "name": name,
            "sha256": sha256_bytes(&bytes),
            "size_bytes": count as u64,
            "index": index
        }));
        index += 1;
    }
    Ok(chunks)
}

fn build_distribution_manifest(
    request: &ArchiveSnapshotCreateRequest,
    snapshot_id: &str,
    height: u64,
    block_hash: &str,
    archive_name: &str,
    archive_sha256: &str,
    source_manifest_sha256: &str,
    created_at: u64,
    chunks: Vec<Value>,
    runtime_report: &Value,
) -> Value {
    json!({
        "schema": DISTRIBUTION_SCHEMA,
        "snapshot_id": snapshot_id,
        "snapshot_class": SNAPSHOT_CLASS_VALIDATOR_PRUNED,
        "allowed_roles": ["validator", "onboarding_validator", "quarantined_validator"],
        "supported_receiver_operating_systems": ["macos", "linux", "windows"],
        "receiver_format": {"archive_container": "tar", "compression": "zstd", "chunk_size": ARCHIVE_CHUNK_SIZE, "path_style": "relative-state-files"},
        "chain_id": request.chain_id,
        "network_id": request.network_id,
        "genesis_hash": request.genesis_hash,
        "height": height,
        "hash": block_hash,
        "created_at": created_at,
        "producer": request.source_node_id,
        "source_role": SOURCE_ROLE_ARCHIVE_VALIDATOR,
        "producer_role": SOURCE_ROLE_ARCHIVE_VALIDATOR,
        "producer_node_kind": PRODUCER_NODE_KIND,
        "catalog_schema": CATALOG_SCHEMA,
        "distribution_schema": DISTRIBUTION_SCHEMA,
        "binary_compatibility": BINARY_COMPATIBILITY,
        "signature_scheme": "aegis-pqc",
        "signature_domain": DISTRIBUTION_DOMAIN,
        "archive_filename": archive_name,
        "archive_sha256": archive_sha256,
        "source_manifest_sha256": source_manifest_sha256,
        "runtime_verification": runtime_report,
        "consensus_fork": request.consensus_fork,
        "verification_status": "green",
        "status": "published",
        "chunks": chunks
    })
}

fn verify_with_runtime(
    runtime: &Path,
    request: &ArchiveSnapshotCreateRequest,
    manifest_path: &Path,
    snapshot_root: &Path,
) -> Result<Value, String> {
    let mut command = Command::new(runtime);
    command
        .arg("verify-snapshot")
        .arg("--chain-id")
        .arg(request.chain_id.to_string())
        .arg("--network-id")
        .arg(&request.network_id)
        .arg("--genesis-hash")
        .arg(&request.genesis_hash)
        .arg("--source-workspace")
        .arg(&request.workspace)
        .arg("--manifest")
        .arg(manifest_path)
        .arg("--snapshot-root")
        .arg(snapshot_root)
        .arg("--snapshot-class")
        .arg(SNAPSHOT_CLASS_VALIDATOR_PRUNED)
        .arg("--target-role")
        .arg("validator");
    let report = run_json_command(&mut command, "archive snapshot verification")?;
    if report.get("success").and_then(Value::as_bool) != Some(true) {
        return Err(format!("Archive runtime rejected snapshot: {report}"));
    }
    Ok(report)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MajorityProofMarker {
    height: u64,
    hash: String,
}

fn validate_majority_proof(
    path: &Path,
    chain_id: u64,
    network_id: &str,
    genesis_hash: &str,
) -> Result<MajorityProofMarker, String> {
    let proof = read_json(path)?;
    if proof
        .get("source_node_majority_branch_proven")
        .and_then(Value::as_bool)
        != Some(true)
        || proof.get("chain_id").and_then(Value::as_u64) != Some(chain_id)
        || proof.get("network_id").and_then(Value::as_str) != Some(network_id)
        || proof.get("genesis_hash").and_then(Value::as_str) != Some(genesis_hash)
    {
        return Err(
            "Archive snapshot publication requires a matching majority-proof marker.".to_string(),
        );
    }
    let height = required_u64(&proof, "height")?;
    let hash = required_string(&proof, "hash")?;
    Ok(MajorityProofMarker { height, hash })
}

fn require_runtime_snapshot_matches_marker(
    marker: &MajorityProofMarker,
    runtime_report: &Value,
) -> Result<(), String> {
    let runtime_height = required_u64(runtime_report, "snapshot_height")?;
    let runtime_hash = required_string(runtime_report, "snapshot_hash")?;
    if marker.height != runtime_height || marker.hash != runtime_hash {
        return Err(format!(
            "Archive snapshot runtime created snapshot does not match the majority-proof marker: marker height={} hash={}, runtime height={} hash={}; refusing to package.",
            marker.height, marker.hash, runtime_height, runtime_hash
        ));
    }
    Ok(())
}

fn validate_canonical_testnet_request(
    request: &ArchiveSnapshotCreateRequest,
) -> Result<(), String> {
    if request.chain_id != CANONICAL_TESTNET_CHAIN_ID
        || request.network_id != CANONICAL_TESTNET_NETWORK_ID
        || !request
            .genesis_hash
            .eq_ignore_ascii_case(CANONICAL_TESTNET_GENESIS_HASH)
    {
        return Err(
            "Imported snapshot does not identify canonical Synergy Testnet v3 (chain 1266)."
                .to_string(),
        );
    }
    let fork = request.consensus_fork.as_object().ok_or_else(|| {
        "Imported snapshot requires canonical consensus fork metadata.".to_string()
    })?;
    let fork_height = fork
        .get("fork_height")
        .and_then(Value::as_u64)
        .ok_or_else(|| "Canonical consensus fork is missing fork_height.".to_string())?;
    let parent_height = fork
        .get("parent_height")
        .and_then(Value::as_u64)
        .ok_or_else(|| "Canonical consensus fork is missing parent_height.".to_string())?;
    if fork_height != parent_height.saturating_add(1)
        || required_string(&Value::Object(fork.clone()), "parent_hash").is_err()
        || required_string(&Value::Object(fork.clone()), "state_root").is_err()
        || fork.get("old_consensus_algorithm").and_then(Value::as_str) != Some("FN-DSA")
        || fork.get("new_consensus_algorithm").and_then(Value::as_str) != Some("FN-DSA")
        || fork.get("parser_mode").and_then(Value::as_str) != Some("fail_closed")
        || fork
            .get("new_validator_registry")
            .and_then(Value::as_array)
            .is_none_or(Vec::is_empty)
    {
        return Err(
            "Imported snapshot consensus fork is not canonical Testnet metadata.".to_string(),
        );
    }
    Ok(())
}

fn validate_import_runtime_report(
    report: &Value,
    marker: &MajorityProofMarker,
) -> Result<(), String> {
    require_bool(report, "success", true)?;
    if report.get("fail_closed").and_then(Value::as_bool) == Some(true) {
        return Err("Imported runtime report is marked fail_closed.".to_string());
    }
    require_bool(report, "source_node_majority_branch_proven", true)?;
    require_bool(report, "source_qc_aegis_pqc_verified", true)?;
    for field in [
        "keys_or_configs_copied",
        "genesis_mutated",
        "quorum_mutated",
        "chain_state_mutated",
        "canonical_locks_mutated",
        "committed_qcs_mutated",
    ] {
        require_bool(report, field, false)?;
    }
    let height = required_u64(report, "snapshot_height")?;
    let hash = required_string(report, "snapshot_hash")?;
    if height != marker.height || hash != marker.hash {
        return Err(format!(
            "Imported runtime report does not match the majority-proof marker: marker height={} hash={}, report height={} hash={}",
            marker.height, marker.hash, height, hash
        ));
    }
    let manifest_hash = required_string(report, "manifest_hash")?;
    if !is_sha256(Some(&manifest_hash)) {
        return Err("Imported runtime report has an invalid manifest_hash.".to_string());
    }
    if report
        .get("qc_vote_count")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        == 0
        || report
            .get("qc_signers")
            .and_then(Value::as_array)
            .is_none_or(Vec::is_empty)
    {
        return Err("Imported runtime report lacks verified committed QC evidence.".to_string());
    }
    Ok(())
}

fn validate_import_manifest(
    request: &ArchiveSnapshotCreateRequest,
    marker: &MajorityProofMarker,
    manifest: &Value,
    report: &Value,
    expected_manifest_hash: &str,
) -> Result<(), String> {
    if manifest.get("source_role").and_then(Value::as_str) != Some(RUNTIME_SNAPSHOT_SOURCE_ROLE) {
        return Err("Imported runtime snapshot source_role must remain VALIDATOR.".to_string());
    }
    let roles = manifest
        .get("allowed_restore_roles")
        .and_then(Value::as_array)
        .ok_or_else(|| "Imported runtime snapshot is missing allowed restore roles.".to_string())?;
    let actual_roles = roles
        .iter()
        .filter_map(Value::as_str)
        .map(|role| role.trim().replace('-', "_").to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    let required_roles = ["validator", "onboarding_validator", "quarantined_validator"]
        .into_iter()
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    if actual_roles != required_roles {
        return Err(
            "Imported validator-pruned snapshot has an unsupported allowed restore-role set."
                .to_string(),
        );
    }
    if required_u64(manifest, "snapshot_height")? != marker.height
        || required_string(manifest, "snapshot_block_hash")? != marker.hash
        || required_u64(manifest, "canonical_lock_height")? != marker.height
        || required_string(manifest, "canonical_lock_hash")? != marker.hash
    {
        return Err(
            "Imported runtime snapshot height/hash does not match the majority-proof marker."
                .to_string(),
        );
    }
    if manifest.get("consensus_fork") != Some(&request.consensus_fork) {
        return Err("Imported runtime snapshot consensus fork mismatch.".to_string());
    }
    let qc = manifest
        .get("qc_evidence")
        .and_then(Value::as_object)
        .ok_or_else(|| "Imported runtime snapshot is missing committed QC evidence.".to_string())?;
    if qc.get("aegis_pqc_verified").and_then(Value::as_bool) != Some(true)
        || qc
            .get("duplicate_signer_check_passed")
            .and_then(Value::as_bool)
            != Some(true)
        || qc
            .get("relayers_rpc_support_counted_toward_quorum")
            .and_then(Value::as_bool)
            != Some(false)
        || qc.get("committed_qc_height").and_then(Value::as_u64) != Some(marker.height)
        || qc
            .get("committed_qc_hash")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || qc.get("vote_count").and_then(Value::as_u64).unwrap_or(0) == 0
        || qc
            .get("signer_set")
            .and_then(Value::as_array)
            .is_none_or(Vec::is_empty)
    {
        return Err(
            "Imported runtime snapshot lacks verified committed QC/Aegis evidence.".to_string(),
        );
    }
    if report.get("manifest_hash").and_then(Value::as_str) != Some(expected_manifest_hash) {
        return Err("Imported runtime report manifest hash is inconsistent.".to_string());
    }
    Ok(())
}

fn validate_runtime_verification_report(
    report: &Value,
    marker: &MajorityProofMarker,
    expected_manifest_hash: &str,
) -> Result<(), String> {
    require_bool(report, "success", true)?;
    if report.get("fail_closed").and_then(Value::as_bool) == Some(true) {
        return Err("Archive runtime verification report is marked fail_closed.".to_string());
    }
    if report.get("snapshot_class").and_then(Value::as_str) != Some(SNAPSHOT_CLASS_VALIDATOR_PRUNED)
        || report.get("source_role").and_then(Value::as_str) != Some(RUNTIME_SNAPSHOT_SOURCE_ROLE)
        || required_u64(report, "snapshot_height")? != marker.height
        || report.get("manifest_hash").and_then(Value::as_str) != Some(expected_manifest_hash)
    {
        return Err(
            "Archive runtime verification report does not match imported snapshot.".to_string(),
        );
    }
    for field in [
        "source_qc_aegis_pqc_verified",
        "duplicate_signer_check_passed",
        "manifest_signature_verified",
        "file_checksums_verified",
    ] {
        require_bool(report, field, true)?;
    }
    if required_u64(report, "committed_qc_height")? != marker.height
        || required_string(report, "committed_qc_hash")?.is_empty()
        || report
            .get("committed_qc_vote_count")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            == 0
        || report
            .get("committed_qc_signers")
            .and_then(Value::as_array)
            .is_none_or(Vec::is_empty)
        || report
            .get("relayers_rpc_support_counted_toward_quorum")
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err(
            "Archive runtime verification did not prove committed QC/Aegis evidence.".to_string(),
        );
    }
    if let Some(materialized) = report.get("materialized_state") {
        if materialized
            .get("snapshot_metadata_consistent")
            .and_then(Value::as_bool)
            != Some(true)
        {
            return Err(
                "Archive runtime verification reported inconsistent materialized state."
                    .to_string(),
            );
        }
    }
    Ok(())
}

fn configured_runtime() -> Result<PathBuf, String> {
    std::env::var_os("SYNERGY_ARCHIVE_RUNTIME")
        .or_else(|| std::env::var_os("SYNERGY_TESTNET_RUNTIME"))
        .map(PathBuf::from)
        .filter(|path| path.is_file())
        .ok_or_else(|| {
            "Archive snapshot lifecycle requires SYNERGY_ARCHIVE_RUNTIME or SYNERGY_TESTNET_RUNTIME pointing to the packaged runtime verifier.".to_string()
        })
}

fn sign_and_verify_json(input: &Path, signature: &Path, domain: &str) -> Result<(), String> {
    let signer = std::env::var_os("SYNERGY_AEGIS_CLI")
        .map(PathBuf::from)
        .filter(|path| path.is_file())
        .ok_or_else(|| {
            "Archive snapshot publication requires SYNERGY_AEGIS_CLI for distribution signing."
                .to_string()
        })?;
    let status = Command::new(&signer)
        .args(["sign-json", "--domain", domain, "--input"])
        .arg(input)
        .args(["--output"])
        .arg(signature)
        .stdout(Stdio::null())
        .status()
        .map_err(|error| format!("Failed to run archive distribution signer: {error}"))?;
    if !status.success() || !signature.is_file() {
        return Err("Archive distribution manifest signing failed closed.".to_string());
    }
    let expected_signer = expected_archive_signer_sha256()?;
    let status = Command::new(&signer)
        .args(["verify-json", "--domain", domain, "--input"])
        .arg(input)
        .args(["--signature"])
        .arg(signature)
        .args(["--expected-signer-sha256", &expected_signer])
        .stdout(Stdio::null())
        .status()
        .map_err(|error| format!("Failed to run archive distribution verifier: {error}"))?;
    if !status.success() {
        return Err(
            "Archive distribution manifest signature verification failed closed.".to_string(),
        );
    }
    Ok(())
}

fn expected_archive_signer_sha256() -> Result<String, String> {
    if let Ok(value) = std::env::var("SYNERGY_AEGIS_ARCHIVE_SIGNER_SHA256") {
        return normalize_archive_signer_sha256(&value);
    }

    let resource_root = std::env::var_os("SYNERGY_RESOURCE_ROOT")
        .map(PathBuf::from)
        .or_else(|| std::env::current_dir().ok())
        .ok_or_else(|| {
            "Archive snapshot verification requires the pinned archive authority fingerprint."
                .to_string()
        })?;
    let authority_path = resource_root
        .join("testnet")
        .join("runtime")
        .join("configs")
        .join("archive-snapshot-authority.json");
    let authority = read_json(&authority_path).map_err(|error| {
        format!("Archive snapshot verification requires pinned authority metadata: {error}")
    })?;
    let value = authority
        .get("signer_public_key_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            format!(
                "Archive authority metadata {} is missing signer_public_key_sha256.",
                authority_path.display()
            )
        })?;
    normalize_archive_signer_sha256(value)
}

fn normalize_archive_signer_sha256(value: &str) -> Result<String, String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.len() != 64 || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(
            "Archive authority signer fingerprint must be a 64-character SHA-256 hex value."
                .to_string(),
        );
    }
    Ok(normalized)
}

fn run_json_command(command: &mut Command, operation: &str) -> Result<Value, String> {
    let output = command
        .output()
        .map_err(|error| format!("Failed to run {operation}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "{operation} failed closed with exit {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("{operation} did not return JSON: {error}"))
}

fn required_path(value: &Value, key: &str) -> Result<PathBuf, String> {
    required_string(value, key).map(PathBuf::from)
}

fn required_string(value: &Value, key: &str) -> Result<String, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| format!("Archive snapshot metadata is missing {key}."))
}

fn required_u64(value: &Value, key: &str) -> Result<u64, String> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("Archive snapshot metadata is missing {key}."))
}

fn require_bool(value: &Value, key: &str, expected: bool) -> Result<(), String> {
    if value.get(key).and_then(Value::as_bool) == Some(expected) {
        Ok(())
    } else {
        Err(format!(
            "Archive snapshot metadata requires {key}={expected}."
        ))
    }
}

fn matches_source_role(value: Option<&str>) -> bool {
    matches!(
        value
            .map(|role| role.trim().replace('-', "_").to_ascii_lowercase())
            .as_deref(),
        Some("archive_validator") | Some("archive_node") | Some("validator")
    )
}

fn require_compatibility_metadata(value: &Value, label: &str) -> Result<(), String> {
    if value.get("producer_role").and_then(Value::as_str) != Some(SOURCE_ROLE_ARCHIVE_VALIDATOR)
        || value.get("producer_node_kind").and_then(Value::as_str) != Some(PRODUCER_NODE_KIND)
        || value.get("catalog_schema").and_then(Value::as_str) != Some(CATALOG_SCHEMA)
        || value.get("distribution_schema").and_then(Value::as_str) != Some(DISTRIBUTION_SCHEMA)
        || value.get("binary_compatibility").and_then(Value::as_str) != Some(BINARY_COMPATIBILITY)
    {
        return Err(format!(
            "Archive {label} has missing or incompatible producer/schema/binary metadata."
        ));
    }
    Ok(())
}

fn validate_artifact_url(value: &Value, field: &str, expected_suffix: &str) -> Result<(), String> {
    let url = required_string(value, field)?;
    if !(url.starts_with("https://") || url.starts_with("http://"))
        || url.chars().any(char::is_whitespace)
        || !url
            .split('?')
            .next()
            .unwrap_or_default()
            .ends_with(expected_suffix)
    {
        return Err(format!(
            "Archive catalog artifact URL {field} is missing, non-public, or has an unexpected path."
        ));
    }
    Ok(())
}

fn validate_state_relative_path(path: &str) -> Result<(), String> {
    if path.is_empty() || path.starts_with('/') || path.contains("..") {
        return Err(format!("Snapshot path is not relative and safe: {path}"));
    }
    if FORBIDDEN_PATH_FRAGMENTS
        .iter()
        .any(|fragment| path.to_ascii_lowercase().contains(fragment))
    {
        return Err(format!("Snapshot path contains forbidden material: {path}"));
    }
    Ok(())
}

fn validate_relative_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.contains('/')
        || name.contains('\\')
        || name == "."
        || name == ".."
        || name.starts_with('.')
    {
        return Err(format!("Archive name is not a safe relative name: {name}"));
    }
    Ok(())
}

fn immutable_snapshot_id(height: u64, block_hash: &str) -> String {
    let suffix = block_hash
        .chars()
        .filter(|character| character.is_ascii_hexdigit())
        .take(16)
        .collect::<String>()
        .to_ascii_lowercase();
    format!("snapshot-{height:09}-{suffix}")
}

fn is_sha256(value: Option<&str>) -> bool {
    value.is_some_and(|value| {
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file = File::open(path)
        .map_err(|error| format!("Failed to open {} for hashing: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 1024 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("Failed to read {} for hashing: {error}", path.display()))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn catalog_content_root(snapshots: &[Value]) -> Result<String, String> {
    let mut hasher = Sha256::new();
    for snapshot in snapshots {
        let bytes = serde_json::to_vec(snapshot)
            .map_err(|error| format!("Failed to canonicalize archive catalog entry: {error}"))?;
        hasher.update(bytes);
        hasher.update([0]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn read_json(path: &Path) -> Result<Value, String> {
    let contents = fs::read_to_string(path)
        .map_err(|error| format!("Failed to read {}: {error}", path.display()))?;
    serde_json::from_str(&contents)
        .map_err(|error| format!("Failed to parse {}: {error}", path.display()))
}

fn write_canonical_json(path: &Path, value: &Value) -> Result<(), String> {
    let canonical = canonicalize_json(value);
    let bytes = serde_json::to_vec_pretty(&canonical)
        .map_err(|error| format!("Failed to serialize {}: {error}", path.display()))?;
    let mut file = File::create(path)
        .map_err(|error| format!("Failed to create {}: {error}", path.display()))?;
    file.write_all(&bytes)
        .and_then(|_| file.write_all(b"\n"))
        .map_err(|error| format!("Failed to write {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("Failed to sync {}: {error}", path.display()))
}

fn canonicalize_json(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut sorted = Map::new();
            let mut keys = object.keys().collect::<Vec<_>>();
            keys.sort();
            for key in keys {
                sorted.insert(key.clone(), canonicalize_json(&object[key]));
            }
            Value::Object(sorted)
        }
        Value::Array(values) => Value::Array(values.iter().map(canonicalize_json).collect()),
        other => other.clone(),
    }
}

fn sync_directory(path: &Path) -> Result<(), String> {
    let directory = File::open(path)
        .map_err(|error| format!("Failed to open {} for sync: {error}", path.display()))?;
    match directory.sync_all() {
        Ok(()) => Ok(()),
        Err(error) if directory_sync_is_unsupported(&error) => Ok(()),
        Err(error) => Err(format!("Failed to sync {}: {error}", path.display())),
    }
}

fn directory_sync_is_unsupported(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::Unsupported
        || matches!(error.raw_os_error(), Some(45) | Some(95))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Mutex, OnceLock};

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    struct EnvironmentGuard {
        previous: Vec<(&'static str, Option<OsString>)>,
    }

    impl EnvironmentGuard {
        fn clear(names: &[&'static str]) -> Self {
            let previous = names
                .iter()
                .map(|name| (*name, std::env::var_os(name)))
                .collect::<Vec<_>>();
            for name in names {
                std::env::remove_var(name);
            }
            Self { previous }
        }
    }

    impl Drop for EnvironmentGuard {
        fn drop(&mut self) {
            for (name, value) in self.previous.drain(..) {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
    }

    #[test]
    fn validator_pruned_runtime_source_role_matches_testnet_policy() {
        assert_eq!(RUNTIME_SNAPSHOT_SOURCE_ROLE, "VALIDATOR");
        assert_eq!(SOURCE_ROLE_ARCHIVE_VALIDATOR, "archive_validator");
    }

    #[test]
    fn directory_sync_tolerates_only_unsupported_filesystems() {
        assert!(directory_sync_is_unsupported(
            &std::io::Error::from_raw_os_error(45)
        ));
        assert!(directory_sync_is_unsupported(
            &std::io::Error::from_raw_os_error(95)
        ));
        assert!(!directory_sync_is_unsupported(
            &std::io::Error::from_raw_os_error(5)
        ));
    }

    fn fork() -> Value {
        json!({"fork_height": 10, "parent_hash": "abc"})
    }

    fn import_fork() -> Value {
        json!({
            "fork_height": 10,
            "parent_height": 9,
            "parent_hash": "parent-hash",
            "state_root": "state-root",
            "old_consensus_algorithm": "FN-DSA",
            "new_consensus_algorithm": "FN-DSA",
            "new_validator_registry": [{"validator_address": "validator-1"}],
            "parser_mode": "fail_closed"
        })
    }

    fn import_request(marker_path: &Path, consensus_fork: Value) -> ArchiveSnapshotCreateRequest {
        ArchiveSnapshotCreateRequest {
            workspace: PathBuf::from("/archive/workspace"),
            publish_root: PathBuf::from("/archive/published"),
            source_node_id: "archive-validator".to_string(),
            chain_id: CANONICAL_TESTNET_CHAIN_ID,
            network_id: CANONICAL_TESTNET_NETWORK_ID.to_string(),
            genesis_hash: CANONICAL_TESTNET_GENESIS_HASH.to_string(),
            consensus_fork,
            majority_proof_marker: marker_path.to_path_buf(),
        }
    }

    fn write_import_fixture(root: &Path, snapshot_class: &str) -> Value {
        let account_state = b"{\"accounts\":[]}";
        let canonical_locks = b"{\"100\":{\"block_hash\":\"block-hash\"}}";
        fs::write(root.join("account_state.json"), account_state).unwrap();
        fs::write(root.join("canonical_locks.json"), canonical_locks).unwrap();
        let files = json!([
            {"relative_path": "account_state.json", "sha256": sha256_bytes(account_state), "bytes": account_state.len()},
            {"relative_path": "canonical_locks.json", "sha256": sha256_bytes(canonical_locks), "bytes": canonical_locks.len()}
        ]);
        let manifest = json!({
            "manifest_version": 1,
            "snapshot_class": snapshot_class,
            "chain_id": CANONICAL_TESTNET_CHAIN_ID,
            "network_id": CANONICAL_TESTNET_NETWORK_ID,
            "genesis_hash": CANONICAL_TESTNET_GENESIS_HASH,
            "source_node_majority_branch": true,
            "source_role": RUNTIME_SNAPSHOT_SOURCE_ROLE,
            "allowed_restore_roles": ["validator", "onboarding_validator", "quarantined_validator"],
            "snapshot_height": 100,
            "snapshot_block_hash": "block-hash",
            "canonical_lock_height": 100,
            "canonical_lock_hash": "block-hash",
            "consensus_fork": import_fork(),
            "qc_evidence": {
                "committed_qc_height": 100,
                "committed_qc_hash": "qc-hash",
                "vote_count": 4,
                "signer_set": ["validator-1", "validator-2", "validator-3", "validator-4"],
                "aegis_pqc_verified": true,
                "duplicate_signer_check_passed": true,
                "relayers_rpc_support_counted_toward_quorum": false
            },
            "files": files
        });
        let signed = json!({
            "manifest": manifest,
            "signature_domain": "SYNERGY_ARCHIVE_SNAPSHOT_MANIFEST_V1",
            "aegis_pq_signature": {"algorithm": "FN-DSA", "signature_bytes": "fixture"}
        });
        write_canonical_json(&root.join("snapshot-100-manifest.json"), &signed).unwrap();
        json!({
            "success": true,
            "source_node_majority_branch_proven": true,
            "source_qc_aegis_pqc_verified": true,
            "keys_or_configs_copied": false,
            "genesis_mutated": false,
            "quorum_mutated": false,
            "chain_state_mutated": false,
            "canonical_locks_mutated": false,
            "committed_qcs_mutated": false,
            "snapshot_height": 100,
            "snapshot_hash": "block-hash",
            "manifest_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "manifest_path": "/validator/data/snapshots/snapshot-100-manifest.json",
            "qc_vote_count": 4,
            "qc_signers": ["validator-1", "validator-2", "validator-3", "validator-4"]
        })
    }

    fn import_marker() -> MajorityProofMarker {
        MajorityProofMarker {
            height: 100,
            hash: "block-hash".to_string(),
        }
    }

    #[cfg(unix)]
    fn write_fake_aegis_cli(path: &Path) {
        fs::write(
            path,
            r#"#!/bin/sh
set -eu
command="$1"
shift
case "$command" in
  sign-json)
    output=""
    while [ "$#" -gt 0 ]; do
      if [ "$1" = "--output" ]; then
        output="$2"
        shift 2
      else
        shift
      fi
    done
    [ -n "$output" ]
    printf '%s\n' 'test-signature' > "$output"
    ;;
  verify-json)
    ;;
  *)
    exit 1
    ;;
esac
"#,
        )
        .unwrap();
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).unwrap();
    }

    #[test]
    fn imported_validator_snapshot_source_passes_all_local_gates() {
        let root = tempfile::tempdir().unwrap();
        let report = write_import_fixture(root.path(), SNAPSHOT_CLASS_VALIDATOR_PRUNED);
        let request = import_request(root.path(), import_fork());
        validate_canonical_testnet_request(&request)
            .expect("fixture uses canonical Testnet metadata");
        let (manifest_path, signed) =
            validate_imported_snapshot_source(&request, &import_marker(), root.path(), &report)
                .expect("valid validator-pruned import should pass");
        assert_eq!(
            manifest_path.file_name().unwrap(),
            "snapshot-100-manifest.json"
        );
        assert_eq!(
            signed["manifest"]["source_role"],
            json!(RUNTIME_SNAPSHOT_SOURCE_ROLE)
        );
    }

    #[test]
    fn imported_snapshot_hash_must_match_majority_proof() {
        let root = tempfile::tempdir().unwrap();
        let mut report = write_import_fixture(root.path(), SNAPSHOT_CLASS_VALIDATOR_PRUNED);
        report["snapshot_hash"] = json!("wrong-hash");
        let request = import_request(root.path(), import_fork());
        let error =
            validate_imported_snapshot_source(&request, &import_marker(), root.path(), &report)
                .expect_err("hash mismatch must fail closed");
        assert!(error.contains("majority-proof marker"), "{error}");
    }

    #[test]
    fn imported_manifest_hash_and_height_must_match_runtime_report() {
        let root = tempfile::tempdir().unwrap();
        let report = write_import_fixture(root.path(), SNAPSHOT_CLASS_VALIDATOR_PRUNED);
        let mut signed = read_json(&root.path().join("snapshot-100-manifest.json")).unwrap();
        signed["manifest"]["snapshot_block_hash"] = json!("different-hash");
        write_canonical_json(&root.path().join("snapshot-100-manifest.json"), &signed).unwrap();
        let request = import_request(root.path(), import_fork());
        let error =
            validate_imported_snapshot_source(&request, &import_marker(), root.path(), &report)
                .expect_err("manifest/report mismatch must fail closed");
        assert!(error.contains("height/hash"), "{error}");
    }

    #[test]
    fn imported_snapshot_identity_must_be_canonical_testnet() {
        let root = tempfile::tempdir().unwrap();
        let report = write_import_fixture(root.path(), SNAPSHOT_CLASS_VALIDATOR_PRUNED);
        let mut request = import_request(root.path(), import_fork());
        request.genesis_hash = "wrong-genesis".to_string();
        let error = validate_canonical_testnet_request(&request)
            .expect_err("wrong Testnet identity must fail closed");
        assert!(error.contains("canonical Synergy Testnet v3"), "{error}");
        assert!(report["success"].as_bool().unwrap());
    }

    #[test]
    fn imported_snapshot_rejects_missing_materialized_file() {
        let root = tempfile::tempdir().unwrap();
        let report = write_import_fixture(root.path(), SNAPSHOT_CLASS_VALIDATOR_PRUNED);
        fs::remove_file(root.path().join("account_state.json")).unwrap();
        let request = import_request(root.path(), import_fork());
        let error =
            validate_imported_snapshot_source(&request, &import_marker(), root.path(), &report)
                .expect_err("missing state file must fail closed");
        assert!(error.contains("account_state.json"), "{error}");
    }

    #[test]
    fn imported_snapshot_rejects_wrong_snapshot_class() {
        let root = tempfile::tempdir().unwrap();
        let report = write_import_fixture(root.path(), "archive-full");
        let request = import_request(root.path(), import_fork());
        let error =
            validate_imported_snapshot_source(&request, &import_marker(), root.path(), &report)
                .expect_err("wrong snapshot class must fail closed");
        assert!(error.contains("chain, class, or version"), "{error}");
    }

    fn catalog_entry() -> Value {
        json!({
            "snapshot_id": "snapshot-000000010-abcdef12",
            "snapshot_class": SNAPSHOT_CLASS_VALIDATOR_PRUNED,
            "chain_id": 1266,
            "network_id": "synergy-testnet-v3",
            "genesis_hash": "genesis",
            "height": 10,
            "hash": "abcdef1234567890",
            "archive_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "manifest_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "manifest_signature_status": "AEGIS_PQC_VERIFIED",
            "source_role": SOURCE_ROLE_ARCHIVE_VALIDATOR,
            "producer_role": SOURCE_ROLE_ARCHIVE_VALIDATOR,
            "producer_node_kind": PRODUCER_NODE_KIND,
            "catalog_schema": CATALOG_SCHEMA,
            "distribution_schema": DISTRIBUTION_SCHEMA,
            "binary_compatibility": BINARY_COMPATIBILITY,
            "allowed_roles": ["validator"],
            "archive_filename": "snapshot.tar.zst",
            "receiver_format": {"archive_container": "tar", "compression": "zstd"},
            "supported_receiver_operating_systems": ["macos", "linux", "windows"],
            "snapshot_url": "https://archive.example/snapshots/10/snapshot.tar.zst",
            "manifest_url": "https://archive.example/snapshots/10/distribution-manifest.json",
            "manifest_signature_url": "https://archive.example/snapshots/10/signature.sig",
            "checksums_url": "https://archive.example/snapshots/10/checksums.sha256",
            "consensus_fork": fork(),
            "status": "published"
        })
    }

    fn catalog_with(entry: Value) -> Value {
        let snapshots = vec![entry];
        json!({
            "schema": CATALOG_SCHEMA,
            "chain_id": 1266,
            "network_id": "synergy-testnet-v3",
            "genesis_hash": "genesis",
            "producer_role": SOURCE_ROLE_ARCHIVE_VALIDATOR,
            "producer_node_kind": PRODUCER_NODE_KIND,
            "catalog_schema": CATALOG_SCHEMA,
            "distribution_schema": DISTRIBUTION_SCHEMA,
            "binary_compatibility": BINARY_COMPATIBILITY,
            "catalog_signature_status": "AEGIS_PQC_VERIFIED",
            "signature_scheme": "aegis-pqc",
            "signature_domain": CATALOG_DOMAIN,
            "catalog_content_root": catalog_content_root(&snapshots).unwrap(),
            "snapshots": snapshots
        })
    }

    #[test]
    fn catalog_rejects_non_archive_validator_provenance() {
        let mut entry = catalog_entry();
        entry["producer_role"] = json!("GENESIS_VALIDATOR");
        let error = validate_catalog_for_consumer(
            &catalog_with(entry),
            1266,
            "synergy-testnet-v3",
            "genesis",
            &fork(),
        )
        .expect_err("genesis validator provenance must be rejected");
        assert!(error.contains("archive_validator provenance"), "{error}");
    }

    #[test]
    fn catalog_rejects_missing_or_untrusted_artifact_url() {
        let mut entry = catalog_entry();
        entry["snapshot_url"] = json!("/local/snapshot.tar.zst");
        let error = validate_catalog_for_consumer(
            &catalog_with(entry),
            1266,
            "synergy-testnet-v3",
            "genesis",
            &fork(),
        )
        .expect_err("catalog must provide public artifact URLs");
        assert!(error.contains("artifact URL snapshot_url"), "{error}");
    }

    #[test]
    fn catalog_rejects_incompatible_binary_metadata() {
        let mut entry = catalog_entry();
        entry["binary_compatibility"] = json!("legacy-validator");
        let error = validate_catalog_for_consumer(
            &catalog_with(entry),
            1266,
            "synergy-testnet-v3",
            "genesis",
            &fork(),
        )
        .expect_err("legacy binary compatibility must be rejected");
        assert!(error.contains("incompatible"), "{error}");
    }

    #[test]
    fn publication_stamps_catalog_and_verified_snapshot_freshness() {
        let snapshot_id = "snapshot-000000010-abcdef12";
        let mut catalog = catalog_with(catalog_entry());

        stamp_catalog_verification(&mut catalog, snapshot_id, 1_725_000_000).unwrap();

        assert_eq!(catalog["updated_at"], json!(1_725_000_000_u64));
        assert_eq!(
            catalog["snapshots"][0]["last_verified_at"],
            json!(1_725_000_000_u64)
        );
    }

    #[cfg(unix)]
    #[test]
    fn publication_catalog_hashes_exact_distribution_manifest_bytes() {
        let _env_lock = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
        let env_names = [
            "SYNERGY_AEGIS_CLI",
            "SYNERGY_AEGIS_ARCHIVE_SIGNER_SHA256",
            "SYNERGY_SNAPSHOT_LOCAL_ONLY",
            "SYNERGY_SNAPSHOT_R2_ENDPOINT",
            "SYNERGY_SNAPSHOT_R2_BUCKET",
            "SYNERGY_SNAPSHOT_PUBLIC_BASE_URL",
            "SYNERGY_SNAPSHOT_R2_ACCESS_KEY_ID",
            "SYNERGY_SNAPSHOT_R2_SECRET_ACCESS_KEY",
        ];
        let _environment = EnvironmentGuard::clear(&env_names);
        let root = tempfile::tempdir().unwrap();
        let source_root = root.path().join("source");
        fs::create_dir_all(&source_root).unwrap();
        let runtime_report = write_import_fixture(&source_root, SNAPSHOT_CLASS_VALIDATOR_PRUNED);
        let source_manifest_path = source_root.join("snapshot-100-manifest.json");
        let source_manifest_sha256 = sha256_file(&source_manifest_path).unwrap();
        let signer_path = root.path().join("aegis-test-signer");
        write_fake_aegis_cli(&signer_path);
        std::env::set_var("SYNERGY_AEGIS_CLI", &signer_path);
        std::env::set_var(
            "SYNERGY_AEGIS_ARCHIVE_SIGNER_SHA256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        std::env::set_var("SYNERGY_SNAPSHOT_LOCAL_ONLY", "true");
        std::env::set_var("SYNERGY_SNAPSHOT_R2_BUCKET", "snapshot-test");
        std::env::set_var(
            "SYNERGY_SNAPSHOT_PUBLIC_BASE_URL",
            "https://archive.example",
        );

        let mut request = import_request(root.path(), import_fork());
        request.workspace = source_root.clone();
        request.publish_root = root.path().join("published");
        let publication = publish_preverified(
            &request,
            &source_root,
            &source_manifest_path,
            &runtime_report,
        )
        .expect("valid snapshot should publish");

        let distribution_path =
            PathBuf::from(&publication.snapshot_path).join("distribution-manifest.json");
        let distribution_bytes = fs::read(&distribution_path).unwrap();
        let distribution_sha256 = sha256_bytes(&distribution_bytes);
        let distribution = read_json(&distribution_path).unwrap();
        let catalog = read_json(Path::new(&publication.catalog_path)).unwrap();
        let catalog_snapshot = catalog["snapshots"]
            .as_array()
            .unwrap()
            .iter()
            .find(|snapshot| snapshot["snapshot_id"] == publication.snapshot_id)
            .unwrap();

        assert_eq!(
            distribution["source_manifest_sha256"].as_str(),
            Some(source_manifest_sha256.as_str())
        );
        assert_ne!(distribution_sha256, source_manifest_sha256);
        assert_eq!(
            catalog_snapshot["manifest_sha256"].as_str(),
            Some(distribution_sha256.as_str())
        );
        assert_eq!(publication.manifest_sha256, distribution_sha256);
    }

    #[test]
    fn archive_authority_fingerprint_is_normalized_and_fail_closed() {
        assert_eq!(
            normalize_archive_signer_sha256(
                "8411D9BFF2E669F69E1D649600EA80FB60AAD663959DBB4D45B5E64C3C613199"
            )
            .unwrap(),
            "8411d9bff2e669f69e1d649600ea80fb60aad663959dbb4d45b5e64c3c613199"
        );
        assert!(normalize_archive_signer_sha256("untrusted").is_err());
    }

    #[test]
    fn stale_majority_proof_marker_rejects_runtime_snapshot() {
        let marker = MajorityProofMarker {
            height: 100,
            hash: "marker-hash".to_string(),
        };
        let error = require_runtime_snapshot_matches_marker(
            &marker,
            &json!({
                "snapshot_height": 101,
                "snapshot_hash": "runtime-hash"
            }),
        )
        .expect_err("runtime snapshot must match the marker exactly");
        assert!(
            error.contains("does not match the majority-proof marker"),
            "{error}"
        );
        assert!(
            error.contains("marker height=100 hash=marker-hash"),
            "{error}"
        );
    }

    #[test]
    fn local_only_r2_config_does_not_require_upload_credentials() {
        let _guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
        let names = [
            "SYNERGY_SNAPSHOT_LOCAL_ONLY",
            "SYNERGY_SNAPSHOT_R2_ENDPOINT",
            "SYNERGY_SNAPSHOT_R2_BUCKET",
            "SYNERGY_SNAPSHOT_PUBLIC_BASE_URL",
            "SYNERGY_SNAPSHOT_R2_ACCESS_KEY_ID",
            "SYNERGY_SNAPSHOT_R2_SECRET_ACCESS_KEY",
        ];
        let _environment = EnvironmentGuard::clear(&names);
        std::env::set_var("SYNERGY_SNAPSHOT_LOCAL_ONLY", "true");
        std::env::set_var("SYNERGY_SNAPSHOT_R2_BUCKET", "testnet-snapshot");
        std::env::set_var(
            "SYNERGY_SNAPSHOT_PUBLIC_BASE_URL",
            "https://archive.example/",
        );

        let config =
            r2_config().expect("local-only config should be valid without R2 upload credentials");
        assert!(config.local_only);
        assert_eq!(config.bucket, "testnet-snapshot");
        assert_eq!(config.public_base_url, "https://archive.example");
        assert!(config.endpoint.is_none());
        assert!(config.access_key_id.is_none());
        assert!(config.secret_access_key.is_none());
        assert!(r2_command(&config).is_err());
    }

    #[test]
    fn r2_publication_includes_every_declared_snapshot_chunk() {
        let root = tempfile::tempdir().unwrap();
        let snapshot = root.path().join("snapshot");
        fs::create_dir_all(&snapshot).unwrap();
        write_canonical_json(
            &snapshot.join("distribution-manifest.json"),
            &json!({
                "chunks": [
                    {"name": "snapshot.tar.zst.part-000000"},
                    {"name": "snapshot.tar.zst.part-000001"}
                ]
            }),
        )
        .unwrap();

        let artifacts = r2_snapshot_artifacts(
            &snapshot,
            &snapshot.join("snapshot.tar.zst"),
            &snapshot.join("checksums.sha256"),
            "snapshots/843613",
        )
        .unwrap();
        let keys = artifacts
            .into_iter()
            .map(|(_, key)| key)
            .collect::<Vec<_>>();

        assert!(keys.contains(&"snapshots/843613/snapshot.tar.zst.part-000000".to_string()));
        assert!(keys.contains(&"snapshots/843613/snapshot.tar.zst.part-000001".to_string()));
    }
}
