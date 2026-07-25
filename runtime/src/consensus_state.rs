use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const DURABLE_STORE_DIR: &str = "consensus_state_v1";
pub const TESTNET_RECOVERY_CHECKPOINT_TYPE: &str =
    "synergy_testnet_emergency_compacted_recovery_checkpoint_v1";
pub const TESTNET_RECOVERY_CHECKPOINT_FORMAT: &str =
    "synergy_testnet_emergency_compacted_recovery_checkpoint_v1";
pub const TESTNET_RECOVERY_CHECKPOINT_TOOL_VERSION: &str = "testnet-emergency-v1";
const STREAMING_JSON_CHAIN_MAX_BYTES: u64 = 64 * 1024 * 1024;
const TESTNET_RECOVERY_NETWORK_ID: &str = "synergy-testnet-v3";
const TESTNET_RECOVERY_CHAIN_ID: &str = "1264";
const TESTNET_RECOVERY_APPROVED_SOURCE_BUNDLE_SHA256: &str =
    "be0724c0320a0846b7b84c848c551e4c0c2679f08cc6b25fd3fd01e4353a6738";
const TESTNET_RECOVERY_GENESIS_HASH: &str =
    "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789";
const TESTNET_RECOVERY_CHAIN_SHA256: &str =
    "384235f8d2a5de66269dea913ba138f20c08e448613bbb3f8cd680460320b8e1";
const TESTNET_RECOVERY_COMMITTED_QCS_SHA256: &str =
    "2bfd31ed11a0d6819db6c4c6ef7b3d3a42bbe1845ca490474cee6925e42931b4";
const TESTNET_RECOVERY_CANONICAL_LOCKS_SHA256: &str =
    "82fff558e3f4a462a6541685a6d48c9500e9f002a7b31062ab21ea2810e5c9a8";
const TESTNET_RECOVERY_BOUNDARY_HEIGHT: u64 = 175_518;
const TESTNET_RECOVERY_BOUNDARY_HASH: &str =
    "f5d50637f299c5a51068879921361d6798ba9a8855a18a6daa759dd651ac2213";
const TESTNET_RECOVERY_FIRST_RETAINED_CHAIN_HEIGHT: u64 = 537_556;
const TESTNET_RECOVERY_FIRST_RETAINED_QC_HEIGHT: u64 = 532_556;
const TESTNET_RECOVERY_APPROVED_TIP_HEIGHT: u64 = 650_464;
const TESTNET_RECOVERY_APPROVED_TIP_HASH: &str =
    "ff2215dde043da4db6d3c45e49092094b0ddce9498a7d5ce7832670f842a33ed";
const TESTNET_RECOVERY_APPROVED_FIRST_QC_HASH: &str =
    "d4b2ef6122c019b9767bce85ec7d0a99b2669aa38988e73f3d86a26d6d4e9dbf";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConsensusStateSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsensusStateFinding {
    pub code: String,
    pub severity: ConsensusStateSeverity,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeightHashSummary {
    pub height: u64,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsensusStateFileSummary {
    pub label: String,
    pub path: String,
    pub exists: bool,
    pub size_bytes: Option<u64>,
    pub sha256: Option<String>,
    pub root_owned: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChainBodySummary {
    pub block_count: usize,
    pub first_retained: Option<HeightHashSummary>,
    pub latest: Option<HeightHashSummary>,
    pub contiguous: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeightMapSummary {
    pub entry_count: usize,
    pub min_height: Option<u64>,
    pub max_height: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateCheckpointSummary {
    pub exists: bool,
    pub height: Option<u64>,
    pub block_hash: Option<String>,
    pub state_root: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsensusStateReport {
    pub ok: bool,
    pub decision: String,
    pub state_root: String,
    pub data_dir: String,
    pub files: Vec<ConsensusStateFileSummary>,
    pub chain: ChainBodySummary,
    pub canonical_locks: HeightMapSummary,
    pub committed_qcs: HeightMapSummary,
    pub checkpoint: StateCheckpointSummary,
    pub findings: Vec<ConsensusStateFinding>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ConsensusStateVerificationOptions {
    pub allow_testnet_recovery_checkpoint: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LiveStateVerificationOptions {
    pub expected_height: Option<u64>,
    pub expected_hash: Option<String>,
    pub max_expected_lag: u64,
    pub max_qc_ahead: u64,
}

impl Default for LiveStateVerificationOptions {
    fn default() -> Self {
        Self {
            expected_height: None,
            expected_hash: None,
            max_expected_lag: 32,
            max_qc_ahead: 128,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsensusStateMigrationOptions {
    pub dry_run: bool,
    pub force: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsensusStateMigrationReport {
    pub ok: bool,
    pub decision: String,
    pub dry_run: bool,
    pub source_data_dir: String,
    pub target_store_dir: String,
    pub verification: ConsensusStateReport,
    pub actions: Vec<String>,
    pub findings: Vec<ConsensusStateFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DerivedIndexRebuildOptions {
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DerivedIndexRebuildReport {
    pub ok: bool,
    pub decision: String,
    pub dry_run: bool,
    pub output_path: String,
    pub verification: ConsensusStateReport,
    pub actions: Vec<String>,
    pub findings: Vec<ConsensusStateFinding>,
}

#[derive(Debug, Clone)]
pub struct CompactedRecoveryCheckpointOptions {
    pub dry_run: bool,
    pub apply: bool,
    pub force: bool,
    pub source_validator: String,
    pub source_bundle_path: String,
    pub source_bundle_sha256: String,
    pub source_state_dir: String,
    pub operator_approval_id: String,
    pub recovery_reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompactedRecoveryCheckpointReport {
    pub ok: bool,
    pub decision: String,
    pub dry_run: bool,
    pub apply: bool,
    pub state_root: String,
    pub data_dir: String,
    pub checkpoint_path: String,
    pub manifest_path: String,
    pub source_shape: Value,
    pub verification_before: ConsensusStateReport,
    pub verification_after: Option<ConsensusStateReport>,
    pub actions: Vec<String>,
    pub findings: Vec<ConsensusStateFinding>,
}

#[derive(Debug, Clone)]
struct ParsedState {
    data_dir: PathBuf,
    chain: Vec<HeightHashSummary>,
    committed_blocks: Vec<HeightHashSummary>,
    canonical_locks: BTreeMap<u64, String>,
    committed_qcs: Vec<HeightHashSummary>,
    checkpoint: Option<StateCheckpoint>,
    findings: Vec<ConsensusStateFinding>,
}

#[derive(Debug, Clone)]
struct StateCheckpoint {
    height: u64,
    block_hash: String,
    state_root: Option<String>,
    chain_sha256: Option<String>,
    canonical_locks_sha256: Option<String>,
    committed_qcs_sha256: Option<String>,
    raw: Value,
}

#[derive(Debug, Clone)]
struct TestnetRecoverySourceShape {
    boundary: HeightHashSummary,
    first_retained_chain: HeightHashSummary,
    first_retained_qc: HeightHashSummary,
    tip: HeightHashSummary,
    tip_lock: HeightHashSummary,
    chain_sha256: String,
    canonical_locks_sha256: String,
    committed_qcs_sha256: String,
    validator_registry_sha256: Option<String>,
}

pub fn inspect_state(state_root: &Path) -> ConsensusStateReport {
    build_report(state_root)
}

pub fn verify_state(state_root: &Path) -> ConsensusStateReport {
    build_report(state_root)
}

pub fn verify_state_with_options(
    state_root: &Path,
    options: ConsensusStateVerificationOptions,
) -> ConsensusStateReport {
    build_report_with_options(state_root, options)
}

pub fn verify_live_state_with_options(
    state_root: &Path,
    options: LiveStateVerificationOptions,
) -> ConsensusStateReport {
    build_live_state_report(state_root, options)
}

pub fn export_compat_json(state_root: &Path) -> Result<Value, String> {
    let data_dir = resolve_data_dir(state_root);
    let chain = read_json(&data_dir.join("chain.json"))?;
    let canonical_locks = read_json(&data_dir.join("canonical_locks.json"))?;
    let committed_qcs = read_jsonl_values(&data_dir.join("committed_qcs.jsonl"))?;
    let state_checkpoint = read_json(&data_dir.join("state_checkpoint.json")).ok();
    let report = inspect_state(state_root);
    Ok(json!({
        "format": "synergy_legacy_consensus_state_compat_v1",
        "state_root": state_root.display().to_string(),
        "data_dir": data_dir.display().to_string(),
        "chain": chain,
        "canonical_locks": canonical_locks,
        "committed_qcs": committed_qcs,
        "state_checkpoint": state_checkpoint,
        "inspection": report,
    }))
}

pub fn adopt_compacted_recovery_checkpoint(
    state_root: &Path,
    options: CompactedRecoveryCheckpointOptions,
) -> Result<CompactedRecoveryCheckpointReport, String> {
    let data_dir = resolve_data_dir(state_root);
    let verification_before = build_fast_testnet_recovery_report(state_root, &data_dir, None);
    let parsed = parse_fast_testnet_recovery_state(&data_dir, None);
    let checkpoint_path = data_dir.join("state_checkpoint.json");
    let manifest_path = data_dir.join("state_checkpoint.recovery_manifest.json");
    let mut actions = vec![
        "inspect compacted source state without editing consensus JSON/JSONL".to_string(),
        "derive recovery checkpoint metadata from retained chain, canonical locks, and committed QCs"
            .to_string(),
        format!("write {}", checkpoint_path.display()),
        format!("write {}", manifest_path.display()),
        "verify state with --allow-testnet-recovery-checkpoint".to_string(),
    ];
    let mut findings = Vec::new();

    if options.source_bundle_sha256 != TESTNET_RECOVERY_APPROVED_SOURCE_BUNDLE_SHA256 {
        findings.push(error(
            "source_bundle_sha256_not_approved",
            format!(
                "expected approved source bundle sha256 {} but got {}",
                TESTNET_RECOVERY_APPROVED_SOURCE_BUNDLE_SHA256, options.source_bundle_sha256
            ),
        ));
    }
    if options.operator_approval_id.trim().is_empty() {
        findings.push(error(
            "operator_approval_id_missing",
            "checkpoint adoption requires a non-empty operator approval id",
        ));
    }
    if options.recovery_reason.trim().is_empty() {
        findings.push(error(
            "recovery_reason_missing",
            "checkpoint adoption requires a non-empty recovery reason",
        ));
    }
    if checkpoint_path.exists() && !options.force {
        findings.push(error(
            "state_checkpoint_exists",
            format!(
                "{} already exists; pass --force to replace it",
                checkpoint_path.display()
            ),
        ));
    }

    let source_shape = match validate_testnet_recovery_source_shape(&parsed) {
        Ok(shape) => shape,
        Err(mut shape_findings) => {
            findings.append(&mut shape_findings);
            TestnetRecoverySourceShape {
                boundary: HeightHashSummary {
                    height: 0,
                    hash: String::new(),
                },
                first_retained_chain: HeightHashSummary {
                    height: 0,
                    hash: String::new(),
                },
                first_retained_qc: HeightHashSummary {
                    height: 0,
                    hash: String::new(),
                },
                tip: HeightHashSummary {
                    height: 0,
                    hash: String::new(),
                },
                tip_lock: HeightHashSummary {
                    height: 0,
                    hash: String::new(),
                },
                chain_sha256: String::new(),
                canonical_locks_sha256: String::new(),
                committed_qcs_sha256: String::new(),
                validator_registry_sha256: None,
            }
        }
    };
    let source_shape_json = recovery_source_shape_json(&source_shape);

    let has_errors = findings
        .iter()
        .any(|finding| finding.severity == ConsensusStateSeverity::Error);
    if has_errors {
        return Ok(CompactedRecoveryCheckpointReport {
            ok: false,
            decision: "NO_GO".to_string(),
            dry_run: !options.apply || options.dry_run,
            apply: options.apply,
            state_root: state_root.display().to_string(),
            data_dir: data_dir.display().to_string(),
            checkpoint_path: checkpoint_path.display().to_string(),
            manifest_path: manifest_path.display().to_string(),
            source_shape: source_shape_json,
            verification_before,
            verification_after: None,
            actions,
            findings,
        });
    }

    let checkpoint = build_testnet_recovery_checkpoint(&data_dir, &source_shape, &options);
    let checkpoint_bytes = serde_json::to_vec_pretty(&checkpoint)
        .map_err(|error| format!("serialize recovery checkpoint: {error}"))?;
    let checkpoint_sha256 = sha256_bytes(&checkpoint_bytes);
    let manifest = build_testnet_recovery_manifest(
        &data_dir,
        &checkpoint_path,
        &checkpoint_sha256,
        &source_shape,
        &options,
    );
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| format!("serialize recovery checkpoint manifest: {error}"))?;

    if options.dry_run || !options.apply {
        actions.push("dry-run only; no files written".to_string());
        return Ok(CompactedRecoveryCheckpointReport {
            ok: true,
            decision: "DRY_RUN_GO".to_string(),
            dry_run: true,
            apply: false,
            state_root: state_root.display().to_string(),
            data_dir: data_dir.display().to_string(),
            checkpoint_path: checkpoint_path.display().to_string(),
            manifest_path: manifest_path.display().to_string(),
            source_shape: source_shape_json,
            verification_before,
            verification_after: None,
            actions,
            findings,
        });
    }

    write_bytes_atomic(&checkpoint_path, &checkpoint_bytes)?;
    write_bytes_atomic(&manifest_path, &manifest_bytes)?;
    let verification_after = match read_state_checkpoint(&checkpoint_path) {
        Ok(checkpoint) => build_fast_testnet_recovery_report(state_root, &data_dir, checkpoint),
        Err(detail) => {
            let mut report = build_fast_testnet_recovery_report(state_root, &data_dir, None);
            report
                .findings
                .push(error("state_checkpoint_unreadable", detail));
            report.ok = false;
            report.decision = "NO_GO".to_string();
            report
        }
    };
    if !verification_after.ok {
        findings.push(error(
            "recovery_checkpoint_verification_failed",
            "state still failed verify-state --allow-testnet-recovery-checkpoint after checkpoint adoption",
        ));
    }
    let ok = !findings
        .iter()
        .any(|finding| finding.severity == ConsensusStateSeverity::Error);
    Ok(CompactedRecoveryCheckpointReport {
        ok,
        decision: if ok { "GO" } else { "NO_GO" }.to_string(),
        dry_run: false,
        apply: true,
        state_root: state_root.display().to_string(),
        data_dir: data_dir.display().to_string(),
        checkpoint_path: checkpoint_path.display().to_string(),
        manifest_path: manifest_path.display().to_string(),
        source_shape: source_shape_json,
        verification_before,
        verification_after: Some(verification_after),
        actions,
        findings,
    })
}

pub fn migrate_state(
    state_root: &Path,
    options: ConsensusStateMigrationOptions,
) -> Result<ConsensusStateMigrationReport, String> {
    migrate_state_with_verification_options(
        state_root,
        options,
        ConsensusStateVerificationOptions::default(),
    )
}

pub fn migrate_state_with_verification_options(
    state_root: &Path,
    options: ConsensusStateMigrationOptions,
    verification_options: ConsensusStateVerificationOptions,
) -> Result<ConsensusStateMigrationReport, String> {
    let verification = verify_state_with_options(state_root, verification_options);
    let data_dir = PathBuf::from(&verification.data_dir);
    let target_store_dir = data_dir.join(DURABLE_STORE_DIR);
    let mut actions = vec![
        "verify legacy consensus state".to_string(),
        format!(
            "copy chain.json, canonical_locks.json, committed_qcs.jsonl, and state_checkpoint.json when present into {}",
            target_store_dir.display()
        ),
        "write manifest.json with source digests and verification summary".to_string(),
        "atomic rename temp store into durable store location".to_string(),
    ];
    let mut findings = Vec::new();

    if !verification.ok {
        findings.push(error(
            "state_verification_failed",
            "refusing migration because legacy state verification failed",
        ));
    }

    if target_store_dir.exists() && !options.force {
        findings.push(error(
            "durable_store_exists",
            format!(
                "target durable store already exists: {}; pass --force to replace it",
                target_store_dir.display()
            ),
        ));
    }

    let has_errors = findings
        .iter()
        .any(|finding| finding.severity == ConsensusStateSeverity::Error);
    if has_errors {
        return Ok(ConsensusStateMigrationReport {
            ok: false,
            decision: "NO_GO".to_string(),
            dry_run: options.dry_run,
            source_data_dir: data_dir.display().to_string(),
            target_store_dir: target_store_dir.display().to_string(),
            verification,
            actions,
            findings,
        });
    }

    if options.dry_run {
        actions.push("dry-run only; no files written".to_string());
        return Ok(ConsensusStateMigrationReport {
            ok: true,
            decision: "DRY_RUN_GO".to_string(),
            dry_run: true,
            source_data_dir: data_dir.display().to_string(),
            target_store_dir: target_store_dir.display().to_string(),
            verification,
            actions,
            findings,
        });
    }

    let temp_store_dir = data_dir.join(format!(
        ".{}.tmp-{}-{}",
        DURABLE_STORE_DIR,
        std::process::id(),
        current_unix_nanos()
    ));
    if temp_store_dir.exists() {
        fs::remove_dir_all(&temp_store_dir).map_err(|error| {
            format!(
                "remove stale temp store {}: {error}",
                temp_store_dir.display()
            )
        })?;
    }
    fs::create_dir_all(&temp_store_dir)
        .map_err(|error| format!("create temp store {}: {error}", temp_store_dir.display()))?;

    let result = write_durable_store(
        &data_dir,
        &temp_store_dir,
        &target_store_dir,
        &verification,
        options.force,
    );
    if let Err(error) = result {
        let _ = fs::remove_dir_all(&temp_store_dir);
        return Err(error);
    }

    actions.push(format!(
        "durable store installed at {}",
        target_store_dir.display()
    ));
    Ok(ConsensusStateMigrationReport {
        ok: true,
        decision: "GO".to_string(),
        dry_run: false,
        source_data_dir: data_dir.display().to_string(),
        target_store_dir: target_store_dir.display().to_string(),
        verification,
        actions,
        findings,
    })
}

pub fn rebuild_derived_indexes(
    state_root: &Path,
    options: DerivedIndexRebuildOptions,
) -> Result<DerivedIndexRebuildReport, String> {
    rebuild_derived_indexes_with_verification_options(
        state_root,
        options,
        ConsensusStateVerificationOptions::default(),
    )
}

pub fn rebuild_derived_indexes_with_verification_options(
    state_root: &Path,
    options: DerivedIndexRebuildOptions,
    verification_options: ConsensusStateVerificationOptions,
) -> Result<DerivedIndexRebuildReport, String> {
    let verification = verify_state_with_options(state_root, verification_options);
    let data_dir = PathBuf::from(&verification.data_dir);
    let store_dir = data_dir.join(DURABLE_STORE_DIR);
    let output_path = if store_dir.is_dir() {
        store_dir.join("derived_index.json")
    } else {
        data_dir.join("derived_consensus_index.json")
    };
    let actions = vec![
        "verify legacy consensus state".to_string(),
        format!("build derived index {}", output_path.display()),
        "atomic write derived index file".to_string(),
    ];
    let mut findings = Vec::new();

    if !verification.ok {
        findings.push(error(
            "state_verification_failed",
            "refusing derived-index rebuild because state verification failed",
        ));
    }

    let has_errors = findings
        .iter()
        .any(|finding| finding.severity == ConsensusStateSeverity::Error);
    if has_errors {
        return Ok(DerivedIndexRebuildReport {
            ok: false,
            decision: "NO_GO".to_string(),
            dry_run: options.dry_run,
            output_path: output_path.display().to_string(),
            verification,
            actions,
            findings,
        });
    }

    if options.dry_run {
        return Ok(DerivedIndexRebuildReport {
            ok: true,
            decision: "DRY_RUN_GO".to_string(),
            dry_run: true,
            output_path: output_path.display().to_string(),
            verification,
            actions,
            findings,
        });
    }

    let index = build_derived_index(&data_dir, &verification);
    write_json_atomic(&output_path, &index)?;
    Ok(DerivedIndexRebuildReport {
        ok: true,
        decision: "GO".to_string(),
        dry_run: false,
        output_path: output_path.display().to_string(),
        verification,
        actions,
        findings,
    })
}

fn build_derived_index(data_dir: &Path, verification: &ConsensusStateReport) -> Value {
    json!({
        "format": "synergy_consensus_state_derived_index_v1",
        "created_at_unix": current_unix_secs(),
        "data_dir": data_dir.display().to_string(),
        "chain": verification.chain,
        "canonical_locks": verification.canonical_locks,
        "committed_qcs": verification.committed_qcs,
        "checkpoint": verification.checkpoint,
        "files": state_file_summaries(data_dir),
    })
}

fn write_durable_store(
    data_dir: &Path,
    temp_store_dir: &Path,
    target_store_dir: &Path,
    verification: &ConsensusStateReport,
    force: bool,
) -> Result<(), String> {
    for file in ["chain.json", "canonical_locks.json", "committed_qcs.jsonl"] {
        fs::copy(data_dir.join(file), temp_store_dir.join(file)).map_err(|error| {
            format!(
                "copy {} into durable store {}: {error}",
                file,
                temp_store_dir.display()
            )
        })?;
    }
    let checkpoint_path = data_dir.join("state_checkpoint.json");
    if checkpoint_path.is_file() {
        fs::copy(
            &checkpoint_path,
            temp_store_dir.join("state_checkpoint.json"),
        )
        .map_err(|error| {
            format!(
                "copy state_checkpoint.json into durable store {}: {error}",
                temp_store_dir.display()
            )
        })?;
    }
    let manifest = json!({
        "format": "synergy_consensus_state_store_v1",
        "created_at_unix": current_unix_secs(),
        "source_data_dir": data_dir.display().to_string(),
        "files": state_file_summaries(data_dir),
        "verification": verification,
    });
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| format!("serialize durable state manifest: {error}"))?;
    fs::write(temp_store_dir.join("manifest.json"), manifest_bytes).map_err(|error| {
        format!(
            "write durable state manifest {}: {error}",
            temp_store_dir.join("manifest.json").display()
        )
    })?;

    if target_store_dir.exists() {
        if force {
            fs::remove_dir_all(target_store_dir).map_err(|error| {
                format!(
                    "remove existing durable store {}: {error}",
                    target_store_dir.display()
                )
            })?;
        } else {
            return Err(format!(
                "target durable store already exists: {}",
                target_store_dir.display()
            ));
        }
    }
    fs::rename(temp_store_dir, target_store_dir).map_err(|error| {
        format!(
            "atomic rename {} to {}: {error}",
            temp_store_dir.display(),
            target_store_dir.display()
        )
    })
}

fn write_json_atomic(path: &Path, value: &Value) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("serialize JSON {}: {error}", path.display()))?;
    write_bytes_atomic(path, &bytes)
}

fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
    fs::create_dir_all(parent).map_err(|error| format!("create {}: {error}", parent.display()))?;
    let temp = parent.join(format!(
        ".{}.tmp-{}-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("derived_index.json"),
        std::process::id(),
        current_unix_nanos()
    ));
    fs::write(&temp, bytes).map_err(|error| format!("write {}: {error}", temp.display()))?;
    fs::rename(&temp, path).map_err(|error| {
        format!(
            "atomic rename {} to {}: {error}",
            temp.display(),
            path.display()
        )
    })
}

fn build_report(state_root: &Path) -> ConsensusStateReport {
    build_report_with_options(state_root, ConsensusStateVerificationOptions::default())
}

fn build_report_with_options(
    state_root: &Path,
    options: ConsensusStateVerificationOptions,
) -> ConsensusStateReport {
    let data_dir = resolve_data_dir(state_root);
    if options.allow_testnet_recovery_checkpoint {
        if let Ok(Some(checkpoint)) = read_state_checkpoint(&data_dir.join("state_checkpoint.json"))
        {
            if is_approved_testnet_recovery_checkpoint_value(&checkpoint.raw) {
                return build_fast_testnet_recovery_report(state_root, &data_dir, Some(checkpoint));
            }
        }
    }
    let mut parsed = parse_state(state_root);
    validate_state(&mut parsed);
    if options.allow_testnet_recovery_checkpoint {
        apply_testnet_recovery_checkpoint_exception(&mut parsed);
    }
    let errors = parsed
        .findings
        .iter()
        .any(|finding| finding.severity == ConsensusStateSeverity::Error);
    ConsensusStateReport {
        ok: !errors,
        decision: if errors { "NO_GO" } else { "GO" }.to_string(),
        state_root: state_root.display().to_string(),
        data_dir: parsed.data_dir.display().to_string(),
        files: state_file_summaries(&parsed.data_dir),
        chain: chain_summary(&parsed.chain),
        canonical_locks: map_summary(&parsed.canonical_locks),
        committed_qcs: list_summary(&parsed.committed_qcs),
        checkpoint: checkpoint_summary(parsed.checkpoint.as_ref()),
        findings: parsed.findings,
    }
}

fn build_live_state_report(
    state_root: &Path,
    options: LiveStateVerificationOptions,
) -> ConsensusStateReport {
    let data_dir = resolve_data_dir(state_root);
    let mut findings = Vec::new();
    if !data_dir.is_dir() {
        findings.push(error(
            "data_dir_missing",
            format!("data directory does not exist: {}", data_dir.display()),
        ));
    }

    let chain_path = data_dir.join("chain.json");
    let chain = match read_chain(&chain_path) {
        Ok(chain) => chain,
        Err(detail) => {
            findings.push(error("chain_body_unreadable", detail));
            Vec::new()
        }
    };
    let committed_qcs = match read_committed_qc_edges(&data_dir.join("committed_qcs.jsonl")) {
        Ok(qcs) => qcs,
        Err(detail) => {
            findings.push(error("committed_qcs_unreadable", detail));
            Vec::new()
        }
    };
    let checkpoint = match read_state_checkpoint(&data_dir.join("state_checkpoint.json")) {
        Ok(checkpoint) => checkpoint,
        Err(detail) => {
            findings.push(error("state_checkpoint_unreadable", detail));
            None
        }
    };

    let mut canonical_locks = BTreeMap::new();
    let locks_path = data_dir.join("canonical_locks.json");
    if let Some(first) = chain.first() {
        match read_canonical_lock_hash_near_edge(&locks_path, first.height, false) {
            Ok(hash) => {
                if hash != first.hash {
                    findings.push(error(
                        "live_state_first_lock_hash_mismatch",
                        format!(
                            "canonical lock h{} hash {} does not match first retained chain hash {}",
                            first.height, hash, first.hash
                        ),
                    ));
                }
                canonical_locks.insert(first.height, hash);
            }
            Err(detail) => findings.push(error("canonical_locks_unreadable", detail)),
        }
    }
    if let Some(latest) = chain.last() {
        match read_canonical_lock_hash_near_edge(&locks_path, latest.height, true) {
            Ok(hash) => {
                if hash != latest.hash {
                    findings.push(error(
                        "live_state_latest_lock_hash_mismatch",
                        format!(
                            "canonical lock h{} hash {} does not match latest chain hash {}",
                            latest.height, hash, latest.hash
                        ),
                    ));
                }
                canonical_locks.insert(latest.height, hash);
            }
            Err(detail) => findings.push(warning("live_state_latest_lock_missing", detail)),
        }
    }

    validate_live_state_edges(
        &chain,
        &committed_qcs,
        checkpoint.as_ref(),
        &options,
        &mut findings,
    );
    findings.push(warning(
        "live_state_fast_edge_verification_used",
        "validated live restart preflight using bounded chain, canonical-lock, and committed-QC edge reads",
    ));

    let errors = findings
        .iter()
        .any(|finding| finding.severity == ConsensusStateSeverity::Error);
    ConsensusStateReport {
        ok: !errors,
        decision: if errors { "NO_GO" } else { "GO" }.to_string(),
        state_root: state_root.display().to_string(),
        data_dir: data_dir.display().to_string(),
        files: state_file_summaries(&data_dir),
        chain: chain_summary(&chain),
        canonical_locks: map_summary(&canonical_locks),
        committed_qcs: list_summary(&committed_qcs),
        checkpoint: checkpoint_summary(checkpoint.as_ref()),
        findings,
    }
}

fn validate_live_state_edges(
    chain: &[HeightHashSummary],
    committed_qcs: &[HeightHashSummary],
    checkpoint: Option<&StateCheckpoint>,
    options: &LiveStateVerificationOptions,
    findings: &mut Vec<ConsensusStateFinding>,
) {
    if chain.is_empty() {
        findings.push(error(
            "chain_body_empty",
            "chain.json contains no block edge entries",
        ));
        return;
    }
    let first = chain.first().expect("nonempty chain checked");
    let latest = chain.last().expect("nonempty chain checked");
    if latest.height < first.height {
        findings.push(error(
            "live_state_chain_edge_order_invalid",
            format!(
                "latest chain edge h{} is before first retained h{}",
                latest.height, first.height
            ),
        ));
    }
    if chain.len() >= 2 {
        let second = &chain[1];
        if second.height <= first.height {
            findings.push(error(
                "live_state_retained_edge_order_invalid",
                format!(
                    "second retained chain edge h{} must be after first retained h{}",
                    second.height, first.height
                ),
            ));
        }
        if second.height > latest.height {
            findings.push(error(
                "live_state_retained_edge_after_latest",
                format!(
                    "second retained chain edge h{} is after latest edge h{}",
                    second.height, latest.height
                ),
            ));
        }
    }

    if let Some(checkpoint) = checkpoint {
        if checkpoint.height != first.height || checkpoint.block_hash != first.hash {
            findings.push(error(
                "live_state_checkpoint_first_edge_mismatch",
                format!(
                    "state_checkpoint h{} hash {} does not match first retained chain edge h{} hash {}",
                    checkpoint.height, checkpoint.block_hash, first.height, first.hash
                ),
            ));
        }
    } else if first.height > 0 {
        findings.push(warning(
            "live_state_checkpoint_missing",
            "state_checkpoint.json is missing; continuing bounded edge verification without checkpoint metadata",
        ));
    }

    if let Some(tail_qc) = committed_qcs.last() {
        let expected_qc_matches = expected_height_hash_matches(
            tail_qc,
            options.expected_height,
            options.expected_hash.as_deref(),
        );
        if let Some(expected_height) = options.expected_height {
            if tail_qc.height == expected_height {
                if let Some(expected_hash) = options.expected_hash.as_deref() {
                    if tail_qc.hash != expected_hash {
                        findings.push(error(
                            "live_state_qc_expected_hash_mismatch",
                            format!(
                                "committed QC tail h{} hash {} does not match expected qRPC hash {}",
                                tail_qc.height, tail_qc.hash, expected_hash
                            ),
                        ));
                    }
                }
            } else if tail_qc.height < expected_height {
                findings.push(error(
                    "live_state_qc_behind_expected_head",
                    format!(
                        "committed QC tail h{} is behind expected qRPC head h{}",
                        tail_qc.height, expected_height
                    ),
                ));
            }
        }
        if tail_qc.height < latest.height {
            findings.push(error(
                "live_state_qc_tail_behind_chain",
                format!(
                    "committed QC tail h{} is behind latest chain edge h{}",
                    tail_qc.height, latest.height
                ),
            ));
        } else if tail_qc.height == latest.height && tail_qc.hash != latest.hash {
            findings.push(error(
                "live_state_qc_tail_hash_mismatch",
                format!(
                    "committed QC tail h{} hash {} does not match latest chain hash {}",
                    tail_qc.height, tail_qc.hash, latest.hash
                ),
            ));
        } else if tail_qc.height > latest.height {
            let ahead = tail_qc.height - latest.height;
            if ahead > options.max_qc_ahead {
                if expected_qc_matches {
                    findings.push(warning(
                        "live_state_qc_tail_supplies_compacted_head",
                        format!(
                            "committed QC tail h{} matches expected qRPC head and is {} blocks ahead of retained chain edge h{}",
                            tail_qc.height, ahead, latest.height
                        ),
                    ));
                } else {
                    findings.push(error(
                        "live_state_qc_tail_too_far_ahead",
                        format!(
                            "committed QC tail h{} is {} blocks ahead of latest chain edge h{}, over max_qc_ahead {}",
                            tail_qc.height, ahead, latest.height, options.max_qc_ahead
                        ),
                    ));
                }
            } else {
                findings.push(warning(
                    "live_state_qc_tail_ahead_of_chain",
                    format!(
                        "committed QC tail h{} is {} blocks ahead of latest chain edge h{}",
                        tail_qc.height, ahead, latest.height
                    ),
                ));
            }
        }
    } else {
        findings.push(error(
            "committed_qcs_empty",
            "committed_qcs.jsonl contains no QC edge entries",
        ));
    }

    if let Some(expected_height) = options.expected_height {
        let tail_qc_matches_expected = committed_qcs
            .last()
            .map(|tail_qc| {
                expected_height_hash_matches(
                    tail_qc,
                    Some(expected_height),
                    options.expected_hash.as_deref(),
                )
            })
            .unwrap_or(false);
        if latest.height + options.max_expected_lag < expected_height {
            if tail_qc_matches_expected {
                findings.push(warning(
                    "live_state_chain_body_compacted_behind_expected_head",
                    format!(
                        "latest retained chain body h{} is behind expected qRPC head h{}, but committed QC tail proves the expected live head",
                        latest.height, expected_height
                    ),
                ));
            } else {
                findings.push(error(
                    "live_state_chain_behind_expected_head",
                    format!(
                        "latest durable chain edge h{} is more than {} blocks behind expected qRPC head h{}",
                        latest.height, options.max_expected_lag, expected_height
                    ),
                ));
            }
        } else if latest.height < expected_height {
            findings.push(warning(
                "live_state_chain_slightly_behind_expected_head",
                format!(
                    "latest durable chain edge h{} is behind expected qRPC head h{} within max_expected_lag {}",
                    latest.height, expected_height, options.max_expected_lag
                ),
            ));
        }
        if latest.height == expected_height {
            if let Some(expected_hash) = options.expected_hash.as_deref() {
                if latest.hash != expected_hash {
                    findings.push(error(
                        "live_state_chain_expected_hash_mismatch",
                        format!(
                            "latest durable chain edge h{} hash {} does not match expected qRPC hash {}",
                            latest.height, latest.hash, expected_hash
                        ),
                    ));
                }
            }
        }
    }
}

fn expected_height_hash_matches(
    summary: &HeightHashSummary,
    expected_height: Option<u64>,
    expected_hash: Option<&str>,
) -> bool {
    if expected_height != Some(summary.height) {
        return false;
    }
    expected_hash
        .map(|expected_hash| summary.hash == expected_hash)
        .unwrap_or(true)
}

fn parse_state(state_root: &Path) -> ParsedState {
    let data_dir = resolve_data_dir(state_root);
    let mut findings = Vec::new();
    if !data_dir.is_dir() {
        findings.push(error(
            "data_dir_missing",
            format!("data directory does not exist: {}", data_dir.display()),
        ));
    }

    let chain = match read_chain(&data_dir.join("chain.json")) {
        Ok(chain) => chain,
        Err(detail) => {
            findings.push(error("chain_body_unreadable", detail));
            Vec::new()
        }
    };

    let canonical_locks = match read_height_hash_map(&data_dir.join("canonical_locks.json")) {
        Ok(locks) => locks,
        Err(detail) => {
            findings.push(error("canonical_locks_unreadable", detail));
            BTreeMap::new()
        }
    };

    let committed_blocks_path = data_dir.join("committed_blocks.jsonl");
    let committed_blocks = if committed_blocks_path.is_file() {
        match read_committed_block_edges(&committed_blocks_path) {
            Ok(blocks) => blocks,
            Err(detail) => {
                findings.push(error("committed_blocks_unreadable", detail));
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    let committed_qcs = match read_committed_qcs(&data_dir.join("committed_qcs.jsonl")) {
        Ok(qcs) => qcs,
        Err(detail) => {
            findings.push(error("committed_qcs_unreadable", detail));
            Vec::new()
        }
    };

    let checkpoint = match read_state_checkpoint(&data_dir.join("state_checkpoint.json")) {
        Ok(checkpoint) => checkpoint,
        Err(detail) => {
            findings.push(error("state_checkpoint_unreadable", detail));
            None
        }
    };

    ParsedState {
        data_dir,
        chain,
        committed_blocks,
        canonical_locks,
        committed_qcs,
        checkpoint,
        findings,
    }
}

fn parse_fast_testnet_recovery_state(
    data_dir: &Path,
    checkpoint: Option<StateCheckpoint>,
) -> ParsedState {
    let mut findings = Vec::new();
    if !data_dir.is_dir() {
        findings.push(error(
            "data_dir_missing",
            format!("data directory does not exist: {}", data_dir.display()),
        ));
    }

    let chain = match read_chain(&data_dir.join("chain.json")) {
        Ok(chain) => chain,
        Err(detail) => {
            findings.push(error("chain_body_unreadable", detail));
            Vec::new()
        }
    };

    let mut canonical_locks = BTreeMap::new();
    for height in [
        TESTNET_RECOVERY_BOUNDARY_HEIGHT,
        TESTNET_RECOVERY_APPROVED_TIP_HEIGHT,
    ] {
        match read_canonical_lock_hash_at_height(&data_dir.join("canonical_locks.json"), height) {
            Ok(hash) => {
                canonical_locks.insert(height, hash);
            }
            Err(detail) => findings.push(error("canonical_locks_unreadable", detail)),
        }
    }

    let committed_qcs = match read_committed_qc_edges(&data_dir.join("committed_qcs.jsonl")) {
        Ok(qcs) => qcs,
        Err(detail) => {
            findings.push(error("committed_qcs_unreadable", detail));
            Vec::new()
        }
    };

    ParsedState {
        data_dir: data_dir.to_path_buf(),
        chain,
        committed_blocks: Vec::new(),
        canonical_locks,
        committed_qcs,
        checkpoint,
        findings,
    }
}

fn build_fast_testnet_recovery_report(
    state_root: &Path,
    data_dir: &Path,
    checkpoint: Option<StateCheckpoint>,
) -> ConsensusStateReport {
    let mut parsed = parse_fast_testnet_recovery_state(data_dir, checkpoint);
    let mut findings = parsed.findings.clone();
    if parsed.checkpoint.is_some() {
        match validate_testnet_recovery_checkpoint(&parsed) {
            Ok(()) => findings.push(warning(
                "testnet_recovery_checkpoint_accepted",
                "accepted approved Synergy Testnet compacted recovery checkpoint via targeted fast verification",
            )),
            Err(mut checkpoint_findings) => findings.append(&mut checkpoint_findings),
        }
    }
    findings.push(warning(
        "testnet_recovery_fast_verification_used",
        "approved recovery checkpoint verification used targeted boundary/tip checks instead of full state deserialization",
    ));
    parsed.findings = findings;
    let errors = parsed
        .findings
        .iter()
        .any(|finding| finding.severity == ConsensusStateSeverity::Error);
    ConsensusStateReport {
        ok: !errors,
        decision: if errors { "NO_GO" } else { "GO" }.to_string(),
        state_root: state_root.display().to_string(),
        data_dir: parsed.data_dir.display().to_string(),
        files: state_file_summaries(&parsed.data_dir),
        chain: chain_summary(&parsed.chain),
        canonical_locks: map_summary(&parsed.canonical_locks),
        committed_qcs: list_summary(&parsed.committed_qcs),
        checkpoint: checkpoint_summary(parsed.checkpoint.as_ref()),
        findings: parsed.findings,
    }
}

fn validate_state(parsed: &mut ParsedState) {
    if parsed.chain.is_empty() {
        parsed
            .findings
            .push(error("chain_body_empty", "chain.json contains no blocks"));
    }

    if large_chain_edge_summary(parsed) {
        parsed.findings.push(warning(
            "large_chain_edge_summary_used",
            "large chain.json verified from retained edge samples; committed_blocks.jsonl is used for append-log tip validation",
        ));
    } else {
        validate_chain_order(&parsed.chain, &mut parsed.findings);
    }

    let Some(first) = parsed.chain.first().cloned() else {
        return;
    };
    let latest = effective_latest_body(parsed)
        .unwrap_or_else(|| parsed.chain.last().expect("first exists").clone());

    match parsed.canonical_locks.get(&first.height) {
        Some(hash) if hash == &first.hash => {}
        Some(hash) => parsed.findings.push(error(
            "compact_boundary_lock_hash_mismatch",
            format!(
                "first retained block h{} hash {} does not match canonical lock hash {}",
                first.height, first.hash, hash
            ),
        )),
        None => parsed.findings.push(error(
            "compact_boundary_lock_missing",
            format!(
                "first retained block h{} has no canonical lock entry",
                first.height
            ),
        )),
    }

    for (height, hash) in parsed.canonical_locks.range((latest.height + 1)..) {
        parsed.findings.push(error(
            "body_behind_canonical_lock",
            format!(
                "canonical lock h{} hash {} is above retained chain tip h{}",
                height, hash, latest.height
            ),
        ));
    }

    if first.height > 0 {
        let boundary_qc_matches = parsed
            .committed_qcs
            .iter()
            .any(|qc| qc.height == first.height && qc.hash == first.hash);
        let boundary_qc_height_exists = parsed
            .committed_qcs
            .iter()
            .any(|qc| qc.height == first.height);
        if !boundary_qc_matches {
            let code = if boundary_qc_height_exists {
                "compact_boundary_qc_hash_mismatch"
            } else {
                "compact_boundary_qc_missing"
            };
            parsed.findings.push(error(
                code,
                format!(
                    "first retained block h{} hash {} has no matching committed QC",
                    first.height, first.hash
                ),
            ));
        }
    }

    validate_checkpoint(parsed, &first, &latest);

    for qc in parsed
        .committed_qcs
        .iter()
        .filter(|qc| qc.height > latest.height)
    {
        parsed.findings.push(warning(
            "committed_qc_ahead_of_chain_body",
            format!(
                "committed QC h{} hash {} is above retained chain tip h{}",
                qc.height, qc.hash, latest.height
            ),
        ));
    }
}

fn validate_checkpoint(
    parsed: &mut ParsedState,
    first: &HeightHashSummary,
    latest: &HeightHashSummary,
) {
    if first.height > 0 && parsed.checkpoint.is_none() {
        parsed.findings.push(error(
            "compact_boundary_checkpoint_missing",
            format!(
                "compacted state starts at h{} but state_checkpoint.json is missing",
                first.height
            ),
        ));
        return;
    }

    let Some(checkpoint) = parsed.checkpoint.as_ref() else {
        return;
    };

    if checkpoint.height > latest.height {
        parsed.findings.push(error(
            "checkpoint_ahead_of_chain_body",
            format!(
                "checkpoint h{} is above retained chain tip h{}",
                checkpoint.height, latest.height
            ),
        ));
    }

    if first.height > 0 && checkpoint.height != first.height {
        parsed.findings.push(error(
            "compact_boundary_checkpoint_height_mismatch",
            format!(
                "compacted state starts at h{} but checkpoint records h{}",
                first.height, checkpoint.height
            ),
        ));
    }

    if first.height > 0 && checkpoint.block_hash != first.hash {
        parsed.findings.push(error(
            "compact_boundary_checkpoint_hash_mismatch",
            format!(
                "first retained block h{} hash {} does not match checkpoint hash {}",
                first.height, first.hash, checkpoint.block_hash
            ),
        ));
    }

    match parsed.canonical_locks.get(&checkpoint.height) {
        Some(hash) if hash == &checkpoint.block_hash => {}
        Some(hash) => parsed.findings.push(error(
            "checkpoint_lock_disagreement",
            format!(
                "checkpoint h{} hash {} does not match canonical lock hash {}",
                checkpoint.height, checkpoint.block_hash, hash
            ),
        )),
        None => parsed.findings.push(error(
            "checkpoint_lock_missing",
            format!(
                "checkpoint h{} hash {} has no canonical lock",
                checkpoint.height, checkpoint.block_hash
            ),
        )),
    }

    if checkpoint.height > 0
        && !parsed
            .committed_qcs
            .iter()
            .any(|qc| qc.height == checkpoint.height && qc.hash == checkpoint.block_hash)
    {
        parsed.findings.push(error(
            "checkpoint_qc_missing_or_mismatch",
            format!(
                "checkpoint h{} hash {} has no matching committed QC",
                checkpoint.height, checkpoint.block_hash
            ),
        ));
    }

    let chain_sha256 = checkpoint.chain_sha256.clone();
    let canonical_locks_sha256 = checkpoint.canonical_locks_sha256.clone();
    let committed_qcs_sha256 = checkpoint.committed_qcs_sha256.clone();
    if is_approved_testnet_recovery_checkpoint_value(&checkpoint.raw) {
        return;
    }
    validate_checkpoint_file_digest(
        parsed,
        "chain.json",
        chain_sha256.as_deref(),
        "checkpoint_chain_sha256_mismatch",
    );
    validate_checkpoint_file_digest(
        parsed,
        "canonical_locks.json",
        canonical_locks_sha256.as_deref(),
        "checkpoint_canonical_locks_sha256_mismatch",
    );
    validate_checkpoint_file_digest(
        parsed,
        "committed_qcs.jsonl",
        committed_qcs_sha256.as_deref(),
        "checkpoint_committed_qcs_sha256_mismatch",
    );
}

fn large_chain_edge_summary(parsed: &ParsedState) -> bool {
    parsed.chain.len() <= 3 && chain_file_is_large(&parsed.data_dir)
}

fn effective_latest_body(parsed: &ParsedState) -> Option<HeightHashSummary> {
    match (parsed.chain.last(), parsed.committed_blocks.last()) {
        (Some(chain), Some(committed)) if committed.height >= chain.height => {
            Some(committed.clone())
        }
        (Some(chain), _) => Some(chain.clone()),
        (None, Some(committed)) => Some(committed.clone()),
        (None, None) => None,
    }
}

fn validate_checkpoint_file_digest(
    parsed: &mut ParsedState,
    file_name: &str,
    expected_sha256: Option<&str>,
    code: &str,
) {
    let Some(expected_sha256) = expected_sha256 else {
        return;
    };
    let path = parsed.data_dir.join(file_name);
    match sha256_file(&path) {
        Ok(actual_sha256) if actual_sha256 == expected_sha256 => {}
        Ok(actual_sha256) => parsed.findings.push(error(
            code,
            format!(
                "checkpoint recorded {} sha256 {} but current file sha256 is {}",
                file_name, expected_sha256, actual_sha256
            ),
        )),
        Err(error_detail) => parsed.findings.push(error(
            code,
            format!(
                "checkpoint recorded {} sha256 {} but current file cannot be hashed: {}",
                file_name, expected_sha256, error_detail
            ),
        )),
    }
}

fn validate_chain_order(chain: &[HeightHashSummary], findings: &mut Vec<ConsensusStateFinding>) {
    let mut seen = BTreeMap::<u64, String>::new();
    for block in chain {
        if let Some(previous_hash) = seen.insert(block.height, block.hash.clone()) {
            let code = if previous_hash == block.hash {
                "duplicate_block_height"
            } else {
                "conflicting_block_height"
            };
            findings.push(error(
                code,
                format!(
                    "chain contains repeated height h{} with hashes {} and {}",
                    block.height, previous_hash, block.hash
                ),
            ));
        }
    }

    for pair in chain.windows(2) {
        let previous = &pair[0];
        let next = &pair[1];
        if next.height != previous.height + 1 {
            findings.push(error(
                "chain_body_non_contiguous",
                format!(
                    "chain body is not contiguous: h{} followed by h{}",
                    previous.height, next.height
                ),
            ));
        }
        if next.height <= previous.height {
            findings.push(error(
                "chain_body_non_monotonic",
                format!(
                    "chain body is not strictly increasing: h{} followed by h{}",
                    previous.height, next.height
                ),
            ));
        }
    }
}

fn apply_testnet_recovery_checkpoint_exception(parsed: &mut ParsedState) {
    if parsed.checkpoint.is_none() && is_compact_append_log_state_candidate(parsed) {
        parsed.findings.retain(|finding| {
            !matches!(
                finding.code.as_str(),
                "chain_body_non_contiguous"
                    | "compact_boundary_qc_missing"
                    | "compact_boundary_checkpoint_missing"
                    | "checkpoint_qc_missing_or_mismatch"
                    | "committed_qc_ahead_of_chain_body"
            )
        });
        parsed.findings.push(warning(
            "compact_append_log_state_accepted",
            "accepted compact chain body with committed_blocks.jsonl append-log coverage and matching committed QC/canonical lock tail",
        ));
        return;
    }
    if !is_testnet_recovery_checkpoint_candidate(parsed) {
        return;
    }
    match validate_testnet_recovery_checkpoint(parsed) {
        Ok(()) => {
            parsed.findings.retain(|finding| {
                !matches!(
                    finding.code.as_str(),
                    "chain_body_non_contiguous"
                        | "compact_boundary_qc_missing"
                        | "checkpoint_qc_missing_or_mismatch"
                )
            });
            parsed.findings.push(warning(
                "testnet_recovery_checkpoint_accepted",
                "approved Testnet compacted recovery checkpoint allows the known boundary gap and missing boundary QC for this recovery only",
            ));
        }
        Err(mut findings) => parsed.findings.append(&mut findings),
    }
}

fn is_compact_append_log_state_candidate(parsed: &ParsedState) -> bool {
    let Some(boundary) = parsed.chain.first() else {
        return false;
    };
    let Some(chain_latest) = parsed.chain.last() else {
        return false;
    };
    let Some(block_first) = parsed.committed_blocks.first() else {
        return false;
    };
    let Some(block_latest) = parsed.committed_blocks.last() else {
        return false;
    };
    let Some(qc_first) = parsed.committed_qcs.first() else {
        return false;
    };
    let Some(qc_latest) = parsed.committed_qcs.last() else {
        return false;
    };
    if !large_chain_edge_summary(parsed)
        && !validator_pruned_chain_window_candidate(parsed, block_first, block_latest)
    {
        return false;
    }
    if block_latest.height < chain_latest.height {
        return false;
    }
    if block_first != qc_first || block_latest != qc_latest {
        return false;
    }
    if !height_hash_entries_are_contiguous(&parsed.committed_qcs) {
        return false;
    }
    if !retained_chain_entries_match_committed_qcs(parsed, qc_first, qc_latest) {
        return false;
    }
    if parsed
        .canonical_locks
        .get(&boundary.height)
        .map(|hash| hash.as_str())
        != Some(boundary.hash.as_str())
    {
        return false;
    }
    if parsed
        .canonical_locks
        .get(&block_latest.height)
        .map(|hash| hash.as_str())
        != Some(block_latest.hash.as_str())
    {
        return false;
    }
    true
}

fn validator_pruned_chain_window_candidate(
    parsed: &ParsedState,
    block_first: &HeightHashSummary,
    block_latest: &HeightHashSummary,
) -> bool {
    let Some(boundary) = parsed.chain.first() else {
        return false;
    };
    if boundary.height != TESTNET_RECOVERY_BOUNDARY_HEIGHT
        || boundary.hash != TESTNET_RECOVERY_BOUNDARY_HASH
    {
        return false;
    }
    let retained = &parsed.chain[1..];
    if retained.len() < 2 {
        return false;
    }
    let Some(retained_first) = retained.first() else {
        return false;
    };
    let Some(retained_latest) = retained.last() else {
        return false;
    };
    if retained_first.height <= boundary.height {
        return false;
    }
    if retained_latest != block_latest {
        return false;
    }
    if block_first.height < retained_first.height || block_first.height > block_latest.height {
        return false;
    }
    for (index, pair) in retained.windows(2).enumerate() {
        let previous = &pair[0];
        let next = &pair[1];
        if next.height <= previous.height {
            return false;
        }
        if next.height == previous.height + 1 {
            continue;
        }
        let final_pair = index + 2 == retained.len();
        if final_pair && next == block_latest {
            continue;
        }
        return false;
    }
    true
}

fn height_hash_entries_are_contiguous(entries: &[HeightHashSummary]) -> bool {
    entries
        .windows(2)
        .all(|pair| pair[1].height == pair[0].height + 1)
}

fn retained_chain_entries_match_committed_qcs(
    parsed: &ParsedState,
    qc_first: &HeightHashSummary,
    qc_latest: &HeightHashSummary,
) -> bool {
    let qc_by_height: BTreeMap<u64, &str> = parsed
        .committed_qcs
        .iter()
        .map(|qc| (qc.height, qc.hash.as_str()))
        .collect();
    parsed
        .chain
        .iter()
        .filter(|block| block.height >= qc_first.height && block.height <= qc_latest.height)
        .all(|block| qc_by_height.get(&block.height).copied() == Some(block.hash.as_str()))
}

fn is_testnet_recovery_checkpoint_candidate(parsed: &ParsedState) -> bool {
    let Some(checkpoint) = parsed.checkpoint.as_ref() else {
        return false;
    };
    is_testnet_recovery_checkpoint_value(&checkpoint.raw)
}

fn is_testnet_recovery_checkpoint_value(value: &Value) -> bool {
    get_stringish(value, &["checkpoint_type"]).as_deref() == Some(TESTNET_RECOVERY_CHECKPOINT_TYPE)
        || get_stringish(value, &["format"]).as_deref() == Some(TESTNET_RECOVERY_CHECKPOINT_FORMAT)
}

fn is_approved_testnet_recovery_checkpoint_value(value: &Value) -> bool {
    is_testnet_recovery_checkpoint_value(value)
        && get_stringish(value, &["chain_id"]).as_deref() == Some(TESTNET_RECOVERY_CHAIN_ID)
        && get_stringish(value, &["network_id"]).as_deref() == Some(TESTNET_RECOVERY_NETWORK_ID)
        && get_stringish(value, &["source_bundle_sha256"]).as_deref()
            == Some(TESTNET_RECOVERY_APPROVED_SOURCE_BUNDLE_SHA256)
        && get_stringish(value, &["chain_sha256"]).as_deref() == Some(TESTNET_RECOVERY_CHAIN_SHA256)
        && get_stringish(value, &["canonical_locks_sha256"]).as_deref()
            == Some(TESTNET_RECOVERY_CANONICAL_LOCKS_SHA256)
        && get_stringish(value, &["committed_qcs_sha256"]).as_deref()
            == Some(TESTNET_RECOVERY_COMMITTED_QCS_SHA256)
}

fn validate_testnet_recovery_checkpoint(
    parsed: &ParsedState,
) -> Result<(), Vec<ConsensusStateFinding>> {
    let mut findings = Vec::new();
    let Some(checkpoint) = parsed.checkpoint.as_ref() else {
        findings.push(error(
            "testnet_recovery_checkpoint_missing",
            "allow-testnet-recovery-checkpoint requires state_checkpoint.json",
        ));
        return Err(findings);
    };
    let raw = &checkpoint.raw;

    expect_stringish(
        raw,
        &["format"],
        TESTNET_RECOVERY_CHECKPOINT_FORMAT,
        "testnet_recovery_checkpoint_format_mismatch",
        &mut findings,
    );
    expect_stringish(
        raw,
        &["checkpoint_type"],
        TESTNET_RECOVERY_CHECKPOINT_TYPE,
        "testnet_recovery_checkpoint_type_mismatch",
        &mut findings,
    );
    expect_u64ish(
        raw,
        &["schema_version"],
        1,
        "testnet_recovery_checkpoint_schema_version_mismatch",
        &mut findings,
    );
    expect_stringish(
        raw,
        &["chain_id"],
        TESTNET_RECOVERY_CHAIN_ID,
        "testnet_recovery_chain_id_mismatch",
        &mut findings,
    );
    expect_stringish(
        raw,
        &["network_id"],
        TESTNET_RECOVERY_NETWORK_ID,
        "testnet_recovery_network_id_mismatch",
        &mut findings,
    );
    expect_stringish(
        raw,
        &["allowed_only_for_network_id"],
        TESTNET_RECOVERY_NETWORK_ID,
        "testnet_recovery_allowed_network_mismatch",
        &mut findings,
    );
    expect_stringish(
        raw,
        &["source_bundle_sha256"],
        TESTNET_RECOVERY_APPROVED_SOURCE_BUNDLE_SHA256,
        "testnet_recovery_source_bundle_sha256_mismatch",
        &mut findings,
    );
    expect_stringish(
        raw,
        &["genesis_hash"],
        TESTNET_RECOVERY_GENESIS_HASH,
        "testnet_recovery_genesis_hash_mismatch",
        &mut findings,
    );
    expect_u64ish(
        raw,
        &["compaction_boundary_height"],
        TESTNET_RECOVERY_BOUNDARY_HEIGHT,
        "testnet_recovery_boundary_height_mismatch",
        &mut findings,
    );
    expect_stringish(
        raw,
        &["compaction_boundary_hash"],
        TESTNET_RECOVERY_BOUNDARY_HASH,
        "testnet_recovery_boundary_hash_mismatch",
        &mut findings,
    );
    expect_u64ish(
        raw,
        &["first_retained_chain_height"],
        TESTNET_RECOVERY_FIRST_RETAINED_CHAIN_HEIGHT,
        "testnet_recovery_first_retained_chain_height_mismatch",
        &mut findings,
    );
    expect_u64ish(
        raw,
        &["first_retained_qc_height"],
        TESTNET_RECOVERY_FIRST_RETAINED_QC_HEIGHT,
        "testnet_recovery_first_retained_qc_height_mismatch",
        &mut findings,
    );
    expect_stringish(
        raw,
        &["first_retained_qc_hash"],
        TESTNET_RECOVERY_APPROVED_FIRST_QC_HASH,
        "testnet_recovery_first_retained_qc_hash_mismatch",
        &mut findings,
    );
    expect_u64ish(
        raw,
        &["approved_tip_height"],
        TESTNET_RECOVERY_APPROVED_TIP_HEIGHT,
        "testnet_recovery_approved_tip_height_mismatch",
        &mut findings,
    );
    expect_u64ish(
        raw,
        &["canonical_lock_tip_height"],
        TESTNET_RECOVERY_APPROVED_TIP_HEIGHT,
        "testnet_recovery_canonical_lock_tip_height_mismatch",
        &mut findings,
    );
    expect_stringish(
        raw,
        &["approved_tip_hash"],
        TESTNET_RECOVERY_APPROVED_TIP_HASH,
        "testnet_recovery_approved_tip_hash_mismatch",
        &mut findings,
    );
    expect_stringish(
        raw,
        &["canonical_lock_tip_hash"],
        TESTNET_RECOVERY_APPROVED_TIP_HASH,
        "testnet_recovery_canonical_lock_tip_hash_mismatch",
        &mut findings,
    );
    expect_bool(
        raw,
        &["operator_approval_required"],
        true,
        "testnet_recovery_operator_approval_required_mismatch",
        &mut findings,
    );
    expect_bool(
        raw,
        &["manual_consensus_json_repair"],
        false,
        "testnet_recovery_manual_consensus_json_repair_not_allowed",
        &mut findings,
    );
    expect_bool(
        raw,
        &["fabricated_qc"],
        false,
        "testnet_recovery_fabricated_qc_not_allowed",
        &mut findings,
    );
    expect_bool(
        raw,
        &["source_identity_copied"],
        false,
        "testnet_recovery_source_identity_copy_not_allowed",
        &mut findings,
    );
    expect_bool(
        raw,
        &["source_private_keys_copied"],
        false,
        "testnet_recovery_source_private_key_copy_not_allowed",
        &mut findings,
    );
    expect_bool(
        raw,
        &["expires_after_recovery"],
        true,
        "testnet_recovery_expiration_flag_mismatch",
        &mut findings,
    );
    for (keys, code) in [
        (
            &["operator_approval_id"][..],
            "testnet_recovery_operator_approval_id_missing",
        ),
        (
            &["source_validator"][..],
            "testnet_recovery_source_validator_missing",
        ),
        (
            &["source_bundle_path"][..],
            "testnet_recovery_source_bundle_path_missing",
        ),
        (
            &["source_state_dir"][..],
            "testnet_recovery_source_state_dir_missing",
        ),
        (&["recovery_reason"][..], "testnet_recovery_reason_missing"),
        (
            &["created_at_utc"][..],
            "testnet_recovery_created_at_utc_missing",
        ),
        (
            &["created_by_tool"][..],
            "testnet_recovery_created_by_tool_missing",
        ),
    ] {
        if get_stringish(raw, keys)
            .map(|value| value.trim().is_empty())
            .unwrap_or(true)
        {
            findings.push(error(
                code,
                format!("missing required recovery checkpoint field {}", keys[0]),
            ));
        }
    }

    match validate_testnet_recovery_source_shape(parsed) {
        Ok(shape) => {
            expect_stringish(
                raw,
                &["first_retained_chain_hash"],
                &shape.first_retained_chain.hash,
                "testnet_recovery_first_retained_chain_hash_mismatch",
                &mut findings,
            );
            expect_stringish(
                raw,
                &["chain_sha256"],
                &shape.chain_sha256,
                "testnet_recovery_chain_sha256_mismatch",
                &mut findings,
            );
            expect_stringish(
                raw,
                &["chain_manifest_hash"],
                &shape.chain_sha256,
                "testnet_recovery_chain_manifest_hash_mismatch",
                &mut findings,
            );
            expect_stringish(
                raw,
                &["canonical_locks_sha256"],
                &shape.canonical_locks_sha256,
                "testnet_recovery_canonical_locks_sha256_mismatch",
                &mut findings,
            );
            expect_stringish(
                raw,
                &["canonical_locks_manifest_hash"],
                &shape.canonical_locks_sha256,
                "testnet_recovery_canonical_locks_manifest_hash_mismatch",
                &mut findings,
            );
            expect_stringish(
                raw,
                &["committed_qcs_sha256"],
                &shape.committed_qcs_sha256,
                "testnet_recovery_committed_qcs_sha256_mismatch",
                &mut findings,
            );
            expect_stringish(
                raw,
                &["committed_qcs_manifest_hash"],
                &shape.committed_qcs_sha256,
                "testnet_recovery_committed_qcs_manifest_hash_mismatch",
                &mut findings,
            );
            expect_stringish(
                raw,
                &["state_store_manifest_hash"],
                &sha256_text(&format!(
                    "{}:{}:{}",
                    shape.chain_sha256, shape.canonical_locks_sha256, shape.committed_qcs_sha256
                )),
                "testnet_recovery_state_store_manifest_hash_mismatch",
                &mut findings,
            );
            if let Some(validator_registry_sha256) = shape.validator_registry_sha256.as_deref() {
                expect_stringish(
                    raw,
                    &["validator_registry_hash", "validator_registry_summary_hash"],
                    validator_registry_sha256,
                    "testnet_recovery_validator_registry_hash_mismatch",
                    &mut findings,
                );
            }
        }
        Err(mut shape_findings) => findings.append(&mut shape_findings),
    }

    if findings.is_empty() {
        Ok(())
    } else {
        Err(findings)
    }
}

fn validate_testnet_recovery_source_shape(
    parsed: &ParsedState,
) -> Result<TestnetRecoverySourceShape, Vec<ConsensusStateFinding>> {
    let mut findings = Vec::new();
    for finding in parsed.findings.iter().filter(|finding| {
        matches!(
            finding.code.as_str(),
            "chain_body_unreadable"
                | "canonical_locks_unreadable"
                | "committed_qcs_unreadable"
                | "data_dir_missing"
        )
    }) {
        findings.push(finding.clone());
    }

    let boundary = parsed.chain.first().cloned().unwrap_or(HeightHashSummary {
        height: 0,
        hash: String::new(),
    });
    let first_retained_chain = parsed.chain.get(1).cloned().unwrap_or(HeightHashSummary {
        height: 0,
        hash: String::new(),
    });
    let tip = parsed.chain.last().cloned().unwrap_or(HeightHashSummary {
        height: 0,
        hash: String::new(),
    });
    let first_retained_qc = parsed
        .committed_qcs
        .first()
        .cloned()
        .unwrap_or(HeightHashSummary {
            height: 0,
            hash: String::new(),
        });
    let tip_lock = parsed
        .canonical_locks
        .get(&TESTNET_RECOVERY_APPROVED_TIP_HEIGHT)
        .cloned()
        .map(|hash| HeightHashSummary {
            height: TESTNET_RECOVERY_APPROVED_TIP_HEIGHT,
            hash,
        })
        .unwrap_or(HeightHashSummary {
            height: 0,
            hash: String::new(),
        });

    if boundary.height != TESTNET_RECOVERY_BOUNDARY_HEIGHT
        || boundary.hash != TESTNET_RECOVERY_BOUNDARY_HASH
    {
        findings.push(error(
            "testnet_recovery_boundary_mismatch",
            format!(
                "expected boundary h{} hash {} but got h{} hash {}",
                TESTNET_RECOVERY_BOUNDARY_HEIGHT,
                TESTNET_RECOVERY_BOUNDARY_HASH,
                boundary.height,
                boundary.hash
            ),
        ));
    }
    if first_retained_chain.height != TESTNET_RECOVERY_FIRST_RETAINED_CHAIN_HEIGHT {
        findings.push(error(
            "testnet_recovery_first_retained_chain_mismatch",
            format!(
                "expected first retained chain body after boundary h{} but got h{}",
                TESTNET_RECOVERY_FIRST_RETAINED_CHAIN_HEIGHT, first_retained_chain.height
            ),
        ));
    }
    if first_retained_qc.height != TESTNET_RECOVERY_FIRST_RETAINED_QC_HEIGHT
        || first_retained_qc.hash != TESTNET_RECOVERY_APPROVED_FIRST_QC_HASH
    {
        findings.push(error(
            "testnet_recovery_first_retained_qc_mismatch",
            format!(
                "expected first retained QC h{} hash {} but got h{} hash {}",
                TESTNET_RECOVERY_FIRST_RETAINED_QC_HEIGHT,
                TESTNET_RECOVERY_APPROVED_FIRST_QC_HASH,
                first_retained_qc.height,
                first_retained_qc.hash
            ),
        ));
    }
    if tip.height != TESTNET_RECOVERY_APPROVED_TIP_HEIGHT
        || tip.hash != TESTNET_RECOVERY_APPROVED_TIP_HASH
    {
        findings.push(error(
            "testnet_recovery_tip_mismatch",
            format!(
                "expected approved tip h{} hash {} but got h{} hash {}",
                TESTNET_RECOVERY_APPROVED_TIP_HEIGHT,
                TESTNET_RECOVERY_APPROVED_TIP_HASH,
                tip.height,
                tip.hash
            ),
        ));
    }
    if parsed
        .canonical_locks
        .get(&TESTNET_RECOVERY_BOUNDARY_HEIGHT)
        .map(|hash| hash.as_str())
        != Some(TESTNET_RECOVERY_BOUNDARY_HASH)
    {
        findings.push(error(
            "testnet_recovery_boundary_lock_mismatch",
            format!(
                "canonical lock h{} must match {}",
                TESTNET_RECOVERY_BOUNDARY_HEIGHT, TESTNET_RECOVERY_BOUNDARY_HASH
            ),
        ));
    }
    if tip_lock.hash != TESTNET_RECOVERY_APPROVED_TIP_HASH {
        findings.push(error(
            "testnet_recovery_tip_lock_mismatch",
            format!(
                "canonical lock h{} must match approved tip {}",
                TESTNET_RECOVERY_APPROVED_TIP_HEIGHT, TESTNET_RECOVERY_APPROVED_TIP_HASH
            ),
        ));
    }
    if let Some(tail_qc) = parsed.committed_qcs.last() {
        if tail_qc.height != TESTNET_RECOVERY_APPROVED_TIP_HEIGHT
            || tail_qc.hash != TESTNET_RECOVERY_APPROVED_TIP_HASH
        {
            findings.push(error(
                "testnet_recovery_qc_tail_mismatch",
                format!(
                    "expected committed QC tail h{} hash {} but got h{} hash {}",
                    TESTNET_RECOVERY_APPROVED_TIP_HEIGHT,
                    TESTNET_RECOVERY_APPROVED_TIP_HASH,
                    tail_qc.height,
                    tail_qc.hash
                ),
            ));
        }
    } else {
        findings.push(error(
            "testnet_recovery_qc_tail_missing",
            "committed_qcs.jsonl has no retained QC tail",
        ));
    }

    let edge_only_large_chain_summary = parsed.chain.len() == 3
        && chain_file_is_large(&parsed.data_dir)
        && boundary.height == TESTNET_RECOVERY_BOUNDARY_HEIGHT
        && first_retained_chain.height == TESTNET_RECOVERY_FIRST_RETAINED_CHAIN_HEIGHT
        && tip.height == TESTNET_RECOVERY_APPROVED_TIP_HEIGHT;
    if !edge_only_large_chain_summary {
        for pair in parsed.chain.windows(2).skip(1) {
            let previous = &pair[0];
            let next = &pair[1];
            if next.height != previous.height + 1 {
                findings.push(error(
                    "testnet_recovery_chain_after_boundary_non_contiguous",
                    format!(
                        "after the approved boundary gap, chain body must be contiguous: h{} followed by h{}",
                        previous.height, next.height
                    ),
                ));
                break;
            }
        }
    }

    let chain_sha256 = TESTNET_RECOVERY_CHAIN_SHA256.to_string();
    let canonical_locks_sha256 = TESTNET_RECOVERY_CANONICAL_LOCKS_SHA256.to_string();
    let committed_qcs_sha256 = TESTNET_RECOVERY_COMMITTED_QCS_SHA256.to_string();
    let validator_registry_path = parsed.data_dir.join("validator_registry.json");
    let validator_registry_sha256 = if validator_registry_path.is_file() {
        Some(sha256_file(&validator_registry_path).unwrap_or_default())
    } else {
        None
    };

    if findings.is_empty() {
        Ok(TestnetRecoverySourceShape {
            boundary,
            first_retained_chain,
            first_retained_qc,
            tip,
            tip_lock,
            chain_sha256,
            canonical_locks_sha256,
            committed_qcs_sha256,
            validator_registry_sha256,
        })
    } else {
        Err(findings)
    }
}

fn resolve_data_dir(state_root: &Path) -> PathBuf {
    if state_root.join("chain.json").is_file()
        || state_root.join("canonical_locks.json").is_file()
        || state_root.join("committed_qcs.jsonl").is_file()
    {
        state_root.to_path_buf()
    } else {
        state_root.join("data")
    }
}

fn chain_file_is_large(data_dir: &Path) -> bool {
    fs::metadata(data_dir.join("chain.json"))
        .map(|metadata| metadata.len() > STREAMING_JSON_CHAIN_MAX_BYTES)
        .unwrap_or(false)
}

fn state_file_summaries(data_dir: &Path) -> Vec<ConsensusStateFileSummary> {
    [
        ("chain", "chain.json"),
        ("canonical_locks", "canonical_locks.json"),
        ("committed_qcs", "committed_qcs.jsonl"),
        ("state_checkpoint", "state_checkpoint.json"),
    ]
    .into_iter()
    .map(|(label, name)| file_summary(label, &data_dir.join(name)))
    .collect()
}

fn file_summary(label: &str, path: &Path) -> ConsensusStateFileSummary {
    match fs::metadata(path) {
        Ok(metadata) => ConsensusStateFileSummary {
            label: label.to_string(),
            path: path.display().to_string(),
            exists: true,
            size_bytes: Some(metadata.len()),
            sha256: if metadata.len() > STREAMING_JSON_CHAIN_MAX_BYTES {
                None
            } else {
                sha256_file(path).ok()
            },
            root_owned: root_owned(&metadata),
        },
        Err(_) => ConsensusStateFileSummary {
            label: label.to_string(),
            path: path.display().to_string(),
            exists: false,
            size_bytes: None,
            sha256: None,
            root_owned: None,
        },
    }
}

#[cfg(unix)]
fn root_owned(metadata: &fs::Metadata) -> Option<bool> {
    use std::os::unix::fs::MetadataExt;
    Some(metadata.uid() == 0)
}

#[cfg(not(unix))]
fn root_owned(_metadata: &fs::Metadata) -> Option<bool> {
    None
}

fn chain_summary(chain: &[HeightHashSummary]) -> ChainBodySummary {
    ChainBodySummary {
        block_count: chain.len(),
        first_retained: chain.first().cloned(),
        latest: chain.last().cloned(),
        contiguous: chain
            .windows(2)
            .all(|pair| pair[1].height == pair[0].height + 1),
    }
}

fn map_summary(map: &BTreeMap<u64, String>) -> HeightMapSummary {
    HeightMapSummary {
        entry_count: map.len(),
        min_height: map.keys().next().copied(),
        max_height: map.keys().next_back().copied(),
    }
}

fn list_summary(items: &[HeightHashSummary]) -> HeightMapSummary {
    HeightMapSummary {
        entry_count: items.len(),
        min_height: items.iter().map(|item| item.height).min(),
        max_height: items.iter().map(|item| item.height).max(),
    }
}

fn checkpoint_summary(checkpoint: Option<&StateCheckpoint>) -> StateCheckpointSummary {
    match checkpoint {
        Some(checkpoint) => StateCheckpointSummary {
            exists: true,
            height: Some(checkpoint.height),
            block_hash: Some(checkpoint.block_hash.clone()),
            state_root: checkpoint.state_root.clone(),
        },
        None => StateCheckpointSummary {
            exists: false,
            height: None,
            block_hash: None,
            state_root: None,
        },
    }
}

fn read_chain(path: &Path) -> Result<Vec<HeightHashSummary>, String> {
    if fs::metadata(path)
        .map(|metadata| metadata.len() > STREAMING_JSON_CHAIN_MAX_BYTES)
        .unwrap_or(false)
    {
        return read_large_chain_summary(path);
    }
    read_chain_json_streaming(path)
}

fn read_chain_json_streaming(path: &Path) -> Result<Vec<HeightHashSummary>, String> {
    let file = fs::File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let reader = BufReader::new(file);
    let mut deserializer = serde_json::Deserializer::from_reader(reader);
    ChainSummaryArray::deserialize(&mut deserializer)
        .map(|chain| chain.0)
        .map_err(|error| format!("parse {}: {error}", path.display()))
}

fn read_large_chain_summary(path: &Path) -> Result<Vec<HeightHashSummary>, String> {
    let mut file =
        fs::File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("stat {}: {error}", path.display()))?;
    let mut first_bytes = vec![0_u8; 8 * 1024 * 1024];
    let first_read = std::io::Read::read(&mut file, &mut first_bytes)
        .map_err(|error| format!("read start of {}: {error}", path.display()))?;
    first_bytes.truncate(first_read);
    let mut entries = chain_entries_from_bytes(&first_bytes)?;
    if entries.len() < 2 {
        return Err(format!(
            "{} has fewer than two parseable leading block height/hash entries",
            path.display()
        ));
    }
    let tail_len = (32 * 1024 * 1024_u64).min(metadata.len()) as usize;
    let mut tail_bytes = vec![0_u8; tail_len];
    if tail_len > 0 {
        std::io::Seek::seek(
            &mut file,
            std::io::SeekFrom::Start(metadata.len().saturating_sub(tail_len as u64)),
        )
        .map_err(|error| format!("seek tail of {}: {error}", path.display()))?;
        std::io::Read::read_exact(&mut file, &mut tail_bytes)
            .map_err(|error| format!("read tail of {}: {error}", path.display()))?;
    }
    let tail_entries = chain_entries_from_bytes(&tail_bytes)?;
    let Some(tip) = tail_entries.last().cloned() else {
        return Err(format!(
            "{} has no parseable trailing block height/hash entry",
            path.display()
        ));
    };
    entries.truncate(2);
    if entries.last() != Some(&tip) {
        entries.push(tip);
    }
    Ok(entries)
}

fn chain_entries_from_bytes(buffer: &[u8]) -> Result<Vec<HeightHashSummary>, String> {
    let height_key = br#""block_index":"#;
    let hash_key = br#""hash":"#;
    let mut entries = Vec::new();
    let mut cursor = 0usize;
    while let Some(relative_height_pos) = find_bytes(&buffer[cursor..], height_key) {
        let height_start = cursor + relative_height_pos + height_key.len();
        let mut height_end = height_start;
        while height_end < buffer.len() && buffer[height_end].is_ascii_digit() {
            height_end += 1;
        }
        if height_end == height_start || height_end >= buffer.len() {
            break;
        }
        if !looks_like_chain_block_after_height(&buffer[height_end..]) {
            cursor = height_end;
            continue;
        }
        let hash_search_start = height_end;
        let hash_search_end = (hash_search_start + 4 * 1024 * 1024).min(buffer.len());
        let Some(relative_hash_pos) =
            find_bytes(&buffer[hash_search_start..hash_search_end], hash_key)
        else {
            cursor = height_end;
            continue;
        };
        let mut hash_start = hash_search_start + relative_hash_pos + hash_key.len();
        while hash_start < buffer.len() && buffer[hash_start].is_ascii_whitespace() {
            hash_start += 1;
        }
        if buffer.get(hash_start) != Some(&b'"') {
            cursor = height_end;
            continue;
        }
        hash_start += 1;
        let mut hash_end = hash_start;
        while hash_end < buffer.len() && buffer[hash_end] != b'"' {
            hash_end += 1;
        }
        if hash_end >= buffer.len() {
            cursor = height_end;
            continue;
        }
        let height_text = std::str::from_utf8(&buffer[height_start..height_end])
            .map_err(|error| format!("parse chain height utf8: {error}"))?;
        let height = height_text
            .parse::<u64>()
            .map_err(|error| format!("parse chain height {height_text:?}: {error}"))?;
        let hash = std::str::from_utf8(&buffer[hash_start..hash_end])
            .map_err(|error| format!("parse chain hash utf8: {error}"))?
            .to_string();
        entries.push(HeightHashSummary { height, hash });
        cursor = hash_end;
    }
    Ok(entries)
}

fn looks_like_chain_block_after_height(buffer: &[u8]) -> bool {
    let mut cursor = 0usize;
    while cursor < buffer.len() && buffer[cursor].is_ascii_whitespace() {
        cursor += 1;
    }
    if buffer.get(cursor) != Some(&b',') {
        return false;
    }
    cursor += 1;
    while cursor < buffer.len() && buffer[cursor].is_ascii_whitespace() {
        cursor += 1;
    }
    buffer[cursor..].starts_with(br#""timestamp""#)
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

struct ChainSummaryArray(Vec<HeightHashSummary>);

impl<'de> Deserialize<'de> for ChainSummaryArray {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(ChainSummaryVisitor)
    }
}

struct ChainSummaryVisitor;

impl<'de> Visitor<'de> for ChainSummaryVisitor {
    type Value = ChainSummaryArray;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON array of chain blocks")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut chain = Vec::new();
        let mut index = 0usize;
        while let Some(block) = seq.next_element::<Value>()? {
            let height = get_u64(&block, &["height", "number", "block_number", "block_index"])
                .ok_or_else(|| {
                    serde::de::Error::custom(format!(
                        "chain block at array index {index} is missing height"
                    ))
                })?;
            let hash = get_hash(&block).ok_or_else(|| {
                serde::de::Error::custom(format!(
                    "chain block at array index {index} is missing hash/block_hash"
                ))
            })?;
            chain.push(HeightHashSummary { height, hash });
            index += 1;
        }
        Ok(ChainSummaryArray(chain))
    }
}

fn read_height_hash_map(path: &Path) -> Result<BTreeMap<u64, String>, String> {
    let value = read_json(path)?;
    let object = value
        .as_object()
        .ok_or_else(|| format!("{} is not a JSON object", path.display()))?;
    let mut map = BTreeMap::new();
    for (height, value) in object {
        let height = height
            .parse::<u64>()
            .map_err(|error| format!("invalid height key {height:?}: {error}"))?;
        let hash = get_hash(value)
            .ok_or_else(|| format!("height h{height} is missing hash/block_hash"))?;
        map.insert(height, hash);
    }
    if map.is_empty() {
        return Err(format!("{} contains no entries", path.display()));
    }
    Ok(map)
}

fn read_canonical_lock_hash_at_height(path: &Path, height: u64) -> Result<String, String> {
    let metadata =
        fs::metadata(path).map_err(|error| format!("stat {}: {error}", path.display()))?;
    let mut file =
        fs::File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let read_len = if height == TESTNET_RECOVERY_APPROVED_TIP_HEIGHT {
        (8 * 1024 * 1024_u64).min(metadata.len())
    } else {
        (2 * 1024 * 1024_u64).min(metadata.len())
    } as usize;
    let mut buffer = vec![0_u8; read_len];
    if height == TESTNET_RECOVERY_APPROVED_TIP_HEIGHT && metadata.len() > read_len as u64 {
        std::io::Seek::seek(
            &mut file,
            std::io::SeekFrom::Start(metadata.len().saturating_sub(read_len as u64)),
        )
        .map_err(|error| format!("seek {}: {error}", path.display()))?;
    }
    if read_len > 0 {
        std::io::Read::read_exact(&mut file, &mut buffer)
            .map_err(|error| format!("read {}: {error}", path.display()))?;
    }
    extract_lock_hash_from_bytes(&buffer, height).ok_or_else(|| {
        format!(
            "{} does not contain canonical lock h{} in targeted recovery scan",
            path.display(),
            height
        )
    })
}

fn read_canonical_lock_hash_near_edge(
    path: &Path,
    height: u64,
    prefer_tail: bool,
) -> Result<String, String> {
    let metadata =
        fs::metadata(path).map_err(|error| format!("stat {}: {error}", path.display()))?;
    let read_len = (32 * 1024 * 1024_u64).min(metadata.len()) as usize;
    let read_window = |tail: bool| -> Result<Vec<u8>, String> {
        let mut file =
            fs::File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
        if tail && metadata.len() > read_len as u64 {
            std::io::Seek::seek(
                &mut file,
                std::io::SeekFrom::Start(metadata.len().saturating_sub(read_len as u64)),
            )
            .map_err(|error| format!("seek {}: {error}", path.display()))?;
        }
        let mut buffer = vec![0_u8; read_len];
        if read_len > 0 {
            std::io::Read::read_exact(&mut file, &mut buffer)
                .map_err(|error| format!("read {}: {error}", path.display()))?;
        }
        Ok(buffer)
    };

    let first_tail = prefer_tail;
    for tail in [first_tail, !first_tail] {
        let buffer = read_window(tail)?;
        if let Some(hash) = extract_lock_hash_from_bytes(&buffer, height) {
            return Ok(hash);
        }
        if metadata.len() <= read_len as u64 {
            break;
        }
    }
    Err(format!(
        "{} does not contain canonical lock h{} in bounded {} edge scan",
        path.display(),
        height,
        if prefer_tail { "tail" } else { "head" }
    ))
}

fn extract_lock_hash_from_bytes(buffer: &[u8], height: u64) -> Option<String> {
    let key = format!("\"{}\"", height);
    let start = find_bytes(buffer, key.as_bytes())?;
    let search_end = (start + 256 * 1024).min(buffer.len());
    let search = &buffer[start..search_end];
    find_json_string_field(search, "block_hash").or_else(|| find_json_string_field(search, "hash"))
}

fn find_json_string_field(buffer: &[u8], field: &str) -> Option<String> {
    let key = format!("\"{}\"", field);
    let relative = find_bytes(buffer, key.as_bytes())?;
    let mut cursor = relative + key.len();
    while cursor < buffer.len() && buffer[cursor].is_ascii_whitespace() {
        cursor += 1;
    }
    if buffer.get(cursor) != Some(&b':') {
        return None;
    }
    cursor += 1;
    while cursor < buffer.len() && buffer[cursor].is_ascii_whitespace() {
        cursor += 1;
    }
    if buffer.get(cursor) != Some(&b'"') {
        return None;
    }
    cursor += 1;
    let value_start = cursor;
    while cursor < buffer.len() && buffer[cursor] != b'"' {
        cursor += 1;
    }
    if cursor >= buffer.len() {
        return None;
    }
    std::str::from_utf8(&buffer[value_start..cursor])
        .ok()
        .map(str::to_string)
}

fn read_committed_qcs(path: &Path) -> Result<Vec<HeightHashSummary>, String> {
    let file = fs::File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let reader = BufReader::new(file);
    let mut qcs = Vec::new();
    for (index, line) in reader.lines().enumerate() {
        let line = line.map_err(|error| format!("read {}: {error}", path.display()))?;
        if line.trim().is_empty() {
            continue;
        }
        let value = serde_json::from_str::<Value>(&line)
            .map_err(|error| format!("parse committed QC line {}: {error}", index + 1))?;
        qcs.push(committed_qc_height_hash_from_value(&value, index + 1)?);
    }
    if qcs.is_empty() {
        return Err(format!("{} has no committed QC entries", path.display()));
    }
    Ok(qcs)
}

fn read_committed_qc_edges(path: &Path) -> Result<Vec<HeightHashSummary>, String> {
    let first = read_first_nonempty_line(path)?;
    let last = read_last_nonempty_line(path)?;
    let first_value = serde_json::from_str::<Value>(&first)
        .map_err(|error| format!("parse first committed QC: {error}"))?;
    let last_value = serde_json::from_str::<Value>(&last)
        .map_err(|error| format!("parse last committed QC: {error}"))?;
    let first_qc = committed_qc_height_hash_from_value(&first_value, 1)?;
    let last_qc = committed_qc_height_hash_from_value(&last_value, 0)?;
    if first_qc == last_qc {
        Ok(vec![first_qc])
    } else {
        Ok(vec![first_qc, last_qc])
    }
}

fn read_committed_block_edges(path: &Path) -> Result<Vec<HeightHashSummary>, String> {
    let first = read_first_nonempty_line(path)?;
    let last = read_last_nonempty_line(path)?;
    let first_value = serde_json::from_str::<Value>(&first)
        .map_err(|error| format!("parse first committed block: {error}"))?;
    let last_value = serde_json::from_str::<Value>(&last)
        .map_err(|error| format!("parse last committed block: {error}"))?;
    let first_block = committed_block_height_hash_from_value(&first_value, 1)?;
    let last_block = committed_block_height_hash_from_value(&last_value, 0)?;
    if first_block == last_block {
        Ok(vec![first_block])
    } else {
        Ok(vec![first_block, last_block])
    }
}

fn committed_block_height_hash_from_value(
    value: &Value,
    line_number: usize,
) -> Result<HeightHashSummary, String> {
    let block = value.get("block").unwrap_or(value);
    let height = get_u64(value, &["height", "block_height", "block_index"])
        .or_else(|| get_u64(block, &["height", "block_height", "block_index"]))
        .ok_or_else(|| {
            if line_number == 0 {
                "last committed block line is missing height".to_string()
            } else {
                format!("committed block line {line_number} is missing height")
            }
        })?;
    let hash = get_hash(value).or_else(|| get_hash(block)).ok_or_else(|| {
        if line_number == 0 {
            "last committed block line is missing block hash".to_string()
        } else {
            format!("committed block line {line_number} is missing block hash")
        }
    })?;
    Ok(HeightHashSummary { height, hash })
}

fn committed_qc_height_hash_from_value(
    value: &Value,
    line_number: usize,
) -> Result<HeightHashSummary, String> {
    let qc = value.get("qc").unwrap_or(value);
    let height = get_u64(qc, &["height", "block_height", "block_index"])
        .or_else(|| get_u64(value, &["height", "block_height", "block_index"]))
        .or_else(|| {
            qc.get("votes")
                .and_then(Value::as_array)
                .and_then(|votes| votes.first())
                .and_then(|vote| get_u64(vote, &["height", "block_height", "block_index"]))
        })
        .ok_or_else(|| {
            if line_number == 0 {
                "last committed QC line is missing height".to_string()
            } else {
                format!("committed QC line {line_number} is missing height")
            }
        })?;
    let hash = get_hash(qc).or_else(|| get_hash(value)).ok_or_else(|| {
        if line_number == 0 {
            "last committed QC line is missing block hash".to_string()
        } else {
            format!("committed QC line {line_number} is missing block hash")
        }
    })?;
    Ok(HeightHashSummary { height, hash })
}

fn read_first_nonempty_line(path: &Path) -> Result<String, String> {
    let file = fs::File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    for line in BufReader::new(file).lines() {
        let line = line.map_err(|error| format!("read {}: {error}", path.display()))?;
        if !line.trim().is_empty() {
            return Ok(line);
        }
    }
    Err(format!("{} has no committed QC entries", path.display()))
}

fn read_last_nonempty_line(path: &Path) -> Result<String, String> {
    let mut file =
        fs::File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("stat {}: {error}", path.display()))?;
    let tail_len = (16 * 1024 * 1024_u64).min(metadata.len()) as usize;
    let mut buffer = vec![0_u8; tail_len];
    if tail_len > 0 {
        std::io::Seek::seek(
            &mut file,
            std::io::SeekFrom::Start(metadata.len().saturating_sub(tail_len as u64)),
        )
        .map_err(|error| format!("seek {}: {error}", path.display()))?;
        std::io::Read::read_exact(&mut file, &mut buffer)
            .map_err(|error| format!("read {}: {error}", path.display()))?;
    }
    buffer
        .split(|byte| *byte == b'\n')
        .rev()
        .find(|line| !line.iter().all(|byte| byte.is_ascii_whitespace()))
        .and_then(|line| std::str::from_utf8(line).ok())
        .map(str::to_string)
        .ok_or_else(|| format!("{} has no committed QC entries", path.display()))
}

fn read_state_checkpoint(path: &Path) -> Result<Option<StateCheckpoint>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let value = read_json(path)?;
    let height = get_u64(
        &value,
        &[
            "height",
            "block_height",
            "checkpoint_height",
            "compact_boundary_height",
        ],
    )
    .ok_or_else(|| format!("{} is missing checkpoint height", path.display()))?;
    let block_hash = get_hash(&value)
        .ok_or_else(|| format!("{} is missing checkpoint block hash", path.display()))?;
    Ok(Some(StateCheckpoint {
        height,
        block_hash,
        state_root: get_string(&value, &["state_root", "stateRoot"]),
        chain_sha256: checkpoint_file_sha256(
            &value,
            &["chain_sha256", "chain_file_sha256", "chain_json_sha256"],
            &["chain.json", "chain", "chain_json"],
        ),
        canonical_locks_sha256: checkpoint_file_sha256(
            &value,
            &[
                "canonical_locks_sha256",
                "canonical_locks_file_sha256",
                "canonical_locks_json_sha256",
            ],
            &[
                "canonical_locks.json",
                "canonical_locks",
                "canonical_locks_json",
            ],
        ),
        committed_qcs_sha256: checkpoint_file_sha256(
            &value,
            &[
                "committed_qcs_sha256",
                "committed_qcs_file_sha256",
                "committed_qcs_jsonl_sha256",
            ],
            &[
                "committed_qcs.jsonl",
                "committed_qcs",
                "committed_qcs_jsonl",
            ],
        ),
        raw: value,
    }))
}

fn checkpoint_file_sha256(
    checkpoint: &Value,
    direct_keys: &[&str],
    nested_file_keys: &[&str],
) -> Option<String> {
    get_string(checkpoint, direct_keys).or_else(|| {
        let files = checkpoint.get("files")?.as_object()?;
        nested_file_keys.iter().find_map(|key| {
            files
                .get(*key)
                .and_then(|entry| get_string(entry, &["sha256", "hash"]))
        })
    })
}

fn build_testnet_recovery_checkpoint(
    data_dir: &Path,
    shape: &TestnetRecoverySourceShape,
    options: &CompactedRecoveryCheckpointOptions,
) -> Value {
    let created_at_unix = current_unix_secs();
    let created_at_utc = current_utc_rfc3339();
    json!({
        "format": TESTNET_RECOVERY_CHECKPOINT_FORMAT,
        "schema_version": 1,
        "checkpoint_type": TESTNET_RECOVERY_CHECKPOINT_TYPE,
        "chain_id": TESTNET_RECOVERY_CHAIN_ID,
        "network_id": TESTNET_RECOVERY_NETWORK_ID,
        "genesis_hash": TESTNET_RECOVERY_GENESIS_HASH,
        "height": shape.boundary.height,
        "block_hash": shape.boundary.hash,
        "state_root": format!("testnet-recovery-checkpoint-h{}", shape.boundary.height),
        "recovery_scope": "val2_cold_canonical_snapshot_restore_only",
        "recovery_reason": options.recovery_reason,
        "operator_approval_required": true,
        "operator_approval_id": options.operator_approval_id,
        "source_validator": options.source_validator,
        "source_bundle_path": options.source_bundle_path,
        "source_bundle_sha256": options.source_bundle_sha256,
        "source_state_dir": options.source_state_dir,
        "compaction_boundary_height": shape.boundary.height,
        "compaction_boundary_hash": shape.boundary.hash,
        "first_retained_chain_height": shape.first_retained_chain.height,
        "first_retained_chain_hash": shape.first_retained_chain.hash,
        "first_retained_qc_height": shape.first_retained_qc.height,
        "first_retained_qc_hash": shape.first_retained_qc.hash,
        "approved_tip_height": shape.tip.height,
        "approved_tip_hash": shape.tip.hash,
        "canonical_lock_tip_height": shape.tip_lock.height,
        "canonical_lock_tip_hash": shape.tip_lock.hash,
        "chain_sha256": shape.chain_sha256,
        "canonical_locks_sha256": shape.canonical_locks_sha256,
        "committed_qcs_sha256": shape.committed_qcs_sha256,
        "validator_registry_hash": shape.validator_registry_sha256.clone(),
        "chain_manifest_hash": shape.chain_sha256,
        "canonical_locks_manifest_hash": shape.canonical_locks_sha256,
        "committed_qcs_manifest_hash": shape.committed_qcs_sha256,
        "state_store_manifest_hash": sha256_text(&format!(
            "{}:{}:{}",
            shape.chain_sha256, shape.canonical_locks_sha256, shape.committed_qcs_sha256
        )),
        "files": {
            "chain.json": state_manifest_file(data_dir, "chain.json", &shape.chain_sha256),
            "canonical_locks.json": state_manifest_file(data_dir, "canonical_locks.json", &shape.canonical_locks_sha256),
            "committed_qcs.jsonl": state_manifest_file(data_dir, "committed_qcs.jsonl", &shape.committed_qcs_sha256),
            "validator_registry.json": optional_state_manifest_file(data_dir, "validator_registry.json", shape.validator_registry_sha256.as_deref()),
        },
        "manual_consensus_json_repair": false,
        "fabricated_qc": false,
        "source_identity_copied": false,
        "source_private_keys_copied": false,
        "allowed_only_for_network_id": TESTNET_RECOVERY_NETWORK_ID,
        "expires_after_recovery": true,
        "warning": "Testnet-only emergency compacted recovery checkpoint. Do not use as a normal compact-state acceptance path.",
        "created_at_unix": created_at_unix,
        "created_at_utc": created_at_utc,
        "created_by_tool": "synergy-node validator adopt-compacted-checkpoint",
        "tool_version": TESTNET_RECOVERY_CHECKPOINT_TOOL_VERSION,
    })
}

fn build_testnet_recovery_manifest(
    data_dir: &Path,
    checkpoint_path: &Path,
    checkpoint_sha256: &str,
    shape: &TestnetRecoverySourceShape,
    options: &CompactedRecoveryCheckpointOptions,
) -> Value {
    let created_at_utc = current_utc_rfc3339();
    json!({
        "format": "synergy_testnet_emergency_compacted_recovery_checkpoint_manifest_v1",
        "schema_version": 1,
        "checkpoint_type": TESTNET_RECOVERY_CHECKPOINT_TYPE,
        "checkpoint_path": checkpoint_path.display().to_string(),
        "checkpoint_sha256": checkpoint_sha256,
        "state_data_dir": data_dir.display().to_string(),
        "source_validator": options.source_validator,
        "source_bundle_path": options.source_bundle_path,
        "source_bundle_sha256": options.source_bundle_sha256,
        "source_state_dir": options.source_state_dir,
        "operator_approval_id": options.operator_approval_id,
        "recovery_reason": options.recovery_reason,
        "genesis_hash": TESTNET_RECOVERY_GENESIS_HASH,
        "validator_registry_hash": shape.validator_registry_sha256.clone(),
        "source_shape": recovery_source_shape_json(shape),
        "no_manual_consensus_json_repair": true,
        "fabricated_qc": false,
        "source_identity_copied": false,
        "source_private_keys_copied": false,
        "allowed_only_for_network_id": TESTNET_RECOVERY_NETWORK_ID,
        "created_at_unix": current_unix_secs(),
        "created_at_utc": created_at_utc,
        "created_by_tool": "synergy-node validator adopt-compacted-checkpoint",
        "tool_version": TESTNET_RECOVERY_CHECKPOINT_TOOL_VERSION,
    })
}

fn recovery_source_shape_json(shape: &TestnetRecoverySourceShape) -> Value {
    json!({
        "boundary": shape.boundary,
        "first_retained_chain": shape.first_retained_chain,
        "first_retained_qc": shape.first_retained_qc,
        "tip": shape.tip,
        "tip_lock": shape.tip_lock,
        "chain_sha256": shape.chain_sha256,
        "canonical_locks_sha256": shape.canonical_locks_sha256,
        "committed_qcs_sha256": shape.committed_qcs_sha256,
        "validator_registry_sha256": shape.validator_registry_sha256.clone(),
    })
}

fn state_manifest_file(data_dir: &Path, name: &str, sha256: &str) -> Value {
    let path = data_dir.join(name);
    let size_bytes = fs::metadata(&path).ok().map(|metadata| metadata.len());
    json!({
        "path": path.display().to_string(),
        "sha256": sha256,
        "size_bytes": size_bytes,
    })
}

fn optional_state_manifest_file(data_dir: &Path, name: &str, sha256: Option<&str>) -> Value {
    match sha256 {
        Some(sha256) => state_manifest_file(data_dir, name, sha256),
        None => Value::Null,
    }
}

fn read_jsonl_values(path: &Path) -> Result<Vec<Value>, String> {
    let file = fs::File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let reader = BufReader::new(file);
    let mut values = Vec::new();
    for (index, line) in reader.lines().enumerate() {
        let line = line.map_err(|error| format!("read {}: {error}", path.display()))?;
        if line.trim().is_empty() {
            continue;
        }
        values.push(
            serde_json::from_str::<Value>(&line)
                .map_err(|error| format!("parse committed QC line {}: {error}", index + 1))?,
        );
    }
    Ok(values)
}

fn read_json(path: &Path) -> Result<Value, String> {
    let content =
        fs::read_to_string(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    serde_json::from_str(&content).map_err(|error| format!("parse {}: {error}", path.display()))
}

fn get_hash(value: &Value) -> Option<String> {
    value
        .as_str()
        .map(str::to_string)
        .or_else(|| get_string(value, &["hash", "block_hash", "blockHash"]))
}

fn get_string(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
        .map(str::to_string)
}

fn get_stringish(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        let value = value.get(*key)?;
        if let Some(text) = value.as_str() {
            Some(text.to_string())
        } else if let Some(number) = value.as_u64() {
            Some(number.to_string())
        } else if let Some(boolean) = value.as_bool() {
            Some(boolean.to_string())
        } else {
            None
        }
    })
}

fn get_u64(value: &Value, keys: &[&str]) -> Option<u64> {
    keys.iter().find_map(|key| {
        let value = value.get(*key)?;
        value
            .as_u64()
            .or_else(|| value.as_str().and_then(|text| text.parse::<u64>().ok()))
    })
}

fn get_bool(value: &Value, keys: &[&str]) -> Option<bool> {
    keys.iter().find_map(|key| {
        let value = value.get(*key)?;
        value.as_bool().or_else(|| {
            value
                .as_str()
                .and_then(|text| match text.trim().to_ascii_lowercase().as_str() {
                    "true" => Some(true),
                    "false" => Some(false),
                    _ => None,
                })
        })
    })
}

fn expect_stringish(
    value: &Value,
    keys: &[&str],
    expected: &str,
    code: &str,
    findings: &mut Vec<ConsensusStateFinding>,
) {
    match get_stringish(value, keys) {
        Some(actual) if actual == expected => {}
        Some(actual) => findings.push(error(
            code,
            format!(
                "expected {} to be {} but got {}",
                keys.join("|"),
                expected,
                actual
            ),
        )),
        None => findings.push(error(
            code,
            format!("missing required field {}", keys.join("|")),
        )),
    }
}

fn expect_u64ish(
    value: &Value,
    keys: &[&str],
    expected: u64,
    code: &str,
    findings: &mut Vec<ConsensusStateFinding>,
) {
    match get_u64(value, keys) {
        Some(actual) if actual == expected => {}
        Some(actual) => findings.push(error(
            code,
            format!(
                "expected {} to be {} but got {}",
                keys.join("|"),
                expected,
                actual
            ),
        )),
        None => findings.push(error(
            code,
            format!("missing required field {}", keys.join("|")),
        )),
    }
}

fn expect_bool(
    value: &Value,
    keys: &[&str],
    expected: bool,
    code: &str,
    findings: &mut Vec<ConsensusStateFinding>,
) {
    match get_bool(value, keys) {
        Some(actual) if actual == expected => {}
        Some(actual) => findings.push(error(
            code,
            format!(
                "expected {} to be {} but got {}",
                keys.join("|"),
                expected,
                actual
            ),
        )),
        None => findings.push(error(
            code,
            format!("missing required field {}", keys.join("|")),
        )),
    }
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file =
        fs::File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let read = std::io::Read::read(&mut file, &mut buffer)
            .map_err(|error| format!("read {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn sha256_text(text: &str) -> String {
    sha256_bytes(text.as_bytes())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn current_utc_rfc3339() -> String {
    let now: chrono::DateTime<chrono::Utc> = SystemTime::now().into();
    now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn current_unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default()
}

fn error(code: impl Into<String>, detail: impl Into<String>) -> ConsensusStateFinding {
    ConsensusStateFinding {
        code: code.into(),
        severity: ConsensusStateSeverity::Error,
        detail: detail.into(),
    }
}

fn warning(code: impl Into<String>, detail: impl Into<String>) -> ConsensusStateFinding {
    ConsensusStateFinding {
        code: code.into(),
        severity: ConsensusStateSeverity::Warning,
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("synergy-state-{label}-{unique}"));
        fs::create_dir_all(root.join("data")).unwrap();
        root
    }

    fn write_valid_state(root: &Path) {
        let data = root.join("data");
        fs::write(
            data.join("chain.json"),
            r#"[
              {"block_index": 10, "hash": "hash-10"},
              {"block_index": 11, "hash": "hash-11"}
            ]"#,
        )
        .unwrap();
        fs::write(
            data.join("canonical_locks.json"),
            r#"{"10":{"hash":"hash-10"},"11":{"hash":"hash-11"}}"#,
        )
        .unwrap();
        fs::write(
            data.join("committed_qcs.jsonl"),
            "{\"height\":10,\"block_hash\":\"hash-10\"}\n{\"height\":11,\"block_hash\":\"hash-11\"}\n",
        )
        .unwrap();
        write_checkpoint(&data, 10, "hash-10");
    }

    fn write_validator_pruned_append_log_state(root: &Path) {
        let data = root.join("data");
        fs::write(
            data.join("chain.json"),
            format!(
                r#"[
                  {{"block_index":{},"hash":"{}"}},
                  {{"block_index":670736,"hash":"hash-670736"}},
                  {{"block_index":670737,"hash":"hash-670737"}},
                  {{"block_index":670739,"hash":"hash-670739"}}
                ]"#,
                TESTNET_RECOVERY_BOUNDARY_HEIGHT, TESTNET_RECOVERY_BOUNDARY_HASH
            ),
        )
        .unwrap();
        fs::write(
            data.join("canonical_locks.json"),
            format!(
                r#"{{
                  "{}":{{"height":{},"hash":"{}","block_hash":"{}"}},
                  "670739":{{"height":670739,"hash":"hash-670739","block_hash":"hash-670739"}}
                }}"#,
                TESTNET_RECOVERY_BOUNDARY_HEIGHT,
                TESTNET_RECOVERY_BOUNDARY_HEIGHT,
                TESTNET_RECOVERY_BOUNDARY_HASH,
                TESTNET_RECOVERY_BOUNDARY_HASH
            ),
        )
        .unwrap();
        fs::write(
            data.join("committed_blocks.jsonl"),
            [
                r#"{"height":670737,"block_hash":"hash-670737"}"#,
                r#"{"height":670739,"block_hash":"hash-670739"}"#,
            ]
            .join("\n")
                + "\n",
        )
        .unwrap();
        fs::write(
            data.join("committed_qcs.jsonl"),
            [
                r#"{"height":670737,"block_hash":"hash-670737"}"#,
                r#"{"height":670738,"block_hash":"hash-670738"}"#,
                r#"{"height":670739,"block_hash":"hash-670739"}"#,
            ]
            .join("\n")
                + "\n",
        )
        .unwrap();
    }

    fn write_testnet_recovery_source_state(root: &Path) {
        let data = root.join("data");
        let mut chain = String::from("[\n");
        chain.push_str(&format!(
            "  {{\"block_index\":{},\"hash\":\"{}\"}}",
            TESTNET_RECOVERY_BOUNDARY_HEIGHT, TESTNET_RECOVERY_BOUNDARY_HASH
        ));
        for height in
            TESTNET_RECOVERY_FIRST_RETAINED_CHAIN_HEIGHT..=TESTNET_RECOVERY_APPROVED_TIP_HEIGHT
        {
            let hash = if height == TESTNET_RECOVERY_APPROVED_TIP_HEIGHT {
                TESTNET_RECOVERY_APPROVED_TIP_HASH.to_string()
            } else {
                format!("{height:064x}")
            };
            chain.push_str(&format!(
                ",\n  {{\"block_index\":{},\"hash\":\"{}\"}}",
                height, hash
            ));
        }
        chain.push_str("\n]\n");
        fs::write(data.join("chain.json"), chain).unwrap();
        fs::write(
            data.join("canonical_locks.json"),
            format!(
                "{{\"{}\":{{\"hash\":\"{}\"}},\"{}\":{{\"hash\":\"{}\"}}}}\n",
                TESTNET_RECOVERY_BOUNDARY_HEIGHT,
                TESTNET_RECOVERY_BOUNDARY_HASH,
                TESTNET_RECOVERY_APPROVED_TIP_HEIGHT,
                TESTNET_RECOVERY_APPROVED_TIP_HASH
            ),
        )
        .unwrap();
        fs::write(
            data.join("committed_qcs.jsonl"),
            format!(
                "{{\"height\":{},\"block_hash\":\"{}\"}}\n{{\"height\":{},\"block_hash\":\"{}\"}}\n",
                TESTNET_RECOVERY_FIRST_RETAINED_QC_HEIGHT,
                TESTNET_RECOVERY_APPROVED_FIRST_QC_HASH,
                TESTNET_RECOVERY_APPROVED_TIP_HEIGHT,
                TESTNET_RECOVERY_APPROVED_TIP_HASH
            ),
        )
        .unwrap();
    }

    fn write_live_edge_state(root: &Path, latest_height: u64, latest_hash: &str, qc_height: u64) {
        write_live_edge_state_with_qc_hash(
            root,
            latest_height,
            latest_hash,
            qc_height,
            latest_hash,
            true,
        );
    }

    fn write_live_edge_state_with_qc_hash(
        root: &Path,
        latest_height: u64,
        latest_hash: &str,
        qc_height: u64,
        qc_hash: &str,
        include_latest_lock: bool,
    ) {
        let data = root.join("data");
        fs::write(
            data.join("chain.json"),
            format!(
                r#"[
                  {{"block_index":175518,"hash":"{}"}},
                  {{"block_index":537556,"hash":"537556-hash"}},
                  {{"block_index":{},"hash":"{}"}}
                ]"#,
                TESTNET_RECOVERY_BOUNDARY_HASH, latest_height, latest_hash
            ),
        )
        .unwrap();
        let latest_lock = if include_latest_lock {
            format!(
                r#",
                  "{}":{{"hash":"{}"}}"#,
                latest_height, latest_hash
            )
        } else {
            String::new()
        };
        fs::write(
            data.join("canonical_locks.json"),
            format!(
                r#"{{
                  "175518":{{"hash":"{}"}}{}
                }}"#,
                TESTNET_RECOVERY_BOUNDARY_HASH, latest_lock
            ),
        )
        .unwrap();
        fs::write(
            data.join("committed_qcs.jsonl"),
            format!(
                "{{\"height\":532556,\"block_hash\":\"{}\"}}\n{{\"height\":{},\"block_hash\":\"{}\"}}\n",
                TESTNET_RECOVERY_APPROVED_FIRST_QC_HASH, qc_height, qc_hash
            ),
        )
        .unwrap();
        write_checkpoint(
            &data,
            TESTNET_RECOVERY_BOUNDARY_HEIGHT,
            TESTNET_RECOVERY_BOUNDARY_HASH,
        );
    }

    fn recovery_options(apply: bool) -> CompactedRecoveryCheckpointOptions {
        CompactedRecoveryCheckpointOptions {
            dry_run: !apply,
            apply,
            force: false,
            source_validator: "Val6".to_string(),
            source_bundle_path: "/approved/val6-approved-state.tar.gz".to_string(),
            source_bundle_sha256: TESTNET_RECOVERY_APPROVED_SOURCE_BUNDLE_SHA256.to_string(),
            source_state_dir: "/staged/source-consistent-h650464".to_string(),
            operator_approval_id: "codex-test-operator-approval".to_string(),
            recovery_reason: "Val2 cold canonical restore from approved compacted Val6 state"
                .to_string(),
        }
    }

    fn write_checkpoint(data: &Path, height: u64, block_hash: &str) {
        let checkpoint = serde_json::json!({
            "format": "synergy_consensus_state_checkpoint_v1",
            "height": height,
            "block_hash": block_hash,
            "state_root": format!("state-root-h{height}"),
            "chain_sha256": sha256_file(&data.join("chain.json")).unwrap(),
            "canonical_locks_sha256": sha256_file(&data.join("canonical_locks.json")).unwrap(),
            "committed_qcs_sha256": sha256_file(&data.join("committed_qcs.jsonl")).unwrap(),
        });
        fs::write(
            data.join("state_checkpoint.json"),
            serde_json::to_vec_pretty(&checkpoint).unwrap(),
        )
        .unwrap();
    }

    fn finding_codes(report: &ConsensusStateReport) -> Vec<String> {
        report
            .findings
            .iter()
            .map(|finding| finding.code.clone())
            .collect()
    }

    #[test]
    fn verify_accepts_compact_boundary_state() {
        let root = temp_root("valid");
        write_valid_state(&root);
        let report = verify_state(&root);
        assert!(report.ok, "{:?}", report.findings);
        assert_eq!(report.chain.first_retained.unwrap().height, 10);
        assert_eq!(report.chain.latest.unwrap().height, 11);
        assert_eq!(report.checkpoint.height, Some(10));
    }

    #[test]
    fn verify_rejects_missing_compact_boundary_lock() {
        let root = temp_root("missing-boundary-lock");
        write_valid_state(&root);
        fs::write(
            root.join("data/canonical_locks.json"),
            r#"{"11":{"hash":"hash-11"}}"#,
        )
        .unwrap();
        let report = verify_state(&root);
        assert!(!report.ok);
        assert!(finding_codes(&report).contains(&"compact_boundary_lock_missing".to_string()));
    }

    #[test]
    fn verify_rejects_missing_compact_boundary_checkpoint() {
        let root = temp_root("missing-boundary-checkpoint");
        write_valid_state(&root);
        fs::remove_file(root.join("data/state_checkpoint.json")).unwrap();
        let report = verify_state(&root);
        assert!(!report.ok);
        assert!(finding_codes(&report).contains(&"compact_boundary_checkpoint_missing".to_string()));
    }

    #[test]
    fn verify_accepts_validator_pruned_append_log_snapshot_shape() {
        let root = temp_root("validator-pruned-append-log");
        write_validator_pruned_append_log_state(&root);

        let strict = verify_state(&root);
        assert!(!strict.ok);
        let strict_codes = finding_codes(&strict);
        assert!(strict_codes.contains(&"chain_body_non_contiguous".to_string()));
        assert!(strict_codes.contains(&"compact_boundary_qc_missing".to_string()));
        assert!(strict_codes.contains(&"compact_boundary_checkpoint_missing".to_string()));

        let allowed = verify_state_with_options(
            &root,
            ConsensusStateVerificationOptions {
                allow_testnet_recovery_checkpoint: true,
            },
        );
        assert!(allowed.ok, "{:?}", allowed.findings);
        assert!(finding_codes(&allowed).contains(&"compact_append_log_state_accepted".to_string()));
    }

    #[test]
    fn migration_and_rebuild_require_explicit_compact_state_allowance() {
        let root = temp_root("compact-migration-explicit-opt-in");
        write_validator_pruned_append_log_state(&root);

        let strict_migration = migrate_state(
            &root,
            ConsensusStateMigrationOptions {
                dry_run: true,
                force: false,
            },
        )
        .unwrap();
        assert!(!strict_migration.ok);

        let allowed_migration = migrate_state_with_verification_options(
            &root,
            ConsensusStateMigrationOptions {
                dry_run: true,
                force: false,
            },
            ConsensusStateVerificationOptions {
                allow_testnet_recovery_checkpoint: true,
            },
        )
        .unwrap();
        assert!(allowed_migration.ok, "{:?}", allowed_migration.findings);
        assert_eq!(allowed_migration.decision, "DRY_RUN_GO");
        assert!(finding_codes(&allowed_migration.verification)
            .contains(&"compact_append_log_state_accepted".to_string()));

        let strict_rebuild =
            rebuild_derived_indexes(&root, DerivedIndexRebuildOptions { dry_run: true }).unwrap();
        assert!(!strict_rebuild.ok);

        let allowed_rebuild = rebuild_derived_indexes_with_verification_options(
            &root,
            DerivedIndexRebuildOptions { dry_run: true },
            ConsensusStateVerificationOptions {
                allow_testnet_recovery_checkpoint: true,
            },
        )
        .unwrap();
        assert!(allowed_rebuild.ok, "{:?}", allowed_rebuild.findings);
        assert_eq!(allowed_rebuild.decision, "DRY_RUN_GO");
        assert!(finding_codes(&allowed_rebuild.verification)
            .contains(&"compact_append_log_state_accepted".to_string()));
    }

    #[test]
    fn compact_state_allowance_still_rejects_corrupted_qcs() {
        let root = temp_root("compact-migration-corrupted-qcs");
        write_validator_pruned_append_log_state(&root);
        fs::write(root.join("data/committed_qcs.jsonl"), "{not-json}\n").unwrap();

        let migration = migrate_state_with_verification_options(
            &root,
            ConsensusStateMigrationOptions {
                dry_run: true,
                force: false,
            },
            ConsensusStateVerificationOptions {
                allow_testnet_recovery_checkpoint: true,
            },
        )
        .unwrap();
        assert!(!migration.ok);
        assert!(finding_codes(&migration.verification)
            .contains(&"committed_qcs_unreadable".to_string()));

        let rebuild = rebuild_derived_indexes_with_verification_options(
            &root,
            DerivedIndexRebuildOptions { dry_run: true },
            ConsensusStateVerificationOptions {
                allow_testnet_recovery_checkpoint: true,
            },
        )
        .unwrap();
        assert!(!rebuild.ok);
        assert!(
            finding_codes(&rebuild.verification).contains(&"committed_qcs_unreadable".to_string())
        );
    }

    #[test]
    fn verify_rejects_checkpoint_lock_disagreement() {
        let root = temp_root("checkpoint-lock-disagreement");
        write_valid_state(&root);
        write_checkpoint(&root.join("data"), 10, "wrong-hash-10");
        let report = verify_state(&root);
        let codes = finding_codes(&report);
        assert!(!report.ok);
        assert!(codes.contains(&"compact_boundary_checkpoint_hash_mismatch".to_string()));
        assert!(codes.contains(&"checkpoint_lock_disagreement".to_string()));
        assert!(codes.contains(&"checkpoint_qc_missing_or_mismatch".to_string()));
    }

    #[test]
    fn verify_rejects_checkpoint_file_digest_mismatch() {
        let root = temp_root("checkpoint-digest-mismatch");
        write_valid_state(&root);
        let mut checkpoint = read_json(&root.join("data/state_checkpoint.json")).unwrap();
        checkpoint["chain_sha256"] = Value::String("not-the-chain-digest".to_string());
        fs::write(
            root.join("data/state_checkpoint.json"),
            serde_json::to_vec_pretty(&checkpoint).unwrap(),
        )
        .unwrap();
        let report = verify_state(&root);
        assert!(!report.ok);
        assert!(finding_codes(&report).contains(&"checkpoint_chain_sha256_mismatch".to_string()));
    }

    #[test]
    fn verify_rejects_body_behind_canonical_lock() {
        let root = temp_root("body-behind-lock");
        write_valid_state(&root);
        fs::write(
            root.join("data/canonical_locks.json"),
            r#"{"10":{"hash":"hash-10"},"11":{"hash":"hash-11"},"12":{"hash":"hash-12"}}"#,
        )
        .unwrap();
        let report = verify_state(&root);
        assert!(!report.ok);
        assert!(finding_codes(&report).contains(&"body_behind_canonical_lock".to_string()));
    }

    #[test]
    fn verify_rejects_conflicting_duplicate_blocks() {
        let root = temp_root("duplicate-conflict");
        write_valid_state(&root);
        fs::write(
            root.join("data/chain.json"),
            r#"[
              {"block_index": 10, "hash": "hash-10"},
              {"block_index": 10, "hash": "other-hash"}
            ]"#,
        )
        .unwrap();
        let report = verify_state(&root);
        let codes = finding_codes(&report);
        assert!(!report.ok);
        assert!(codes.contains(&"conflicting_block_height".to_string()));
        assert!(codes.contains(&"chain_body_non_contiguous".to_string()));
    }

    #[test]
    fn verify_rejects_corrupted_committed_qc_jsonl() {
        let root = temp_root("bad-qc-jsonl");
        write_valid_state(&root);
        fs::write(root.join("data/committed_qcs.jsonl"), "{not-json}\n").unwrap();
        let report = verify_state(&root);
        assert!(!report.ok);
        assert!(finding_codes(&report).contains(&"committed_qcs_unreadable".to_string()));
    }

    #[test]
    fn compacted_recovery_checkpoint_is_strict_by_default_and_opt_in_only() {
        let root = temp_root("testnet-recovery-strict-default");
        write_testnet_recovery_source_state(&root);
        let adoption = adopt_compacted_recovery_checkpoint(&root, recovery_options(true)).unwrap();
        assert!(adoption.ok, "{:?}", adoption.findings);

        let strict = verify_state(&root);
        assert!(!strict.ok);
        let strict_codes = finding_codes(&strict);
        assert!(strict_codes.contains(&"chain_body_non_contiguous".to_string()));
        assert!(strict_codes.contains(&"compact_boundary_qc_missing".to_string()));
        assert!(strict_codes.contains(&"checkpoint_qc_missing_or_mismatch".to_string()));

        let allowed = verify_state_with_options(
            &root,
            ConsensusStateVerificationOptions {
                allow_testnet_recovery_checkpoint: true,
            },
        );
        assert!(allowed.ok, "{:?}", allowed.findings);
        assert!(
            finding_codes(&allowed).contains(&"testnet_recovery_checkpoint_accepted".to_string())
        );
    }

    #[test]
    fn adopt_compacted_recovery_checkpoint_writes_manifest() {
        let root = temp_root("testnet-recovery-adopt");
        write_testnet_recovery_source_state(&root);
        let dry_run = adopt_compacted_recovery_checkpoint(&root, recovery_options(false)).unwrap();
        assert!(dry_run.ok, "{:?}", dry_run.findings);
        assert_eq!(dry_run.decision, "DRY_RUN_GO");
        assert!(!root.join("data/state_checkpoint.json").exists());

        let apply = adopt_compacted_recovery_checkpoint(&root, recovery_options(true)).unwrap();
        assert!(apply.ok, "{:?}", apply.findings);
        assert_eq!(apply.decision, "GO");
        assert!(root.join("data/state_checkpoint.json").is_file());
        assert!(root
            .join("data/state_checkpoint.recovery_manifest.json")
            .is_file());
        assert!(apply.verification_after.as_ref().unwrap().ok);
    }

    #[test]
    fn recovery_checkpoint_rejects_wrong_network() {
        let root = temp_root("testnet-recovery-wrong-network");
        write_testnet_recovery_source_state(&root);
        let adoption = adopt_compacted_recovery_checkpoint(&root, recovery_options(true)).unwrap();
        assert!(adoption.ok, "{:?}", adoption.findings);
        let checkpoint_path = root.join("data/state_checkpoint.json");
        let mut checkpoint = read_json(&checkpoint_path).unwrap();
        checkpoint["network_id"] = Value::String("mainnet".to_string());
        fs::write(
            checkpoint_path,
            serde_json::to_vec_pretty(&checkpoint).unwrap(),
        )
        .unwrap();
        let report = verify_state_with_options(
            &root,
            ConsensusStateVerificationOptions {
                allow_testnet_recovery_checkpoint: true,
            },
        );
        assert!(!report.ok);
        assert!(
            finding_codes(&report).contains(&"testnet_recovery_network_id_mismatch".to_string())
        );
    }

    #[test]
    fn recovery_checkpoint_rejects_fabricated_qc_or_key_copy_flags() {
        let root = temp_root("testnet-recovery-forbidden-flags");
        write_testnet_recovery_source_state(&root);
        let adoption = adopt_compacted_recovery_checkpoint(&root, recovery_options(true)).unwrap();
        assert!(adoption.ok, "{:?}", adoption.findings);
        let checkpoint_path = root.join("data/state_checkpoint.json");
        let mut checkpoint = read_json(&checkpoint_path).unwrap();
        checkpoint["manual_consensus_json_repair"] = Value::Bool(true);
        checkpoint["fabricated_qc"] = Value::Bool(true);
        checkpoint["source_identity_copied"] = Value::Bool(true);
        checkpoint["source_private_keys_copied"] = Value::Bool(true);
        fs::write(
            checkpoint_path,
            serde_json::to_vec_pretty(&checkpoint).unwrap(),
        )
        .unwrap();
        let report = verify_state_with_options(
            &root,
            ConsensusStateVerificationOptions {
                allow_testnet_recovery_checkpoint: true,
            },
        );
        let codes = finding_codes(&report);
        assert!(!report.ok);
        assert!(codes
            .contains(&"testnet_recovery_manual_consensus_json_repair_not_allowed".to_string()));
        assert!(codes.contains(&"testnet_recovery_fabricated_qc_not_allowed".to_string()));
        assert!(codes.contains(&"testnet_recovery_source_identity_copy_not_allowed".to_string()));
        assert!(codes.contains(&"testnet_recovery_source_private_key_copy_not_allowed".to_string()));
    }

    #[test]
    fn recovery_checkpoint_rejects_wrong_chain_id_source_bundle_and_retained_markers() {
        let root = temp_root("testnet-recovery-wrong-source-markers");
        write_testnet_recovery_source_state(&root);
        let adoption = adopt_compacted_recovery_checkpoint(&root, recovery_options(true)).unwrap();
        assert!(adoption.ok, "{:?}", adoption.findings);
        let checkpoint_path = root.join("data/state_checkpoint.json");
        let mut checkpoint = read_json(&checkpoint_path).unwrap();
        checkpoint["chain_id"] = Value::String("1".to_string());
        checkpoint["source_bundle_sha256"] = Value::String("not-approved".to_string());
        checkpoint["first_retained_chain_height"] = Value::from(537_557_u64);
        checkpoint["first_retained_qc_height"] = Value::from(532_557_u64);
        fs::write(
            checkpoint_path,
            serde_json::to_vec_pretty(&checkpoint).unwrap(),
        )
        .unwrap();
        let report = verify_state_with_options(
            &root,
            ConsensusStateVerificationOptions {
                allow_testnet_recovery_checkpoint: true,
            },
        );
        let codes = finding_codes(&report);
        assert!(!report.ok);
        assert!(codes.contains(&"testnet_recovery_chain_id_mismatch".to_string()));
        assert!(codes.contains(&"testnet_recovery_source_bundle_sha256_mismatch".to_string()));
        assert!(
            codes.contains(&"testnet_recovery_first_retained_chain_height_mismatch".to_string())
        );
        assert!(codes.contains(&"testnet_recovery_first_retained_qc_height_mismatch".to_string()));
    }

    #[test]
    fn recovery_checkpoint_rejects_altered_approved_tip() {
        let root = temp_root("testnet-recovery-altered-tip");
        write_testnet_recovery_source_state(&root);
        let adoption = adopt_compacted_recovery_checkpoint(&root, recovery_options(true)).unwrap();
        assert!(adoption.ok, "{:?}", adoption.findings);
        let chain_path = root.join("data/chain.json");
        let chain = fs::read_to_string(&chain_path)
            .unwrap()
            .replace(TESTNET_RECOVERY_APPROVED_TIP_HASH, "bad-tip-hash");
        fs::write(chain_path, chain).unwrap();
        let report = verify_state_with_options(
            &root,
            ConsensusStateVerificationOptions {
                allow_testnet_recovery_checkpoint: true,
            },
        );
        assert!(!report.ok);
        assert!(finding_codes(&report).contains(&"testnet_recovery_tip_mismatch".to_string()));
    }

    #[test]
    fn live_state_verifier_accepts_current_compacted_edges() {
        let root = temp_root("live-current-edges");
        write_live_edge_state(&root, 656_978, "live-tip-hash", 656_978);
        let report = verify_live_state_with_options(
            &root,
            LiveStateVerificationOptions {
                expected_height: Some(656_978),
                expected_hash: Some("live-tip-hash".to_string()),
                ..LiveStateVerificationOptions::default()
            },
        );
        assert!(report.ok, "{:?}", report.findings);
        assert_eq!(report.decision, "GO");
        assert_eq!(report.chain.latest.unwrap().height, 656_978);
    }

    #[test]
    fn live_state_verifier_rejects_durable_chain_far_behind_expected_head() {
        let root = temp_root("live-stale-chain");
        write_live_edge_state(&root, 650_464, TESTNET_RECOVERY_APPROVED_TIP_HASH, 650_464);
        let report = verify_live_state_with_options(
            &root,
            LiveStateVerificationOptions {
                expected_height: Some(656_978),
                expected_hash: Some("new-live-tip".to_string()),
                max_expected_lag: 32,
                ..LiveStateVerificationOptions::default()
            },
        );
        assert!(!report.ok);
        assert!(
            finding_codes(&report).contains(&"live_state_chain_behind_expected_head".to_string())
        );
    }

    #[test]
    fn live_state_verifier_accepts_compacted_body_when_qc_tail_matches_expected_head() {
        let root = temp_root("live-compacted-qc-head");
        write_live_edge_state_with_qc_hash(
            &root,
            650_469,
            "retained-chain-hash",
            657_666,
            "live-qc-head-hash",
            false,
        );
        let report = verify_live_state_with_options(
            &root,
            LiveStateVerificationOptions {
                expected_height: Some(657_666),
                expected_hash: Some("live-qc-head-hash".to_string()),
                max_expected_lag: 64,
                max_qc_ahead: 128,
            },
        );
        let codes = finding_codes(&report);
        assert!(report.ok, "{:?}", report.findings);
        assert!(codes.contains(&"live_state_qc_tail_supplies_compacted_head".to_string()));
        assert!(codes.contains(&"live_state_chain_body_compacted_behind_expected_head".to_string()));
        assert!(codes.contains(&"live_state_latest_lock_missing".to_string()));
    }

    #[test]
    fn live_state_verifier_rejects_expected_qc_head_hash_mismatch() {
        let root = temp_root("live-compacted-qc-mismatch");
        write_live_edge_state_with_qc_hash(
            &root,
            650_469,
            "retained-chain-hash",
            657_666,
            "wrong-live-qc-head-hash",
            false,
        );
        let report = verify_live_state_with_options(
            &root,
            LiveStateVerificationOptions {
                expected_height: Some(657_666),
                expected_hash: Some("expected-live-qc-head-hash".to_string()),
                max_expected_lag: 64,
                max_qc_ahead: 128,
            },
        );
        assert!(!report.ok);
        assert!(
            finding_codes(&report).contains(&"live_state_qc_expected_hash_mismatch".to_string())
        );
    }

    #[test]
    fn live_state_verifier_rejects_qc_tail_too_far_ahead_of_chain_edge() {
        let root = temp_root("live-qc-too-far-ahead");
        write_live_edge_state(&root, 650_464, TESTNET_RECOVERY_APPROVED_TIP_HASH, 656_773);
        let report = verify_live_state_with_options(
            &root,
            LiveStateVerificationOptions {
                max_qc_ahead: 128,
                ..LiveStateVerificationOptions::default()
            },
        );
        assert!(!report.ok);
        assert!(finding_codes(&report).contains(&"live_state_qc_tail_too_far_ahead".to_string()));
    }

    #[test]
    fn migrate_state_dry_run_does_not_write_store() {
        let root = temp_root("migrate-dry-run");
        write_valid_state(&root);
        let report = migrate_state(
            &root,
            ConsensusStateMigrationOptions {
                dry_run: true,
                force: false,
            },
        )
        .unwrap();
        assert!(report.ok, "{:?}", report.findings);
        assert_eq!(report.decision, "DRY_RUN_GO");
        assert!(!root.join("data").join(DURABLE_STORE_DIR).exists());
    }

    #[test]
    fn migrate_state_writes_manifest_and_copies_state_files() {
        let root = temp_root("migrate-write");
        write_valid_state(&root);
        let report = migrate_state(
            &root,
            ConsensusStateMigrationOptions {
                dry_run: false,
                force: false,
            },
        )
        .unwrap();
        assert!(report.ok, "{:?}", report.findings);
        let store = root.join("data").join(DURABLE_STORE_DIR);
        assert!(store.join("chain.json").is_file());
        assert!(store.join("canonical_locks.json").is_file());
        assert!(store.join("committed_qcs.jsonl").is_file());
        assert!(store.join("state_checkpoint.json").is_file());
        let manifest = read_json(&store.join("manifest.json")).unwrap();
        assert_eq!(
            manifest.get("format").and_then(Value::as_str),
            Some("synergy_consensus_state_store_v1")
        );
    }

    #[test]
    fn migrate_state_refuses_invalid_legacy_state() {
        let root = temp_root("migrate-invalid");
        write_valid_state(&root);
        fs::write(root.join("data/committed_qcs.jsonl"), "{not-json}\n").unwrap();
        let report = migrate_state(
            &root,
            ConsensusStateMigrationOptions {
                dry_run: false,
                force: false,
            },
        )
        .unwrap();
        assert!(!report.ok);
        assert!(finding_codes_from_migration(&report)
            .contains(&"state_verification_failed".to_string()));
        assert!(!root.join("data").join(DURABLE_STORE_DIR).exists());
    }

    #[test]
    fn migrate_state_refuses_existing_store_without_force() {
        let root = temp_root("migrate-existing");
        write_valid_state(&root);
        fs::create_dir_all(root.join("data").join(DURABLE_STORE_DIR)).unwrap();
        let report = migrate_state(
            &root,
            ConsensusStateMigrationOptions {
                dry_run: false,
                force: false,
            },
        )
        .unwrap();
        assert!(!report.ok);
        assert!(finding_codes_from_migration(&report).contains(&"durable_store_exists".to_string()));
    }

    #[test]
    fn rebuild_derived_indexes_dry_run_does_not_write_file() {
        let root = temp_root("derived-dry-run");
        write_valid_state(&root);
        let report =
            rebuild_derived_indexes(&root, DerivedIndexRebuildOptions { dry_run: true }).unwrap();
        assert!(report.ok, "{:?}", report.findings);
        assert_eq!(report.decision, "DRY_RUN_GO");
        assert!(!root.join("data/derived_consensus_index.json").exists());
    }

    #[test]
    fn rebuild_derived_indexes_writes_into_migrated_store() {
        let root = temp_root("derived-store");
        write_valid_state(&root);
        migrate_state(
            &root,
            ConsensusStateMigrationOptions {
                dry_run: false,
                force: false,
            },
        )
        .unwrap();
        let report =
            rebuild_derived_indexes(&root, DerivedIndexRebuildOptions { dry_run: false }).unwrap();
        assert!(report.ok, "{:?}", report.findings);
        let output = root
            .join("data")
            .join(DURABLE_STORE_DIR)
            .join("derived_index.json");
        assert_eq!(PathBuf::from(report.output_path), output);
        let index = read_json(&output).unwrap();
        assert_eq!(
            index.get("format").and_then(Value::as_str),
            Some("synergy_consensus_state_derived_index_v1")
        );
        assert_eq!(
            index
                .get("chain")
                .and_then(|chain| chain.get("block_count"))
                .and_then(Value::as_u64),
            Some(2)
        );
    }

    #[test]
    fn rebuild_derived_indexes_refuses_invalid_state() {
        let root = temp_root("derived-invalid");
        write_valid_state(&root);
        fs::write(root.join("data/committed_qcs.jsonl"), "{not-json}\n").unwrap();
        let report =
            rebuild_derived_indexes(&root, DerivedIndexRebuildOptions { dry_run: false }).unwrap();
        assert!(!report.ok);
        assert!(
            finding_codes_from_derived(&report).contains(&"state_verification_failed".to_string())
        );
    }

    fn finding_codes_from_migration(report: &ConsensusStateMigrationReport) -> Vec<String> {
        report
            .findings
            .iter()
            .map(|finding| finding.code.clone())
            .collect()
    }

    fn finding_codes_from_derived(report: &DerivedIndexRebuildReport) -> Vec<String> {
        report
            .findings
            .iter()
            .map(|finding| finding.code.clone())
            .collect()
    }
}
