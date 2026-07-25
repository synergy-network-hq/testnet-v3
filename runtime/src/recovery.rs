use crate::block::Block;
use crate::consensus::consensus_fork::{
    self, normalize_consensus_key_algorithm, parse_consensus_public_key_material,
};
use crate::consensus::dual_quorum::{
    required_validator_quorum, DualQuorumConsensus, QuorumCertificate,
};
use crate::consensus::validator_keys::{
    parse_validator_public_key, parse_validator_public_key_with_declared_algorithm,
};
use crate::crypto::aegis_pqvm::{AegisPqvmKeyRegistry, AegisPqvmVerifier};
use crate::crypto::pqc::{PQCAlgorithm, PQCManager, PQCPublicKey, PQCSignature};
#[cfg(not(test))]
use crate::genesis::canonical_genesis;
use crate::synergy_types::{
    AegisPqKeyRole, ClusterMap, QuorumCertificate as AegisQuorumCertificate, ValidatorSet,
    ValidatorStatus, SYNERGY_TESTNET_V3_CHAIN_ID, SYNERGY_TESTNET_V3_NETWORK_ID,
};
use crate::validator::{ValidatorManager, VALIDATOR_SHADOW_PHASE_BLOCKS};
use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use sha3::{Digest, Sha3_256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub const EXPECTED_GENESIS_HASH: &str =
    "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789";
pub const BASELINE_VALIDATOR_COUNT: usize = 5;
const ALLOWED_STATE_FILES: &[&str] = &[
    "chain.json",
    "canonical_locks.json",
    "committed_qcs.json",
    "committed_qcs.jsonl",
    "dag_state.json",
    "validator_registry.json",
    "token_state.json",
    "synid_registry.json",
];

const FILES_NEVER_TO_TOUCH: &[&str] = &[
    "config/",
    "node.env",
    ".env",
    "validator.key",
    "private.key",
    "private_key",
    "consensus.private.key",
    "consensus_private.key",
    "identity",
    "wireguard",
    "wg0",
    "tls",
    "credential",
    "spreadsheet",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TargetRole {
    Validator,
    Relayer,
    Rpc,
    Archive,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryType {
    NoAction,
    TransientCachePrune,
    CanonicalStateReconcile,
    SupportChainFastSync,
    ArchiveSnapshotRestore,
    UnsafeRequiresOperatorApproval,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryPlan {
    pub plan_id: String,
    pub created_at: String,
    pub target_node_id: String,
    pub target_role: TargetRole,
    pub chain_id: u64,
    pub network_id: String,
    pub genesis_hash: String,
    pub target_current_height: u64,
    pub target_current_hash: String,
    pub target_canonical_lock_height: u64,
    pub target_canonical_lock_hash: String,
    pub target_runtime_sha256: String,
    pub source_nodes_used: Vec<String>,
    pub source_common_height: u64,
    pub source_common_hash: String,
    pub source_canonical_lock_height: u64,
    pub source_canonical_lock_hash: String,
    pub source_committed_qc_height: u64,
    pub source_committed_qc_hash: String,
    pub source_qc_vote_count: u64,
    pub source_qc_signers: Vec<String>,
    pub source_active_validator_count: usize,
    pub source_required_quorum: usize,
    pub source_qc_aegis_pqc_verified: bool,
    pub majority_branch_proven: bool,
    pub target_is_minority_or_lagged: bool,
    pub recovery_type: RecoveryType,
    pub files_to_read: Vec<String>,
    pub files_to_backup: Vec<String>,
    pub files_to_mutate: Vec<String>,
    pub files_never_to_touch: Vec<String>,
    pub keys_or_configs_copied: bool,
    pub canonical_locks_mutated: bool,
    pub committed_qcs_mutated: bool,
    pub chain_state_mutated: bool,
    pub dag_state_mutated: bool,
    pub registry_state_mutated: bool,
    pub token_state_mutated: bool,
    pub evidence_path: String,
    pub rollback_path: String,
    pub preconditions: Vec<String>,
    pub postconditions: Vec<String>,
    pub failure_reason: Option<String>,
    pub operator_approval_required: bool,
}

#[derive(Debug, Clone)]
pub struct BuildPlanInput {
    pub target_node_id: String,
    pub target_role: TargetRole,
    pub chain_id: u64,
    pub network_id: String,
    pub genesis_hash: String,
    pub target_data_dir: PathBuf,
    pub source_state_dir: Option<PathBuf>,
    pub source_evidence_dirs: Vec<PathBuf>,
    pub source_nodes_used: Vec<String>,
    pub source_common_height: Option<u64>,
    pub source_common_hash: Option<String>,
    pub source_canonical_lock_height: Option<u64>,
    pub source_canonical_lock_hash: Option<String>,
    pub target_runtime_sha256: String,
    pub evidence_path: PathBuf,
    pub rollback_path: PathBuf,
    pub recovery_type: Option<RecoveryType>,
    pub conflict_height: Option<u64>,
    pub expected_target_conflict_hash: Option<String>,
    pub expected_source_conflict_hash: Option<String>,
    pub target_stopped_or_quarantined: bool,
}

#[derive(Debug, Clone)]
pub struct ApplyPlanInput {
    pub plan_path: PathBuf,
    pub confirm_target_stopped: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryVerification {
    pub valid_for_apply: bool,
    pub fail_closed: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub mutation_flags: MutationFlags,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MutationFlags {
    pub keys_or_configs_copied: bool,
    pub canonical_locks_mutated: bool,
    pub committed_qcs_mutated: bool,
    pub chain_state_mutated: bool,
    pub dag_state_mutated: bool,
    pub registry_state_mutated: bool,
    pub token_state_mutated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyPlanResult {
    pub plan_id: String,
    pub applied: bool,
    pub fail_closed: bool,
    pub evidence_path: String,
    pub rollback_path: String,
    pub files_backed_up: Vec<String>,
    pub files_mutated: Vec<String>,
    pub mutation_flags: MutationFlags,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RecoveryProof {
    #[serde(default)]
    chain_id: u64,
    #[serde(default)]
    network_id: String,
    #[serde(default)]
    genesis_hash: String,
    #[serde(default)]
    source_nodes_used: Vec<String>,
    #[serde(default)]
    source_common_height: u64,
    #[serde(default)]
    source_common_hash: String,
    #[serde(default)]
    source_canonical_lock_height: u64,
    #[serde(default)]
    source_canonical_lock_hash: String,
    qc: AegisQuorumCertificate,
    validator_set: ValidatorSet,
    cluster_map: ClusterMap,
}

#[derive(Debug, Clone)]
pub struct QcProofSummary {
    pub height: u64,
    pub hash: String,
    pub vote_count: u64,
    pub signers: Vec<String>,
    pub active_validator_count: usize,
    pub required_quorum: usize,
    pub verified: bool,
    pub failure: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct LegacyCommittedQcLogEntry {
    #[allow(dead_code)]
    block_hash: String,
    qc: LegacyQuorumCertificate,
}

#[derive(Debug, Clone, Deserialize)]
struct LegacyQuorumCertificate {
    block_hash: String,
    epoch_number: u64,
    round_number: u64,
    aggregate_signature: Vec<u8>,
    participant_bitmap: Vec<u8>,
    cumulative_weight: f64,
    validation_quorum_met: bool,
    cooperation_quorum_met: bool,
    votes: Vec<LegacyVote>,
}

#[derive(Debug, Clone, Deserialize)]
struct LegacyVote {
    validator_address: String,
    block_hash: String,
    block_index: u64,
    epoch_number: u64,
    round_number: u64,
    signature: PQCSignature,
    signer_public_key: Vec<u8>,
}

#[derive(Debug, Clone)]
struct LegacyValidator {
    public_key: PQCPublicKey,
}

pub const MISSING_QC_OFFLINE_MARKER: &str = "STATE_SYNC_OFFLINE_WORKSPACE";

#[derive(Debug, Clone)]
pub struct MissingQcRepairOptions {
    pub state_root: PathBuf,
    pub expected_height: u64,
    pub expected_qc_sha256: String,
    pub source_qc_paths: Vec<PathBuf>,
    pub source_nodes: Vec<String>,
    pub block_path: PathBuf,
    pub dry_run: bool,
    pub apply: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissingQcRepairReport {
    pub ok: bool,
    pub decision: String,
    pub dry_run: bool,
    pub applied: bool,
    pub state_root: String,
    pub data_dir: String,
    pub expected_height: u64,
    pub block_hash: String,
    pub source_qc_sha256: String,
    pub source_nodes: Vec<String>,
    pub verified_qc_signers: Vec<String>,
    pub original_qc_count: u64,
    pub repaired_qc_count: u64,
    pub original_qcs_sha256: String,
    pub repaired_qcs_sha256: String,
    pub backup_path: Option<String>,
    pub receipt_path: Option<String>,
    pub verification_after: Option<crate::consensus_state::ConsensusStateReport>,
    pub actions: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct VerifiedCommittedQcLogEntry {
    block_hash: String,
    qc: QuorumCertificate,
}

#[derive(Debug)]
struct QcRewriteSummary {
    original_count: u64,
    original_sha256: String,
    repaired_sha256: String,
    previous_hash: String,
    next_hash: String,
}

pub fn status() -> Value {
    json!({
        "status": "idle",
        "fail_closed": true,
        "commands": [
            "recovery inspect-divergence",
            "recovery build-plan",
            "recovery verify-plan",
            "recovery apply-plan",
            "recovery status"
        ],
        "chain_id": SYNERGY_TESTNET_V3_CHAIN_ID,
        "network_id": SYNERGY_TESTNET_V3_NETWORK_ID,
        "genesis_hash": EXPECTED_GENESIS_HASH,
        "quorum": {
            "policy": "ceil(active_validator_count * 2 / 3)",
            "genesis_baseline_required": required_validator_quorum(BASELINE_VALIDATOR_COUNT),
            "baseline_validators": BASELINE_VALIDATOR_COUNT,
            "relayers_rpc_archive_count_toward_quorum": false
        },
        "mutation_policy": {
            "preserve_evidence_before_mutation": true,
            "copy_keys": false,
            "copy_configs": false,
            "lower_quorum": false,
            "require_aegis_pqvm_qc": true
        }
    })
}

pub fn repair_missing_committed_qc(
    options: MissingQcRepairOptions,
) -> Result<MissingQcRepairReport, String> {
    if options.dry_run == options.apply {
        return Err("repair-missing-qc requires exactly one of --dry-run or --apply".to_string());
    }
    if options.expected_height == 0 {
        return Err("repair-missing-qc expected height must be greater than zero".to_string());
    }
    if options.source_qc_paths.len() < 2 {
        return Err(
            "repair-missing-qc requires at least two independently collected --source-qc files"
                .to_string(),
        );
    }
    if options.source_qc_paths.len() != options.source_nodes.len() {
        return Err(
            "repair-missing-qc requires one distinct --source-node for each --source-qc"
                .to_string(),
        );
    }
    let source_nodes = distinct_nonempty_values(&options.source_nodes, "source node")?;
    if source_nodes.len() != options.source_nodes.len() {
        return Err("repair-missing-qc source nodes must be distinct".to_string());
    }

    let state_root = workspace_root(&options.state_root);
    let data_dir = data_dir(&options.state_root);
    let offline_marker = state_root.join(MISSING_QC_OFFLINE_MARKER);
    if !offline_marker.is_file() {
        return Err(format!(
            "repair-missing-qc requires the stopped-validator marker {}",
            offline_marker.display()
        ));
    }

    let expected_qc_sha256 = options.expected_qc_sha256.trim().to_ascii_lowercase();
    if expected_qc_sha256.len() != 64
        || !expected_qc_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("repair-missing-qc expected QC sha256 must be 64 hex characters".to_string());
    }

    let canonical_sources = options
        .source_qc_paths
        .iter()
        .map(|path| {
            fs::canonicalize(path)
                .map_err(|error| format!("canonicalize source QC {}: {error}", path.display()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut distinct_sources = BTreeSet::new();
    for path in &canonical_sources {
        if !distinct_sources.insert(path.clone()) {
            return Err("repair-missing-qc source QC paths must be distinct".to_string());
        }
    }

    let source_qc_bytes = fs::read(&canonical_sources[0])
        .map_err(|error| format!("read source QC {}: {error}", canonical_sources[0].display()))?;
    let source_line = normalized_single_jsonl_line(&source_qc_bytes)?;
    let source_digest = sha256_bytes(&source_qc_bytes);
    if source_digest != expected_qc_sha256 {
        return Err(format!(
            "source QC sha256 {source_digest} does not match expected {expected_qc_sha256}"
        ));
    }
    for path in canonical_sources.iter().skip(1) {
        let bytes = fs::read(path)
            .map_err(|error| format!("read source QC {}: {error}", path.display()))?;
        let digest = sha256_bytes(&bytes);
        if digest != expected_qc_sha256 || bytes != source_qc_bytes {
            return Err(format!(
                "source QC {} is not byte-identical to the independently verified digest {}",
                path.display(),
                expected_qc_sha256
            ));
        }
    }

    let verified_entry: VerifiedCommittedQcLogEntry =
        serde_json::from_slice(source_line.strip_suffix(b"\n").unwrap_or(&source_line))
            .map_err(|error| format!("parse source committed QC: {error}"))?;
    let legacy_entry: LegacyCommittedQcLogEntry =
        serde_json::from_slice(source_line.strip_suffix(b"\n").unwrap_or(&source_line))
            .map_err(|error| format!("parse source legacy committed QC: {error}"))?;
    let qc_height = legacy_qc_height(&legacy_entry.qc)?;
    if qc_height != options.expected_height {
        return Err(format!(
            "source QC height {qc_height} does not match expected height {}",
            options.expected_height
        ));
    }
    if verified_entry.block_hash != verified_entry.qc.block_hash
        || legacy_entry.block_hash != legacy_entry.qc.block_hash
    {
        return Err("source QC wrapper block hash does not match the certificate".to_string());
    }

    let supplied_block = read_repair_block(&options.block_path)?;
    if supplied_block.block_index != options.expected_height {
        return Err(format!(
            "repair block height {} does not match expected height {}",
            supplied_block.block_index, options.expected_height
        ));
    }
    if supplied_block.hash != verified_entry.qc.block_hash {
        return Err("repair block hash does not match source QC block hash".to_string());
    }
    let (previous_block, local_block, next_block) =
        read_local_block_triplet(&data_dir, options.expected_height)?;
    if local_block.hash != supplied_block.hash {
        return Err(format!(
            "local committed block h{} hash {} does not match supplied block hash {}",
            options.expected_height, local_block.hash, supplied_block.hash
        ));
    }
    if local_block.previous_hash != previous_block.hash
        || supplied_block.previous_hash != previous_block.hash
    {
        return Err("repair block does not extend the exact local previous block".to_string());
    }
    if next_block.previous_hash != supplied_block.hash {
        return Err("local next block does not extend the repair block".to_string());
    }
    let mut retained_lock_count = 0usize;
    for block in [&previous_block, &local_block, &next_block] {
        if let Some(lock) = read_canonical_lock_hash_at(&data_dir, block.block_index) {
            retained_lock_count += 1;
            if lock != block.hash {
                return Err(format!(
                    "retained canonical lock h{} hash {} does not match local block hash {}",
                    block.block_index, lock, block.hash
                ));
            }
        }
    }

    supplied_block.verify_proposer_signature()?;
    let validator_manager = Arc::new(ValidatorManager::new());
    let validator_registry_path = data_dir.join("validator_registry.json");
    validator_manager
        .load_registry(
            validator_registry_path
                .to_str()
                .ok_or_else(|| "validator registry path is not UTF-8".to_string())?,
        )
        .map_err(|error| format!("load canonical validator registry: {error}"))?;
    DualQuorumConsensus::verify_commit_certificate_for_block_static(
        &supplied_block,
        &verified_entry.qc,
        &validator_manager,
    )?;
    let qc_proof = verify_legacy_qc(&data_dir, legacy_entry.qc)?;
    if !qc_proof.verified || qc_proof.hash != supplied_block.hash {
        return Err("source QC did not pass canonical legacy Aegis verification".to_string());
    }

    let qcs_path = data_dir.join("committed_qcs.jsonl");
    let before_metadata =
        fs::metadata(&qcs_path).map_err(|error| format!("stat {}: {error}", qcs_path.display()))?;
    let temp_path = qcs_path.with_extension(format!(
        "jsonl.qc-repair-{}-{}.tmp",
        options.expected_height,
        std::process::id()
    ));
    let rewrite = match scan_and_rewrite_missing_qc(
        &qcs_path,
        options.expected_height,
        &source_line,
        options.apply.then_some(temp_path.as_path()),
    ) {
        Ok(summary) => summary,
        Err(error) => {
            let _ = fs::remove_file(&temp_path);
            return Err(error);
        }
    };
    if rewrite.previous_hash != previous_block.hash {
        let _ = fs::remove_file(&temp_path);
        return Err(format!(
            "committed QC h{} hash {} does not match the local previous block hash {}",
            options.expected_height - 1,
            rewrite.previous_hash,
            previous_block.hash
        ));
    }
    if rewrite.next_hash != next_block.hash {
        let _ = fs::remove_file(&temp_path);
        return Err(format!(
            "committed QC h{} hash {} does not match the local next block hash {}",
            options.expected_height + 1,
            rewrite.next_hash,
            next_block.hash
        ));
    }
    let after_scan_metadata = fs::metadata(&qcs_path)
        .map_err(|error| format!("restat {}: {error}", qcs_path.display()))?;
    if before_metadata.len() != after_scan_metadata.len()
        || before_metadata.modified().ok() != after_scan_metadata.modified().ok()
    {
        let _ = fs::remove_file(&temp_path);
        return Err(
            "committed QC log changed during repair validation; validator is not safely offline"
                .to_string(),
        );
    }

    let actions = vec![
        format!(
            "verified exact internal QC gap at h{}",
            options.expected_height
        ),
        format!(
            "verified {} byte-identical source copies with sha256 {}",
            canonical_sources.len(),
            expected_qc_sha256
        ),
        format!(
            "verified local block/QC parent-child continuity and rejected conflicts across {} retained historical lock(s)",
            retained_lock_count
        ),
        "verified proposer signature and all QC Aegis vote signatures against canonical membership"
            .to_string(),
        "prepared atomic committed_qcs.jsonl replacement with rollback evidence".to_string(),
    ];

    if options.dry_run {
        return Ok(MissingQcRepairReport {
            ok: true,
            decision: "GO".to_string(),
            dry_run: true,
            applied: false,
            state_root: state_root.display().to_string(),
            data_dir: data_dir.display().to_string(),
            expected_height: options.expected_height,
            block_hash: supplied_block.hash,
            source_qc_sha256: expected_qc_sha256,
            source_nodes,
            verified_qc_signers: qc_proof.signers,
            original_qc_count: rewrite.original_count,
            repaired_qc_count: rewrite.original_count + 1,
            original_qcs_sha256: rewrite.original_sha256,
            repaired_qcs_sha256: rewrite.repaired_sha256,
            backup_path: None,
            receipt_path: None,
            verification_after: None,
            actions,
        });
    }

    let timestamp = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let backup_dir = state_root.join("evidence").join(format!(
        "missing-qc-{}-{timestamp}",
        options.expected_height
    ));
    fs::create_dir_all(&backup_dir)
        .map_err(|error| format!("create repair evidence {}: {error}", backup_dir.display()))?;
    let backup_qcs = backup_dir.join("committed_qcs.before.jsonl");
    fs::hard_link(&qcs_path, &backup_qcs)
        .or_else(|_| {
            fs::copy(&qcs_path, &backup_qcs)
                .map(|_| ())
                .map_err(|error| error)
        })
        .map_err(|error| format!("preserve committed QC rollback copy: {error}"))?;
    fs::copy(&options.block_path, backup_dir.join("block.json"))
        .map_err(|error| format!("preserve repair block evidence: {error}"))?;
    for (index, source) in canonical_sources.iter().enumerate() {
        fs::copy(
            source,
            backup_dir.join(format!("source-qc-{}.json", index + 1)),
        )
        .map_err(|error| format!("preserve source QC evidence: {error}"))?;
    }

    fs::set_permissions(&temp_path, before_metadata.permissions())
        .map_err(|error| format!("set repaired QC permissions: {error}"))?;
    fs::rename(&temp_path, &qcs_path)
        .map_err(|error| format!("atomically replace committed QC log: {error}"))?;
    if let Err(error) = sync_parent_directory(&qcs_path) {
        return Err(rollback_missing_qc_repair(
            &qcs_path,
            &backup_qcs,
            &backup_dir,
            format!("repaired QC directory sync failed: {error}"),
        ));
    }

    let verification_after = crate::consensus_state::verify_state_with_options(
        &state_root,
        crate::consensus_state::ConsensusStateVerificationOptions {
            allow_testnet_recovery_checkpoint: true,
        },
    );
    if !verification_after.ok {
        return Err(rollback_missing_qc_repair(
            &qcs_path,
            &backup_qcs,
            &backup_dir,
            "repaired committed QC log failed full state verification".to_string(),
        ));
    }

    let receipt_path = backup_dir.join("repair-receipt.json");
    let mut report = MissingQcRepairReport {
        ok: true,
        decision: "GO".to_string(),
        dry_run: false,
        applied: true,
        state_root: state_root.display().to_string(),
        data_dir: data_dir.display().to_string(),
        expected_height: options.expected_height,
        block_hash: supplied_block.hash,
        source_qc_sha256: expected_qc_sha256,
        source_nodes,
        verified_qc_signers: qc_proof.signers,
        original_qc_count: rewrite.original_count,
        repaired_qc_count: rewrite.original_count + 1,
        original_qcs_sha256: rewrite.original_sha256,
        repaired_qcs_sha256: rewrite.repaired_sha256,
        backup_path: Some(backup_qcs.display().to_string()),
        receipt_path: Some(receipt_path.display().to_string()),
        verification_after: Some(verification_after),
        actions,
    };
    if let Err(error) = crate::consensus::self_realign::write_json_atomic(&receipt_path, &report) {
        let _ = fs::remove_file(receipt_path.with_extension("json.tmp"));
        return Err(rollback_missing_qc_repair(
            &qcs_path,
            &backup_qcs,
            &backup_dir,
            format!("write repair receipt {}: {error}", receipt_path.display()),
        ));
    }
    if let Err(error) = sync_parent_directory(&receipt_path) {
        let _ = fs::remove_file(&receipt_path);
        return Err(rollback_missing_qc_repair(
            &qcs_path,
            &backup_qcs,
            &backup_dir,
            format!("sync repair receipt {}: {error}", receipt_path.display()),
        ));
    }
    report.receipt_path = Some(receipt_path.display().to_string());
    Ok(report)
}

fn rollback_missing_qc_repair(
    qcs_path: &Path,
    backup_qcs: &Path,
    backup_dir: &Path,
    cause: String,
) -> String {
    let rejected = backup_dir.join("committed_qcs.rejected.jsonl");
    let _ = fs::copy(qcs_path, &rejected);
    let rollback_path = qcs_path.with_extension(format!(
        "jsonl.qc-repair-rollback-{}.tmp",
        std::process::id()
    ));
    let rollback_result = (|| -> Result<(), String> {
        let _ = fs::remove_file(&rollback_path);
        fs::copy(backup_qcs, &rollback_path)
            .map_err(|error| format!("stage committed QC rollback copy: {error}"))?;
        let backup_metadata = fs::metadata(backup_qcs)
            .map_err(|error| format!("stat committed QC rollback copy: {error}"))?;
        fs::set_permissions(&rollback_path, backup_metadata.permissions())
            .map_err(|error| format!("set committed QC rollback permissions: {error}"))?;
        fs::File::open(&rollback_path)
            .and_then(|file| file.sync_all())
            .map_err(|error| format!("sync committed QC rollback copy: {error}"))?;
        fs::rename(&rollback_path, qcs_path)
            .map_err(|error| format!("atomically restore committed QC rollback copy: {error}"))?;
        sync_parent_directory(qcs_path)
    })();
    let _ = fs::remove_file(&rollback_path);

    match rollback_result {
        Ok(()) => format!(
            "{cause}; committed QC log was rolled back; evidence: {}",
            backup_dir.display()
        ),
        Err(rollback_error) => format!(
            "{cause}; CRITICAL: committed QC rollback failed: {rollback_error}; restore manually from {}",
            backup_qcs.display()
        ),
    }
}

fn workspace_root(state_root: &Path) -> PathBuf {
    if state_root.join("data").is_dir() {
        state_root.to_path_buf()
    } else if state_root.file_name().and_then(|name| name.to_str()) == Some("data") {
        state_root
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| state_root.to_path_buf())
    } else {
        state_root.to_path_buf()
    }
}

fn distinct_nonempty_values(values: &[String], label: &str) -> Result<Vec<String>, String> {
    let mut distinct = BTreeSet::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(format!("repair-missing-qc {label} cannot be empty"));
        }
        distinct.insert(trimmed.to_string());
    }
    Ok(distinct.into_iter().collect())
}

fn normalized_single_jsonl_line(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let nonempty = bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.iter().all(|byte| byte.is_ascii_whitespace()))
        .collect::<Vec<_>>();
    if nonempty.len() != 1 {
        return Err("source QC file must contain exactly one non-empty JSONL entry".to_string());
    }
    serde_json::from_slice::<Value>(nonempty[0])
        .map_err(|error| format!("parse source QC JSONL entry: {error}"))?;
    let mut line = nonempty[0].to_vec();
    line.push(b'\n');
    Ok(line)
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn read_repair_block(path: &Path) -> Result<Block, String> {
    let value = read_json(path)?;
    let block = value.get("block").unwrap_or(&value).clone();
    serde_json::from_value(block)
        .map_err(|error| format!("parse repair block {}: {error}", path.display()))
}

fn read_local_block_triplet(
    data_dir: &Path,
    expected_height: u64,
) -> Result<(Block, Block, Block), String> {
    let path = data_dir.join("committed_blocks.jsonl");
    let file =
        fs::File::open(&path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let mut reader = BufReader::with_capacity(1024 * 1024, file);
    let mut line = Vec::new();
    let mut previous = None;
    let mut target = None;
    let mut next = None;
    loop {
        line.clear();
        let read = reader
            .read_until(b'\n', &mut line)
            .map_err(|error| format!("read {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        if line.iter().all(|byte| byte.is_ascii_whitespace()) {
            continue;
        }
        let value: Value = serde_json::from_slice(&line)
            .map_err(|error| format!("parse committed block entry: {error}"))?;
        let block_value = value.get("block").unwrap_or(&value);
        let height = get_u64(block_value, &["height", "block_height", "block_index"])
            .ok_or_else(|| "committed block entry is missing height".to_string())?;
        if height + 1 < expected_height {
            continue;
        }
        if height > expected_height + 1 {
            break;
        }
        let block: Block = serde_json::from_value(block_value.clone())
            .map_err(|error| format!("parse committed block h{height}: {error}"))?;
        match height.cmp(&expected_height) {
            std::cmp::Ordering::Less if height + 1 == expected_height => previous = Some(block),
            std::cmp::Ordering::Equal => target = Some(block),
            std::cmp::Ordering::Greater if height == expected_height + 1 => next = Some(block),
            _ => {}
        }
    }
    Ok((
        previous
            .ok_or_else(|| format!("local committed block h{} is missing", expected_height - 1))?,
        target.ok_or_else(|| format!("local committed block h{expected_height} is missing"))?,
        next.ok_or_else(|| format!("local committed block h{} is missing", expected_height + 1))?,
    ))
}

fn scan_and_rewrite_missing_qc(
    qcs_path: &Path,
    expected_height: u64,
    source_line: &[u8],
    temp_path: Option<&Path>,
) -> Result<QcRewriteSummary, String> {
    let file = fs::File::open(qcs_path)
        .map_err(|error| format!("open {}: {error}", qcs_path.display()))?;
    let mut reader = BufReader::with_capacity(1024 * 1024, file);
    let mut writer = match temp_path {
        Some(path) => Some(BufWriter::with_capacity(
            1024 * 1024,
            fs::File::create(path)
                .map_err(|error| format!("create repaired QC log {}: {error}", path.display()))?,
        )),
        None => None,
    };
    let mut original_hasher = Sha256::new();
    let mut repaired_hasher = Sha256::new();
    let mut previous_height = None;
    let mut previous_hash = None;
    let mut gap_previous_hash = None;
    let mut gap_next_hash = None;
    let mut gap_found = false;
    let mut count = 0u64;
    let mut line = Vec::new();
    loop {
        line.clear();
        let read = reader
            .read_until(b'\n', &mut line)
            .map_err(|error| format!("read {}: {error}", qcs_path.display()))?;
        if read == 0 {
            break;
        }
        if line.iter().all(|byte| byte.is_ascii_whitespace()) {
            return Err("committed QC log contains an empty line".to_string());
        }
        original_hasher.update(&line);
        let value: Value = serde_json::from_slice(&line)
            .map_err(|error| format!("parse committed QC line {}: {error}", count + 1))?;
        let summary = committed_qc_summary_from_value(&value).ok_or_else(|| {
            format!(
                "committed QC line {} is missing an exact height or block hash",
                count + 1
            )
        })?;
        if summary.height == expected_height {
            return Err(format!(
                "committed QC h{expected_height} already exists; refusing duplicate repair"
            ));
        }
        if let Some(previous) = previous_height {
            if summary.height <= previous {
                return Err(format!(
                    "committed QC log is duplicate or reordered: h{previous} followed by h{}",
                    summary.height
                ));
            }
            if summary.height != previous + 1 {
                if !gap_found
                    && previous + 1 == expected_height
                    && summary.height == expected_height + 1
                {
                    gap_previous_hash = previous_hash.clone();
                    gap_next_hash = Some(summary.hash.clone());
                    repaired_hasher.update(source_line);
                    if let Some(writer) = writer.as_mut() {
                        writer
                            .write_all(source_line)
                            .map_err(|error| format!("write repaired QC entry: {error}"))?;
                    }
                    gap_found = true;
                } else {
                    return Err(format!(
                        "committed QC log has an unexpected gap: h{previous} followed by h{}",
                        summary.height
                    ));
                }
            }
        }
        repaired_hasher.update(&line);
        if let Some(writer) = writer.as_mut() {
            writer
                .write_all(&line)
                .map_err(|error| format!("write repaired QC log: {error}"))?;
        }
        previous_height = Some(summary.height);
        previous_hash = Some(summary.hash);
        count += 1;
    }
    if !gap_found {
        return Err(format!(
            "committed QC log does not contain the exact internal h{expected_height} gap"
        ));
    }
    if let Some(writer) = writer.as_mut() {
        writer
            .flush()
            .map_err(|error| format!("flush repaired QC log: {error}"))?;
        writer
            .get_ref()
            .sync_all()
            .map_err(|error| format!("sync repaired QC log: {error}"))?;
    }
    Ok(QcRewriteSummary {
        original_count: count,
        original_sha256: hex::encode(original_hasher.finalize()),
        repaired_sha256: hex::encode(repaired_hasher.finalize()),
        previous_hash: gap_previous_hash
            .ok_or_else(|| "repair gap previous QC hash was not captured".to_string())?,
        next_hash: gap_next_hash
            .ok_or_else(|| "repair gap next QC hash was not captured".to_string())?,
    })
}

fn sync_parent_directory(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
    let directory = fs::File::open(parent)
        .map_err(|error| format!("open directory {}: {error}", parent.display()))?;
    directory
        .sync_all()
        .map_err(|error| format!("sync directory {}: {error}", parent.display()))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ValidatorUpgradePreflightCode {
    DataRootMissing,
    ChainBodyMissing,
    ChainBodyEmpty,
    ChainBodyMalformed,
    ChainBodyNonMonotonic,
    CanonicalLocksMissing,
    CanonicalLocksMalformed,
    CompactBoundaryLockMissing,
    CompactBoundaryLockHashMismatch,
    BoundaryCommittedQcMissing,
    BoundaryCommittedQcHashMismatch,
    CanonicalLocksAheadOfChainBody,
    UpgradeArtifactUnreadable,
    RollbackBinaryUnreadable,
    RollbackBinaryNotExecutable,
    ConfigDigestUnavailable,
    ValidatorSetDigestUnavailable,
    ArchiveNotDisabled,
    ArchiveCanonicalUnverified,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ValidatorUpgradePreflightSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorUpgradePreflightFinding {
    pub code: ValidatorUpgradePreflightCode,
    pub severity: ValidatorUpgradePreflightSeverity,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorUpgradePreflightFileDigest {
    pub label: String,
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockSummaryReport {
    pub height: u64,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorUpgradePreflightReport {
    pub ok: bool,
    pub decision: String,
    pub data_dir: String,
    pub first_retained_height: Option<u64>,
    pub first_retained_hash: Option<String>,
    pub latest_height: Option<u64>,
    pub latest_hash: Option<String>,
    pub canonical_lock_min_height: Option<u64>,
    pub canonical_lock_max_height: Option<u64>,
    pub boundary_lock_present: bool,
    pub boundary_committed_qc_present: bool,
    pub locks_above_chain_tip: Vec<LockSummaryReport>,
    pub file_digests: Vec<ValidatorUpgradePreflightFileDigest>,
    pub findings: Vec<ValidatorUpgradePreflightFinding>,
}

#[derive(Debug, Clone, Default)]
pub struct ValidatorUpgradePreflightOptions {
    pub allow_derived_index_rebuild: bool,
    pub artifact_path: Option<PathBuf>,
    pub current_binary_path: Option<PathBuf>,
    pub rollback_binary_path: Option<PathBuf>,
    pub config_path: Option<PathBuf>,
    pub validator_set_path: Option<PathBuf>,
    pub archive_status_path: Option<PathBuf>,
}

pub fn preflight_validator_upgrade(
    source_root: &Path,
    options: ValidatorUpgradePreflightOptions,
) -> Result<ValidatorUpgradePreflightReport, String> {
    let data_dir = data_dir(source_root);
    let mut findings = Vec::new();
    let mut file_digests = Vec::new();

    if !data_dir.is_dir() {
        findings.push(preflight_error(
            ValidatorUpgradePreflightCode::DataRootMissing,
            format!("data directory does not exist: {}", data_dir.display()),
        ));
        return Ok(ValidatorUpgradePreflightReport {
            ok: false,
            decision: "NO_GO".to_string(),
            data_dir: data_dir.display().to_string(),
            first_retained_height: None,
            first_retained_hash: None,
            latest_height: None,
            latest_hash: None,
            canonical_lock_min_height: None,
            canonical_lock_max_height: None,
            boundary_lock_present: false,
            boundary_committed_qc_present: false,
            locks_above_chain_tip: Vec::new(),
            file_digests,
            findings,
        });
    }

    for (label, path, code) in [
        (
            "upgrade_artifact",
            options.artifact_path.as_ref(),
            ValidatorUpgradePreflightCode::UpgradeArtifactUnreadable,
        ),
        (
            "current_binary",
            options.current_binary_path.as_ref(),
            ValidatorUpgradePreflightCode::UpgradeArtifactUnreadable,
        ),
        (
            "config",
            options.config_path.as_ref(),
            ValidatorUpgradePreflightCode::ConfigDigestUnavailable,
        ),
        (
            "validator_set",
            options.validator_set_path.as_ref(),
            ValidatorUpgradePreflightCode::ValidatorSetDigestUnavailable,
        ),
    ] {
        if let Some(path) = path {
            match sha256_file(path) {
                Ok(sha256) => file_digests.push(ValidatorUpgradePreflightFileDigest {
                    label: label.to_string(),
                    path: path.display().to_string(),
                    sha256,
                }),
                Err(error) => findings.push(preflight_error(
                    code,
                    format!("cannot digest {label} {}: {error}", path.display()),
                )),
            }
        }
    }

    if let Some(path) = options.rollback_binary_path.as_ref() {
        match sha256_file(path) {
            Ok(sha256) => {
                file_digests.push(ValidatorUpgradePreflightFileDigest {
                    label: "rollback_binary".to_string(),
                    path: path.display().to_string(),
                    sha256,
                });
                if !is_executable(path) {
                    findings.push(preflight_error(
                        ValidatorUpgradePreflightCode::RollbackBinaryNotExecutable,
                        format!("rollback binary is not executable: {}", path.display()),
                    ));
                }
            }
            Err(error) => findings.push(preflight_error(
                ValidatorUpgradePreflightCode::RollbackBinaryUnreadable,
                format!("cannot digest rollback binary {}: {error}", path.display()),
            )),
        }
    }

    if let Some(path) = options.archive_status_path.as_ref() {
        match read_json(path) {
            Ok(value) => {
                let enabled = value
                    .get("enabled")
                    .and_then(Value::as_bool)
                    .unwrap_or_else(|| {
                        value
                            .get("status")
                            .and_then(Value::as_str)
                            .map(|status| {
                                !matches!(
                                    status.trim().to_ascii_lowercase().as_str(),
                                    "disabled" | "offline" | "stopped" | "contained"
                                )
                            })
                            .unwrap_or(false)
                    });
                if enabled {
                    findings.push(preflight_error(
                        ValidatorUpgradePreflightCode::ArchiveNotDisabled,
                        format!("archive status is not disabled/offline: {}", path.display()),
                    ));
                }
                if value
                    .get("canonical_verified")
                    .and_then(Value::as_bool)
                    .is_some_and(|verified| !verified)
                {
                    findings.push(preflight_error(
                        ValidatorUpgradePreflightCode::ArchiveCanonicalUnverified,
                        format!("archive canonical verification failed: {}", path.display()),
                    ));
                }
            }
            Err(error) => findings.push(preflight_warning(
                ValidatorUpgradePreflightCode::ArchiveCanonicalUnverified,
                format!("archive status was not readable: {error}"),
            )),
        }
    }

    let chain = match read_chain_summaries(&data_dir) {
        Ok(chain) => chain,
        Err(error) => {
            findings.push(preflight_error(
                ValidatorUpgradePreflightCode::ChainBodyMalformed,
                error,
            ));
            Vec::new()
        }
    };
    if !data_dir.join("chain.json").is_file() {
        findings.push(preflight_error(
            ValidatorUpgradePreflightCode::ChainBodyMissing,
            format!("missing {}", data_dir.join("chain.json").display()),
        ));
    }
    if chain.is_empty() && data_dir.join("chain.json").is_file() {
        findings.push(preflight_error(
            ValidatorUpgradePreflightCode::ChainBodyEmpty,
            "chain.json contains no retained blocks".to_string(),
        ));
    }

    let mut first_retained = chain.first().cloned();
    let mut latest = chain.last().cloned();
    if let Err(error) = validate_chain_monotonic(&chain) {
        findings.push(preflight_error(
            ValidatorUpgradePreflightCode::ChainBodyNonMonotonic,
            error,
        ));
        first_retained = None;
        latest = None;
    }

    let locks = match read_canonical_lock_map(&data_dir) {
        Ok(locks) => locks,
        Err(error) => {
            let code = if data_dir.join("canonical_locks.json").is_file() {
                ValidatorUpgradePreflightCode::CanonicalLocksMalformed
            } else {
                ValidatorUpgradePreflightCode::CanonicalLocksMissing
            };
            findings.push(preflight_error(code, error));
            BTreeMap::new()
        }
    };

    let canonical_lock_min_height = locks.keys().next().copied();
    let canonical_lock_max_height = locks.keys().next_back().copied();
    let mut boundary_lock_present = false;
    let mut boundary_committed_qc_present = false;

    if let Some(boundary) = first_retained.as_ref() {
        match locks.get(&boundary.height) {
            Some(hash) if hash == &boundary.hash => {
                boundary_lock_present = true;
            }
            Some(hash) => findings.push(preflight_error(
                ValidatorUpgradePreflightCode::CompactBoundaryLockHashMismatch,
                format!(
                    "boundary h{} lock hash {} does not match chain body hash {}",
                    boundary.height, hash, boundary.hash
                ),
            )),
            None => findings.push(preflight_error(
                ValidatorUpgradePreflightCode::CompactBoundaryLockMissing,
                format!(
                    "first retained chain body height h{} has no canonical lock",
                    boundary.height
                ),
            )),
        }

        match read_committed_qc_summaries(&data_dir) {
            Ok(qcs) => {
                if qcs
                    .iter()
                    .any(|qc| qc.height == boundary.height && qc.hash == boundary.hash)
                {
                    boundary_committed_qc_present = true;
                } else if qcs.iter().any(|qc| qc.height == boundary.height) {
                    findings.push(preflight_error(
                        ValidatorUpgradePreflightCode::BoundaryCommittedQcHashMismatch,
                        format!(
                            "committed QC exists for boundary h{} but not for hash {}",
                            boundary.height, boundary.hash
                        ),
                    ));
                } else if boundary.height > 0 {
                    findings.push(preflight_error(
                        ValidatorUpgradePreflightCode::BoundaryCommittedQcMissing,
                        format!(
                            "no committed QC proves first retained chain body height h{}",
                            boundary.height
                        ),
                    ));
                } else {
                    boundary_committed_qc_present = true;
                }
            }
            Err(error) => {
                if boundary.height > 0 {
                    findings.push(preflight_error(
                        ValidatorUpgradePreflightCode::BoundaryCommittedQcMissing,
                        error,
                    ));
                } else {
                    boundary_committed_qc_present = true;
                }
            }
        }
    }

    let locks_above_chain_tip = latest
        .as_ref()
        .map(|tip| {
            locks
                .range((tip.height + 1)..)
                .map(|(height, hash)| LockSummaryReport {
                    height: *height,
                    hash: hash.clone(),
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if !locks_above_chain_tip.is_empty() {
        let detail = format!(
            "{} canonical lock(s) are above retained chain tip h{}",
            locks_above_chain_tip.len(),
            latest.as_ref().map(|tip| tip.height).unwrap_or_default()
        );
        if options.allow_derived_index_rebuild
            && boundary_lock_present
            && boundary_committed_qc_present
        {
            findings.push(preflight_warning(
                ValidatorUpgradePreflightCode::CanonicalLocksAheadOfChainBody,
                format!("{detail}; derived index rebuild/prune is required before start"),
            ));
        } else {
            findings.push(preflight_error(
                ValidatorUpgradePreflightCode::CanonicalLocksAheadOfChainBody,
                detail,
            ));
        }
    }

    let ok = !findings
        .iter()
        .any(|finding| finding.severity == ValidatorUpgradePreflightSeverity::Error);
    Ok(ValidatorUpgradePreflightReport {
        ok,
        decision: if ok { "GO" } else { "NO_GO" }.to_string(),
        data_dir: data_dir.display().to_string(),
        first_retained_height: first_retained.as_ref().map(|block| block.height),
        first_retained_hash: first_retained.as_ref().map(|block| block.hash.clone()),
        latest_height: latest.as_ref().map(|block| block.height),
        latest_hash: latest.as_ref().map(|block| block.hash.clone()),
        canonical_lock_min_height,
        canonical_lock_max_height,
        boundary_lock_present,
        boundary_committed_qc_present,
        locks_above_chain_tip,
        file_digests,
        findings,
    })
}

fn preflight_error(
    code: ValidatorUpgradePreflightCode,
    detail: String,
) -> ValidatorUpgradePreflightFinding {
    ValidatorUpgradePreflightFinding {
        code,
        severity: ValidatorUpgradePreflightSeverity::Error,
        detail,
    }
}

fn preflight_warning(
    code: ValidatorUpgradePreflightCode,
    detail: String,
) -> ValidatorUpgradePreflightFinding {
    ValidatorUpgradePreflightFinding {
        code,
        severity: ValidatorUpgradePreflightSeverity::Warning,
        detail,
    }
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(hex::encode(hasher.finalize()))
}

fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path)
            .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

fn read_chain_summaries(data_dir: &Path) -> Result<Vec<BlockSummary>, String> {
    let path = data_dir.join("chain.json");
    let value = read_json(&path)?;
    let blocks = value
        .as_array()
        .ok_or_else(|| format!("{} is not a JSON array", path.display()))?;
    blocks
        .iter()
        .enumerate()
        .map(|(index, block)| {
            let height = get_u64(block, &["height", "number", "block_number", "block_index"])
                .ok_or_else(|| format!("chain block at array index {index} is missing height"))?;
            let hash = get_string(block, &["hash", "block_hash"]).ok_or_else(|| {
                format!("chain block at array index {index} is missing block hash")
            })?;
            Ok(BlockSummary { height, hash })
        })
        .collect()
}

fn validate_chain_monotonic(chain: &[BlockSummary]) -> Result<(), String> {
    for pair in chain.windows(2) {
        let previous = &pair[0];
        let next = &pair[1];
        if next.height != previous.height + 1 {
            return Err(format!(
                "chain body is not contiguous: h{} followed by h{}",
                previous.height, next.height
            ));
        }
    }
    Ok(())
}

fn read_canonical_lock_map(data_dir: &Path) -> Result<BTreeMap<u64, String>, String> {
    let path = data_dir.join("canonical_locks.json");
    let value = read_json(&path)?;
    let object = value
        .as_object()
        .ok_or_else(|| format!("{} is not a JSON object", path.display()))?;
    let mut locks = BTreeMap::new();
    for (height, entry) in object {
        let height = height
            .parse::<u64>()
            .map_err(|error| format!("canonical lock height {height:?} is invalid: {error}"))?;
        let hash = get_string(entry, &["hash", "block_hash"])
            .ok_or_else(|| format!("canonical lock h{height} is missing hash/block_hash"))?;
        locks.insert(height, hash);
    }
    if locks.is_empty() {
        return Err(format!("{} contains no locks", path.display()));
    }
    Ok(locks)
}

#[derive(Debug, Clone)]
struct CommittedQcSummary {
    height: u64,
    hash: String,
}

fn read_committed_qc_summaries(data_dir: &Path) -> Result<Vec<CommittedQcSummary>, String> {
    let path = data_dir.join("committed_qcs.jsonl");
    let file =
        fs::File::open(&path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let reader = BufReader::new(file);
    let mut qcs = Vec::new();
    for (index, line) in reader.lines().enumerate() {
        let line = line.map_err(|error| format!("read {}: {error}", path.display()))?;
        if line.trim().is_empty() {
            continue;
        }
        let value = serde_json::from_str::<Value>(&line)
            .map_err(|error| format!("parse committed QC line {}: {error}", index + 1))?;
        if let Some(summary) = committed_qc_summary_from_value(&value) {
            qcs.push(summary);
        }
    }
    if qcs.is_empty() {
        return Err(format!("{} has no committed QC entries", path.display()));
    }
    Ok(qcs)
}

fn committed_qc_summary_from_value(value: &Value) -> Option<CommittedQcSummary> {
    let qc = value.get("qc").unwrap_or(value);
    let hash = get_string(qc, &["block_hash", "hash"])
        .or_else(|| get_string(value, &["block_hash", "hash"]))?;
    let height = get_u64(qc, &["height", "block_height", "block_index"])
        .or_else(|| get_u64(value, &["height", "block_height", "block_index"]))
        .or_else(|| {
            qc.get("votes")
                .and_then(Value::as_array)
                .and_then(|votes| votes.first())
                .and_then(|vote| get_u64(vote, &["height", "block_height", "block_index"]))
        })?;
    Some(CommittedQcSummary { height, hash })
}

pub fn inspect_divergence(input: &BuildPlanInput) -> Value {
    let target = read_node_state(&input.target_data_dir, input.conflict_height);
    let source_dir = input
        .source_state_dir
        .as_deref()
        .or_else(|| input.source_evidence_dirs.first().map(PathBuf::as_path));
    let source = source_dir.map(|path| read_node_state(path, input.conflict_height));
    json!({
        "chain_id": input.chain_id,
        "network_id": input.network_id,
        "genesis_hash": input.genesis_hash,
        "target_node_id": input.target_node_id,
        "target_role": input.target_role,
        "target": target,
        "source": source,
        "fail_closed": true,
        "note": "inspection is read-only and does not choose a branch without verified quorum/QC evidence"
    })
}

pub fn build_plan(input: BuildPlanInput) -> RecoveryPlan {
    let mut failures = Vec::new();
    if input.chain_id != SYNERGY_TESTNET_V3_CHAIN_ID {
        failures.push(format!(
            "wrong chain_id {}; expected {}",
            input.chain_id, SYNERGY_TESTNET_V3_CHAIN_ID
        ));
    }
    if input.network_id != SYNERGY_TESTNET_V3_NETWORK_ID {
        failures.push(format!(
            "wrong network_id {}; expected {}",
            input.network_id, SYNERGY_TESTNET_V3_NETWORK_ID
        ));
    }
    if !input
        .genesis_hash
        .eq_ignore_ascii_case(EXPECTED_GENESIS_HASH)
    {
        failures.push(format!(
            "wrong genesis_hash {}; expected {}",
            input.genesis_hash, EXPECTED_GENESIS_HASH
        ));
    }

    let target = read_node_state(&input.target_data_dir, input.conflict_height);
    failures.extend(target.errors.iter().cloned());

    let source_dir = input.source_state_dir.clone().unwrap_or_else(|| {
        input
            .source_evidence_dirs
            .first()
            .cloned()
            .unwrap_or_default()
    });
    if source_dir.as_os_str().is_empty() {
        failures.push("missing --source-state-dir or --source-evidence-dir".to_string());
    }
    let source = read_node_state(&source_dir, input.conflict_height);
    failures.extend(source.errors.iter().cloned());

    let proof = load_recovery_proof(&source_dir);
    let qc_summary = match proof {
        Ok(proof) => verify_recovery_proof(&proof, &source_dir),
        Err(sidecar_error) => {
            match verify_legacy_committed_qc(&source_dir, input.conflict_height) {
                Ok(summary) => summary,
                Err(legacy_error) => QcProofSummary {
                    height: 0,
                    hash: String::new(),
                    vote_count: 0,
                    signers: Vec::new(),
                    active_validator_count: 0,
                    required_quorum: 0,
                    verified: false,
                    failure: Some(format!(
                        "{sidecar_error}; legacy committed QC rejected: {legacy_error}"
                    )),
                },
            }
        }
    };
    if let Some(error) = qc_summary.failure.as_ref() {
        failures.push(format!("QC proof rejected: {error}"));
    }

    let source_nodes_raw = if input.source_nodes_used.is_empty() {
        qc_summary.signers.clone()
    } else {
        input.source_nodes_used.clone()
    };
    let required_quorum = qc_summary.required_quorum;
    let source_node_check = validate_source_nodes(&source_nodes_raw, required_quorum);
    let mut source_nodes_used = source_nodes_raw;
    source_nodes_used.sort();
    source_nodes_used.dedup();
    failures.extend(source_node_check.iter().cloned());

    let source_common_height = input
        .source_common_height
        .or(source.latest_height)
        .unwrap_or_default();
    let source_common_hash = input
        .source_common_hash
        .or(source.latest_hash.clone())
        .unwrap_or_default();
    let source_canonical_lock_height = input
        .source_canonical_lock_height
        .or(source.canonical_lock_height)
        .unwrap_or_default();
    let source_canonical_lock_hash = input
        .source_canonical_lock_hash
        .or(source.canonical_lock_hash.clone())
        .unwrap_or_default();
    if qc_summary.verified
        && !qc_summary.hash.is_empty()
        && !source_canonical_lock_hash.is_empty()
        && qc_summary.hash != source_canonical_lock_hash
    {
        failures.push(format!(
            "verified source QC hash {} does not match source canonical lock hash {}",
            qc_summary.hash, source_canonical_lock_hash
        ));
    }

    if let Some(expected) = input.expected_target_conflict_hash.as_ref() {
        if target.conflict_hash.as_deref() != Some(expected.as_str()) {
            failures.push(format!(
                "target conflict hash mismatch: expected {expected}, found {}",
                target.conflict_hash.clone().unwrap_or_default()
            ));
        }
    }
    if let Some(expected) = input.expected_source_conflict_hash.as_ref() {
        if source.conflict_hash.as_deref() != Some(expected.as_str()) {
            failures.push(format!(
                "source conflict hash mismatch: expected {expected}, found {}",
                source.conflict_hash.clone().unwrap_or_default()
            ));
        }
    }

    let target_is_minority_or_lagged = source_common_height
        > target.latest_height.unwrap_or_default()
        || conflict_hashes_diverge(&target, &source)
        || target.canonical_lock_hash != Some(source_canonical_lock_hash.clone());

    let mut majority_branch_proven = qc_summary.verified
        && qc_summary.vote_count >= required_quorum as u64
        && source_nodes_used.len() >= required_quorum
        && source_node_check.is_empty();
    if source_common_height == 0 || source_common_hash.is_empty() {
        majority_branch_proven = false;
    }
    if !majority_branch_proven {
        failures.push(format!(
            "majority branch is not proven by {required_quorum}-of-{} active validators and a verified Aegis/PQVM QC",
            qc_summary.active_validator_count
        ));
    }
    if !target_is_minority_or_lagged {
        failures.push("target is not proven minority or lagged relative to source".to_string());
    }

    let recovery_type = input.recovery_type.unwrap_or_else(|| {
        if !target_is_minority_or_lagged {
            RecoveryType::NoAction
        } else if matches!(input.target_role, TargetRole::Relayer | TargetRole::Rpc) {
            RecoveryType::SupportChainFastSync
        } else if matches!(input.target_role, TargetRole::Validator) {
            RecoveryType::CanonicalStateReconcile
        } else {
            RecoveryType::ArchiveSnapshotRestore
        }
    });

    let (files_to_read, files_to_backup, files_to_mutate, file_failures) =
        build_file_plan(&input.target_data_dir, &source_dir, &recovery_type);
    failures.extend(file_failures);

    let flags = mutation_flags(&files_to_mutate);
    failures.extend(validate_source_state_consistency(
        &recovery_type,
        &source_dir,
        &files_to_read,
        target.latest_height.unwrap_or_default(),
        target.canonical_lock_height.unwrap_or_default(),
        source_common_height,
        source_canonical_lock_height,
        qc_summary.height,
    ));
    let mut preconditions = vec![
        "chain_id=1264".to_string(),
        "network_id=synergy-testnet-v3".to_string(),
        "genesis_hash_matches_canonical".to_string(),
        "source_qc_aegis_pqc_verified=true".to_string(),
        "source_signers_are_active_baseline_validators=true".to_string(),
        "keys_or_configs_copied=false".to_string(),
        "evidence_preserved_before_mutation=true".to_string(),
        "rollback_backup_written_before_mutation=true".to_string(),
    ];
    if matches!(input.target_role, TargetRole::Validator) {
        preconditions.push(format!(
            "target_stopped_or_quarantined={}",
            input.target_stopped_or_quarantined
        ));
    }

    let mut operator_approval_required = !failures.is_empty()
        || !majority_branch_proven
        || matches!(recovery_type, RecoveryType::UnsafeRequiresOperatorApproval);
    if has_forbidden_mutation_path(&files_to_mutate) || flags.keys_or_configs_copied {
        operator_approval_required = true;
        failures.push("plan would touch keys/configs/secrets; refused".to_string());
    }

    let mut plan = RecoveryPlan {
        plan_id: String::new(),
        created_at: Utc::now().to_rfc3339(),
        target_node_id: input.target_node_id,
        target_role: input.target_role,
        chain_id: input.chain_id,
        network_id: input.network_id,
        genesis_hash: input.genesis_hash,
        target_current_height: target.latest_height.unwrap_or_default(),
        target_current_hash: target.latest_hash.unwrap_or_default(),
        target_canonical_lock_height: target.canonical_lock_height.unwrap_or_default(),
        target_canonical_lock_hash: target.canonical_lock_hash.unwrap_or_default(),
        target_runtime_sha256: input.target_runtime_sha256,
        source_nodes_used,
        source_common_height,
        source_common_hash,
        source_canonical_lock_height,
        source_canonical_lock_hash,
        source_committed_qc_height: qc_summary.height,
        source_committed_qc_hash: qc_summary.hash,
        source_qc_vote_count: qc_summary.vote_count,
        source_qc_signers: qc_summary.signers,
        source_active_validator_count: qc_summary.active_validator_count,
        source_required_quorum: required_quorum,
        source_qc_aegis_pqc_verified: qc_summary.verified,
        majority_branch_proven,
        target_is_minority_or_lagged,
        recovery_type,
        files_to_read,
        files_to_backup,
        files_to_mutate,
        files_never_to_touch: FILES_NEVER_TO_TOUCH
            .iter()
            .map(|value| value.to_string())
            .collect(),
        keys_or_configs_copied: flags.keys_or_configs_copied,
        canonical_locks_mutated: flags.canonical_locks_mutated,
        committed_qcs_mutated: flags.committed_qcs_mutated,
        chain_state_mutated: flags.chain_state_mutated,
        dag_state_mutated: flags.dag_state_mutated,
        registry_state_mutated: flags.registry_state_mutated,
        token_state_mutated: flags.token_state_mutated,
        evidence_path: input.evidence_path.to_string_lossy().to_string(),
        rollback_path: input.rollback_path.to_string_lossy().to_string(),
        preconditions,
        postconditions: vec![
            "exact_common_height_match_required_before_rejoin".to_string(),
            "qc_vote_count_must_meet_dynamic_two_thirds_quorum".to_string(),
            "keys_or_configs_copied=false".to_string(),
            "no_quarantine_marker_after_rejoin".to_string(),
            "no_vote_locks_above_canonical_or_finalized_height".to_string(),
        ],
        failure_reason: (!failures.is_empty()).then(|| failures.join("; ")),
        operator_approval_required,
    };
    plan.plan_id = plan_id(&plan);
    plan
}

pub fn verify_plan(plan: &RecoveryPlan) -> RecoveryVerification {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    if plan.chain_id != SYNERGY_TESTNET_V3_CHAIN_ID {
        errors.push(format!(
            "wrong chain_id {}; expected {}",
            plan.chain_id, SYNERGY_TESTNET_V3_CHAIN_ID
        ));
    }
    if plan.network_id != SYNERGY_TESTNET_V3_NETWORK_ID {
        errors.push(format!(
            "wrong network_id {}; expected {}",
            plan.network_id, SYNERGY_TESTNET_V3_NETWORK_ID
        ));
    }
    if !plan
        .genesis_hash
        .eq_ignore_ascii_case(EXPECTED_GENESIS_HASH)
    {
        errors.push("wrong genesis_hash".to_string());
    }
    if !plan.source_qc_aegis_pqc_verified {
        errors.push("source QC is not verified through Aegis/PQVM".to_string());
    }
    if plan.source_qc_vote_count < plan.source_required_quorum as u64 {
        errors.push(format!(
            "source QC vote_count {} is below {}-of-{}",
            plan.source_qc_vote_count,
            plan.source_required_quorum,
            plan.source_active_validator_count
        ));
    }
    errors.extend(validate_source_nodes(
        &plan.source_qc_signers,
        plan.source_required_quorum,
    ));
    errors.extend(validate_source_nodes(
        &plan.source_nodes_used,
        plan.source_required_quorum,
    ));
    if has_duplicates(&plan.source_qc_signers) {
        errors.push("source QC contains duplicate signer".to_string());
    }
    if !plan.majority_branch_proven {
        errors.push("majority_branch_proven is false".to_string());
    }
    if !plan.target_is_minority_or_lagged && plan.recovery_type != RecoveryType::NoAction {
        errors.push("target_is_minority_or_lagged is false".to_string());
    }
    if has_forbidden_mutation_path(&plan.files_to_mutate) || plan.keys_or_configs_copied {
        errors.push("plan would copy or mutate keys/configs/secrets".to_string());
    }
    if plan.evidence_path.trim().is_empty() {
        errors.push("evidence_path is empty".to_string());
    }
    if plan.rollback_path.trim().is_empty() {
        errors.push("rollback_path is empty".to_string());
    }
    if plan.operator_approval_required {
        errors.push("operator_approval_required is true".to_string());
    }
    if plan.failure_reason.is_some() {
        errors.push(format!(
            "plan failure_reason is set: {}",
            plan.failure_reason.clone().unwrap_or_default()
        ));
    }
    if matches!(plan.target_role, TargetRole::Validator)
        && !plan
            .preconditions
            .iter()
            .any(|item| item == "target_stopped_or_quarantined=true")
        && plan.recovery_type != RecoveryType::NoAction
    {
        warnings.push(
            "validator apply will be refused until target_stopped_or_quarantined=true".to_string(),
        );
    }

    RecoveryVerification {
        valid_for_apply: errors.is_empty() && warnings.is_empty(),
        fail_closed: !errors.is_empty() || !warnings.is_empty(),
        errors,
        warnings,
        mutation_flags: MutationFlags {
            keys_or_configs_copied: plan.keys_or_configs_copied,
            canonical_locks_mutated: plan.canonical_locks_mutated,
            committed_qcs_mutated: plan.committed_qcs_mutated,
            chain_state_mutated: plan.chain_state_mutated,
            dag_state_mutated: plan.dag_state_mutated,
            registry_state_mutated: plan.registry_state_mutated,
            token_state_mutated: plan.token_state_mutated,
        },
    }
}

pub fn apply_plan(input: ApplyPlanInput) -> Result<ApplyPlanResult, String> {
    let content = fs::read_to_string(&input.plan_path)
        .map_err(|error| format!("read recovery plan {}: {error}", input.plan_path.display()))?;
    let mut plan: RecoveryPlan =
        serde_json::from_str(&content).map_err(|error| format!("parse recovery plan: {error}"))?;
    if input.confirm_target_stopped
        && !plan
            .preconditions
            .iter()
            .any(|item| item == "target_stopped_or_quarantined=true")
    {
        plan.preconditions
            .push("target_stopped_or_quarantined=true".to_string());
    }
    let verification = verify_plan(&plan);
    if !verification.valid_for_apply {
        let mut reasons = verification.errors;
        reasons.extend(verification.warnings);
        return Err(format!(
            "recovery plan refused fail-closed: {}",
            reasons.join("; ")
        ));
    }

    let evidence_root = PathBuf::from(&plan.evidence_path);
    let rollback_root = PathBuf::from(&plan.rollback_path);
    fs::create_dir_all(evidence_root.join("target-before"))
        .map_err(|error| format!("create evidence directory: {error}"))?;
    fs::create_dir_all(&rollback_root)
        .map_err(|error| format!("create rollback directory: {error}"))?;

    let mut files_backed_up = Vec::new();
    for target in &plan.files_to_backup {
        let target_path = PathBuf::from(target);
        if target_path.exists() {
            let evidence_copy = evidence_root
                .join("target-before")
                .join(file_name(&target_path)?);
            let rollback_copy = rollback_root.join(file_name(&target_path)?);
            copy_file(&target_path, &evidence_copy)?;
            copy_file(&target_path, &rollback_copy)?;
            files_backed_up.push(target_path.to_string_lossy().to_string());
        }
    }
    if plan.recovery_type == RecoveryType::NoAction {
        return Ok(ApplyPlanResult {
            plan_id: plan.plan_id,
            applied: false,
            fail_closed: false,
            evidence_path: plan.evidence_path,
            rollback_path: plan.rollback_path,
            files_backed_up,
            files_mutated: Vec::new(),
            mutation_flags: verification.mutation_flags,
        });
    }

    let mut files_mutated = Vec::new();
    for target in &plan.files_to_mutate {
        let target_path = PathBuf::from(target);
        let Some(source) = matching_source_for_target(&plan.files_to_read, &target_path) else {
            return Err(format!(
                "missing source file for target mutation {}",
                target_path.display()
            ));
        };
        atomic_copy(&source, &target_path)?;
        files_mutated.push(target_path.to_string_lossy().to_string());
    }

    Ok(ApplyPlanResult {
        plan_id: plan.plan_id,
        applied: true,
        fail_closed: false,
        evidence_path: plan.evidence_path,
        rollback_path: plan.rollback_path,
        files_backed_up,
        files_mutated,
        mutation_flags: verification.mutation_flags,
    })
}

pub fn write_plan(plan: &RecoveryPlan, path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create plan directory {}: {error}", parent.display()))?;
    }
    let data = serde_json::to_vec_pretty(plan)
        .map_err(|error| format!("serialize recovery plan: {error}"))?;
    let temp = path.with_extension("json.tmp");
    fs::write(&temp, data)
        .map_err(|error| format!("write temp plan {}: {error}", temp.display()))?;
    fs::rename(&temp, path)
        .map_err(|error| format!("replace recovery plan {}: {error}", path.display()))
}

fn read_node_state(path: &Path, conflict_height: Option<u64>) -> NodeState {
    let data_dir = data_dir(path);
    let latest = read_latest_block(path, &data_dir);
    let canonical = read_canonical_lock(&data_dir);
    let conflict_hash =
        conflict_height.and_then(|height| read_block_hash_at(path, &data_dir, height));
    NodeState {
        latest_height: latest.as_ref().map(|block| block.height),
        latest_hash: latest.as_ref().map(|block| block.hash.clone()),
        canonical_lock_height: canonical.as_ref().map(|lock| lock.height),
        canonical_lock_hash: canonical.as_ref().map(|lock| lock.hash.clone()),
        conflict_hash,
        errors: Vec::new(),
    }
}

#[derive(Debug, Clone)]
struct NodeState {
    latest_height: Option<u64>,
    latest_hash: Option<String>,
    canonical_lock_height: Option<u64>,
    canonical_lock_hash: Option<String>,
    conflict_hash: Option<String>,
    errors: Vec<String>,
}

#[derive(Debug, Clone)]
struct BlockSummary {
    height: u64,
    hash: String,
}

#[derive(Debug, Clone)]
struct LockSummary {
    height: u64,
    hash: String,
}

impl Serialize for NodeState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        json!({
            "latest_height": self.latest_height,
            "latest_hash": self.latest_hash,
            "canonical_lock_height": self.canonical_lock_height,
            "canonical_lock_hash": self.canonical_lock_hash,
            "conflict_hash": self.conflict_hash,
            "errors": self.errors,
        })
        .serialize(serializer)
    }
}

fn data_dir(path: &Path) -> PathBuf {
    if path.join("data").is_dir() {
        path.join("data")
    } else {
        path.to_path_buf()
    }
}

fn read_latest_block(root: &Path, data_dir: &Path) -> Option<BlockSummary> {
    let chain_path = data_dir.join("chain.json");
    if let Ok(content) = fs::read_to_string(chain_path) {
        if let Ok(blocks) = serde_json::from_str::<Vec<Block>>(&content) {
            if let Some(block) = blocks.last() {
                return Some(BlockSummary {
                    height: block.block_index,
                    hash: block.hash.clone(),
                });
            }
        }
    }
    read_rpc_block(root.join("rpc/latest_block.json"))
}

fn read_block_hash_at(root: &Path, data_dir: &Path, height: u64) -> Option<String> {
    let chain_path = data_dir.join("chain.json");
    if let Ok(content) = fs::read_to_string(chain_path) {
        if let Ok(blocks) = serde_json::from_str::<Vec<Block>>(&content) {
            if let Some(hash) = blocks
                .iter()
                .find(|block| block.block_index == height)
                .map(|block| block.hash.clone())
            {
                return Some(hash);
            }
        }
    }
    read_rpc_block(root.join(format!("rpc/block_{height}.json")))
        .map(|block| block.hash)
        .or_else(|| read_canonical_lock_hash_at(data_dir, height))
}

fn read_rpc_block(path: PathBuf) -> Option<BlockSummary> {
    let value = read_json(&path).ok()?;
    let value = unwrap_rpc(&value);
    let block = value.get("block").unwrap_or(value);
    let height = get_u64(block, &["height", "number", "block_number", "block_index"])?;
    let hash = get_string(block, &["hash", "block_hash"])?;
    Some(BlockSummary { height, hash })
}

fn read_canonical_lock(data_dir: &Path) -> Option<LockSummary> {
    let value = read_json(&data_dir.join("canonical_locks.json")).ok()?;
    let object = value.as_object()?;
    let height = object
        .keys()
        .filter_map(|key| key.parse::<u64>().ok())
        .max()?;
    let entry = object.get(&height.to_string())?;
    let hash = get_string(entry, &["hash", "block_hash"])?;
    Some(LockSummary { height, hash })
}

fn read_canonical_lock_hash_at(data_dir: &Path, height: u64) -> Option<String> {
    let value = read_json(&data_dir.join("canonical_locks.json")).ok()?;
    let entry = value.as_object()?.get(&height.to_string())?;
    get_string(entry, &["hash", "block_hash"])
}

fn load_recovery_proof(source_dir: &Path) -> Result<RecoveryProof, String> {
    for candidate in [
        "recovery-proof.json",
        "recovery_proof.json",
        "aegis_qc_proof.json",
        "data/recovery-proof.json",
        "data/aegis_qc_proof.json",
    ] {
        let path = source_dir.join(candidate);
        if path.exists() {
            let content = fs::read_to_string(&path)
                .map_err(|error| format!("read recovery proof {}: {error}", path.display()))?;
            let proof = serde_json::from_str::<RecoveryProof>(&content)
                .map_err(|error| format!("parse recovery proof {}: {error}", path.display()))?;
            return Ok(proof);
        }
    }
    Err(
        "missing recovery-proof.json with Aegis/PQVM QC, validator_set, and cluster_map"
            .to_string(),
    )
}

fn verify_legacy_committed_qc(
    source_dir: &Path,
    min_height: Option<u64>,
) -> Result<QcProofSummary, String> {
    let data_dir = data_dir(source_dir);
    let qc = latest_legacy_committed_qc(&data_dir, min_height)?;
    verify_legacy_qc(&data_dir, qc)
}

pub fn verify_latest_committed_qc_in_state_dir(
    source_dir: &Path,
    min_height: Option<u64>,
) -> Result<QcProofSummary, String> {
    verify_legacy_committed_qc(source_dir, min_height)
}

pub fn verify_latest_committed_qc_in_state_dir_at_or_below(
    source_dir: &Path,
    max_height: u64,
    min_height: Option<u64>,
) -> Result<QcProofSummary, String> {
    let data_dir = data_dir(source_dir);
    let qc = latest_legacy_committed_qc_at_or_below(&data_dir, max_height, min_height)?;
    verify_legacy_qc(&data_dir, qc)
}

fn latest_legacy_committed_qc(
    data_dir: &Path,
    min_height: Option<u64>,
) -> Result<LegacyQuorumCertificate, String> {
    let path = data_dir.join("committed_qcs.jsonl");
    let Some(line) = read_last_nonempty_line(&path)
        .map_err(|error| format!("read latest line from {}: {error}", path.display()))?
    else {
        return Err(format!("{} has no committed QC entries", path.display()));
    };
    let entry = serde_json::from_str::<LegacyCommittedQcLogEntry>(&line)
        .map_err(|error| format!("parse latest committed QC: {error}"))?;
    let height = legacy_qc_height(&entry.qc)?;
    if let Some(min_height) = min_height {
        if height < min_height {
            return Err(format!(
                "latest committed QC height {height} is below required recovery height {min_height}"
            ));
        }
    }
    Ok(entry.qc)
}

const REVERSE_LINE_CHUNK_BYTES: usize = 64 * 1024;

fn read_last_nonempty_line(path: &Path) -> std::io::Result<Option<String>> {
    let mut file = fs::File::open(path)?;
    let mut position = file.seek(SeekFrom::End(0))?;
    let mut suffix = Vec::new();

    while position > 0 {
        let chunk_len = usize::try_from(position.min(REVERSE_LINE_CHUNK_BYTES as u64))
            .unwrap_or(REVERSE_LINE_CHUNK_BYTES);
        position -= chunk_len as u64;
        file.seek(SeekFrom::Start(position))?;

        let mut chunk = vec![0_u8; chunk_len];
        file.read_exact(&mut chunk)?;
        chunk.extend_from_slice(&suffix);

        let mut line_end = chunk.len();
        for newline in chunk
            .iter()
            .enumerate()
            .rev()
            .filter_map(|(index, byte)| (*byte == b'\n').then_some(index))
        {
            let line = &chunk[newline + 1..line_end];
            if line.iter().any(|byte| !byte.is_ascii_whitespace()) {
                return String::from_utf8(line.to_vec())
                    .map(Some)
                    .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error));
            }
            line_end = newline;
        }

        suffix = chunk[..line_end].to_vec();
    }

    if suffix.iter().any(|byte| !byte.is_ascii_whitespace()) {
        return String::from_utf8(suffix)
            .map(Some)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error));
    }
    Ok(None)
}

fn latest_legacy_committed_qc_at_or_below(
    data_dir: &Path,
    max_height: u64,
    min_height: Option<u64>,
) -> Result<LegacyQuorumCertificate, String> {
    let path = data_dir.join("committed_qcs.jsonl");
    let file =
        fs::File::open(&path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let reader = BufReader::new(file);
    let mut candidate = None;
    let mut latest_seen_height = None;
    for line in reader.lines() {
        let line = line.map_err(|error| format!("read {}: {error}", path.display()))?;
        if line.trim().is_empty() {
            continue;
        }
        let entry = serde_json::from_str::<LegacyCommittedQcLogEntry>(&line)
            .map_err(|error| format!("parse committed QC entry: {error}"))?;
        let height = legacy_qc_height(&entry.qc)?;
        latest_seen_height = Some(height);
        if height > max_height {
            continue;
        }
        if let Some(min_height) = min_height {
            if height < min_height {
                continue;
            }
        }
        candidate = Some(entry.qc);
    }
    candidate.ok_or_else(|| {
        let latest = latest_seen_height
            .map(|height| height.to_string())
            .unwrap_or_else(|| "none".to_string());
        format!(
            "no committed QC at or below persisted chain height {max_height}; latest committed QC height seen: {latest}"
        )
    })
}

fn verify_legacy_qc(
    data_dir: &Path,
    qc: LegacyQuorumCertificate,
) -> Result<QcProofSummary, String> {
    if qc.block_hash.trim().is_empty() {
        return Err("committed QC block_hash is empty".to_string());
    }
    if qc.aggregate_signature.is_empty() {
        return Err("committed QC aggregate signature is missing".to_string());
    }
    if qc.participant_bitmap.is_empty() {
        return Err("committed QC participant bitmap is missing".to_string());
    }
    if !qc.validation_quorum_met || !qc.cooperation_quorum_met {
        return Err(
            "committed QC does not prove both validation and cooperation quorum".to_string(),
        );
    }

    let height = legacy_qc_height(&qc)?;
    let validators = load_legacy_active_baseline_validators(data_dir, height)?;
    let required_quorum = required_quorum_for_active_validator_count(validators.len())?;
    if qc.votes.len() < required_quorum {
        return Err(format!(
            "committed QC has {} vote(s), {required_quorum} required",
            qc.votes.len(),
        ));
    }

    let mut seen = BTreeSet::new();
    let manager = PQCManager::new();
    for vote in &qc.votes {
        if vote.block_hash != qc.block_hash {
            return Err("QC vote signs a different block hash".to_string());
        }
        if vote.block_index != height {
            return Err("QC vote height does not match committed QC height".to_string());
        }
        if vote.epoch_number != qc.epoch_number || vote.round_number != qc.round_number {
            return Err("QC vote epoch/round does not match committed QC".to_string());
        }
        if !seen.insert(vote.validator_address.clone()) {
            return Err("committed QC contains duplicate signer".to_string());
        }
        let validator = validators.get(&vote.validator_address).ok_or_else(|| {
            format!(
                "committed QC signer {} is not an ACTIVE canonical baseline validator",
                vote.validator_address
            )
        })?;
        if vote.signer_public_key != validator.public_key.key_data {
            return Err(format!(
                "signer public key does not match canonical consensus key for validator {}",
                vote.validator_address
            ));
        }
        if vote.signature.algorithm != validator.public_key.algorithm {
            return Err(format!(
                "signature algorithm does not match canonical consensus key for validator {}",
                vote.validator_address
            ));
        }
        let payload = legacy_vote_signature_payload(vote);
        let valid = manager
            .verify(&validator.public_key, &vote.signature, payload.as_bytes())
            .map_err(|error| format!("PQC vote signature verify error: {error}"))?;
        if !valid {
            return Err(format!(
                "invalid PQC vote signature from validator {}",
                vote.validator_address
            ));
        }
    }

    if seen.len() < required_quorum {
        return Err(format!(
            "committed QC has {} unique signer(s), {required_quorum} required",
            seen.len(),
        ));
    }
    let signer_count = seen.len() as f64;
    if qc.cumulative_weight > 0.0 && (qc.cumulative_weight - signer_count).abs() > 0.000_001 {
        return Err(format!(
            "committed QC cumulative_weight mismatch: computed {signer_count}, declared {}",
            qc.cumulative_weight
        ));
    }

    Ok(QcProofSummary {
        height,
        hash: qc.block_hash,
        vote_count: seen.len() as u64,
        signers: seen.into_iter().collect(),
        active_validator_count: validators.len(),
        required_quorum,
        verified: true,
        failure: None,
    })
}

fn required_quorum_for_active_validator_count(
    active_validator_count: usize,
) -> Result<usize, String> {
    if active_validator_count == 0 {
        return Err("active canonical validator set is empty".to_string());
    }
    Ok(required_validator_quorum(active_validator_count).max(1))
}

fn legacy_qc_height(qc: &LegacyQuorumCertificate) -> Result<u64, String> {
    let mut heights = qc.votes.iter().map(|vote| vote.block_index);
    let Some(height) = heights.next() else {
        return Err("committed QC has no votes".to_string());
    };
    if heights.any(|candidate| candidate != height) {
        return Err("committed QC votes do not agree on height".to_string());
    }
    Ok(height)
}

fn legacy_vote_signature_payload(vote: &LegacyVote) -> String {
    format!(
        "{}:{}:{}:{}:{}",
        vote.validator_address,
        vote.block_index,
        vote.round_number,
        vote.block_hash,
        vote.epoch_number
    )
}

fn load_legacy_active_baseline_validators(
    data_dir: &Path,
    consensus_height: u64,
) -> Result<std::collections::BTreeMap<String, LegacyValidator>, String> {
    let value = read_json(&data_dir.join("validator_registry.json"))?;
    let validators = value
        .get("validators")
        .and_then(Value::as_object)
        .ok_or_else(|| "validator_registry.json missing validators object".to_string())?;
    if let Some(migration) = consensus_fork::active_consensus_fork_migration()? {
        if migration.applies_to_height(consensus_height) {
            migration.validate()?;
            let mut canonical_post_fork_keys = std::collections::BTreeMap::new();
            for validator in &migration.new_validator_registry {
                let (algorithm, key_data) = parse_consensus_public_key_material(
                    &validator.validator_address,
                    &validator.consensus_public_key,
                    Some(&validator.consensus_key_type),
                )?;
                if algorithm != PQCAlgorithm::FNDSA {
                    return Err(format!(
                        "post-fork validator {} consensus key is not FN-DSA",
                        validator.validator_address
                    ));
                }
                canonical_post_fork_keys.insert(
                    validator.validator_address.clone(),
                    PQCPublicKey {
                        algorithm,
                        key_data,
                        key_id: format!("validator-consensus:{}", validator.validator_address),
                        created_at: migration.fork_height,
                    },
                );
            }
            let mut active = std::collections::BTreeMap::new();
            for (address, record) in validators {
                let status = get_string(record, &["status"]).unwrap_or_default();
                if status != "Active" && status != "ACTIVE" {
                    continue;
                }
                let public_key = if let Some(public_key) = canonical_post_fork_keys.get(address) {
                    public_key.clone()
                } else {
                    let activation_effective_height =
                        active_post_fork_validator_effective_height(data_dir, address, record)?;
                    if activation_effective_height > consensus_height {
                        continue;
                    }
                    if !post_fork_dynamic_validator_has_consensus_participation(record) {
                        continue;
                    }
                    let public_key_text =
                        get_string(record, &["public_key", "consensus_public_key"]).ok_or_else(
                            || {
                                format!(
                            "active post-fork validator {address} is missing consensus public key"
                        )
                            },
                        )?;
                    let public_key = if let Some(algorithm_label) = get_string(
                        record,
                        &[
                            "consensus_key_type",
                            "public_key_algorithm",
                            "consensus_public_key_algorithm",
                        ],
                    ) {
                        parse_validator_public_key_with_declared_algorithm(
                            address,
                            &public_key_text,
                            &algorithm_label,
                        )?
                    } else {
                        parse_validator_public_key(address, &public_key_text).or_else(|error| {
                            if error.contains("missing consensus key algorithm prefix") {
                                return parse_validator_public_key_with_declared_algorithm(
                                    address,
                                    &public_key_text,
                                    "FN-DSA",
                                );
                            }
                            Err(error)
                        })?
                    };
                    if public_key.algorithm != PQCAlgorithm::FNDSA {
                        return Err(format!(
                            "active post-fork validator {address} consensus key is not FN-DSA"
                        ));
                    }
                    public_key
                };
                active.insert(
                    address.clone(),
                    LegacyValidator {
                        public_key: public_key.clone(),
                    },
                );
            }
            if active.is_empty() {
                return Err("post-fork active validator registry is empty".to_string());
            }
            if active.len() < BASELINE_VALIDATOR_COUNT {
                return Err(format!(
                    "post-fork active validator registry has {} validator(s), expected at least {BASELINE_VALIDATOR_COUNT}",
                    active.len()
                ));
            }
            return Ok(active);
        }
    }
    let canonical_keys = canonical_consensus_keys_for_height(consensus_height)?;
    let mut active = std::collections::BTreeMap::new();
    let mut seen_canonical_keys = BTreeSet::new();
    for (address, record) in validators {
        let status = get_string(record, &["status"]).unwrap_or_default();
        if status != "Active" && status != "ACTIVE" {
            continue;
        }
        let public_key_text = get_string(record, &["public_key", "consensus_public_key"])
            .ok_or_else(|| format!("validator {address} is missing consensus public key"))?;
        let public_key = if let Some(algorithm_label) = get_string(
            record,
            &[
                "consensus_key_type",
                "public_key_algorithm",
                "consensus_public_key_algorithm",
            ],
        ) {
            parse_validator_public_key_with_declared_algorithm(
                address,
                &public_key_text,
                &algorithm_label,
            )?
        } else {
            parse_validator_public_key(address, &public_key_text).or_else(|error| {
                if error.contains("missing consensus key algorithm prefix") {
                    return parse_validator_public_key_with_declared_algorithm(
                        address,
                        &public_key_text,
                        "FN-DSA",
                    );
                }
                Err(error)
            })?
        };
        if !canonical_keys.is_empty() && !canonical_keys.contains(&public_key.key_data) {
            return Err(format!(
                "active validator {address} consensus public key is not in canonical genesis"
            ));
        }
        seen_canonical_keys.insert(public_key.key_data.clone());
        active.insert(address.clone(), LegacyValidator { public_key });
    }
    if active.len() != BASELINE_VALIDATOR_COUNT {
        return Err(format!(
            "active validator registry has {} canonical validator(s), expected {BASELINE_VALIDATOR_COUNT}",
            active.len()
        ));
    }
    if seen_canonical_keys.len() != BASELINE_VALIDATOR_COUNT {
        return Err(format!(
            "active validator registry has {} unique canonical key(s), expected {BASELINE_VALIDATOR_COUNT}",
            seen_canonical_keys.len()
        ));
    }
    Ok(active)
}

fn post_fork_dynamic_validator_has_consensus_participation(record: &Value) -> bool {
    get_u64(record, &["last_vote_timestamp"]).unwrap_or(0) > 0
        || get_u64(record, &["total_transactions_validated"]).unwrap_or(0) > 0
        || get_u64(record, &["total_blocks_produced"]).unwrap_or(0) > 0
}

fn active_post_fork_validator_effective_height(
    data_dir: &Path,
    address: &str,
    record: &Value,
) -> Result<u64, String> {
    if let Some(height) = get_u64(record, &["activation_effective_height"]) {
        return Ok(height);
    }
    if let Some(height) = get_u64(record, &["activation_recorded_height"]) {
        return Ok(height.saturating_add(1));
    }
    if let Some(height) = get_u64(record, &["shadow_started_at_height"]) {
        return Ok(height
            .saturating_add(VALIDATOR_SHADOW_PHASE_BLOCKS)
            .saturating_add(1));
    }

    let activation_tx_hash = get_string(record, &["activation_tx_hash"])
        .filter(|hash| !hash.trim().is_empty())
        .ok_or_else(|| {
            format!(
                "active post-fork validator {address} is not in canonical fork registry and has no activation_effective_height or activation_tx_hash"
            )
        })?;
    committed_activation_tx_effective_height(data_dir, address, activation_tx_hash.trim())
}

fn committed_activation_tx_effective_height(
    data_dir: &Path,
    address: &str,
    activation_tx_hash: &str,
) -> Result<u64, String> {
    let dag_state = read_json(&data_dir.join("dag_state.json")).map_err(|error| {
        format!(
            "active post-fork validator {address} activation_tx_hash {activation_tx_hash} cannot be verified from dag_state.json: {error}"
        )
    })?;
    let node_hash = dag_state
        .get("transaction_index")
        .and_then(Value::as_object)
        .and_then(|index| index.get(activation_tx_hash))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            format!(
                "active post-fork validator {address} activation_tx_hash {activation_tx_hash} is not committed in DAG transaction index"
            )
        })?;
    let node = dag_state
        .get("vertices")
        .and_then(Value::as_object)
        .and_then(|vertices| vertices.get(node_hash))
        .ok_or_else(|| {
            format!(
                "active post-fork validator {address} activation_tx_hash {activation_tx_hash} points to missing DAG vertex {node_hash}"
            )
        })?;
    let status = get_string(node, &["status"]).unwrap_or_default();
    if !status.eq_ignore_ascii_case("committed") {
        return Err(format!(
            "active post-fork validator {address} activation_tx_hash {activation_tx_hash} DAG vertex is not committed"
        ));
    }
    let contains_hash = node
        .get("transaction_hashes")
        .and_then(Value::as_array)
        .map(|hashes| {
            hashes
                .iter()
                .any(|hash| hash.as_str() == Some(activation_tx_hash))
        })
        .unwrap_or(false);
    if !contains_hash {
        return Err(format!(
            "active post-fork validator {address} activation_tx_hash {activation_tx_hash} is missing from its DAG vertex transaction_hashes"
        ));
    }

    let transactions = node
        .get("transactions")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            format!(
                "active post-fork validator {address} activation_tx_hash {activation_tx_hash} DAG vertex has no transactions"
            )
        })?;
    let activation_matches = transactions.iter().any(|transaction| {
        transaction
            .get("data")
            .and_then(Value::as_str)
            .and_then(|data| data.strip_prefix("validator_activation:"))
            .and_then(|payload| serde_json::from_str::<Value>(payload).ok())
            .and_then(|payload| {
                payload
                    .get("validator")
                    .and_then(Value::as_str)
                    .map(|validator| validator == address)
            })
            .unwrap_or(false)
    });
    if !activation_matches {
        return Err(format!(
            "active post-fork validator {address} activation_tx_hash {activation_tx_hash} is not a committed validator_activation transaction for that address"
        ));
    }

    let activation_block_height = get_u64(node, &["block_number", "height_hint"]).ok_or_else(|| {
        format!(
            "active post-fork validator {address} activation_tx_hash {activation_tx_hash} committed DAG vertex has no block height"
        )
    })?;
    Ok(activation_block_height
        .saturating_add(VALIDATOR_SHADOW_PHASE_BLOCKS)
        .saturating_add(1))
}

fn canonical_consensus_keys_for_height(consensus_height: u64) -> Result<BTreeSet<Vec<u8>>, String> {
    if let Some(migration) = consensus_fork::active_consensus_fork_migration()? {
        if migration.applies_to_height(consensus_height) {
            let mut keys = BTreeSet::new();
            for validator in &migration.new_validator_registry {
                let (_, key_data) = parse_consensus_public_key_material(
                    &validator.validator_address,
                    &validator.consensus_public_key,
                    Some(&validator.consensus_key_type),
                )?;
                keys.insert(key_data);
            }
            return Ok(keys);
        }
    }
    canonical_genesis_consensus_keys()
}

fn canonical_genesis_consensus_keys() -> Result<BTreeSet<Vec<u8>>, String> {
    #[cfg(not(test))]
    {
        let genesis = canonical_genesis()?;
        let mut keys = BTreeSet::new();
        for validator in genesis.validators() {
            let public_key = parse_validator_public_key_with_declared_algorithm(
                &validator.validator_id,
                &validator.consensus_public_key,
                &validator.consensus_key_type,
            )?;
            keys.insert(public_key.key_data);
        }
        return Ok(keys);
    }
    #[cfg(test)]
    {
        Ok(BTreeSet::new())
    }
}

fn verify_recovery_proof(proof: &RecoveryProof, source_dir: &Path) -> QcProofSummary {
    let mut failure = Vec::new();
    let active_validator_count = proof
        .validator_set
        .validators
        .iter()
        .filter(|validator| validator.status == ValidatorStatus::Active)
        .count();
    let required_quorum = required_validator_quorum(active_validator_count);
    if proof.chain_id != 0 && proof.chain_id != SYNERGY_TESTNET_V3_CHAIN_ID {
        failure.push(format!("proof chain_id {} is not 1264", proof.chain_id));
    }
    if !proof.network_id.is_empty() && proof.network_id != SYNERGY_TESTNET_V3_NETWORK_ID {
        failure.push(format!(
            "proof network_id {} is not canonical",
            proof.network_id
        ));
    }
    if !proof.genesis_hash.is_empty()
        && !proof
            .genesis_hash
            .eq_ignore_ascii_case(EXPECTED_GENESIS_HASH)
    {
        failure.push("proof genesis_hash mismatch".to_string());
    }
    let signers = match qc_signers(&proof.qc, &proof.validator_set) {
        Ok(signers) => signers,
        Err(error) => {
            failure.push(error);
            Vec::new()
        }
    };
    if let Err(error) = validate_validator_set_against_active_registry(
        &proof.validator_set,
        proof.qc.height.0,
        source_dir,
    ) {
        failure.push(error);
    }
    let verified = if failure.is_empty() {
        match verifier_from_validator_set(&proof.validator_set).and_then(|verifier| {
            verifier
                .verify_qc_checked(&proof.qc, &proof.validator_set, &proof.cluster_map)
                .map_err(|error| error.to_string())
        }) {
            Ok(()) => true,
            Err(error) => {
                failure.push(error);
                false
            }
        }
    } else {
        false
    };
    QcProofSummary {
        height: proof.qc.height.0,
        hash: proof.qc.block_id.0.clone(),
        vote_count: proof.qc.aegis_pq_key_ids.len() as u64,
        signers,
        active_validator_count,
        required_quorum,
        verified,
        failure: (!failure.is_empty()).then(|| failure.join("; ")),
    }
}

#[cfg(not(test))]
fn validate_validator_set_against_active_registry(
    validator_set: &ValidatorSet,
    consensus_height: u64,
    data_dir: &Path,
) -> Result<(), String> {
    let active = load_legacy_active_baseline_validators(data_dir, consensus_height)?;
    let active_records = validator_set
        .validators
        .iter()
        .filter(|validator| validator.status == ValidatorStatus::Active)
        .collect::<Vec<_>>();
    if active_records.len() != active.len() {
        return Err(format!(
            "validator set has {} active validator(s), expected {} active validator(s) for QC height {consensus_height}",
            active_records.len(),
            active.len()
        ));
    }
    let mut seen = BTreeSet::new();
    for validator in active_records {
        if !seen.insert(validator.validator_id.0.clone()) {
            return Err(format!(
                "validator set contains duplicate active validator {}",
                validator.validator_id.0
            ));
        }
        let Some(expected_validator) = active.get(&validator.validator_id.0) else {
            return Err(format!(
                "validator {} is not active in the source validator registry at QC height {consensus_height}",
                validator.validator_id.0
            ));
        };
        let algorithm = parse_algorithm(&validator.consensus_public_key.algorithm)?;
        if algorithm != expected_validator.public_key.algorithm {
            return Err(format!(
                "validator {} consensus public key algorithm does not match active registry",
                validator.validator_id.0
            ));
        }
        if validator.consensus_public_key.key_bytes != expected_validator.public_key.key_data {
            return Err(format!(
                "validator {} consensus public key does not match active registry",
                validator.validator_id.0
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
fn validate_validator_set_against_active_registry(
    validator_set: &ValidatorSet,
    _consensus_height: u64,
    _data_dir: &Path,
) -> Result<(), String> {
    if validator_set.validators.len() != BASELINE_VALIDATOR_COUNT {
        return Err(format!(
            "validator set has {} validators, expected canonical {BASELINE_VALIDATOR_COUNT}",
            validator_set.validators.len()
        ));
    }
    if validator_set
        .validators
        .iter()
        .any(|validator| validator.status != ValidatorStatus::Active)
    {
        return Err("proof validator set contains non-ACTIVE validator".to_string());
    }
    Ok(())
}

fn verifier_from_validator_set(validator_set: &ValidatorSet) -> Result<AegisPqvmVerifier, String> {
    let mut registry = AegisPqvmKeyRegistry::default();
    for validator in &validator_set.validators {
        if validator.status != ValidatorStatus::Active {
            continue;
        }
        let public_key = PQCPublicKey {
            algorithm: parse_algorithm(&validator.consensus_public_key.algorithm)?,
            key_data: validator.consensus_public_key.key_bytes.clone(),
            key_id: validator.consensus_public_key.key_id.0.clone(),
            created_at: 0,
        };
        registry.register_public_key(
            &validator.validator_uma_id.0,
            public_key,
            vec![AegisPqKeyRole::ConsensusVote],
            validator.activation_epoch,
        );
    }
    AegisPqvmVerifier::initialize_required(registry).map_err(|error| error.to_string())
}

fn qc_signers(
    qc: &AegisQuorumCertificate,
    validator_set: &ValidatorSet,
) -> Result<Vec<String>, String> {
    let validators = validator_set.canonicalized().validators;
    let indexes = bitmap_signer_indexes(&qc.signer_bitmap, validators.len())?;
    if indexes.len() != qc.aegis_pq_key_ids.len() {
        return Err("QC signer bitmap/key count mismatch".to_string());
    }
    let mut out = Vec::new();
    for index in indexes {
        let validator = validators
            .get(index)
            .ok_or_else(|| "QC signer bitmap references missing validator".to_string())?;
        out.push(validator.validator_id.0.clone());
    }
    Ok(out)
}

fn bitmap_signer_indexes(bitmap: &[u8], validator_count: usize) -> Result<Vec<usize>, String> {
    let mut indexes = Vec::new();
    for index in 0..validator_count {
        let byte = index / 8;
        let bit = index % 8;
        let Some(value) = bitmap.get(byte) else {
            continue;
        };
        if value & (1 << bit) != 0 {
            indexes.push(index);
        }
    }
    if indexes.is_empty() {
        return Err("QC signer bitmap is empty".to_string());
    }
    Ok(indexes)
}

fn parse_algorithm(value: &str) -> Result<PQCAlgorithm, String> {
    normalize_consensus_key_algorithm(value)
}

fn build_file_plan(
    target_data_dir: &Path,
    source_dir: &Path,
    recovery_type: &RecoveryType,
) -> (Vec<String>, Vec<String>, Vec<String>, Vec<String>) {
    if *recovery_type == RecoveryType::NoAction {
        return (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    }
    let target_data_dir = data_dir(target_data_dir);
    let source_data_dir = data_dir(source_dir);
    let mut files_to_read = Vec::new();
    let mut files_to_backup = Vec::new();
    let mut files_to_mutate = Vec::new();
    let mut failures = Vec::new();
    for file in ALLOWED_STATE_FILES {
        let source = source_data_dir.join(file);
        let target = target_data_dir.join(file);
        if source.exists() {
            files_to_read.push(source.to_string_lossy().to_string());
            files_to_backup.push(target.to_string_lossy().to_string());
            files_to_mutate.push(target.to_string_lossy().to_string());
        }
    }
    if files_to_mutate.is_empty() {
        failures.push(
            "source state directory contains no approved recoverable state files".to_string(),
        );
    }
    (files_to_read, files_to_backup, files_to_mutate, failures)
}

fn validate_source_state_consistency(
    recovery_type: &RecoveryType,
    source_dir: &Path,
    files_to_read: &[String],
    target_current_height: u64,
    target_canonical_lock_height: u64,
    source_common_height: u64,
    source_canonical_lock_height: u64,
    source_committed_qc_height: u64,
) -> Vec<String> {
    if *recovery_type == RecoveryType::NoAction {
        return Vec::new();
    }

    let mut failures = Vec::new();
    let source_data_dir = data_dir(source_dir);
    let has_source_chain = files_to_read.iter().any(|path| {
        Path::new(path).file_name().and_then(|name| name.to_str()) == Some("chain.json")
    });
    let source_advances_target = source_common_height > target_current_height
        || source_canonical_lock_height > target_current_height
        || source_committed_qc_height > target_current_height;

    if source_advances_target && !has_source_chain {
        failures.push(
            "source chain.json is required when recovery advances the target beyond its current height; proof-only bundles are not valid mutation sources"
                .to_string(),
        );
    }

    if has_source_chain {
        match chain_latest_height(&source_data_dir) {
            Ok(Some(height)) => {
                let required = source_common_height
                    .max(source_canonical_lock_height)
                    .max(source_committed_qc_height);
                if height < required {
                    failures.push(format!(
                        "source chain.json latest height {height} is below required recovery height {required}"
                    ));
                }
            }
            Ok(None) => failures.push("source chain.json has no blocks".to_string()),
            Err(error) => failures.push(format!("source chain.json rejected: {error}")),
        }
    }

    let reads_committed_qcs_jsonl = files_to_read.iter().any(|path| {
        Path::new(path).file_name().and_then(|name| name.to_str()) == Some("committed_qcs.jsonl")
    });
    if reads_committed_qcs_jsonl {
        match committed_qc_span(&source_data_dir) {
            Ok(span) => {
                let bridge_from = target_current_height.min(target_canonical_lock_height);
                if span.first_height > bridge_from.saturating_add(1) {
                    failures.push(format!(
                        "source committed_qcs.jsonl begins at height {}, which cannot bridge target height {}; provide a complete committed-QC source, not a tail",
                        span.first_height, bridge_from
                    ));
                }
                if span.last_height < source_committed_qc_height {
                    failures.push(format!(
                        "source committed_qcs.jsonl latest height {} is below verified source QC height {}",
                        span.last_height, source_committed_qc_height
                    ));
                }
            }
            Err(error) => failures.push(format!("source committed_qcs.jsonl rejected: {error}")),
        }
    }

    failures
}

#[derive(Debug, Clone, Copy)]
struct CommittedQcSpan {
    first_height: u64,
    last_height: u64,
}

fn chain_latest_height(data_dir: &Path) -> Result<Option<u64>, String> {
    let path = data_dir.join("chain.json");
    let content =
        fs::read_to_string(&path).map_err(|error| format!("read {}: {error}", path.display()))?;
    let blocks = serde_json::from_str::<Vec<Block>>(&content)
        .map_err(|error| format!("parse {}: {error}", path.display()))?;
    Ok(blocks.last().map(|block| block.block_index))
}

fn committed_qc_span(data_dir: &Path) -> Result<CommittedQcSpan, String> {
    let path = data_dir.join("committed_qcs.jsonl");
    let file =
        fs::File::open(&path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let reader = BufReader::new(file);
    let mut first_height = None;
    let mut last_height = None;
    for line in reader.lines() {
        let line = line.map_err(|error| format!("read {}: {error}", path.display()))?;
        if line.trim().is_empty() {
            continue;
        }
        let entry = serde_json::from_str::<LegacyCommittedQcLogEntry>(&line)
            .map_err(|error| format!("parse committed QC entry: {error}"))?;
        let height = legacy_qc_height(&entry.qc)?;
        first_height.get_or_insert(height);
        last_height = Some(height);
    }
    Ok(CommittedQcSpan {
        first_height: first_height
            .ok_or_else(|| format!("{} has no committed QC entries", path.display()))?,
        last_height: last_height.unwrap_or_default(),
    })
}

fn validate_source_nodes(nodes: &[String], required_quorum: usize) -> Vec<String> {
    let mut failures = Vec::new();
    if nodes.len() < required_quorum {
        failures.push(format!(
            "source has {} signer/source node(s), {required_quorum} required",
            nodes.len(),
        ));
    }
    if has_duplicates(nodes) {
        failures.push("duplicate signer/source node detected".to_string());
    }
    for node in nodes {
        let normalized = node.trim().to_ascii_lowercase();
        if normalized.contains("relayer")
            || normalized.contains("rpc")
            || normalized.contains("archive")
            || normalized.contains("observer")
            || normalized.contains("boot")
            || normalized.contains("seed")
            || normalized.contains("shadow")
        {
            failures.push(format!(
                "non-validator source {node} cannot count toward quorum"
            ));
        }
    }
    failures
}

fn mutation_flags(files_to_mutate: &[String]) -> MutationFlags {
    MutationFlags {
        keys_or_configs_copied: has_forbidden_mutation_path(files_to_mutate),
        canonical_locks_mutated: files_to_mutate
            .iter()
            .any(|path| path.ends_with("canonical_locks.json")),
        committed_qcs_mutated: files_to_mutate
            .iter()
            .any(|path| path.contains("committed_qcs")),
        chain_state_mutated: files_to_mutate
            .iter()
            .any(|path| path.ends_with("chain.json")),
        dag_state_mutated: files_to_mutate
            .iter()
            .any(|path| path.ends_with("dag_state.json")),
        registry_state_mutated: files_to_mutate
            .iter()
            .any(|path| path.ends_with("validator_registry.json")),
        token_state_mutated: files_to_mutate
            .iter()
            .any(|path| path.ends_with("token_state.json")),
    }
}

fn has_forbidden_mutation_path(paths: &[String]) -> bool {
    paths.iter().any(|path| {
        let normalized = path.to_ascii_lowercase();
        FILES_NEVER_TO_TOUCH
            .iter()
            .any(|forbidden| normalized.contains(forbidden))
    })
}

fn conflict_hashes_diverge(target: &NodeState, source: &NodeState) -> bool {
    matches!(
        (&target.conflict_hash, &source.conflict_hash),
        (Some(target_hash), Some(source_hash)) if target_hash != source_hash
    )
}

fn plan_id(plan: &RecoveryPlan) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(plan.created_at.as_bytes());
    hasher.update(plan.target_node_id.as_bytes());
    hasher.update(plan.source_common_hash.as_bytes());
    hasher.update(plan.target_current_hash.as_bytes());
    hex::encode(hasher.finalize())
}

fn read_json(path: &Path) -> Result<Value, String> {
    let content =
        fs::read_to_string(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    serde_json::from_str(&content).map_err(|error| format!("parse {}: {error}", path.display()))
}

fn unwrap_rpc(value: &Value) -> &Value {
    value.get("result").unwrap_or(value)
}

fn get_string(value: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(text) = value.get(*key).and_then(Value::as_str) {
            return Some(text.to_string());
        }
    }
    None
}

fn get_u64(value: &Value, keys: &[&str]) -> Option<u64> {
    for key in keys {
        if let Some(number) = value.get(*key).and_then(Value::as_u64) {
            return Some(number);
        }
        if let Some(text) = value.get(*key).and_then(Value::as_str) {
            if let Ok(number) = text.parse::<u64>() {
                return Some(number);
            }
        }
    }
    None
}

fn has_duplicates(values: &[String]) -> bool {
    let mut seen = BTreeSet::new();
    values
        .iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .any(|value| !seen.insert(value))
}

fn copy_file(source: &Path, target: &Path) -> Result<(), String> {
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create directory {}: {error}", parent.display()))?;
    }
    fs::copy(source, target)
        .map(|_| ())
        .map_err(|error| format!("copy {} to {}: {error}", source.display(), target.display()))
}

fn atomic_copy(source: &Path, target: &Path) -> Result<(), String> {
    if has_forbidden_mutation_path(&[target.to_string_lossy().to_string()]) {
        return Err(format!(
            "refusing forbidden target path {}",
            target.display()
        ));
    }
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create directory {}: {error}", parent.display()))?;
    }
    let data =
        fs::read(source).map_err(|error| format!("read source {}: {error}", source.display()))?;
    let temp = target.with_extension("recovery.tmp");
    let mut file = fs::File::create(&temp)
        .map_err(|error| format!("create temp file {}: {error}", temp.display()))?;
    file.write_all(&data)
        .map_err(|error| format!("write temp file {}: {error}", temp.display()))?;
    file.sync_all()
        .map_err(|error| format!("sync temp file {}: {error}", temp.display()))?;
    fs::rename(&temp, target)
        .map_err(|error| format!("replace target {}: {error}", target.display()))
}

fn matching_source_for_target(files_to_read: &[String], target: &Path) -> Option<PathBuf> {
    let target_name = target.file_name()?.to_string_lossy();
    files_to_read.iter().find_map(|source| {
        let source_path = PathBuf::from(source);
        (source_path.file_name()?.to_string_lossy() == target_name).then_some(source_path)
    })
}

fn file_name(path: &Path) -> Result<PathBuf, String> {
    path.file_name()
        .map(PathBuf::from)
        .ok_or_else(|| format!("path has no file name: {}", path.display()))
}

#[allow(dead_code)]
fn decode_base64_public_key(encoded: &str) -> Result<Vec<u8>, String> {
    general_purpose::STANDARD
        .decode(encoded.trim())
        .map_err(|error| format!("decode public key: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aegis_pqvm::AegisPqvmSigner;
    use crate::synergy_types::{
        BlockId, ChainId, ClusterAssignment, ClusterId, Epoch, Height, NetworkId, Round, UmaId,
        ValidatorId, Vote, VotePhase,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root(name: &str) -> PathBuf {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "synergy-recovery-{name}-{}-{now}",
            std::process::id()
        ));
        fs::create_dir_all(root.join("data")).unwrap();
        root
    }

    #[test]
    fn latest_qc_tail_reader_handles_large_lines_without_scanning_the_prefix() {
        let root = temp_root("latest-qc-tail-reader");
        let path = root.join("data/committed_qcs.jsonl");
        let large_line = format!("{{\"payload\":\"{}\"}}", "x".repeat(96 * 1024));
        fs::write(&path, format!("{{\"height\":1}}\n{large_line}\n  \n")).unwrap();
        assert_eq!(read_last_nonempty_line(&path).unwrap(), Some(large_line));

        fs::write(&path, b"first\nlast").unwrap();
        assert_eq!(
            read_last_nonempty_line(&path).unwrap().as_deref(),
            Some("last")
        );
        fs::remove_dir_all(root).unwrap();
    }

    fn genesis_required_quorum() -> usize {
        required_validator_quorum(BASELINE_VALIDATOR_COUNT)
    }

    fn write_chain(root: &Path, heights: &[(&str, u64)]) {
        let mut previous = EXPECTED_GENESIS_HASH.to_string();
        let blocks = heights
            .iter()
            .map(|(hash, height)| {
                let mut block = Block::new_with_timestamp(
                    *height,
                    Vec::new(),
                    previous.clone(),
                    "validator-1".to_string(),
                    *height,
                    100 + height,
                );
                block.hash = (*hash).to_string();
                previous = block.hash.clone();
                block
            })
            .collect::<Vec<_>>();
        fs::write(
            root.join("data/chain.json"),
            serde_json::to_string(&blocks).unwrap(),
        )
        .unwrap();
    }

    fn write_lock(root: &Path, height: u64, hash: &str) {
        fs::write(
            root.join("data/canonical_locks.json"),
            json!({height.to_string(): {"block_hash": hash}}).to_string(),
        )
        .unwrap();
    }

    fn write_locks(root: &Path, locks: &[(u64, &str)]) {
        let mut object = serde_json::Map::new();
        for (height, hash) in locks {
            object.insert(height.to_string(), json!({"block_hash": hash}));
        }
        fs::write(
            root.join("data/canonical_locks.json"),
            Value::Object(object).to_string(),
        )
        .unwrap();
    }

    fn write_preflight_qc(root: &Path, height: u64, hash: &str) {
        fs::write(
            root.join("data/committed_qcs.jsonl"),
            format!(
                "{}\n",
                json!({
                    "block_hash": hash,
                    "qc": {
                        "block_hash": hash,
                        "votes": [{"block_index": height}]
                    }
                })
            ),
        )
        .unwrap();
    }

    fn compact_qc_line(height: u64, hash: &str) -> Vec<u8> {
        format!(
            "{}\n",
            json!({
                "block_hash": hash,
                "qc": {
                    "block_hash": hash,
                    "votes": [{"block_index": height}]
                }
            })
        )
        .into_bytes()
    }

    fn full_missing_qc_fixture(
        root: &Path,
        corrupt_vote_signature: bool,
    ) -> (PathBuf, PathBuf, PathBuf, String) {
        fs::write(root.join(MISSING_QC_OFFLINE_MARKER), "validator stopped\n").unwrap();
        let mut manager = PQCManager::new();
        let validator_manager = ValidatorManager::new();
        let mut keys = Vec::new();
        for index in 0..BASELINE_VALIDATOR_COUNT {
            let address = format!("synv11missingqcvalidator{index}");
            let (public_key, private_key) = manager.generate_keypair(PQCAlgorithm::FNDSA).unwrap();
            validator_manager
                .register_validator(crate::validator::ValidatorRegistration {
                    address: address.clone(),
                    public_key: format!(
                        "fn-dsa:{}",
                        general_purpose::STANDARD.encode(&public_key.key_data)
                    ),
                    name: format!("Missing QC Validator {index}"),
                    stake_amount: 50_000_000_000_000,
                    submitted_at: 1,
                    registration_tx_hash: format!("registration-{index}"),
                })
                .unwrap();
            validator_manager.approve_validator(&address).unwrap();
            validator_manager.update_validator_stake(&address, 50_000_000_000_000);
            validator_manager.update_synergy_score(&address, 100.0);
            keys.push((address, public_key, private_key));
        }
        validator_manager
            .save_registry(root.join("data/validator_registry.json").to_str().unwrap())
            .unwrap();

        let mut previous = Block::new_with_timestamp(
            9,
            Vec::new(),
            "h8-parent".to_string(),
            keys[0].0.clone(),
            9,
            109,
        );
        let previous_signature = manager.sign(&keys[0].2, previous.hash.as_bytes()).unwrap();
        previous.proposer_public_key = keys[0].1.key_data.clone();
        previous.block_signature = previous_signature.signature_data;
        previous.block_signature_algorithm = "fn-dsa".to_string();

        let mut target = Block::new_with_timestamp(
            10,
            Vec::new(),
            previous.hash.clone(),
            keys[0].0.clone(),
            10,
            110,
        );
        let target_signature = manager.sign(&keys[0].2, target.hash.as_bytes()).unwrap();
        target.proposer_public_key = keys[0].1.key_data.clone();
        target.block_signature = target_signature.signature_data;
        target.block_signature_algorithm = "fn-dsa".to_string();

        let mut next = Block::new_with_timestamp(
            11,
            Vec::new(),
            target.hash.clone(),
            keys[1].0.clone(),
            11,
            111,
        );
        let next_signature = manager.sign(&keys[1].2, next.hash.as_bytes()).unwrap();
        next.proposer_public_key = keys[1].1.key_data.clone();
        next.block_signature = next_signature.signature_data;
        next.block_signature_algorithm = "fn-dsa".to_string();

        let committed_blocks = [&previous, &target, &next]
            .into_iter()
            .map(|block| {
                serde_json::to_string(&json!({"block_hash": block.hash, "block": block})).unwrap()
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        fs::write(root.join("data/committed_blocks.jsonl"), committed_blocks).unwrap();
        let mut qcs = compact_qc_line(9, &previous.hash);
        qcs.extend(compact_qc_line(11, &next.hash));
        fs::write(root.join("data/committed_qcs.jsonl"), qcs).unwrap();

        let mut votes = keys
            .iter()
            .take(genesis_required_quorum())
            .map(|(address, public_key, private_key)| {
                let payload = format!("{address}:10:0:{}:0", target.hash);
                let signature = manager.sign(private_key, payload.as_bytes()).unwrap();
                json!({
                    "validator_address": address,
                    "block_hash": target.hash,
                    "block_index": 10,
                    "epoch_number": 0,
                    "round_number": 0,
                    "signature": signature,
                    "signer_public_key": public_key.key_data,
                    "timestamp": 110,
                })
            })
            .collect::<Vec<_>>();
        if corrupt_vote_signature {
            let byte = votes[0]["signature"]["signature_data"][0].as_u64().unwrap();
            votes[0]["signature"]["signature_data"][0] = json!(byte ^ 1);
        }
        let qc = json!({
            "block_hash": target.hash,
            "epoch_number": 0,
            "round_number": 0,
            "aggregate_signature": [1, 2, 3, 4],
            "participant_bitmap": [15],
            "cumulative_weight": genesis_required_quorum() as f64,
            "validation_quorum_met": true,
            "cooperation_quorum_met": true,
            "timestamp": 110,
            "votes": votes,
        });
        let source_bytes = format!(
            "{}\n",
            serde_json::to_string(&json!({"block_hash": target.hash, "qc": qc})).unwrap()
        )
        .into_bytes();
        let source_one = root.join("source-validator-2-qc.json");
        let source_two = root.join("source-validator-6-qc.json");
        fs::write(&source_one, &source_bytes).unwrap();
        fs::write(&source_two, &source_bytes).unwrap();
        let block_path = root.join("block-10.json");
        fs::write(
            &block_path,
            serde_json::to_vec(&json!({"height": 10, "hash": target.hash, "block": target}))
                .unwrap(),
        )
        .unwrap();
        (
            source_one,
            source_two,
            block_path,
            sha256_bytes(&source_bytes),
        )
    }

    #[test]
    fn missing_qc_repair_dry_run_verifies_full_aegis_and_block_evidence() {
        let root = temp_root("missing-qc-full-dry-run");
        let (source_one, source_two, block_path, digest) = full_missing_qc_fixture(&root, false);

        let report = repair_missing_committed_qc(MissingQcRepairOptions {
            state_root: root.clone(),
            expected_height: 10,
            expected_qc_sha256: digest,
            source_qc_paths: vec![source_one, source_two],
            source_nodes: vec!["validator-2".to_string(), "validator-6".to_string()],
            block_path,
            dry_run: true,
            apply: false,
        })
        .unwrap();

        assert!(report.ok);
        assert!(!report.applied);
        assert_eq!(report.verified_qc_signers.len(), genesis_required_quorum());
        assert_eq!(report.original_qc_count, 2);
        assert_eq!(report.repaired_qc_count, 3);
        assert_eq!(
            fs::read_to_string(root.join("data/committed_qcs.jsonl"))
                .unwrap()
                .lines()
                .count(),
            2
        );
    }

    #[test]
    fn missing_qc_repair_rejects_invalid_aegis_vote_signature() {
        let root = temp_root("missing-qc-invalid-aegis");
        let (source_one, source_two, block_path, digest) = full_missing_qc_fixture(&root, true);

        let error = repair_missing_committed_qc(MissingQcRepairOptions {
            state_root: root,
            expected_height: 10,
            expected_qc_sha256: digest,
            source_qc_paths: vec![source_one, source_two],
            source_nodes: vec!["validator-2".to_string(), "validator-6".to_string()],
            block_path,
            dry_run: true,
            apply: false,
        })
        .unwrap_err();

        assert!(
            error.contains("invalid vote signature")
                || error.contains("signature verification failed")
                || error.contains("PQC"),
            "unexpected validation error: {error}"
        );
    }

    #[test]
    fn missing_qc_rewrite_inserts_only_the_exact_internal_gap() {
        let root = temp_root("missing-qc-exact-gap");
        let qcs = root.join("data/committed_qcs.jsonl");
        let repaired = root.join("data/committed_qcs.repaired.jsonl");
        let mut original = Vec::new();
        for (height, hash) in [(8, "h8"), (9, "h9"), (11, "h11"), (12, "h12")] {
            original.extend(compact_qc_line(height, hash));
        }
        fs::write(&qcs, &original).unwrap();
        let source = compact_qc_line(10, "h10");

        let summary = scan_and_rewrite_missing_qc(&qcs, 10, &source, Some(&repaired)).unwrap();

        assert_eq!(summary.original_count, 4);
        assert_eq!(summary.previous_hash, "h9");
        assert_eq!(summary.next_hash, "h11");
        assert_eq!(summary.original_sha256, sha256_bytes(&original));
        let repaired_bytes = fs::read(&repaired).unwrap();
        let heights = repaired_bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| {
                let value: Value = serde_json::from_slice(line).unwrap();
                committed_qc_summary_from_value(&value).unwrap().height
            })
            .collect::<Vec<_>>();
        assert_eq!(heights, vec![8, 9, 10, 11, 12]);
        assert_eq!(summary.repaired_sha256, sha256_bytes(&repaired_bytes));
    }

    #[test]
    fn missing_qc_rollback_restores_original_log_and_preserves_rejected_repair() {
        let root = temp_root("missing-qc-rollback");
        let qcs = root.join("data/committed_qcs.jsonl");
        let backup_dir = root.join("evidence/missing-qc-rollback");
        fs::create_dir_all(&backup_dir).unwrap();
        let backup_qcs = backup_dir.join("committed_qcs.before.jsonl");
        let original = compact_qc_line(9, "original-h9");
        let repaired = compact_qc_line(10, "repaired-h10");
        fs::write(&qcs, &repaired).unwrap();
        fs::write(&backup_qcs, &original).unwrap();

        let error = rollback_missing_qc_repair(
            &qcs,
            &backup_qcs,
            &backup_dir,
            "simulated post-swap failure".to_string(),
        );

        assert!(error.contains("was rolled back"), "{error}");
        assert_eq!(fs::read(&qcs).unwrap(), original);
        assert_eq!(
            fs::read(backup_dir.join("committed_qcs.rejected.jsonl")).unwrap(),
            repaired
        );
    }

    #[test]
    fn missing_qc_rewrite_rejects_duplicate_or_reordered_entries() {
        let root = temp_root("missing-qc-duplicate");
        let qcs = root.join("data/committed_qcs.jsonl");
        let mut original = Vec::new();
        for (height, hash) in [(8, "h8"), (9, "h9"), (9, "h9-duplicate"), (11, "h11")] {
            original.extend(compact_qc_line(height, hash));
        }
        fs::write(&qcs, original).unwrap();

        let error =
            scan_and_rewrite_missing_qc(&qcs, 10, &compact_qc_line(10, "h10"), None).unwrap_err();

        assert!(error.contains("duplicate or reordered"));
    }

    #[test]
    fn missing_qc_rewrite_rejects_any_additional_gap() {
        let root = temp_root("missing-qc-extra-gap");
        let qcs = root.join("data/committed_qcs.jsonl");
        let mut original = Vec::new();
        for (height, hash) in [(7, "h7"), (9, "h9"), (11, "h11")] {
            original.extend(compact_qc_line(height, hash));
        }
        fs::write(&qcs, original).unwrap();

        let error =
            scan_and_rewrite_missing_qc(&qcs, 10, &compact_qc_line(10, "h10"), None).unwrap_err();

        assert!(error.contains("unexpected gap"));
    }

    #[test]
    fn missing_qc_rewrite_rejects_existing_target_height() {
        let root = temp_root("missing-qc-existing");
        let qcs = root.join("data/committed_qcs.jsonl");
        let mut original = Vec::new();
        for (height, hash) in [(9, "h9"), (10, "h10"), (11, "h11")] {
            original.extend(compact_qc_line(height, hash));
        }
        fs::write(&qcs, original).unwrap();

        let error =
            scan_and_rewrite_missing_qc(&qcs, 10, &compact_qc_line(10, "h10"), None).unwrap_err();

        assert!(error.contains("already exists"));
    }

    fn write_recoverable_files(root: &Path) {
        for file in ALLOWED_STATE_FILES {
            let path = root.join("data").join(file);
            if !path.exists() {
                fs::write(path, format!("{file}\n")).unwrap();
            }
        }
    }

    #[test]
    fn preflight_upgrade_classifies_val1_compact_boundary_failure() {
        let root = temp_root("val1-compact-boundary-preflight");
        write_chain(
            &root,
            &[("boundary-h175518", 175_518), ("tip-h175519", 175_519)],
        );
        write_locks(&root, &[(175_520, "stale-lock-above-tip")]);
        fs::write(root.join("data/committed_qcs.jsonl"), "").unwrap();

        let report =
            preflight_validator_upgrade(&root, ValidatorUpgradePreflightOptions::default())
                .expect("preflight should return a report");

        assert!(!report.ok);
        assert_eq!(report.decision, "NO_GO");
        assert_eq!(report.first_retained_height, Some(175_518));
        assert_eq!(report.latest_height, Some(175_519));
        assert_eq!(report.locks_above_chain_tip.len(), 1);
        let codes = report
            .findings
            .iter()
            .map(|finding| &finding.code)
            .collect::<Vec<_>>();
        assert!(codes.contains(&&ValidatorUpgradePreflightCode::CompactBoundaryLockMissing));
        assert!(codes.contains(&&ValidatorUpgradePreflightCode::BoundaryCommittedQcMissing));
        assert!(codes.contains(&&ValidatorUpgradePreflightCode::CanonicalLocksAheadOfChainBody));
    }

    #[test]
    fn preflight_upgrade_rejects_stale_locks_above_tip_by_default() {
        let root = temp_root("stale-lock-default-no-go");
        write_chain(&root, &[("boundary-h10", 10), ("tip-h11", 11)]);
        write_locks(&root, &[(10, "boundary-h10"), (12, "stale-lock-above-tip")]);
        write_preflight_qc(&root, 10, "boundary-h10");

        let report =
            preflight_validator_upgrade(&root, ValidatorUpgradePreflightOptions::default())
                .expect("preflight should return a report");

        assert!(!report.ok);
        assert!(report.findings.iter().any(|finding| finding.code
            == ValidatorUpgradePreflightCode::CanonicalLocksAheadOfChainBody
            && finding.severity == ValidatorUpgradePreflightSeverity::Error));
    }

    #[test]
    fn preflight_upgrade_allows_stale_locks_when_boundary_qc_is_safe_and_rebuild_requested() {
        let root = temp_root("stale-lock-safe-rebuild");
        write_chain(&root, &[("boundary-h10", 10), ("tip-h11", 11)]);
        write_locks(&root, &[(10, "boundary-h10"), (12, "stale-lock-above-tip")]);
        write_preflight_qc(&root, 10, "boundary-h10");

        let report = preflight_validator_upgrade(
            &root,
            ValidatorUpgradePreflightOptions {
                allow_derived_index_rebuild: true,
                ..ValidatorUpgradePreflightOptions::default()
            },
        )
        .expect("preflight should return a report");

        assert!(report.ok);
        assert_eq!(report.decision, "GO");
        assert!(report.boundary_lock_present);
        assert!(report.boundary_committed_qc_present);
        assert_eq!(report.locks_above_chain_tip.len(), 1);
        assert!(report.findings.iter().any(|finding| finding.code
            == ValidatorUpgradePreflightCode::CanonicalLocksAheadOfChainBody
            && finding.severity == ValidatorUpgradePreflightSeverity::Warning));
    }

    fn signed_qc_fixture(
        signer_count: usize,
    ) -> (
        AegisPqvmSigner,
        ValidatorSet,
        ClusterMap,
        AegisQuorumCertificate,
    ) {
        let mut signer = AegisPqvmSigner::initialize_required().unwrap();
        let mut records = Vec::new();
        let mut key_ids = Vec::new();
        for index in 0..BASELINE_VALIDATOR_COUNT {
            let uma = format!("uma-{index}");
            let key_id = signer
                .generate_and_register_key(&uma, vec![AegisPqKeyRole::ConsensusVote], Epoch(0))
                .unwrap();
            let public = signer.public_key_record(&key_id).unwrap();
            records.push(crate::synergy_types::ValidatorRecord {
                validator_id: ValidatorId(format!("validator-{}", index + 1)),
                validator_uma_id: UmaId(uma),
                consensus_public_key: public.clone(),
                peer_public_key: public.clone(),
                operator_public_key: public,
                voting_weight: 1,
                status: ValidatorStatus::Active,
                cluster_id: ClusterId(0),
                activation_epoch: Epoch(0),
            });
            key_ids.push(key_id);
        }
        let set = ValidatorSet {
            epoch: Epoch(0),
            validators: records.clone(),
        };
        let cluster = ClusterMap {
            epoch: Epoch(0),
            assignments: records
                .iter()
                .map(|record| ClusterAssignment {
                    cluster_id: ClusterId(0),
                    validator_id: record.validator_id.clone(),
                })
                .collect(),
        };
        let set_hash = set.hash().unwrap();
        let cluster_hash = cluster.hash().unwrap();
        let block_id = BlockId::from("majority-hash");
        let votes = (0..signer_count)
            .map(|index| {
                let mut vote = Vote {
                    chain_id: ChainId::synergy_testnet_v3(),
                    network_id: NetworkId::synergy_testnet_v3(),
                    height: Height(10),
                    round: Round(0),
                    epoch: Epoch(0),
                    cluster_id: ClusterId(0),
                    phase: VotePhase::Commit,
                    block_id: block_id.clone(),
                    validator_id: records[index].validator_id.clone(),
                    validator_uma_id: records[index].validator_uma_id.clone(),
                    key_id: key_ids[index].clone(),
                    active_validator_set_hash: set_hash,
                    cluster_map_hash: cluster_hash,
                    aegis_pq_signature: crate::synergy_types::AegisPqSignature {
                        algorithm: String::new(),
                        signature_bytes: Vec::new(),
                    },
                };
                vote.aegis_pq_signature = signer
                    .sign_vote(&vote.signing_bytes().unwrap(), &key_ids[index])
                    .unwrap();
                vote
            })
            .collect::<Vec<_>>();
        let qc = AegisQuorumCertificate {
            qc_version: 1,
            chain_id: ChainId::synergy_testnet_v3(),
            network_id: NetworkId::synergy_testnet_v3(),
            height: Height(10),
            round: Round(0),
            epoch: Epoch(0),
            cluster_id: ClusterId(0),
            phase: VotePhase::Commit,
            block_id,
            active_validator_set_hash: set_hash,
            cluster_map_hash: cluster_hash,
            threshold_weight_required: genesis_required_quorum() as u64,
            signed_weight: signer_count as u64,
            signer_bitmap: vec![((1u16 << signer_count) - 1) as u8],
            aegis_pq_signatures: votes
                .iter()
                .map(|vote| vote.aegis_pq_signature.clone())
                .collect(),
            aegis_pq_key_ids: key_ids[0..signer_count].to_vec(),
        };
        (signer, set, cluster, qc)
    }

    fn write_proof(
        root: &Path,
        qc: &AegisQuorumCertificate,
        set: &ValidatorSet,
        cluster: &ClusterMap,
    ) {
        fs::write(
            root.join("recovery-proof.json"),
            serde_json::to_string(&json!({
                "chain_id": SYNERGY_TESTNET_V3_CHAIN_ID,
                "network_id": SYNERGY_TESTNET_V3_NETWORK_ID,
                "genesis_hash": EXPECTED_GENESIS_HASH,
                "source_nodes_used": (1..=genesis_required_quorum())
                    .map(|index| format!("validator-{index}"))
                    .collect::<Vec<_>>(),
                "source_common_height": 10,
                "source_common_hash": "majority-hash",
                "source_canonical_lock_height": 10,
                "source_canonical_lock_hash": "majority-hash",
                "qc": qc,
                "validator_set": set,
                "cluster_map": cluster,
            }))
            .unwrap(),
        )
        .unwrap();
    }

    fn write_legacy_qc_fixture(root: &Path, signer_count: usize) {
        write_legacy_qc_fixture_at_heights(root, signer_count, &[(10, "majority-hash")]);
    }

    fn write_legacy_qc_fixture_at_heights(
        root: &Path,
        signer_count: usize,
        heights: &[(u64, &str)],
    ) {
        let mut manager = PQCManager::new();
        let mut validators = serde_json::Map::new();
        let mut keys = Vec::new();
        for index in 0..BASELINE_VALIDATOR_COUNT {
            let address = format!("synv11testvalidator{index}");
            let (public_key, private_key) = manager.generate_keypair(PQCAlgorithm::FNDSA).unwrap();
            validators.insert(
                address.clone(),
                json!({
                    "address": address,
                    "status": "Active",
                    "public_key": format!(
                        "fn-dsa:{}",
                        general_purpose::STANDARD.encode(&public_key.key_data)
                    ),
                    "synergy_score": 100.0,
                    "cluster_id": 0,
                }),
            );
            keys.push((address, public_key, private_key));
        }
        fs::write(
            root.join("data/validator_registry.json"),
            json!({
                "validators": validators,
                "clusters": {"0": []},
                "current_epoch": 0,
            })
            .to_string(),
        )
        .unwrap();

        let mut lines = String::new();
        for (height, block_hash) in heights {
            let votes = keys
                .iter()
                .take(signer_count)
                .map(|(address, public_key, private_key)| {
                    let payload = format!("{address}:{height}:0:{block_hash}:0");
                    let signature = manager.sign(private_key, payload.as_bytes()).unwrap();
                    json!({
                        "validator_address": address,
                        "block_hash": block_hash,
                        "block_index": height,
                        "epoch_number": 0,
                        "round_number": 0,
                        "signature": signature,
                        "signer_public_key": public_key.key_data,
                        "timestamp": 100,
                    })
                })
                .collect::<Vec<_>>();
            let qc = json!({
                "block_hash": block_hash,
                "epoch_number": 0,
                "round_number": 0,
                "aggregate_signature": [1, 2, 3, 4],
                "participant_bitmap": [15],
                "cumulative_weight": signer_count as f64,
                "validation_quorum_met": true,
                "cooperation_quorum_met": true,
                "timestamp": 100,
                "votes": votes,
            });
            lines.push_str(
                &(serde_json::to_string(&json!({"block_hash": block_hash, "qc": qc})).unwrap()
                    + "\n"),
            );
        }
        fs::write(root.join("data/committed_qcs.jsonl"), lines).unwrap();
    }

    #[test]
    fn legacy_qc_verification_accepts_unprefixed_fndsa_keys_and_ignores_synergy_score() {
        let root = temp_root("legacy-unprefixed-validator-keys");
        let mut manager = PQCManager::new();
        let mut validators = serde_json::Map::new();
        let mut keys = Vec::new();
        let height = 10;
        let block_hash = "legacy-unprefixed-majority-hash";
        let signer_count = genesis_required_quorum();

        for index in 0..BASELINE_VALIDATOR_COUNT {
            let address = format!("synv11testvalidator{index}");
            let (public_key, private_key) = manager.generate_keypair(PQCAlgorithm::FNDSA).unwrap();
            validators.insert(
                address.clone(),
                json!({
                    "address": address,
                    "status": "Active",
                    "public_key": general_purpose::STANDARD.encode(&public_key.key_data),
                    "synergy_score": if index < signer_count { 1.0 } else { 100.0 },
                    "cluster_id": 0,
                }),
            );
            keys.push((address, public_key, private_key));
        }
        fs::write(
            root.join("data/validator_registry.json"),
            json!({
                "validators": validators,
                "clusters": {"0": []},
                "current_epoch": 0,
            })
            .to_string(),
        )
        .unwrap();

        let votes = keys
            .iter()
            .take(signer_count)
            .map(|(address, public_key, private_key)| {
                let payload = format!("{address}:{height}:0:{block_hash}:0");
                let signature = manager.sign(private_key, payload.as_bytes()).unwrap();
                json!({
                    "validator_address": address,
                    "block_hash": block_hash,
                    "block_index": height,
                    "epoch_number": 0,
                    "round_number": 0,
                    "signature": signature,
                    "signer_public_key": public_key.key_data,
                    "timestamp": 100,
                })
            })
            .collect::<Vec<_>>();
        fs::write(
            root.join("data/committed_qcs.jsonl"),
            serde_json::to_string(&json!({
                "block_hash": block_hash,
                "qc": {
                    "block_hash": block_hash,
                    "epoch_number": 0,
                    "round_number": 0,
                    "aggregate_signature": [1, 2, 3, 4],
                    "participant_bitmap": [15],
                    "cumulative_weight": signer_count as f64,
                    "validation_quorum_met": true,
                    "cooperation_quorum_met": true,
                    "timestamp": 100,
                    "votes": votes,
                }
            }))
            .unwrap()
                + "\n",
        )
        .unwrap();

        let summary =
            verify_latest_committed_qc_in_state_dir_at_or_below(&root, height, None).unwrap();

        assert!(summary.verified);
        assert_eq!(summary.height, height);
        assert_eq!(summary.vote_count, signer_count as u64);
        assert_eq!(summary.hash, block_hash);
    }

    fn write_activation_dag_fixture(
        root: &Path,
        validator_address: &str,
        activation_tx_hash: &str,
        activation_block_height: u64,
    ) {
        fs::write(
            root.join("data/dag_state.json"),
            json!({
                "transaction_index": {
                    activation_tx_hash: "activation-node"
                },
                "vertices": {
                    "activation-node": {
                        "status": "committed",
                        "block_number": activation_block_height,
                        "height_hint": activation_block_height,
                        "transaction_hashes": [activation_tx_hash],
                        "transactions": [{
                            "data": format!(
                                "validator_activation:{}",
                                json!({"validator": validator_address}).to_string()
                            )
                        }]
                    }
                },
                "tips": [],
                "latest_committed_block": activation_block_height,
            })
            .to_string(),
        )
        .unwrap();
    }

    #[test]
    fn post_fork_qc_verification_requires_five_of_six_quorum_for_expanded_set() {
        let root = temp_root("post-fork-untyped-registry-qc");
        fs::create_dir_all(root.join("config")).unwrap();
        let mut manager = PQCManager::new();
        let mut validators = serde_json::Map::new();
        let mut registry = Vec::new();
        let mut keys = Vec::new();
        for index in 0..=BASELINE_VALIDATOR_COUNT {
            let address = format!("synv11postforkvalidator{index}");
            let (public_key, private_key) = manager.generate_keypair(PQCAlgorithm::FNDSA).unwrap();
            let encoded = general_purpose::STANDARD.encode(&public_key.key_data);
            validators.insert(
                address.clone(),
                json!({
                    "address": address,
                    "status": "Active",
                    "public_key": encoded,
                    "synergy_score": 100.0,
                    "cluster_id": 0,
                }),
            );
            registry.push(json!({
                "validator_address": address,
                "consensus_key_type": "FN-DSA",
                "consensus_public_key": encoded,
            }));
            keys.push((address, public_key, private_key));
        }
        fs::write(
            root.join("data/validator_registry.json"),
            json!({
                "validators": validators,
                "clusters": {"0": []},
                "current_epoch": 0,
            })
            .to_string(),
        )
        .unwrap();
        let fork_path = root.join("config/consensus-fork-migration.json");
        fs::write(
            &fork_path,
            serde_json::to_vec_pretty(&json!({
                "fork_height": 204216,
                "parent_height": 204215,
                "parent_hash": "e209bd7554a06dfb052d5ff7ffd5664efc05e6cd1c5cadc9d139fa5bb9072816",
                "state_root": "test-state-root",
                "old_consensus_algorithm": "FN-DSA",
                "new_consensus_algorithm": "FN-DSA",
                "new_validator_registry": registry,
                "migration_reason": "test post-fork QC verification",
                "parser_mode": "fail_closed",
            }))
            .unwrap(),
        )
        .unwrap();

        let height = 204216;
        let block_hash = "post-fork-majority-hash";
        let required_quorum = required_validator_quorum(keys.len());
        assert_eq!(required_quorum, 5);
        let votes = keys
            .iter()
            .take(required_quorum)
            .map(|(address, public_key, private_key)| {
                let payload = format!("{address}:{height}:0:{block_hash}:0");
                let signature = manager.sign(private_key, payload.as_bytes()).unwrap();
                json!({
                    "validator_address": address,
                    "block_hash": block_hash,
                    "block_index": height,
                    "epoch_number": 0,
                    "round_number": 0,
                    "signature": signature,
                    "signer_public_key": public_key.key_data,
                    "timestamp": 100,
                })
            })
            .collect::<Vec<_>>();
        fs::write(
            root.join("data/committed_qcs.jsonl"),
            serde_json::to_string(&json!({
                "block_hash": block_hash,
                "qc": {
                    "block_hash": block_hash,
                    "epoch_number": 0,
                    "round_number": 0,
                    "aggregate_signature": [1, 2, 3, 4],
                    "participant_bitmap": [15],
                    "cumulative_weight": required_quorum as f64,
                    "validation_quorum_met": true,
                    "cooperation_quorum_met": true,
                    "timestamp": 100,
                    "votes": votes,
                }
            }))
            .unwrap()
                + "\n",
        )
        .unwrap();

        let previous_fork = std::env::var(consensus_fork::CONSENSUS_FORK_MIGRATION_ENV).ok();
        std::env::set_var(consensus_fork::CONSENSUS_FORK_MIGRATION_ENV, &fork_path);
        let result = verify_latest_committed_qc_in_state_dir_at_or_below(&root, height, None);
        match previous_fork {
            Some(value) => std::env::set_var(consensus_fork::CONSENSUS_FORK_MIGRATION_ENV, value),
            None => std::env::remove_var(consensus_fork::CONSENSUS_FORK_MIGRATION_ENV),
        }

        let summary = result.expect("five-of-six quorum must satisfy current Testnet QC");
        assert_eq!(summary.vote_count, required_quorum as u64);
        assert_eq!(summary.height, height);
    }

    #[test]
    fn post_fork_qc_verification_accepts_later_activated_validator_signer() {
        let root = temp_root("post-fork-activated-validator-qc");
        fs::create_dir_all(root.join("config")).unwrap();
        let mut manager = PQCManager::new();
        let mut validators = serde_json::Map::new();
        let mut registry = Vec::new();
        let mut keys = Vec::new();
        let height = 205300;
        let activation_block_height = height - VALIDATOR_SHADOW_PHASE_BLOCKS - 1;
        let activation_tx_hash = "syntxn-later-activated-validator";
        let activated_validator_address =
            format!("synv11postforkvalidator{BASELINE_VALIDATOR_COUNT}");

        for index in 0..=BASELINE_VALIDATOR_COUNT {
            let address = format!("synv11postforkvalidator{index}");
            let (public_key, private_key) = manager.generate_keypair(PQCAlgorithm::FNDSA).unwrap();
            let encoded = general_purpose::STANDARD.encode(&public_key.key_data);
            let mut record = json!({
                "address": address,
                "status": "Active",
                "public_key": encoded,
                "synergy_score": 100.0,
                "cluster_id": 0,
            });
            if index == BASELINE_VALIDATOR_COUNT {
                record["activation_tx_hash"] = json!(activation_tx_hash);
                record["last_vote_timestamp"] = json!(100);
                record["total_transactions_validated"] = json!(1);
            } else {
                record["consensus_key_type"] = json!("FN-DSA");
                registry.push(json!({
                    "validator_address": address,
                    "consensus_key_type": "FN-DSA",
                    "consensus_public_key": encoded,
                }));
            }
            validators.insert(address.clone(), record);
            keys.push((address, public_key, private_key));
        }
        fs::write(
            root.join("data/validator_registry.json"),
            json!({
                "validators": validators,
                "clusters": {"0": []},
                "current_epoch": 0,
            })
            .to_string(),
        )
        .unwrap();
        let fork_path = root.join("config/consensus-fork-migration.json");
        fs::write(
            &fork_path,
            serde_json::to_vec_pretty(&json!({
                "fork_height": 204216,
                "parent_height": 204215,
                "parent_hash": "e209bd7554a06dfb052d5ff7ffd5664efc05e6cd1c5cadc9d139fa5bb9072816",
                "state_root": "test-state-root",
                "old_consensus_algorithm": "FN-DSA",
                "new_consensus_algorithm": "FN-DSA",
                "new_validator_registry": registry,
                "migration_reason": "test later activated validator QC verification",
                "parser_mode": "fail_closed",
            }))
            .unwrap(),
        )
        .unwrap();
        write_activation_dag_fixture(
            &root,
            &activated_validator_address,
            activation_tx_hash,
            activation_block_height,
        );

        let block_hash = "post-fork-activated-validator-hash";
        let signer_indices = [0usize, 1, 2, 3, BASELINE_VALIDATOR_COUNT];
        let votes = signer_indices
            .iter()
            .map(|index| {
                let (address, public_key, private_key) = &keys[*index];
                let payload = format!("{address}:{height}:0:{block_hash}:0");
                let signature = manager.sign(private_key, payload.as_bytes()).unwrap();
                json!({
                    "validator_address": address,
                    "block_hash": block_hash,
                    "block_index": height,
                    "epoch_number": 0,
                    "round_number": 0,
                    "signature": signature,
                    "signer_public_key": public_key.key_data,
                    "timestamp": 100,
                })
            })
            .collect::<Vec<_>>();
        fs::write(
            root.join("data/committed_qcs.jsonl"),
            serde_json::to_string(&json!({
                "block_hash": block_hash,
                "qc": {
                    "block_hash": block_hash,
                    "epoch_number": 0,
                    "round_number": 0,
                    "aggregate_signature": [1, 2, 3, 4],
                    "participant_bitmap": [15],
                    "cumulative_weight": signer_indices.len() as f64,
                    "validation_quorum_met": true,
                    "cooperation_quorum_met": true,
                    "timestamp": 100,
                    "votes": votes,
                }
            }))
            .unwrap()
                + "\n",
        )
        .unwrap();

        let previous_fork = std::env::var(consensus_fork::CONSENSUS_FORK_MIGRATION_ENV).ok();
        std::env::set_var(consensus_fork::CONSENSUS_FORK_MIGRATION_ENV, &fork_path);
        let result = verify_latest_committed_qc_in_state_dir_at_or_below(&root, height, None);
        match previous_fork {
            Some(value) => std::env::set_var(consensus_fork::CONSENSUS_FORK_MIGRATION_ENV, value),
            None => std::env::remove_var(consensus_fork::CONSENSUS_FORK_MIGRATION_ENV),
        }

        let summary = result.unwrap();
        assert!(summary.verified);
        assert_eq!(summary.height, height);
        assert_eq!(summary.vote_count, signer_indices.len() as u64);
        assert_eq!(summary.hash, block_hash);
        assert!(summary.signers.contains(&activated_validator_address));
    }

    #[test]
    fn post_fork_qc_verification_ignores_activated_validator_without_consensus_participation() {
        let root = temp_root("post-fork-activated-nonparticipant-qc");
        fs::create_dir_all(root.join("config")).unwrap();
        let mut manager = PQCManager::new();
        let mut validators = serde_json::Map::new();
        let mut registry = Vec::new();
        let mut keys = Vec::new();
        let height = 760_908;
        let activated_validator_address =
            format!("synv11postforkvalidator{}", BASELINE_VALIDATOR_COUNT + 1);

        for index in 0..=(BASELINE_VALIDATOR_COUNT + 1) {
            let address = format!("synv11postforkvalidator{index}");
            let (public_key, private_key) = manager.generate_keypair(PQCAlgorithm::FNDSA).unwrap();
            let encoded = general_purpose::STANDARD.encode(&public_key.key_data);
            let mut record = json!({
                "address": address,
                "status": "Active",
                "public_key": encoded,
                "synergy_score": 100.0,
                "cluster_id": 0,
            });
            if index == BASELINE_VALIDATOR_COUNT + 1 {
                record["activation_effective_height"] = json!(height - 100);
                record["last_vote_timestamp"] = json!(0);
                record["total_blocks_produced"] = json!(0);
                record["total_transactions_validated"] = json!(0);
            } else {
                registry.push(json!({
                    "validator_address": address,
                    "consensus_key_type": "FN-DSA",
                    "consensus_public_key": encoded,
                }));
            }
            validators.insert(address.clone(), record);
            keys.push((address, public_key, private_key));
        }
        fs::write(
            root.join("data/validator_registry.json"),
            json!({
                "validators": validators,
                "clusters": {"0": []},
                "current_epoch": 0,
            })
            .to_string(),
        )
        .unwrap();
        let fork_path = root.join("config/consensus-fork-migration.json");
        fs::write(
            &fork_path,
            serde_json::to_vec_pretty(&json!({
                "fork_height": 204216,
                "parent_height": 204215,
                "parent_hash": "e209bd7554a06dfb052d5ff7ffd5664efc05e6cd1c5cadc9d139fa5bb9072816",
                "state_root": "test-state-root",
                "old_consensus_algorithm": "FN-DSA",
                "new_consensus_algorithm": "FN-DSA",
                "new_validator_registry": registry,
                "migration_reason": "test activated nonparticipant QC verification",
                "parser_mode": "fail_closed",
            }))
            .unwrap(),
        )
        .unwrap();

        let block_hash = "post-fork-activated-nonparticipant-hash";
        let required_quorum = required_validator_quorum(BASELINE_VALIDATOR_COUNT + 1);
        assert_eq!(required_quorum, 4);
        let votes = keys
            .iter()
            .take(required_quorum)
            .map(|(address, public_key, private_key)| {
                let payload = format!("{address}:{height}:0:{block_hash}:0");
                let signature = manager.sign(private_key, payload.as_bytes()).unwrap();
                json!({
                    "validator_address": address,
                    "block_hash": block_hash,
                    "block_index": height,
                    "epoch_number": 0,
                    "round_number": 0,
                    "signature": signature,
                    "signer_public_key": public_key.key_data,
                    "timestamp": 100,
                })
            })
            .collect::<Vec<_>>();
        fs::write(
            root.join("data/committed_qcs.jsonl"),
            serde_json::to_string(&json!({
                "block_hash": block_hash,
                "qc": {
                    "block_hash": block_hash,
                    "epoch_number": 0,
                    "round_number": 0,
                    "aggregate_signature": [1, 2, 3, 4],
                    "participant_bitmap": [15],
                    "cumulative_weight": required_quorum as f64,
                    "validation_quorum_met": true,
                    "cooperation_quorum_met": true,
                    "timestamp": 100,
                    "votes": votes,
                }
            }))
            .unwrap()
                + "\n",
        )
        .unwrap();

        let previous_fork = std::env::var(consensus_fork::CONSENSUS_FORK_MIGRATION_ENV).ok();
        std::env::set_var(consensus_fork::CONSENSUS_FORK_MIGRATION_ENV, &fork_path);
        let result = verify_latest_committed_qc_in_state_dir_at_or_below(&root, height, None);
        match previous_fork {
            Some(value) => std::env::set_var(consensus_fork::CONSENSUS_FORK_MIGRATION_ENV, value),
            None => std::env::remove_var(consensus_fork::CONSENSUS_FORK_MIGRATION_ENV),
        }

        let summary = result.unwrap();
        assert!(summary.verified);
        assert_eq!(summary.height, height);
        assert_eq!(summary.vote_count, required_quorum as u64);
        assert!(!summary.signers.contains(&activated_validator_address));
        assert_eq!(summary.active_validator_count, BASELINE_VALIDATOR_COUNT + 1);
    }

    #[test]
    fn post_fork_qc_verification_rejects_unactivated_extra_validator() {
        let root = temp_root("post-fork-unactivated-validator-qc");
        fs::create_dir_all(root.join("config")).unwrap();
        let mut manager = PQCManager::new();
        let mut validators = serde_json::Map::new();
        let mut registry = Vec::new();
        let mut keys = Vec::new();
        let height = 204300;

        for index in 0..=BASELINE_VALIDATOR_COUNT {
            let address = format!("synv11postforkvalidator{index}");
            let (public_key, private_key) = manager.generate_keypair(PQCAlgorithm::FNDSA).unwrap();
            let encoded = general_purpose::STANDARD.encode(&public_key.key_data);
            validators.insert(
                address.clone(),
                json!({
                    "address": address,
                    "status": "Active",
                    "public_key": encoded,
                    "consensus_key_type": "FN-DSA",
                    "synergy_score": 100.0,
                    "cluster_id": 0,
                }),
            );
            if index < BASELINE_VALIDATOR_COUNT {
                registry.push(json!({
                    "validator_address": address,
                    "consensus_key_type": "FN-DSA",
                    "consensus_public_key": encoded,
                }));
            }
            keys.push((address, public_key, private_key));
        }
        fs::write(
            root.join("data/validator_registry.json"),
            json!({
                "validators": validators,
                "clusters": {"0": []},
                "current_epoch": 0,
            })
            .to_string(),
        )
        .unwrap();
        let fork_path = root.join("config/consensus-fork-migration.json");
        fs::write(
            &fork_path,
            serde_json::to_vec_pretty(&json!({
                "fork_height": 204216,
                "parent_height": 204215,
                "parent_hash": "e209bd7554a06dfb052d5ff7ffd5664efc05e6cd1c5cadc9d139fa5bb9072816",
                "state_root": "test-state-root",
                "old_consensus_algorithm": "FN-DSA",
                "new_consensus_algorithm": "FN-DSA",
                "new_validator_registry": registry,
                "migration_reason": "test unactivated validator rejection",
                "parser_mode": "fail_closed",
            }))
            .unwrap(),
        )
        .unwrap();

        let block_hash = "post-fork-unactivated-validator-hash";
        let signer_indices = [0usize, 1, 2, 3, BASELINE_VALIDATOR_COUNT];
        let votes = signer_indices
            .iter()
            .map(|index| {
                let (address, public_key, private_key) = &keys[*index];
                let payload = format!("{address}:{height}:0:{block_hash}:0");
                let signature = manager.sign(private_key, payload.as_bytes()).unwrap();
                json!({
                    "validator_address": address,
                    "block_hash": block_hash,
                    "block_index": height,
                    "epoch_number": 0,
                    "round_number": 0,
                    "signature": signature,
                    "signer_public_key": public_key.key_data,
                    "timestamp": 100,
                })
            })
            .collect::<Vec<_>>();
        fs::write(
            root.join("data/committed_qcs.jsonl"),
            serde_json::to_string(&json!({
                "block_hash": block_hash,
                "qc": {
                    "block_hash": block_hash,
                    "epoch_number": 0,
                    "round_number": 0,
                    "aggregate_signature": [1, 2, 3, 4],
                    "participant_bitmap": [15],
                    "cumulative_weight": signer_indices.len() as f64,
                    "validation_quorum_met": true,
                    "cooperation_quorum_met": true,
                    "timestamp": 100,
                    "votes": votes,
                }
            }))
            .unwrap()
                + "\n",
        )
        .unwrap();

        let previous_fork = std::env::var(consensus_fork::CONSENSUS_FORK_MIGRATION_ENV).ok();
        std::env::set_var(consensus_fork::CONSENSUS_FORK_MIGRATION_ENV, &fork_path);
        let result = verify_latest_committed_qc_in_state_dir_at_or_below(&root, height, None);
        match previous_fork {
            Some(value) => std::env::set_var(consensus_fork::CONSENSUS_FORK_MIGRATION_ENV, value),
            None => std::env::remove_var(consensus_fork::CONSENSUS_FORK_MIGRATION_ENV),
        }

        let error = result.unwrap_err();
        assert!(error.contains("has no activation_effective_height or activation_tx_hash"));
    }

    #[test]
    fn committed_qc_selection_is_bounded_by_persisted_chain_tip() {
        let root = temp_root("bounded-qc");
        write_legacy_qc_fixture_at_heights(
            &root,
            genesis_required_quorum(),
            &[(10, "hash-10"), (11, "hash-11"), (12, "hash-12")],
        );

        let summary = verify_latest_committed_qc_in_state_dir_at_or_below(&root, 11, None).unwrap();

        assert!(summary.verified);
        assert_eq!(summary.height, 11);
        assert_eq!(summary.hash, "hash-11");
        assert_eq!(summary.vote_count, genesis_required_quorum() as u64);
    }

    fn base_input(target: &Path, source: &Path) -> BuildPlanInput {
        BuildPlanInput {
            target_node_id: "Val1".to_string(),
            target_role: TargetRole::Validator,
            chain_id: SYNERGY_TESTNET_V3_CHAIN_ID,
            network_id: SYNERGY_TESTNET_V3_NETWORK_ID.to_string(),
            genesis_hash: EXPECTED_GENESIS_HASH.to_string(),
            target_data_dir: target.to_path_buf(),
            source_state_dir: Some(source.to_path_buf()),
            source_evidence_dirs: Vec::new(),
            source_nodes_used: (1..=genesis_required_quorum())
                .map(|index| format!("validator-{index}"))
                .collect(),
            source_common_height: Some(10),
            source_common_hash: Some("majority-hash".to_string()),
            source_canonical_lock_height: Some(10),
            source_canonical_lock_hash: Some("majority-hash".to_string()),
            target_runtime_sha256: "runtime-sha".to_string(),
            evidence_path: target.join("evidence"),
            rollback_path: target.join("rollback"),
            recovery_type: None,
            conflict_height: Some(10),
            expected_target_conflict_hash: Some("minority-hash".to_string()),
            expected_source_conflict_hash: Some("majority-hash".to_string()),
            target_stopped_or_quarantined: true,
        }
    }

    fn prepare_plan() -> (PathBuf, PathBuf, RecoveryPlan) {
        let target = temp_root("target");
        let source = temp_root("source");
        write_chain(&target, &[("minority-hash", 10)]);
        write_lock(&target, 10, "minority-hash");
        write_chain(&source, &[("majority-hash", 10)]);
        write_lock(&source, 10, "majority-hash");
        write_recoverable_files(&source);
        write_legacy_qc_fixture(&source, genesis_required_quorum());
        let (_signer, set, cluster, qc) = signed_qc_fixture(genesis_required_quorum());
        write_proof(&source, &qc, &set, &cluster);
        let plan = build_plan(base_input(&target, &source));
        (target, source, plan)
    }

    #[test]
    fn plan_uses_canonical_lock_for_conflict_hash_when_block_missing() {
        let target = temp_root("lock-only-target");
        let source = temp_root("lock-only-source");
        write_chain(&target, &[("old-target-tip", 9)]);
        write_lock(&target, 10, "minority-hash");
        write_chain(&source, &[("majority-hash", 10)]);
        write_lock(&source, 10, "majority-hash");
        write_recoverable_files(&source);
        write_legacy_qc_fixture(&source, genesis_required_quorum());
        let (_signer, set, cluster, qc) = signed_qc_fixture(genesis_required_quorum());
        write_proof(&source, &qc, &set, &cluster);

        let plan = build_plan(base_input(&target, &source));

        assert_eq!(plan.target_canonical_lock_hash, "minority-hash");
        assert!(plan.failure_reason.is_none());
        assert!(!plan.operator_approval_required);
    }

    #[test]
    fn plan_uses_canonical_lock_for_conflict_hash_when_chain_lacks_height() {
        let target = temp_root("chain-short-target");
        let source = temp_root("chain-short-source");
        write_chain(&target, &[("old-target-tip", 9)]);
        write_lock(&target, 10, "minority-hash");
        write_chain(&source, &[("majority-hash", 10)]);
        write_lock(&source, 10, "majority-hash");
        write_recoverable_files(&source);
        write_legacy_qc_fixture(&source, genesis_required_quorum());
        let (_signer, set, cluster, qc) = signed_qc_fixture(genesis_required_quorum());
        write_proof(&source, &qc, &set, &cluster);

        let plan = build_plan(base_input(&target, &source));

        assert_eq!(plan.target_canonical_lock_hash, "minority-hash");
        assert!(plan.failure_reason.is_none());
        assert!(!plan.operator_approval_required);
    }

    #[test]
    fn plan_rejects_wrong_chain_id() {
        let (target, source, _) = prepare_plan();
        let mut input = base_input(&target, &source);
        input.chain_id = 1;
        let plan = build_plan(input);
        assert!(plan.failure_reason.unwrap().contains("wrong chain_id"));
    }

    #[test]
    fn plan_rejects_wrong_network_id() {
        let (target, source, _) = prepare_plan();
        let mut input = base_input(&target, &source);
        input.network_id = "wrong".to_string();
        let plan = build_plan(input);
        assert!(plan.failure_reason.unwrap().contains("wrong network_id"));
    }

    #[test]
    fn plan_rejects_wrong_genesis_hash() {
        let (target, source, _) = prepare_plan();
        let mut input = base_input(&target, &source);
        input.genesis_hash = "bad".to_string();
        let plan = build_plan(input);
        assert!(plan.failure_reason.unwrap().contains("wrong genesis_hash"));
    }

    #[test]
    fn plan_rejects_qc_with_invalid_aegis_signature() {
        let target = temp_root("invalid-sig-target");
        let source = temp_root("invalid-sig-source");
        write_chain(&target, &[("minority-hash", 10)]);
        write_lock(&target, 10, "minority-hash");
        write_chain(&source, &[("majority-hash", 10)]);
        write_lock(&source, 10, "majority-hash");
        write_recoverable_files(&source);
        let (_signer, set, cluster, mut qc) = signed_qc_fixture(genesis_required_quorum());
        qc.aegis_pq_signatures[0].signature_bytes[0] ^= 1;
        write_proof(&source, &qc, &set, &cluster);
        let plan = build_plan(base_input(&target, &source));
        assert!(!plan.source_qc_aegis_pqc_verified);
        assert!(plan.operator_approval_required);
    }

    #[test]
    fn plan_rejects_qc_with_duplicate_signer() {
        let (target, source, _) = prepare_plan();
        let mut input = base_input(&target, &source);
        input.source_nodes_used[1] = input.source_nodes_used[0].clone();
        let plan = build_plan(input);
        assert!(plan.failure_reason.unwrap().contains("duplicate"));
    }

    #[test]
    fn plan_rejects_qc_below_dynamic_quorum() {
        let target = temp_root("below-target");
        let source = temp_root("below-source");
        write_chain(&target, &[("minority-hash", 10)]);
        write_lock(&target, 10, "minority-hash");
        write_chain(&source, &[("majority-hash", 10)]);
        write_lock(&source, 10, "majority-hash");
        write_recoverable_files(&source);
        let (_signer, set, cluster, qc) = signed_qc_fixture(3);
        write_proof(&source, &qc, &set, &cluster);
        let plan = build_plan(base_input(&target, &source));
        assert!(verify_plan(&plan)
            .errors
            .iter()
            .any(|error| error.contains("below")));
    }

    #[test]
    fn plan_rejects_relayer_as_quorum_signer() {
        let (target, source, _) = prepare_plan();
        let mut input = base_input(&target, &source);
        input.source_nodes_used[3] = "Relayer-1".to_string();
        let plan = build_plan(input);
        assert!(plan
            .failure_reason
            .unwrap()
            .contains("non-validator source"));
    }

    #[test]
    fn plan_rejects_non_active_validator_as_quorum_signer() {
        let target = temp_root("inactive-target");
        let source = temp_root("inactive-source");
        write_chain(&target, &[("minority-hash", 10)]);
        write_lock(&target, 10, "minority-hash");
        write_chain(&source, &[("majority-hash", 10)]);
        write_lock(&source, 10, "majority-hash");
        write_recoverable_files(&source);
        let (_signer, mut set, cluster, qc) = signed_qc_fixture(genesis_required_quorum());
        set.validators[0].status = ValidatorStatus::Shadow;
        write_proof(&source, &qc, &set, &cluster);
        let plan = build_plan(base_input(&target, &source));
        assert!(!plan.source_qc_aegis_pqc_verified);
    }

    #[test]
    fn plan_preserves_keys_and_configs() {
        let (_target, _source, plan) = prepare_plan();
        assert!(plan
            .files_never_to_touch
            .iter()
            .any(|file| file.contains("config")));
        assert!(!plan
            .files_to_mutate
            .iter()
            .any(|path| path.contains("config")));
    }

    #[test]
    fn plan_reports_keys_or_configs_copied_false() {
        let (_target, _source, plan) = prepare_plan();
        assert!(!plan.keys_or_configs_copied);
    }

    #[test]
    fn plan_reports_canonical_locks_mutated_flag() {
        let (_target, _source, plan) = prepare_plan();
        assert!(plan.canonical_locks_mutated);
    }

    #[test]
    fn plan_reports_committed_qcs_mutated_flag() {
        let (_target, _source, plan) = prepare_plan();
        assert!(plan.committed_qcs_mutated);
    }

    #[test]
    fn validator_recovery_requires_target_stopped_or_quarantined() {
        let (target, source, _) = prepare_plan();
        let mut input = base_input(&target, &source);
        input.target_stopped_or_quarantined = false;
        let plan = build_plan(input);
        let plan_path = target.join("plan.json");
        write_plan(&plan, &plan_path).unwrap();
        let error = apply_plan(ApplyPlanInput {
            plan_path,
            confirm_target_stopped: false,
        })
        .unwrap_err();
        assert!(error.contains("target_stopped_or_quarantined"));
    }

    #[test]
    fn validator_recovery_rejects_unproven_majority_branch() {
        let target = temp_root("unproven-target");
        let source = temp_root("unproven-source");
        write_chain(&target, &[("minority-hash", 10)]);
        write_lock(&target, 10, "minority-hash");
        write_chain(&source, &[("majority-hash", 10)]);
        write_lock(&source, 10, "majority-hash");
        write_recoverable_files(&source);
        let plan = build_plan(base_input(&target, &source));
        assert!(!plan.majority_branch_proven);
        assert!(plan.operator_approval_required);
    }

    #[test]
    fn validator_recovery_accepts_proven_majority_branch() {
        let (_target, _source, plan) = prepare_plan();
        let verification = verify_plan(&plan);
        assert!(verification.errors.is_empty(), "{:?}", verification.errors);
        assert!(plan.majority_branch_proven);
    }

    #[test]
    fn validator_recovery_accepts_legacy_committed_qc_without_sidecar_proof() {
        let target = temp_root("legacy-target");
        let source = temp_root("legacy-source");
        write_chain(&target, &[("minority-hash", 10)]);
        write_lock(&target, 10, "minority-hash");
        write_chain(&source, &[("majority-hash", 10)]);
        write_lock(&source, 10, "majority-hash");
        write_recoverable_files(&source);
        write_legacy_qc_fixture(&source, genesis_required_quorum());
        let plan = build_plan(base_input(&target, &source));
        let verification = verify_plan(&plan);
        assert!(verification.errors.is_empty(), "{:?}", verification.errors);
        assert!(plan.source_qc_aegis_pqc_verified);
        assert!(plan.majority_branch_proven);
    }

    #[test]
    fn validator_recovery_rejects_proof_only_source_when_advancing_target() {
        let target = temp_root("proof-only-target");
        let source = temp_root("proof-only-source");
        write_chain(&target, &[("minority-hash", 5)]);
        write_lock(&target, 5, "minority-hash");
        write_lock(&source, 10, "majority-hash");
        write_legacy_qc_fixture(&source, genesis_required_quorum());
        let (_signer, set, cluster, qc) = signed_qc_fixture(genesis_required_quorum());
        write_proof(&source, &qc, &set, &cluster);

        let mut input = base_input(&target, &source);
        input.source_common_height = Some(10);
        input.source_common_hash = Some("majority-hash".to_string());
        input.source_canonical_lock_height = Some(10);
        input.source_canonical_lock_hash = Some("majority-hash".to_string());
        input.expected_target_conflict_hash = None;
        input.expected_source_conflict_hash = None;
        let plan = build_plan(input);

        let failure = plan.failure_reason.unwrap_or_default();
        assert!(
            failure.contains("source chain.json is required"),
            "{failure}"
        );
        assert!(plan.operator_approval_required);
    }

    #[test]
    fn validator_recovery_rejects_committed_qc_tail_that_cannot_bridge_target() {
        let target = temp_root("qc-tail-target");
        let source = temp_root("qc-tail-source");
        write_chain(&target, &[("target-tip", 5)]);
        write_lock(&target, 5, "target-tip");
        write_chain(&source, &[("majority-hash", 10)]);
        write_lock(&source, 10, "majority-hash");
        write_legacy_qc_fixture(&source, genesis_required_quorum());
        let (_signer, set, cluster, qc) = signed_qc_fixture(genesis_required_quorum());
        write_proof(&source, &qc, &set, &cluster);

        let mut input = base_input(&target, &source);
        input.source_common_height = Some(10);
        input.source_common_hash = Some("majority-hash".to_string());
        input.source_canonical_lock_height = Some(10);
        input.source_canonical_lock_hash = Some("majority-hash".to_string());
        input.expected_target_conflict_hash = None;
        input.expected_source_conflict_hash = None;
        let plan = build_plan(input);

        let failure = plan.failure_reason.unwrap_or_default();
        assert!(
            failure.contains("cannot bridge target height 5"),
            "{failure}"
        );
        assert!(plan.operator_approval_required);
    }

    #[test]
    fn relayer_recovery_accepts_verified_support_snapshot() {
        let (target, source, _) = prepare_plan();
        let mut input = base_input(&target, &source);
        input.target_role = TargetRole::Relayer;
        input.target_node_id = "Relayer-1".to_string();
        let plan = build_plan(input);
        assert_eq!(plan.recovery_type, RecoveryType::SupportChainFastSync);
        assert!(plan.majority_branch_proven);
    }

    #[test]
    fn relayer_recovery_rejects_wrong_genesis_snapshot() {
        let (target, source, _) = prepare_plan();
        let mut input = base_input(&target, &source);
        input.target_role = TargetRole::Relayer;
        input.genesis_hash = "wrong".to_string();
        let plan = build_plan(input);
        assert!(plan.failure_reason.unwrap().contains("wrong genesis_hash"));
    }

    #[test]
    fn apply_plan_refuses_invalid_plan() {
        let (target, source, _) = prepare_plan();
        let mut input = base_input(&target, &source);
        input.chain_id = 99;
        let plan = build_plan(input);
        let plan_path = target.join("invalid-plan.json");
        write_plan(&plan, &plan_path).unwrap();
        assert!(apply_plan(ApplyPlanInput {
            plan_path,
            confirm_target_stopped: true,
        })
        .is_err());
    }

    #[test]
    fn apply_plan_writes_evidence_before_mutation() {
        let (target, _source, plan) = prepare_plan();
        let plan_path = target.join("plan.json");
        write_plan(&plan, &plan_path).unwrap();
        let result = apply_plan(ApplyPlanInput {
            plan_path,
            confirm_target_stopped: true,
        })
        .unwrap();
        assert!(!result.files_backed_up.is_empty());
        assert!(target.join("evidence/target-before/chain.json").exists());
    }

    #[test]
    fn apply_plan_writes_rollback_backup() {
        let (target, _source, plan) = prepare_plan();
        let plan_path = target.join("plan.json");
        write_plan(&plan, &plan_path).unwrap();
        apply_plan(ApplyPlanInput {
            plan_path,
            confirm_target_stopped: true,
        })
        .unwrap();
        assert!(target.join("rollback/chain.json").exists());
    }

    #[test]
    fn recovered_validator_rejoin_requires_common_height_match() {
        let (_target, _source, plan) = prepare_plan();
        assert!(plan
            .postconditions
            .iter()
            .any(|condition| condition == "exact_common_height_match_required_before_rejoin"));
    }
}
