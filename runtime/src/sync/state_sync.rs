use crate::consensus_state::{ConsensusStateReport, ConsensusStateSeverity};
use crate::synergy_types::{ChainId, Hash, NetworkId, SYNERGY_TESTNET_V3_NETWORK_ID};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub const STATE_SYNC_PROTOCOL_VERSION: &str = "synergy-state-sync-v1";
pub const STATE_SYNC_OFFLINE_WORKSPACE_MARKER: &str = "STATE_SYNC_OFFLINE_WORKSPACE";
pub const STATE_SYNC_REPAIR_BUNDLE_DIR: &str = "state_sync_repair_bundle";
pub const STATE_SYNC_REPAIR_RECEIPT: &str = "state_sync_repair_receipt.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateSyncRequest {
    pub protocol_version: String,
    pub requesting_node_id: String,
    pub requesting_role: String,
    pub chain_id: u64,
    pub network_id: String,
    pub genesis_hash: String,
    pub local_height: u64,
    pub local_hash: String,
    pub target_height: u64,
    pub target_hash: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateSyncSourceProof {
    pub protocol_version: String,
    pub source_node_id: String,
    pub source_role: String,
    #[serde(default)]
    pub source_cluster_id: Option<String>,
    pub source_peer_quarantined: bool,
    pub chain_id: u64,
    pub network_id: String,
    pub genesis_hash: String,
    pub common_height: u64,
    pub common_hash: String,
    pub target_height: u64,
    pub target_hash: String,
    pub source_height: u64,
    pub source_hash: String,
    pub finalized_qc_aegis_pqc_verified: bool,
    pub parent_continuity_verified: bool,
    pub state_root_matches: bool,
    pub validator_set_hash: String,
    pub cluster_map_hash: String,
    pub protocol_config_hash: String,
    #[serde(default)]
    pub majority_branch_verified: bool,
    #[serde(default)]
    pub public_rpc_only: bool,
    #[serde(default)]
    pub atlas_only: bool,
    pub snapshot_class: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateSyncHeightSpan {
    pub start: u64,
    pub end: u64,
    pub count: u64,
}

impl StateSyncHeightSpan {
    fn covers(&self, start: u64, end: u64) -> bool {
        self.start <= start && self.end >= end && self.count >= end.saturating_sub(start) + 1
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateSyncTransferProof {
    pub transfer_id: String,
    pub complete: bool,
    pub block_bodies: Option<StateSyncHeightSpan>,
    pub committed_qcs: Option<StateSyncHeightSpan>,
    pub canonical_locks: Option<StateSyncHeightSpan>,
    pub transfer_content_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateSyncFinding {
    pub code: String,
    pub severity: ConsensusStateSeverity,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateSyncRepairPlan {
    pub ok: bool,
    pub decision: String,
    pub dry_run_only: bool,
    pub protocol_version: String,
    pub chain_id: u64,
    pub network_id: String,
    pub genesis_hash: String,
    pub requesting_node_id: String,
    pub source_node_id: String,
    pub source_role: String,
    pub source_cluster_id: Option<String>,
    pub local_height: u64,
    pub local_hash: String,
    pub target_height: u64,
    pub target_hash: String,
    pub transfer_id: String,
    pub transfer_content_sha256: String,
    pub validator_set_hash: String,
    pub cluster_map_hash: String,
    pub protocol_config_hash: String,
    pub majority_branch_verified: bool,
    pub files_to_verify: Vec<String>,
    pub actions: Vec<String>,
    pub findings: Vec<StateSyncFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateSyncRepairApplyOptions {
    pub dry_run: bool,
    pub apply: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateSyncRepairReceipt {
    pub format: String,
    pub created_at_unix: u64,
    pub plan_sha256: String,
    pub transfer_id: String,
    pub transfer_content_sha256: String,
    pub requesting_node_id: String,
    pub source_node_id: String,
    pub source_cluster_id: Option<String>,
    pub local_height: u64,
    pub target_height: u64,
    pub target_hash: String,
    pub workspace: String,
    pub backup_path: String,
    pub repaired_data_dir: String,
    pub derived_index_rebuilt: bool,
    pub qc_fabricated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateSyncRepairApplyReport {
    pub ok: bool,
    pub decision: String,
    pub dry_run: bool,
    pub applied: bool,
    pub workspace: String,
    pub backup_path: Option<String>,
    pub receipt_path: Option<String>,
    pub original_verification: ConsensusStateReport,
    pub repaired_verification: Option<ConsensusStateReport>,
    pub actions: Vec<String>,
    pub findings: Vec<StateSyncFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct StateSyncRepairBundleManifest {
    #[serde(default)]
    format: String,
    #[serde(default)]
    transfer_id: String,
    #[serde(default)]
    transfer_content_sha256: String,
    #[serde(default)]
    source_node_id: String,
    #[serde(default)]
    source_role: String,
    #[serde(default)]
    source_cluster_id: Option<String>,
    #[serde(default)]
    validator_set_digest: String,
    #[serde(default)]
    validator_set_hash: String,
    #[serde(default)]
    cluster_map_digest: String,
    #[serde(default)]
    cluster_map_hash: String,
    #[serde(default)]
    protocol_config_digest: String,
    #[serde(default)]
    protocol_config_hash: String,
    #[serde(default)]
    compatible_protocol_config_digests: Vec<String>,
    #[serde(default)]
    compatible_protocol_config_hashes: Vec<String>,
    #[serde(default)]
    majority_branch_verified: bool,
    #[serde(default)]
    finalized_qc_aegis_pqc_verified: bool,
    #[serde(default)]
    archive_contained: bool,
    #[serde(default)]
    archive_canonical: bool,
    #[serde(default)]
    public_rpc_only: bool,
    #[serde(default)]
    atlas_only: bool,
}

pub fn build_state_sync_repair_plan(
    request: &StateSyncRequest,
    source: &StateSyncSourceProof,
    transfer: &StateSyncTransferProof,
    local_state: Option<&ConsensusStateReport>,
) -> StateSyncRepairPlan {
    let mut findings = Vec::new();
    validate_request(request, &mut findings);
    validate_source_proof(request, source, &mut findings);
    validate_transfer(request, transfer, &mut findings);
    validate_local_state(request, local_state, &mut findings);

    let ok = !findings
        .iter()
        .any(|finding| finding.severity == ConsensusStateSeverity::Error);
    let repair_start = request.local_height.saturating_add(1);
    let actions = vec![
        "verify source proof against chain_id, network_id, genesis hash, common block, and target block".to_string(),
        format!("verify block bodies for h{repair_start}..h{}", request.target_height),
        format!("verify committed QC proof for h{repair_start}..h{}", request.target_height),
        format!("verify canonical lock proof for h{repair_start}..h{}", request.target_height),
        "verify parent continuity and state-root match before writing any chain state".to_string(),
        "dry-run only; no chain files are mutated by this plan".to_string(),
    ];

    StateSyncRepairPlan {
        ok,
        decision: if ok {
            "DRY_RUN_GO".to_string()
        } else {
            "NO_GO".to_string()
        },
        dry_run_only: true,
        protocol_version: STATE_SYNC_PROTOCOL_VERSION.to_string(),
        chain_id: request.chain_id,
        network_id: request.network_id.clone(),
        genesis_hash: request.genesis_hash.clone(),
        requesting_node_id: request.requesting_node_id.clone(),
        source_node_id: source.source_node_id.clone(),
        source_role: source.source_role.clone(),
        source_cluster_id: source.source_cluster_id.clone(),
        local_height: request.local_height,
        local_hash: request.local_hash.clone(),
        target_height: request.target_height,
        target_hash: request.target_hash.clone(),
        transfer_id: transfer.transfer_id.clone(),
        transfer_content_sha256: transfer.transfer_content_sha256.clone(),
        validator_set_hash: source.validator_set_hash.clone(),
        cluster_map_hash: source.cluster_map_hash.clone(),
        protocol_config_hash: source.protocol_config_hash.clone(),
        majority_branch_verified: source.majority_branch_verified,
        files_to_verify: vec![
            "chain.json".to_string(),
            "committed_qcs.jsonl".to_string(),
            "canonical_locks.json".to_string(),
        ],
        actions,
        findings,
    }
}

pub fn apply_state_sync_repair(
    plan: &StateSyncRepairPlan,
    workspace: &Path,
    options: StateSyncRepairApplyOptions,
) -> Result<StateSyncRepairApplyReport, String> {
    let original_verification = crate::consensus_state::verify_state(workspace);
    let workspace = workspace.to_path_buf();
    let data_dir = workspace.join("data");
    let bundle_dir = workspace.join(STATE_SYNC_REPAIR_BUNDLE_DIR);
    let mut actions = vec![
        "verify repair plan and source proof metadata".to_string(),
        "verify offline workspace marker and local state anchor".to_string(),
        "verify repair bundle body, QC, lock, manifest, and content digest".to_string(),
        "create backup of original data directory".to_string(),
        "stage repaired state in temporary workspace".to_string(),
        "verify staged state invariants and rebuild derived indexes".to_string(),
        "write repair receipt before committing staged state".to_string(),
        "atomically swap repaired state into workspace data directory".to_string(),
    ];
    let mut findings = Vec::new();

    validate_apply_mode(&options, &mut findings);
    validate_apply_plan(plan, &mut findings);
    validate_offline_workspace(&workspace, &data_dir, &mut findings);
    validate_current_anchor(&data_dir, &original_verification, plan, &mut findings);

    let manifest = read_bundle_manifest(&bundle_dir, &mut findings);
    let bundle = read_repair_bundle(&bundle_dir, &mut findings);
    if let Some(bundle) = bundle.as_ref() {
        validate_bundle_coverage(bundle, plan, &mut findings);
    }
    let bundle_content_sha256 = match sha256_repair_bundle(&bundle_dir) {
        Ok(hash) => Some(hash),
        Err(detail) => {
            findings.push(error("state_sync_repair_bundle_unhashable", detail));
            None
        }
    };
    if let Some(manifest) = manifest.as_ref() {
        validate_bundle_manifest(
            manifest,
            plan,
            bundle_content_sha256.as_deref(),
            &mut findings,
        );
    }

    if has_errors(&findings) {
        return Ok(StateSyncRepairApplyReport {
            ok: false,
            decision: "NO_GO".to_string(),
            dry_run: options.dry_run,
            applied: false,
            workspace: workspace.display().to_string(),
            backup_path: None,
            receipt_path: None,
            original_verification,
            repaired_verification: None,
            actions,
            findings,
        });
    }

    if options.dry_run {
        actions.push("dry-run only; original workspace was not mutated".to_string());
        return Ok(StateSyncRepairApplyReport {
            ok: true,
            decision: "DRY_RUN_GO".to_string(),
            dry_run: true,
            applied: false,
            workspace: workspace.display().to_string(),
            backup_path: None,
            receipt_path: None,
            original_verification,
            repaired_verification: None,
            actions,
            findings,
        });
    }

    let backup_dir = workspace.join(format!(
        "state-sync-backup-{}-{}",
        std::process::id(),
        current_unix_nanos()
    ));
    let temp_workspace = workspace.join(format!(
        ".state-sync-repair-tmp-{}-{}",
        std::process::id(),
        current_unix_nanos()
    ));
    let temp_data_dir = temp_workspace.join("data");

    copy_dir_all(&data_dir, &backup_dir.join("data"))?;
    copy_dir_all(&data_dir, &temp_data_dir)?;

    let apply_result = (|| -> Result<(ConsensusStateReport, StateSyncRepairReceipt), String> {
        stage_repaired_state(
            &temp_data_dir,
            bundle.as_ref().expect("bundle validated"),
            plan,
        )?;
        let staged_verification = crate::consensus_state::verify_state(&temp_workspace);
        if !staged_verification.ok {
            return Err(format!(
                "staged repair failed verification: {:?}",
                staged_verification.findings
            ));
        }
        let rebuild_report = crate::consensus_state::rebuild_derived_indexes(
            &temp_workspace,
            crate::consensus_state::DerivedIndexRebuildOptions { dry_run: false },
        )?;
        if !rebuild_report.ok {
            return Err(format!(
                "derived-index rebuild failed closed: {:?}",
                rebuild_report.findings
            ));
        }
        let receipt = StateSyncRepairReceipt {
            format: "synergy-state-sync-repair-receipt-v1".to_string(),
            created_at_unix: current_unix_secs(),
            plan_sha256: sha256_json(plan)?,
            transfer_id: plan.transfer_id.clone(),
            transfer_content_sha256: plan.transfer_content_sha256.clone(),
            requesting_node_id: plan.requesting_node_id.clone(),
            source_node_id: plan.source_node_id.clone(),
            source_cluster_id: plan.source_cluster_id.clone(),
            local_height: plan.local_height,
            target_height: plan.target_height,
            target_hash: plan.target_hash.clone(),
            workspace: workspace.display().to_string(),
            backup_path: backup_dir.display().to_string(),
            repaired_data_dir: data_dir.display().to_string(),
            derived_index_rebuilt: true,
            qc_fabricated: false,
        };
        write_json_pretty(&temp_data_dir.join(STATE_SYNC_REPAIR_RECEIPT), &receipt)?;
        Ok((staged_verification, receipt))
    })();

    let (staged_verification, _receipt) = match apply_result {
        Ok(result) => result,
        Err(error) => {
            let _ = fs::remove_dir_all(&temp_workspace);
            return Err(error);
        }
    };

    let old_data_dir = workspace.join(format!(
        ".state-sync-old-data-{}-{}",
        std::process::id(),
        current_unix_nanos()
    ));
    fs::rename(&data_dir, &old_data_dir).map_err(|error| {
        format!(
            "move original data dir {} to {}: {error}",
            data_dir.display(),
            old_data_dir.display()
        )
    })?;
    if let Err(error) = fs::rename(&temp_data_dir, &data_dir) {
        let _ = fs::rename(&old_data_dir, &data_dir);
        let _ = fs::remove_dir_all(&temp_workspace);
        return Err(format!(
            "commit repaired data dir {} to {}: {error}",
            temp_data_dir.display(),
            data_dir.display()
        ));
    }
    let _ = fs::remove_dir_all(&temp_workspace);
    let _ = fs::remove_dir_all(&old_data_dir);

    let final_verification = crate::consensus_state::verify_state(&workspace);
    if !final_verification.ok {
        findings.push(error(
            "state_sync_repair_post_commit_verification_failed",
            "repaired state failed verification after atomic swap",
        ));
    }
    actions.push(format!(
        "backup written to {}",
        backup_dir.join("data").display()
    ));
    actions.push(format!(
        "repair receipt written to {}",
        data_dir.join(STATE_SYNC_REPAIR_RECEIPT).display()
    ));

    Ok(StateSyncRepairApplyReport {
        ok: !has_errors(&findings),
        decision: if has_errors(&findings) { "NO_GO" } else { "GO" }.to_string(),
        dry_run: false,
        applied: !has_errors(&findings),
        workspace: workspace.display().to_string(),
        backup_path: Some(backup_dir.display().to_string()),
        receipt_path: Some(
            data_dir
                .join(STATE_SYNC_REPAIR_RECEIPT)
                .display()
                .to_string(),
        ),
        original_verification,
        repaired_verification: Some(if final_verification.ok {
            final_verification
        } else {
            staged_verification
        }),
        actions,
        findings,
    })
}

#[derive(Debug, Clone)]
struct RepairBundle {
    chain: Vec<Value>,
    chain_heights: BTreeMap<u64, String>,
    canonical_locks: BTreeMap<u64, Value>,
    committed_qcs: Vec<Value>,
    committed_qc_heights: BTreeMap<u64, String>,
    state_checkpoint: Option<Value>,
}

fn validate_apply_mode(
    options: &StateSyncRepairApplyOptions,
    findings: &mut Vec<StateSyncFinding>,
) {
    if options.dry_run == options.apply {
        findings.push(error(
            "state_sync_repair_mode_invalid",
            "exactly one of dry_run or apply must be selected",
        ));
    }
}

fn validate_apply_plan(plan: &StateSyncRepairPlan, findings: &mut Vec<StateSyncFinding>) {
    if plan.protocol_version != STATE_SYNC_PROTOCOL_VERSION {
        findings.push(error(
            "state_sync_repair_plan_protocol_mismatch",
            format!(
                "expected plan protocol_version {}, found {}",
                STATE_SYNC_PROTOCOL_VERSION, plan.protocol_version
            ),
        ));
    }
    if !plan.ok || plan.decision == "NO_GO" {
        findings.push(error(
            "state_sync_repair_plan_unverified",
            "repair apply requires a verified GO dry-run plan",
        ));
    }
    if plan
        .findings
        .iter()
        .any(|finding| finding.severity == ConsensusStateSeverity::Error)
    {
        findings.push(error(
            "state_sync_repair_plan_has_error_findings",
            "repair plan contains error findings",
        ));
    }
    if let Err(detail) = ChainId(plan.chain_id).require_testnet_v3() {
        findings.push(error("state_sync_repair_wrong_chain_id", detail));
    }
    if let Err(detail) = NetworkId(plan.network_id.clone()).require_testnet_v3() {
        findings.push(error("state_sync_repair_wrong_network_id", detail));
    }
    for (label, value) in [
        ("plan.genesis_hash", &plan.genesis_hash),
        ("plan.local_hash", &plan.local_hash),
        ("plan.target_hash", &plan.target_hash),
        (
            "plan.transfer_content_sha256",
            &plan.transfer_content_sha256,
        ),
        ("plan.validator_set_hash", &plan.validator_set_hash),
        ("plan.cluster_map_hash", &plan.cluster_map_hash),
        ("plan.protocol_config_hash", &plan.protocol_config_hash),
    ] {
        require_hash(label, value, findings);
    }
    if plan.target_height <= plan.local_height {
        findings.push(error(
            "state_sync_repair_target_not_ahead",
            "repair target height must be ahead of local height",
        ));
    }
    if plan
        .source_cluster_id
        .as_deref()
        .unwrap_or_default()
        .is_empty()
    {
        findings.push(error(
            "state_sync_repair_cluster_id_missing",
            "repair plan must carry a source cluster id",
        ));
    }
    if !plan.majority_branch_verified {
        findings.push(error(
            "state_sync_repair_minority_branch_unverified",
            "repair apply refuses plans without majority branch proof",
        ));
    }
    reject_unsafe_source_role("plan.source_role", &plan.source_role, findings);
}

fn validate_offline_workspace(
    workspace: &Path,
    data_dir: &Path,
    findings: &mut Vec<StateSyncFinding>,
) {
    if !workspace
        .join(STATE_SYNC_OFFLINE_WORKSPACE_MARKER)
        .is_file()
    {
        findings.push(error(
            "state_sync_repair_offline_workspace_marker_missing",
            format!(
                "apply requires an offline fixture marker file: {}",
                workspace
                    .join(STATE_SYNC_OFFLINE_WORKSPACE_MARKER)
                    .display()
            ),
        ));
    }
    if !data_dir.is_dir() {
        findings.push(error(
            "state_sync_repair_data_dir_missing",
            format!(
                "repair workspace must contain a data directory: {}",
                data_dir.display()
            ),
        ));
    }
}

fn validate_current_anchor(
    data_dir: &Path,
    report: &ConsensusStateReport,
    plan: &StateSyncRepairPlan,
    findings: &mut Vec<StateSyncFinding>,
) {
    let anchor_matches_latest = report
        .chain
        .latest
        .as_ref()
        .map(|latest| latest.height == plan.local_height && latest.hash == plan.local_hash)
        .unwrap_or(false);
    let compact_boundary_starts_after_anchor = report
        .chain
        .first_retained
        .as_ref()
        .map(|first| first.height == plan.local_height.saturating_add(1))
        .unwrap_or(false);
    let chain_contains_common_anchor = read_json_array_strict(&data_dir.join("chain.json"))
        .map(|chain| {
            chain.iter().any(|block| {
                value_height(block) == Some(plan.local_height)
                    && value_hash(block).as_deref() == Some(plan.local_hash.as_str())
            })
        })
        .unwrap_or(false);

    if !anchor_matches_latest
        && !compact_boundary_starts_after_anchor
        && !chain_contains_common_anchor
    {
        findings.push(error(
            "state_sync_repair_local_anchor_mismatch",
            format!(
                "workspace chain does not anchor at plan local h{} {}",
                plan.local_height, plan.local_hash
            ),
        ));
    }
}

fn read_bundle_manifest(
    bundle_dir: &Path,
    findings: &mut Vec<StateSyncFinding>,
) -> Option<StateSyncRepairBundleManifest> {
    let path = bundle_dir.join("repair_manifest.json");
    match fs::read_to_string(&path) {
        Ok(content) => match serde_json::from_str(&content) {
            Ok(manifest) => Some(manifest),
            Err(error_detail) => {
                findings.push(error(
                    "state_sync_repair_manifest_unreadable",
                    format!("parse {}: {error_detail}", path.display()),
                ));
                None
            }
        },
        Err(error_detail) => {
            findings.push(error(
                "state_sync_repair_manifest_missing",
                format!("read {}: {error_detail}", path.display()),
            ));
            None
        }
    }
}

fn read_repair_bundle(
    bundle_dir: &Path,
    findings: &mut Vec<StateSyncFinding>,
) -> Option<RepairBundle> {
    let chain_path = bundle_dir.join("chain.json");
    let locks_path = bundle_dir.join("canonical_locks.json");
    let qcs_path = bundle_dir.join("committed_qcs.jsonl");
    let chain = read_json_array(&chain_path, "state_sync_repair_chain_unreadable", findings)?;
    let chain_heights = collect_height_hashes(&chain, "repair chain", findings);
    let canonical_locks =
        read_height_value_map(&locks_path, "state_sync_repair_locks_unreadable", findings)?;
    let committed_qcs = read_jsonl_values(&qcs_path, "state_sync_repair_qcs_unreadable", findings)?;
    let committed_qc_heights = collect_height_hashes(&committed_qcs, "repair QC", findings);
    let checkpoint_path = bundle_dir.join("state_checkpoint.json");
    let state_checkpoint = if checkpoint_path.is_file() {
        match read_json_value(&checkpoint_path) {
            Ok(value) => Some(value),
            Err(detail) => {
                findings.push(error("state_sync_repair_checkpoint_unreadable", detail));
                None
            }
        }
    } else {
        None
    };

    Some(RepairBundle {
        chain,
        chain_heights,
        canonical_locks,
        committed_qcs,
        committed_qc_heights,
        state_checkpoint,
    })
}

fn validate_bundle_coverage(
    bundle: &RepairBundle,
    plan: &StateSyncRepairPlan,
    findings: &mut Vec<StateSyncFinding>,
) {
    let start = plan.local_height.saturating_add(1);
    for height in start..=plan.target_height {
        if !bundle.chain_heights.contains_key(&height) {
            findings.push(error(
                "state_sync_repair_missing_block_body",
                format!("repair bundle is missing block body h{height}"),
            ));
        }
        if !bundle.committed_qc_heights.contains_key(&height) {
            findings.push(error(
                "state_sync_repair_missing_committed_qc",
                format!("repair bundle is missing committed QC h{height}"),
            ));
        }
        if !bundle.canonical_locks.contains_key(&height) {
            findings.push(error(
                "state_sync_repair_missing_canonical_lock",
                format!("repair bundle is missing canonical lock h{height}"),
            ));
        }
    }
    match bundle.chain_heights.get(&plan.target_height) {
        Some(hash) if hash == &plan.target_hash => {}
        Some(hash) => findings.push(error(
            "state_sync_repair_target_hash_mismatch",
            format!(
                "repair bundle target h{} hash {} does not match plan target hash {}",
                plan.target_height, hash, plan.target_hash
            ),
        )),
        None => {}
    }
}

fn validate_bundle_manifest(
    manifest: &StateSyncRepairBundleManifest,
    plan: &StateSyncRepairPlan,
    content_sha256: Option<&str>,
    findings: &mut Vec<StateSyncFinding>,
) {
    if manifest.transfer_id != plan.transfer_id {
        findings.push(error(
            "state_sync_repair_transfer_id_mismatch",
            "repair manifest transfer_id does not match plan",
        ));
    }
    if manifest.transfer_content_sha256 != plan.transfer_content_sha256 {
        findings.push(error(
            "state_sync_repair_transfer_digest_mismatch",
            "repair manifest transfer digest does not match plan",
        ));
    }
    if let Some(actual) = content_sha256 {
        if actual != plan.transfer_content_sha256 {
            findings.push(error(
                "state_sync_repair_content_digest_mismatch",
                format!(
                    "repair bundle content sha256 {actual} does not match plan {}",
                    plan.transfer_content_sha256
                ),
            ));
        }
    }
    if manifest.source_node_id != plan.source_node_id {
        findings.push(error(
            "state_sync_repair_source_id_mismatch",
            "repair manifest source node does not match plan",
        ));
    }
    if manifest.source_role != plan.source_role {
        findings.push(error(
            "state_sync_repair_source_role_mismatch",
            "repair manifest source role does not match plan",
        ));
    }
    if manifest.source_cluster_id != plan.source_cluster_id {
        findings.push(error(
            "state_sync_repair_cluster_id_mismatch",
            "repair manifest source cluster id does not match plan",
        ));
    }

    let validator_set_digest = non_empty(&manifest.validator_set_digest)
        .or_else(|| non_empty(&manifest.validator_set_hash));
    if validator_set_digest != Some(plan.validator_set_hash.as_str()) {
        findings.push(error(
            "state_sync_repair_validator_set_digest_mismatch",
            "repair manifest validator-set digest does not match plan",
        ));
    }

    let cluster_map_digest =
        non_empty(&manifest.cluster_map_digest).or_else(|| non_empty(&manifest.cluster_map_hash));
    if cluster_map_digest != Some(plan.cluster_map_hash.as_str()) {
        findings.push(error(
            "state_sync_repair_cluster_map_digest_mismatch",
            "repair manifest cluster-map digest does not match plan",
        ));
    }

    let protocol_config_digest = non_empty(&manifest.protocol_config_digest)
        .or_else(|| non_empty(&manifest.protocol_config_hash));
    let compatible_config = manifest
        .compatible_protocol_config_digests
        .iter()
        .chain(manifest.compatible_protocol_config_hashes.iter())
        .any(|digest| digest == &plan.protocol_config_hash);
    if protocol_config_digest != Some(plan.protocol_config_hash.as_str()) && !compatible_config {
        findings.push(error(
            "state_sync_repair_config_digest_mismatch",
            "repair manifest config digest does not match plan and is not explicitly compatible",
        ));
    }

    reject_unsafe_source_role("manifest.source_role", &manifest.source_role, findings);
    if !manifest.majority_branch_verified {
        findings.push(error(
            "state_sync_repair_manifest_minority_branch_unverified",
            "repair manifest does not prove majority branch membership",
        ));
    }
    if !manifest.finalized_qc_aegis_pqc_verified {
        findings.push(error(
            "state_sync_repair_manifest_missing_qc_verification",
            "repair manifest does not carry verified QC evidence",
        ));
    }
    let manifest_archive_role = manifest.source_role.eq_ignore_ascii_case("archive")
        || manifest
            .source_role
            .eq_ignore_ascii_case("archive_validator")
        || manifest
            .source_role
            .eq_ignore_ascii_case("archive-validator");
    if manifest.archive_contained || (manifest_archive_role && !manifest.archive_canonical) {
        findings.push(error(
            "state_sync_repair_archive_source_not_canonical",
            "archive-contained or noncanonical archive evidence cannot be used for repair",
        ));
    }
    if manifest.public_rpc_only {
        findings.push(error(
            "state_sync_repair_public_rpc_only_source_rejected",
            "public RPC-only evidence cannot be used for repair",
        ));
    }
    if manifest.atlas_only {
        findings.push(error(
            "state_sync_repair_atlas_only_source_rejected",
            "Atlas-only evidence cannot be used for repair",
        ));
    }
}

fn stage_repaired_state(
    data_dir: &Path,
    bundle: &RepairBundle,
    plan: &StateSyncRepairPlan,
) -> Result<(), String> {
    let chain_path = data_dir.join("chain.json");
    let locks_path = data_dir.join("canonical_locks.json");
    let qcs_path = data_dir.join("committed_qcs.jsonl");

    let mut chain = read_json_array_strict(&chain_path)?;
    chain.retain(|block| value_height(block).is_some_and(|height| height <= plan.local_height));
    let mut bundle_chain = bundle.chain.clone();
    bundle_chain.sort_by_key(|block| value_height(block).unwrap_or(u64::MAX));
    chain.extend(bundle_chain);
    write_json_pretty(&chain_path, &Value::Array(chain))?;

    let mut locks = read_height_value_map_strict(&locks_path)?;
    locks.retain(|height, _| *height <= plan.local_height);
    for (height, value) in &bundle.canonical_locks {
        locks.insert(*height, value.clone());
    }
    write_json_pretty(&locks_path, &height_value_map_to_json(&locks))?;

    let mut qcs = read_jsonl_values_strict(&qcs_path)?;
    qcs.retain(|qc| value_height(qc).is_some_and(|height| height <= plan.local_height));
    qcs.extend(bundle.committed_qcs.clone());
    write_jsonl_values(&qcs_path, &qcs)?;

    if let Some(checkpoint) = &bundle.state_checkpoint {
        write_json_pretty(&data_dir.join("state_checkpoint.json"), checkpoint)?;
    }
    Ok(())
}

fn reject_unsafe_source_role(label: &str, role: &str, findings: &mut Vec<StateSyncFinding>) {
    if role.eq_ignore_ascii_case("archive")
        || role.eq_ignore_ascii_case("archive_validator")
        || role.eq_ignore_ascii_case("archive-validator")
    {
        findings.push(error(
            "state_sync_repair_archive_source_rejected",
            format!("{label} cannot be an archive source for protocol-native repair"),
        ));
    }
    if role.eq_ignore_ascii_case("public_rpc") || role.eq_ignore_ascii_case("public-rpc") {
        findings.push(error(
            "state_sync_repair_public_rpc_only_source_rejected",
            format!("{label} cannot be public RPC-only evidence"),
        ));
    }
    if role.eq_ignore_ascii_case("atlas") {
        findings.push(error(
            "state_sync_repair_atlas_only_source_rejected",
            format!("{label} cannot be Atlas-only evidence"),
        ));
    }
}

fn read_json_array(
    path: &Path,
    code: &str,
    findings: &mut Vec<StateSyncFinding>,
) -> Option<Vec<Value>> {
    match read_json_array_strict(path) {
        Ok(values) => Some(values),
        Err(detail) => {
            findings.push(error(code, detail));
            None
        }
    }
}

fn read_json_array_strict(path: &Path) -> Result<Vec<Value>, String> {
    let value = read_json_value(path)?;
    value
        .as_array()
        .cloned()
        .ok_or_else(|| format!("{} is not a JSON array", path.display()))
}

fn read_height_value_map(
    path: &Path,
    code: &str,
    findings: &mut Vec<StateSyncFinding>,
) -> Option<BTreeMap<u64, Value>> {
    match read_height_value_map_strict(path) {
        Ok(values) => Some(values),
        Err(detail) => {
            findings.push(error(code, detail));
            None
        }
    }
}

fn read_height_value_map_strict(path: &Path) -> Result<BTreeMap<u64, Value>, String> {
    let value = read_json_value(path)?;
    let object = value
        .as_object()
        .ok_or_else(|| format!("{} is not a JSON object", path.display()))?;
    let mut map = BTreeMap::new();
    for (height, value) in object {
        let height = height
            .parse::<u64>()
            .map_err(|error| format!("invalid height key {height:?}: {error}"))?;
        map.insert(height, value.clone());
    }
    Ok(map)
}

fn read_jsonl_values(
    path: &Path,
    code: &str,
    findings: &mut Vec<StateSyncFinding>,
) -> Option<Vec<Value>> {
    match read_jsonl_values_strict(path) {
        Ok(values) => Some(values),
        Err(detail) => {
            findings.push(error(code, detail));
            None
        }
    }
}

fn read_jsonl_values_strict(path: &Path) -> Result<Vec<Value>, String> {
    let file = fs::File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let reader = BufReader::new(file);
    let mut values = Vec::new();
    for (index, line) in reader.lines().enumerate() {
        let line = line.map_err(|error| format!("read {}: {error}", path.display()))?;
        if line.trim().is_empty() {
            continue;
        }
        values.push(
            serde_json::from_str(&line).map_err(|error| {
                format!("parse line {} in {}: {error}", index + 1, path.display())
            })?,
        );
    }
    Ok(values)
}

fn collect_height_hashes(
    values: &[Value],
    label: &str,
    findings: &mut Vec<StateSyncFinding>,
) -> BTreeMap<u64, String> {
    let mut map = BTreeMap::new();
    for (index, value) in values.iter().enumerate() {
        match (value_height(value), value_hash(value)) {
            (Some(height), Some(hash)) => {
                if let Some(previous) = map.insert(height, hash.clone()) {
                    findings.push(error(
                        "state_sync_repair_duplicate_height",
                        format!(
                            "{label} has duplicate height h{height} hashes {previous} and {hash}"
                        ),
                    ));
                }
            }
            _ => findings.push(error(
                "state_sync_repair_height_hash_missing",
                format!("{label} entry at index {index} is missing height or hash"),
            )),
        }
    }
    map
}

fn value_height(value: &Value) -> Option<u64> {
    let qc = value.get("qc").unwrap_or(value);
    [
        "height",
        "number",
        "block_number",
        "block_index",
        "block_height",
    ]
    .into_iter()
    .find_map(|key| {
        qc.get(key)
            .or_else(|| value.get(key))
            .and_then(|value| value.as_u64().or_else(|| value.as_str()?.parse().ok()))
    })
    .or_else(|| {
        qc.get("votes")
            .and_then(Value::as_array)
            .and_then(|votes| votes.first())
            .and_then(value_height)
    })
}

fn value_hash(value: &Value) -> Option<String> {
    let qc = value.get("qc").unwrap_or(value);
    qc.as_str()
        .map(str::to_string)
        .or_else(|| {
            ["hash", "block_hash", "blockHash"]
                .into_iter()
                .find_map(|key| {
                    qc.get(key)
                        .or_else(|| value.get(key))
                        .and_then(Value::as_str)
                })
                .map(str::to_string)
        })
        .or_else(|| {
            qc.get("votes")
                .and_then(Value::as_array)
                .and_then(|votes| votes.first())
                .and_then(value_hash)
        })
}

fn height_value_map_to_json(map: &BTreeMap<u64, Value>) -> Value {
    let object = map
        .iter()
        .map(|(height, value)| (height.to_string(), value.clone()))
        .collect();
    Value::Object(object)
}

fn read_json_value(path: &Path) -> Result<Value, String> {
    let content =
        fs::read_to_string(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    serde_json::from_str(&content).map_err(|error| format!("parse {}: {error}", path.display()))
}

fn write_json_pretty<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("serialize {}: {error}", path.display()))?;
    fs::write(path, bytes).map_err(|error| format!("write {}: {error}", path.display()))
}

fn write_jsonl_values(path: &Path, values: &[Value]) -> Result<(), String> {
    let mut content = String::new();
    for value in values {
        content.push_str(
            &serde_json::to_string(value)
                .map_err(|error| format!("serialize JSONL {}: {error}", path.display()))?,
        );
        content.push('\n');
    }
    fs::write(path, content).map_err(|error| format!("write {}: {error}", path.display()))
}

fn sha256_repair_bundle(bundle_dir: &Path) -> Result<String, String> {
    let mut hasher = Sha256::new();
    for name in [
        "chain.json",
        "canonical_locks.json",
        "committed_qcs.jsonl",
        "state_checkpoint.json",
    ] {
        let path = bundle_dir.join(name);
        if !path.exists() {
            if name == "state_checkpoint.json" {
                continue;
            }
            return Err(format!("repair bundle file missing: {}", path.display()));
        }
        hasher.update(name.as_bytes());
        hasher.update([0]);
        hasher
            .update(fs::read(&path).map_err(|error| format!("read {}: {error}", path.display()))?);
        hasher.update([0]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn sha256_json<T: Serialize>(value: &T) -> Result<String, String> {
    let bytes = serde_json::to_vec(value).map_err(|error| format!("serialize JSON: {error}"))?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(hex::encode(hasher.finalize()))
}

fn copy_dir_all(source: &Path, target: &Path) -> Result<(), String> {
    fs::create_dir_all(target).map_err(|error| format!("create {}: {error}", target.display()))?;
    for entry in
        fs::read_dir(source).map_err(|error| format!("read {}: {error}", source.display()))?
    {
        let entry = entry.map_err(|error| format!("read {} entry: {error}", source.display()))?;
        let file_type = entry
            .file_type()
            .map_err(|error| format!("read file type {}: {error}", entry.path().display()))?;
        let destination = target.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_all(&entry.path(), &destination)?;
        } else if file_type.is_file() {
            fs::copy(entry.path(), &destination)
                .map_err(|error| format!("copy to {}: {error}", destination.display()))?;
        }
    }
    Ok(())
}

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn current_unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default()
}

fn non_empty(value: &str) -> Option<&str> {
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn has_errors(findings: &[StateSyncFinding]) -> bool {
    findings
        .iter()
        .any(|finding| finding.severity == ConsensusStateSeverity::Error)
}

fn validate_request(request: &StateSyncRequest, findings: &mut Vec<StateSyncFinding>) {
    if request.protocol_version != STATE_SYNC_PROTOCOL_VERSION {
        findings.push(error(
            "state_sync_protocol_version_mismatch",
            format!(
                "expected protocol_version {}, found {}",
                STATE_SYNC_PROTOCOL_VERSION, request.protocol_version
            ),
        ));
    }
    if let Err(detail) = ChainId(request.chain_id).require_testnet_v3() {
        findings.push(error("state_sync_wrong_chain_id", detail));
    }
    if let Err(detail) = NetworkId(request.network_id.clone()).require_testnet_v3() {
        findings.push(error("state_sync_wrong_network_id", detail));
    }
    require_hash("request.genesis_hash", &request.genesis_hash, findings);
    require_hash("request.local_hash", &request.local_hash, findings);
    require_hash("request.target_hash", &request.target_hash, findings);
    if request.target_height <= request.local_height {
        findings.push(error(
            "state_sync_target_not_ahead",
            format!(
                "target height {} must be ahead of local height {}",
                request.target_height, request.local_height
            ),
        ));
    }
}

fn validate_source_proof(
    request: &StateSyncRequest,
    source: &StateSyncSourceProof,
    findings: &mut Vec<StateSyncFinding>,
) {
    if source.protocol_version != STATE_SYNC_PROTOCOL_VERSION {
        findings.push(error(
            "state_sync_source_protocol_version_mismatch",
            format!(
                "expected source protocol_version {}, found {}",
                STATE_SYNC_PROTOCOL_VERSION, source.protocol_version
            ),
        ));
    }
    if source.chain_id != request.chain_id
        || source.network_id != request.network_id
        || source.genesis_hash != request.genesis_hash
    {
        findings.push(error(
            "state_sync_source_identity_mismatch",
            "source proof chain_id, network_id, or genesis hash does not match the request",
        ));
    }
    if source.network_id != SYNERGY_TESTNET_V3_NETWORK_ID {
        findings.push(error(
            "state_sync_source_wrong_network_id",
            format!("source network_id must be {SYNERGY_TESTNET_V3_NETWORK_ID}"),
        ));
    }
    for (label, value) in [
        ("source.genesis_hash", &source.genesis_hash),
        ("source.common_hash", &source.common_hash),
        ("source.target_hash", &source.target_hash),
        ("source.source_hash", &source.source_hash),
        ("source.validator_set_hash", &source.validator_set_hash),
        ("source.cluster_map_hash", &source.cluster_map_hash),
        ("source.protocol_config_hash", &source.protocol_config_hash),
    ] {
        require_hash(label, value, findings);
    }
    if source.common_height != request.local_height || source.common_hash != request.local_hash {
        findings.push(error(
            "state_sync_common_block_mismatch",
            "source proof common block does not match the requester's local block",
        ));
    }
    if source.target_height != request.target_height || source.target_hash != request.target_hash {
        findings.push(error(
            "state_sync_target_block_mismatch",
            "source proof target block does not match the requested target block",
        ));
    }
    if source.source_height < request.target_height {
        findings.push(error(
            "state_sync_source_peer_stale",
            format!(
                "source height {} is below requested target height {}",
                source.source_height, request.target_height
            ),
        ));
    }
    if source.source_height == request.target_height && source.source_hash != request.target_hash {
        findings.push(error(
            "state_sync_source_hash_mismatch",
            "source hash at target height does not match requested target hash",
        ));
    }
    if source.source_peer_quarantined {
        findings.push(error(
            "state_sync_source_peer_quarantined",
            "refusing to state-sync from a quarantined source peer",
        ));
    }
    if source.source_role.eq_ignore_ascii_case("archive")
        || source.source_role.eq_ignore_ascii_case("archive_validator")
        || source.source_role.eq_ignore_ascii_case("archive-validator")
    {
        findings.push(error(
            "state_sync_archive_source_rejected",
            "protocol-native state sync cannot use archive snapshot source roles",
        ));
    }
    if source.source_role.eq_ignore_ascii_case("public_rpc")
        || source.source_role.eq_ignore_ascii_case("public-rpc")
        || source.public_rpc_only
    {
        findings.push(error(
            "state_sync_public_rpc_only_source_rejected",
            "protocol-native repair cannot trust public RPC-only proof as a repair source",
        ));
    }
    if source.source_role.eq_ignore_ascii_case("atlas") || source.atlas_only {
        findings.push(error(
            "state_sync_atlas_only_source_rejected",
            "protocol-native repair cannot trust Atlas-only proof as a repair source",
        ));
    }
    if source.snapshot_class.is_some() {
        findings.push(error(
            "state_sync_snapshot_source_rejected",
            "state-sync repair requires protocol-native block/QC/lock proofs, not snapshot manifests",
        ));
    }
    match source.source_cluster_id.as_deref() {
        Some(cluster_id) if !cluster_id.trim().is_empty() => {}
        _ => findings.push(error(
            "state_sync_cluster_id_missing",
            "source proof must declare the validator cluster id used for repair",
        )),
    }
    if !source.majority_branch_verified {
        findings.push(error(
            "state_sync_minority_branch_unverified",
            "source proof must verify majority branch membership and must not choose by raw height",
        ));
    }
    if !source.finalized_qc_aegis_pqc_verified {
        findings.push(error(
            "state_sync_qc_not_verified",
            "source target proof is missing Aegis PQC QC verification",
        ));
    }
    if !source.parent_continuity_verified {
        findings.push(error(
            "state_sync_parent_continuity_unverified",
            "source proof did not verify parent continuity from local common block to target",
        ));
    }
    if !source.state_root_matches {
        findings.push(error(
            "state_sync_state_root_mismatch",
            "source proof did not prove the target state root",
        ));
    }
}

fn validate_transfer(
    request: &StateSyncRequest,
    transfer: &StateSyncTransferProof,
    findings: &mut Vec<StateSyncFinding>,
) {
    require_hash(
        "transfer.transfer_content_sha256",
        &transfer.transfer_content_sha256,
        findings,
    );
    if !transfer.complete {
        findings.push(error(
            "state_sync_partial_transfer",
            "transfer proof is marked incomplete",
        ));
    }
    let start = request.local_height.saturating_add(1);
    let end = request.target_height;
    require_span(
        "state_sync_body_range_missing",
        "state_sync_body_range_incomplete",
        "block body",
        transfer.block_bodies.as_ref(),
        start,
        end,
        findings,
    );
    require_span(
        "state_sync_qc_range_missing",
        "state_sync_qc_range_incomplete",
        "committed QC",
        transfer.committed_qcs.as_ref(),
        start,
        end,
        findings,
    );
    require_span(
        "state_sync_lock_range_missing",
        "state_sync_lock_range_incomplete",
        "canonical lock",
        transfer.canonical_locks.as_ref(),
        start,
        end,
        findings,
    );
}

fn validate_local_state(
    request: &StateSyncRequest,
    local_state: Option<&ConsensusStateReport>,
    findings: &mut Vec<StateSyncFinding>,
) {
    let Some(local_state) = local_state else {
        findings.push(warning(
            "state_sync_local_state_not_supplied",
            "local state report was not supplied; plan remains dry-run only",
        ));
        return;
    };
    if !local_state.ok {
        findings.push(error(
            "state_sync_local_state_failed_verification",
            "local consensus state verification failed before state sync planning",
        ));
    }
    let Some(latest) = &local_state.chain.latest else {
        findings.push(error(
            "state_sync_local_tip_missing",
            "local state report has no latest retained chain block",
        ));
        return;
    };
    if latest.height != request.local_height || latest.hash != request.local_hash {
        findings.push(error(
            "state_sync_local_tip_mismatch",
            format!(
                "local state report latest h{} {} does not match request local h{} {}",
                latest.height, latest.hash, request.local_height, request.local_hash
            ),
        ));
    }
}

fn require_span(
    missing_code: &str,
    incomplete_code: &str,
    label: &str,
    span: Option<&StateSyncHeightSpan>,
    start: u64,
    end: u64,
    findings: &mut Vec<StateSyncFinding>,
) {
    match span {
        Some(span) if span.covers(start, end) => {}
        Some(span) => findings.push(error(
            incomplete_code,
            format!(
                "{label} span h{}..h{} count {} does not cover required h{start}..h{end}",
                span.start, span.end, span.count
            ),
        )),
        None => findings.push(error(
            missing_code,
            format!("{label} proof is required for h{start}..h{end}"),
        )),
    }
}

fn require_hash(label: &str, value: &str, findings: &mut Vec<StateSyncFinding>) {
    if Hash::from_hex(value).is_err() {
        findings.push(error(
            "state_sync_invalid_hash",
            format!("{label} must be a 32-byte hex hash"),
        ));
    }
}

fn error(code: impl Into<String>, detail: impl Into<String>) -> StateSyncFinding {
    StateSyncFinding {
        code: code.into(),
        severity: ConsensusStateSeverity::Error,
        detail: detail.into(),
    }
}

fn warning(code: impl Into<String>, detail: impl Into<String>) -> StateSyncFinding {
    StateSyncFinding {
        code: code.into(),
        severity: ConsensusStateSeverity::Warning,
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus_state::{
        ChainBodySummary, ConsensusStateFileSummary, HeightHashSummary, HeightMapSummary,
        StateCheckpointSummary,
    };
    use serde_json::json;
    use std::path::{Path, PathBuf};

    fn hash(byte: u8) -> String {
        hex::encode([byte; 32])
    }

    fn height_hash(height: u64) -> String {
        let mut hasher = Sha256::new();
        hasher.update(height.to_be_bytes());
        hex::encode(hasher.finalize())
    }

    fn temp_workspace(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("synergy-state-sync-{label}-{unique}"));
        fs::create_dir_all(root.join("data")).unwrap();
        fs::write(root.join(STATE_SYNC_OFFLINE_WORKSPACE_MARKER), "fixture\n").unwrap();
        root
    }

    fn write_state(root: &Path, start: u64, end: u64) {
        let data = root.join("data");
        let chain = (start..=end)
            .map(|height| {
                json!({
                    "block_index": height,
                    "hash": height_hash(height),
                })
            })
            .collect::<Vec<_>>();
        let locks = (start..=end)
            .map(|height| (height.to_string(), Value::String(height_hash(height))))
            .collect::<serde_json::Map<String, Value>>();
        let qcs = (start..=end)
            .map(|height| {
                json!({
                    "height": height,
                    "block_hash": height_hash(height),
                })
                .to_string()
            })
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(
            data.join("chain.json"),
            serde_json::to_vec_pretty(&Value::Array(chain)).unwrap(),
        )
        .unwrap();
        fs::write(
            data.join("canonical_locks.json"),
            serde_json::to_vec_pretty(&Value::Object(locks)).unwrap(),
        )
        .unwrap();
        fs::write(data.join("committed_qcs.jsonl"), format!("{qcs}\n")).unwrap();
        write_state_checkpoint(&data, start, &height_hash(start));
    }

    fn write_forked_state(root: &Path, start: u64, end: u64, fork_start: u64) {
        let data = root.join("data");
        let branch_hash = |height| {
            if height >= fork_start {
                height_hash(height + 900_000)
            } else {
                height_hash(height)
            }
        };
        let chain = (start..=end)
            .map(|height| {
                json!({
                    "block_index": height,
                    "hash": branch_hash(height),
                })
            })
            .collect::<Vec<_>>();
        let locks = (start..=end)
            .map(|height| (height.to_string(), Value::String(branch_hash(height))))
            .collect::<serde_json::Map<String, Value>>();
        let qcs = (start..=end)
            .map(|height| {
                json!({
                    "height": height,
                    "block_hash": branch_hash(height),
                })
                .to_string()
            })
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(
            data.join("chain.json"),
            serde_json::to_vec_pretty(&Value::Array(chain)).unwrap(),
        )
        .unwrap();
        fs::write(
            data.join("canonical_locks.json"),
            serde_json::to_vec_pretty(&Value::Object(locks)).unwrap(),
        )
        .unwrap();
        fs::write(data.join("committed_qcs.jsonl"), format!("{qcs}\n")).unwrap();
        write_state_checkpoint(&data, start, &height_hash(start));
    }

    fn write_state_checkpoint(data: &Path, height: u64, block_hash: &str) {
        let checkpoint = json!({
            "format": "synergy_consensus_state_checkpoint_v1",
            "height": height,
            "block_hash": block_hash,
            "state_root": height_hash(height + 10_000),
        });
        fs::write(
            data.join("state_checkpoint.json"),
            serde_json::to_vec_pretty(&checkpoint).unwrap(),
        )
        .unwrap();
    }

    fn write_repair_bundle(root: &Path, start: u64, end: u64) -> String {
        write_repair_bundle_with_options(root, start, end, false)
    }

    fn write_repair_bundle_with_options(
        root: &Path,
        start: u64,
        end: u64,
        corrupt_checkpoint: bool,
    ) -> String {
        let bundle = root.join(STATE_SYNC_REPAIR_BUNDLE_DIR);
        fs::create_dir_all(&bundle).unwrap();
        let chain = (start..=end)
            .map(|height| {
                json!({
                    "block_index": height,
                    "hash": height_hash(height),
                })
            })
            .collect::<Vec<_>>();
        let locks = (start..=end)
            .map(|height| (height.to_string(), Value::String(height_hash(height))))
            .collect::<serde_json::Map<String, Value>>();
        let qcs = (start..=end)
            .map(|height| {
                json!({
                    "height": height,
                    "block_hash": height_hash(height),
                })
                .to_string()
            })
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(
            bundle.join("chain.json"),
            serde_json::to_vec_pretty(&Value::Array(chain)).unwrap(),
        )
        .unwrap();
        fs::write(
            bundle.join("canonical_locks.json"),
            serde_json::to_vec_pretty(&Value::Object(locks)).unwrap(),
        )
        .unwrap();
        fs::write(bundle.join("committed_qcs.jsonl"), format!("{qcs}\n")).unwrap();
        if corrupt_checkpoint {
            let checkpoint = json!({
                "format": "synergy_consensus_state_checkpoint_v1",
                "height": start,
                "block_hash": height_hash(end),
                "state_root": height_hash(end + 20_000),
            });
            fs::write(
                bundle.join("state_checkpoint.json"),
                serde_json::to_vec_pretty(&checkpoint).unwrap(),
            )
            .unwrap();
        }
        let digest = sha256_repair_bundle(&bundle).unwrap();
        let manifest = json!({
            "format": "synergy-state-sync-repair-bundle-v1",
            "transfer_id": "transfer-1",
            "transfer_content_sha256": digest,
            "source_node_id": "validator-2",
            "source_role": "validator",
            "source_cluster_id": "cluster-1",
            "validator_set_digest": hash(4),
            "cluster_map_digest": hash(5),
            "protocol_config_digest": hash(6),
            "majority_branch_verified": true,
            "finalized_qc_aegis_pqc_verified": true,
            "archive_contained": false,
            "archive_canonical": false,
            "public_rpc_only": false,
            "atlas_only": false,
        });
        fs::write(
            bundle.join("repair_manifest.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        digest
    }

    fn request() -> StateSyncRequest {
        StateSyncRequest {
            protocol_version: STATE_SYNC_PROTOCOL_VERSION.to_string(),
            requesting_node_id: "validator-6".to_string(),
            requesting_role: "validator".to_string(),
            chain_id: 1264,
            network_id: SYNERGY_TESTNET_V3_NETWORK_ID.to_string(),
            genesis_hash: hash(1),
            local_height: 100,
            local_hash: hash(2),
            target_height: 105,
            target_hash: hash(3),
            reason: "lagging validator dry-run repair".to_string(),
        }
    }

    fn source() -> StateSyncSourceProof {
        StateSyncSourceProof {
            protocol_version: STATE_SYNC_PROTOCOL_VERSION.to_string(),
            source_node_id: "validator-2".to_string(),
            source_role: "validator".to_string(),
            source_cluster_id: Some("cluster-1".to_string()),
            source_peer_quarantined: false,
            chain_id: 1264,
            network_id: SYNERGY_TESTNET_V3_NETWORK_ID.to_string(),
            genesis_hash: hash(1),
            common_height: 100,
            common_hash: hash(2),
            target_height: 105,
            target_hash: hash(3),
            source_height: 105,
            source_hash: hash(3),
            finalized_qc_aegis_pqc_verified: true,
            parent_continuity_verified: true,
            state_root_matches: true,
            validator_set_hash: hash(4),
            cluster_map_hash: hash(5),
            protocol_config_hash: hash(6),
            majority_branch_verified: true,
            public_rpc_only: false,
            atlas_only: false,
            snapshot_class: None,
        }
    }

    fn span() -> StateSyncHeightSpan {
        StateSyncHeightSpan {
            start: 101,
            end: 105,
            count: 5,
        }
    }

    fn transfer() -> StateSyncTransferProof {
        StateSyncTransferProof {
            transfer_id: "transfer-1".to_string(),
            complete: true,
            block_bodies: Some(span()),
            committed_qcs: Some(span()),
            canonical_locks: Some(span()),
            transfer_content_sha256: hash(7),
        }
    }

    fn local_state() -> ConsensusStateReport {
        ConsensusStateReport {
            ok: true,
            decision: "GO".to_string(),
            state_root: "/tmp/state".to_string(),
            data_dir: "/tmp/state/data".to_string(),
            files: vec![ConsensusStateFileSummary {
                label: "chain".to_string(),
                path: "/tmp/state/data/chain.json".to_string(),
                exists: true,
                size_bytes: Some(1),
                sha256: Some(hash(8)),
                root_owned: Some(false),
            }],
            chain: ChainBodySummary {
                block_count: 1,
                first_retained: Some(HeightHashSummary {
                    height: 100,
                    hash: hash(2),
                }),
                latest: Some(HeightHashSummary {
                    height: 100,
                    hash: hash(2),
                }),
                contiguous: true,
            },
            canonical_locks: HeightMapSummary {
                entry_count: 1,
                min_height: Some(100),
                max_height: Some(100),
            },
            committed_qcs: HeightMapSummary {
                entry_count: 1,
                min_height: Some(100),
                max_height: Some(100),
            },
            checkpoint: StateCheckpointSummary {
                exists: true,
                height: Some(100),
                block_hash: Some(hash(2)),
                state_root: Some(hash(9)),
            },
            findings: Vec::new(),
        }
    }

    fn codes(plan: &StateSyncRepairPlan) -> Vec<String> {
        plan.findings
            .iter()
            .map(|finding| finding.code.clone())
            .collect()
    }

    #[test]
    fn lagging_validator_with_complete_native_proofs_gets_dry_run_plan() {
        let plan =
            build_state_sync_repair_plan(&request(), &source(), &transfer(), Some(&local_state()));

        assert!(plan.ok);
        assert_eq!(plan.decision, "DRY_RUN_GO");
        assert!(plan.dry_run_only);
        assert!(plan
            .actions
            .iter()
            .any(|action| action.contains("no chain files are mutated")));
    }

    #[test]
    fn body_only_transfer_is_rejected() {
        let mut transfer = transfer();
        transfer.committed_qcs = None;
        transfer.canonical_locks = None;
        let plan =
            build_state_sync_repair_plan(&request(), &source(), &transfer, Some(&local_state()));

        assert!(!plan.ok);
        let codes = codes(&plan);
        assert!(codes.contains(&"state_sync_qc_range_missing".to_string()));
        assert!(codes.contains(&"state_sync_lock_range_missing".to_string()));
    }

    #[test]
    fn qc_only_transfer_is_rejected() {
        let mut transfer = transfer();
        transfer.block_bodies = None;
        transfer.canonical_locks = None;
        let plan =
            build_state_sync_repair_plan(&request(), &source(), &transfer, Some(&local_state()));

        assert!(!plan.ok);
        let codes = codes(&plan);
        assert!(codes.contains(&"state_sync_body_range_missing".to_string()));
        assert!(codes.contains(&"state_sync_lock_range_missing".to_string()));
    }

    #[test]
    fn lock_only_transfer_is_rejected() {
        let mut transfer = transfer();
        transfer.block_bodies = None;
        transfer.committed_qcs = None;
        let plan =
            build_state_sync_repair_plan(&request(), &source(), &transfer, Some(&local_state()));

        assert!(!plan.ok);
        let codes = codes(&plan);
        assert!(codes.contains(&"state_sync_body_range_missing".to_string()));
        assert!(codes.contains(&"state_sync_qc_range_missing".to_string()));
    }

    #[test]
    fn divergent_common_block_is_rejected() {
        let mut source = source();
        source.common_hash = hash(9);
        let plan =
            build_state_sync_repair_plan(&request(), &source, &transfer(), Some(&local_state()));

        assert!(!plan.ok);
        assert!(codes(&plan).contains(&"state_sync_common_block_mismatch".to_string()));
    }

    #[test]
    fn stale_source_peer_is_rejected() {
        let mut source = source();
        source.source_height = 104;
        let plan =
            build_state_sync_repair_plan(&request(), &source, &transfer(), Some(&local_state()));

        assert!(!plan.ok);
        assert!(codes(&plan).contains(&"state_sync_source_peer_stale".to_string()));
    }

    #[test]
    fn malicious_or_unverified_source_peer_is_rejected() {
        let mut source = source();
        source.source_peer_quarantined = true;
        source.finalized_qc_aegis_pqc_verified = false;
        source.state_root_matches = false;
        let plan =
            build_state_sync_repair_plan(&request(), &source, &transfer(), Some(&local_state()));

        assert!(!plan.ok);
        let codes = codes(&plan);
        assert!(codes.contains(&"state_sync_source_peer_quarantined".to_string()));
        assert!(codes.contains(&"state_sync_qc_not_verified".to_string()));
        assert!(codes.contains(&"state_sync_state_root_mismatch".to_string()));
    }

    #[test]
    fn partial_transfer_is_rejected() {
        let mut transfer = transfer();
        transfer.complete = false;
        transfer.block_bodies = Some(StateSyncHeightSpan {
            start: 101,
            end: 103,
            count: 3,
        });
        let plan =
            build_state_sync_repair_plan(&request(), &source(), &transfer, Some(&local_state()));

        assert!(!plan.ok);
        let codes = codes(&plan);
        assert!(codes.contains(&"state_sync_partial_transfer".to_string()));
        assert!(codes.contains(&"state_sync_body_range_incomplete".to_string()));
    }

    #[test]
    fn archive_snapshot_source_is_rejected() {
        let mut source = source();
        source.source_role = "archive_validator".to_string();
        source.snapshot_class = Some("archive-bootstrap".to_string());
        let plan =
            build_state_sync_repair_plan(&request(), &source, &transfer(), Some(&local_state()));

        assert!(!plan.ok);
        let codes = codes(&plan);
        assert!(codes.contains(&"state_sync_archive_source_rejected".to_string()));
        assert!(codes.contains(&"state_sync_snapshot_source_rejected".to_string()));
    }

    fn plan_for_workspace(
        root: &Path,
        local_height: u64,
        target_height: u64,
    ) -> StateSyncRepairPlan {
        let digest = write_repair_bundle(root, local_height + 1, target_height);
        let mut req = request();
        req.local_height = local_height;
        req.local_hash = height_hash(local_height);
        req.target_height = target_height;
        req.target_hash = height_hash(target_height);

        let mut src = source();
        src.common_height = local_height;
        src.common_hash = height_hash(local_height);
        src.target_height = target_height;
        src.target_hash = height_hash(target_height);
        src.source_height = target_height;
        src.source_hash = height_hash(target_height);

        let mut xfer = transfer();
        xfer.block_bodies = Some(StateSyncHeightSpan {
            start: local_height + 1,
            end: target_height,
            count: target_height - local_height,
        });
        xfer.committed_qcs = xfer.block_bodies.clone();
        xfer.canonical_locks = xfer.block_bodies.clone();
        xfer.transfer_content_sha256 = digest;

        build_state_sync_repair_plan(&req, &src, &xfer, None)
    }

    fn apply_codes(report: &StateSyncRepairApplyReport) -> Vec<String> {
        report
            .findings
            .iter()
            .map(|finding| finding.code.clone())
            .collect()
    }

    #[test]
    fn state_sync_repair_dry_run_does_not_mutate() {
        let root = temp_workspace("dry-run");
        write_state(&root, 100, 100);
        let plan = plan_for_workspace(&root, 100, 105);

        let report = apply_state_sync_repair(
            &plan,
            &root,
            StateSyncRepairApplyOptions {
                dry_run: true,
                apply: false,
            },
        )
        .unwrap();

        assert!(report.ok, "{:?}", report.findings);
        assert_eq!(report.decision, "DRY_RUN_GO");
        assert!(!report.applied);
        assert!(!root.join("data").join(STATE_SYNC_REPAIR_RECEIPT).exists());
        assert_eq!(
            crate::consensus_state::verify_state(&root)
                .chain
                .latest
                .unwrap()
                .height,
            100
        );
    }

    #[test]
    fn state_sync_repair_apply_writes_receipt_backup_and_derived_index() {
        let root = temp_workspace("apply");
        write_state(&root, 100, 100);
        let plan = plan_for_workspace(&root, 100, 105);

        let report = apply_state_sync_repair(
            &plan,
            &root,
            StateSyncRepairApplyOptions {
                dry_run: false,
                apply: true,
            },
        )
        .unwrap();

        assert!(report.ok, "{:?}", report.findings);
        assert!(report.applied);
        assert!(PathBuf::from(report.backup_path.unwrap())
            .join("data")
            .is_dir());
        assert!(root.join("data").join(STATE_SYNC_REPAIR_RECEIPT).is_file());
        assert!(root.join("data/derived_consensus_index.json").is_file());
        let repaired = crate::consensus_state::verify_state(&root);
        assert!(repaired.ok, "{:?}", repaired.findings);
        assert_eq!(repaired.chain.latest.unwrap().height, 105);
    }

    #[test]
    fn state_sync_repair_apply_refuses_minority_proof() {
        let root = temp_workspace("minority");
        write_state(&root, 100, 100);
        let mut plan = plan_for_workspace(&root, 100, 105);
        plan.majority_branch_verified = false;

        let report = apply_state_sync_repair(
            &plan,
            &root,
            StateSyncRepairApplyOptions {
                dry_run: false,
                apply: true,
            },
        )
        .unwrap();

        assert!(!report.ok);
        assert!(apply_codes(&report)
            .contains(&"state_sync_repair_minority_branch_unverified".to_string()));
        assert_eq!(
            crate::consensus_state::verify_state(&root)
                .chain
                .latest
                .unwrap()
                .height,
            100
        );
    }

    #[test]
    fn state_sync_repair_apply_refuses_archive_contained_source() {
        let root = temp_workspace("archive-contained");
        write_state(&root, 100, 100);
        let plan = plan_for_workspace(&root, 100, 105);
        let manifest_path = root
            .join(STATE_SYNC_REPAIR_BUNDLE_DIR)
            .join("repair_manifest.json");
        let mut manifest = read_json_value(&manifest_path).unwrap();
        manifest["archive_contained"] = Value::Bool(true);
        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let report = apply_state_sync_repair(
            &plan,
            &root,
            StateSyncRepairApplyOptions {
                dry_run: false,
                apply: true,
            },
        )
        .unwrap();

        assert!(!report.ok);
        assert!(apply_codes(&report)
            .contains(&"state_sync_repair_archive_source_not_canonical".to_string()));
    }

    #[test]
    fn state_sync_repair_apply_refuses_public_rpc_or_atlas_only_source() {
        let root = temp_workspace("public-atlas");
        write_state(&root, 100, 100);
        let mut plan = plan_for_workspace(&root, 100, 105);
        plan.source_role = "public_rpc".to_string();

        let report = apply_state_sync_repair(
            &plan,
            &root,
            StateSyncRepairApplyOptions {
                dry_run: false,
                apply: true,
            },
        )
        .unwrap();

        assert!(!report.ok);
        assert!(apply_codes(&report)
            .contains(&"state_sync_repair_public_rpc_only_source_rejected".to_string()));

        let root = temp_workspace("atlas-only");
        write_state(&root, 100, 100);
        let mut plan = plan_for_workspace(&root, 100, 105);
        plan.source_role = "atlas".to_string();
        let report = apply_state_sync_repair(
            &plan,
            &root,
            StateSyncRepairApplyOptions {
                dry_run: false,
                apply: true,
            },
        )
        .unwrap();
        assert!(!report.ok);
        assert!(apply_codes(&report)
            .contains(&"state_sync_repair_atlas_only_source_rejected".to_string()));
    }

    #[test]
    fn state_sync_repair_apply_repairs_body_behind_lock_from_verified_peer_bundle() {
        let root = temp_workspace("body-behind-lock");
        write_state(&root, 100, 100);
        fs::write(
            root.join("data/canonical_locks.json"),
            serde_json::to_vec_pretty(&json!({
                "100": height_hash(100),
                "101": height_hash(101),
                "102": height_hash(102),
                "103": height_hash(103),
                "104": height_hash(104),
                "105": height_hash(105),
            }))
            .unwrap(),
        )
        .unwrap();
        assert!(!crate::consensus_state::verify_state(&root).ok);
        let plan = plan_for_workspace(&root, 100, 105);

        let report = apply_state_sync_repair(
            &plan,
            &root,
            StateSyncRepairApplyOptions {
                dry_run: false,
                apply: true,
            },
        )
        .unwrap();

        assert!(report.ok, "{:?}", report.findings);
        assert_eq!(
            crate::consensus_state::verify_state(&root)
                .chain
                .latest
                .unwrap()
                .height,
            105
        );
    }

    #[test]
    fn state_sync_repair_apply_repairs_602192_fixture() {
        let root = temp_workspace("h602192");
        write_forked_state(&root, 602_190, 602_193, 602_192);
        assert!(crate::consensus_state::verify_state(&root).ok);
        let plan = plan_for_workspace(&root, 602_191, 602_193);

        let report = apply_state_sync_repair(
            &plan,
            &root,
            StateSyncRepairApplyOptions {
                dry_run: false,
                apply: true,
            },
        )
        .unwrap();

        assert!(report.ok, "{:?}", report.findings);
        let repaired = crate::consensus_state::verify_state(&root);
        assert_eq!(repaired.chain.latest.unwrap().height, 602_193);
        let chain = read_json_value(&root.join("data/chain.json")).unwrap();
        assert_eq!(
            chain[2]["hash"].as_str().map(str::to_string),
            Some(height_hash(602_192))
        );
        assert_eq!(
            chain[3]["hash"].as_str().map(str::to_string),
            Some(height_hash(602_193))
        );
    }

    #[test]
    fn state_sync_repair_apply_repairs_602435_fixture() {
        let root = temp_workspace("h602435");
        write_forked_state(&root, 602_433, 602_436, 602_435);
        assert!(crate::consensus_state::verify_state(&root).ok);
        let plan = plan_for_workspace(&root, 602_434, 602_436);

        let report = apply_state_sync_repair(
            &plan,
            &root,
            StateSyncRepairApplyOptions {
                dry_run: false,
                apply: true,
            },
        )
        .unwrap();

        assert!(report.ok, "{:?}", report.findings);
        let repaired = crate::consensus_state::verify_state(&root);
        assert_eq!(repaired.chain.latest.unwrap().height, 602_436);
        let chain = read_json_value(&root.join("data/chain.json")).unwrap();
        assert_eq!(
            chain[2]["hash"].as_str().map(str::to_string),
            Some(height_hash(602_435))
        );
        assert_eq!(
            chain[3]["hash"].as_str().map(str::to_string),
            Some(height_hash(602_436))
        );
    }

    #[test]
    fn val1_missing_boundary_qc_remains_blocked_without_verified_evidence() {
        let root = temp_workspace("val1-no-qc");
        write_state(&root, 100, 100);
        let plan = plan_for_workspace(&root, 100, 105);
        fs::write(
            root.join(STATE_SYNC_REPAIR_BUNDLE_DIR)
                .join("committed_qcs.jsonl"),
            "",
        )
        .unwrap();

        let report = apply_state_sync_repair(
            &plan,
            &root,
            StateSyncRepairApplyOptions {
                dry_run: false,
                apply: true,
            },
        )
        .unwrap();

        assert!(!report.ok);
        assert!(
            apply_codes(&report).contains(&"state_sync_repair_content_digest_mismatch".to_string())
        );
        assert!(
            apply_codes(&report).contains(&"state_sync_repair_missing_committed_qc".to_string())
        );
        assert_eq!(
            crate::consensus_state::verify_state(&root)
                .chain
                .latest
                .unwrap()
                .height,
            100
        );
    }

    #[test]
    fn interrupted_state_sync_repair_leaves_original_state_intact() {
        let root = temp_workspace("partial-failure");
        write_state(&root, 100, 100);
        let digest = write_repair_bundle_with_options(&root, 101, 105, true);
        let mut plan = plan_for_workspace(&root, 100, 105);
        plan.transfer_content_sha256 = digest;

        let result = apply_state_sync_repair(
            &plan,
            &root,
            StateSyncRepairApplyOptions {
                dry_run: false,
                apply: true,
            },
        );

        assert!(result.is_err());
        let original = crate::consensus_state::verify_state(&root);
        assert!(original.ok, "{:?}", original.findings);
        assert_eq!(original.chain.latest.unwrap().height, 100);
        assert!(!root.join("data").join(STATE_SYNC_REPAIR_RECEIPT).exists());
    }
}
