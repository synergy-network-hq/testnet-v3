use crate::consensus::consensus_fork::{validate_snapshot_fork_metadata, ConsensusForkMigration};
use crate::consensus::self_realign::{
    normalize_snapshot_class, verify_signed_snapshot_manifest, SignedSnapshotManifest,
    SnapshotVerificationPolicy, SnapshotVerificationReport, SNAPSHOT_CLASS_ARCHIVE_BOOTSTRAP,
    SNAPSHOT_CLASS_ARCHIVE_FULL, SNAPSHOT_CLASS_VALIDATOR_PRUNED,
};
use crate::crypto::aegis_pqvm::{
    AegisPqvmSigner, AegisPqvmVerifier, SYNERGY_ARCHIVE_SNAPSHOT_CATALOG_V1,
    SYNERGY_ARCHIVE_SNAPSHOT_MANIFEST_V1,
};
use crate::synergy_types::{
    AegisPqKeyId, AegisPqKeyRole, AegisPqSignature, CanonicalSerialize, ChainId, ClusterId, Hash,
    Height, NetworkId, QuorumCertificate,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const ARCHIVE_SNAPSHOT_INTERVAL_BLOCKS: u64 = 15_000;
pub const ARCHIVE_SNAPSHOT_CHUNK_SIZE_BYTES: u64 = 512 * 1024 * 1024;
pub const ARCHIVE_SNAPSHOT_RETENTION_PER_CLASS: usize = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ArchiveNodeStatus {
    Uninitialized,
    AegisPqvmInitializing,
    AegisPqvmReady,
    ConnectingToTestnet,
    SyncingFromGenesis,
    SyncingFromSnapshot,
    VerifyingChain,
    ArchiveReady,
    CreatingSnapshot,
    ServingSnapshots,
    Degraded,
    FailedClosed,
}

impl ArchiveNodeStatus {
    pub fn can_serve_snapshots(&self) -> bool {
        matches!(self, Self::ArchiveReady | Self::ServingSnapshots)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveValidatorConfig {
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub role: String,
    pub snapshot_interval_blocks: u64,
    pub snapshot_chunk_size_bytes: u64,
    pub retain_verified_snapshots_per_class: usize,
    pub fail_closed_on_verification_error: bool,
    pub archive_peer_key_role: AegisPqKeyRole,
    pub snapshot_signing_key_role: AegisPqKeyRole,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveReseedSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveReseedFinding {
    pub code: String,
    pub severity: ArchiveReseedSeverity,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveReseedPlanInput {
    pub signed_manifest: SignedSnapshotManifest,
    pub snapshot_root: Option<PathBuf>,
    pub archive_services_disabled: bool,
    pub archive_publication_disabled: bool,
    pub unsafe_inventory_reviewed: bool,
    pub current_finalized_height: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveReseedPlanReport {
    pub ok: bool,
    pub decision: String,
    pub dry_run_only: bool,
    pub snapshot_class: String,
    pub snapshot_height: u64,
    pub verification: SnapshotVerificationReport,
    pub actions: Vec<String>,
    pub findings: Vec<ArchiveReseedFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveStatusInput {
    #[serde(default)]
    pub archive_services_disabled: bool,
    #[serde(default)]
    pub snapshot_api_disabled: bool,
    #[serde(default)]
    pub snapshot_worker_disabled: bool,
    #[serde(default)]
    pub archive_publication_disabled: bool,
    #[serde(default)]
    pub unsafe_inventory_reviewed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveUnsafeSnapshotRecord {
    pub snapshot_id: String,
    pub height: u64,
    pub snapshot_class: String,
    pub block_hash: String,
    #[serde(default)]
    pub canonical_verified: bool,
    #[serde(default)]
    pub unsafe_marked: bool,
    #[serde(default)]
    pub quarantined: bool,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveUnsafeSnapshotInventory {
    #[serde(default)]
    pub snapshots: Vec<ArchiveUnsafeSnapshotRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveSafetyReport {
    pub ok: bool,
    pub decision: String,
    pub dry_run_only: bool,
    pub command: String,
    pub services_remain_disabled: bool,
    pub snapshot_api_remains_disabled: bool,
    pub snapshot_worker_remains_disabled: bool,
    pub actions: Vec<String>,
    pub unsafe_snapshots: Vec<ArchiveUnsafeSnapshotRecord>,
    pub findings: Vec<ArchiveReseedFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveCanonicalVerificationInput {
    pub signed_manifest: SignedSnapshotManifest,
    pub snapshot_root: Option<PathBuf>,
    pub expected_height: u64,
    pub expected_block_hash: String,
    pub expected_snapshot_class: String,
    #[serde(default)]
    pub source_canonical: bool,
    #[serde(default)]
    pub allow_validator_pruned_support_snapshot: bool,
    pub current_finalized_height: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveCanonicalVerificationReport {
    pub ok: bool,
    pub decision: String,
    pub dry_run_only: bool,
    pub snapshot_class: String,
    pub snapshot_height: u64,
    pub trusted_for_reseed: bool,
    pub trusted_for_publication: bool,
    pub verification: SnapshotVerificationReport,
    pub findings: Vec<ArchiveReseedFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveReseedDryRunInput {
    pub plan: ArchiveReseedPlanReport,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchivePublishSnapshotInput {
    pub signed_manifest: SignedSnapshotManifest,
    pub snapshot_root: Option<PathBuf>,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub snapshot_api_disabled: bool,
    #[serde(default)]
    pub snapshot_worker_disabled: bool,
    #[serde(default)]
    pub source_canonical: bool,
    #[serde(default)]
    pub unsafe_snapshot: bool,
    pub current_finalized_height: Option<u64>,
}

pub fn build_archive_reseed_plan(input: &ArchiveReseedPlanInput) -> ArchiveReseedPlanReport {
    let mut policy = SnapshotVerificationPolicy {
        target_role: Some("archive_validator".to_string()),
        current_finalized_height: input.current_finalized_height,
        ..SnapshotVerificationPolicy::default()
    };
    policy.expected_snapshot_class = None;
    let verification = verify_signed_snapshot_manifest(
        &input.signed_manifest,
        &policy,
        input.snapshot_root.as_deref(),
    );
    let snapshot_class = verification.snapshot_class.clone();
    let mut findings = Vec::new();

    if !verification.success {
        findings.push(archive_error(
            "snapshot_verification_failed",
            verification.errors.join("; "),
        ));
    }

    match normalize_snapshot_class(&snapshot_class) {
        Some(SNAPSHOT_CLASS_ARCHIVE_BOOTSTRAP) | Some(SNAPSHOT_CLASS_ARCHIVE_FULL) => {}
        Some(class) => findings.push(archive_error(
            "snapshot_class_not_archive",
            format!("archive reseed requires archive-bootstrap or archive-full, got {class}"),
        )),
        None => findings.push(archive_error(
            "snapshot_class_unsupported",
            format!("unsupported snapshot class {snapshot_class}"),
        )),
    }

    if !input.archive_services_disabled {
        findings.push(archive_error(
            "archive_services_not_disabled",
            "archive services must be stopped/unloaded before reseed planning",
        ));
    }
    if !input.archive_publication_disabled {
        findings.push(archive_error(
            "archive_publication_not_disabled",
            "snapshot API/catalog publication must remain disabled during reseed",
        ));
    }
    if !input.unsafe_inventory_reviewed {
        findings.push(archive_error(
            "unsafe_inventory_not_reviewed",
            "stale or noncanonical archive data must be inventoried before reseed",
        ));
    }

    let has_errors = findings
        .iter()
        .any(|finding| finding.severity == ArchiveReseedSeverity::Error);
    ArchiveReseedPlanReport {
        ok: !has_errors,
        decision: if has_errors { "NO_GO" } else { "DRY_RUN_GO" }.to_string(),
        dry_run_only: true,
        snapshot_class,
        snapshot_height: verification.snapshot_height,
        verification,
        actions: vec![
            "keep archive validator services stopped and publication disabled".to_string(),
            "quarantine or mark unsafe all stale archive data before install".to_string(),
            "verify signed archive manifest, file digests, state root, QC, and restore role"
                .to_string(),
            "prepare archive reseed install plan for separate operator approval".to_string(),
            "run post-reseed archive verification before any service start".to_string(),
        ],
        findings,
    }
}

pub fn archive_status(input: &ArchiveStatusInput) -> ArchiveSafetyReport {
    let mut findings = Vec::new();
    if !input.archive_services_disabled {
        findings.push(archive_error(
            "archive_services_not_disabled",
            "archive validator services must remain stopped/unloaded",
        ));
    }
    if !input.snapshot_api_disabled {
        findings.push(archive_error(
            "snapshot_api_not_disabled",
            "snapshot API must remain disabled",
        ));
    }
    if !input.snapshot_worker_disabled {
        findings.push(archive_error(
            "snapshot_worker_not_disabled",
            "snapshot worker must remain disabled",
        ));
    }
    if !input.archive_publication_disabled {
        findings.push(archive_error(
            "archive_publication_not_disabled",
            "archive publication must remain disabled",
        ));
    }
    if !input.unsafe_inventory_reviewed {
        findings.push(archive_warning(
            "unsafe_inventory_not_reviewed",
            "unsafe snapshot inventory has not been reviewed",
        ));
    }
    archive_safety_report(
        "status",
        input.archive_services_disabled,
        input.snapshot_api_disabled,
        input.snapshot_worker_disabled,
        Vec::new(),
        vec![
            "confirm archive services are stopped and unloaded".to_string(),
            "confirm snapshot API, worker, and publication remain disabled".to_string(),
            "review unsafe snapshot inventory before reseed or publish".to_string(),
        ],
        findings,
    )
}

pub fn verify_archive_canonical_snapshot(
    input: &ArchiveCanonicalVerificationInput,
) -> ArchiveCanonicalVerificationReport {
    let mut policy = SnapshotVerificationPolicy {
        current_finalized_height: input.current_finalized_height,
        ..SnapshotVerificationPolicy::default()
    };
    policy.expected_snapshot_class = None;
    let verification = verify_signed_snapshot_manifest(
        &input.signed_manifest,
        &policy,
        input.snapshot_root.as_deref(),
    );
    let snapshot_class = verification.snapshot_class.clone();
    let snapshot_height = verification.snapshot_height;
    let mut findings = Vec::new();

    if !verification.success {
        findings.push(archive_error(
            "snapshot_verification_failed",
            verification.errors.join("; "),
        ));
    }
    if snapshot_height != input.expected_height {
        findings.push(archive_error(
            "snapshot_height_mismatch",
            format!(
                "expected h{} but manifest is h{}",
                input.expected_height, snapshot_height
            ),
        ));
    }
    if input.signed_manifest.manifest.snapshot_block_hash != input.expected_block_hash {
        findings.push(archive_error(
            "snapshot_block_hash_mismatch",
            format!(
                "expected block hash {} but manifest has {}",
                input.expected_block_hash, input.signed_manifest.manifest.snapshot_block_hash
            ),
        ));
    }
    if normalize_snapshot_class(&snapshot_class)
        != normalize_snapshot_class(&input.expected_snapshot_class)
    {
        findings.push(archive_error(
            "snapshot_class_mismatch",
            format!(
                "expected snapshot class {} but manifest has {}",
                input.expected_snapshot_class, snapshot_class
            ),
        ));
    }
    if !input.source_canonical {
        findings.push(archive_error(
            "snapshot_source_not_canonical",
            "snapshot source is not proven canonical",
        ));
    }

    let normalized_class = normalize_snapshot_class(&snapshot_class);
    let archive_class = matches!(
        normalized_class,
        Some(SNAPSHOT_CLASS_ARCHIVE_BOOTSTRAP) | Some(SNAPSHOT_CLASS_ARCHIVE_FULL)
    );
    let validator_pruned_support = normalized_class == Some(SNAPSHOT_CLASS_VALIDATOR_PRUNED)
        && input.allow_validator_pruned_support_snapshot;
    if !archive_class && !validator_pruned_support {
        findings.push(archive_error(
            "snapshot_class_not_allowed",
            format!("snapshot class {snapshot_class} is not allowed for this archive gate"),
        ));
    }

    let has_errors = has_archive_errors(&findings);
    ArchiveCanonicalVerificationReport {
        ok: !has_errors,
        decision: if has_errors { "NO_GO" } else { "DRY_RUN_GO" }.to_string(),
        dry_run_only: true,
        snapshot_class,
        snapshot_height,
        trusted_for_reseed: !has_errors && archive_class,
        trusted_for_publication: !has_errors && (archive_class || validator_pruned_support),
        verification,
        findings,
    }
}

pub fn dry_run_archive_reseed(input: &ArchiveReseedDryRunInput) -> ArchiveSafetyReport {
    let mut findings = input.plan.findings.clone();
    if !input.dry_run {
        findings.push(archive_error(
            "archive_reseed_apply_forbidden",
            "archive reseed command is available only with --dry-run in Prompt 2",
        ));
    }
    if !input.plan.ok {
        findings.push(archive_error(
            "archive_reseed_plan_not_go",
            "archive reseed dry-run requires a GO reseed plan",
        ));
    }
    archive_safety_report(
        "reseed_dry_run",
        true,
        true,
        true,
        Vec::new(),
        vec![
            format!(
                "verify archive {} snapshot at h{}",
                input.plan.snapshot_class, input.plan.snapshot_height
            ),
            "keep archive validator service stopped/unloaded".to_string(),
            "keep snapshot API and worker disabled".to_string(),
            "stage file-copy plan only after separate operator approval".to_string(),
            "do not start archive service or publish snapshots from dry-run".to_string(),
        ],
        findings,
    )
}

pub fn dry_run_publish_snapshot(input: &ArchivePublishSnapshotInput) -> ArchiveSafetyReport {
    let mut policy = SnapshotVerificationPolicy {
        current_finalized_height: input.current_finalized_height,
        ..SnapshotVerificationPolicy::default()
    };
    policy.expected_snapshot_class = None;
    let verification = verify_signed_snapshot_manifest(
        &input.signed_manifest,
        &policy,
        input.snapshot_root.as_deref(),
    );
    let mut findings = Vec::new();
    if !input.dry_run {
        findings.push(archive_error(
            "snapshot_publish_apply_forbidden",
            "snapshot publication is available only with --dry-run in Prompt 2",
        ));
    }
    if !input.snapshot_api_disabled {
        findings.push(archive_error(
            "snapshot_api_not_disabled",
            "snapshot API must remain disabled during publish dry-run",
        ));
    }
    if !input.snapshot_worker_disabled {
        findings.push(archive_error(
            "snapshot_worker_not_disabled",
            "snapshot worker must remain disabled during publish dry-run",
        ));
    }
    if !verification.success {
        findings.push(archive_error(
            "snapshot_verification_failed",
            verification.errors.join("; "),
        ));
    }
    if !input.source_canonical {
        findings.push(archive_error(
            "snapshot_worker_noncanonical_source",
            "snapshot worker refuses noncanonical source evidence",
        ));
    }
    if input.unsafe_snapshot {
        findings.push(archive_error(
            "snapshot_api_unsafe_snapshot",
            "snapshot API refuses snapshots marked unsafe",
        ));
    }
    archive_safety_report(
        "publish_snapshot_dry_run",
        true,
        input.snapshot_api_disabled,
        input.snapshot_worker_disabled,
        Vec::new(),
        vec![
            "verify signed snapshot manifest and file digests".to_string(),
            "refuse noncanonical source evidence".to_string(),
            "refuse snapshots marked unsafe".to_string(),
            "leave snapshot API and worker disabled".to_string(),
        ],
        findings,
    )
}

pub fn list_unsafe_snapshots(input: &ArchiveUnsafeSnapshotInventory) -> ArchiveSafetyReport {
    let unsafe_snapshots = input
        .snapshots
        .iter()
        .filter(|snapshot| !snapshot.canonical_verified || snapshot.unsafe_marked)
        .cloned()
        .collect::<Vec<_>>();
    archive_safety_report(
        "list_unsafe_snapshots",
        true,
        true,
        true,
        unsafe_snapshots,
        vec!["list unsafe or noncanonical snapshots without mutating files".to_string()],
        Vec::new(),
    )
}

pub fn mark_unsafe_snapshot(snapshot: ArchiveUnsafeSnapshotRecord) -> ArchiveSafetyReport {
    let mut marked = snapshot;
    marked.unsafe_marked = true;
    if marked.reason.as_deref().unwrap_or("").trim().is_empty() {
        marked.reason = Some("operator_marked_unsafe".to_string());
    }
    archive_safety_report(
        "mark_unsafe_snapshot",
        true,
        true,
        true,
        vec![marked],
        vec![
            "dry-run unsafe marker only; no snapshot data is deleted".to_string(),
            "review marker before any fixture-only mutation".to_string(),
        ],
        Vec::new(),
    )
}

pub fn quarantine_snapshot(snapshot: ArchiveUnsafeSnapshotRecord) -> ArchiveSafetyReport {
    let mut quarantined = snapshot;
    quarantined.unsafe_marked = true;
    quarantined.quarantined = true;
    if quarantined
        .reason
        .as_deref()
        .unwrap_or("")
        .trim()
        .is_empty()
    {
        quarantined.reason = Some("operator_quarantine".to_string());
    }
    archive_safety_report(
        "quarantine_snapshot",
        true,
        true,
        true,
        vec![quarantined],
        vec![
            "dry-run quarantine plan only; no snapshot data is deleted".to_string(),
            "move data only in fixture tests or after separate operator approval".to_string(),
        ],
        Vec::new(),
    )
}

fn archive_safety_report(
    command: &'static str,
    services_remain_disabled: bool,
    snapshot_api_remains_disabled: bool,
    snapshot_worker_remains_disabled: bool,
    unsafe_snapshots: Vec<ArchiveUnsafeSnapshotRecord>,
    actions: Vec<String>,
    findings: Vec<ArchiveReseedFinding>,
) -> ArchiveSafetyReport {
    let has_errors = has_archive_errors(&findings);
    ArchiveSafetyReport {
        ok: !has_errors,
        decision: if has_errors { "NO_GO" } else { "DRY_RUN_GO" }.to_string(),
        dry_run_only: true,
        command: command.to_string(),
        services_remain_disabled,
        snapshot_api_remains_disabled,
        snapshot_worker_remains_disabled,
        actions,
        unsafe_snapshots,
        findings,
    }
}

fn has_archive_errors(findings: &[ArchiveReseedFinding]) -> bool {
    findings
        .iter()
        .any(|finding| finding.severity == ArchiveReseedSeverity::Error)
}

fn archive_error(code: impl Into<String>, detail: impl Into<String>) -> ArchiveReseedFinding {
    ArchiveReseedFinding {
        code: code.into(),
        severity: ArchiveReseedSeverity::Error,
        detail: detail.into(),
    }
}

fn archive_warning(code: impl Into<String>, detail: impl Into<String>) -> ArchiveReseedFinding {
    ArchiveReseedFinding {
        code: code.into(),
        severity: ArchiveReseedSeverity::Warning,
        detail: detail.into(),
    }
}

impl ArchiveValidatorConfig {
    pub fn testnet_default() -> Self {
        Self {
            chain_id: ChainId::synergy_testnet_v3(),
            network_id: NetworkId::synergy_testnet_v3(),
            role: "ARCHIVE_OBSERVER".to_string(),
            snapshot_interval_blocks: ARCHIVE_SNAPSHOT_INTERVAL_BLOCKS,
            snapshot_chunk_size_bytes: ARCHIVE_SNAPSHOT_CHUNK_SIZE_BYTES,
            retain_verified_snapshots_per_class: ARCHIVE_SNAPSHOT_RETENTION_PER_CLASS,
            fail_closed_on_verification_error: true,
            archive_peer_key_role: AegisPqKeyRole::ArchivePeer,
            snapshot_signing_key_role: AegisPqKeyRole::ArchiveSnapshotSigner,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        self.chain_id.require_testnet_v3()?;
        self.network_id.require_testnet_v3()?;
        if self.role != "ARCHIVE_OBSERVER" && self.role != "ARCHIVE_VALIDATOR_NON_CONSENSUS" {
            return Err(
                "archive validator package must use a non-consensus archive role".to_string(),
            );
        }
        if self.snapshot_interval_blocks != ARCHIVE_SNAPSHOT_INTERVAL_BLOCKS {
            return Err("testnet archive snapshot interval must be 15000 blocks".to_string());
        }
        if self.snapshot_chunk_size_bytes != ARCHIVE_SNAPSHOT_CHUNK_SIZE_BYTES {
            return Err("testnet archive snapshot chunks must be 512 MiB".to_string());
        }
        if self.retain_verified_snapshots_per_class != ARCHIVE_SNAPSHOT_RETENTION_PER_CLASS {
            return Err(
                "testnet archive must retain the latest 2 verified snapshots per class".to_string(),
            );
        }
        if !self.fail_closed_on_verification_error {
            return Err("archive validator must fail closed on verification error".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotManifest {
    pub snapshot_version: u32,
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub genesis_hash: Hash,
    pub snapshot_height: Height,
    pub snapshot_block_id: String,
    pub snapshot_block_hash: Hash,
    pub snapshot_parent_hash: Hash,
    pub snapshot_state_root: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consensus_fork: Option<ConsensusForkMigration>,
    pub snapshot_receipt_root: Hash,
    pub snapshot_qc_hash: Hash,
    pub snapshot_epoch: crate::synergy_types::Epoch,
    pub snapshot_cluster_id: ClusterId,
    pub active_validator_set_hash: Hash,
    pub eligible_validator_set_hash: Hash,
    pub cluster_map_hash: Hash,
    pub proposer_schedule_hash: Hash,
    pub protocol_config_hash: Hash,
    pub aegis_pqvm_version: String,
    pub archive_node_id: String,
    pub archive_node_role: String,
    pub archive_node_aegis_key_id: AegisPqKeyId,
    pub snapshot_signing_key_id: AegisPqKeyId,
    pub created_at_unix_ms: u64,
    pub snapshot_interval_blocks: u64,
    pub previous_snapshot_height: Height,
    pub previous_snapshot_manifest_hash: Hash,
    pub content_root: Hash,
    pub chunk_hashes_root: Hash,
    pub state_db_format_version: String,
    pub block_store_format_version: String,
    pub compression_algorithm: String,
    pub chunk_size_bytes: u64,
    pub total_uncompressed_bytes: u64,
    pub total_compressed_bytes: u64,
    pub required_replay_start_height: Height,
    pub required_replay_end_height: Height,
    pub manifest_domain_separator: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotCatalogEntry {
    pub height: Height,
    pub manifest_hash: Hash,
    pub content_root: Hash,
    pub state_root: Hash,
    pub download_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotCatalog {
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub genesis_hash: Hash,
    pub archive_node_id: String,
    pub latest_verified_height: Height,
    pub latest_snapshot_height: Height,
    pub snapshots: Vec<SnapshotCatalogEntry>,
    pub catalog_content_root: Hash,
    pub catalog_created_at_unix_ms: u64,
    pub catalog_signature_key_id: AegisPqKeyId,
}

pub struct ArchiveValidatorNode {
    pub config: ArchiveValidatorConfig,
    pub status: ArchiveNodeStatus,
}

impl ArchiveValidatorNode {
    pub fn new(config: ArchiveValidatorConfig) -> Result<Self, String> {
        config.validate()?;
        Ok(Self {
            config,
            status: ArchiveNodeStatus::Uninitialized,
        })
    }

    pub fn can_vote(&self) -> bool {
        false
    }

    pub fn can_propose(&self) -> bool {
        false
    }

    pub fn can_count_in_qc(&self) -> bool {
        false
    }

    pub fn verify_finalized_qc(
        &self,
        qc: &QuorumCertificate,
        verifier: &AegisPqvmVerifier,
        validator_set: &crate::synergy_types::ValidatorSet,
        cluster_map: &crate::synergy_types::ClusterMap,
    ) -> Result<(), String> {
        self.config.validate()?;
        verifier
            .verify_qc_checked(qc, validator_set, cluster_map)
            .map_err(|error| error.to_string())
    }

    pub fn sign_manifest(
        &self,
        signer: &mut AegisPqvmSigner,
        manifest: &SnapshotManifest,
    ) -> Result<AegisPqSignature, String> {
        self.config.validate()?;
        if manifest.chain_id != self.config.chain_id
            || manifest.network_id != self.config.network_id
        {
            return Err("snapshot manifest chain/network mismatch".to_string());
        }
        signer
            .sign_domain(
                SYNERGY_ARCHIVE_SNAPSHOT_MANIFEST_V1,
                &manifest.canonical_bytes()?,
                &manifest.snapshot_signing_key_id,
            )
            .map_err(|error| error.to_string())
    }

    pub fn sign_catalog(
        &self,
        signer: &mut AegisPqvmSigner,
        catalog: &SnapshotCatalog,
    ) -> Result<AegisPqSignature, String> {
        self.config.validate()?;
        signer
            .sign_domain(
                SYNERGY_ARCHIVE_SNAPSHOT_CATALOG_V1,
                &catalog.canonical_bytes()?,
                &catalog.catalog_signature_key_id,
            )
            .map_err(|error| error.to_string())
    }
}

pub fn verify_snapshot_manifest(
    manifest: &SnapshotManifest,
    signature: &AegisPqSignature,
    expected_genesis_hash: Hash,
    verifier: &AegisPqvmVerifier,
) -> Result<(), String> {
    manifest.chain_id.require_testnet_v3()?;
    manifest.network_id.require_testnet_v3()?;
    if manifest.genesis_hash != expected_genesis_hash {
        return Err("snapshot genesis_hash mismatch".to_string());
    }
    if manifest.manifest_domain_separator != SYNERGY_ARCHIVE_SNAPSHOT_MANIFEST_V1 {
        return Err("snapshot manifest domain separator mismatch".to_string());
    }
    if manifest.content_root == Hash::zero() {
        return Err("snapshot content_root missing".to_string());
    }
    validate_snapshot_fork_metadata(manifest.snapshot_height.0, manifest.consensus_fork.as_ref())?;
    verifier
        .verify_domain_signature(
            SYNERGY_ARCHIVE_SNAPSHOT_MANIFEST_V1,
            &manifest.canonical_bytes()?,
            &manifest.archive_node_id,
            &manifest.snapshot_signing_key_id,
            manifest.snapshot_epoch,
            AegisPqKeyRole::ArchiveSnapshotSigner,
            signature,
        )
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::self_realign::{
        create_snapshot_manifest, sign_snapshot_manifest, SnapshotBuildInput, SnapshotQcEvidence,
        SNAPSHOT_CLASS_VALIDATOR_PRUNED, VALIDATOR_PRUNED_REQUIRED_STATE_FILES,
    };
    use crate::crypto::aegis_pqvm::AegisPqvmSigner;
    use crate::synergy_types::{AegisPqPublicKey, Epoch};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crate has repository parent")
            .to_path_buf()
    }

    fn temp_snapshot_root(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("synergy-archive-reseed-{label}-{unique}"));
        std::fs::create_dir_all(&root).unwrap();
        for file_name in VALIDATOR_PRUNED_REQUIRED_STATE_FILES {
            let contents = match *file_name {
                "chain.json" => b"[]".as_slice(),
                "committed_blocks.jsonl" | "committed_qcs.jsonl" => b"{}\n".as_slice(),
                _ => b"{}".as_slice(),
            };
            std::fs::write(root.join(file_name), contents).unwrap();
        }
        root
    }

    fn reseed_signer() -> (AegisPqvmSigner, AegisPqKeyId, AegisPqPublicKey) {
        let mut signer = AegisPqvmSigner::initialize_required().unwrap();
        let key_id = signer
            .generate_and_register_key(
                "archive-1",
                vec![AegisPqKeyRole::ArchiveSnapshotSigner],
                Epoch(0),
            )
            .unwrap();
        let public = signer.public_key_record(&key_id).unwrap();
        (signer, key_id, public)
    }

    fn reseed_qc_evidence_at(height: u64) -> SnapshotQcEvidence {
        SnapshotQcEvidence {
            committed_qc_height: height,
            committed_qc_hash: "qc-hash".to_string(),
            vote_count: 4,
            signer_set: vec![
                "validator-1".to_string(),
                "validator-2".to_string(),
                "validator-3".to_string(),
                "validator-4".to_string(),
            ],
            aegis_pqc_verified: true,
            duplicate_signer_check_passed: true,
            active_validator_count: 5,
            active_validator_set_meets_baseline: true,
            relayers_rpc_support_counted_toward_quorum: false,
        }
    }

    fn reseed_signed_manifest(snapshot_class: &str) -> (SignedSnapshotManifest, PathBuf) {
        reseed_signed_manifest_at(snapshot_class, 100, "block-hash")
    }

    fn reseed_signed_manifest_at(
        snapshot_class: &str,
        snapshot_height: u64,
        snapshot_block_hash: &str,
    ) -> (SignedSnapshotManifest, PathBuf) {
        let root = temp_snapshot_root(snapshot_class);
        let (mut signer, key_id, public) = reseed_signer();
        let manifest = create_snapshot_manifest(SnapshotBuildInput {
            state_dir: root.clone(),
            snapshot_class: snapshot_class.to_string(),
            allowed_restore_roles: Vec::new(),
            snapshot_height,
            snapshot_block_hash: snapshot_block_hash.to_string(),
            parent_hash: "parent-hash".to_string(),
            state_root: None,
            canonical_lock_height: snapshot_height,
            canonical_lock_hash: snapshot_block_hash.to_string(),
            qc_evidence: reseed_qc_evidence_at(snapshot_height),
            active_validator_set: (1..=5).map(|index| format!("validator-{index}")).collect(),
            source_node_id: "validator-2".to_string(),
            source_role: "VALIDATOR".to_string(),
            runtime_checksum: "runtime-sha256".to_string(),
            source_node_quarantined: false,
            source_node_majority_branch: true,
            conflict_height_hash: Some(snapshot_block_hash.to_string()),
            manifest_signer_uma_id: "archive-1".to_string(),
            manifest_signing_key_id: key_id,
            manifest_signer_public_key: public,
            manifest_signature_epoch: 0,
            created_at: 1,
        })
        .unwrap();
        (sign_snapshot_manifest(&mut signer, manifest).unwrap(), root)
    }

    fn finding_codes(report: &ArchiveReseedPlanReport) -> Vec<String> {
        report
            .findings
            .iter()
            .map(|finding| finding.code.clone())
            .collect()
    }

    fn canonical_codes(report: &ArchiveCanonicalVerificationReport) -> Vec<String> {
        report
            .findings
            .iter()
            .map(|finding| finding.code.clone())
            .collect()
    }

    fn safety_codes(report: &ArchiveSafetyReport) -> Vec<String> {
        report
            .findings
            .iter()
            .map(|finding| finding.code.clone())
            .collect()
    }

    #[test]
    fn archive_node_cannot_vote_propose_or_count_in_qc() {
        let archive = ArchiveValidatorNode::new(ArchiveValidatorConfig::testnet_default()).unwrap();
        assert!(!archive.can_vote());
        assert!(!archive.can_propose());
        assert!(!archive.can_count_in_qc());
    }

    #[test]
    fn archive_config_enforces_testnet_chain_and_network() {
        let mut config = ArchiveValidatorConfig::testnet_default();
        config.chain_id = ChainId(999);
        assert!(ArchiveValidatorNode::new(config).is_err());
        let mut config = ArchiveValidatorConfig::testnet_default();
        config.network_id = NetworkId("wrong".to_string());
        assert!(ArchiveValidatorNode::new(config).is_err());
    }

    #[test]
    fn archive_reseed_plan_accepts_verified_archive_bootstrap_manifest_dry_run_only() {
        let (signed_manifest, root) = reseed_signed_manifest(SNAPSHOT_CLASS_ARCHIVE_BOOTSTRAP);
        let report = build_archive_reseed_plan(&ArchiveReseedPlanInput {
            signed_manifest,
            snapshot_root: Some(root),
            archive_services_disabled: true,
            archive_publication_disabled: true,
            unsafe_inventory_reviewed: true,
            current_finalized_height: Some(100),
        });
        assert!(report.ok, "{:?}", report.findings);
        assert_eq!(report.decision, "DRY_RUN_GO");
        assert!(report.dry_run_only);
        assert_eq!(report.snapshot_class, SNAPSHOT_CLASS_ARCHIVE_BOOTSTRAP);
    }

    #[test]
    fn archive_reseed_plan_rejects_validator_pruned_manifest() {
        let (signed_manifest, root) = reseed_signed_manifest(SNAPSHOT_CLASS_VALIDATOR_PRUNED);
        let report = build_archive_reseed_plan(&ArchiveReseedPlanInput {
            signed_manifest,
            snapshot_root: Some(root),
            archive_services_disabled: true,
            archive_publication_disabled: true,
            unsafe_inventory_reviewed: true,
            current_finalized_height: Some(100),
        });
        assert!(!report.ok);
        assert!(finding_codes(&report).contains(&"snapshot_class_not_archive".to_string()));
    }

    #[test]
    fn archive_reseed_plan_requires_containment_before_reseed() {
        let (signed_manifest, root) = reseed_signed_manifest(SNAPSHOT_CLASS_ARCHIVE_BOOTSTRAP);
        let report = build_archive_reseed_plan(&ArchiveReseedPlanInput {
            signed_manifest,
            snapshot_root: Some(root),
            archive_services_disabled: false,
            archive_publication_disabled: false,
            unsafe_inventory_reviewed: false,
            current_finalized_height: Some(100),
        });
        let codes = finding_codes(&report);
        assert!(!report.ok);
        assert!(codes.contains(&"archive_services_not_disabled".to_string()));
        assert!(codes.contains(&"archive_publication_not_disabled".to_string()));
        assert!(codes.contains(&"unsafe_inventory_not_reviewed".to_string()));
    }

    #[test]
    fn h602192_noncanonical_archive_snapshot_remains_contained() {
        let report = list_unsafe_snapshots(&ArchiveUnsafeSnapshotInventory {
            snapshots: vec![ArchiveUnsafeSnapshotRecord {
                snapshot_id: "archive-h602192".to_string(),
                height: 602_192,
                snapshot_class: SNAPSHOT_CLASS_ARCHIVE_BOOTSTRAP.to_string(),
                block_hash: "noncanonical-hash".to_string(),
                canonical_verified: false,
                unsafe_marked: true,
                quarantined: true,
                reason: Some("noncanonical archive incident fixture".to_string()),
            }],
        });
        assert!(report.ok, "{:?}", report.findings);
        assert_eq!(report.unsafe_snapshots.len(), 1);
        assert_eq!(report.unsafe_snapshots[0].height, 602_192);
        assert!(report.unsafe_snapshots[0].quarantined);
    }

    #[test]
    fn h537712_archive_full_mismatch_is_rejected() {
        let (signed_manifest, root) =
            reseed_signed_manifest_at(SNAPSHOT_CLASS_ARCHIVE_FULL, 537_712, "archive-full-hash");
        let report = verify_archive_canonical_snapshot(&ArchiveCanonicalVerificationInput {
            signed_manifest,
            snapshot_root: Some(root),
            expected_height: 537_712,
            expected_block_hash: "different-hash".to_string(),
            expected_snapshot_class: SNAPSHOT_CLASS_ARCHIVE_FULL.to_string(),
            source_canonical: true,
            allow_validator_pruned_support_snapshot: false,
            current_finalized_height: Some(537_712),
        });
        assert!(!report.ok);
        assert!(!report.trusted_for_reseed);
        assert!(canonical_codes(&report).contains(&"snapshot_block_hash_mismatch".to_string()));
    }

    #[test]
    fn h601891_validator_pruned_is_accepted_only_with_matching_proof() {
        let (signed_manifest, root) = reseed_signed_manifest_at(
            SNAPSHOT_CLASS_VALIDATOR_PRUNED,
            601_891,
            "validator-pruned-hash",
        );
        let report = verify_archive_canonical_snapshot(&ArchiveCanonicalVerificationInput {
            signed_manifest: signed_manifest.clone(),
            snapshot_root: Some(root.clone()),
            expected_height: 601_891,
            expected_block_hash: "validator-pruned-hash".to_string(),
            expected_snapshot_class: SNAPSHOT_CLASS_VALIDATOR_PRUNED.to_string(),
            source_canonical: true,
            allow_validator_pruned_support_snapshot: true,
            current_finalized_height: Some(601_891),
        });
        assert!(report.ok, "{:?}", report.findings);
        assert!(!report.trusted_for_reseed);
        assert!(report.trusted_for_publication);

        let rejected = verify_archive_canonical_snapshot(&ArchiveCanonicalVerificationInput {
            signed_manifest,
            snapshot_root: Some(root),
            expected_height: 601_891,
            expected_block_hash: "wrong-hash".to_string(),
            expected_snapshot_class: SNAPSHOT_CLASS_VALIDATOR_PRUNED.to_string(),
            source_canonical: true,
            allow_validator_pruned_support_snapshot: true,
            current_finalized_height: Some(601_891),
        });
        assert!(!rejected.ok);
        assert!(canonical_codes(&rejected).contains(&"snapshot_block_hash_mismatch".to_string()));
    }

    #[test]
    fn snapshot_worker_refuses_noncanonical_source() {
        let (signed_manifest, root) = reseed_signed_manifest(SNAPSHOT_CLASS_ARCHIVE_BOOTSTRAP);
        let report = dry_run_publish_snapshot(&ArchivePublishSnapshotInput {
            signed_manifest,
            snapshot_root: Some(root),
            dry_run: true,
            snapshot_api_disabled: true,
            snapshot_worker_disabled: true,
            source_canonical: false,
            unsafe_snapshot: false,
            current_finalized_height: Some(100),
        });
        assert!(!report.ok);
        assert!(safety_codes(&report).contains(&"snapshot_worker_noncanonical_source".to_string()));
        assert!(report.snapshot_worker_remains_disabled);
    }

    #[test]
    fn snapshot_api_refuses_unsafe_snapshot() {
        let (signed_manifest, root) = reseed_signed_manifest(SNAPSHOT_CLASS_ARCHIVE_BOOTSTRAP);
        let report = dry_run_publish_snapshot(&ArchivePublishSnapshotInput {
            signed_manifest,
            snapshot_root: Some(root),
            dry_run: true,
            snapshot_api_disabled: true,
            snapshot_worker_disabled: true,
            source_canonical: true,
            unsafe_snapshot: true,
            current_finalized_height: Some(100),
        });
        assert!(!report.ok);
        assert!(safety_codes(&report).contains(&"snapshot_api_unsafe_snapshot".to_string()));
        assert!(report.snapshot_api_remains_disabled);
    }

    #[test]
    fn archive_reseed_dry_run_shows_steps_and_keeps_services_disabled() {
        let (signed_manifest, root) = reseed_signed_manifest(SNAPSHOT_CLASS_ARCHIVE_BOOTSTRAP);
        let plan = build_archive_reseed_plan(&ArchiveReseedPlanInput {
            signed_manifest,
            snapshot_root: Some(root),
            archive_services_disabled: true,
            archive_publication_disabled: true,
            unsafe_inventory_reviewed: true,
            current_finalized_height: Some(100),
        });
        assert!(plan.ok, "{:?}", plan.findings);
        let report = dry_run_archive_reseed(&ArchiveReseedDryRunInput {
            plan,
            dry_run: true,
        });
        assert!(report.ok, "{:?}", report.findings);
        assert!(report.services_remain_disabled);
        assert!(report.snapshot_api_remains_disabled);
        assert!(report.snapshot_worker_remains_disabled);
        assert!(report
            .actions
            .iter()
            .any(|action| action.contains("keep archive validator service stopped")));
    }

    #[test]
    fn snapshot_manifest_must_be_signed_with_real_aegis_pqc() {
        let mut signer = AegisPqvmSigner::initialize_required().unwrap();
        let key_id = signer
            .generate_and_register_key(
                "archive-node-1",
                vec![AegisPqKeyRole::ArchiveSnapshotSigner],
                Epoch(0),
            )
            .unwrap();
        let manifest = SnapshotManifest {
            snapshot_version: 1,
            chain_id: ChainId::synergy_testnet_v3(),
            network_id: NetworkId::synergy_testnet_v3(),
            genesis_hash: Hash::from_domain_bytes("genesis", b"test"),
            snapshot_height: Height(10_000),
            snapshot_block_id: "block".to_string(),
            snapshot_block_hash: Hash::from_domain_bytes("block", b"10000"),
            snapshot_parent_hash: Hash::zero(),
            snapshot_state_root: Hash::from_domain_bytes("state", b"10000"),
            consensus_fork: None,
            snapshot_receipt_root: Hash::zero(),
            snapshot_qc_hash: Hash::from_domain_bytes("qc", b"10000"),
            snapshot_epoch: Epoch(0),
            snapshot_cluster_id: ClusterId(0),
            active_validator_set_hash: Hash::zero(),
            eligible_validator_set_hash: Hash::zero(),
            cluster_map_hash: Hash::zero(),
            proposer_schedule_hash: Hash::zero(),
            protocol_config_hash: Hash::zero(),
            aegis_pqvm_version: "aegis-pqvm".to_string(),
            archive_node_id: "archive-node-1".to_string(),
            archive_node_role: "ARCHIVE_OBSERVER".to_string(),
            archive_node_aegis_key_id: key_id.clone(),
            snapshot_signing_key_id: key_id,
            created_at_unix_ms: 0,
            snapshot_interval_blocks: ARCHIVE_SNAPSHOT_INTERVAL_BLOCKS,
            previous_snapshot_height: Height(0),
            previous_snapshot_manifest_hash: Hash::zero(),
            content_root: Hash::from_domain_bytes("content", b"snapshot"),
            chunk_hashes_root: Hash::from_domain_bytes("chunks", b"snapshot"),
            state_db_format_version: "v1".to_string(),
            block_store_format_version: "v1".to_string(),
            compression_algorithm: "zstd".to_string(),
            chunk_size_bytes: ARCHIVE_SNAPSHOT_CHUNK_SIZE_BYTES,
            total_uncompressed_bytes: 1,
            total_compressed_bytes: 1,
            required_replay_start_height: Height(10_001),
            required_replay_end_height: Height(10_000),
            manifest_domain_separator: SYNERGY_ARCHIVE_SNAPSHOT_MANIFEST_V1.to_string(),
        };
        let archive = ArchiveValidatorNode::new(ArchiveValidatorConfig::testnet_default()).unwrap();
        let sig = archive.sign_manifest(&mut signer, &manifest).unwrap();
        assert!(verify_snapshot_manifest(
            &manifest,
            &sig,
            manifest.genesis_hash,
            &signer.verifier()
        )
        .is_ok());
        let mut corrupted = manifest.clone();
        corrupted.chain_id = ChainId(999);
        assert!(verify_snapshot_manifest(
            &corrupted,
            &sig,
            manifest.genesis_hash,
            &signer.verifier()
        )
        .is_err());
    }

    #[test]
    fn archive_package_contains_required_linux_macos_and_windows_assets() {
        let root = repo_root().join("archive-validator");
        for path in [
            "README.md",
            "setup-archive-validator.sh",
            "uninstall-archive-validator.sh",
            "verify-archive-validator-install.sh",
            "package-archive-validator.sh",
            ".env.example",
            "config/archive-validator.testnet.toml",
            "config/snapshot-policy.testnet.toml",
            "config/archive-api.testnet.toml",
            "config/genesis.testnet.json.template",
            "systemd/synergy-archive-validator.service",
            "systemd/synergy-archive-snapshot-api.service",
            "systemd/synergy-archive-snapshot-worker.service",
            "launchd/io.synergynetwork.archive-validator.plist",
            "launchd/io.synergynetwork.archive-snapshot-api.plist",
            "launchd/io.synergynetwork.archive-snapshot-worker.plist",
            "macos/build-macos-pkg.sh",
            "macos/preinstall",
            "macos/postinstall",
            "macos/uninstall-macos.sh",
            "macos/entitlements.plist",
            "macos/README-GATEKEEPER.md",
            "macos-m4/setup-archive-validator-m4.sh",
            "macos-m4/verify-archive-validator-m4.sh",
            "macos-m4/restore-archive-bootstrap-m4.sh",
            "macos-m4/run-isolated-mac-acceptance.sh",
            "macos-m4/launchd/io.synergynetwork.archive-validator.plist.in",
            "macos-m4/launchd/io.synergynetwork.archive-snapshot-api.plist.in",
            "macos-m4/launchd/io.synergynetwork.archive-snapshot-worker.plist.in",
            "docs/MACOS_INSTALL.md",
            "docs/MACOS_M4_HANDOFF.md",
            "docs/WINDOWS_VALIDATOR_SNAPSHOT_RESTORE.md",
            "docs/SNAPSHOT_VERIFICATION.md",
            "windows/Restore-ValidatorSnapshot.ps1",
            "windows/Setup-WindowsValidatorFromArchiveSnapshot.ps1",
            "bin/README.md",
        ] {
            assert!(
                root.join(path).exists(),
                "missing archive package asset: {path}"
            );
        }
    }

    #[test]
    fn archive_package_scripts_fail_closed_for_artifacts_and_gatekeeper() {
        let root = repo_root().join("archive-validator");
        let package_script = std::fs::read_to_string(root.join("package-archive-validator.sh"))
            .expect("package script");
        assert!(package_script.contains("synergy-archive-validator-testnet-v3-linux-x64.zip"));
        assert!(package_script.contains("synergy-archive-validator-testnet-v3-macos-universal.zip"));
        assert!(
            package_script.contains("synergy-archive-validator-testnet-v3-windows-receiver.zip")
        );
        assert!(package_script.contains("synergy-archive-validator-testnet-v3.zip"));
        assert!(package_script.contains("Refusing to package private keys"));
        assert!(package_script.contains("snapshots"));
        assert!(package_script.contains("evidence"));
        assert!(package_script.contains("package_windows"));

        let macos_script =
            std::fs::read_to_string(root.join("macos/build-macos-pkg.sh")).expect("macos script");
        for required in [
            "DEVELOPER_ID_APPLICATION",
            "DEVELOPER_ID_INSTALLER",
            "notarytool submit",
            "stapler staple",
            "spctl --assess",
            "pkgutil --check-signature",
        ] {
            assert!(
                macos_script.contains(required),
                "macOS package script must require {required}"
            );
        }

        let m4_package_script =
            std::fs::read_to_string(root.join("package-archive-validator-macos-m4.sh"))
                .expect("m4 package script");
        for required in [
            "xattr -dr com.apple.quarantine",
            "codesign --force --sign -",
            "codesign --verify",
            "synergy-archive-validator-testnet-v3-macos-m4-storage-volume.zip",
            "config/consensus-fork-migration.json",
            "runtime_root=/Users/Shared/Synergy/archive-validator",
        ] {
            assert!(
                m4_package_script.contains(required),
                "M4 package builder must contain {required}"
            );
        }

        let archive_authority = std::fs::read_to_string(root.join("macos/archive-authority.py"))
            .expect("archive authority script");
        for required in [
            "DEFAULT_ROOT = Path(\"/Users/Shared/Synergy/archive-validator\")",
            "DEFAULT_PUBLISH_ROOT = Path(\"/Volumes/Synergy_Archive/archive-validator/snapshots\")",
            "FORK_HEIGHT = 204_216",
            "FORK_PARENT_HEIGHT = 204_215",
            "POST_FORK_CONSENSUS_ALGORITHM = \"FN-DSA\"",
            "latest_local_canonical_height(workspace: Path) -> int | None",
            "\"consensus_fork\": consensus_fork",
            "validate_consensus_fork_metadata(distribution_fork)",
            "snapshot catalog consensus fork metadata mismatch",
            "SUPPORTED_RECEIVER_OPERATING_SYSTEMS = [\"macos\", \"linux\", \"windows\"]",
            "\"supported_receiver_operating_systems\": SUPPORTED_RECEIVER_OPERATING_SYSTEMS",
            "\"receiver_format\": RECEIVER_FORMAT",
            "\"receivers/\"",
        ] {
            assert!(
                archive_authority.contains(required),
                "archive authority must contain {required}"
            );
        }

        let m4_setup = std::fs::read_to_string(root.join("macos-m4/setup-archive-validator-m4.sh"))
            .expect("m4 setup script");
        for required in [
            "source \"${PACKAGE_ROOT}/archive-paths.sh\"",
            "archive_paths_load_defaults",
            "archive_paths_validate",
            "SMB_ROOT=\"$(archive_paths_prefix \"${TEST_ROOT}\" \"${ARCHIVE_STORAGE_VOLUME}/archive-validator\")\"",
            "PUBLISH_ROOT=\"$(archive_paths_prefix \"${TEST_ROOT}\" \"${ARCHIVE_PUBLISH_ROOT}\")\"",
            "INCOMING_BOOTSTRAP=\"${SMB_ROOT}/incoming/bootstrap\"",
            "xattr -dr com.apple.quarantine",
            "codesign --force --sign -",
            "launchctl kickstart -k",
            "wait_for_tcp 127.0.0.1 5622 archive_p2p",
            "wait_for_qrpc_latest_block 5640",
            "required archive storage volume is not mounted",
            "archive storage volume missing in test root",
            "consensus-fork-migration.json",
        ] {
            assert!(
                m4_setup.contains(required),
                "M4 setup script must contain {required}"
            );
        }

        let m4_paths = std::fs::read_to_string(root.join("macos-m4/archive-paths.sh"))
            .expect("m4 path contract");
        for required in [
            "ARCHIVE_STORAGE_VOLUME=\"${SYNERGY_ARCHIVE_STORAGE_VOLUME:-/Volumes/Synergy_Archive}\"",
            "ARCHIVE_APP_ROOT=\"${SYNERGY_ARCHIVE_APP_ROOT:-${SYNERGY_ARCHIVE_ROOT:-/Users/Shared/Synergy/archive-validator}}\"",
            "ARCHIVE_PUBLISH_ROOT=\"${SYNERGY_SNAPSHOT_PUBLISH_ROOT:-${ARCHIVE_STORAGE_VOLUME}/archive-validator/snapshots}\"",
            "archive_paths_validate()",
            "archive app root and publish root must be separate trees",
            "archive publish root must be below storage volume",
        ] {
            assert!(
                m4_paths.contains(required),
                "M4 path contract must contain {required}"
            );
        }

        let m4_verify =
            std::fs::read_to_string(root.join("macos-m4/verify-archive-validator-m4.sh"))
                .expect("m4 verify script");
        for required in [
            "source \"${PACKAGE_ROOT}/archive-paths.sh\"",
            "archive_paths_load_defaults",
            "archive_paths_validate",
            "SMB_ROOT=\"$(archive_paths_prefix \"${TEST_ROOT}\" \"${ARCHIVE_STORAGE_VOLUME}/archive-validator\")\"",
            "PUBLISH_ROOT=\"$(archive_paths_prefix \"${TEST_ROOT}\" \"${ARCHIVE_PUBLISH_ROOT}\")\"",
            "INCOMING_BOOTSTRAP=\"${SMB_ROOT}/incoming/bootstrap\"",
            "assert_no_quarantine",
            "assert_codesign_valid",
            "assert_launchd_running",
            "wait_for_tcp 127.0.0.1",
            "wait_for_qrpc_latest_block",
            "archive fork metadata missing",
            "archive_validator_verify_ok=true",
        ] {
            assert!(
                m4_verify.contains(required),
                "M4 verifier must contain {required}"
            );
        }

        let m4_restore =
            std::fs::read_to_string(root.join("macos-m4/restore-archive-bootstrap-m4.sh"))
                .expect("m4 restore script");
        for required in [
            "source \"${PACKAGE_ROOT}/archive-paths.sh\"",
            "archive_paths_load_defaults",
            "archive_paths_validate",
            "APP_ROOT=\"$(archive_paths_prefix \"${TEST_ROOT}\" \"${ARCHIVE_APP_ROOT}\")\"",
            "SMB_ROOT=\"$(archive_paths_prefix \"${TEST_ROOT}\" \"${ARCHIVE_STORAGE_VOLUME}/archive-validator\")\"",
            "INCOMING_BOOTSTRAP=\"${SMB_ROOT}/incoming/bootstrap\"",
            "archive storage volume missing in test root",
            "archive-bootstrap",
            "archive-validator-bootstrap",
            "validator-pruned bootstrap is rejected for Archive Validator restore",
            "historical_archive_complete_from_genesis",
            "archive-bootstrap-limitation.json",
            "launchctl kickstart -k",
            "wait_for_qrpc_latest_block",
            "io.synergynetwork.archive-snapshot-api",
            "archive_bootstrap_restore_ok=true",
        ] {
            assert!(
                m4_restore.contains(required),
                "M4 restore script must contain {required}"
            );
        }

        let m4_acceptance =
            std::fs::read_to_string(root.join("macos-m4/run-isolated-mac-acceptance.sh"))
                .expect("m4 acceptance script");
        for required in [
            "source \"${PACKAGE_ROOT}/archive-paths.sh\"",
            "archive_paths_load_defaults",
            "archive_paths_validate",
            "STORAGE_VOLUME=\"${TEST_ROOT}${ARCHIVE_STORAGE_VOLUME}\"",
            "APP_ROOT=\"${TEST_ROOT}${ARCHIVE_APP_ROOT}\"",
            "PUBLISH_ROOT=\"${TEST_ROOT}${ARCHIVE_PUBLISH_ROOT}\"",
            "INCOMING_BOOTSTRAP=\"${SMB_ROOT}/incoming/bootstrap\"",
            "mkdir -p \"${STORAGE_VOLUME}\"",
            "start_plist_service",
            "ProgramArguments",
            "wait_for_tcp 127.0.0.1 45622 archive_p2p",
            "wait_for_tcp 127.0.0.1 48641 snapshot_api",
            "wait_for_tcp 127.0.0.1 46030 archive_metrics",
            "snapshot_consensus_fork_metadata_published_ok=true",
            "post-fork distribution missing consensus_fork was not rejected",
            "snapshot_worker_pending_majority_proof_ok=true",
        ] {
            assert!(
                m4_acceptance.contains(required),
                "M4 acceptance must contain {required}"
            );
        }

        let windows_restore =
            std::fs::read_to_string(root.join("windows/Restore-ValidatorSnapshot.ps1"))
                .expect("windows restore script");
        for required in [
            "supported_receiver_operating_systems",
            "validator-pruned",
            "zstd",
            "tar",
            "verify-snapshot",
            "windows_snapshot_restore_ok=true",
            "snapshot-restore-evidence",
            "chain_id",
            "genesis_hash",
        ] {
            assert!(
                windows_restore.contains(required),
                "Windows restore script must contain {required}"
            );
        }

        let windows_setup = std::fs::read_to_string(
            root.join("windows/Setup-WindowsValidatorFromArchiveSnapshot.ps1"),
        )
        .expect("windows setup script");
        for required in [
            "nodectl.ps1",
            "install_and_start.ps1",
            "Restore-ValidatorSnapshot.ps1",
            "validator-pruned",
            "StartAfterRestore",
        ] {
            assert!(
                windows_setup.contains(required),
                "Windows setup script must contain {required}"
            );
        }
    }
}
