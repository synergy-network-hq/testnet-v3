use crate::consensus::consensus_fork::{
    active_consensus_fork_migration, validate_snapshot_fork_metadata, ConsensusForkMigration,
};
use crate::consensus::dual_quorum::required_validator_quorum;
use crate::crypto::aegis_pqvm::{
    AegisPqKeyLifecycleRecord, AegisPqvmSigner, AegisPqvmVerifier,
    SYNERGY_ARCHIVE_SNAPSHOT_MANIFEST_V1,
};
use crate::synergy_types::{
    AegisPqKeyId, AegisPqKeyRole, AegisPqPublicKey, AegisPqSignature, CanonicalSerialize, Epoch,
    SYNERGY_TESTNET_V3_CHAIN_ID, SYNERGY_TESTNET_V3_NETWORK_ID,
};
use serde::de::{IgnoredAny, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufReader, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Canonical Testnet-v3 genesis hash, read from the loaded genesis.
/// Previously a hardcoded Testnet-v2 literal, which let a v3 node assert a
/// retired chain identity during recovery/realignment/diagnostics.
pub fn expected_genesis_hash() -> String {
    crate::genesis::canonical_genesis()
        .map(|genesis| genesis.hash().to_string())
        .unwrap_or_default()
}
/// Self-realignment baseline validator count.
///
/// NOTE (2026-07-27, unresolved): this is `5` while
/// `crate::recovery::BASELINE_VALIDATOR_COUNT` is `6`, and the Testnet-v3
/// genesis defines six active validators. Setting this to 6 regressed the suite
/// from 24 to 69 failures, which indicates the two constants denote DIFFERENT
/// concepts rather than one being simply stale. Resolving this needs the
/// governing intent for the self-realignment baseline — see
/// launch/evidence/toolchain-and-build/BASELINE_VALIDATOR_COUNT_DISCREPANCY.md
pub const BASELINE_VALIDATOR_COUNT: usize = 5;
pub const DEFAULT_SNAPSHOT_INTERVAL_BLOCKS: u64 = 5_000;
pub const DEFAULT_SNAPSHOT_INTERVAL_SECS: u64 = 15 * 60;
pub const DEFAULT_SNAPSHOT_RETENTION_COUNT: usize = 2;
pub const DEFAULT_SHADOW_OBSERVATION_BLOCKS: u64 = 500;

pub const SNAPSHOT_CLASS_VALIDATOR_PRUNED: &str = "validator-pruned";
pub const SNAPSHOT_CLASS_SUPPORT_RELAYER: &str = "support-relayer";
pub const SNAPSHOT_CLASS_SUPPORT_RPC: &str = "support-rpc";
pub const SNAPSHOT_CLASS_SUPPORT_OBSERVER: &str = "support-observer";
pub const SNAPSHOT_CLASS_INDEXER_FULL: &str = "indexer-full";
pub const SNAPSHOT_CLASS_INDEXER_REPLAY: &str = "indexer-replay";
pub const SNAPSHOT_CLASS_ARCHIVE_FULL: &str = "archive-full";
pub const SNAPSHOT_CLASS_ARCHIVE_BOOTSTRAP: &str = "archive-bootstrap";

pub fn required_snapshot_quorum_for_validator_count(active_validator_count: usize) -> u64 {
    required_validator_quorum(active_validator_count) as u64
}

const SNAPSHOT_MANIFEST_VERSION: u32 = 1;
const SNAPSHOT_STATE_ROOT_DOMAIN: &[u8] = b"SYNERGY_SNAPSHOT_STATE_ROOT_V1";
const SNAPSHOT_ALLOWED_FILES: &[&str] = &[
    "chain.json",
    "committed_blocks.jsonl",
    "canonical_locks.json",
    "committed_qcs.json",
    "committed_qcs.jsonl",
    "dag_state.json",
    "validator_registry.json",
    "token_state.json",
    "account_state.json",
    "state_checkpoint.json",
];

pub const VALIDATOR_PRUNED_REQUIRED_STATE_FILES: &[&str] = &[
    "chain.json",
    "committed_blocks.jsonl",
    "canonical_locks.json",
    "committed_qcs.jsonl",
    "token_state.json",
    "validator_registry.json",
];

pub fn launch_snapshot_allowed_files() -> &'static [&'static str] {
    SNAPSHOT_ALLOWED_FILES
}

pub fn required_snapshot_files_for_class(snapshot_class: &str) -> &'static [&'static str] {
    if normalize_snapshot_class(snapshot_class) == Some(SNAPSHOT_CLASS_VALIDATOR_PRUNED) {
        VALIDATOR_PRUNED_REQUIRED_STATE_FILES
    } else {
        &[]
    }
}

pub fn validate_snapshot_file_contract(
    snapshot_class: &str,
    present_files: &[&str],
) -> Result<(), String> {
    for required_file in required_snapshot_files_for_class(snapshot_class) {
        if !present_files.iter().any(|present| present == required_file) {
            return Err(format!(
                "snapshot class {} requires state file {}",
                normalize_snapshot_class(snapshot_class).unwrap_or(snapshot_class),
                required_file
            ));
        }
    }
    Ok(())
}

pub fn normalize_snapshot_class(value: &str) -> Option<&'static str> {
    let normalized = value.trim().to_ascii_lowercase().replace('_', "-");
    match normalized.as_str() {
        SNAPSHOT_CLASS_VALIDATOR_PRUNED => Some(SNAPSHOT_CLASS_VALIDATOR_PRUNED),
        SNAPSHOT_CLASS_SUPPORT_RELAYER => Some(SNAPSHOT_CLASS_SUPPORT_RELAYER),
        SNAPSHOT_CLASS_SUPPORT_RPC => Some(SNAPSHOT_CLASS_SUPPORT_RPC),
        SNAPSHOT_CLASS_SUPPORT_OBSERVER | "observer" => Some(SNAPSHOT_CLASS_SUPPORT_OBSERVER),
        SNAPSHOT_CLASS_INDEXER_FULL => Some(SNAPSHOT_CLASS_INDEXER_FULL),
        SNAPSHOT_CLASS_INDEXER_REPLAY => Some(SNAPSHOT_CLASS_INDEXER_REPLAY),
        SNAPSHOT_CLASS_ARCHIVE_FULL => Some(SNAPSHOT_CLASS_ARCHIVE_FULL),
        SNAPSHOT_CLASS_ARCHIVE_BOOTSTRAP | "archive-validator-bootstrap" => {
            Some(SNAPSHOT_CLASS_ARCHIVE_BOOTSTRAP)
        }
        _ => None,
    }
}

pub fn default_snapshot_class() -> String {
    SNAPSHOT_CLASS_VALIDATOR_PRUNED.to_string()
}

pub fn default_allowed_restore_roles() -> Vec<String> {
    vec!["validator".to_string()]
}

pub fn default_allowed_restore_roles_for_class(snapshot_class: &str) -> Option<Vec<String>> {
    let snapshot_class = normalize_snapshot_class(snapshot_class)?;
    let roles = match snapshot_class {
        SNAPSHOT_CLASS_VALIDATOR_PRUNED => {
            vec!["validator", "onboarding_validator", "quarantined_validator"]
        }
        SNAPSHOT_CLASS_SUPPORT_RELAYER => vec!["relayer"],
        SNAPSHOT_CLASS_SUPPORT_RPC => vec!["rpc", "rpc_gateway"],
        SNAPSHOT_CLASS_SUPPORT_OBSERVER => vec!["observer"],
        SNAPSHOT_CLASS_INDEXER_FULL | SNAPSHOT_CLASS_INDEXER_REPLAY => {
            vec!["indexer", "explorer", "atlas_indexer", "explorer_indexer"]
        }
        SNAPSHOT_CLASS_ARCHIVE_FULL => vec!["archive", "archive_validator", "snapshot_authority"],
        SNAPSHOT_CLASS_ARCHIVE_BOOTSTRAP => {
            vec!["archive", "archive_validator", "snapshot_authority"]
        }
        _ => return None,
    };
    Some(roles.into_iter().map(str::to_string).collect())
}

pub fn supported_restore_roles_for_class(snapshot_class: &str) -> Option<Vec<String>> {
    let snapshot_class = normalize_snapshot_class(snapshot_class)?;
    let mut roles = default_allowed_restore_roles_for_class(snapshot_class)?;
    if snapshot_class == SNAPSHOT_CLASS_ARCHIVE_FULL {
        roles.extend(
            ["validator", "onboarding_validator", "quarantined_validator"]
                .into_iter()
                .map(str::to_string),
        );
    }
    Some(roles)
}

pub fn snapshot_class_uses_compact_history(snapshot_class: &str) -> bool {
    match normalize_snapshot_class(snapshot_class) {
        Some(SNAPSHOT_CLASS_ARCHIVE_FULL)
        | Some(SNAPSHOT_CLASS_ARCHIVE_BOOTSTRAP)
        | Some(SNAPSHOT_CLASS_INDEXER_FULL)
        | Some(SNAPSHOT_CLASS_INDEXER_REPLAY) => false,
        Some(_) => true,
        None => false,
    }
}

pub fn normalize_snapshot_role(role: &str) -> String {
    role.trim()
        .to_ascii_lowercase()
        .replace('-', "_")
        .replace(' ', "_")
}

pub fn snapshot_class_allows_role(snapshot_class: &str, role: &str) -> bool {
    let Some(supported) = supported_restore_roles_for_class(snapshot_class) else {
        return false;
    };
    let role = normalize_snapshot_role(role);
    supported.iter().any(|allowed| allowed == &role)
}

pub fn snapshot_producer_role_is_authorized(role: &str) -> bool {
    matches!(
        normalize_snapshot_role(role).as_str(),
        "validator"
            | "archive"
            | "archive_node"
            | "archive_validator"
            | "archive_validator_non_consensus"
            | "archive_observer"
            | "snapshot_authority"
            | "explorer_indexer"
            | "atlas_indexer"
    )
}

pub fn snapshot_producer_role_validation_error(snapshot_class: &str, role: &str) -> Option<String> {
    let normalized_role = normalize_snapshot_role(role);
    if normalized_role == "genesis_validator" {
        return Some(
            "snapshot producer role GENESIS_VALIDATOR is legacy/stale; expected current role VALIDATOR"
                .to_string(),
        );
    }
    if normalize_snapshot_class(snapshot_class) == Some(SNAPSHOT_CLASS_VALIDATOR_PRUNED)
        && normalized_role != "validator"
    {
        return Some(format!(
            "validator-pruned snapshot producer role must be VALIDATOR; got {}",
            role.trim()
        ));
    }
    if !snapshot_producer_role_is_authorized(role) {
        return Some("snapshot producer role is not authorized".to_string());
    }
    None
}

pub fn canonical_snapshot_producer_role_for_class(
    snapshot_class: &str,
    role: &str,
) -> Result<String, String> {
    if let Some(error) = snapshot_producer_role_validation_error(snapshot_class, role) {
        return Err(error);
    }
    if normalize_snapshot_class(snapshot_class) == Some(SNAPSHOT_CLASS_VALIDATOR_PRUNED) {
        Ok("VALIDATOR".to_string())
    } else {
        Ok(role.trim().to_string())
    }
}
const SNAPSHOT_FORBIDDEN_PATH_FRAGMENTS: &[&str] = &[
    "config",
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
    "secret",
    "password",
    "genesis",
    "quorum",
    "runtime",
    "log",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RealignmentState {
    Active,
    Suspect,
    Quarantined,
    EvidencePreserved,
    ChainDataWipeReady,
    ChainDataWiped,
    SnapshotDiscovery,
    SnapshotDownloading,
    SnapshotVerified,
    SnapshotRestored,
    SpeedSyncing,
    CaughtUp,
    ShadowObserving,
    ShadowPassed,
    ReadyToRejoin,
    VoteOnly,
    PendingReactivation,
    FailedClosed,
}

impl RealignmentState {
    pub fn consensus_duties_enabled(self) -> bool {
        matches!(self, Self::Active | Self::VoteOnly)
    }

    pub fn voting_duties_enabled(self) -> bool {
        matches!(self, Self::Active | Self::VoteOnly)
    }

    pub fn proposer_duties_enabled(self) -> bool {
        self == Self::Active
    }

    pub fn can_shadow_observe(self) -> bool {
        matches!(self, Self::CaughtUp | Self::ShadowObserving)
    }
}

fn recovery_state_from_status_value(value: &serde_json::Value) -> Option<RealignmentState> {
    let state = ["new_state", "typed_status", "recovery_state", "status"]
        .iter()
        .filter_map(|key| value.get(*key).and_then(serde_json::Value::as_str))
        .map(|state| state.trim().to_ascii_uppercase())
        .find(|state| !state.is_empty());
    let vote_only = value
        .get("vote_only_rejoin")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
        || value
            .get("proposer_duties_disabled")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
    if vote_only {
        return Some(RealignmentState::VoteOnly);
    }
    match state?.as_str() {
        "ACTIVE" => Some(RealignmentState::Active),
        "SUSPECT" => Some(RealignmentState::Suspect),
        "QUARANTINED" | "SELF_QUARANTINED_DIVERGENCE" => Some(RealignmentState::Quarantined),
        "EVIDENCE_PRESERVED" => Some(RealignmentState::EvidencePreserved),
        "CHAIN_DATA_WIPE_READY" => Some(RealignmentState::ChainDataWipeReady),
        "CHAIN_DATA_WIPED" => Some(RealignmentState::ChainDataWiped),
        "SNAPSHOT_DISCOVERY" => Some(RealignmentState::SnapshotDiscovery),
        "SNAPSHOT_DOWNLOADING" => Some(RealignmentState::SnapshotDownloading),
        "SNAPSHOT_VERIFIED" => Some(RealignmentState::SnapshotVerified),
        "SNAPSHOT_RESTORED" => Some(RealignmentState::SnapshotRestored),
        "SPEED_SYNCING" => Some(RealignmentState::SpeedSyncing),
        "CAUGHT_UP" => Some(RealignmentState::CaughtUp),
        "SHADOW_OBSERVING" | "SHADOW" => Some(RealignmentState::ShadowObserving),
        "SHADOW_PASSED" => Some(RealignmentState::ShadowPassed),
        "READY_TO_REJOIN" => Some(RealignmentState::ReadyToRejoin),
        "VOTE_ONLY" | "VOTEONLY" => Some(RealignmentState::VoteOnly),
        "PENDING_REACTIVATION" => Some(RealignmentState::PendingReactivation),
        "FAILED_CLOSED" => Some(RealignmentState::FailedClosed),
        _ => None,
    }
}

/// Read the durable recovery state written by rejoin and promotion operations.
///
/// Quarantine marker files are deliberately removed after their evidence is
/// preserved, so restart-time duty gates must also consult this status file.
pub fn persisted_recovery_state() -> Option<RealignmentState> {
    let path = crate::utils::resolve_data_path("data/self_heal_status.json");
    let bytes = fs::read(path).ok()?;
    let value = serde_json::from_slice::<serde_json::Value>(&bytes).ok()?;
    recovery_state_from_status_value(&value)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotSchedule {
    pub interval_finalized_blocks: u64,
    pub interval_seconds: u64,
    pub retain_last: usize,
}

impl SnapshotSchedule {
    pub fn launch_default() -> Self {
        Self {
            interval_finalized_blocks: DEFAULT_SNAPSHOT_INTERVAL_BLOCKS,
            interval_seconds: DEFAULT_SNAPSHOT_INTERVAL_SECS,
            retain_last: DEFAULT_SNAPSHOT_RETENTION_COUNT,
        }
    }

    pub fn should_create_snapshot(
        &self,
        last_snapshot_height: Option<u64>,
        last_snapshot_created_at: Option<u64>,
        current_finalized_height: u64,
        now_unix_secs: u64,
    ) -> bool {
        let block_due = last_snapshot_height
            .map(|height| {
                current_finalized_height.saturating_sub(height) >= self.interval_finalized_blocks
            })
            .unwrap_or(true);
        let time_due = last_snapshot_created_at
            .map(|created_at| now_unix_secs.saturating_sub(created_at) >= self.interval_seconds)
            .unwrap_or(true);
        block_due || time_due
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotFileEntry {
    pub relative_path: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotQcEvidence {
    pub committed_qc_height: u64,
    pub committed_qc_hash: String,
    pub vote_count: u64,
    pub signer_set: Vec<String>,
    pub aegis_pqc_verified: bool,
    pub duplicate_signer_check_passed: bool,
    #[serde(default)]
    pub active_validator_count: usize,
    #[serde(default, alias = "active_validator_set_is_genesis_5")]
    pub active_validator_set_meets_baseline: bool,
    pub relayers_rpc_support_counted_toward_quorum: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotManifest {
    pub manifest_version: u32,
    pub chain_id: u64,
    pub chain_id_hex: String,
    pub network_id: String,
    pub genesis_hash: String,
    #[serde(default = "default_snapshot_class")]
    pub snapshot_class: String,
    #[serde(default = "default_allowed_restore_roles")]
    pub allowed_restore_roles: Vec<String>,
    pub snapshot_height: u64,
    pub snapshot_block_hash: String,
    pub parent_hash: String,
    pub state_root: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consensus_fork: Option<ConsensusForkMigration>,
    pub canonical_lock_height: u64,
    pub canonical_lock_hash: String,
    pub qc_evidence: SnapshotQcEvidence,
    pub active_validator_set: Vec<String>,
    pub quorum_threshold: u64,
    pub files: Vec<SnapshotFileEntry>,
    pub full_archive_sha256: String,
    pub created_at: u64,
    pub source_node_id: String,
    pub source_role: String,
    pub runtime_checksum: String,
    pub source_node_quarantined: bool,
    pub source_node_majority_branch: bool,
    pub conflict_height_hash: Option<String>,
    pub manifest_signer_uma_id: String,
    pub manifest_signing_key_id: AegisPqKeyId,
    pub manifest_signer_public_key: AegisPqPublicKey,
    pub manifest_signature_epoch: u64,
}

impl SnapshotManifest {
    pub fn manifest_hash(&self) -> Result<String, String> {
        let bytes = self.canonical_bytes()?;
        Ok(sha256_hex(&bytes))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedSnapshotManifest {
    pub manifest: SnapshotManifest,
    pub signature_domain: String,
    pub aegis_pq_signature: AegisPqSignature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotBuildInput {
    pub state_dir: PathBuf,
    pub snapshot_class: String,
    pub allowed_restore_roles: Vec<String>,
    pub snapshot_height: u64,
    pub snapshot_block_hash: String,
    pub parent_hash: String,
    pub state_root: Option<String>,
    pub canonical_lock_height: u64,
    pub canonical_lock_hash: String,
    pub qc_evidence: SnapshotQcEvidence,
    pub active_validator_set: Vec<String>,
    pub source_node_id: String,
    pub source_role: String,
    pub runtime_checksum: String,
    pub source_node_quarantined: bool,
    pub source_node_majority_branch: bool,
    pub conflict_height_hash: Option<String>,
    pub manifest_signer_uma_id: String,
    pub manifest_signing_key_id: AegisPqKeyId,
    pub manifest_signer_public_key: AegisPqPublicKey,
    pub manifest_signature_epoch: u64,
    pub created_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotVerificationPolicy {
    pub expected_chain_id: u64,
    pub expected_network_id: String,
    pub expected_genesis_hash: String,
    pub expected_snapshot_class: Option<String>,
    pub target_role: Option<String>,
    pub required_quorum: u64,
    pub expected_validator_count: usize,
    pub current_finalized_height: Option<u64>,
    pub max_snapshot_lag_blocks: Option<u64>,
    pub require_manifest_signature: bool,
    pub require_file_checksums: bool,
}

impl Default for SnapshotVerificationPolicy {
    fn default() -> Self {
        Self {
            expected_chain_id: SYNERGY_TESTNET_V3_CHAIN_ID,
            expected_network_id: SYNERGY_TESTNET_V3_NETWORK_ID.to_string(),
            expected_genesis_hash: expected_genesis_hash(),
            expected_snapshot_class: None,
            target_role: None,
            required_quorum: 0,
            expected_validator_count: 0,
            current_finalized_height: None,
            max_snapshot_lag_blocks: Some(DEFAULT_SNAPSHOT_INTERVAL_BLOCKS * 2),
            require_manifest_signature: true,
            require_file_checksums: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotVerificationReport {
    pub success: bool,
    pub fail_closed: bool,
    pub errors: Vec<String>,
    pub manifest_hash: Option<String>,
    pub snapshot_class: String,
    pub source_role: String,
    pub allowed_restore_roles: Vec<String>,
    pub snapshot_height: u64,
    pub committed_qc_height: u64,
    pub committed_qc_hash: String,
    pub committed_qc_vote_count: u64,
    pub committed_qc_signers: Vec<String>,
    pub source_qc_aegis_pqc_verified: bool,
    pub duplicate_signer_check_passed: bool,
    pub active_validator_count: usize,
    #[serde(default)]
    pub active_validator_set_meets_baseline: bool,
    pub relayers_rpc_support_counted_toward_quorum: bool,
    pub manifest_signature_verified: bool,
    pub file_checksums_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineMarker {
    pub validator_id: String,
    pub reason: String,
    pub detected_height: u64,
    pub detected_hash: String,
    pub quorum_majority_height: u64,
    pub quorum_majority_hash: String,
    pub local_conflicting_height: Option<u64>,
    pub local_conflicting_hash: Option<String>,
    pub evidence_path: String,
    pub detected_at: u64,
    pub recovery_state: RealignmentState,
    pub voting_disabled: bool,
    pub proposing_disabled: bool,
    pub qc_aggregation_disabled: bool,
    pub canonical_source_disabled: bool,
    pub rejoin_eligibility: bool,
}

impl QuarantineMarker {
    pub fn divergence(
        validator_id: impl Into<String>,
        reason: impl Into<String>,
        detected_height: u64,
        detected_hash: impl Into<String>,
        quorum_majority_height: u64,
        quorum_majority_hash: impl Into<String>,
        local_conflicting_hash: Option<String>,
        evidence_path: impl Into<String>,
    ) -> Self {
        Self {
            validator_id: validator_id.into(),
            reason: reason.into(),
            detected_height,
            detected_hash: detected_hash.into(),
            quorum_majority_height,
            quorum_majority_hash: quorum_majority_hash.into(),
            local_conflicting_height: local_conflicting_hash.as_ref().map(|_| detected_height),
            local_conflicting_hash,
            evidence_path: evidence_path.into(),
            detected_at: now_secs(),
            recovery_state: RealignmentState::Quarantined,
            voting_disabled: true,
            proposing_disabled: true,
            qc_aggregation_disabled: true,
            canonical_source_disabled: true,
            rejoin_eligibility: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorDutyGate {
    pub state: RealignmentState,
    pub can_vote: bool,
    pub can_propose: bool,
    pub can_aggregate_qc: bool,
    pub can_count_toward_quorum: bool,
    pub can_enter_proposer_schedule: bool,
    pub can_serve_as_canonical_source: bool,
    pub shadow_signs_real_votes: bool,
}

impl ValidatorDutyGate {
    pub fn for_state(state: RealignmentState) -> Self {
        let active = state == RealignmentState::Active;
        let vote_only = state == RealignmentState::VoteOnly;
        Self {
            state,
            can_vote: active || vote_only,
            can_propose: active,
            can_aggregate_qc: active,
            can_count_toward_quorum: active || vote_only,
            can_enter_proposer_schedule: active,
            can_serve_as_canonical_source: active,
            shadow_signs_real_votes: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerBranchEvidence {
    pub node_id: String,
    pub role: PeerEvidenceRole,
    pub active_validator: bool,
    pub height: u64,
    pub block_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PeerEvidenceRole {
    Validator,
    Relayer,
    RpcGateway,
    Archive,
    Observer,
    ShadowValidator,
    OnboardingValidator,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MajorityBranchProof {
    pub proven: bool,
    pub height: u64,
    pub majority_hash: Option<String>,
    pub signer_set: Vec<String>,
    pub counted_validator_count: usize,
    pub ignored_support_count: usize,
    pub errors: Vec<String>,
}

pub fn prove_majority_branch(
    reports: &[PeerBranchEvidence],
    quorum_threshold: usize,
) -> MajorityBranchProof {
    let mut counts: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut ignored_support_count = 0;
    let mut height = 0;
    for report in reports {
        height = height.max(report.height);
        if report.role == PeerEvidenceRole::Validator && report.active_validator {
            counts
                .entry(report.block_hash.clone())
                .or_default()
                .insert(report.node_id.clone());
        } else {
            ignored_support_count += 1;
        }
    }

    let mut errors = Vec::new();
    let mut majority_hash = None;
    let mut signer_set = Vec::new();
    for (hash, signers) in &counts {
        if signers.len() >= quorum_threshold {
            majority_hash = Some(hash.clone());
            signer_set = signers.iter().cloned().collect();
            break;
        }
    }
    if majority_hash.is_none() {
        errors.push(format!(
            "no {quorum_threshold}-of-{} active validator majority",
            reports
                .iter()
                .filter(|report| {
                    report.role == PeerEvidenceRole::Validator && report.active_validator
                })
                .map(|report| report.node_id.as_str())
                .collect::<BTreeSet<_>>()
                .len()
        ));
    }
    let counted_validator_count = counts.values().map(BTreeSet::len).sum::<usize>();

    MajorityBranchProof {
        proven: errors.is_empty(),
        height,
        majority_hash,
        signer_set,
        counted_validator_count,
        ignored_support_count,
        errors,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainStateWipePlan {
    pub validator_id: String,
    pub data_dir: String,
    pub evidence_path: String,
    pub files_to_preserve: Vec<String>,
    pub files_to_wipe: Vec<String>,
    pub files_never_to_touch: Vec<String>,
    pub canonical_locks_mutated: bool,
    pub committed_qcs_mutated: bool,
    pub chain_state_mutated: bool,
    pub dag_state_mutated: bool,
    pub registry_state_mutated: bool,
    pub token_state_mutated: bool,
    pub keys_or_configs_copied: bool,
    pub genesis_mutated: bool,
    pub quorum_mutated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainStateWipeResult {
    pub success: bool,
    pub evidence_path: String,
    pub files_preserved: Vec<String>,
    pub files_wiped: Vec<String>,
    pub canonical_locks_mutated: bool,
    pub committed_qcs_mutated: bool,
    pub chain_state_mutated: bool,
    pub dag_state_mutated: bool,
    pub registry_state_mutated: bool,
    pub token_state_mutated: bool,
    pub keys_or_configs_copied: bool,
    pub genesis_mutated: bool,
    pub quorum_mutated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WipeApplyPreconditions {
    pub validator_quarantined: bool,
    pub evidence_preserved: bool,
    pub snapshot_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotRestorePlan {
    pub validator_id: String,
    pub snapshot_manifest_hash: String,
    pub snapshot_height: u64,
    pub source_snapshot: String,
    pub target_data_dir: String,
    pub files_to_restore: Vec<String>,
    pub keys_or_configs_copied: bool,
    pub genesis_mutated: bool,
    pub quorum_mutated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpeedSyncPolicy {
    pub chain_id: u64,
    pub network_id: String,
    pub genesis_hash: String,
    pub reject_stale_peers: bool,
    pub reject_quarantined_peers: bool,
    pub verify_qc_aegis_pqc: bool,
    pub verify_parent_continuity: bool,
    pub verify_state_root: bool,
}

impl Default for SpeedSyncPolicy {
    fn default() -> Self {
        Self {
            chain_id: SYNERGY_TESTNET_V3_CHAIN_ID,
            network_id: SYNERGY_TESTNET_V3_NETWORK_ID.to_string(),
            genesis_hash: expected_genesis_hash(),
            reject_stale_peers: true,
            reject_quarantined_peers: true,
            verify_qc_aegis_pqc: true,
            verify_parent_continuity: true,
            verify_state_root: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalPeerStatus {
    pub peer_id: String,
    pub chain_id: u64,
    pub network_id: String,
    pub genesis_hash: String,
    pub height: u64,
    pub block_hash: String,
    pub quarantined: bool,
    pub qc_aegis_pqc_verified: bool,
    pub parent_continuity_verified: bool,
    pub state_root_matches: bool,
}

pub fn validate_speed_sync_peer(
    peer: &CanonicalPeerStatus,
    local_height: u64,
    policy: &SpeedSyncPolicy,
) -> Result<(), String> {
    if peer.chain_id != policy.chain_id {
        return Err("speed-sync peer rejected: wrong chain_id".to_string());
    }
    if peer.network_id != policy.network_id {
        return Err("speed-sync peer rejected: wrong network_id".to_string());
    }
    if !peer.genesis_hash.eq_ignore_ascii_case(&policy.genesis_hash) {
        return Err("speed-sync peer rejected: wrong genesis_hash".to_string());
    }
    if policy.reject_stale_peers && peer.height <= local_height {
        return Err("speed-sync peer rejected: stale peer height".to_string());
    }
    if policy.reject_quarantined_peers && peer.quarantined {
        return Err("speed-sync peer rejected: source peer is quarantined".to_string());
    }
    if policy.verify_qc_aegis_pqc && !peer.qc_aegis_pqc_verified {
        return Err("speed-sync peer rejected: QC was not verified through Aegis/PQC".to_string());
    }
    if policy.verify_parent_continuity && !peer.parent_continuity_verified {
        return Err("speed-sync peer rejected: parent continuity is unverified".to_string());
    }
    if policy.verify_state_root && !peer.state_root_matches {
        return Err("speed-sync peer rejected: state root/checkpoint mismatch".to_string());
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowDecisionRecord {
    pub height: u64,
    pub canonical_hash: String,
    pub would_have_voted_hash: Option<String>,
    pub would_have_proposed_hash: Option<String>,
    pub state_root_matches: bool,
    pub rejected_valid_majority_block: bool,
    pub accepted_conflicting_block: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowObservation {
    pub validator_id: String,
    pub state: RealignmentState,
    pub required_blocks: u64,
    pub records: Vec<ShadowDecisionRecord>,
    pub failures: Vec<String>,
}

impl ShadowObservation {
    pub fn new(validator_id: impl Into<String>, required_blocks: u64) -> Self {
        Self {
            validator_id: validator_id.into(),
            state: RealignmentState::ShadowObserving,
            required_blocks,
            records: Vec::new(),
            failures: Vec::new(),
        }
    }

    pub fn record(&mut self, record: ShadowDecisionRecord) {
        if let Some(hash) = record.would_have_voted_hash.as_ref() {
            if hash != &record.canonical_hash {
                self.failures.push(format!(
                    "would-have-voted conflict at height {}",
                    record.height
                ));
            }
        }
        if let Some(hash) = record.would_have_proposed_hash.as_ref() {
            if hash != &record.canonical_hash {
                self.failures.push(format!(
                    "would-have-proposed conflict at height {}",
                    record.height
                ));
            }
        }
        if record.rejected_valid_majority_block {
            self.failures.push(format!(
                "would have rejected valid majority block at height {}",
                record.height
            ));
        }
        if record.accepted_conflicting_block {
            self.failures.push(format!(
                "would have accepted conflicting block at height {}",
                record.height
            ));
        }
        if !record.state_root_matches {
            self.failures
                .push(format!("state root mismatch at height {}", record.height));
        }
        self.records.push(record);
    }

    pub fn evaluate(mut self) -> Self {
        if self.records.len() < self.required_blocks as usize {
            self.failures.push(format!(
                "shadow observation has {} block(s), {} required",
                self.records.len(),
                self.required_blocks
            ));
        }
        self.state = if self.failures.is_empty() {
            RealignmentState::ShadowPassed
        } else {
            RealignmentState::Quarantined
        };
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejoinEligibilityInput {
    pub validator_id: String,
    pub state: RealignmentState,
    pub shadow_passed: bool,
    pub exact_common_height_match: bool,
    pub latest_finalized_qc_aegis_pqc_verified: bool,
    pub no_stale_vote_locks_above_finalized: bool,
    pub no_proposal_cache_conflicts_above_finalized: bool,
    pub quarantine_reason_cleared: bool,
    pub chain_id: u64,
    pub network_id: String,
    pub genesis_hash: String,
    pub state_root_matches: bool,
    pub own_validator_key_intact: bool,
    pub keys_or_configs_copied: bool,
    pub rejoin_at_finalized_safe_boundary: bool,
    pub cluster_marks_pending_reactivation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejoinEligibilityReport {
    pub eligible: bool,
    pub fail_closed: bool,
    pub validator_id: String,
    pub previous_state: RealignmentState,
    pub new_state: RealignmentState,
    pub blocked_reasons: Vec<String>,
}

pub fn evaluate_rejoin_eligibility(input: RejoinEligibilityInput) -> RejoinEligibilityReport {
    let mut blocked = Vec::new();
    if input.state != RealignmentState::ReadyToRejoin
        && input.state != RealignmentState::ShadowPassed
        && input.state != RealignmentState::CaughtUp
    {
        blocked.push("validator is not CAUGHT_UP, READY_TO_REJOIN, or SHADOW_PASSED".to_string());
    }
    let vote_only_proof_ready = input.exact_common_height_match
        && input.latest_finalized_qc_aegis_pqc_verified
        && input.no_stale_vote_locks_above_finalized
        && input.no_proposal_cache_conflicts_above_finalized
        && input.quarantine_reason_cleared
        && input.state_root_matches
        && input.own_validator_key_intact
        && !input.keys_or_configs_copied
        && input.cluster_marks_pending_reactivation;
    if !input.shadow_passed && !vote_only_proof_ready {
        blocked.push(
            "shadow observation has not passed and vote-only proof is incomplete".to_string(),
        );
    }
    if !input.exact_common_height_match {
        blocked.push("exact common-height hash does not match quorum".to_string());
    }
    if !input.latest_finalized_qc_aegis_pqc_verified {
        blocked.push("latest finalized QC was not verified through Aegis/PQC".to_string());
    }
    if !input.no_stale_vote_locks_above_finalized {
        blocked.push("stale vote locks remain above finalized height".to_string());
    }
    if !input.no_proposal_cache_conflicts_above_finalized {
        blocked.push("proposal cache conflict remains above finalized height".to_string());
    }
    if !input.quarantine_reason_cleared {
        blocked.push("quarantine reason has not cleared".to_string());
    }
    if input.chain_id != SYNERGY_TESTNET_V3_CHAIN_ID {
        blocked.push("wrong chain_id".to_string());
    }
    if input.network_id != SYNERGY_TESTNET_V3_NETWORK_ID {
        blocked.push("wrong network_id".to_string());
    }
    if !input
        .genesis_hash
        .eq_ignore_ascii_case(&expected_genesis_hash())
    {
        blocked.push("wrong genesis_hash".to_string());
    }
    if !input.state_root_matches {
        blocked.push("state root/checkpoint does not match quorum".to_string());
    }
    if !input.own_validator_key_intact {
        blocked.push("own validator key is not intact".to_string());
    }
    if input.keys_or_configs_copied {
        blocked.push("keys or configs were copied".to_string());
    }
    if input.shadow_passed && !input.rejoin_at_finalized_safe_boundary {
        blocked.push("rejoin is not at a finalized safe boundary".to_string());
    }
    if !input.cluster_marks_pending_reactivation {
        blocked.push("cluster has not marked validator PENDING_REACTIVATION".to_string());
    }
    let eligible = blocked.is_empty();
    RejoinEligibilityReport {
        eligible,
        fail_closed: !eligible,
        validator_id: input.validator_id,
        previous_state: input.state,
        new_state: if eligible {
            RealignmentState::VoteOnly
        } else {
            RealignmentState::Quarantined
        },
        blocked_reasons: blocked,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationResponse {
    pub success: bool,
    pub typed_status: String,
    pub reason: String,
    pub evidence_path: String,
    pub chain_id: u64,
    pub network_id: String,
    pub genesis_hash: String,
    pub validator_id: String,
    pub previous_state: RealignmentState,
    pub new_state: RealignmentState,
    pub canonical_locks_mutated: bool,
    pub committed_qcs_mutated: bool,
    pub chain_state_mutated: bool,
    pub keys_or_configs_copied: bool,
    pub genesis_mutated: bool,
    pub quorum_mutated: bool,
    pub snapshot_manifest_hash: Option<String>,
    pub snapshot_height: Option<u64>,
    pub source_peer: Option<String>,
    pub source_snapshot: Option<String>,
    pub aegis_pqc_verification_result: bool,
    pub next_required_action: String,
}

pub fn fail_closed_mutation_response(
    validator_id: impl Into<String>,
    previous_state: RealignmentState,
    reason: impl Into<String>,
    evidence_path: impl Into<String>,
) -> MutationResponse {
    MutationResponse {
        success: false,
        typed_status: "FAILED_CLOSED".to_string(),
        reason: reason.into(),
        evidence_path: evidence_path.into(),
        chain_id: SYNERGY_TESTNET_V3_CHAIN_ID,
        network_id: SYNERGY_TESTNET_V3_NETWORK_ID.to_string(),
        genesis_hash: expected_genesis_hash(),
        validator_id: validator_id.into(),
        previous_state,
        new_state: RealignmentState::Quarantined,
        canonical_locks_mutated: false,
        committed_qcs_mutated: false,
        chain_state_mutated: false,
        keys_or_configs_copied: false,
        genesis_mutated: false,
        quorum_mutated: false,
        snapshot_manifest_hash: None,
        snapshot_height: None,
        source_peer: None,
        source_snapshot: None,
        aegis_pqc_verification_result: false,
        next_required_action: "verify_snapshot_manifest_or_preserve_evidence".to_string(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealignmentLifecycle {
    pub validator_id: String,
    pub state: RealignmentState,
    pub history: Vec<RealignmentState>,
}

impl RealignmentLifecycle {
    pub fn new_active(validator_id: impl Into<String>) -> Self {
        Self {
            validator_id: validator_id.into(),
            state: RealignmentState::Active,
            history: vec![RealignmentState::Active],
        }
    }

    pub fn transition(&mut self, next: RealignmentState) -> Result<(), String> {
        if !allowed_transition(self.state, next) {
            return Err(format!(
                "invalid self-realignment transition {:?} -> {:?}",
                self.state, next
            ));
        }
        self.state = next;
        self.history.push(next);
        Ok(())
    }
}

pub fn create_snapshot_manifest(input: SnapshotBuildInput) -> Result<SnapshotManifest, String> {
    let snapshot_class = normalize_snapshot_class(&input.snapshot_class)
        .ok_or_else(|| format!("unsupported snapshot class {}", input.snapshot_class))?
        .to_string();
    let files = collect_snapshot_files(&input.state_dir, &snapshot_class)?;
    let full_archive_sha256 = manifest_files_digest(&files)?;
    let state_root = match input.state_root {
        Some(root) if !root.trim().is_empty() => Some(root),
        _ => Some(snapshot_state_root_digest(&files)?),
    };
    let allowed_restore_roles = if input.allowed_restore_roles.is_empty() {
        default_allowed_restore_roles_for_class(&snapshot_class)
            .ok_or_else(|| format!("unsupported snapshot class {snapshot_class}"))?
    } else {
        input
            .allowed_restore_roles
            .iter()
            .map(|role| normalize_snapshot_role(role))
            .collect::<Vec<_>>()
    };
    if allowed_restore_roles.is_empty() {
        return Err("snapshot manifest requires at least one allowed restore role".to_string());
    }
    for role in &allowed_restore_roles {
        if !snapshot_class_allows_role(&snapshot_class, role) {
            return Err(format!(
                "snapshot class {snapshot_class} is not compatible with restore role {role}"
            ));
        }
    }
    let source_role =
        canonical_snapshot_producer_role_for_class(&snapshot_class, &input.source_role)?;
    let quorum_threshold =
        required_snapshot_quorum_for_validator_count(input.active_validator_set.len());
    Ok(SnapshotManifest {
        manifest_version: SNAPSHOT_MANIFEST_VERSION,
        chain_id: SYNERGY_TESTNET_V3_CHAIN_ID,
        chain_id_hex: "0x4f0".to_string(),
        network_id: SYNERGY_TESTNET_V3_NETWORK_ID.to_string(),
        genesis_hash: expected_genesis_hash(),
        snapshot_class,
        allowed_restore_roles,
        snapshot_height: input.snapshot_height,
        snapshot_block_hash: input.snapshot_block_hash,
        parent_hash: input.parent_hash,
        state_root,
        consensus_fork: active_consensus_fork_migration()?,
        canonical_lock_height: input.canonical_lock_height,
        canonical_lock_hash: input.canonical_lock_hash,
        qc_evidence: input.qc_evidence,
        active_validator_set: input.active_validator_set,
        quorum_threshold,
        files,
        full_archive_sha256,
        created_at: input.created_at,
        source_node_id: input.source_node_id,
        source_role,
        runtime_checksum: input.runtime_checksum,
        source_node_quarantined: input.source_node_quarantined,
        source_node_majority_branch: input.source_node_majority_branch,
        conflict_height_hash: input.conflict_height_hash,
        manifest_signer_uma_id: input.manifest_signer_uma_id,
        manifest_signing_key_id: input.manifest_signing_key_id,
        manifest_signer_public_key: input.manifest_signer_public_key,
        manifest_signature_epoch: input.manifest_signature_epoch,
    })
}

pub fn sign_snapshot_manifest(
    signer: &mut AegisPqvmSigner,
    manifest: SnapshotManifest,
) -> Result<SignedSnapshotManifest, String> {
    let signature = signer
        .sign_domain(
            SYNERGY_ARCHIVE_SNAPSHOT_MANIFEST_V1,
            &manifest.canonical_bytes()?,
            &manifest.manifest_signing_key_id,
        )
        .map_err(|error| error.to_string())?;
    Ok(SignedSnapshotManifest {
        manifest,
        signature_domain: SYNERGY_ARCHIVE_SNAPSHOT_MANIFEST_V1.to_string(),
        aegis_pq_signature: signature,
    })
}

pub fn verify_signed_snapshot_manifest(
    signed: &SignedSnapshotManifest,
    policy: &SnapshotVerificationPolicy,
    snapshot_root: Option<&Path>,
) -> SnapshotVerificationReport {
    let manifest = &signed.manifest;
    let mut errors = Vec::new();
    let manifest_hash = match manifest.manifest_hash() {
        Ok(hash) => Some(hash),
        Err(error) => {
            errors.push(error);
            None
        }
    };

    if manifest.manifest_version != SNAPSHOT_MANIFEST_VERSION {
        errors.push("snapshot manifest version mismatch".to_string());
    }
    if manifest.chain_id != policy.expected_chain_id {
        errors.push("snapshot manifest wrong chain_id".to_string());
    }
    if manifest.chain_id_hex != "0x4f0" {
        errors.push("snapshot manifest wrong chain_id_hex".to_string());
    }
    if manifest.network_id != policy.expected_network_id {
        errors.push("snapshot manifest wrong network_id".to_string());
    }
    if !manifest
        .genesis_hash
        .eq_ignore_ascii_case(&policy.expected_genesis_hash)
    {
        errors.push("snapshot manifest wrong genesis_hash".to_string());
    }
    let normalized_class = match normalize_snapshot_class(&manifest.snapshot_class) {
        Some(snapshot_class) => snapshot_class.to_string(),
        None => {
            errors.push(format!(
                "snapshot manifest unsupported snapshot_class {}",
                manifest.snapshot_class
            ));
            manifest.snapshot_class.clone()
        }
    };
    let manifest_files = manifest
        .files
        .iter()
        .map(|entry| entry.relative_path.as_str())
        .collect::<Vec<_>>();
    if let Err(error) = validate_snapshot_file_contract(&normalized_class, &manifest_files) {
        errors.push(error);
    }
    if let Some(expected_class) = policy.expected_snapshot_class.as_deref() {
        match normalize_snapshot_class(expected_class) {
            Some(expected) if expected == normalized_class => {}
            Some(expected) => errors.push(format!(
                "snapshot class mismatch: expected {expected}, got {normalized_class}"
            )),
            None => errors.push(format!(
                "snapshot verification policy requested unsupported class {expected_class}"
            )),
        }
    }
    if manifest.allowed_restore_roles.is_empty() {
        errors.push("snapshot manifest has no allowed restore roles".to_string());
    }
    for role in &manifest.allowed_restore_roles {
        let normalized_role = normalize_snapshot_role(role);
        if !snapshot_class_allows_role(&normalized_class, &normalized_role) {
            errors.push(format!(
                "snapshot class {normalized_class} is not compatible with restore role {normalized_role}"
            ));
        }
    }
    if let Some(target_role) = policy.target_role.as_deref() {
        let target_role = normalize_snapshot_role(target_role);
        if !manifest
            .allowed_restore_roles
            .iter()
            .map(|role| normalize_snapshot_role(role))
            .any(|allowed| allowed == target_role)
        {
            errors.push(format!(
                "snapshot target role {target_role} is not allowed for class {normalized_class}"
            ));
        }
    }
    let dynamic_required_quorum =
        required_snapshot_quorum_for_validator_count(manifest.active_validator_set.len());
    let required_quorum = policy.required_quorum.max(dynamic_required_quorum);
    if manifest.active_validator_set.is_empty() {
        errors.push("snapshot active validator set is empty".to_string());
    }
    if manifest.quorum_threshold < required_quorum {
        errors.push(format!(
            "snapshot manifest quorum threshold {} is below required {required_quorum}",
            manifest.quorum_threshold
        ));
    }
    let active_validator_set_meets_baseline =
        manifest.active_validator_set.len() >= policy.expected_validator_count;
    if !active_validator_set_meets_baseline {
        errors.push("snapshot active validator set is below the validator count".to_string());
    }
    if manifest.qc_evidence.vote_count < required_quorum {
        errors.push(format!(
            "snapshot committed QC vote_count below {required_quorum}"
        ));
    }
    if !manifest.qc_evidence.aegis_pqc_verified {
        errors.push("snapshot committed QC was not verified through Aegis/PQC".to_string());
    }
    if !manifest.qc_evidence.duplicate_signer_check_passed {
        errors.push("snapshot committed QC duplicate signer check failed".to_string());
    }
    let qc_active_validator_count = if manifest.qc_evidence.active_validator_count == 0 {
        manifest.active_validator_set.len()
    } else {
        manifest.qc_evidence.active_validator_count
    };
    if qc_active_validator_count != manifest.active_validator_set.len() {
        errors.push(format!(
            "snapshot QC active validator count {qc_active_validator_count} does not match manifest active validator set {}",
            manifest.active_validator_set.len()
        ));
    }
    if manifest
        .qc_evidence
        .relayers_rpc_support_counted_toward_quorum
    {
        errors.push("snapshot QC counted relayer/RPC/support node toward quorum".to_string());
    }
    let signer_set = manifest
        .qc_evidence
        .signer_set
        .iter()
        .collect::<BTreeSet<_>>();
    if signer_set.len() != manifest.qc_evidence.signer_set.len() {
        errors.push("snapshot committed QC contains duplicate signer".to_string());
    }
    for signer in signer_set {
        if !manifest
            .active_validator_set
            .iter()
            .any(|active| active == signer)
        {
            errors.push(format!(
                "snapshot committed QC signer {signer} is not in the active validator set"
            ));
        }
    }
    if manifest.source_node_quarantined {
        errors.push("snapshot source node is quarantined".to_string());
    }
    if manifest.source_node_id.trim().is_empty() || manifest.source_node_id == "unknown-validator" {
        errors.push("snapshot producer identity is invalid".to_string());
    }
    if let Some(error) =
        snapshot_producer_role_validation_error(&normalized_class, &manifest.source_role)
    {
        errors.push(error);
    }
    if manifest.runtime_checksum.trim().is_empty() || manifest.runtime_checksum == "unknown" {
        errors.push("snapshot runtime checksum is missing".to_string());
    }
    if !manifest.source_node_majority_branch {
        errors.push("snapshot source node is not proven on the majority branch".to_string());
    }
    if let (Some(current), Some(max_lag)) = (
        policy.current_finalized_height,
        policy.max_snapshot_lag_blocks,
    ) {
        if current.saturating_sub(manifest.snapshot_height) > max_lag {
            errors.push("snapshot is stale beyond allowed lag".to_string());
        }
    }
    match manifest
        .state_root
        .as_deref()
        .map(str::trim)
        .filter(|root| !root.is_empty())
    {
        Some(root) => match snapshot_state_root_digest(&manifest.files) {
            Ok(expected) if expected == root => {}
            Ok(_) => errors.push("snapshot finalized state root mismatch".to_string()),
            Err(error) => errors.push(error),
        },
        None => errors.push("snapshot manifest missing finalized state root".to_string()),
    }
    if let Err(error) =
        validate_snapshot_fork_metadata(manifest.snapshot_height, manifest.consensus_fork.as_ref())
    {
        errors.push(error);
    }

    let mut manifest_signature_verified = false;
    if policy.require_manifest_signature {
        match verify_manifest_signature(signed) {
            Ok(()) => manifest_signature_verified = true,
            Err(error) => errors.push(error),
        }
    }

    let mut file_checksums_verified = false;
    if policy.require_file_checksums {
        match verify_snapshot_file_checksums(manifest, snapshot_root) {
            Ok(()) => file_checksums_verified = true,
            Err(error) => errors.push(error),
        }
    }

    SnapshotVerificationReport {
        success: errors.is_empty(),
        fail_closed: !errors.is_empty(),
        errors,
        manifest_hash,
        snapshot_class: normalized_class,
        source_role: manifest.source_role.clone(),
        allowed_restore_roles: manifest
            .allowed_restore_roles
            .iter()
            .map(|role| normalize_snapshot_role(role))
            .collect(),
        snapshot_height: manifest.snapshot_height,
        committed_qc_height: manifest.qc_evidence.committed_qc_height,
        committed_qc_hash: manifest.qc_evidence.committed_qc_hash.clone(),
        committed_qc_vote_count: manifest.qc_evidence.vote_count,
        committed_qc_signers: manifest.qc_evidence.signer_set.clone(),
        source_qc_aegis_pqc_verified: manifest.qc_evidence.aegis_pqc_verified,
        duplicate_signer_check_passed: manifest.qc_evidence.duplicate_signer_check_passed,
        active_validator_count: qc_active_validator_count,
        active_validator_set_meets_baseline,
        relayers_rpc_support_counted_toward_quorum: manifest
            .qc_evidence
            .relayers_rpc_support_counted_toward_quorum,
        manifest_signature_verified,
        file_checksums_verified,
    }
}

pub fn build_chain_state_wipe_plan(
    validator_id: impl Into<String>,
    data_dir: &Path,
    evidence_path: &Path,
) -> Result<ChainStateWipePlan, String> {
    let mut files_to_wipe = Vec::new();
    for entry in SNAPSHOT_ALLOWED_FILES {
        let path = data_dir.join(entry);
        if path.exists() {
            files_to_wipe.push(path.to_string_lossy().to_string());
        }
    }
    let files_to_preserve = files_to_wipe.clone();
    let plan = ChainStateWipePlan {
        validator_id: validator_id.into(),
        data_dir: data_dir.to_string_lossy().to_string(),
        evidence_path: evidence_path.to_string_lossy().to_string(),
        canonical_locks_mutated: files_to_wipe
            .iter()
            .any(|path| path.ends_with("canonical_locks.json")),
        committed_qcs_mutated: files_to_wipe.iter().any(|path| {
            path.ends_with("committed_qcs.json") || path.ends_with("committed_qcs.jsonl")
        }),
        chain_state_mutated: files_to_wipe
            .iter()
            .any(|path| path.ends_with("chain.json")),
        dag_state_mutated: files_to_wipe
            .iter()
            .any(|path| path.ends_with("dag_state.json")),
        registry_state_mutated: files_to_wipe
            .iter()
            .any(|path| path.ends_with("validator_registry.json")),
        token_state_mutated: files_to_wipe
            .iter()
            .any(|path| path.ends_with("token_state.json") || path.ends_with("account_state.json")),
        files_to_preserve,
        files_to_wipe,
        files_never_to_touch: SNAPSHOT_FORBIDDEN_PATH_FRAGMENTS
            .iter()
            .map(|item| item.to_string())
            .collect(),
        keys_or_configs_copied: false,
        genesis_mutated: false,
        quorum_mutated: false,
    };
    validate_chain_state_wipe_plan(&plan)?;
    Ok(plan)
}

pub fn validate_chain_state_wipe_plan(plan: &ChainStateWipePlan) -> Result<(), String> {
    if plan.keys_or_configs_copied {
        return Err("wipe plan would copy keys or configs".to_string());
    }
    if plan.genesis_mutated {
        return Err("wipe plan would mutate genesis".to_string());
    }
    if plan.quorum_mutated {
        return Err("wipe plan would mutate quorum".to_string());
    }
    for path in &plan.files_to_wipe {
        if contains_forbidden_fragment(path) {
            return Err(format!("wipe plan includes forbidden path {path}"));
        }
        let basename = Path::new(path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        if !SNAPSHOT_ALLOWED_FILES
            .iter()
            .any(|allowed| allowed == &basename)
        {
            return Err(format!("wipe plan includes non-chain-data file {path}"));
        }
    }
    Ok(())
}

pub fn apply_chain_state_wipe_plan(
    plan: &ChainStateWipePlan,
    preconditions: WipeApplyPreconditions,
) -> Result<ChainStateWipeResult, String> {
    validate_chain_state_wipe_plan(plan)?;
    if !preconditions.validator_quarantined {
        return Err("refusing chain wipe: validator is not quarantined".to_string());
    }
    if !preconditions.evidence_preserved {
        return Err("refusing chain wipe: evidence has not been preserved".to_string());
    }
    if !preconditions.snapshot_verified {
        return Err("refusing chain wipe: replacement snapshot is not verified".to_string());
    }
    let evidence_root = PathBuf::from(&plan.evidence_path);
    fs::create_dir_all(&evidence_root)
        .map_err(|error| format!("create evidence path {}: {error}", evidence_root.display()))?;
    let mut files_preserved = Vec::new();
    let mut files_wiped = Vec::new();
    for path_text in &plan.files_to_wipe {
        let path = PathBuf::from(path_text);
        if !path.exists() {
            continue;
        }
        let target = evidence_root.join(
            path.file_name()
                .ok_or_else(|| format!("wipe path has no file name: {}", path.display()))?,
        );
        fs::copy(&path, &target).map_err(|error| {
            format!(
                "preserve chain evidence {} -> {}: {error}",
                path.display(),
                target.display()
            )
        })?;
        files_preserved.push(target.to_string_lossy().to_string());
        fs::remove_file(&path)
            .map_err(|error| format!("wipe chain file {}: {error}", path.display()))?;
        files_wiped.push(path.to_string_lossy().to_string());
    }
    Ok(ChainStateWipeResult {
        success: true,
        evidence_path: plan.evidence_path.clone(),
        files_preserved,
        files_wiped,
        canonical_locks_mutated: plan.canonical_locks_mutated,
        committed_qcs_mutated: plan.committed_qcs_mutated,
        chain_state_mutated: plan.chain_state_mutated,
        dag_state_mutated: plan.dag_state_mutated,
        registry_state_mutated: plan.registry_state_mutated,
        token_state_mutated: plan.token_state_mutated,
        keys_or_configs_copied: false,
        genesis_mutated: false,
        quorum_mutated: false,
    })
}

pub fn build_snapshot_restore_plan(
    validator_id: impl Into<String>,
    signed: &SignedSnapshotManifest,
    source_snapshot: impl Into<String>,
    target_data_dir: &Path,
    verification: &SnapshotVerificationReport,
) -> Result<SnapshotRestorePlan, String> {
    let manifest_files = signed
        .manifest
        .files
        .iter()
        .map(|entry| entry.relative_path.as_str())
        .collect::<Vec<_>>();
    validate_snapshot_file_contract(&signed.manifest.snapshot_class, &manifest_files)
        .map_err(|error| format!("refusing restore plan: {error}"))?;
    if !verification.success {
        return Err("refusing restore plan: snapshot verification failed".to_string());
    }
    let manifest_hash = verification
        .manifest_hash
        .clone()
        .ok_or_else(|| "refusing restore plan: manifest hash unavailable".to_string())?;
    Ok(SnapshotRestorePlan {
        validator_id: validator_id.into(),
        snapshot_manifest_hash: manifest_hash,
        snapshot_height: signed.manifest.snapshot_height,
        source_snapshot: source_snapshot.into(),
        target_data_dir: target_data_dir.to_string_lossy().to_string(),
        files_to_restore: signed
            .manifest
            .files
            .iter()
            .map(|entry| entry.relative_path.clone())
            .collect(),
        keys_or_configs_copied: false,
        genesis_mutated: false,
        quorum_mutated: false,
    })
}

fn allowed_transition(current: RealignmentState, next: RealignmentState) -> bool {
    use RealignmentState::*;
    matches!(
        (current, next),
        (Active, Suspect)
            | (Suspect, Quarantined)
            | (Active, Quarantined)
            | (Quarantined, EvidencePreserved)
            | (EvidencePreserved, ChainDataWipeReady)
            | (ChainDataWipeReady, ChainDataWiped)
            | (ChainDataWiped, SnapshotDiscovery)
            | (SnapshotDiscovery, SnapshotDownloading)
            | (SnapshotDownloading, SnapshotVerified)
            | (SnapshotDiscovery, SnapshotVerified)
            | (SnapshotVerified, SnapshotRestored)
            | (SnapshotRestored, SpeedSyncing)
            | (SpeedSyncing, CaughtUp)
            | (CaughtUp, VoteOnly)
            | (CaughtUp, ShadowObserving)
            | (ShadowObserving, ShadowPassed)
            | (ShadowPassed, ReadyToRejoin)
            | (ShadowPassed, VoteOnly)
            | (ReadyToRejoin, VoteOnly)
            | (ReadyToRejoin, PendingReactivation)
            | (VoteOnly, Active)
            | (VoteOnly, Quarantined)
            | (PendingReactivation, Active)
            | (_, FailedClosed)
            | (ShadowObserving, Quarantined)
            | (SnapshotVerified, Quarantined)
            | (SpeedSyncing, Quarantined)
    )
}

fn collect_snapshot_files(
    state_dir: &Path,
    snapshot_class: &str,
) -> Result<Vec<SnapshotFileEntry>, String> {
    let mut files = Vec::new();
    let data_dir = if state_dir.join("data").is_dir() {
        state_dir.join("data")
    } else {
        state_dir.to_path_buf()
    };
    for file_name in SNAPSHOT_ALLOWED_FILES {
        let path = data_dir.join(file_name);
        if path.exists() {
            let relative_path = file_name.to_string();
            verify_snapshot_relative_path(&relative_path)?;
            files.push(snapshot_file_entry(&path, relative_path)?);
        }
    }
    if files.is_empty() {
        return Err("snapshot contains no chain/state files".to_string());
    }
    let present_files = files
        .iter()
        .map(|entry| entry.relative_path.as_str())
        .collect::<Vec<_>>();
    validate_snapshot_file_contract(snapshot_class, &present_files)?;
    Ok(files)
}

fn snapshot_file_entry(path: &Path, relative_path: String) -> Result<SnapshotFileEntry, String> {
    let mut file = fs::File::open(path)
        .map_err(|error| format!("open snapshot file {}: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = [0u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("read snapshot file {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        bytes += read as u64;
    }
    Ok(SnapshotFileEntry {
        relative_path,
        sha256: hex::encode(hasher.finalize()),
        bytes,
    })
}

fn verify_snapshot_file_checksums(
    manifest: &SnapshotManifest,
    snapshot_root: Option<&Path>,
) -> Result<(), String> {
    let expected_digest = manifest_files_digest(&manifest.files)?;
    if manifest.full_archive_sha256 != expected_digest {
        return Err("snapshot archive digest does not match manifest file list".to_string());
    }
    if let Some(root) = snapshot_root {
        for entry in &manifest.files {
            verify_snapshot_relative_path(&entry.relative_path)?;
            let actual_entry = snapshot_file_entry(
                &root.join(&entry.relative_path),
                entry.relative_path.clone(),
            )?;
            if actual_entry.bytes != entry.bytes {
                return Err(format!(
                    "snapshot file {} size mismatch",
                    entry.relative_path
                ));
            }
            if actual_entry.sha256 != entry.sha256 {
                return Err(format!(
                    "snapshot file {} checksum mismatch",
                    entry.relative_path
                ));
            }
            if entry.relative_path == "chain.json" {
                validate_snapshot_chain_json(&root.join(&entry.relative_path))?;
            }
        }
    }
    Ok(())
}

fn validate_snapshot_chain_json(path: &Path) -> Result<(), String> {
    let file =
        fs::File::open(path).map_err(|error| format!("open snapshot chain.json: {error}"))?;
    let reader = BufReader::with_capacity(1024 * 1024, file);
    let mut deserializer = serde_json::Deserializer::from_reader(reader);
    serde::de::Deserializer::deserialize_seq(&mut deserializer, StrictJsonArrayVisitor)
        .map_err(|error| format!("snapshot chain.json is not a valid JSON array: {error}"))?;
    deserializer
        .end()
        .map_err(|error| format!("snapshot chain.json has trailing data: {error}"))
}

struct StrictJsonArrayVisitor;

impl<'de> Visitor<'de> for StrictJsonArrayVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a single JSON array")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(())
    }
}

fn verify_manifest_signature(signed: &SignedSnapshotManifest) -> Result<(), String> {
    if signed.signature_domain != SYNERGY_ARCHIVE_SNAPSHOT_MANIFEST_V1 {
        return Err("snapshot manifest signature domain mismatch".to_string());
    }
    if !signed.aegis_pq_signature.is_present() {
        return Err("snapshot manifest is unsigned".to_string());
    }
    let manifest = &signed.manifest;
    let lifecycle = AegisPqKeyLifecycleRecord {
        uma_id: manifest.manifest_signer_uma_id.clone(),
        key_id: manifest.manifest_signing_key_id.clone(),
        roles: vec![AegisPqKeyRole::ArchiveSnapshotSigner],
        active_from_epoch: Epoch(manifest.manifest_signature_epoch),
        active_until_epoch: None,
        revoked_from_epoch: None,
    };
    let verifier = AegisPqvmVerifier::initialize_required_for_public_key(
        manifest.manifest_signer_public_key.clone(),
        lifecycle,
    )
    .map_err(|error| error.to_string())?;
    let current_payload = manifest.canonical_bytes()?;
    match verify_manifest_signature_payload(&verifier, signed, &current_payload) {
        Ok(()) => Ok(()),
        Err(current_error) => {
            let legacy_payload = legacy_snapshot_manifest_canonical_bytes(manifest)?;
            verify_manifest_signature_payload(&verifier, signed, &legacy_payload)
                .map_err(|_| current_error)
        }
    }
}

fn verify_manifest_signature_payload(
    verifier: &AegisPqvmVerifier,
    signed: &SignedSnapshotManifest,
    payload: &[u8],
) -> Result<(), String> {
    let manifest = &signed.manifest;
    verifier
        .verify_domain_signature(
            SYNERGY_ARCHIVE_SNAPSHOT_MANIFEST_V1,
            payload,
            &manifest.manifest_signer_uma_id,
            &manifest.manifest_signing_key_id,
            Epoch(manifest.manifest_signature_epoch),
            AegisPqKeyRole::ArchiveSnapshotSigner,
            &signed.aegis_pq_signature,
        )
        .map_err(|error| error.to_string())
}

#[derive(Serialize)]
struct LegacySnapshotManifestRef<'a> {
    manifest_version: u32,
    chain_id: u64,
    chain_id_hex: &'a str,
    network_id: &'a str,
    genesis_hash: &'a str,
    snapshot_class: &'a str,
    allowed_restore_roles: &'a [String],
    snapshot_height: u64,
    snapshot_block_hash: &'a str,
    parent_hash: &'a str,
    state_root: Option<&'a String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    consensus_fork: Option<&'a ConsensusForkMigration>,
    canonical_lock_height: u64,
    canonical_lock_hash: &'a str,
    qc_evidence: LegacySnapshotQcEvidenceRef<'a>,
    active_validator_set: &'a [String],
    quorum_threshold: u64,
    files: &'a [SnapshotFileEntry],
    full_archive_sha256: &'a str,
    created_at: u64,
    source_node_id: &'a str,
    source_role: &'a str,
    runtime_checksum: &'a str,
    source_node_quarantined: bool,
    source_node_majority_branch: bool,
    conflict_height_hash: Option<&'a String>,
    manifest_signer_uma_id: &'a str,
    manifest_signing_key_id: &'a AegisPqKeyId,
    manifest_signer_public_key: &'a AegisPqPublicKey,
    manifest_signature_epoch: u64,
}

#[derive(Serialize)]
struct LegacySnapshotQcEvidenceRef<'a> {
    committed_qc_height: u64,
    committed_qc_hash: &'a str,
    vote_count: u64,
    signer_set: &'a [String],
    aegis_pqc_verified: bool,
    duplicate_signer_check_passed: bool,
    active_validator_count: usize,
    active_validator_set_is_genesis_5: bool,
    relayers_rpc_support_counted_toward_quorum: bool,
}

fn legacy_snapshot_manifest_canonical_bytes(
    manifest: &SnapshotManifest,
) -> Result<Vec<u8>, String> {
    let legacy = LegacySnapshotManifestRef {
        manifest_version: manifest.manifest_version,
        chain_id: manifest.chain_id,
        chain_id_hex: &manifest.chain_id_hex,
        network_id: &manifest.network_id,
        genesis_hash: &manifest.genesis_hash,
        snapshot_class: &manifest.snapshot_class,
        allowed_restore_roles: &manifest.allowed_restore_roles,
        snapshot_height: manifest.snapshot_height,
        snapshot_block_hash: &manifest.snapshot_block_hash,
        parent_hash: &manifest.parent_hash,
        state_root: manifest.state_root.as_ref(),
        consensus_fork: manifest.consensus_fork.as_ref(),
        canonical_lock_height: manifest.canonical_lock_height,
        canonical_lock_hash: &manifest.canonical_lock_hash,
        qc_evidence: LegacySnapshotQcEvidenceRef {
            committed_qc_height: manifest.qc_evidence.committed_qc_height,
            committed_qc_hash: &manifest.qc_evidence.committed_qc_hash,
            vote_count: manifest.qc_evidence.vote_count,
            signer_set: &manifest.qc_evidence.signer_set,
            aegis_pqc_verified: manifest.qc_evidence.aegis_pqc_verified,
            duplicate_signer_check_passed: manifest.qc_evidence.duplicate_signer_check_passed,
            active_validator_count: manifest.qc_evidence.active_validator_count,
            active_validator_set_is_genesis_5: manifest
                .qc_evidence
                .active_validator_set_meets_baseline,
            relayers_rpc_support_counted_toward_quorum: manifest
                .qc_evidence
                .relayers_rpc_support_counted_toward_quorum,
        },
        active_validator_set: &manifest.active_validator_set,
        quorum_threshold: manifest.quorum_threshold,
        files: &manifest.files,
        full_archive_sha256: &manifest.full_archive_sha256,
        created_at: manifest.created_at,
        source_node_id: &manifest.source_node_id,
        source_role: &manifest.source_role,
        runtime_checksum: &manifest.runtime_checksum,
        source_node_quarantined: manifest.source_node_quarantined,
        source_node_majority_branch: manifest.source_node_majority_branch,
        conflict_height_hash: manifest.conflict_height_hash.as_ref(),
        manifest_signer_uma_id: &manifest.manifest_signer_uma_id,
        manifest_signing_key_id: &manifest.manifest_signing_key_id,
        manifest_signer_public_key: &manifest.manifest_signer_public_key,
        manifest_signature_epoch: manifest.manifest_signature_epoch,
    };
    serde_json::to_vec(&legacy)
        .map_err(|error| format!("legacy canonical serialize failed: {error}"))
}

fn verify_snapshot_relative_path(relative_path: &str) -> Result<(), String> {
    let path = Path::new(relative_path);
    if path.is_absolute() {
        return Err("snapshot path must be relative".to_string());
    }
    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err("snapshot path contains unsafe traversal".to_string());
    }
    if contains_forbidden_fragment(relative_path) {
        return Err(format!(
            "snapshot path {relative_path} contains forbidden key/config/runtime material"
        ));
    }
    let basename = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    if !SNAPSHOT_ALLOWED_FILES
        .iter()
        .any(|allowed| allowed == &basename)
    {
        return Err(format!(
            "snapshot path {relative_path} is not launch-approved chain state"
        ));
    }
    Ok(())
}

fn contains_forbidden_fragment(path: &str) -> bool {
    let normalized = path.replace('\\', "/").to_ascii_lowercase();
    SNAPSHOT_FORBIDDEN_PATH_FRAGMENTS
        .iter()
        .any(|fragment| normalized.contains(fragment))
}

fn manifest_files_digest(files: &[SnapshotFileEntry]) -> Result<String, String> {
    let mut canonical = files.to_vec();
    canonical.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    serde_json::to_vec(&canonical)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| format!("snapshot file digest serialize failed: {error}"))
}

fn snapshot_state_root_digest(files: &[SnapshotFileEntry]) -> Result<String, String> {
    let mut canonical = files.to_vec();
    canonical.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| format!("snapshot state root serialize failed: {error}"))?;
    let mut hasher = Sha256::new();
    hasher.update(SNAPSHOT_STATE_ROOT_DOMAIN);
    hasher.update(&bytes);
    Ok(hex::encode(hasher.finalize()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

pub fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    let bytes =
        serde_json::to_vec_pretty(value).map_err(|error| format!("serialize json: {error}"))?;
    let tmp = path.with_extension("json.tmp");
    let mut file =
        fs::File::create(&tmp).map_err(|error| format!("create {}: {error}", tmp.display()))?;
    file.write_all(&bytes)
        .map_err(|error| format!("write {}: {error}", tmp.display()))?;
    file.sync_all()
        .map_err(|error| format!("sync {}: {error}", tmp.display()))?;
    drop(file);
    fs::rename(&tmp, path).map_err(|error| format!("replace {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aegis_pqvm::AegisPqvmSigner;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn baseline_required_quorum() -> usize {
        required_snapshot_quorum_for_validator_count(BASELINE_VALIDATOR_COUNT) as usize
    }

    fn temp_root(name: &str) -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let root = crate::utils::test_temp_root(format!(
            "synergy-self-realign-{name}-{}-{id}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn signer() -> (AegisPqvmSigner, AegisPqKeyId, AegisPqPublicKey) {
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

    fn qc_evidence() -> SnapshotQcEvidence {
        SnapshotQcEvidence {
            committed_qc_height: 100,
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

    fn validators() -> Vec<String> {
        (1..=5).map(|index| format!("validator-{index}")).collect()
    }

    fn state_dir() -> PathBuf {
        let root = temp_root("state");
        fs::write(root.join("chain.json"), b"chain").unwrap();
        fs::write(root.join("committed_blocks.jsonl"), b"blocks\n").unwrap();
        fs::write(root.join("canonical_locks.json"), b"locks").unwrap();
        fs::write(root.join("committed_qcs.jsonl"), b"qcs").unwrap();
        fs::write(root.join("token_state.json"), b"token-state").unwrap();
        fs::write(root.join("validator_registry.json"), b"validators").unwrap();
        root
    }

    fn signed_manifest_with(
        active_validator_set: Vec<String>,
        qc_evidence: SnapshotQcEvidence,
    ) -> SignedSnapshotManifest {
        let (mut signer, key_id, public) = signer();
        let manifest = create_snapshot_manifest(SnapshotBuildInput {
            state_dir: state_dir(),
            snapshot_class: SNAPSHOT_CLASS_VALIDATOR_PRUNED.to_string(),
            allowed_restore_roles: vec!["validator".to_string()],
            snapshot_height: 100,
            snapshot_block_hash: "block-hash".to_string(),
            parent_hash: "parent-hash".to_string(),
            state_root: None,
            canonical_lock_height: 100,
            canonical_lock_hash: "block-hash".to_string(),
            qc_evidence,
            active_validator_set,
            source_node_id: "validator-2".to_string(),
            source_role: "VALIDATOR".to_string(),
            runtime_checksum: "runtime-sha256".to_string(),
            source_node_quarantined: false,
            source_node_majority_branch: true,
            conflict_height_hash: Some("block-hash".to_string()),
            manifest_signer_uma_id: "archive-1".to_string(),
            manifest_signing_key_id: key_id,
            manifest_signer_public_key: public,
            manifest_signature_epoch: 0,
            created_at: 1,
        })
        .unwrap();
        sign_snapshot_manifest(&mut signer, manifest).unwrap()
    }

    fn signed_manifest() -> SignedSnapshotManifest {
        signed_manifest_with(validators(), qc_evidence())
    }

    fn verify(signed: &SignedSnapshotManifest) -> SnapshotVerificationReport {
        verify_signed_snapshot_manifest(signed, &SnapshotVerificationPolicy::default(), None)
    }

    #[test]
    fn signed_snapshot_manifest_canonicalization_is_deterministic() {
        let signed = signed_manifest();
        let first = signed.manifest.canonical_bytes().unwrap();
        let second = signed.manifest.canonical_bytes().unwrap();
        assert_eq!(first, second);
        assert_eq!(
            signed.manifest.manifest_hash().unwrap(),
            signed.manifest.manifest_hash().unwrap()
        );
    }

    #[test]
    fn valid_signed_snapshot_accepted() {
        let report = verify(&signed_manifest());
        assert!(report.success, "{:?}", report.errors);
        assert!(report.manifest_signature_verified);
        assert!(report.file_checksums_verified);
        assert_eq!(report.snapshot_class, SNAPSHOT_CLASS_VALIDATOR_PRUNED);
        assert_eq!(report.allowed_restore_roles, vec!["validator".to_string()]);
    }

    #[test]
    fn validator_pruned_snapshot_requires_token_state_for_creation_and_restore() {
        let root = state_dir();
        fs::remove_file(root.join("token_state.json")).unwrap();
        let (_signer, key_id, public) = signer();
        let error = create_snapshot_manifest(SnapshotBuildInput {
            state_dir: root,
            snapshot_class: SNAPSHOT_CLASS_VALIDATOR_PRUNED.to_string(),
            allowed_restore_roles: vec!["validator".to_string()],
            snapshot_height: 100,
            snapshot_block_hash: "block-hash".to_string(),
            parent_hash: "parent-hash".to_string(),
            state_root: None,
            canonical_lock_height: 100,
            canonical_lock_hash: "block-hash".to_string(),
            qc_evidence: qc_evidence(),
            active_validator_set: validators(),
            source_node_id: "validator-2".to_string(),
            source_role: "VALIDATOR".to_string(),
            runtime_checksum: "runtime-sha256".to_string(),
            source_node_quarantined: false,
            source_node_majority_branch: true,
            conflict_height_hash: Some("block-hash".to_string()),
            manifest_signer_uma_id: "archive-1".to_string(),
            manifest_signing_key_id: key_id,
            manifest_signer_public_key: public,
            manifest_signature_epoch: 0,
            created_at: 1,
        })
        .expect_err("validator-pruned creation must require token state");
        assert!(
            error.contains("token_state.json"),
            "unexpected error: {error}"
        );

        let mut signed = signed_manifest();
        signed
            .manifest
            .files
            .retain(|entry| entry.relative_path != "token_state.json");
        let report = verify(&signed);
        assert!(!report.success);
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("token_state.json")));
        let restore_error = build_snapshot_restore_plan(
            "validator-1",
            &signed,
            "snapshot.tar",
            Path::new("data"),
            &report,
        )
        .expect_err("restore must reject an incomplete validator-pruned snapshot");
        assert!(restore_error.contains("token_state.json"));
    }

    #[test]
    fn validator_pruned_manifest_canonicalizes_validator_source_role() {
        let (mut signer, key_id, public) = signer();
        let manifest = create_snapshot_manifest(SnapshotBuildInput {
            state_dir: state_dir(),
            snapshot_class: SNAPSHOT_CLASS_VALIDATOR_PRUNED.to_string(),
            allowed_restore_roles: vec!["validator".to_string()],
            snapshot_height: 100,
            snapshot_block_hash: "block-hash".to_string(),
            parent_hash: "parent-hash".to_string(),
            state_root: None,
            canonical_lock_height: 100,
            canonical_lock_hash: "block-hash".to_string(),
            qc_evidence: qc_evidence(),
            active_validator_set: validators(),
            source_node_id: "validator-2".to_string(),
            source_role: "validator".to_string(),
            runtime_checksum: "runtime-sha256".to_string(),
            source_node_quarantined: false,
            source_node_majority_branch: true,
            conflict_height_hash: Some("block-hash".to_string()),
            manifest_signer_uma_id: "archive-1".to_string(),
            manifest_signing_key_id: key_id,
            manifest_signer_public_key: public,
            manifest_signature_epoch: 0,
            created_at: 1,
        })
        .unwrap();
        assert_eq!(manifest.source_role, "VALIDATOR");

        let signed = sign_snapshot_manifest(&mut signer, manifest).unwrap();
        assert!(verify(&signed).success);
    }

    #[test]
    fn validator_pruned_snapshot_accepts_onboarding_validator_restore_target() {
        let (mut signer, key_id, public) = signer();
        let manifest = create_snapshot_manifest(SnapshotBuildInput {
            state_dir: state_dir(),
            snapshot_class: SNAPSHOT_CLASS_VALIDATOR_PRUNED.to_string(),
            allowed_restore_roles: Vec::new(),
            snapshot_height: 100,
            snapshot_block_hash: "block-hash".to_string(),
            parent_hash: "parent-hash".to_string(),
            state_root: None,
            canonical_lock_height: 100,
            canonical_lock_hash: "block-hash".to_string(),
            qc_evidence: qc_evidence(),
            active_validator_set: validators(),
            source_node_id: "validator-2".to_string(),
            source_role: "validator".to_string(),
            runtime_checksum: "runtime-sha256".to_string(),
            source_node_quarantined: false,
            source_node_majority_branch: true,
            conflict_height_hash: Some("block-hash".to_string()),
            manifest_signer_uma_id: "archive-1".to_string(),
            manifest_signing_key_id: key_id,
            manifest_signer_public_key: public,
            manifest_signature_epoch: 0,
            created_at: 1,
        })
        .unwrap();
        assert_eq!(manifest.source_role, "VALIDATOR");
        assert!(manifest
            .allowed_restore_roles
            .iter()
            .any(|role| role == "onboarding_validator"));

        let signed = sign_snapshot_manifest(&mut signer, manifest).unwrap();
        let report = verify_signed_snapshot_manifest(
            &signed,
            &SnapshotVerificationPolicy {
                expected_snapshot_class: Some(SNAPSHOT_CLASS_VALIDATOR_PRUNED.to_string()),
                target_role: Some("onboarding_validator".to_string()),
                ..SnapshotVerificationPolicy::default()
            },
            None,
        );

        assert!(report.success, "{:?}", report.errors);
    }

    #[test]
    fn current_role_snapshot_classes_are_supported() {
        assert!(snapshot_class_allows_role(
            SNAPSHOT_CLASS_VALIDATOR_PRUNED,
            "validator"
        ));
        assert!(snapshot_class_allows_role(
            SNAPSHOT_CLASS_SUPPORT_RELAYER,
            "relayer"
        ));
        assert!(snapshot_class_allows_role(
            SNAPSHOT_CLASS_SUPPORT_OBSERVER,
            "observer"
        ));
        assert!(snapshot_class_allows_role(
            SNAPSHOT_CLASS_INDEXER_REPLAY,
            "explorer_indexer"
        ));
        assert!(snapshot_class_allows_role(
            SNAPSHOT_CLASS_SUPPORT_RPC,
            "rpc_gateway"
        ));
        assert!(snapshot_class_allows_role(
            SNAPSHOT_CLASS_ARCHIVE_FULL,
            "archive_validator"
        ));
        assert!(snapshot_class_allows_role(
            SNAPSHOT_CLASS_ARCHIVE_FULL,
            "validator"
        ));
    }

    #[test]
    fn archive_full_defaults_remain_archive_only() {
        assert_eq!(
            default_allowed_restore_roles_for_class(SNAPSHOT_CLASS_ARCHIVE_FULL).unwrap(),
            vec![
                "archive".to_string(),
                "archive_validator".to_string(),
                "snapshot_authority".to_string()
            ]
        );
    }

    #[test]
    fn archive_full_can_explicitly_authorize_validator_recovery() {
        let (mut signer, key_id, public) = signer();
        let manifest = create_snapshot_manifest(SnapshotBuildInput {
            state_dir: state_dir(),
            snapshot_class: SNAPSHOT_CLASS_ARCHIVE_FULL.to_string(),
            allowed_restore_roles: vec![
                "archive_validator".to_string(),
                "validator".to_string(),
                "quarantined_validator".to_string(),
            ],
            snapshot_height: 100,
            snapshot_block_hash: "block-hash".to_string(),
            parent_hash: "parent-hash".to_string(),
            state_root: None,
            canonical_lock_height: 100,
            canonical_lock_hash: "block-hash".to_string(),
            qc_evidence: qc_evidence(),
            active_validator_set: validators(),
            source_node_id: "validator-2".to_string(),
            source_role: "VALIDATOR".to_string(),
            runtime_checksum: "runtime-sha256".to_string(),
            source_node_quarantined: false,
            source_node_majority_branch: true,
            conflict_height_hash: Some("block-hash".to_string()),
            manifest_signer_uma_id: "archive-1".to_string(),
            manifest_signing_key_id: key_id,
            manifest_signer_public_key: public,
            manifest_signature_epoch: 0,
            created_at: 1,
        })
        .unwrap();
        let signed = sign_snapshot_manifest(&mut signer, manifest).unwrap();
        let policy = SnapshotVerificationPolicy {
            expected_snapshot_class: Some(SNAPSHOT_CLASS_ARCHIVE_FULL.to_string()),
            target_role: Some("validator".to_string()),
            ..SnapshotVerificationPolicy::default()
        };
        let report = verify_signed_snapshot_manifest(&signed, &policy, None);
        assert!(report.success, "{:?}", report.errors);
        assert_eq!(report.snapshot_class, SNAPSHOT_CLASS_ARCHIVE_FULL);
        assert!(report
            .allowed_restore_roles
            .iter()
            .any(|role| role == "validator"));
    }

    #[test]
    fn unsupported_future_role_snapshot_classes_are_rejected() {
        assert_eq!(normalize_snapshot_class("committee"), None);
        assert_eq!(normalize_snapshot_class("oracle"), None);
        assert_eq!(normalize_snapshot_class("compute"), None);
        assert!(!snapshot_class_allows_role("committee", "committee"));
    }

    #[test]
    fn support_observer_snapshot_class_accepts_only_observer() {
        assert_eq!(
            normalize_snapshot_class("observer"),
            Some(SNAPSHOT_CLASS_SUPPORT_OBSERVER)
        );
        assert!(snapshot_class_allows_role(
            SNAPSHOT_CLASS_SUPPORT_OBSERVER,
            "observer"
        ));
        assert!(!snapshot_class_allows_role(
            SNAPSHOT_CLASS_SUPPORT_OBSERVER,
            "validator"
        ));
    }

    #[test]
    fn current_compact_snapshot_classes_are_role_specific_support_only() {
        assert!(snapshot_class_uses_compact_history(
            SNAPSHOT_CLASS_VALIDATOR_PRUNED
        ));
        assert!(snapshot_class_uses_compact_history(
            SNAPSHOT_CLASS_SUPPORT_RELAYER
        ));
        assert!(snapshot_class_uses_compact_history(
            SNAPSHOT_CLASS_SUPPORT_OBSERVER
        ));
        assert!(snapshot_class_uses_compact_history(
            SNAPSHOT_CLASS_SUPPORT_RPC
        ));
        assert!(!snapshot_class_uses_compact_history(
            SNAPSHOT_CLASS_INDEXER_REPLAY
        ));
        assert!(!snapshot_class_uses_compact_history(
            SNAPSHOT_CLASS_ARCHIVE_FULL
        ));
    }

    #[test]
    fn expanded_active_validator_set_snapshot_accepted() {
        let mut active_validator_set = validators();
        active_validator_set.push("validator-6".to_string());
        let mut qc_evidence = qc_evidence();
        qc_evidence.active_validator_count = active_validator_set.len();
        qc_evidence.active_validator_set_meets_baseline = false;
        qc_evidence.vote_count =
            required_snapshot_quorum_for_validator_count(active_validator_set.len());
        qc_evidence.signer_set.push("validator-5".to_string());

        let report = verify(&signed_manifest_with(active_validator_set, qc_evidence));

        assert!(report.success, "{:?}", report.errors);
    }

    #[test]
    fn archive_bootstrap_class_accepts_archive_roles_and_alias() {
        assert_eq!(
            normalize_snapshot_class("archive-validator-bootstrap"),
            Some(SNAPSHOT_CLASS_ARCHIVE_BOOTSTRAP)
        );
        assert!(snapshot_class_allows_role(
            SNAPSHOT_CLASS_ARCHIVE_BOOTSTRAP,
            "archive_validator"
        ));
        assert!(!snapshot_class_allows_role(
            SNAPSHOT_CLASS_ARCHIVE_BOOTSTRAP,
            "validator"
        ));

        let (mut signer, key_id, public) = signer();
        let manifest = create_snapshot_manifest(SnapshotBuildInput {
            state_dir: state_dir(),
            snapshot_class: "archive-validator-bootstrap".to_string(),
            allowed_restore_roles: vec!["archive_validator".to_string()],
            snapshot_height: 100,
            snapshot_block_hash: "block-hash".to_string(),
            parent_hash: "parent-hash".to_string(),
            state_root: None,
            canonical_lock_height: 100,
            canonical_lock_hash: "block-hash".to_string(),
            qc_evidence: qc_evidence(),
            active_validator_set: validators(),
            source_node_id: "validator-2".to_string(),
            source_role: "VALIDATOR".to_string(),
            runtime_checksum: "runtime-sha256".to_string(),
            source_node_quarantined: false,
            source_node_majority_branch: true,
            conflict_height_hash: Some("block-hash".to_string()),
            manifest_signer_uma_id: "archive-1".to_string(),
            manifest_signing_key_id: key_id,
            manifest_signer_public_key: public,
            manifest_signature_epoch: 0,
            created_at: 1,
        })
        .unwrap();
        assert_eq!(manifest.snapshot_class, SNAPSHOT_CLASS_ARCHIVE_BOOTSTRAP);
        let signed = sign_snapshot_manifest(&mut signer, manifest).unwrap();
        let report = verify_signed_snapshot_manifest(
            &signed,
            &SnapshotVerificationPolicy {
                expected_snapshot_class: Some(SNAPSHOT_CLASS_ARCHIVE_BOOTSTRAP.to_string()),
                target_role: Some("archive_validator".to_string()),
                ..SnapshotVerificationPolicy::default()
            },
            None,
        );
        assert!(report.success, "{:?}", report.errors);
        assert_eq!(report.snapshot_class, SNAPSHOT_CLASS_ARCHIVE_BOOTSTRAP);
    }

    #[test]
    fn snapshot_verification_enforces_class_and_target_role() {
        let signed = signed_manifest();
        let wrong_class = verify_signed_snapshot_manifest(
            &signed,
            &SnapshotVerificationPolicy {
                expected_snapshot_class: Some(SNAPSHOT_CLASS_SUPPORT_RPC.to_string()),
                target_role: Some("rpc".to_string()),
                ..SnapshotVerificationPolicy::default()
            },
            None,
        );
        assert!(!wrong_class.success);
        assert!(wrong_class
            .errors
            .iter()
            .any(|error| error.contains("snapshot class mismatch")));
        assert!(wrong_class
            .errors
            .iter()
            .any(|error| error.contains("snapshot target role rpc is not allowed")));

        let wrong_target = verify_signed_snapshot_manifest(
            &signed,
            &SnapshotVerificationPolicy {
                expected_snapshot_class: Some(SNAPSHOT_CLASS_VALIDATOR_PRUNED.to_string()),
                target_role: Some("indexer".to_string()),
                ..SnapshotVerificationPolicy::default()
            },
            None,
        );
        assert!(!wrong_target.success);
        assert!(wrong_target
            .errors
            .iter()
            .any(|error| error.contains("snapshot target role indexer is not allowed")));
    }

    #[test]
    fn unsigned_snapshot_rejected() {
        let mut signed = signed_manifest();
        signed.aegis_pq_signature.algorithm.clear();
        signed.aegis_pq_signature.signature_bytes.clear();
        let report = verify(&signed);
        assert!(report.errors.iter().any(|error| error.contains("unsigned")));
    }

    #[test]
    fn snapshot_manifest_requires_chain_id_1264() {
        let mut signed = signed_manifest();
        signed.manifest.chain_id = 1263;
        let report = verify(&signed);
        assert!(report.errors.iter().any(|error| error.contains("chain_id")));
    }

    #[test]
    fn snapshot_manifest_requires_network_id() {
        let mut signed = signed_manifest();
        signed.manifest.network_id = "testnet".to_string();
        let report = verify(&signed);
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("network_id")));
    }

    #[test]
    fn snapshot_manifest_requires_genesis_hash() {
        let mut signed = signed_manifest();
        signed.manifest.genesis_hash = "wrong".to_string();
        let report = verify(&signed);
        assert!(report.errors.iter().any(|error| error.contains("genesis")));
    }

    #[test]
    fn snapshot_rejects_wrong_genesis() {
        let mut signed = signed_manifest();
        signed.manifest.genesis_hash = "f00".to_string();
        assert!(!verify(&signed).success);
    }

    #[test]
    fn snapshot_rejects_wrong_chain() {
        let mut signed = signed_manifest();
        signed.manifest.chain_id_hex = "0x4ef".to_string();
        assert!(!verify(&signed).success);
    }

    #[test]
    fn snapshot_rejects_invalid_qc() {
        let mut signed = signed_manifest();
        signed.manifest.qc_evidence.aegis_pqc_verified = false;
        let report = verify(&signed);
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("Aegis/PQC")));
    }

    #[test]
    fn snapshot_rejects_duplicate_signer_qc() {
        let mut signed = signed_manifest();
        signed.manifest.qc_evidence.signer_set[3] = "validator-1".to_string();
        let report = verify(&signed);
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("duplicate")));
    }

    #[test]
    fn snapshot_rejects_vote_count_below_required_quorum() {
        let mut signed = signed_manifest();
        signed.manifest.qc_evidence.vote_count = 3;
        let report = verify(&signed);
        let required_quorum = required_snapshot_quorum_for_validator_count(
            signed.manifest.active_validator_set.len(),
        );
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains(&format!("below {required_quorum}"))));
    }

    #[test]
    fn snapshot_rejects_vote_count_below_expanded_validator_quorum() {
        let active_validator_set = (1..=6)
            .map(|index| format!("validator-{index}"))
            .collect::<Vec<_>>();
        let mut evidence = qc_evidence();
        evidence.active_validator_count = active_validator_set.len();
        evidence.active_validator_set_meets_baseline = false;
        evidence.vote_count = required_snapshot_quorum_for_validator_count(6) - 1;
        evidence.signer_set.truncate(evidence.vote_count as usize);
        let signed = signed_manifest_with(active_validator_set, evidence);

        assert_eq!(
            signed.manifest.quorum_threshold,
            required_snapshot_quorum_for_validator_count(6)
        );
        let report = verify(&signed);
        assert!(report.errors.iter().any(|error| error.contains(&format!(
            "below {}",
            required_snapshot_quorum_for_validator_count(6)
        ))));
    }

    #[test]
    fn snapshot_rejects_non_active_signer() {
        let mut signed = signed_manifest();
        signed.manifest.qc_evidence.signer_set[3] = "relayer-1".to_string();
        let report = verify(&signed);
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("active validator set")));
    }

    #[test]
    fn snapshot_rejects_invalid_artifact_hash() {
        let mut signed = signed_manifest();
        signed.manifest.full_archive_sha256 = "bad-artifact-hash".to_string();
        let report = verify(&signed);
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("archive digest")));
    }

    #[test]
    fn snapshot_rejects_invalid_state_root() {
        let mut signed = signed_manifest();
        signed.manifest.state_root = Some("bad-state-root".to_string());
        let report = verify(&signed);
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("state root")));
    }

    #[test]
    fn snapshot_rejects_chain_json_with_trailing_bytes() {
        let root = temp_root("trailing-chain-json");
        fs::write(root.join("chain.json"), b"[{\"block_index\":100,\"hash\":\"block-hash\",\"previous_hash\":\"parent-hash\",\"transactions\":[],\"validator_id\":\"validator-1\",\"nonce\":1}]stale-tail").unwrap();
        fs::write(root.join("committed_blocks.jsonl"), b"blocks\n").unwrap();
        fs::write(root.join("canonical_locks.json"), b"locks").unwrap();
        fs::write(root.join("committed_qcs.jsonl"), b"qcs").unwrap();
        fs::write(root.join("token_state.json"), b"token-state").unwrap();
        fs::write(root.join("validator_registry.json"), b"validators").unwrap();
        let (mut signer, key_id, public) = signer();
        let manifest = create_snapshot_manifest(SnapshotBuildInput {
            state_dir: root.clone(),
            snapshot_class: SNAPSHOT_CLASS_VALIDATOR_PRUNED.to_string(),
            allowed_restore_roles: vec!["validator".to_string()],
            snapshot_height: 100,
            snapshot_block_hash: "block-hash".to_string(),
            parent_hash: "parent-hash".to_string(),
            state_root: None,
            canonical_lock_height: 100,
            canonical_lock_hash: "block-hash".to_string(),
            qc_evidence: qc_evidence(),
            active_validator_set: validators(),
            source_node_id: "validator-2".to_string(),
            source_role: "VALIDATOR".to_string(),
            runtime_checksum: "runtime-sha256".to_string(),
            source_node_quarantined: false,
            source_node_majority_branch: true,
            conflict_height_hash: Some("block-hash".to_string()),
            manifest_signer_uma_id: "archive-1".to_string(),
            manifest_signing_key_id: key_id,
            manifest_signer_public_key: public,
            manifest_signature_epoch: 0,
            created_at: 1,
        })
        .unwrap();
        let signed = sign_snapshot_manifest(&mut signer, manifest).unwrap();

        let report = verify_signed_snapshot_manifest(
            &signed,
            &SnapshotVerificationPolicy::default(),
            Some(&root),
        );

        assert!(!report.success);
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("trailing data")));
    }

    #[test]
    fn snapshot_rejects_invalid_producer_identity() {
        let mut signed = signed_manifest();
        signed.manifest.source_node_id = "unknown-validator".to_string();
        let report = verify(&signed);
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("producer identity")));
    }

    #[test]
    fn snapshot_rejects_unauthorized_source_role() {
        let mut signed = signed_manifest();
        signed.manifest.source_role = "RPC_GATEWAY".to_string();
        let report = verify(&signed);
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("producer role")));
    }

    #[test]
    fn snapshot_creation_rejects_legacy_genesis_validator_source_role() {
        let (_signer, key_id, public) = signer();
        let error = create_snapshot_manifest(SnapshotBuildInput {
            state_dir: state_dir(),
            snapshot_class: SNAPSHOT_CLASS_VALIDATOR_PRUNED.to_string(),
            allowed_restore_roles: vec!["validator".to_string()],
            snapshot_height: 100,
            snapshot_block_hash: "block-hash".to_string(),
            parent_hash: "parent-hash".to_string(),
            state_root: None,
            canonical_lock_height: 100,
            canonical_lock_hash: "block-hash".to_string(),
            qc_evidence: qc_evidence(),
            active_validator_set: validators(),
            source_node_id: "validator-2".to_string(),
            source_role: "GENESIS_VALIDATOR".to_string(),
            runtime_checksum: "runtime-sha256".to_string(),
            source_node_quarantined: false,
            source_node_majority_branch: true,
            conflict_height_hash: Some("block-hash".to_string()),
            manifest_signer_uma_id: "archive-1".to_string(),
            manifest_signing_key_id: key_id,
            manifest_signer_public_key: public,
            manifest_signature_epoch: 0,
            created_at: 1,
        })
        .unwrap_err();

        assert!(error.contains("GENESIS_VALIDATOR"));
        assert!(error.contains("legacy/stale"));
        assert!(error.contains("VALIDATOR"));
    }

    #[test]
    fn snapshot_verification_rejects_legacy_genesis_validator_source_role_as_stale() {
        let mut signed = signed_manifest();
        signed.manifest.source_role = "GENESIS_VALIDATOR".to_string();

        let report = verify(&signed);

        assert!(!report.success);
        assert!(report.errors.iter().any(|error| {
            error.contains("GENESIS_VALIDATOR")
                && error.contains("legacy/stale")
                && error.contains("VALIDATOR")
        }));
    }

    #[test]
    fn validator_pruned_snapshot_rejects_archive_node_source_role() {
        let mut signed = signed_manifest();
        signed.manifest.source_role = "ARCHIVE_NODE".to_string();

        let report = verify(&signed);

        assert!(!report.success);
        assert!(report.errors.iter().any(|error| {
            error.contains("validator-pruned")
                && error.contains("producer role must be VALIDATOR")
                && error.contains("ARCHIVE_NODE")
        }));
    }

    #[test]
    fn snapshot_accepts_archive_validator_source_role_aliases() {
        for role in [
            "ARCHIVE_VALIDATOR",
            "archive-validator",
            "archive_validator_non_consensus",
            "archive observer",
        ] {
            assert!(
                snapshot_producer_role_is_authorized(role),
                "source role {role} should be authorized"
            );
        }
    }

    #[test]
    fn snapshot_rejects_missing_runtime_checksum() {
        let mut signed = signed_manifest();
        signed.manifest.runtime_checksum.clear();
        let report = verify(&signed);
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("runtime checksum")));
    }

    #[test]
    fn snapshot_rejects_invalid_aegis_pqc_signature() {
        let mut signed = signed_manifest();
        signed.aegis_pq_signature.signature_bytes[0] ^= 0xff;
        let report = verify(&signed);
        assert!(!report.manifest_signature_verified);
        assert!(!report.success);
    }

    #[test]
    fn snapshot_file_entry_hashes_large_files_by_streaming() {
        let root = temp_root("streaming-file-entry");
        let path = root.join("chain.json");
        let mut file = fs::File::create(&path).unwrap();
        let mut expected = Sha256::new();
        let chunk_len = 1024 * 1024;
        for index in 0..8u8 {
            let chunk = vec![index; chunk_len];
            expected.update(&chunk);
            file.write_all(&chunk).unwrap();
        }
        drop(file);

        let entry = snapshot_file_entry(&path, "chain.json".to_string()).unwrap();

        assert_eq!(entry.bytes, (chunk_len * 8) as u64);
        assert_eq!(entry.sha256, hex::encode(expected.finalize()));
    }

    #[test]
    fn snapshot_preserves_no_keys_or_configs() {
        let root = temp_root("forbidden");
        fs::write(root.join("chain.json"), b"chain").unwrap();
        fs::write(root.join("validator.key"), b"secret").unwrap();
        let files = collect_snapshot_files(&root, SNAPSHOT_CLASS_ARCHIVE_FULL).unwrap();
        assert!(files
            .iter()
            .all(|entry| entry.relative_path != "validator.key"));
    }

    #[test]
    fn snapshot_restore_does_not_mutate_genesis() {
        let signed = signed_manifest();
        let verification = verify(&signed);
        let plan = build_snapshot_restore_plan(
            "validator-1",
            &signed,
            "snapshot.tar",
            Path::new("data"),
            &verification,
        )
        .unwrap();
        assert!(!plan.genesis_mutated);
    }

    #[test]
    fn snapshot_restore_does_not_mutate_quorum() {
        let signed = signed_manifest();
        let verification = verify(&signed);
        let plan = build_snapshot_restore_plan(
            "validator-1",
            &signed,
            "snapshot.tar",
            Path::new("data"),
            &verification,
        )
        .unwrap();
        assert!(!plan.quorum_mutated);
    }

    #[test]
    fn canonical_lock_conflict_triggers_self_quarantine() {
        let marker = QuarantineMarker::divergence(
            "validator-1",
            "canonical lock conflict",
            71160,
            "local",
            71160,
            "majority",
            Some("local".to_string()),
            "/evidence",
        );
        assert_eq!(marker.recovery_state, RealignmentState::Quarantined);
        assert!(marker.voting_disabled);
    }

    #[test]
    fn majority_peer_evidence_triggers_cluster_quarantine() {
        let reports = vec![
            PeerBranchEvidence {
                node_id: "validator-1".to_string(),
                role: PeerEvidenceRole::Validator,
                active_validator: true,
                height: 10,
                block_hash: "a".to_string(),
            },
            PeerBranchEvidence {
                node_id: "validator-2".to_string(),
                role: PeerEvidenceRole::Validator,
                active_validator: true,
                height: 10,
                block_hash: "a".to_string(),
            },
            PeerBranchEvidence {
                node_id: "validator-3".to_string(),
                role: PeerEvidenceRole::Validator,
                active_validator: true,
                height: 10,
                block_hash: "a".to_string(),
            },
            PeerBranchEvidence {
                node_id: "validator-4".to_string(),
                role: PeerEvidenceRole::Validator,
                active_validator: true,
                height: 10,
                block_hash: "a".to_string(),
            },
            PeerBranchEvidence {
                node_id: "rpc".to_string(),
                role: PeerEvidenceRole::RpcGateway,
                active_validator: false,
                height: 10,
                block_hash: "b".to_string(),
            },
        ];
        let proof = prove_majority_branch(&reports, baseline_required_quorum());
        assert!(proof.proven);
        assert_eq!(proof.majority_hash.as_deref(), Some("a"));
        assert_eq!(proof.ignored_support_count, 1);
    }

    #[test]
    fn quarantined_validator_does_not_vote() {
        assert!(!ValidatorDutyGate::for_state(RealignmentState::Quarantined).can_vote);
    }

    #[test]
    fn quarantined_validator_does_not_propose() {
        assert!(!ValidatorDutyGate::for_state(RealignmentState::Quarantined).can_propose);
    }

    #[test]
    fn quarantined_validator_does_not_aggregate_qc() {
        assert!(!ValidatorDutyGate::for_state(RealignmentState::Quarantined).can_aggregate_qc);
    }

    #[test]
    fn quarantined_validator_not_in_proposer_schedule() {
        assert!(
            !ValidatorDutyGate::for_state(RealignmentState::Quarantined)
                .can_enter_proposer_schedule
        );
    }

    #[test]
    fn vote_only_rejoin_votes_but_cannot_propose() {
        let gate = ValidatorDutyGate::for_state(RealignmentState::VoteOnly);
        assert!(gate.can_vote);
        assert!(gate.can_count_toward_quorum);
        assert!(!gate.can_propose);
        assert!(!gate.can_aggregate_qc);
        assert!(!gate.can_enter_proposer_schedule);
    }

    #[test]
    fn relayer_not_counted_toward_quarantine_quorum() {
        let reports = vec![
            PeerBranchEvidence {
                node_id: "validator-1".to_string(),
                role: PeerEvidenceRole::Validator,
                active_validator: true,
                height: 10,
                block_hash: "a".to_string(),
            },
            PeerBranchEvidence {
                node_id: "validator-2".to_string(),
                role: PeerEvidenceRole::Validator,
                active_validator: true,
                height: 10,
                block_hash: "a".to_string(),
            },
            PeerBranchEvidence {
                node_id: "validator-3".to_string(),
                role: PeerEvidenceRole::Validator,
                active_validator: true,
                height: 10,
                block_hash: "a".to_string(),
            },
            PeerBranchEvidence {
                node_id: "relayer-1".to_string(),
                role: PeerEvidenceRole::Relayer,
                active_validator: false,
                height: 10,
                block_hash: "a".to_string(),
            },
        ];
        assert!(!prove_majority_branch(&reports, baseline_required_quorum()).proven);
    }

    #[test]
    fn rpc_not_counted_toward_quarantine_quorum() {
        let reports = vec![
            PeerBranchEvidence {
                node_id: "validator-1".to_string(),
                role: PeerEvidenceRole::Validator,
                active_validator: true,
                height: 10,
                block_hash: "a".to_string(),
            },
            PeerBranchEvidence {
                node_id: "validator-2".to_string(),
                role: PeerEvidenceRole::Validator,
                active_validator: true,
                height: 10,
                block_hash: "a".to_string(),
            },
            PeerBranchEvidence {
                node_id: "validator-3".to_string(),
                role: PeerEvidenceRole::Validator,
                active_validator: true,
                height: 10,
                block_hash: "a".to_string(),
            },
            PeerBranchEvidence {
                node_id: "rpc".to_string(),
                role: PeerEvidenceRole::RpcGateway,
                active_validator: false,
                height: 10,
                block_hash: "a".to_string(),
            },
        ];
        assert!(!prove_majority_branch(&reports, baseline_required_quorum()).proven);
    }

    #[test]
    fn divergent_validator_wipes_only_chain_data() {
        let root = temp_root("wipe-only");
        fs::write(root.join("chain.json"), b"chain").unwrap();
        fs::write(root.join("validator.key"), b"secret").unwrap();
        let plan =
            build_chain_state_wipe_plan("validator-1", &root, &root.join("evidence")).unwrap();
        assert!(plan
            .files_to_wipe
            .iter()
            .any(|path| path.ends_with("chain.json")));
        assert!(!plan
            .files_to_wipe
            .iter()
            .any(|path| path.ends_with("validator.key")));
    }

    #[test]
    fn divergent_validator_keeps_own_keys() {
        let plan = build_chain_state_wipe_plan("validator-1", &state_dir(), &temp_root("evidence"))
            .unwrap();
        assert!(!plan.keys_or_configs_copied);
    }

    #[test]
    fn divergent_validator_keeps_own_config() {
        let plan = build_chain_state_wipe_plan("validator-1", &state_dir(), &temp_root("evidence"))
            .unwrap();
        assert!(!plan
            .files_to_wipe
            .iter()
            .any(|path| path.contains("config")));
    }

    #[test]
    fn self_heal_restores_verified_snapshot() {
        let signed = signed_manifest();
        let verification = verify(&signed);
        assert!(build_snapshot_restore_plan(
            "validator-1",
            &signed,
            "snapshot.tar",
            Path::new("data"),
            &verification
        )
        .is_ok());
    }

    #[test]
    fn self_heal_rejects_unverified_snapshot() {
        let mut signed = signed_manifest();
        signed.manifest.qc_evidence.aegis_pqc_verified = false;
        let verification = verify(&signed);
        assert!(build_snapshot_restore_plan(
            "validator-1",
            &signed,
            "snapshot.tar",
            Path::new("data"),
            &verification
        )
        .is_err());
    }

    #[test]
    fn self_heal_speed_sync_rejects_wrong_chain_peer() {
        let mut peer = good_peer();
        peer.chain_id = 1263;
        assert!(validate_speed_sync_peer(&peer, 1, &SpeedSyncPolicy::default()).is_err());
    }

    #[test]
    fn self_heal_speed_sync_rejects_minority_peer() {
        let mut peer = good_peer();
        peer.quarantined = true;
        assert!(validate_speed_sync_peer(&peer, 1, &SpeedSyncPolicy::default()).is_err());
    }

    #[test]
    fn self_heal_rejoin_requires_common_height_match() {
        let mut input = eligible_rejoin_input();
        input.exact_common_height_match = false;
        assert!(!evaluate_rejoin_eligibility(input).eligible);
    }

    #[test]
    fn shadow_validator_signs_no_real_votes() {
        assert!(
            !ValidatorDutyGate::for_state(RealignmentState::ShadowObserving)
                .shadow_signs_real_votes
        );
    }

    #[test]
    fn shadow_validator_records_would_have_voted() {
        let mut shadow = ShadowObservation::new("validator-1", 1);
        shadow.record(ShadowDecisionRecord {
            height: 1,
            canonical_hash: "a".to_string(),
            would_have_voted_hash: Some("a".to_string()),
            would_have_proposed_hash: None,
            state_root_matches: true,
            rejected_valid_majority_block: false,
            accepted_conflicting_block: false,
        });
        assert_eq!(shadow.records.len(), 1);
    }

    #[test]
    fn shadow_fails_on_would_have_voted_conflict() {
        let mut shadow = ShadowObservation::new("validator-1", 1);
        shadow.record(ShadowDecisionRecord {
            height: 1,
            canonical_hash: "a".to_string(),
            would_have_voted_hash: Some("b".to_string()),
            would_have_proposed_hash: None,
            state_root_matches: true,
            rejected_valid_majority_block: false,
            accepted_conflicting_block: false,
        });
        assert_eq!(shadow.evaluate().state, RealignmentState::Quarantined);
    }

    #[test]
    fn shadow_fails_on_state_root_mismatch() {
        let mut shadow = ShadowObservation::new("validator-1", 1);
        shadow.record(ShadowDecisionRecord {
            height: 1,
            canonical_hash: "a".to_string(),
            would_have_voted_hash: Some("a".to_string()),
            would_have_proposed_hash: None,
            state_root_matches: false,
            rejected_valid_majority_block: false,
            accepted_conflicting_block: false,
        });
        assert_eq!(shadow.evaluate().state, RealignmentState::Quarantined);
    }

    #[test]
    fn shadow_passes_after_epoch_of_matching_blocks() {
        let mut shadow = ShadowObservation::new("validator-1", 2);
        for height in 1..=2 {
            shadow.record(ShadowDecisionRecord {
                height,
                canonical_hash: format!("h{height}"),
                would_have_voted_hash: Some(format!("h{height}")),
                would_have_proposed_hash: None,
                state_root_matches: true,
                rejected_valid_majority_block: false,
                accepted_conflicting_block: false,
            });
        }
        assert_eq!(shadow.evaluate().state, RealignmentState::ShadowPassed);
    }

    #[test]
    fn rejoin_requires_shadow_pass() {
        let mut input = eligible_rejoin_input();
        input.shadow_passed = false;
        input.exact_common_height_match = false;
        assert!(!evaluate_rejoin_eligibility(input).eligible);
    }

    #[test]
    fn rejoin_only_at_finalized_boundary() {
        let mut input = eligible_rejoin_input();
        input.rejoin_at_finalized_safe_boundary = false;
        assert!(!evaluate_rejoin_eligibility(input).eligible);
    }

    #[test]
    fn validator_quorum_continues_when_one_quarantined() {
        let proof_reports = (1..=4)
            .map(|index| PeerBranchEvidence {
                node_id: format!("validator-{index}"),
                role: PeerEvidenceRole::Validator,
                active_validator: true,
                height: 99,
                block_hash: "majority".to_string(),
            })
            .collect::<Vec<_>>();
        assert!(prove_majority_branch(&proof_reports, baseline_required_quorum()).proven);
    }

    #[test]
    fn divergent_validator_quarantined_does_not_reduce_dynamic_genesis_quorum() {
        assert!(
            ValidatorDutyGate::for_state(RealignmentState::Quarantined).can_count_toward_quorum
                == false
        );
        assert!(BASELINE_VALIDATOR_COUNT - 1 >= baseline_required_quorum());
    }

    #[test]
    fn recovered_validator_rejoins_without_split() {
        let report = evaluate_rejoin_eligibility(eligible_rejoin_input());
        assert!(report.eligible);
        assert_eq!(report.new_state, RealignmentState::VoteOnly);
    }

    #[test]
    fn repeated_divergence_does_not_require_manual_state_surgery() {
        let mut lifecycle = RealignmentLifecycle::new_active("validator-1");
        for state in [
            RealignmentState::Suspect,
            RealignmentState::Quarantined,
            RealignmentState::EvidencePreserved,
            RealignmentState::ChainDataWipeReady,
            RealignmentState::ChainDataWiped,
            RealignmentState::SnapshotDiscovery,
            RealignmentState::SnapshotVerified,
            RealignmentState::SnapshotRestored,
            RealignmentState::SpeedSyncing,
            RealignmentState::CaughtUp,
            RealignmentState::ShadowObserving,
            RealignmentState::ShadowPassed,
            RealignmentState::ReadyToRejoin,
            RealignmentState::PendingReactivation,
            RealignmentState::Active,
        ] {
            lifecycle.transition(state).unwrap();
        }
        assert_eq!(lifecycle.state, RealignmentState::Active);
    }

    #[test]
    fn quorum_threshold_follows_dynamic_policy() {
        assert_eq!(
            baseline_required_quorum(),
            required_validator_quorum(BASELINE_VALIDATOR_COUNT)
        );
        assert_eq!(required_snapshot_quorum_for_validator_count(6), 5);
        assert_eq!(required_snapshot_quorum_for_validator_count(7), 5);
        assert_eq!(required_snapshot_quorum_for_validator_count(10), 7);
        assert_eq!(required_snapshot_quorum_for_validator_count(13), 9);
    }

    #[test]
    fn shadow_validator_not_counted() {
        let reports = vec![
            PeerBranchEvidence {
                node_id: "validator-1".to_string(),
                role: PeerEvidenceRole::Validator,
                active_validator: true,
                height: 10,
                block_hash: "a".to_string(),
            },
            PeerBranchEvidence {
                node_id: "validator-2".to_string(),
                role: PeerEvidenceRole::Validator,
                active_validator: true,
                height: 10,
                block_hash: "a".to_string(),
            },
            PeerBranchEvidence {
                node_id: "validator-3".to_string(),
                role: PeerEvidenceRole::Validator,
                active_validator: true,
                height: 10,
                block_hash: "a".to_string(),
            },
            PeerBranchEvidence {
                node_id: "new-validator".to_string(),
                role: PeerEvidenceRole::ShadowValidator,
                active_validator: false,
                height: 10,
                block_hash: "a".to_string(),
            },
        ];
        assert!(!prove_majority_branch(&reports, baseline_required_quorum()).proven);
    }

    #[test]
    fn diagnose_divergence_matches_direct_state() {
        let reports = vec![
            PeerBranchEvidence {
                node_id: "validator-1".to_string(),
                role: PeerEvidenceRole::Validator,
                active_validator: true,
                height: 10,
                block_hash: "a".to_string(),
            },
            PeerBranchEvidence {
                node_id: "validator-2".to_string(),
                role: PeerEvidenceRole::Validator,
                active_validator: true,
                height: 10,
                block_hash: "a".to_string(),
            },
            PeerBranchEvidence {
                node_id: "validator-3".to_string(),
                role: PeerEvidenceRole::Validator,
                active_validator: true,
                height: 10,
                block_hash: "a".to_string(),
            },
            PeerBranchEvidence {
                node_id: "validator-4".to_string(),
                role: PeerEvidenceRole::Validator,
                active_validator: true,
                height: 10,
                block_hash: "a".to_string(),
            },
        ];
        let proof = prove_majority_branch(&reports, baseline_required_quorum());
        assert_eq!(proof.majority_hash.as_deref(), Some("a"));
    }

    #[test]
    fn diagnose_quarantine_returns_typed_body() {
        let marker = QuarantineMarker::divergence(
            "validator-1",
            "conflict",
            1,
            "local",
            1,
            "majority",
            Some("local".to_string()),
            "/evidence",
        );
        let value = serde_json::to_value(marker).unwrap();
        assert!(value.get("recovery_state").is_some());
    }

    #[test]
    fn self_heal_status_returns_typed_body() {
        let response = fail_closed_mutation_response(
            "validator-1",
            RealignmentState::Quarantined,
            "missing verified snapshot",
            "/evidence",
        );
        assert_eq!(response.typed_status, "FAILED_CLOSED");
    }

    #[test]
    fn failed_snapshot_verify_returns_reason() {
        let mut signed = signed_manifest();
        signed.manifest.qc_evidence.vote_count = 3;
        let report = verify(&signed);
        assert!(!report.errors.is_empty());
    }

    #[test]
    fn mutation_response_includes_safety_flags() {
        let response = fail_closed_mutation_response(
            "validator-1",
            RealignmentState::Quarantined,
            "missing verified snapshot",
            "/evidence",
        );
        assert!(!response.keys_or_configs_copied);
        assert!(!response.genesis_mutated);
        assert!(!response.quorum_mutated);
    }

    fn good_peer() -> CanonicalPeerStatus {
        CanonicalPeerStatus {
            peer_id: "validator-2".to_string(),
            chain_id: SYNERGY_TESTNET_V3_CHAIN_ID,
            network_id: SYNERGY_TESTNET_V3_NETWORK_ID.to_string(),
            genesis_hash: expected_genesis_hash(),
            height: 10,
            block_hash: "hash".to_string(),
            quarantined: false,
            qc_aegis_pqc_verified: true,
            parent_continuity_verified: true,
            state_root_matches: true,
        }
    }

    fn eligible_rejoin_input() -> RejoinEligibilityInput {
        RejoinEligibilityInput {
            validator_id: "validator-1".to_string(),
            state: RealignmentState::ReadyToRejoin,
            shadow_passed: true,
            exact_common_height_match: true,
            latest_finalized_qc_aegis_pqc_verified: true,
            no_stale_vote_locks_above_finalized: true,
            no_proposal_cache_conflicts_above_finalized: true,
            quarantine_reason_cleared: true,
            chain_id: SYNERGY_TESTNET_V3_CHAIN_ID,
            network_id: SYNERGY_TESTNET_V3_NETWORK_ID.to_string(),
            genesis_hash: expected_genesis_hash(),
            state_root_matches: true,
            own_validator_key_intact: true,
            keys_or_configs_copied: false,
            rejoin_at_finalized_safe_boundary: true,
            cluster_marks_pending_reactivation: true,
        }
    }
}
