use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const VALIDATOR_OPERATIONS_SCHEMA_VERSION: &str = "synergy.validator-operations.v1";
pub const VALIDATOR_OPERATIONS_SNAPSHOT_RELATIVE_PATH: &str =
    "data/operations/validator-operations-v1.json";
pub const MAX_VALIDATOR_OPERATIONS_SNAPSHOT_BYTES: u64 = 1024 * 1024;
pub const DEFAULT_MAX_SYNC_GAP: u64 = 1;
pub const DEFAULT_FINALITY_STALL_AFTER_MS: u64 = 30_000;
pub const REQUIRED_HOST_PREFLIGHT_CHECK_IDS: &[&str] = &[
    "genesis_hash",
    "chain_id",
    "network",
    "release_id",
    "release_tag",
    "binary_sha256",
    "core_revision",
    "synq_revision",
    "aegis_revision",
    "validator_config",
    "key_binding",
    "validator_registry",
    "protected_pipeline_config",
    "etdag_roots",
    "vpn_reachability",
    "peer_readiness",
    "storage",
    "clock_sync",
];

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ServiceState {
    Active,
    Activating,
    Inactive,
    Failed,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProgressState {
    Advancing,
    Stable,
    Stalled,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CertificateStatus {
    Missing,
    Collecting,
    Formed,
    Rejected,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProtectedPipelineSource {
    GenesisBootstrap,
    NormalEtdag,
    NormalEtdagSteadyState,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProtectedPipelinePhase {
    GenesisBootstrap,
    Collecting,
    CutoffReady,
    CutReady,
    OrderReady,
    CommittedInParent,
    RevealAuthorized,
    Revealing,
    ReadyForExecution,
    Consumed,
    Failed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PreflightCheckStatus {
    Pass,
    Fail,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ValidatorHealthClass {
    Healthy,
    Syncing,
    Degraded,
    Stalled,
    Offline,
    Misconfigured,
    ReleaseMismatch,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ValidatorLifecycleAction {
    Start,
    Stop,
    Restart,
}

impl ValidatorLifecycleAction {
    pub fn as_nodectl_action(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Restart => "restart",
        }
    }

    pub fn requires_preflight(self) -> bool {
        !matches!(self, Self::Stop)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StructuredLogSeverity {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Critical,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StructuredLogSubsystem {
    Service,
    Network,
    Consensus,
    Finality,
    Posy,
    ProtectedPipeline,
    Storage,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ValidatorDiscovery {
    pub validator_id: String,
    pub hostname: String,
    pub chain_id: String,
    pub network: String,
    pub incarnation: String,
    pub validator_public_key_fingerprint: String,
    pub consensus_public_key_fingerprint: String,
    pub ingress_public_key_fingerprint: String,
    pub key_binding_status: String,
    pub vpn_address: String,
    pub p2p_address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rpc_address: Option<String>,
    pub management_address: String,
    pub data_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseIdentity {
    pub release_id: String,
    pub release_tag: String,
    pub binary_sha256: String,
    pub core_revision: String,
    pub synq_revision: String,
    pub aegis_revision: String,
    pub genesis_hash: String,
    pub protocol_version: String,
    pub protected_pipeline_version: String,
    pub validator_config_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ValidatorServiceStatus {
    pub state: ServiceState,
    pub unit_identity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_id: Option<u32>,
    pub uptime_seconds: u64,
    pub restart_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ValidatorPeerStatus {
    pub p2p_listener_ready: bool,
    pub connected_peer_count: u32,
    pub authenticated_validator_peer_count: u32,
    pub expected_validator_peer_count: u32,
    pub peer_quorum_threshold: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ValidatorChainStatus {
    pub head_height: u64,
    pub finalized_height: u64,
    pub head_progress: ProgressState,
    pub finality_progress: ProgressState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_finalized_at_utc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub millis_since_last_finalized: Option<u64>,
    pub sync_target_height: u64,
    pub quorum_available: bool,
    pub divergence_detected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PosyStatus {
    pub current_height: u64,
    pub finalized_height: u64,
    pub current_view: u64,
    pub expected_proposer: String,
    pub proposal_seen: bool,
    pub validation_votes: u32,
    pub validation_votes_required: u32,
    pub vc_status: CertificateStatus,
    pub finality_votes: u32,
    pub finality_votes_required: u32,
    pub qc_status: CertificateStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_finalized_at_utc: Option<String>,
    pub view_change_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProtectedPipelineStatus {
    pub target_height: u64,
    pub source: ProtectedPipelineSource,
    pub phase: ProtectedPipelinePhase,
    pub availability_count: u32,
    pub availability_required: u32,
    pub cutoff_marker_count: u32,
    pub cutoff_markers_required: u32,
    pub cut_ready: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cut_root: Option<String>,
    pub order_ready: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protected_batch_root: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_commitment: Option<String>,
    pub reveal_authorized: bool,
    pub reveal_share_count: u32,
    pub reveal_shares_required: u32,
    pub execution_ready: bool,
    pub consumed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ValidatorResourceStatus {
    pub cpu_percent: f64,
    pub memory_bytes: u64,
    pub memory_percent: f64,
    pub disk_used_percent: f64,
    pub network_rx_bytes_per_second: u64,
    pub network_tx_bytes_per_second: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ValidatorPreflightCheck {
    pub id: String,
    pub status: PreflightCheckStatus,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostPreflightStatus {
    pub schema_version: String,
    pub validator_id: String,
    pub generated_at_utc: String,
    pub ready: bool,
    pub required_check_ids: Vec<String>,
    pub checks: Vec<ValidatorPreflightCheck>,
    pub blocking_check_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ValidatorLifecycleRequest {
    pub action: ValidatorLifecycleAction,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorLifecycleResult {
    pub schema_version: String,
    pub validator_id: String,
    pub action: ValidatorLifecycleAction,
    pub accepted: bool,
    pub exit_code: i32,
    pub executed_at_utc: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StructuredLogEntry {
    pub sequence: u64,
    pub observed_at_utc: String,
    pub severity: StructuredLogSeverity,
    pub subsystem: StructuredLogSubsystem,
    pub message: String,
    pub redacted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StructuredLogsResponse {
    pub schema_version: String,
    pub validator_id: String,
    pub generated_at_utc: String,
    pub entries: Vec<StructuredLogEntry>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiagnosticSnapshot {
    pub schema_version: String,
    pub snapshot_id: String,
    pub captured_at_utc: String,
    pub validator_id: String,
    pub status: ValidatorOperationsStatus,
    pub preflight: HostPreflightStatus,
    pub logs: StructuredLogsResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiagnosticSnapshotResult {
    pub schema_version: String,
    pub snapshot_id: String,
    pub validator_id: String,
    pub captured_at_utc: String,
    pub relative_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ValidatorOperationsObservation {
    pub schema_version: String,
    pub observed_at_utc: String,
    pub discovery: ValidatorDiscovery,
    pub release: ReleaseIdentity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_release: Option<ReleaseIdentity>,
    pub service: ValidatorServiceStatus,
    pub peers: ValidatorPeerStatus,
    pub chain: ValidatorChainStatus,
    pub posy: PosyStatus,
    pub protected_pipeline: ProtectedPipelineStatus,
    pub resources: ValidatorResourceStatus,
    #[serde(default)]
    pub preflight: Vec<ValidatorPreflightCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseMismatchField {
    pub field: String,
    pub expected: String,
    pub actual: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseConsistencyStatus {
    pub matches_expected: bool,
    pub mismatch_fields: Vec<ReleaseMismatchField>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorHealth {
    pub classification: ValidatorHealthClass,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MissingTransition {
    pub from: String,
    pub to: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LivenessDiagnosis {
    pub health: ValidatorHealthClass,
    pub height: u64,
    pub finalized_height: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_missing_transition: Option<MissingTransition>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ValidatorOperationsStatus {
    pub schema_version: String,
    pub generated_at_utc: String,
    pub discovery: ValidatorDiscovery,
    pub release: ReleaseIdentity,
    pub release_consistency: ReleaseConsistencyStatus,
    pub service: ValidatorServiceStatus,
    pub peers: ValidatorPeerStatus,
    pub chain: ValidatorChainStatus,
    pub posy: PosyStatus,
    pub protected_pipeline: ProtectedPipelineStatus,
    pub resources: ValidatorResourceStatus,
    pub preflight: Vec<ValidatorPreflightCheck>,
    pub health: ValidatorHealth,
    pub liveness: LivenessDiagnosis,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClusterReleaseConsistency {
    pub consistent: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_validator_id: Option<String>,
    pub mismatched_validator_ids: Vec<String>,
    pub mismatched_fields_by_validator: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ValidatorOperationsClusterStatus {
    pub schema_version: String,
    pub generated_at_utc: String,
    pub validators: Vec<ValidatorOperationsStatus>,
    pub unavailable_validator_ids: Vec<String>,
    pub release_consistency: ClusterReleaseConsistency,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub common_head_height: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub common_finalized_height: Option<u64>,
    pub quorum_available: bool,
    pub divergence_detected: bool,
}

pub fn evaluate_validator_operations(
    observation: ValidatorOperationsObservation,
) -> ValidatorOperationsStatus {
    let release_consistency =
        compare_release_identity(observation.expected_release.as_ref(), &observation.release);
    let health = evaluate_health(&observation, &release_consistency);
    let liveness = LivenessDiagnosis {
        health: health.classification,
        height: observation.posy.current_height,
        finalized_height: observation.posy.finalized_height,
        first_missing_transition: diagnose_first_missing_transition(&observation),
    };

    ValidatorOperationsStatus {
        schema_version: VALIDATOR_OPERATIONS_SCHEMA_VERSION.to_string(),
        generated_at_utc: observation.observed_at_utc,
        discovery: observation.discovery,
        release: observation.release,
        release_consistency,
        service: observation.service,
        peers: observation.peers,
        chain: observation.chain,
        posy: observation.posy,
        protected_pipeline: observation.protected_pipeline,
        resources: observation.resources,
        preflight: observation.preflight,
        health,
        liveness,
    }
}

pub fn evaluate_host_preflight(status: &ValidatorOperationsStatus) -> HostPreflightStatus {
    let by_id = status
        .preflight
        .iter()
        .map(|check| (check.id.as_str(), check.status))
        .collect::<BTreeMap<_, _>>();
    let mut blocking_check_ids = REQUIRED_HOST_PREFLIGHT_CHECK_IDS
        .iter()
        .filter(|id| by_id.get(**id) != Some(&PreflightCheckStatus::Pass))
        .map(|id| (*id).to_string())
        .collect::<Vec<_>>();
    if !status.release_consistency.matches_expected {
        blocking_check_ids.push("release_consistency".to_string());
    }
    blocking_check_ids.sort();
    blocking_check_ids.dedup();

    HostPreflightStatus {
        schema_version: VALIDATOR_OPERATIONS_SCHEMA_VERSION.to_string(),
        validator_id: status.discovery.validator_id.clone(),
        generated_at_utc: status.generated_at_utc.clone(),
        ready: blocking_check_ids.is_empty(),
        required_check_ids: REQUIRED_HOST_PREFLIGHT_CHECK_IDS
            .iter()
            .map(|id| (*id).to_string())
            .collect(),
        checks: status.preflight.clone(),
        blocking_check_ids,
    }
}

pub fn evaluate_validator_cluster(
    observations: Vec<ValidatorOperationsObservation>,
    unavailable_validator_ids: Vec<String>,
) -> ValidatorOperationsClusterStatus {
    let validators = observations
        .into_iter()
        .map(evaluate_validator_operations)
        .collect::<Vec<_>>();
    aggregate_validator_statuses(validators, unavailable_validator_ids)
}

pub fn aggregate_validator_statuses(
    mut validators: Vec<ValidatorOperationsStatus>,
    mut unavailable_validator_ids: Vec<String>,
) -> ValidatorOperationsClusterStatus {
    validators.sort_by(|left, right| {
        left.discovery
            .validator_id
            .cmp(&right.discovery.validator_id)
    });
    unavailable_validator_ids.sort();
    unavailable_validator_ids.dedup();

    let release_consistency = evaluate_cluster_release_consistency(&validators);
    if !release_consistency.consistent {
        for validator in &mut validators {
            validator.health = ValidatorHealth {
                classification: ValidatorHealthClass::ReleaseMismatch,
                reasons: vec![
                    "Validator release identity diverges from another discovered validator."
                        .to_string(),
                ],
            };
            validator.liveness.health = ValidatorHealthClass::ReleaseMismatch;
        }
    }

    let common_head_height = unavailable_validator_ids
        .is_empty()
        .then(|| common_value(validators.iter().map(|entry| entry.chain.head_height)))
        .flatten();
    let common_finalized_height = unavailable_validator_ids
        .is_empty()
        .then(|| common_value(validators.iter().map(|entry| entry.chain.finalized_height)))
        .flatten();
    let quorum_available =
        !validators.is_empty() && validators.iter().all(|entry| entry.chain.quorum_available);
    let divergence_detected = common_head_height.is_none()
        || common_finalized_height.is_none()
        || validators
            .iter()
            .any(|entry| entry.chain.divergence_detected)
        || !release_consistency.consistent;
    let generated_at_utc = validators
        .iter()
        .map(|entry| entry.generated_at_utc.as_str())
        .max()
        .unwrap_or_default()
        .to_string();

    ValidatorOperationsClusterStatus {
        schema_version: VALIDATOR_OPERATIONS_SCHEMA_VERSION.to_string(),
        generated_at_utc,
        validators,
        unavailable_validator_ids,
        release_consistency,
        common_head_height,
        common_finalized_height,
        quorum_available,
        divergence_detected,
    }
}

pub fn validate_observation(
    observation: &ValidatorOperationsObservation,
    expected_validator_id: Option<&str>,
) -> Result<(), String> {
    if observation.schema_version != VALIDATOR_OPERATIONS_SCHEMA_VERSION {
        return Err(format!(
            "Unsupported validator operations schema version: {}",
            observation.schema_version
        ));
    }
    if observation.discovery.validator_id.trim().is_empty() {
        return Err("validator_id is required".to_string());
    }
    if let Some(expected_validator_id) = expected_validator_id {
        if observation.discovery.validator_id != expected_validator_id {
            return Err(format!(
                "Validator operations snapshot identity mismatch: expected {expected_validator_id}, observed {}",
                observation.discovery.validator_id
            ));
        }
    }
    if observation.discovery.chain_id.trim().is_empty()
        || observation.discovery.network.trim().is_empty()
        || observation.discovery.incarnation.trim().is_empty()
    {
        return Err("chain_id, network, and incarnation are required".to_string());
    }
    validate_release_identity(&observation.release)?;
    if let Some(expected_release) = observation.expected_release.as_ref() {
        validate_release_identity(expected_release)?;
    }
    if observation.chain.finalized_height > observation.chain.head_height {
        return Err("finalized_height cannot exceed head_height".to_string());
    }
    if observation.posy.finalized_height > observation.posy.current_height {
        return Err("PoSy finalized_height cannot exceed current_height".to_string());
    }
    let pipeline = &observation.protected_pipeline;
    if pipeline.cut_ready
        && pipeline
            .cut_root
            .as_deref()
            .map(str::trim)
            .is_none_or(str::is_empty)
    {
        return Err("cut_ready requires a non-empty cut_root".to_string());
    }
    if pipeline.order_ready
        && pipeline
            .protected_batch_root
            .as_deref()
            .map(str::trim)
            .is_none_or(str::is_empty)
    {
        return Err("order_ready requires a non-empty protected_batch_root".to_string());
    }
    if pipeline
        .parent_commitment
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err("parent_commitment cannot be empty".to_string());
    }
    if pipeline.reveal_authorized && pipeline.parent_commitment.is_none() {
        return Err("reveal_authorized requires a parent_commitment".to_string());
    }
    if is_normal_etdag_source(pipeline.source)
        && pipeline.execution_ready
        && !pipeline.reveal_authorized
    {
        return Err("normal ETDAG execution_ready requires reveal authorization".to_string());
    }
    if pipeline.consumed && !pipeline.execution_ready {
        return Err("consumed requires execution_ready".to_string());
    }
    if observation.protected_pipeline.target_height
        > observation.posy.current_height.saturating_add(2)
    {
        return Err(
            "ProtectedPipeline target_height is outside the supported look-ahead window"
                .to_string(),
        );
    }
    validate_threshold(
        "validation votes",
        observation.posy.validation_votes,
        observation.posy.validation_votes_required,
    )?;
    validate_threshold(
        "finality votes",
        observation.posy.finality_votes,
        observation.posy.finality_votes_required,
    )?;
    if is_normal_etdag_source(observation.protected_pipeline.source) {
        validate_threshold(
            "availability evidence",
            observation.protected_pipeline.availability_count,
            observation.protected_pipeline.availability_required,
        )?;
        validate_threshold(
            "cutoff markers",
            observation.protected_pipeline.cutoff_marker_count,
            observation.protected_pipeline.cutoff_markers_required,
        )?;
        validate_threshold(
            "reveal shares",
            observation.protected_pipeline.reveal_share_count,
            observation.protected_pipeline.reveal_shares_required,
        )?;
    }
    for (label, value) in [
        ("cpu_percent", observation.resources.cpu_percent),
        ("memory_percent", observation.resources.memory_percent),
        ("disk_used_percent", observation.resources.disk_used_percent),
    ] {
        if !(0.0..=100.0).contains(&value) {
            return Err(format!("{label} must be within 0..=100"));
        }
    }
    Ok(())
}

fn validate_threshold(label: &str, observed: u32, required: u32) -> Result<(), String> {
    if required == 0 {
        return Err(format!(
            "{label} required threshold must be greater than zero"
        ));
    }
    if observed > required.saturating_mul(2) {
        return Err(format!("{label} count is outside the bounded schema range"));
    }
    Ok(())
}

fn validate_release_identity(release: &ReleaseIdentity) -> Result<(), String> {
    for (label, value) in [
        ("release_id", release.release_id.as_str()),
        ("release_tag", release.release_tag.as_str()),
        ("core_revision", release.core_revision.as_str()),
        ("synq_revision", release.synq_revision.as_str()),
        ("aegis_revision", release.aegis_revision.as_str()),
        ("genesis_hash", release.genesis_hash.as_str()),
        ("protocol_version", release.protocol_version.as_str()),
        (
            "protected_pipeline_version",
            release.protected_pipeline_version.as_str(),
        ),
        (
            "validator_config_version",
            release.validator_config_version.as_str(),
        ),
    ] {
        if value.trim().is_empty() {
            return Err(format!("{label} is required"));
        }
    }
    if !is_sha256(&release.binary_sha256) {
        return Err("binary_sha256 must contain exactly 64 hexadecimal characters".to_string());
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn compare_release_identity(
    expected: Option<&ReleaseIdentity>,
    actual: &ReleaseIdentity,
) -> ReleaseConsistencyStatus {
    let Some(expected) = expected else {
        return ReleaseConsistencyStatus {
            matches_expected: true,
            mismatch_fields: Vec::new(),
        };
    };

    let mut mismatch_fields = Vec::new();
    compare_release_field(
        &mut mismatch_fields,
        "release_id",
        &expected.release_id,
        &actual.release_id,
    );
    compare_release_field(
        &mut mismatch_fields,
        "release_tag",
        &expected.release_tag,
        &actual.release_tag,
    );
    compare_release_field(
        &mut mismatch_fields,
        "binary_sha256",
        &expected.binary_sha256,
        &actual.binary_sha256,
    );
    compare_release_field(
        &mut mismatch_fields,
        "core_revision",
        &expected.core_revision,
        &actual.core_revision,
    );
    compare_release_field(
        &mut mismatch_fields,
        "synq_revision",
        &expected.synq_revision,
        &actual.synq_revision,
    );
    compare_release_field(
        &mut mismatch_fields,
        "aegis_revision",
        &expected.aegis_revision,
        &actual.aegis_revision,
    );
    compare_release_field(
        &mut mismatch_fields,
        "genesis_hash",
        &expected.genesis_hash,
        &actual.genesis_hash,
    );
    compare_release_field(
        &mut mismatch_fields,
        "protocol_version",
        &expected.protocol_version,
        &actual.protocol_version,
    );
    compare_release_field(
        &mut mismatch_fields,
        "protected_pipeline_version",
        &expected.protected_pipeline_version,
        &actual.protected_pipeline_version,
    );
    compare_release_field(
        &mut mismatch_fields,
        "validator_config_version",
        &expected.validator_config_version,
        &actual.validator_config_version,
    );

    ReleaseConsistencyStatus {
        matches_expected: mismatch_fields.is_empty(),
        mismatch_fields,
    }
}

fn compare_release_field(
    output: &mut Vec<ReleaseMismatchField>,
    field: &str,
    expected: &str,
    actual: &str,
) {
    if expected != actual {
        output.push(ReleaseMismatchField {
            field: field.to_string(),
            expected: expected.to_string(),
            actual: actual.to_string(),
        });
    }
}

fn evaluate_health(
    observation: &ValidatorOperationsObservation,
    release_consistency: &ReleaseConsistencyStatus,
) -> ValidatorHealth {
    let failed_preflight = observation
        .preflight
        .iter()
        .filter(|check| check.status == PreflightCheckStatus::Fail)
        .map(|check| check.id.clone())
        .collect::<Vec<_>>();
    if !failed_preflight.is_empty() {
        return ValidatorHealth {
            classification: ValidatorHealthClass::Misconfigured,
            reasons: vec![format!(
                "Validator preflight failed: {}.",
                failed_preflight.join(", ")
            )],
        };
    }
    if !release_consistency.matches_expected {
        return ValidatorHealth {
            classification: ValidatorHealthClass::ReleaseMismatch,
            reasons: vec![format!(
                "Release mismatch in fields: {}.",
                release_consistency
                    .mismatch_fields
                    .iter()
                    .map(|entry| entry.field.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )],
        };
    }
    if observation.service.state != ServiceState::Active {
        return ValidatorHealth {
            classification: ValidatorHealthClass::Offline,
            reasons: vec![format!(
                "Validator service state is {:?}.",
                observation.service.state
            )],
        };
    }
    if observation.chain.divergence_detected
        || observation.chain.finality_progress == ProgressState::Stalled
        || observation
            .chain
            .millis_since_last_finalized
            .is_some_and(|age| age >= DEFAULT_FINALITY_STALL_AFTER_MS)
        || observation.posy.vc_status == CertificateStatus::Rejected
        || observation.posy.qc_status == CertificateStatus::Rejected
        || observation.protected_pipeline.phase == ProtectedPipelinePhase::Failed
    {
        return ValidatorHealth {
            classification: ValidatorHealthClass::Stalled,
            reasons: vec![stalled_health_reason(observation)],
        };
    }

    let sync_gap = observation
        .chain
        .sync_target_height
        .saturating_sub(observation.chain.head_height);
    if sync_gap > DEFAULT_MAX_SYNC_GAP {
        return ValidatorHealth {
            classification: ValidatorHealthClass::Syncing,
            reasons: vec![format!(
                "Validator is {sync_gap} blocks behind its sync target."
            )],
        };
    }

    let mut degraded = Vec::new();
    if !observation.peers.p2p_listener_ready {
        degraded.push("P2P listener is not ready.".to_string());
    }
    if observation.peers.authenticated_validator_peer_count
        < observation.peers.peer_quorum_threshold
    {
        degraded.push(format!(
            "Authenticated validator peers {}/{} are below quorum.",
            observation.peers.authenticated_validator_peer_count,
            observation.peers.peer_quorum_threshold
        ));
    }
    if !observation.chain.quorum_available {
        degraded.push("Consensus quorum is not available.".to_string());
    }
    if matches!(
        observation.chain.head_progress,
        ProgressState::Stable | ProgressState::Unknown
    ) {
        degraded.push("Head advancement is not confirmed.".to_string());
    }
    if observation.chain.finality_progress == ProgressState::Unknown {
        degraded.push("Finality advancement is not confirmed.".to_string());
    }

    if degraded.is_empty() {
        ValidatorHealth {
            classification: ValidatorHealthClass::Healthy,
            reasons: vec![
                "Service, peers, head, finality, release, and ProtectedPipeline are healthy."
                    .to_string(),
            ],
        }
    } else {
        ValidatorHealth {
            classification: ValidatorHealthClass::Degraded,
            reasons: degraded,
        }
    }
}

fn stalled_health_reason(observation: &ValidatorOperationsObservation) -> String {
    if observation.chain.divergence_detected {
        return "Consensus divergence was detected.".to_string();
    }
    if observation.protected_pipeline.phase == ProtectedPipelinePhase::Failed {
        return "ProtectedPipeline entered FAILED phase.".to_string();
    }
    if observation.posy.vc_status == CertificateStatus::Rejected {
        return "PoSy validation certificate was rejected.".to_string();
    }
    if observation.posy.qc_status == CertificateStatus::Rejected {
        return "PoSy quorum certificate was rejected.".to_string();
    }
    "Finality is stalled beyond the configured deterministic threshold.".to_string()
}

pub fn diagnose_first_missing_transition(
    observation: &ValidatorOperationsObservation,
) -> Option<MissingTransition> {
    if observation.service.state != ServiceState::Active {
        return Some(missing_transition(
            "SERVICE.START_REQUESTED",
            "SERVICE.ACTIVE",
            format!("service state is {:?}", observation.service.state),
        ));
    }
    if !observation.peers.p2p_listener_ready {
        return Some(missing_transition(
            "P2P.CONFIGURED",
            "P2P.LISTENING",
            "P2P listener is not ready".to_string(),
        ));
    }
    if observation.peers.authenticated_validator_peer_count
        < observation.peers.peer_quorum_threshold
    {
        return Some(missing_transition(
            "P2P.LISTENING",
            "P2P.VALIDATOR_QUORUM",
            format!(
                "authenticated validator peers {}/{}",
                observation.peers.authenticated_validator_peer_count,
                observation.peers.peer_quorum_threshold
            ),
        ));
    }

    let pipeline = &observation.protected_pipeline;
    if is_normal_etdag_source(pipeline.source) {
        if pipeline.availability_count < pipeline.availability_required {
            return Some(missing_transition(
                "PROTECTED_PIPELINE.COLLECTING",
                "PROTECTED_PIPELINE.AVAILABILITY_QUORUM",
                format!(
                    "availability evidence {}/{}",
                    pipeline.availability_count, pipeline.availability_required
                ),
            ));
        }
        if pipeline.cutoff_marker_count < pipeline.cutoff_markers_required {
            return Some(missing_transition(
                "PROTECTED_PIPELINE.AVAILABILITY_QUORUM",
                "PROTECTED_PIPELINE.CUTOFF_READY",
                format!(
                    "cutoff markers {}/{}",
                    pipeline.cutoff_marker_count, pipeline.cutoff_markers_required
                ),
            ));
        }
        if !pipeline.cut_ready {
            return Some(missing_transition(
                "PROTECTED_PIPELINE.CUTOFF_READY",
                "PROTECTED_PIPELINE.CUT_READY",
                "deterministic CutProof is not ready".to_string(),
            ));
        }
        if !pipeline.order_ready {
            return Some(missing_transition(
                "PROTECTED_PIPELINE.CUT_READY",
                "PROTECTED_PIPELINE.ORDER_READY",
                "deterministic protected ordering is not ready".to_string(),
            ));
        }
    }
    if pipeline.parent_commitment.is_none() {
        return Some(missing_transition(
            "PROTECTED_PIPELINE.ORDER_READY",
            "PROTECTED_PIPELINE.COMMITTED_IN_PARENT",
            "required protected-batch commitment is absent from the parent".to_string(),
        ));
    }
    if !observation.posy.proposal_seen {
        return Some(missing_transition(
            "POSY.HEIGHT_READY",
            "POSY.PROPOSAL",
            format!(
                "proposal not seen from expected proposer {}",
                observation.posy.expected_proposer
            ),
        ));
    }
    if observation.posy.validation_votes < observation.posy.validation_votes_required
        || observation.posy.vc_status != CertificateStatus::Formed
    {
        return Some(missing_transition(
            "POSY.PROPOSAL",
            "POSY.VC",
            format!(
                "validation quorum {}/{}",
                observation.posy.validation_votes, observation.posy.validation_votes_required
            ),
        ));
    }
    if is_normal_etdag_source(pipeline.source) {
        if !pipeline.reveal_authorized {
            return Some(missing_transition(
                "PROTECTED_PIPELINE.COMMITTED_IN_PARENT",
                "PROTECTED_PIPELINE.REVEAL_AUTHORIZED",
                "PoSy VC has not authorized reveal for the committed protected batch".to_string(),
            ));
        }
        if pipeline.reveal_share_count < pipeline.reveal_shares_required
            || !pipeline.execution_ready
        {
            return Some(missing_transition(
                "PROTECTED_PIPELINE.REVEAL_AUTHORIZED",
                "PROTECTED_PIPELINE.EXECUTION_READY",
                format!(
                    "reveal shares {}/{}; execution_ready={}",
                    pipeline.reveal_share_count,
                    pipeline.reveal_shares_required,
                    pipeline.execution_ready
                ),
            ));
        }
    } else if !pipeline.execution_ready {
        return Some(missing_transition(
            "PROTECTED_PIPELINE.GENESIS_BOOTSTRAP",
            "PROTECTED_PIPELINE.EXECUTION_READY",
            "Genesis-bound empty protected batch is not ready for execution".to_string(),
        ));
    }
    if observation.posy.finality_votes < observation.posy.finality_votes_required
        || observation.posy.qc_status != CertificateStatus::Formed
    {
        return Some(missing_transition(
            "POSY.VC",
            "POSY.QC",
            format!(
                "finality quorum {}/{}",
                observation.posy.finality_votes, observation.posy.finality_votes_required
            ),
        ));
    }
    if observation.posy.finalized_height < observation.posy.current_height {
        return Some(missing_transition(
            "POSY.QC",
            "POSY.FINALIZED",
            format!(
                "current height {}; finalized height {}",
                observation.posy.current_height, observation.posy.finalized_height
            ),
        ));
    }
    None
}

fn missing_transition(from: &str, to: &str, reason: String) -> MissingTransition {
    MissingTransition {
        from: from.to_string(),
        to: to.to_string(),
        reason,
    }
}

fn is_normal_etdag_source(source: ProtectedPipelineSource) -> bool {
    matches!(
        source,
        ProtectedPipelineSource::NormalEtdag | ProtectedPipelineSource::NormalEtdagSteadyState
    )
}

fn evaluate_cluster_release_consistency(
    validators: &[ValidatorOperationsStatus],
) -> ClusterReleaseConsistency {
    let Some(reference) = validators.first() else {
        return ClusterReleaseConsistency {
            consistent: false,
            reference_validator_id: None,
            mismatched_validator_ids: Vec::new(),
            mismatched_fields_by_validator: BTreeMap::new(),
        };
    };

    let mut mismatched_validator_ids = BTreeSet::new();
    let mut mismatched_fields_by_validator = BTreeMap::new();
    for validator in validators {
        if !validator.release_consistency.matches_expected {
            mismatched_validator_ids.insert(validator.discovery.validator_id.clone());
            mismatched_fields_by_validator.insert(
                validator.discovery.validator_id.clone(),
                validator
                    .release_consistency
                    .mismatch_fields
                    .iter()
                    .map(|entry| entry.field.clone())
                    .collect(),
            );
        }
    }
    for validator in validators.iter().skip(1) {
        let mismatch = compare_release_identity(Some(&reference.release), &validator.release);
        if !mismatch.matches_expected {
            mismatched_validator_ids.insert(validator.discovery.validator_id.clone());
            mismatched_fields_by_validator
                .entry(validator.discovery.validator_id.clone())
                .or_insert_with(Vec::new)
                .extend(
                    mismatch
                        .mismatch_fields
                        .into_iter()
                        .map(|entry| entry.field),
                );
        }
    }
    for fields in mismatched_fields_by_validator.values_mut() {
        fields.sort();
        fields.dedup();
    }

    ClusterReleaseConsistency {
        consistent: mismatched_validator_ids.is_empty(),
        reference_validator_id: Some(reference.discovery.validator_id.clone()),
        mismatched_validator_ids: mismatched_validator_ids.into_iter().collect(),
        mismatched_fields_by_validator,
    }
}

fn common_value<I>(mut values: I) -> Option<u64>
where
    I: Iterator<Item = u64>,
{
    let first = values.next()?;
    values.all(|value| value == first).then_some(first)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct FiveValidatorFixture {
        validator_ids: Vec<String>,
        release_mismatch_validator_id: String,
        first_missing_transition_validator_id: String,
        base_observation: ValidatorOperationsObservation,
    }

    fn five_validator_fixture() -> FiveValidatorFixture {
        serde_json::from_str(include_str!(
            "../fixtures/validator-operations/five-validator-observations.json"
        ))
        .expect("five-validator operations fixture")
    }

    fn release(id: &str, byte: char) -> ReleaseIdentity {
        ReleaseIdentity {
            release_id: id.to_string(),
            release_tag: "v20.0.0-r11".to_string(),
            binary_sha256: std::iter::repeat_n(byte, 64).collect(),
            core_revision: "core-r11".to_string(),
            synq_revision: "synq-r11".to_string(),
            aegis_revision: "aegis-r11".to_string(),
            genesis_hash: "genesis-v3".to_string(),
            protocol_version: "posy-v3".to_string(),
            protected_pipeline_version: "protected-pipeline-v1".to_string(),
            validator_config_version: "validator-config-v3".to_string(),
        }
    }

    fn healthy_observation(id: &str) -> ValidatorOperationsObservation {
        ValidatorOperationsObservation {
            schema_version: VALIDATOR_OPERATIONS_SCHEMA_VERSION.to_string(),
            observed_at_utc: "2026-08-26T12:00:00Z".to_string(),
            discovery: ValidatorDiscovery {
                validator_id: id.to_string(),
                hostname: id.to_string(),
                chain_id: "1266".to_string(),
                network: "testnet-v3".to_string(),
                incarnation: "testnet-v3-genesis".to_string(),
                validator_public_key_fingerprint: "validator-fingerprint".to_string(),
                consensus_public_key_fingerprint: "consensus-fingerprint".to_string(),
                ingress_public_key_fingerprint: "ingress-fingerprint".to_string(),
                key_binding_status: "BOUND".to_string(),
                vpn_address: "10.70.10.2".to_string(),
                p2p_address: "10.70.10.2:5622".to_string(),
                rpc_address: Some("127.0.0.1:8545".to_string()),
                management_address: "10.70.10.2:47990".to_string(),
                data_path: "/opt/synergy/validator/data".to_string(),
            },
            release: release("r11", 'a'),
            expected_release: Some(release("r11", 'a')),
            service: ValidatorServiceStatus {
                state: ServiceState::Active,
                unit_identity: "synergy-validator.service".to_string(),
                process_id: Some(1266),
                uptime_seconds: 600,
                restart_count: 0,
            },
            peers: ValidatorPeerStatus {
                p2p_listener_ready: true,
                connected_peer_count: 4,
                authenticated_validator_peer_count: 4,
                expected_validator_peer_count: 4,
                peer_quorum_threshold: 3,
            },
            chain: ValidatorChainStatus {
                head_height: 128,
                finalized_height: 128,
                head_progress: ProgressState::Advancing,
                finality_progress: ProgressState::Advancing,
                last_finalized_at_utc: Some("2026-08-26T11:59:59Z".to_string()),
                millis_since_last_finalized: Some(1_000),
                sync_target_height: 128,
                quorum_available: true,
                divergence_detected: false,
            },
            posy: PosyStatus {
                current_height: 128,
                finalized_height: 128,
                current_view: 0,
                expected_proposer: "validator-02".to_string(),
                proposal_seen: true,
                validation_votes: 4,
                validation_votes_required: 4,
                vc_status: CertificateStatus::Formed,
                finality_votes: 4,
                finality_votes_required: 4,
                qc_status: CertificateStatus::Formed,
                last_finalized_at_utc: Some("2026-08-26T11:59:59Z".to_string()),
                view_change_count: 0,
            },
            protected_pipeline: ProtectedPipelineStatus {
                target_height: 128,
                source: ProtectedPipelineSource::NormalEtdag,
                phase: ProtectedPipelinePhase::Consumed,
                availability_count: 4,
                availability_required: 4,
                cutoff_marker_count: 4,
                cutoff_markers_required: 4,
                cut_ready: true,
                cut_root: Some("cut-root".to_string()),
                order_ready: true,
                protected_batch_root: Some("batch-root".to_string()),
                parent_commitment: Some("parent-commitment".to_string()),
                reveal_authorized: true,
                reveal_share_count: 4,
                reveal_shares_required: 4,
                execution_ready: true,
                consumed: true,
            },
            resources: ValidatorResourceStatus {
                cpu_percent: 12.5,
                memory_bytes: 512 * 1024 * 1024,
                memory_percent: 25.0,
                disk_used_percent: 30.0,
                network_rx_bytes_per_second: 1_000,
                network_tx_bytes_per_second: 2_000,
            },
            preflight: vec![ValidatorPreflightCheck {
                id: "genesis".to_string(),
                status: PreflightCheckStatus::Pass,
                detail: "canonical Genesis verified".to_string(),
            }],
        }
    }

    #[test]
    fn healthy_status_is_deterministic_and_has_no_missing_transition() {
        let first = evaluate_validator_operations(healthy_observation("validator-02"));
        let second = evaluate_validator_operations(healthy_observation("validator-02"));

        assert_eq!(first, second);
        assert_eq!(first.health.classification, ValidatorHealthClass::Healthy);
        assert!(first.liveness.first_missing_transition.is_none());
    }

    #[test]
    fn five_validator_fixture_covers_fanout_status_and_diagnostics() {
        let fixture = five_validator_fixture();
        assert_eq!(fixture.validator_ids.len(), 5);
        let observations = fixture
            .validator_ids
            .iter()
            .map(|id| {
                let mut observation = fixture.base_observation.clone();
                observation.discovery.validator_id = id.clone();
                observation.discovery.hostname = format!("{id}.testnet-v3");
                if id == &fixture.release_mismatch_validator_id {
                    observation.release.binary_sha256 = "b".repeat(64);
                }
                if id == &fixture.first_missing_transition_validator_id {
                    observation.protected_pipeline.phase = ProtectedPipelinePhase::Revealing;
                    observation.protected_pipeline.reveal_share_count = 2;
                    observation.protected_pipeline.execution_ready = false;
                    observation.protected_pipeline.consumed = false;
                }
                validate_observation(&observation, Some(id)).expect("fixture observation is valid");
                observation
            })
            .collect::<Vec<_>>();

        let cluster = evaluate_validator_cluster(observations, Vec::new());
        assert_eq!(cluster.validators.len(), 5);
        assert_eq!(
            cluster
                .validators
                .iter()
                .map(|status| status.discovery.validator_id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "validator-02",
                "validator-03",
                "validator-04",
                "validator-05",
                "validator-06"
            ]
        );
        assert_eq!(
            cluster.release_consistency.mismatched_validator_ids,
            vec!["validator-04"]
        );
        for status in &cluster.validators {
            assert_eq!(status.release.binary_sha256.len(), 64);
            assert_eq!(status.service.state, ServiceState::Active);
            assert_eq!(status.peers.connected_peer_count, 4);
            assert_eq!(
                (status.chain.head_height, status.chain.finalized_height),
                (128, 128)
            );
            assert_eq!(
                (
                    status.posy.current_view,
                    status.posy.vc_status,
                    status.posy.qc_status
                ),
                (7, CertificateStatus::Formed, CertificateStatus::Formed)
            );
            assert!(status.resources.cpu_percent > 0.0);
            assert!(status.resources.memory_bytes > 0);
            assert!(status.service.uptime_seconds > 0);
        }
        let stalled = cluster
            .validators
            .iter()
            .find(|status| {
                status.discovery.validator_id == fixture.first_missing_transition_validator_id
            })
            .unwrap();
        let transition = stalled
            .liveness
            .first_missing_transition
            .as_ref()
            .expect("first missing transition");
        assert_eq!(transition.to, "PROTECTED_PIPELINE.EXECUTION_READY");
        assert!(transition.reason.contains("reveal shares 2/4"));
        assert_eq!(
            stalled.protected_pipeline.source,
            ProtectedPipelineSource::NormalEtdagSteadyState
        );
    }

    #[test]
    fn host_preflight_and_all_lifecycle_actions_are_stable() {
        let fixture = five_validator_fixture();
        let status = evaluate_validator_operations(fixture.base_observation);
        let preflight = evaluate_host_preflight(&status);
        assert!(preflight.ready);
        assert_eq!(
            preflight.required_check_ids.len(),
            REQUIRED_HOST_PREFLIGHT_CHECK_IDS.len()
        );

        for (encoded, action, nodectl, requires_preflight) in [
            (
                r#"{"action":"START","reason":"operator approved"}"#,
                ValidatorLifecycleAction::Start,
                "start",
                true,
            ),
            (
                r#"{"action":"STOP","reason":"operator approved"}"#,
                ValidatorLifecycleAction::Stop,
                "stop",
                false,
            ),
            (
                r#"{"action":"RESTART","reason":"operator approved"}"#,
                ValidatorLifecycleAction::Restart,
                "restart",
                true,
            ),
        ] {
            let request: ValidatorLifecycleRequest =
                serde_json::from_str(encoded).expect("lifecycle request");
            assert_eq!(request.action, action);
            assert_eq!(request.action.as_nodectl_action(), nodectl);
            assert_eq!(request.action.requires_preflight(), requires_preflight);
        }
        assert!(serde_json::from_str::<ValidatorLifecycleRequest>(
            r#"{"action":"SHELL","reason":"no"}"#
        )
        .is_err());
    }

    #[test]
    fn release_hash_mismatch_has_priority_and_lists_exact_field() {
        let mut observation = healthy_observation("validator-02");
        observation.release.binary_sha256 = std::iter::repeat_n('b', 64).collect();

        let status = evaluate_validator_operations(observation);

        assert_eq!(
            status.health.classification,
            ValidatorHealthClass::ReleaseMismatch
        );
        assert_eq!(status.release_consistency.mismatch_fields.len(), 1);
        assert_eq!(
            status.release_consistency.mismatch_fields[0].field,
            "binary_sha256"
        );
    }

    #[test]
    fn first_missing_transition_reports_posy_validation_quorum() {
        let mut observation = healthy_observation("validator-02");
        observation.posy.validation_votes = 3;
        observation.posy.vc_status = CertificateStatus::Collecting;

        let transition = diagnose_first_missing_transition(&observation).expect("diagnosis");

        assert_eq!(transition.from, "POSY.PROPOSAL");
        assert_eq!(transition.to, "POSY.VC");
        assert_eq!(transition.reason, "validation quorum 3/4");
    }

    #[test]
    fn first_missing_transition_reports_reveal_to_execution() {
        let mut observation = healthy_observation("validator-02");
        observation.protected_pipeline.reveal_share_count = 3;
        observation.protected_pipeline.execution_ready = false;

        let transition = diagnose_first_missing_transition(&observation).expect("diagnosis");

        assert_eq!(transition.from, "PROTECTED_PIPELINE.REVEAL_AUTHORIZED");
        assert_eq!(transition.to, "PROTECTED_PIPELINE.EXECUTION_READY");
        assert_eq!(
            transition.reason,
            "reveal shares 3/4; execution_ready=false"
        );
    }

    #[test]
    fn syncing_precedes_degraded_peer_health() {
        let mut observation = healthy_observation("validator-02");
        observation.chain.head_height = 120;
        observation.chain.sync_target_height = 128;
        observation.peers.authenticated_validator_peer_count = 2;

        let status = evaluate_validator_operations(observation);

        assert_eq!(status.health.classification, ValidatorHealthClass::Syncing);
    }

    #[test]
    fn finality_age_classifies_stalled() {
        let mut observation = healthy_observation("validator-02");
        observation.chain.millis_since_last_finalized = Some(DEFAULT_FINALITY_STALL_AFTER_MS);
        observation.chain.finality_progress = ProgressState::Stable;

        let status = evaluate_validator_operations(observation);

        assert_eq!(status.health.classification, ValidatorHealthClass::Stalled);
    }

    #[test]
    fn cluster_release_divergence_is_critical_for_every_validator() {
        let first = healthy_observation("validator-02");
        let mut second = healthy_observation("validator-03");
        second.expected_release = None;
        second.release = release("r10", 'b');

        let cluster = evaluate_validator_cluster(vec![second, first], Vec::new());

        assert!(!cluster.release_consistency.consistent);
        assert_eq!(
            cluster
                .release_consistency
                .reference_validator_id
                .as_deref(),
            Some("validator-02")
        );
        assert_eq!(
            cluster.release_consistency.mismatched_validator_ids,
            vec!["validator-03"]
        );
        assert!(cluster.validators.iter().all(|validator| {
            validator.health.classification == ValidatorHealthClass::ReleaseMismatch
        }));
    }

    #[test]
    fn cluster_detects_uniform_release_that_mismatches_expected_release() {
        let mut first = healthy_observation("validator-02");
        let mut second = healthy_observation("validator-03");
        first.release = release("r10", 'b');
        second.release = release("r10", 'b');

        let cluster = evaluate_validator_cluster(vec![first, second], Vec::new());

        assert!(!cluster.release_consistency.consistent);
        assert_eq!(
            cluster.release_consistency.mismatched_validator_ids,
            vec!["validator-02", "validator-03"]
        );
    }

    #[test]
    fn genesis_bootstrap_allows_zero_pipeline_evidence_thresholds() {
        let mut observation = healthy_observation("validator-02");
        observation.protected_pipeline.source = ProtectedPipelineSource::GenesisBootstrap;
        observation.protected_pipeline.phase = ProtectedPipelinePhase::GenesisBootstrap;
        observation.protected_pipeline.availability_count = 0;
        observation.protected_pipeline.availability_required = 0;
        observation.protected_pipeline.cutoff_marker_count = 0;
        observation.protected_pipeline.cutoff_markers_required = 0;
        observation.protected_pipeline.reveal_share_count = 0;
        observation.protected_pipeline.reveal_shares_required = 0;
        observation.protected_pipeline.reveal_authorized = false;

        validate_observation(&observation, Some("validator-02"))
            .expect("Genesis bootstrap observation");
        assert!(diagnose_first_missing_transition(&observation).is_none());
    }

    #[test]
    fn steady_state_source_uses_normal_etdag_validation_and_diagnostics() {
        let mut observation = healthy_observation("validator-02");
        observation.protected_pipeline.source = ProtectedPipelineSource::NormalEtdagSteadyState;
        observation.protected_pipeline.availability_count = 3;

        validate_observation(&observation, Some("validator-02")).expect("steady-state observation");
        let transition = diagnose_first_missing_transition(&observation).expect("diagnosis");
        assert_eq!(transition.to, "PROTECTED_PIPELINE.AVAILABILITY_QUORUM");

        let serialized = serde_json::to_value(&observation).expect("serialize observation");
        assert_eq!(
            serialized["protected_pipeline"]["source"],
            "NORMAL_ETDAG_STEADY_STATE"
        );
    }

    #[test]
    fn malformed_or_secret_bearing_snapshot_is_rejected() {
        let mut value = serde_json::to_value(healthy_observation("validator-02"))
            .expect("serialize observation");
        value.as_object_mut().expect("observation object").insert(
            "private_key".to_string(),
            serde_json::json!("do-not-expose"),
        );

        let error = serde_json::from_value::<ValidatorOperationsObservation>(value)
            .expect_err("unknown secret field must fail closed");

        assert!(error.to_string().contains("unknown field"));
        assert!(!error.to_string().contains("do-not-expose"));
    }

    #[test]
    fn validation_rejects_wrong_validator_and_invalid_hash() {
        let observation = healthy_observation("validator-02");
        assert!(validate_observation(&observation, Some("validator-03")).is_err());

        let mut invalid_hash = observation;
        invalid_hash.release.binary_sha256 = "not-a-sha".to_string();
        assert!(validate_observation(&invalid_hash, None).is_err());
    }
}
