use crate::cluster::{fault_tolerance_f, quorum_threshold};
use crate::community_onboarding::{
    evaluate_community_validator_dry_run_join, CommunityValidatorDryRunJoinInput,
};
use crate::synergy_types::{SYNERGY_TESTNET_V3_CHAIN_ID, SYNERGY_TESTNET_V3_NETWORK_ID};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChaosScenario {
    NormalFinality,
    StopValidators,
    NetworkPartition,
    ValidatorCrashMidBlockAppend,
    CrashBetweenQcAppendAndLockWrite,
    CorruptCanonicalLock,
    CorruptCommittedQcs,
    DiskFullWriteFailure,
    DivergentValidator,
    StateCorruption,
    QrpcOverload,
    MetricsFailure,
    PublicRpcStale,
    AtlasMinorityFork,
    ArchiveNoncanonical,
    ArchiveSnapshotContamination,
    RejoinBadCheckpoint,
    RejoinDelayedQc,
    CommunityDryRunJoin,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChaosBehavior {
    Finalizes,
    HaltsSafely,
    QuarantineRequired,
    SurfaceFailClosed,
    ArchiveContained,
    VoteOnlyJoinApproved,
    VoteOnlyJoinBlocked,
    Unsafe,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChaosValidatorFault {
    None,
    Stopped,
    Partitioned,
    DivergentBranch,
    MissingCompactBoundaryLock,
    MissingBoundaryQc,
    BodyBehindLock,
    CrashMidBlockAppend,
    CrashAfterQcAppendBeforeLockWrite,
    CorruptCanonicalLock,
    CorruptCommittedQcsJsonl,
    DiskFullWriteFailure,
    BadCheckpoint,
    DelayedQc,
    QrpcOverloaded,
    MetricsFailed,
    RootOwnedState,
}

impl Default for ChaosValidatorFault {
    fn default() -> Self {
        Self::None
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChaosSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChaosFinding {
    pub code: String,
    pub severity: ChaosSeverity,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChaosHarnessInput {
    pub scenario: ChaosScenario,
    pub expected_behavior: ChaosBehavior,
    pub chain_id: u64,
    pub network_id: String,
    #[serde(default)]
    pub validators: Vec<ChaosValidator>,
    #[serde(default)]
    pub public_rpc_backends: Vec<ChaosBackend>,
    pub atlas: Option<ChaosBackend>,
    pub archive: Option<ChaosArchiveState>,
    pub community_join: Option<CommunityValidatorDryRunJoinInput>,
    #[serde(default)]
    pub unsafe_qc_acceptance_attempted: bool,
    #[serde(default)]
    pub attempted_quorum_threshold: Option<usize>,
    #[serde(default)]
    pub permanent_quarantine_requested: bool,
    #[serde(default)]
    pub fault_evidence_persists: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChaosValidator {
    pub validator_id: String,
    #[serde(default)]
    pub cluster_id: u64,
    pub height: u64,
    pub block_hash: String,
    #[serde(default)]
    pub fault: ChaosValidatorFault,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChaosBackend {
    pub name: String,
    #[serde(default = "default_available")]
    pub available: bool,
    pub height: u64,
    pub block_hash: String,
    #[serde(default)]
    pub synthetic_height: bool,
    #[serde(default)]
    pub lag_tolerance_blocks: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChaosArchiveState {
    #[serde(default)]
    pub configured: bool,
    #[serde(default)]
    pub canonical_verified: bool,
    #[serde(default)]
    pub trusted_by_recovery: bool,
    pub height: Option<u64>,
    pub block_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChaosClusterReport {
    pub cluster_id: u64,
    pub validator_count: usize,
    pub active_consensus_count: usize,
    pub fault_tolerance_f: usize,
    pub quorum_threshold: usize,
    pub can_finalize: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChaosHarnessReport {
    pub ok: bool,
    pub decision: String,
    pub dry_run_only: bool,
    pub scenario: ChaosScenario,
    pub expected_behavior: ChaosBehavior,
    pub actual_behavior: ChaosBehavior,
    pub canonical_height: Option<u64>,
    pub canonical_hash: Option<String>,
    pub clusters: Vec<ChaosClusterReport>,
    pub safety_assertions: ChaosSafetyAssertions,
    pub findings: Vec<ChaosFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChaosSafetyAssertions {
    pub no_unsafe_qc_acceptance: bool,
    pub no_quorum_lowering: bool,
    pub no_permanent_quarantine_without_persistent_evidence: bool,
    pub rejoin_requires_verified_latest_finalized_head: bool,
    pub public_surfaces_fail_closed: bool,
    pub archive_remains_isolated: bool,
}

pub fn run_chaos_harness(input: &ChaosHarnessInput) -> ChaosHarnessReport {
    let mut findings = Vec::new();
    if input.chain_id != SYNERGY_TESTNET_V3_CHAIN_ID {
        findings.push(error(
            "chain_id_mismatch",
            format!(
                "expected chain_id {} but got {}",
                SYNERGY_TESTNET_V3_CHAIN_ID, input.chain_id
            ),
        ));
    }
    if input.network_id != SYNERGY_TESTNET_V3_NETWORK_ID {
        findings.push(error(
            "network_id_mismatch",
            format!(
                "expected network_id {} but got {}",
                SYNERGY_TESTNET_V3_NETWORK_ID, input.network_id
            ),
        ));
    }

    let clusters = evaluate_clusters(&input.validators, &mut findings);
    let canonical = canonical_active_head(&input.validators, &clusters, &mut findings);
    let surfaces_fail_closed =
        public_surfaces_fail_closed(input, canonical.as_ref(), &mut findings);
    let archive_contained = archive_contained(input.archive.as_ref(), &mut findings);
    let quorum_available =
        !clusters.is_empty() && clusters.iter().all(|cluster| cluster.can_finalize);
    let state_fault_present = input
        .validators
        .iter()
        .any(|validator| validator_fault_requires_quarantine(&validator.fault));
    let rejoin_fault_present = input
        .validators
        .iter()
        .any(|validator| validator_fault_blocks_rejoin(&validator.fault));
    let active_divergence_present = active_divergence_present(&input.validators, &clusters);
    let actual_behavior = match input.scenario {
        ChaosScenario::CommunityDryRunJoin => community_join_behavior(input, &mut findings),
        ChaosScenario::RejoinBadCheckpoint | ChaosScenario::RejoinDelayedQc => {
            if rejoin_fault_present {
                ChaosBehavior::VoteOnlyJoinBlocked
            } else {
                community_join_behavior(input, &mut findings)
            }
        }
        ChaosScenario::ArchiveNoncanonical | ChaosScenario::ArchiveSnapshotContamination => {
            if archive_contained {
                ChaosBehavior::ArchiveContained
            } else {
                ChaosBehavior::Unsafe
            }
        }
        ChaosScenario::PublicRpcStale | ChaosScenario::AtlasMinorityFork => {
            if surfaces_fail_closed {
                ChaosBehavior::SurfaceFailClosed
            } else if quorum_available {
                ChaosBehavior::Finalizes
            } else {
                ChaosBehavior::HaltsSafely
            }
        }
        ChaosScenario::DivergentValidator
        | ChaosScenario::StateCorruption
        | ChaosScenario::ValidatorCrashMidBlockAppend
        | ChaosScenario::CrashBetweenQcAppendAndLockWrite
        | ChaosScenario::CorruptCanonicalLock
        | ChaosScenario::CorruptCommittedQcs
        | ChaosScenario::DiskFullWriteFailure => {
            if has_error(&findings) {
                ChaosBehavior::Unsafe
            } else if state_fault_present || active_divergence_present {
                ChaosBehavior::QuarantineRequired
            } else if quorum_available {
                ChaosBehavior::Finalizes
            } else {
                ChaosBehavior::HaltsSafely
            }
        }
        ChaosScenario::QrpcOverload | ChaosScenario::MetricsFailure => {
            if quorum_available {
                ChaosBehavior::Finalizes
            } else {
                ChaosBehavior::HaltsSafely
            }
        }
        ChaosScenario::NormalFinality
        | ChaosScenario::StopValidators
        | ChaosScenario::NetworkPartition => {
            if quorum_available {
                ChaosBehavior::Finalizes
            } else {
                ChaosBehavior::HaltsSafely
            }
        }
    };

    if actual_behavior != input.expected_behavior {
        findings.push(error(
            "unexpected_chaos_behavior",
            format!(
                "expected {:?} but evaluated {:?}",
                input.expected_behavior, actual_behavior
            ),
        ));
    }
    let safety_assertions = evaluate_safety_assertions(
        input,
        &clusters,
        surfaces_fail_closed,
        archive_contained,
        &actual_behavior,
        &mut findings,
    );
    let ok = !has_error(&findings);
    ChaosHarnessReport {
        ok,
        decision: if ok { "PASS" } else { "NO_GO" }.to_string(),
        dry_run_only: true,
        scenario: input.scenario.clone(),
        expected_behavior: input.expected_behavior.clone(),
        actual_behavior,
        canonical_height: canonical.as_ref().map(|head| head.0),
        canonical_hash: canonical.as_ref().map(|head| head.1.clone()),
        clusters,
        safety_assertions,
        findings,
    }
}

fn evaluate_clusters(
    validators: &[ChaosValidator],
    findings: &mut Vec<ChaosFinding>,
) -> Vec<ChaosClusterReport> {
    if validators.is_empty() {
        findings.push(error(
            "validators_empty",
            "chaos scenario has no validators",
        ));
        return Vec::new();
    }
    let mut grouped = BTreeMap::<u64, Vec<&ChaosValidator>>::new();
    for validator in validators {
        grouped
            .entry(validator.cluster_id)
            .or_default()
            .push(validator);
        match validator.fault {
            ChaosValidatorFault::Partitioned => findings.push(warning(
                "network_partition_excludes_validator",
                format!("{} has network partition injected", validator.validator_id),
            )),
            ChaosValidatorFault::QrpcOverloaded => findings.push(warning(
                "qrpc_overloaded_consensus_should_continue",
                format!("{} has qRPC overload injected", validator.validator_id),
            )),
            ChaosValidatorFault::MetricsFailed => findings.push(warning(
                "metrics_failed_consensus_should_continue",
                format!("{} has metrics failure injected", validator.validator_id),
            )),
            ChaosValidatorFault::RootOwnedState => findings.push(warning(
                "root_owned_state_requires_doctor",
                format!("{} has root-owned state injected", validator.validator_id),
            )),
            ChaosValidatorFault::MissingCompactBoundaryLock => findings.push(warning(
                "compact_boundary_lock_missing_requires_quarantine",
                format!(
                    "{} is missing compact-boundary lock",
                    validator.validator_id
                ),
            )),
            ChaosValidatorFault::MissingBoundaryQc => findings.push(warning(
                "boundary_qc_missing_requires_state_sync",
                format!("{} is missing boundary QC", validator.validator_id),
            )),
            ChaosValidatorFault::BodyBehindLock => findings.push(warning(
                "body_behind_lock_requires_state_sync",
                format!("{} has body-behind-lock fault", validator.validator_id),
            )),
            ChaosValidatorFault::CrashMidBlockAppend => findings.push(warning(
                "validator_crash_mid_block_append_requires_repair",
                format!(
                    "{} crashed during block append and must verify state before rejoin",
                    validator.validator_id
                ),
            )),
            ChaosValidatorFault::CrashAfterQcAppendBeforeLockWrite => findings.push(warning(
                "qc_append_before_lock_write_crash_requires_repair",
                format!(
                    "{} crashed after QC append and before canonical lock write",
                    validator.validator_id
                ),
            )),
            ChaosValidatorFault::CorruptCanonicalLock => findings.push(warning(
                "canonical_lock_corruption_requires_quarantine",
                format!(
                    "{} has corrupt canonical lock evidence",
                    validator.validator_id
                ),
            )),
            ChaosValidatorFault::CorruptCommittedQcsJsonl => findings.push(warning(
                "committed_qc_corruption_requires_quarantine",
                format!(
                    "{} has corrupt committed_qcs.jsonl evidence",
                    validator.validator_id
                ),
            )),
            ChaosValidatorFault::DiskFullWriteFailure => findings.push(warning(
                "disk_full_write_failure_halts_without_quorum_lowering",
                format!(
                    "{} has disk-full write failure injected",
                    validator.validator_id
                ),
            )),
            ChaosValidatorFault::BadCheckpoint => findings.push(warning(
                "bad_checkpoint_blocks_rejoin",
                format!("{} has bad checkpoint evidence", validator.validator_id),
            )),
            ChaosValidatorFault::DelayedQc => findings.push(warning(
                "delayed_qc_blocks_rejoin",
                format!("{} has delayed QC evidence", validator.validator_id),
            )),
            ChaosValidatorFault::DivergentBranch => findings.push(warning(
                "divergent_validator_requires_quarantine",
                format!("{} has divergent branch injected", validator.validator_id),
            )),
            ChaosValidatorFault::Stopped | ChaosValidatorFault::None => {}
        }
    }

    grouped
        .into_iter()
        .map(|(cluster_id, validators)| {
            let validator_count = validators.len();
            let active_consensus_count = validators
                .iter()
                .filter(|validator| validator_counts_for_consensus(&validator.fault))
                .count();
            let quorum = quorum_threshold(validator_count);
            let can_finalize = active_consensus_count >= quorum;
            if !can_finalize {
                findings.push(warning(
                    "cluster_halts_safely_without_quorum",
                    format!(
                        "cluster {cluster_id} has {active_consensus_count}/{validator_count} consensus-active validators; quorum requires {quorum}"
                    ),
                ));
            }
            ChaosClusterReport {
                cluster_id,
                validator_count,
                active_consensus_count,
                fault_tolerance_f: fault_tolerance_f(validator_count),
                quorum_threshold: quorum,
                can_finalize,
            }
        })
        .collect()
}

fn canonical_active_head(
    validators: &[ChaosValidator],
    clusters: &[ChaosClusterReport],
    findings: &mut Vec<ChaosFinding>,
) -> Option<(u64, String)> {
    let mut by_cluster = BTreeMap::<u64, BTreeMap<(u64, String), usize>>::new();
    for validator in validators
        .iter()
        .filter(|validator| validator_counts_for_consensus(&validator.fault))
    {
        *by_cluster
            .entry(validator.cluster_id)
            .or_default()
            .entry((validator.height, validator.block_hash.clone()))
            .or_default() += 1;
    }

    let mut canonical = None;
    for cluster in clusters {
        let Some(head_counts) = by_cluster.get(&cluster.cluster_id) else {
            continue;
        };
        let quorum_heads: Vec<_> = head_counts
            .iter()
            .filter(|(_head, count)| **count >= cluster.quorum_threshold)
            .collect();
        if quorum_heads.len() > 1 {
            findings.push(error(
                "conflicting_quorum_heads",
                format!(
                    "cluster {} has {} quorum-certified heads in one scenario",
                    cluster.cluster_id,
                    quorum_heads.len()
                ),
            ));
            continue;
        }
        if let Some((head, _count)) = quorum_heads.first() {
            canonical = Some((*head).clone());
        }
    }
    canonical
}

fn public_surfaces_fail_closed(
    input: &ChaosHarnessInput,
    canonical: Option<&(u64, String)>,
    findings: &mut Vec<ChaosFinding>,
) -> bool {
    let mut failed_closed = false;
    for backend in &input.public_rpc_backends {
        if backend_rejected(backend, canonical, findings) {
            failed_closed = true;
        }
    }
    if let Some(atlas) = input.atlas.as_ref() {
        if backend_rejected(atlas, canonical, findings) {
            failed_closed = true;
        }
    }
    failed_closed
}

fn backend_rejected(
    backend: &ChaosBackend,
    canonical: Option<&(u64, String)>,
    findings: &mut Vec<ChaosFinding>,
) -> bool {
    if !backend.available {
        findings.push(warning(
            "surface_backend_unavailable",
            format!("{} is unavailable and must be excluded", backend.name),
        ));
        return true;
    }
    if backend.synthetic_height {
        findings.push(warning(
            "surface_backend_synthetic_height_rejected",
            format!("{} reported synthetic height", backend.name),
        ));
        return true;
    }
    let Some((canonical_height, canonical_hash)) = canonical else {
        return false;
    };
    if backend.height > *canonical_height {
        findings.push(warning(
            "surface_backend_ahead_of_canonical_rejected",
            format!(
                "{} height {} is ahead of canonical {}",
                backend.name, backend.height, canonical_height
            ),
        ));
        return true;
    }
    let lag = canonical_height.saturating_sub(backend.height);
    if lag > backend.lag_tolerance_blocks {
        findings.push(warning(
            "surface_backend_lag_rejected",
            format!(
                "{} lags canonical by {lag} blocks; tolerance is {}",
                backend.name, backend.lag_tolerance_blocks
            ),
        ));
        return true;
    }
    if backend.height == *canonical_height && backend.block_hash != *canonical_hash {
        findings.push(warning(
            "surface_backend_hash_mismatch_rejected",
            format!(
                "{} hash {} does not match canonical {} at height {}",
                backend.name, backend.block_hash, canonical_hash, canonical_height
            ),
        ));
        return true;
    }
    false
}

fn archive_contained(
    archive: Option<&ChaosArchiveState>,
    findings: &mut Vec<ChaosFinding>,
) -> bool {
    let Some(archive) = archive else {
        return true;
    };
    if !archive.configured {
        return true;
    }
    if archive.canonical_verified {
        return false;
    }
    if archive.trusted_by_recovery {
        findings.push(error(
            "noncanonical_archive_trusted",
            "archive is noncanonical but still trusted by recovery paths",
        ));
        return false;
    }
    findings.push(warning(
        "noncanonical_archive_contained",
        format!(
            "archive remains contained at {:?}:{:?}",
            archive.height, archive.block_hash
        ),
    ));
    true
}

fn community_join_behavior(
    input: &ChaosHarnessInput,
    findings: &mut Vec<ChaosFinding>,
) -> ChaosBehavior {
    let Some(join) = input.community_join.as_ref() else {
        findings.push(error(
            "community_join_input_missing",
            "community dry-run join scenario requires community_join evidence",
        ));
        return ChaosBehavior::Unsafe;
    };
    let report = evaluate_community_validator_dry_run_join(join);
    findings.extend(report.findings.into_iter().map(|finding| ChaosFinding {
        code: finding.code,
        severity: match finding.severity {
            crate::community_onboarding::OnboardingSeverity::Info => ChaosSeverity::Info,
            crate::community_onboarding::OnboardingSeverity::Warning => ChaosSeverity::Warning,
            crate::community_onboarding::OnboardingSeverity::Error => ChaosSeverity::Warning,
        },
        detail: finding.detail,
    }));
    if report.ok {
        ChaosBehavior::VoteOnlyJoinApproved
    } else {
        ChaosBehavior::VoteOnlyJoinBlocked
    }
}

fn active_divergence_present(
    validators: &[ChaosValidator],
    clusters: &[ChaosClusterReport],
) -> bool {
    clusters.iter().any(|cluster| {
        let mut heads = BTreeMap::<(u64, String), usize>::new();
        for validator in validators
            .iter()
            .filter(|validator| validator.cluster_id == cluster.cluster_id)
            .filter(|validator| validator_counts_for_consensus(&validator.fault))
        {
            *heads
                .entry((validator.height, validator.block_hash.clone()))
                .or_default() += 1;
        }
        heads.len() > 1
    })
}

fn validator_counts_for_consensus(fault: &ChaosValidatorFault) -> bool {
    matches!(
        fault,
        ChaosValidatorFault::None
            | ChaosValidatorFault::QrpcOverloaded
            | ChaosValidatorFault::MetricsFailed
    )
}

fn validator_fault_requires_quarantine(fault: &ChaosValidatorFault) -> bool {
    matches!(
        fault,
        ChaosValidatorFault::DivergentBranch
            | ChaosValidatorFault::MissingCompactBoundaryLock
            | ChaosValidatorFault::MissingBoundaryQc
            | ChaosValidatorFault::BodyBehindLock
            | ChaosValidatorFault::CrashMidBlockAppend
            | ChaosValidatorFault::CrashAfterQcAppendBeforeLockWrite
            | ChaosValidatorFault::CorruptCanonicalLock
            | ChaosValidatorFault::CorruptCommittedQcsJsonl
            | ChaosValidatorFault::DiskFullWriteFailure
            | ChaosValidatorFault::RootOwnedState
    )
}

fn validator_fault_blocks_rejoin(fault: &ChaosValidatorFault) -> bool {
    matches!(
        fault,
        ChaosValidatorFault::BadCheckpoint | ChaosValidatorFault::DelayedQc
    )
}

fn evaluate_safety_assertions(
    input: &ChaosHarnessInput,
    clusters: &[ChaosClusterReport],
    surfaces_fail_closed: bool,
    archive_contained: bool,
    actual_behavior: &ChaosBehavior,
    findings: &mut Vec<ChaosFinding>,
) -> ChaosSafetyAssertions {
    let no_unsafe_qc_acceptance = !input.unsafe_qc_acceptance_attempted;
    if !no_unsafe_qc_acceptance {
        findings.push(error(
            "unsafe_qc_acceptance_rejected",
            "chaos scenario attempted to accept unsafe QC evidence",
        ));
    }

    let no_quorum_lowering = input
        .attempted_quorum_threshold
        .map(|attempted| {
            clusters
                .iter()
                .all(|cluster| attempted >= cluster.quorum_threshold)
        })
        .unwrap_or(true);
    if !no_quorum_lowering {
        findings.push(error(
            "quorum_lowering_rejected",
            format!(
                "attempted quorum threshold {:?} is below at least one dynamic cluster threshold",
                input.attempted_quorum_threshold
            ),
        ));
    }

    let no_permanent_quarantine_without_persistent_evidence =
        !(input.permanent_quarantine_requested && !input.fault_evidence_persists);
    if !no_permanent_quarantine_without_persistent_evidence {
        findings.push(error(
            "permanent_quarantine_requires_persistent_evidence",
            "permanent quarantine was requested without persistent fault evidence",
        ));
    }

    let rejoin_requires_verified_latest_finalized_head = match input.scenario {
        ChaosScenario::RejoinBadCheckpoint | ChaosScenario::RejoinDelayedQc => {
            actual_behavior == &ChaosBehavior::VoteOnlyJoinBlocked
        }
        _ => true,
    };
    if !rejoin_requires_verified_latest_finalized_head {
        findings.push(error(
            "rejoin_without_verified_latest_finalized_head_rejected",
            "rejoin was not blocked despite bad checkpoint or delayed QC evidence",
        ));
    }

    let public_surface_scenario = matches!(
        input.scenario,
        ChaosScenario::PublicRpcStale | ChaosScenario::AtlasMinorityFork
    );
    let public_surfaces_fail_closed = !public_surface_scenario || surfaces_fail_closed;
    if !public_surfaces_fail_closed {
        findings.push(error(
            "public_surface_did_not_fail_closed",
            "public RPC or Atlas surface evidence was unsafe but not rejected",
        ));
    }

    let archive_scenario = matches!(
        input.scenario,
        ChaosScenario::ArchiveNoncanonical | ChaosScenario::ArchiveSnapshotContamination
    );
    let archive_remains_isolated = !archive_scenario || archive_contained;
    if !archive_remains_isolated {
        findings.push(error(
            "archive_not_isolated",
            "archive snapshot contamination was not isolated from recovery trust",
        ));
    }

    ChaosSafetyAssertions {
        no_unsafe_qc_acceptance,
        no_quorum_lowering,
        no_permanent_quarantine_without_persistent_evidence,
        rejoin_requires_verified_latest_finalized_head,
        public_surfaces_fail_closed,
        archive_remains_isolated,
    }
}

fn default_available() -> bool {
    true
}

fn error(code: impl Into<String>, detail: impl Into<String>) -> ChaosFinding {
    ChaosFinding {
        code: code.into(),
        severity: ChaosSeverity::Error,
        detail: detail.into(),
    }
}

fn warning(code: impl Into<String>, detail: impl Into<String>) -> ChaosFinding {
    ChaosFinding {
        code: code.into(),
        severity: ChaosSeverity::Warning,
        detail: detail.into(),
    }
}

fn has_error(findings: &[ChaosFinding]) -> bool {
    findings
        .iter()
        .any(|finding| finding.severity == ChaosSeverity::Error)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validator(id: usize, fault: ChaosValidatorFault) -> ChaosValidator {
        ChaosValidator {
            validator_id: format!("validator-{id}"),
            cluster_id: 0,
            height: 100,
            block_hash: "hash-100".to_string(),
            fault,
        }
    }

    fn six_validators() -> Vec<ChaosValidator> {
        validators_with_count(6)
    }

    fn validators_with_count(count: usize) -> Vec<ChaosValidator> {
        (1..=count)
            .map(|id| validator(id, ChaosValidatorFault::None))
            .collect()
    }

    fn validators_in_clusters(cluster_sizes: &[usize]) -> Vec<ChaosValidator> {
        let mut next_id = 1usize;
        let mut validators = Vec::new();
        for (cluster_id, count) in cluster_sizes.iter().enumerate() {
            for _ in 0..*count {
                let mut validator = validator(next_id, ChaosValidatorFault::None);
                validator.cluster_id = cluster_id as u64;
                validators.push(validator);
                next_id += 1;
            }
        }
        validators
    }

    fn partitioned_validators(count: usize, partitioned_count: usize) -> Vec<ChaosValidator> {
        let mut validators = validators_with_count(count);
        for validator in validators.iter_mut().take(partitioned_count) {
            validator.fault = ChaosValidatorFault::Partitioned;
        }
        validators
    }

    fn backend(name: &str, height: u64, hash: &str) -> ChaosBackend {
        ChaosBackend {
            name: name.to_string(),
            available: true,
            height,
            block_hash: hash.to_string(),
            synthetic_height: false,
            lag_tolerance_blocks: 0,
        }
    }

    fn input(
        scenario: ChaosScenario,
        expected_behavior: ChaosBehavior,
        validators: Vec<ChaosValidator>,
    ) -> ChaosHarnessInput {
        ChaosHarnessInput {
            scenario,
            expected_behavior,
            chain_id: SYNERGY_TESTNET_V3_CHAIN_ID,
            network_id: SYNERGY_TESTNET_V3_NETWORK_ID.to_string(),
            validators,
            public_rpc_backends: Vec::new(),
            atlas: None,
            archive: None,
            community_join: None,
            unsafe_qc_acceptance_attempted: false,
            attempted_quorum_threshold: None,
            permanent_quarantine_requested: false,
            fault_evidence_persists: false,
        }
    }

    fn finding_codes(report: &ChaosHarnessReport) -> Vec<String> {
        report
            .findings
            .iter()
            .map(|finding| finding.code.clone())
            .collect()
    }

    #[test]
    fn chaos_stop_two_of_six_halts_safely_under_strict_quorum() {
        let mut validators = six_validators();
        validators[0].fault = ChaosValidatorFault::Stopped;
        validators[1].fault = ChaosValidatorFault::Stopped;
        let report = run_chaos_harness(&input(
            ChaosScenario::StopValidators,
            ChaosBehavior::HaltsSafely,
            validators,
        ));
        assert!(report.ok, "{:?}", report.findings);
        assert_eq!(report.actual_behavior, ChaosBehavior::HaltsSafely);
        assert_eq!(report.clusters[0].quorum_threshold, 5);
        assert_eq!(report.clusters[0].active_consensus_count, 4);
    }

    #[test]
    fn chaos_stop_one_of_six_finalizes_without_quorum_change() {
        let mut validators = six_validators();
        validators[0].fault = ChaosValidatorFault::Stopped;
        let report = run_chaos_harness(&input(
            ChaosScenario::StopValidators,
            ChaosBehavior::Finalizes,
            validators,
        ));
        assert!(report.ok, "{:?}", report.findings);
        assert_eq!(report.actual_behavior, ChaosBehavior::Finalizes);
        assert_eq!(report.clusters[0].quorum_threshold, 5);
        assert_eq!(report.clusters[0].active_consensus_count, 5);
        assert!(report.safety_assertions.no_quorum_lowering);
    }

    #[test]
    fn chaos_stop_three_of_six_halts_safely() {
        let mut validators = six_validators();
        validators[0].fault = ChaosValidatorFault::Stopped;
        validators[1].fault = ChaosValidatorFault::Stopped;
        validators[2].fault = ChaosValidatorFault::Stopped;
        let report = run_chaos_harness(&input(
            ChaosScenario::StopValidators,
            ChaosBehavior::HaltsSafely,
            validators,
        ));
        assert!(report.ok, "{:?}", report.findings);
        assert_eq!(report.actual_behavior, ChaosBehavior::HaltsSafely);
        assert!(finding_codes(&report).contains(&"cluster_halts_safely_without_quorum".to_string()));
    }

    #[test]
    fn chaos_network_partition_two_of_six_halts_safely_without_lowering_quorum() {
        let report = run_chaos_harness(&input(
            ChaosScenario::NetworkPartition,
            ChaosBehavior::HaltsSafely,
            partitioned_validators(6, 2),
        ));
        assert!(report.ok, "{:?}", report.findings);
        assert_eq!(report.actual_behavior, ChaosBehavior::HaltsSafely);
        assert_eq!(report.clusters[0].quorum_threshold, 5);
        assert_eq!(report.clusters[0].active_consensus_count, 4);
        assert!(report.safety_assertions.no_quorum_lowering);
    }

    #[test]
    fn chaos_network_partition_three_of_six_halts_safely() {
        let report = run_chaos_harness(&input(
            ChaosScenario::NetworkPartition,
            ChaosBehavior::HaltsSafely,
            partitioned_validators(6, 3),
        ));
        assert!(report.ok, "{:?}", report.findings);
        assert_eq!(report.actual_behavior, ChaosBehavior::HaltsSafely);
        assert_eq!(report.clusters[0].quorum_threshold, 5);
        assert_eq!(report.clusters[0].active_consensus_count, 3);
        assert!(finding_codes(&report).contains(&"cluster_halts_safely_without_quorum".to_string()));
    }

    #[test]
    fn chaos_network_partition_expanded_clusters_use_dynamic_quorum() {
        for (validator_count, partitioned_count, expected_quorum, expected_behavior) in [
            (7, 2, 5, ChaosBehavior::Finalizes),
            (7, 3, 5, ChaosBehavior::HaltsSafely),
            (10, 3, 7, ChaosBehavior::Finalizes),
            (10, 4, 7, ChaosBehavior::HaltsSafely),
            (13, 4, 9, ChaosBehavior::Finalizes),
            (13, 5, 9, ChaosBehavior::HaltsSafely),
        ] {
            let report = run_chaos_harness(&input(
                ChaosScenario::NetworkPartition,
                expected_behavior.clone(),
                partitioned_validators(validator_count, partitioned_count),
            ));
            assert!(report.ok, "{:?}", report.findings);
            assert_eq!(report.actual_behavior, expected_behavior);
            assert_eq!(report.clusters[0].quorum_threshold, expected_quorum);
            assert_eq!(
                report.clusters[0].active_consensus_count,
                validator_count - partitioned_count
            );
        }
    }

    #[test]
    fn chaos_two_cluster_fixture_reports_independent_dynamic_quorums() {
        let mut validators = validators_in_clusters(&[7, 6]);
        validators[0].fault = ChaosValidatorFault::Partitioned;
        validators[1].fault = ChaosValidatorFault::Partitioned;
        validators[7].fault = ChaosValidatorFault::Stopped;
        let report = run_chaos_harness(&input(
            ChaosScenario::NetworkPartition,
            ChaosBehavior::Finalizes,
            validators,
        ));
        assert!(report.ok, "{:?}", report.findings);
        assert_eq!(report.actual_behavior, ChaosBehavior::Finalizes);
        assert_eq!(report.clusters.len(), 2);
        assert_eq!(report.clusters[0].validator_count, 7);
        assert_eq!(report.clusters[0].quorum_threshold, 5);
        assert_eq!(report.clusters[0].active_consensus_count, 5);
        assert_eq!(report.clusters[1].validator_count, 6);
        assert_eq!(report.clusters[1].quorum_threshold, 5);
        assert_eq!(report.clusters[1].active_consensus_count, 5);
    }

    #[test]
    fn chaos_three_cluster_fixture_halts_only_below_margin_clusters() {
        let mut validators = validators_in_clusters(&[7, 7, 7]);
        validators[0].fault = ChaosValidatorFault::Partitioned;
        validators[1].fault = ChaosValidatorFault::Partitioned;
        validators[7].fault = ChaosValidatorFault::Partitioned;
        validators[8].fault = ChaosValidatorFault::Partitioned;
        validators[9].fault = ChaosValidatorFault::Partitioned;
        validators[14].fault = ChaosValidatorFault::Partitioned;
        validators[15].fault = ChaosValidatorFault::Partitioned;
        let report = run_chaos_harness(&input(
            ChaosScenario::NetworkPartition,
            ChaosBehavior::HaltsSafely,
            validators,
        ));
        assert!(report.ok, "{:?}", report.findings);
        assert_eq!(report.actual_behavior, ChaosBehavior::HaltsSafely);
        assert_eq!(report.clusters.len(), 3);
        assert_eq!(report.clusters[0].active_consensus_count, 5);
        assert_eq!(report.clusters[0].quorum_threshold, 5);
        assert_eq!(report.clusters[1].active_consensus_count, 4);
        assert_eq!(report.clusters[1].quorum_threshold, 5);
        assert!(!report.clusters[1].can_finalize);
        assert_eq!(report.clusters[2].active_consensus_count, 5);
        assert_eq!(report.clusters[2].quorum_threshold, 5);
    }

    #[test]
    fn chaos_divergent_validator_requires_quarantine_without_losing_quorum() {
        let mut validators = six_validators();
        validators[5].fault = ChaosValidatorFault::DivergentBranch;
        validators[5].block_hash = "wrong-hash".to_string();
        let report = run_chaos_harness(&input(
            ChaosScenario::DivergentValidator,
            ChaosBehavior::QuarantineRequired,
            validators,
        ));
        assert!(report.ok, "{:?}", report.findings);
        assert_eq!(report.actual_behavior, ChaosBehavior::QuarantineRequired);
        assert!(
            finding_codes(&report).contains(&"divergent_validator_requires_quarantine".to_string())
        );
    }

    #[test]
    fn chaos_validator_crash_mid_block_append_requires_repair_without_unsafe_qc() {
        let mut validators = six_validators();
        validators[5].fault = ChaosValidatorFault::CrashMidBlockAppend;
        let report = run_chaos_harness(&input(
            ChaosScenario::ValidatorCrashMidBlockAppend,
            ChaosBehavior::QuarantineRequired,
            validators,
        ));
        assert!(report.ok, "{:?}", report.findings);
        assert_eq!(report.actual_behavior, ChaosBehavior::QuarantineRequired);
        assert!(report.safety_assertions.no_unsafe_qc_acceptance);
        assert!(finding_codes(&report)
            .contains(&"validator_crash_mid_block_append_requires_repair".to_string()));
    }

    #[test]
    fn chaos_crash_between_qc_append_and_lock_write_requires_repair() {
        let mut validators = six_validators();
        validators[5].fault = ChaosValidatorFault::CrashAfterQcAppendBeforeLockWrite;
        let report = run_chaos_harness(&input(
            ChaosScenario::CrashBetweenQcAppendAndLockWrite,
            ChaosBehavior::QuarantineRequired,
            validators,
        ));
        assert!(report.ok, "{:?}", report.findings);
        assert_eq!(report.actual_behavior, ChaosBehavior::QuarantineRequired);
        assert!(finding_codes(&report)
            .contains(&"qc_append_before_lock_write_crash_requires_repair".to_string()));
    }

    #[test]
    fn chaos_corrupt_canonical_lock_requires_quarantine() {
        let mut validators = six_validators();
        validators[5].fault = ChaosValidatorFault::CorruptCanonicalLock;
        let report = run_chaos_harness(&input(
            ChaosScenario::CorruptCanonicalLock,
            ChaosBehavior::QuarantineRequired,
            validators,
        ));
        assert!(report.ok, "{:?}", report.findings);
        assert_eq!(report.actual_behavior, ChaosBehavior::QuarantineRequired);
        assert!(finding_codes(&report)
            .contains(&"canonical_lock_corruption_requires_quarantine".to_string()));
    }

    #[test]
    fn chaos_corrupt_committed_qcs_requires_quarantine() {
        let mut validators = six_validators();
        validators[5].fault = ChaosValidatorFault::CorruptCommittedQcsJsonl;
        let report = run_chaos_harness(&input(
            ChaosScenario::CorruptCommittedQcs,
            ChaosBehavior::QuarantineRequired,
            validators,
        ));
        assert!(report.ok, "{:?}", report.findings);
        assert_eq!(report.actual_behavior, ChaosBehavior::QuarantineRequired);
        assert!(finding_codes(&report)
            .contains(&"committed_qc_corruption_requires_quarantine".to_string()));
    }

    #[test]
    fn chaos_disk_full_write_failure_requires_repair_without_quorum_lowering() {
        let mut validators = six_validators();
        validators[5].fault = ChaosValidatorFault::DiskFullWriteFailure;
        let report = run_chaos_harness(&input(
            ChaosScenario::DiskFullWriteFailure,
            ChaosBehavior::QuarantineRequired,
            validators,
        ));
        assert!(report.ok, "{:?}", report.findings);
        assert_eq!(report.actual_behavior, ChaosBehavior::QuarantineRequired);
        assert!(report.safety_assertions.no_quorum_lowering);
        assert!(finding_codes(&report)
            .contains(&"disk_full_write_failure_halts_without_quorum_lowering".to_string()));
    }

    #[test]
    fn chaos_qrpc_overload_does_not_block_consensus_finality() {
        let mut validators = six_validators();
        validators[0].fault = ChaosValidatorFault::QrpcOverloaded;
        let report = run_chaos_harness(&input(
            ChaosScenario::QrpcOverload,
            ChaosBehavior::Finalizes,
            validators,
        ));
        assert!(report.ok, "{:?}", report.findings);
        assert_eq!(report.actual_behavior, ChaosBehavior::Finalizes);
        assert!(finding_codes(&report)
            .contains(&"qrpc_overloaded_consensus_should_continue".to_string()));
    }

    #[test]
    fn chaos_metrics_failure_does_not_block_consensus_finality() {
        let mut validators = six_validators();
        validators[0].fault = ChaosValidatorFault::MetricsFailed;
        let report = run_chaos_harness(&input(
            ChaosScenario::MetricsFailure,
            ChaosBehavior::Finalizes,
            validators,
        ));
        assert!(report.ok, "{:?}", report.findings);
        assert_eq!(report.actual_behavior, ChaosBehavior::Finalizes);
        assert!(finding_codes(&report)
            .contains(&"metrics_failed_consensus_should_continue".to_string()));
    }

    #[test]
    fn chaos_public_surface_stale_backend_fails_closed() {
        let mut scenario = input(
            ChaosScenario::PublicRpcStale,
            ChaosBehavior::SurfaceFailClosed,
            six_validators(),
        );
        scenario
            .public_rpc_backends
            .push(backend("public-rpc", 99, "hash-99"));
        let report = run_chaos_harness(&scenario);
        assert!(report.ok, "{:?}", report.findings);
        assert_eq!(report.actual_behavior, ChaosBehavior::SurfaceFailClosed);
        assert!(report.safety_assertions.public_surfaces_fail_closed);
        assert!(finding_codes(&report).contains(&"surface_backend_lag_rejected".to_string()));
    }

    #[test]
    fn chaos_atlas_backend_mismatch_fails_closed() {
        let mut scenario = input(
            ChaosScenario::AtlasMinorityFork,
            ChaosBehavior::SurfaceFailClosed,
            six_validators(),
        );
        scenario.atlas = Some(backend("atlas", 100, "minority-hash"));
        let report = run_chaos_harness(&scenario);
        assert!(report.ok, "{:?}", report.findings);
        assert_eq!(report.actual_behavior, ChaosBehavior::SurfaceFailClosed);
        assert!(report.safety_assertions.public_surfaces_fail_closed);
        assert!(
            finding_codes(&report).contains(&"surface_backend_hash_mismatch_rejected".to_string())
        );
    }

    #[test]
    fn chaos_noncanonical_archive_must_remain_contained() {
        let mut scenario = input(
            ChaosScenario::ArchiveNoncanonical,
            ChaosBehavior::ArchiveContained,
            six_validators(),
        );
        scenario.archive = Some(ChaosArchiveState {
            configured: true,
            canonical_verified: false,
            trusted_by_recovery: false,
            height: Some(602_192),
            block_hash: Some("0d1c124f".to_string()),
        });
        let report = run_chaos_harness(&scenario);
        assert!(report.ok, "{:?}", report.findings);
        assert_eq!(report.actual_behavior, ChaosBehavior::ArchiveContained);
        assert!(finding_codes(&report).contains(&"noncanonical_archive_contained".to_string()));
    }

    #[test]
    fn chaos_archive_snapshot_contamination_remains_isolated() {
        let mut scenario = input(
            ChaosScenario::ArchiveSnapshotContamination,
            ChaosBehavior::ArchiveContained,
            six_validators(),
        );
        scenario.archive = Some(ChaosArchiveState {
            configured: true,
            canonical_verified: false,
            trusted_by_recovery: false,
            height: Some(602_435),
            block_hash: Some("wrong-archive-hash".to_string()),
        });
        let report = run_chaos_harness(&scenario);
        assert!(report.ok, "{:?}", report.findings);
        assert_eq!(report.actual_behavior, ChaosBehavior::ArchiveContained);
        assert!(report.safety_assertions.archive_remains_isolated);
    }

    #[test]
    fn chaos_noncanonical_archive_trusted_is_unsafe() {
        let mut scenario = input(
            ChaosScenario::ArchiveNoncanonical,
            ChaosBehavior::ArchiveContained,
            six_validators(),
        );
        scenario.archive = Some(ChaosArchiveState {
            configured: true,
            canonical_verified: false,
            trusted_by_recovery: true,
            height: Some(602_192),
            block_hash: Some("0d1c124f".to_string()),
        });
        let report = run_chaos_harness(&scenario);
        assert!(!report.ok);
        assert_eq!(report.actual_behavior, ChaosBehavior::Unsafe);
        assert!(finding_codes(&report).contains(&"noncanonical_archive_trusted".to_string()));
    }

    #[test]
    fn chaos_rejoin_with_bad_checkpoint_is_blocked() {
        let mut validators = six_validators();
        validators[0].fault = ChaosValidatorFault::BadCheckpoint;
        let report = run_chaos_harness(&input(
            ChaosScenario::RejoinBadCheckpoint,
            ChaosBehavior::VoteOnlyJoinBlocked,
            validators,
        ));
        assert!(report.ok, "{:?}", report.findings);
        assert_eq!(report.actual_behavior, ChaosBehavior::VoteOnlyJoinBlocked);
        assert!(
            report
                .safety_assertions
                .rejoin_requires_verified_latest_finalized_head
        );
        assert!(finding_codes(&report).contains(&"bad_checkpoint_blocks_rejoin".to_string()));
    }

    #[test]
    fn chaos_rejoin_with_delayed_qc_is_blocked() {
        let mut validators = six_validators();
        validators[0].fault = ChaosValidatorFault::DelayedQc;
        let report = run_chaos_harness(&input(
            ChaosScenario::RejoinDelayedQc,
            ChaosBehavior::VoteOnlyJoinBlocked,
            validators,
        ));
        assert!(report.ok, "{:?}", report.findings);
        assert_eq!(report.actual_behavior, ChaosBehavior::VoteOnlyJoinBlocked);
        assert!(
            report
                .safety_assertions
                .rejoin_requires_verified_latest_finalized_head
        );
        assert!(finding_codes(&report).contains(&"delayed_qc_blocks_rejoin".to_string()));
    }

    #[test]
    fn chaos_rejects_attempted_quorum_lowering() {
        let mut scenario = input(
            ChaosScenario::NetworkPartition,
            ChaosBehavior::HaltsSafely,
            partitioned_validators(6, 3),
        );
        scenario.attempted_quorum_threshold = Some(3);
        let report = run_chaos_harness(&scenario);
        assert!(!report.ok);
        assert!(!report.safety_assertions.no_quorum_lowering);
        assert!(finding_codes(&report).contains(&"quorum_lowering_rejected".to_string()));
    }

    #[test]
    fn chaos_rejects_unsafe_qc_acceptance_attempt() {
        let mut scenario = input(
            ChaosScenario::CrashBetweenQcAppendAndLockWrite,
            ChaosBehavior::QuarantineRequired,
            six_validators(),
        );
        scenario.validators[5].fault = ChaosValidatorFault::CrashAfterQcAppendBeforeLockWrite;
        scenario.unsafe_qc_acceptance_attempted = true;
        let report = run_chaos_harness(&scenario);
        assert!(!report.ok);
        assert!(!report.safety_assertions.no_unsafe_qc_acceptance);
        assert!(finding_codes(&report).contains(&"unsafe_qc_acceptance_rejected".to_string()));
    }

    #[test]
    fn chaos_rejects_permanent_quarantine_without_persistent_evidence() {
        let mut scenario = input(
            ChaosScenario::DivergentValidator,
            ChaosBehavior::QuarantineRequired,
            six_validators(),
        );
        scenario.validators[5].fault = ChaosValidatorFault::DivergentBranch;
        scenario.permanent_quarantine_requested = true;
        scenario.fault_evidence_persists = false;
        let report = run_chaos_harness(&scenario);
        assert!(!report.ok);
        assert!(
            !report
                .safety_assertions
                .no_permanent_quarantine_without_persistent_evidence
        );
        assert!(finding_codes(&report)
            .contains(&"permanent_quarantine_requires_persistent_evidence".to_string()));
    }
}
