use crate::consensus::self_realign::{RealignmentState, ValidatorDutyGate};
use crate::crypto::aegis_pqvm::AegisPqvmVerifier;
use crate::synergy_types::{
    CanonicalSerialize, ProtocolConfig, QuorumCertificate, StakeStatus, Transaction,
    ValidatorRecord, ValidatorSet, ValidatorStakeRecord, ValidatorStatus,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const REQUIRED_VALIDATOR_STAKE_SNRG: u64 = 50_000;
pub const REQUIRED_VALIDATOR_STAKE_NWEI: u128 = 50_000_000_000_000;
pub const DEFAULT_PEER_ADVANCE_STALL_BLOCKS: u64 = 3;
pub const DEFAULT_VOTE_ONLY_PROBATION_BLOCKS: u64 = 1_000;
pub const VALIDATOR_SUPERVISOR_WORKSPACE_MARKER: &str = "VALIDATOR_SUPERVISOR_OFFLINE_WORKSPACE";
pub const VALIDATOR_SUPERVISOR_STATE_RELATIVE_PATH: &str =
    "supervisor/validator-supervisor-state.json";
pub const MAX_SUPERVISOR_EVIDENCE_AGE_SECS: u64 = 900;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidatorSupervisorAction {
    MaintainActiveDuties,
    IsolateQrpcAndMetrics,
    CollectEvidence,
    QuarantineAndPreserveEvidence,
    RunVerifiedStateSync,
    EnterVoteOnlyRejoin,
    ContinueVoteOnlyProbation,
    EnterProposerProbation,
    ContinueProposerProbation,
    PromoteToActive,
    FailClosedOperatorIntervention,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSupervisorEvidence {
    #[serde(default)]
    pub validator_id: Option<String>,
    #[serde(default)]
    pub cluster_id: Option<String>,
    #[serde(default)]
    pub evidence_created_at_unix: Option<u64>,
    pub current_state: Option<RealignmentState>,
    pub local_finalized_height: u64,
    pub peer_finalized_height: u64,
    pub peer_advance_stall_blocks: Option<u64>,
    pub local_block_hash_disagrees_with_canonical: bool,
    pub canonical_lock_without_body: bool,
    pub body_without_committed_qc: bool,
    pub compact_boundary_lock_missing: bool,
    pub compact_boundary_qc_missing: bool,
    pub compact_boundary_checkpoint_missing: bool,
    pub checkpoint_hash_mismatch: bool,
    pub vote_lock_high_qc_inconsistent: bool,
    pub locks_ahead_of_body_tip: bool,
    pub binary_digest_mismatch: bool,
    pub config_digest_mismatch: bool,
    pub validator_set_digest_mismatch: bool,
    pub peer_count_below_minimum: bool,
    pub disk_space_below_minimum: bool,
    pub memory_below_minimum: bool,
    pub qrpc_degraded: bool,
    pub metrics_degraded: bool,
    pub repeated_panic_loop: bool,
    pub snapshot_verification_failed: bool,
    pub state_sync_verification_failed: bool,
    pub verified_state_sync_plan_available: bool,
    pub exact_finalized_head_match: bool,
    pub latest_qc_verified: bool,
    pub no_unresolved_fork_evidence: bool,
    pub vote_only_finalized_blocks: u64,
    pub vote_only_required_blocks: Option<u64>,
    pub vote_only_missed_votes: u64,
    pub vote_only_divergence_detected: bool,
    pub proposer_probation_passed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSupervisorDecision {
    pub state: RealignmentState,
    pub duty_gate: ValidatorDutyGate,
    pub action: ValidatorSupervisorAction,
    pub reasons: Vec<String>,
    pub fail_closed: bool,
}

pub const VALIDATOR_SUPERVISOR_STATE_SCHEMA: &str = "synergy-validator-supervisor-state-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSupervisorPersistentState {
    pub schema: String,
    pub sequence: u64,
    #[serde(default)]
    pub validator_id: String,
    #[serde(default)]
    pub cluster_id: String,
    pub state: RealignmentState,
    #[serde(default)]
    pub lifecycle_state: Option<RealignmentState>,
    pub duty_gate: ValidatorDutyGate,
    pub last_action: ValidatorSupervisorAction,
    #[serde(default)]
    pub previous_state: Option<RealignmentState>,
    #[serde(default)]
    pub transition_reason: String,
    #[serde(default)]
    pub evidence_hash: String,
    #[serde(default)]
    pub evidence_path: Option<String>,
    #[serde(default)]
    pub evidence_created_at_unix: u64,
    #[serde(default)]
    pub created_at_unix: u64,
    #[serde(default)]
    pub safe_to_vote: bool,
    #[serde(default)]
    pub safe_to_propose: bool,
    #[serde(default)]
    pub safe_to_aggregate_qc: bool,
    #[serde(default)]
    pub counts_toward_quorum: bool,
    pub fail_closed: bool,
    pub reasons: Vec<String>,
    #[serde(default)]
    pub blocked_reasons: Vec<String>,
    #[serde(default)]
    pub next_recommended_actions: Vec<String>,
    pub local_finalized_height: u64,
    pub peer_finalized_height: u64,
    pub vote_only_finalized_blocks: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSupervisorTransitionInput {
    pub previous: Option<ValidatorSupervisorPersistentState>,
    pub evidence: ValidatorSupervisorEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSupervisorTransitionReport {
    pub ok: bool,
    pub dry_run_only: bool,
    pub previous_sequence: Option<u64>,
    pub previous_state: Option<RealignmentState>,
    pub decision: ValidatorSupervisorDecision,
    pub persistent_state: ValidatorSupervisorPersistentState,
    pub write_recommended: bool,
    pub transition_notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidatorSupervisorWriteSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSupervisorWriteFinding {
    pub code: String,
    pub severity: ValidatorSupervisorWriteSeverity,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSupervisorWriteOptions {
    pub dry_run: bool,
    pub apply: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSupervisorWriteReport {
    pub ok: bool,
    pub decision: String,
    pub dry_run: bool,
    pub applied: bool,
    pub workspace: String,
    pub state_path: String,
    pub backup_path: Option<String>,
    pub transition: ValidatorSupervisorTransitionReport,
    pub actions: Vec<String>,
    pub findings: Vec<ValidatorSupervisorWriteFinding>,
}

impl ValidatorSupervisorDecision {
    pub fn can_vote(&self) -> bool {
        self.duty_gate.can_vote
    }

    pub fn can_propose(&self) -> bool {
        self.duty_gate.can_propose
    }
}

pub fn plan_validator_supervisor_transition(
    input: &ValidatorSupervisorTransitionInput,
) -> ValidatorSupervisorTransitionReport {
    let previous = input.previous.as_ref();
    let mut decision = classify_validator_supervisor_state(&input.evidence);
    let mut notes = Vec::new();

    if let Some(previous_state) = previous {
        if previous_state.schema != VALIDATOR_SUPERVISOR_STATE_SCHEMA {
            decision = supervisor_decision(
                RealignmentState::FailedClosed,
                ValidatorSupervisorAction::FailClosedOperatorIntervention,
                vec![format!(
                    "unsupported supervisor state schema {}",
                    previous_state.schema
                )],
                true,
            );
        } else if previous_state.fail_closed && !decision.fail_closed {
            decision = supervisor_decision(
                RealignmentState::FailedClosed,
                ValidatorSupervisorAction::FailClosedOperatorIntervention,
                vec![
                    "previous supervisor state was failed-closed; explicit governed reset is required"
                        .to_string(),
                ],
                true,
            );
        } else if recovery_state_requires_rejoin(previous_state.state)
            && decision.state == RealignmentState::Active
        {
            decision = supervisor_decision(
                RealignmentState::Suspect,
                ValidatorSupervisorAction::CollectEvidence,
                vec![
                    "previous recovery state cannot return directly to active without vote-only rejoin proof"
                        .to_string(),
                ],
                false,
            );
        }
    }

    if previous
        .map(|state| state.state != decision.state)
        .unwrap_or(true)
    {
        notes.push(format!(
            "state_transition={:?}->{:?}",
            previous.map(|state| state.state),
            decision.state
        ));
    }
    if decision.action == ValidatorSupervisorAction::EnterVoteOnlyRejoin {
        notes.push("vote_only_rejoin_requires_persisted_probation_state".to_string());
    }
    if decision.action == ValidatorSupervisorAction::EnterProposerProbation {
        notes.push("proposer_probation_blocks_proposer_duties_until_promotion_proof".to_string());
    }
    if decision.action == ValidatorSupervisorAction::PromoteToActive {
        notes.push("proposer_probation_completed_without_misses_or_divergence".to_string());
    }

    let now = current_unix_secs();
    let evidence_hash = hash_supervisor_evidence(&input.evidence);
    let transition_reason = if decision.reasons.is_empty() {
        format!("{:?}", decision.action)
    } else {
        decision.reasons.join("; ")
    };
    let next_recommended_actions = next_recommended_actions(&decision);
    let persistent_state = ValidatorSupervisorPersistentState {
        schema: VALIDATOR_SUPERVISOR_STATE_SCHEMA.to_string(),
        sequence: previous
            .map(|state| state.sequence.saturating_add(1))
            .unwrap_or(1),
        validator_id: input.evidence.validator_id.clone().unwrap_or_default(),
        cluster_id: input.evidence.cluster_id.clone().unwrap_or_default(),
        state: decision.state,
        lifecycle_state: Some(decision.state),
        duty_gate: decision.duty_gate.clone(),
        last_action: decision.action,
        previous_state: previous.map(|state| state.state),
        transition_reason,
        evidence_hash,
        evidence_path: None,
        evidence_created_at_unix: input.evidence.evidence_created_at_unix.unwrap_or(now),
        created_at_unix: now,
        safe_to_vote: decision.duty_gate.can_vote,
        safe_to_propose: decision.duty_gate.can_propose,
        safe_to_aggregate_qc: decision.duty_gate.can_aggregate_qc,
        counts_toward_quorum: decision.duty_gate.can_count_toward_quorum,
        fail_closed: decision.fail_closed,
        reasons: decision.reasons.clone(),
        blocked_reasons: if decision.state == RealignmentState::Active {
            Vec::new()
        } else {
            decision.reasons.clone()
        },
        next_recommended_actions,
        local_finalized_height: input.evidence.local_finalized_height,
        peer_finalized_height: input.evidence.peer_finalized_height,
        vote_only_finalized_blocks: input.evidence.vote_only_finalized_blocks,
    };
    let write_recommended = previous
        .map(|state| state != &persistent_state)
        .unwrap_or(true);
    ValidatorSupervisorTransitionReport {
        ok: !decision.fail_closed,
        dry_run_only: true,
        previous_sequence: previous.map(|state| state.sequence),
        previous_state: previous.map(|state| state.state),
        decision,
        persistent_state,
        write_recommended,
        transition_notes: notes,
    }
}

pub fn write_validator_supervisor_state(
    transition: &ValidatorSupervisorTransitionReport,
    workspace: &Path,
    options: ValidatorSupervisorWriteOptions,
) -> Result<ValidatorSupervisorWriteReport, String> {
    let state_path = workspace.join(VALIDATOR_SUPERVISOR_STATE_RELATIVE_PATH);
    let mut actions = vec![
        "verify transition report and persistent state invariants".to_string(),
        "verify offline supervisor workspace marker".to_string(),
        "read previous supervisor state when present".to_string(),
        "backup previous supervisor state before apply".to_string(),
        "write new supervisor state to a temporary file".to_string(),
        "atomically rename temporary state into place".to_string(),
    ];
    let mut findings = Vec::new();

    validate_supervisor_write_mode(&options, &mut findings);
    validate_supervisor_workspace(workspace, &mut findings);
    let previous_state = read_previous_supervisor_state(&state_path, &mut findings);
    validate_supervisor_transition_for_write(transition, previous_state.as_ref(), &mut findings);

    if has_write_errors(&findings) {
        return Ok(supervisor_write_report(
            false,
            "NO_GO",
            false,
            workspace,
            &state_path,
            None,
            transition,
            actions,
            findings,
            options.dry_run,
        ));
    }

    if options.dry_run {
        actions.push("dry-run only; supervisor state file was not mutated".to_string());
        return Ok(supervisor_write_report(
            true,
            "DRY_RUN_GO",
            false,
            workspace,
            &state_path,
            None,
            transition,
            actions,
            findings,
            true,
        ));
    }

    let parent = state_path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", state_path.display()))?;
    fs::create_dir_all(parent).map_err(|error| format!("create {}: {error}", parent.display()))?;
    let backup_path = if state_path.is_file() {
        let backup = parent.join(format!(
            "validator-supervisor-state.json.backup-{}-{}",
            std::process::id(),
            current_unix_nanos()
        ));
        fs::copy(&state_path, &backup).map_err(|error| {
            format!(
                "backup previous supervisor state {} to {}: {error}",
                state_path.display(),
                backup.display()
            )
        })?;
        Some(backup)
    } else {
        None
    };
    let temp = parent.join(format!(
        ".validator-supervisor-state.json.tmp-{}-{}",
        std::process::id(),
        current_unix_nanos()
    ));
    let bytes = serde_json::to_vec_pretty(&transition.persistent_state)
        .map_err(|error| format!("serialize supervisor state: {error}"))?;
    fs::write(&temp, bytes).map_err(|error| format!("write {}: {error}", temp.display()))?;
    fs::rename(&temp, &state_path).map_err(|error| {
        let _ = fs::remove_file(&temp);
        format!(
            "atomic rename supervisor state {} to {}: {error}",
            temp.display(),
            state_path.display()
        )
    })?;
    actions.push(format!(
        "supervisor state written to {}",
        state_path.display()
    ));

    Ok(supervisor_write_report(
        true,
        "GO",
        true,
        workspace,
        &state_path,
        backup_path.as_ref(),
        transition,
        actions,
        findings,
        false,
    ))
}

fn validate_supervisor_write_mode(
    options: &ValidatorSupervisorWriteOptions,
    findings: &mut Vec<ValidatorSupervisorWriteFinding>,
) {
    if options.dry_run == options.apply {
        findings.push(write_error(
            "supervisor_write_mode_invalid",
            "exactly one of dry_run or apply must be selected",
        ));
    }
}

fn validate_supervisor_workspace(
    workspace: &Path,
    findings: &mut Vec<ValidatorSupervisorWriteFinding>,
) {
    if !workspace
        .join(VALIDATOR_SUPERVISOR_WORKSPACE_MARKER)
        .is_file()
    {
        findings.push(write_error(
            "supervisor_workspace_marker_missing",
            format!(
                "apply requires offline workspace marker {}",
                workspace
                    .join(VALIDATOR_SUPERVISOR_WORKSPACE_MARKER)
                    .display()
            ),
        ));
    }
}

fn read_previous_supervisor_state(
    state_path: &Path,
    findings: &mut Vec<ValidatorSupervisorWriteFinding>,
) -> Option<ValidatorSupervisorPersistentState> {
    if !state_path.exists() {
        return None;
    }
    match fs::read_to_string(state_path) {
        Ok(content) => match serde_json::from_str::<ValidatorSupervisorPersistentState>(&content) {
            Ok(state) => Some(state),
            Err(error) => {
                findings.push(write_error(
                    "supervisor_previous_state_malformed",
                    format!(
                        "parse previous supervisor state {}: {error}",
                        state_path.display()
                    ),
                ));
                None
            }
        },
        Err(error) => {
            findings.push(write_error(
                "supervisor_previous_state_unreadable",
                format!(
                    "read previous supervisor state {}: {error}",
                    state_path.display()
                ),
            ));
            None
        }
    }
}

fn validate_supervisor_transition_for_write(
    transition: &ValidatorSupervisorTransitionReport,
    previous: Option<&ValidatorSupervisorPersistentState>,
    findings: &mut Vec<ValidatorSupervisorWriteFinding>,
) {
    let state = &transition.persistent_state;
    if state.schema != VALIDATOR_SUPERVISOR_STATE_SCHEMA {
        findings.push(write_error(
            "supervisor_state_schema_mismatch",
            format!("expected schema {}", VALIDATOR_SUPERVISOR_STATE_SCHEMA),
        ));
    }
    if state.validator_id.trim().is_empty() {
        findings.push(write_error(
            "supervisor_validator_id_missing",
            "persisted supervisor state must include validator_id",
        ));
    }
    if state.cluster_id.trim().is_empty() {
        findings.push(write_error(
            "supervisor_cluster_id_missing",
            "persisted supervisor state must include cluster_id",
        ));
    }
    if state.evidence_hash.len() != 64 || hex::decode(&state.evidence_hash).is_err() {
        findings.push(write_error(
            "supervisor_evidence_hash_invalid",
            "persisted supervisor state must include a 32-byte evidence hash",
        ));
    }
    if state.evidence_created_at_unix == 0
        || current_unix_secs().saturating_sub(state.evidence_created_at_unix)
            > MAX_SUPERVISOR_EVIDENCE_AGE_SECS
    {
        findings.push(write_error(
            "supervisor_evidence_stale",
            "supervisor transition evidence is stale or missing a timestamp",
        ));
    }

    match previous {
        Some(previous) => {
            if transition.previous_sequence != Some(previous.sequence) {
                findings.push(write_error(
                    "supervisor_previous_sequence_mismatch",
                    "transition previous_sequence does not match persisted state",
                ));
            }
            if state.sequence <= previous.sequence {
                findings.push(write_error(
                    "supervisor_sequence_not_monotonic",
                    "supervisor state sequence must increase",
                ));
            }
            if previous.fail_closed && state.state == RealignmentState::Active {
                findings.push(write_error(
                    "supervisor_failed_closed_to_active_rejected",
                    "failed-closed state cannot transition directly to active",
                ));
            }
            if recovery_state_requires_rejoin(previous.state)
                && state.state == RealignmentState::Active
            {
                findings.push(write_error(
                    "supervisor_recovery_state_to_active_rejected",
                    "recovery state cannot transition directly to active",
                ));
            }
        }
        None => {
            if transition.previous_sequence.is_some() || state.sequence != 1 {
                findings.push(write_error(
                    "supervisor_first_sequence_invalid",
                    "first supervisor state write must use sequence 1 without previous_sequence",
                ));
            }
        }
    }

    if state.previous_state != transition.previous_state {
        findings.push(write_error(
            "supervisor_previous_state_mismatch",
            "persistent previous_state must match transition previous_state",
        ));
    }
    if state.state != transition.decision.state || state.duty_gate != transition.decision.duty_gate
    {
        findings.push(write_error(
            "supervisor_decision_state_mismatch",
            "persistent state and duty gate must match transition decision",
        ));
    }
    if state.safe_to_vote != state.duty_gate.can_vote
        || state.safe_to_propose != state.duty_gate.can_propose
        || state.safe_to_aggregate_qc != state.duty_gate.can_aggregate_qc
        || state.counts_toward_quorum != state.duty_gate.can_count_toward_quorum
    {
        findings.push(write_error(
            "supervisor_duty_booleans_mismatch",
            "persisted safe duty booleans must match duty gate",
        ));
    }
    if state.state == RealignmentState::VoteOnly && state.safe_to_propose {
        findings.push(write_error(
            "supervisor_vote_only_can_propose_rejected",
            "vote-only state cannot propose",
        ));
    }
    if state.state == RealignmentState::PendingReactivation && state.safe_to_propose {
        findings.push(write_error(
            "supervisor_proposer_probation_can_propose_rejected",
            "proposer probation cannot propose until promotion proof passes",
        ));
    }
    if state.state == RealignmentState::Active
        && (state.fail_closed
            || !state.blocked_reasons.is_empty()
            || !state.safe_to_vote
            || !state.safe_to_propose
            || !state.safe_to_aggregate_qc
            || !state.counts_toward_quorum)
    {
        findings.push(write_error(
            "supervisor_active_state_not_clean",
            "active requires clean state, no blocked reasons, and all active duty gates",
        ));
    }
    if state.fail_closed
        && (state.safe_to_vote
            || state.safe_to_propose
            || state.safe_to_aggregate_qc
            || state.counts_toward_quorum)
    {
        findings.push(write_error(
            "supervisor_failed_closed_duty_gate_open",
            "failed-closed state cannot keep validator duties enabled",
        ));
    }
}

fn hash_supervisor_evidence(evidence: &ValidatorSupervisorEvidence) -> String {
    let bytes = serde_json::to_vec(evidence).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn next_recommended_actions(decision: &ValidatorSupervisorDecision) -> Vec<String> {
    match decision.action {
        ValidatorSupervisorAction::MaintainActiveDuties => {
            vec!["continue normal validator duties".to_string()]
        }
        ValidatorSupervisorAction::IsolateQrpcAndMetrics => {
            vec!["isolate qRPC and metrics without mutating consensus state".to_string()]
        }
        ValidatorSupervisorAction::CollectEvidence => {
            vec!["collect canonical peer evidence before changing duties".to_string()]
        }
        ValidatorSupervisorAction::QuarantineAndPreserveEvidence => vec![
            "quarantine validator duties".to_string(),
            "preserve local evidence before repair".to_string(),
        ],
        ValidatorSupervisorAction::RunVerifiedStateSync => {
            vec!["run verified protocol-native state-sync repair".to_string()]
        }
        ValidatorSupervisorAction::EnterVoteOnlyRejoin => {
            vec!["enter vote-only rejoin and keep proposer duties disabled".to_string()]
        }
        ValidatorSupervisorAction::ContinueVoteOnlyProbation => {
            vec!["continue vote-only probation until finalized-block window passes".to_string()]
        }
        ValidatorSupervisorAction::EnterProposerProbation => {
            vec!["enter proposer probation with proposer duties still disabled".to_string()]
        }
        ValidatorSupervisorAction::ContinueProposerProbation => {
            vec!["continue proposer probation until promotion proof passes".to_string()]
        }
        ValidatorSupervisorAction::PromoteToActive => {
            vec!["promote to active duties after verified promotion proof".to_string()]
        }
        ValidatorSupervisorAction::FailClosedOperatorIntervention => {
            vec![
                "remain failed-closed until governed reset or verified repair evidence".to_string(),
            ]
        }
    }
}

fn supervisor_write_report(
    ok: bool,
    decision: &str,
    applied: bool,
    workspace: &Path,
    state_path: &Path,
    backup_path: Option<&PathBuf>,
    transition: &ValidatorSupervisorTransitionReport,
    actions: Vec<String>,
    findings: Vec<ValidatorSupervisorWriteFinding>,
    dry_run: bool,
) -> ValidatorSupervisorWriteReport {
    ValidatorSupervisorWriteReport {
        ok,
        decision: decision.to_string(),
        dry_run,
        applied,
        workspace: workspace.display().to_string(),
        state_path: state_path.display().to_string(),
        backup_path: backup_path.map(|path| path.display().to_string()),
        transition: transition.clone(),
        actions,
        findings,
    }
}

fn has_write_errors(findings: &[ValidatorSupervisorWriteFinding]) -> bool {
    findings
        .iter()
        .any(|finding| finding.severity == ValidatorSupervisorWriteSeverity::Error)
}

fn write_error(
    code: impl Into<String>,
    detail: impl Into<String>,
) -> ValidatorSupervisorWriteFinding {
    ValidatorSupervisorWriteFinding {
        code: code.into(),
        severity: ValidatorSupervisorWriteSeverity::Error,
        detail: detail.into(),
    }
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

pub fn supervisor_state_for_validator_status(status: &ValidatorStatus) -> RealignmentState {
    match status {
        ValidatorStatus::Active => RealignmentState::Active,
        ValidatorStatus::SelfQuarantinedDivergence => RealignmentState::Quarantined,
        ValidatorStatus::ReconcilingChain => RealignmentState::EvidencePreserved,
        ValidatorStatus::Syncing | ValidatorStatus::SpeedSyncingCanonical => {
            RealignmentState::SpeedSyncing
        }
        ValidatorStatus::SnapshotVerified
        | ValidatorStatus::Replaying
        | ValidatorStatus::Shadow
        | ValidatorStatus::VerifyingCanonicalChain => RealignmentState::ShadowObserving,
        ValidatorStatus::ReadyToRejoin => RealignmentState::ReadyToRejoin,
        ValidatorStatus::RejoiningConsensus => RealignmentState::VoteOnly,
        ValidatorStatus::FailedClosed
        | ValidatorStatus::Jailed
        | ValidatorStatus::Exiting
        | ValidatorStatus::Exited => RealignmentState::FailedClosed,
        ValidatorStatus::Unknown
        | ValidatorStatus::Registered
        | ValidatorStatus::KeyBound
        | ValidatorStatus::StakeRequired
        | ValidatorStatus::StakeSubmitted
        | ValidatorStatus::StakeConfirmed
        | ValidatorStatus::Ready
        | ValidatorStatus::PendingActivation => RealignmentState::Suspect,
    }
}

pub fn supervisor_duty_gate_for_validator_status(status: &ValidatorStatus) -> ValidatorDutyGate {
    ValidatorDutyGate::for_state(supervisor_state_for_validator_status(status))
}

fn recovery_state_requires_rejoin(state: RealignmentState) -> bool {
    matches!(
        state,
        RealignmentState::Quarantined
            | RealignmentState::EvidencePreserved
            | RealignmentState::SpeedSyncing
            | RealignmentState::CaughtUp
            | RealignmentState::ShadowObserving
            | RealignmentState::ShadowPassed
            | RealignmentState::ReadyToRejoin
    )
}

pub fn classify_validator_supervisor_state(
    evidence: &ValidatorSupervisorEvidence,
) -> ValidatorSupervisorDecision {
    let mut reasons = Vec::new();

    if evidence.binary_digest_mismatch {
        reasons.push("binary digest mismatch".to_string());
    }
    if evidence.config_digest_mismatch {
        reasons.push("config digest mismatch".to_string());
    }
    if evidence.validator_set_digest_mismatch {
        reasons.push("validator-set digest mismatch".to_string());
    }
    if evidence.repeated_panic_loop {
        reasons.push("repeated panic loop".to_string());
    }
    if evidence.snapshot_verification_failed {
        reasons.push("snapshot verification failed".to_string());
    }
    if evidence.state_sync_verification_failed {
        reasons.push("state-sync verification failed".to_string());
    }
    if evidence.checkpoint_hash_mismatch {
        reasons.push("checkpoint hash mismatch".to_string());
    }
    if !reasons.is_empty() {
        return supervisor_decision(
            RealignmentState::FailedClosed,
            ValidatorSupervisorAction::FailClosedOperatorIntervention,
            reasons,
            true,
        );
    }

    if evidence.local_block_hash_disagrees_with_canonical {
        reasons.push("local block hash disagrees with canonical proof".to_string());
    }
    if evidence.canonical_lock_without_body {
        reasons.push("canonical lock exists without matching body".to_string());
    }
    if evidence.body_without_committed_qc {
        reasons.push("body exists without committed QC".to_string());
    }
    if evidence.compact_boundary_lock_missing {
        reasons.push("compact boundary lock missing".to_string());
    }
    if evidence.compact_boundary_qc_missing {
        reasons.push("compact boundary QC missing".to_string());
    }
    if evidence.compact_boundary_checkpoint_missing {
        reasons.push("compact boundary checkpoint missing".to_string());
    }
    if evidence.vote_lock_high_qc_inconsistent {
        reasons.push("vote lock and high QC are inconsistent".to_string());
    }
    if evidence.locks_ahead_of_body_tip {
        reasons.push("canonical locks are ahead of the local body tip".to_string());
    }
    if evidence.vote_only_divergence_detected {
        reasons.push("divergence detected during vote-only probation".to_string());
    }
    if !reasons.is_empty() {
        return supervisor_decision(
            RealignmentState::Quarantined,
            ValidatorSupervisorAction::QuarantineAndPreserveEvidence,
            reasons,
            true,
        );
    }

    let stalled_blocks = evidence
        .peer_finalized_height
        .saturating_sub(evidence.local_finalized_height);
    let stall_threshold = evidence
        .peer_advance_stall_blocks
        .unwrap_or(DEFAULT_PEER_ADVANCE_STALL_BLOCKS)
        .max(1);
    if stalled_blocks >= stall_threshold {
        reasons.push(format!(
            "local finalized height is {stalled_blocks} blocks behind peer finalized height"
        ));
        if evidence.verified_state_sync_plan_available {
            return supervisor_decision(
                RealignmentState::SpeedSyncing,
                ValidatorSupervisorAction::RunVerifiedStateSync,
                reasons,
                false,
            );
        }
        return supervisor_decision(
            RealignmentState::Suspect,
            ValidatorSupervisorAction::CollectEvidence,
            reasons,
            false,
        );
    }

    if evidence.peer_count_below_minimum {
        reasons.push("peer count below minimum".to_string());
    }
    if evidence.disk_space_below_minimum {
        reasons.push("disk space below minimum".to_string());
    }
    if evidence.memory_below_minimum {
        reasons.push("memory below minimum".to_string());
    }
    if !reasons.is_empty() {
        return supervisor_decision(
            RealignmentState::Suspect,
            ValidatorSupervisorAction::CollectEvidence,
            reasons,
            false,
        );
    }

    if evidence.exact_finalized_head_match
        && evidence.latest_qc_verified
        && evidence.no_unresolved_fork_evidence
    {
        let required = evidence
            .vote_only_required_blocks
            .unwrap_or(DEFAULT_VOTE_ONLY_PROBATION_BLOCKS);
        if evidence.current_state == Some(RealignmentState::VoteOnly) {
            if evidence.vote_only_finalized_blocks >= required
                && evidence.vote_only_missed_votes == 0
            {
                return supervisor_decision(
                    RealignmentState::PendingReactivation,
                    ValidatorSupervisorAction::EnterProposerProbation,
                    vec!["vote-only probation completed without misses or divergence".to_string()],
                    false,
                );
            }
            return supervisor_decision(
                RealignmentState::VoteOnly,
                ValidatorSupervisorAction::ContinueVoteOnlyProbation,
                vec![format!(
                    "vote-only probation progress {}/{} finalized blocks with {} missed votes",
                    evidence.vote_only_finalized_blocks, required, evidence.vote_only_missed_votes
                )],
                false,
            );
        }
        if evidence.current_state == Some(RealignmentState::PendingReactivation) {
            if evidence.proposer_probation_passed && evidence.vote_only_missed_votes == 0 {
                return supervisor_decision(
                    RealignmentState::Active,
                    ValidatorSupervisorAction::PromoteToActive,
                    vec![
                        "proposer probation promotion proof passed without misses or divergence"
                            .to_string(),
                    ],
                    false,
                );
            }
            return supervisor_decision(
                RealignmentState::PendingReactivation,
                ValidatorSupervisorAction::ContinueProposerProbation,
                vec!["proposer probation remains active until promotion proof passes".to_string()],
                false,
            );
        }
        return supervisor_decision(
            RealignmentState::VoteOnly,
            ValidatorSupervisorAction::EnterVoteOnlyRejoin,
            vec!["exact finalized head and verified QC allow vote-only rejoin".to_string()],
            false,
        );
    }

    if evidence.qrpc_degraded {
        reasons.push("qRPC degraded".to_string());
    }
    if evidence.metrics_degraded {
        reasons.push("metrics degraded".to_string());
    }
    if !reasons.is_empty() {
        return supervisor_decision(
            RealignmentState::Active,
            ValidatorSupervisorAction::IsolateQrpcAndMetrics,
            reasons,
            false,
        );
    }

    supervisor_decision(
        RealignmentState::Active,
        ValidatorSupervisorAction::MaintainActiveDuties,
        Vec::new(),
        false,
    )
}

fn supervisor_decision(
    state: RealignmentState,
    action: ValidatorSupervisorAction,
    reasons: Vec<String>,
    fail_closed: bool,
) -> ValidatorSupervisorDecision {
    ValidatorSupervisorDecision {
        state,
        duty_gate: ValidatorDutyGate::for_state(state),
        action,
        reasons,
        fail_closed,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorLifecycleState {
    pub validator: ValidatorRecord,
    pub stake: Option<ValidatorStakeRecord>,
    pub completed_steps: Vec<ValidatorStatus>,
    pub blocking_reason: String,
}

impl ValidatorLifecycleState {
    pub fn new(validator: ValidatorRecord) -> Self {
        Self {
            validator,
            stake: None,
            completed_steps: Vec::new(),
            blocking_reason: String::new(),
        }
    }
}

#[derive(Debug, Default)]
pub struct ValidatorLifecycleManager {
    states: BTreeMap<String, ValidatorLifecycleState>,
}

impl ValidatorLifecycleManager {
    pub fn insert(&mut self, state: ValidatorLifecycleState) {
        self.states
            .insert(state.validator.validator_id.0.clone(), state);
    }

    pub fn state(&self, validator_id: &str) -> Option<&ValidatorLifecycleState> {
        self.states.get(validator_id)
    }

    pub fn state_mut(&mut self, validator_id: &str) -> Option<&mut ValidatorLifecycleState> {
        self.states.get_mut(validator_id)
    }

    pub fn key_bound_requires_stake(&mut self, validator_id: &str) -> Result<(), String> {
        let state = self
            .state_mut(validator_id)
            .ok_or_else(|| "validator lifecycle state not found".to_string())?;
        if state.validator.status != ValidatorStatus::KeyBound {
            return Err("validator must be KEY_BOUND before STAKE_REQUIRED".to_string());
        }
        state.completed_steps.push(ValidatorStatus::KeyBound);
        state.validator.status = ValidatorStatus::StakeRequired;
        state.blocking_reason = "Stake 50,000 SNRG to continue validator onboarding.".to_string();
        Ok(())
    }

    pub fn submit_stake(
        &mut self,
        validator_id: &str,
        stake: ValidatorStakeRecord,
        stake_tx: &Transaction,
        verifier: &AegisPqvmVerifier,
    ) -> Result<(), String> {
        let state = self
            .state_mut(validator_id)
            .ok_or_else(|| "validator lifecycle state not found".to_string())?;
        if state.validator.status != ValidatorStatus::StakeRequired {
            return Err("stake can only be submitted from STAKE_REQUIRED".to_string());
        }
        stake_tx.chain_id.require_testnet_v3()?;
        stake_tx.network_id.require_testnet_v3()?;
        verifier
            .verify_transaction_signature_checked(stake_tx)
            .map_err(|error| error.to_string())?;
        if stake.validator_id != state.validator.validator_id
            || stake.validator_uma_id != state.validator.validator_uma_id
        {
            return Err("stake record is not assigned to this validator identity".to_string());
        }
        if stake.stake_owner != stake_tx.signer_uma_id.0 {
            return Err("stake owner does not match the staking transaction signer".to_string());
        }
        if stake.stake_status != StakeStatus::Submitted || stake.stake_verified {
            return Err("stake submission must be pending finality and unverified".to_string());
        }
        if stake.stake_amount_nwei < REQUIRED_VALIDATOR_STAKE_NWEI {
            state.blocking_reason = "Submitted stake is below 50,000 SNRG.".to_string();
            return Err("insufficient validator stake".to_string());
        }
        if stake.required_stake_nwei != REQUIRED_VALIDATOR_STAKE_NWEI {
            return Err("stake record required amount does not match protocol minimum".to_string());
        }
        state.stake = Some(stake);
        state.completed_steps.push(ValidatorStatus::StakeRequired);
        state.validator.status = ValidatorStatus::StakeSubmitted;
        state.blocking_reason = "Stake transaction is pending finality.".to_string();
        Ok(())
    }

    pub fn confirm_stake(
        &mut self,
        validator_id: &str,
        finalized_qc: &QuorumCertificate,
        validator_set: &ValidatorSet,
        height_context: &crate::synergy_types::HeightConsensusContext,
        verifier: &AegisPqvmVerifier,
    ) -> Result<(), String> {
        let state = self
            .state_mut(validator_id)
            .ok_or_else(|| "validator lifecycle state not found".to_string())?;
        if state.validator.status != ValidatorStatus::StakeSubmitted {
            return Err("stake can only be confirmed from STAKE_SUBMITTED".to_string());
        }
        let stake = state
            .stake
            .as_mut()
            .ok_or_else(|| "stake record missing".to_string())?;
        if stake.validator_id != state.validator.validator_id
            || stake.validator_uma_id != state.validator.validator_uma_id
        {
            return Err("stake record is not assigned to this validator identity".to_string());
        }
        if stake.stake_status != StakeStatus::Submitted {
            return Err("stake record is not a pending finalized staking transaction".to_string());
        }
        if !verifier.verify_qc(
            finalized_qc,
            validator_set,
            &crate::synergy_types::ClusterMap {
                epoch: validator_set.epoch,
                assignments: validator_set
                    .validators
                    .iter()
                    .map(|record| crate::synergy_types::ClusterAssignment {
                        cluster_id: record.cluster_id,
                        validator_id: record.validator_id.clone(),
                    })
                    .collect(),
            },
            height_context,
        ) {
            stake.stake_status = StakeStatus::InvalidSignature;
            return Err("stake finalized block QC failed Aegis PQC verification".to_string());
        }
        if stake.stake_amount_nwei < REQUIRED_VALIDATOR_STAKE_NWEI {
            stake.stake_status = StakeStatus::Insufficient;
            return Err("stake below required minimum".to_string());
        }
        if stake.stake_finalized_height != finalized_qc.height {
            return Err("stake finalized height does not match finalized QC height".to_string());
        }
        if !stake.stake_slashable {
            return Err("stake lock is not slashable under validator rules".to_string());
        }
        stake.stake_status = StakeStatus::Locked;
        stake.stake_verified = true;
        stake.stake_finalized_qc_hash = crate::synergy_types::Hash::from_domain_bytes(
            "SYNERGY_STAKE_FINALIZED_QC_V1",
            &finalized_qc.canonical_bytes()?,
        );
        state.completed_steps.push(ValidatorStatus::StakeSubmitted);
        state.validator.status = ValidatorStatus::StakeConfirmed;
        state.blocking_reason.clear();
        Ok(())
    }

    pub fn advance_after_stake(
        &mut self,
        validator_id: &str,
        next_status: ValidatorStatus,
        protocol: &ProtocolConfig,
    ) -> Result<(), String> {
        let state = self
            .state_mut(validator_id)
            .ok_or_else(|| "validator lifecycle state not found".to_string())?;
        if matches!(
            next_status,
            ValidatorStatus::Syncing
                | ValidatorStatus::SnapshotVerified
                | ValidatorStatus::Replaying
                | ValidatorStatus::Shadow
                | ValidatorStatus::Ready
                | ValidatorStatus::PendingActivation
                | ValidatorStatus::Active
        ) {
            let stake = state.stake.as_ref().ok_or_else(|| {
                "confirmed stake is required before onboarding can continue".to_string()
            })?;
            if !stake.satisfies_required_stake(protocol) {
                return Err(
                    "confirmed finalized locked stake is required before onboarding can continue"
                        .to_string(),
                );
            }
        }
        let expected_next = match state.validator.status {
            ValidatorStatus::StakeConfirmed => Some(ValidatorStatus::Syncing),
            ValidatorStatus::Syncing => Some(ValidatorStatus::SnapshotVerified),
            ValidatorStatus::SnapshotVerified => Some(ValidatorStatus::Replaying),
            ValidatorStatus::Replaying => Some(ValidatorStatus::Shadow),
            ValidatorStatus::Shadow => Some(ValidatorStatus::Ready),
            ValidatorStatus::Ready => Some(ValidatorStatus::PendingActivation),
            ValidatorStatus::PendingActivation => Some(ValidatorStatus::Active),
            _ => None,
        };
        if expected_next.as_ref() != Some(&next_status) {
            return Err(format!(
                "validator cannot skip onboarding stages after stake confirmation; current={:?}, requested={:?}",
                state.validator.status, next_status
            ));
        }
        state.completed_steps.push(state.validator.status.clone());
        state.validator.status = next_status;
        Ok(())
    }

    pub fn can_vote(&self, validator_id: &str) -> bool {
        self.state(validator_id)
            .map(|state| state.validator.status == ValidatorStatus::Active)
            .unwrap_or(false)
    }

    pub fn can_propose(&self, validator_id: &str) -> bool {
        self.can_vote(validator_id)
    }
}

pub fn lifecycle_order() -> Vec<ValidatorStatus> {
    vec![
        ValidatorStatus::Registered,
        ValidatorStatus::KeyBound,
        ValidatorStatus::StakeRequired,
        ValidatorStatus::StakeSubmitted,
        ValidatorStatus::StakeConfirmed,
        ValidatorStatus::Syncing,
        ValidatorStatus::SnapshotVerified,
        ValidatorStatus::Replaying,
        ValidatorStatus::Shadow,
        ValidatorStatus::Ready,
        ValidatorStatus::PendingActivation,
        ValidatorStatus::Active,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aegis_pqvm::AegisPqvmSigner;
    use crate::synergy_types::{
        deterministic_test_height_context, AegisPqKeyId, AegisPqKeyRole, AegisPqSignature, BlockId,
        ChainId, ClusterAssignment, ClusterId, ClusterMap, Epoch, Hash, Height,
        HeightConsensusContext, NetworkId, QuorumCertificate, Round, TxId, UmaId, ValidatorId,
        ValidatorSet, Vote, VotePhase, POSY_PROTOCOL_VERSION,
    };
    use std::path::PathBuf;

    fn validator_state() -> (AegisPqvmSigner, ValidatorLifecycleState, AegisPqKeyId) {
        let mut signer = AegisPqvmSigner::initialize_required().unwrap();
        let key_id = signer
            .generate_and_register_key("uma-1", vec![AegisPqKeyRole::Transaction], Epoch(0))
            .unwrap();
        let public = signer.public_key_record(&key_id).unwrap();
        let validator = ValidatorRecord {
            validator_id: ValidatorId("validator-1".to_string()),
            validator_uma_id: UmaId("uma-1".to_string()),
            consensus_public_key: public.clone(),
            peer_public_key: public.clone(),
            operator_public_key: public,
            voting_weight: 1,
            status: ValidatorStatus::KeyBound,
            cluster_id: ClusterId(0),
            activation_epoch: Epoch(0),
        };
        (signer, ValidatorLifecycleState::new(validator), key_id)
    }

    fn stake_record(amount: u128) -> ValidatorStakeRecord {
        ValidatorStakeRecord {
            validator_id: ValidatorId("validator-1".to_string()),
            validator_uma_id: UmaId("uma-1".to_string()),
            stake_owner: "uma-1".to_string(),
            stake_amount_nwei: amount,
            required_stake_nwei: REQUIRED_VALIDATOR_STAKE_NWEI,
            stake_tx_hash: TxId("stake-tx".to_string()),
            stake_lock_id: "stake-lock".to_string(),
            stake_status: StakeStatus::Submitted,
            stake_finalized_height: Height(1),
            stake_finalized_block_hash: Hash::zero(),
            stake_finalized_qc_hash: Hash::zero(),
            stake_activation_epoch: Epoch(1),
            stake_unlock_epoch_optional: None,
            stake_slashable: true,
            stake_verified: false,
        }
    }

    fn signed_stake_tx(
        signer: &mut AegisPqvmSigner,
        key_id: &AegisPqKeyId,
        amount: u128,
    ) -> Transaction {
        let mut tx = Transaction {
            version: 1,
            chain_id: ChainId::synergy_testnet_v3(),
            network_id: NetworkId::synergy_testnet_v3(),
            epoch: Epoch(0),
            sender_uma_or_account: "uma-1".to_string(),
            receiver_uma_or_account: "validator-staking".to_string(),
            account_nonce_or_sequence: 0,
            amount_nwei: amount,
            gas_limit: 21_000,
            max_fee_nwei: 1,
            ttl_height: Height(10),
            explicit_dependencies: Vec::new(),
            read_set_hint: Vec::new(),
            write_set_hint: vec!["validator-stake:validator-1".to_string()],
            payload: b"validator-stake".to_vec(),
            signer_uma_id: UmaId("uma-1".to_string()),
            aegis_pq_key_id: key_id.clone(),
            aegis_pq_signature: AegisPqSignature {
                algorithm: String::new(),
                signature_bytes: Vec::new(),
            },
        };
        tx.aegis_pq_signature = signer
            .sign_transaction(&tx.signing_bytes().unwrap(), key_id)
            .unwrap();
        tx
    }

    fn finalized_stake_qc(
        signer: &mut AegisPqvmSigner,
    ) -> (ValidatorSet, HeightConsensusContext, QuorumCertificate) {
        let mut records = Vec::new();
        let mut key_ids = Vec::new();
        for index in 0..6 {
            let uma = format!("qc-uma-{index}");
            let key_id = signer
                .generate_and_register_key(&uma, vec![AegisPqKeyRole::ConsensusVote], Epoch(0))
                .unwrap();
            let public = signer.public_key_record(&key_id).unwrap();
            records.push(ValidatorRecord {
                validator_id: ValidatorId(format!("qc-validator-{index}")),
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
        let protocol = ProtocolConfig::testnet_v3();
        let height_context =
            deterministic_test_height_context(&set, &cluster, &protocol, Height(1), ClusterId(0));
        let height_context_root = height_context.root().unwrap();
        let block_id = BlockId::from("stake-finalized-block");
        let votes = (0..5)
            .map(|index| {
                let mut vote = Vote {
                    chain_id: ChainId::synergy_testnet_v3(),
                    network_id: NetworkId::synergy_testnet_v3(),
                    protocol_version: POSY_PROTOCOL_VERSION.to_string(),
                    height: Height(1),
                    round: Round(0),
                    epoch: Epoch(0),
                    cluster_id: ClusterId(0),
                    height_context_root,
                    phase: VotePhase::Finality,
                    block_id: block_id.clone(),
                    highest_prepared_vc_root: None,
                    validator_id: records[index].validator_id.clone(),
                    validator_uma_id: records[index].validator_uma_id.clone(),
                    key_id: key_ids[index].clone(),
                    active_validator_set_hash: set_hash,
                    cluster_map_hash: cluster_hash,
                    aegis_pq_signature: AegisPqSignature {
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
        let qc = QuorumCertificate {
            qc_version: 1,
            chain_id: ChainId::synergy_testnet_v3(),
            network_id: NetworkId::synergy_testnet_v3(),
            protocol_version: POSY_PROTOCOL_VERSION.to_string(),
            height: Height(1),
            round: Round(0),
            epoch: Epoch(0),
            cluster_id: ClusterId(0),
            height_context_root,
            phase: VotePhase::Finality,
            block_id,
            highest_prepared_vc_root: None,
            active_validator_set_hash: set_hash,
            cluster_map_hash: cluster_hash,
            threshold_weight_required: height_context.strict_weight_quorum().unwrap(),
            signed_weight: 5,
            signer_bitmap: vec![0b0001_1111],
            aegis_pq_signatures: votes
                .iter()
                .map(|vote| vote.aegis_pq_signature.clone())
                .collect(),
            aegis_pq_key_ids: key_ids[0..5].to_vec(),
        };
        (set, height_context, qc)
    }

    #[test]
    fn new_validator_enters_stake_required_after_key_bound() {
        let (_signer, state, _key_id) = validator_state();
        let mut manager = ValidatorLifecycleManager::default();
        manager.insert(state);
        manager.key_bound_requires_stake("validator-1").unwrap();
        assert_eq!(
            manager.state("validator-1").unwrap().validator.status,
            ValidatorStatus::StakeRequired
        );
    }

    #[test]
    fn validator_cannot_proceed_without_confirmed_stake() {
        let (_signer, state, _key_id) = validator_state();
        let mut manager = ValidatorLifecycleManager::default();
        manager.insert(state);
        manager.key_bound_requires_stake("validator-1").unwrap();
        assert!(manager
            .advance_after_stake(
                "validator-1",
                ValidatorStatus::Syncing,
                &ProtocolConfig::testnet_v3()
            )
            .is_err());
        assert!(!manager.can_vote("validator-1"));
        assert!(!manager.can_propose("validator-1"));
    }

    #[test]
    fn under_stake_is_rejected_and_exact_stake_submission_is_accepted() {
        let (mut signer, state, key_id) = validator_state();
        let verifier = signer.verifier();
        let mut manager = ValidatorLifecycleManager::default();
        manager.insert(state);
        manager.key_bound_requires_stake("validator-1").unwrap();
        let under = signed_stake_tx(&mut signer, &key_id, REQUIRED_VALIDATOR_STAKE_NWEI - 1);
        assert!(manager
            .submit_stake(
                "validator-1",
                stake_record(REQUIRED_VALIDATOR_STAKE_NWEI - 1),
                &under,
                &verifier
            )
            .is_err());

        let exact = signed_stake_tx(&mut signer, &key_id, REQUIRED_VALIDATOR_STAKE_NWEI);
        manager
            .submit_stake(
                "validator-1",
                stake_record(REQUIRED_VALIDATOR_STAKE_NWEI),
                &exact,
                &verifier,
            )
            .unwrap();
        assert_eq!(
            manager.state("validator-1").unwrap().validator.status,
            ValidatorStatus::StakeSubmitted
        );
    }

    #[test]
    fn wrong_chain_network_and_invalid_signature_stakes_are_rejected() {
        let (mut signer, state, key_id) = validator_state();
        let verifier = signer.verifier();
        let mut manager = ValidatorLifecycleManager::default();
        manager.insert(state);
        manager.key_bound_requires_stake("validator-1").unwrap();

        let mut wrong_chain = signed_stake_tx(&mut signer, &key_id, REQUIRED_VALIDATOR_STAKE_NWEI);
        wrong_chain.chain_id = ChainId(1263);
        assert!(manager
            .submit_stake(
                "validator-1",
                stake_record(REQUIRED_VALIDATOR_STAKE_NWEI),
                &wrong_chain,
                &verifier
            )
            .is_err());

        let mut wrong_network =
            signed_stake_tx(&mut signer, &key_id, REQUIRED_VALIDATOR_STAKE_NWEI);
        wrong_network.network_id = NetworkId("synergy-invalid-testnet".to_string());
        assert!(manager
            .submit_stake(
                "validator-1",
                stake_record(REQUIRED_VALIDATOR_STAKE_NWEI),
                &wrong_network,
                &verifier
            )
            .is_err());

        let mut invalid_sig = signed_stake_tx(&mut signer, &key_id, REQUIRED_VALIDATOR_STAKE_NWEI);
        invalid_sig.aegis_pq_signature.signature_bytes[0] ^= 0x01;
        assert!(manager
            .submit_stake(
                "validator-1",
                stake_record(REQUIRED_VALIDATOR_STAKE_NWEI),
                &invalid_sig,
                &verifier
            )
            .is_err());
    }

    #[test]
    fn confirmed_stake_gates_onboarding_order_and_all_active_permissions() {
        let (mut signer, state, key_id) = validator_state();
        let verifier = signer.verifier();
        let mut manager = ValidatorLifecycleManager::default();
        manager.insert(state);
        manager.key_bound_requires_stake("validator-1").unwrap();
        let tx = signed_stake_tx(&mut signer, &key_id, REQUIRED_VALIDATOR_STAKE_NWEI);
        manager
            .submit_stake(
                "validator-1",
                stake_record(REQUIRED_VALIDATOR_STAKE_NWEI),
                &tx,
                &verifier,
            )
            .unwrap();

        for status in [
            ValidatorStatus::Ready,
            ValidatorStatus::PendingActivation,
            ValidatorStatus::Active,
        ] {
            assert!(manager
                .advance_after_stake("validator-1", status, &ProtocolConfig::testnet_v3())
                .is_err());
        }
        assert!(!manager.can_vote("validator-1"));
        assert!(!manager.can_propose("validator-1"));

        let (validator_set, height_context, qc) = finalized_stake_qc(&mut signer);
        let verifier = signer.verifier();
        manager
            .confirm_stake(
                "validator-1",
                &qc,
                &validator_set,
                &height_context,
                &verifier,
            )
            .unwrap();
        assert!(manager
            .advance_after_stake(
                "validator-1",
                ValidatorStatus::Ready,
                &ProtocolConfig::testnet_v3()
            )
            .is_err());
        for status in [
            ValidatorStatus::Syncing,
            ValidatorStatus::SnapshotVerified,
            ValidatorStatus::Replaying,
            ValidatorStatus::Shadow,
            ValidatorStatus::Ready,
            ValidatorStatus::PendingActivation,
            ValidatorStatus::Active,
        ] {
            manager
                .advance_after_stake("validator-1", status, &ProtocolConfig::testnet_v3())
                .unwrap();
        }
        assert!(manager.can_vote("validator-1"));
        assert!(manager.can_propose("validator-1"));
    }

    #[test]
    fn unlocked_withdrawn_slashed_or_mismatched_stake_records_fail_closed() {
        let (mut signer, state, key_id) = validator_state();
        let verifier = signer.verifier();
        let tx = signed_stake_tx(&mut signer, &key_id, REQUIRED_VALIDATOR_STAKE_NWEI);

        for status in [
            StakeStatus::Unlocked,
            StakeStatus::Unlocking,
            StakeStatus::Slashed,
            StakeStatus::Finalized,
        ] {
            let mut manager = ValidatorLifecycleManager::default();
            manager.insert(state.clone());
            manager.key_bound_requires_stake("validator-1").unwrap();
            let mut stake = stake_record(REQUIRED_VALIDATOR_STAKE_NWEI);
            stake.stake_status = status;
            assert!(manager
                .submit_stake("validator-1", stake, &tx, &verifier)
                .is_err());
        }

        let mut manager = ValidatorLifecycleManager::default();
        manager.insert(state);
        manager.key_bound_requires_stake("validator-1").unwrap();
        let mut mismatched = stake_record(REQUIRED_VALIDATOR_STAKE_NWEI);
        mismatched.validator_id = ValidatorId("other-validator".to_string());
        assert!(manager
            .submit_stake("validator-1", mismatched, &tx, &verifier)
            .is_err());
    }

    #[test]
    fn over_stake_is_accepted_when_testnet_protocol_allows_it() {
        let (mut signer, state, key_id) = validator_state();
        let verifier = signer.verifier();
        let mut manager = ValidatorLifecycleManager::default();
        manager.insert(state);
        manager.key_bound_requires_stake("validator-1").unwrap();
        let amount = REQUIRED_VALIDATOR_STAKE_NWEI + 1;
        let tx = signed_stake_tx(&mut signer, &key_id, amount);
        manager
            .submit_stake("validator-1", stake_record(amount), &tx, &verifier)
            .unwrap();
        let (validator_set, height_context, qc) = finalized_stake_qc(&mut signer);
        let verifier = signer.verifier();
        manager
            .confirm_stake(
                "validator-1",
                &qc,
                &validator_set,
                &height_context,
                &verifier,
            )
            .unwrap();
        assert!(manager
            .advance_after_stake(
                "validator-1",
                ValidatorStatus::Syncing,
                &ProtocolConfig::testnet_v3()
            )
            .is_ok());
    }

    #[test]
    fn supervisor_quarantines_divergent_or_incomplete_canonical_state() {
        let decision = classify_validator_supervisor_state(&ValidatorSupervisorEvidence {
            local_block_hash_disagrees_with_canonical: true,
            canonical_lock_without_body: true,
            ..ValidatorSupervisorEvidence::default()
        });
        assert_eq!(decision.state, RealignmentState::Quarantined);
        assert_eq!(
            decision.action,
            ValidatorSupervisorAction::QuarantineAndPreserveEvidence
        );
        assert!(decision.fail_closed);
        assert!(!decision.can_vote());
        assert!(!decision.can_propose());
        assert!(decision
            .reasons
            .iter()
            .any(|reason| reason.contains("canonical proof")));
    }

    #[test]
    fn supervisor_fails_closed_on_digest_or_verification_failure() {
        let decision = classify_validator_supervisor_state(&ValidatorSupervisorEvidence {
            validator_set_digest_mismatch: true,
            state_sync_verification_failed: true,
            ..ValidatorSupervisorEvidence::default()
        });
        assert_eq!(decision.state, RealignmentState::FailedClosed);
        assert_eq!(
            decision.action,
            ValidatorSupervisorAction::FailClosedOperatorIntervention
        );
        assert!(decision.fail_closed);
        assert!(!decision.can_vote());
        assert!(!decision.can_propose());
    }

    #[test]
    fn supervisor_runs_verified_state_sync_when_local_height_stalls() {
        let decision = classify_validator_supervisor_state(&ValidatorSupervisorEvidence {
            local_finalized_height: 100,
            peer_finalized_height: 106,
            peer_advance_stall_blocks: Some(3),
            verified_state_sync_plan_available: true,
            ..ValidatorSupervisorEvidence::default()
        });
        assert_eq!(decision.state, RealignmentState::SpeedSyncing);
        assert_eq!(
            decision.action,
            ValidatorSupervisorAction::RunVerifiedStateSync
        );
        assert!(!decision.fail_closed);
        assert!(!decision.can_vote());
        assert!(!decision.can_propose());
    }

    #[test]
    fn supervisor_enters_vote_only_rejoin_from_exact_finalized_proof() {
        let decision = classify_validator_supervisor_state(&ValidatorSupervisorEvidence {
            exact_finalized_head_match: true,
            latest_qc_verified: true,
            no_unresolved_fork_evidence: true,
            ..ValidatorSupervisorEvidence::default()
        });
        assert_eq!(decision.state, RealignmentState::VoteOnly);
        assert_eq!(
            decision.action,
            ValidatorSupervisorAction::EnterVoteOnlyRejoin
        );
        assert!(decision.can_vote());
        assert!(!decision.can_propose());
        assert!(decision.duty_gate.can_count_toward_quorum);
    }

    #[test]
    fn supervisor_enters_proposer_probation_after_clean_vote_only_window() {
        let decision = classify_validator_supervisor_state(&ValidatorSupervisorEvidence {
            current_state: Some(RealignmentState::VoteOnly),
            exact_finalized_head_match: true,
            latest_qc_verified: true,
            no_unresolved_fork_evidence: true,
            vote_only_finalized_blocks: 1_000,
            vote_only_required_blocks: Some(1_000),
            vote_only_missed_votes: 0,
            ..ValidatorSupervisorEvidence::default()
        });
        assert_eq!(decision.state, RealignmentState::PendingReactivation);
        assert_eq!(
            decision.action,
            ValidatorSupervisorAction::EnterProposerProbation
        );
        assert!(!decision.can_vote());
        assert!(!decision.can_propose());
    }

    #[test]
    fn supervisor_promotes_proposer_probation_after_promotion_proof() {
        let decision = classify_validator_supervisor_state(&ValidatorSupervisorEvidence {
            current_state: Some(RealignmentState::PendingReactivation),
            exact_finalized_head_match: true,
            latest_qc_verified: true,
            no_unresolved_fork_evidence: true,
            proposer_probation_passed: true,
            vote_only_missed_votes: 0,
            ..ValidatorSupervisorEvidence::default()
        });
        assert_eq!(decision.state, RealignmentState::Active);
        assert_eq!(decision.action, ValidatorSupervisorAction::PromoteToActive);
        assert!(decision.can_vote());
        assert!(decision.can_propose());
    }

    #[test]
    fn supervisor_keeps_consensus_active_when_only_qrpc_or_metrics_degrade() {
        let decision = classify_validator_supervisor_state(&ValidatorSupervisorEvidence {
            qrpc_degraded: true,
            metrics_degraded: true,
            ..ValidatorSupervisorEvidence::default()
        });
        assert_eq!(decision.state, RealignmentState::Active);
        assert_eq!(
            decision.action,
            ValidatorSupervisorAction::IsolateQrpcAndMetrics
        );
        assert!(!decision.fail_closed);
        assert!(decision.can_vote());
        assert!(decision.can_propose());
    }

    fn persisted_supervisor_state(
        state: RealignmentState,
        fail_closed: bool,
    ) -> ValidatorSupervisorPersistentState {
        ValidatorSupervisorPersistentState {
            schema: VALIDATOR_SUPERVISOR_STATE_SCHEMA.to_string(),
            sequence: 7,
            validator_id: "validator-1".to_string(),
            cluster_id: "cluster-1".to_string(),
            state,
            lifecycle_state: Some(state),
            duty_gate: ValidatorDutyGate::for_state(state),
            last_action: ValidatorSupervisorAction::CollectEvidence,
            previous_state: None,
            transition_reason: "test fixture".to_string(),
            evidence_hash: hex::encode([1_u8; 32]),
            evidence_path: None,
            evidence_created_at_unix: current_unix_secs(),
            created_at_unix: current_unix_secs(),
            safe_to_vote: ValidatorDutyGate::for_state(state).can_vote,
            safe_to_propose: ValidatorDutyGate::for_state(state).can_propose,
            safe_to_aggregate_qc: ValidatorDutyGate::for_state(state).can_aggregate_qc,
            counts_toward_quorum: ValidatorDutyGate::for_state(state).can_count_toward_quorum,
            fail_closed,
            reasons: Vec::new(),
            blocked_reasons: Vec::new(),
            next_recommended_actions: Vec::new(),
            local_finalized_height: 100,
            peer_finalized_height: 100,
            vote_only_finalized_blocks: 0,
        }
    }

    #[test]
    fn supervisor_transition_persists_new_quarantine_decision() {
        let report = plan_validator_supervisor_transition(&ValidatorSupervisorTransitionInput {
            previous: Some(persisted_supervisor_state(RealignmentState::Active, false)),
            evidence: ValidatorSupervisorEvidence {
                compact_boundary_lock_missing: true,
                compact_boundary_qc_missing: true,
                local_finalized_height: 175_518,
                peer_finalized_height: 175_520,
                ..ValidatorSupervisorEvidence::default()
            },
        });
        assert!(!report.ok);
        assert_eq!(report.previous_sequence, Some(7));
        assert_eq!(report.persistent_state.sequence, 8);
        assert_eq!(report.persistent_state.state, RealignmentState::Quarantined);
        assert!(report.persistent_state.fail_closed);
        assert_eq!(report.persistent_state.validator_id, "");
        assert!(!report.persistent_state.duty_gate.can_vote);
        assert!(report.write_recommended);
    }

    #[test]
    fn supervisor_transition_refuses_direct_recovery_state_to_active() {
        let report = plan_validator_supervisor_transition(&ValidatorSupervisorTransitionInput {
            previous: Some(persisted_supervisor_state(
                RealignmentState::EvidencePreserved,
                false,
            )),
            evidence: ValidatorSupervisorEvidence {
                local_finalized_height: 200,
                peer_finalized_height: 200,
                ..ValidatorSupervisorEvidence::default()
            },
        });
        assert!(report.ok);
        assert_eq!(report.decision.state, RealignmentState::Suspect);
        assert_eq!(
            report.decision.action,
            ValidatorSupervisorAction::CollectEvidence
        );
        assert!(report
            .decision
            .reasons
            .iter()
            .any(|reason| reason.contains("cannot return directly to active")));
        assert!(!report.persistent_state.duty_gate.can_vote);
    }

    #[test]
    fn supervisor_transition_allows_vote_only_after_verified_rejoin_proof() {
        let report = plan_validator_supervisor_transition(&ValidatorSupervisorTransitionInput {
            previous: Some(persisted_supervisor_state(
                RealignmentState::EvidencePreserved,
                false,
            )),
            evidence: ValidatorSupervisorEvidence {
                exact_finalized_head_match: true,
                latest_qc_verified: true,
                no_unresolved_fork_evidence: true,
                local_finalized_height: 300,
                peer_finalized_height: 300,
                ..ValidatorSupervisorEvidence::default()
            },
        });
        assert!(report.ok, "{:?}", report.decision.reasons);
        assert_eq!(report.decision.state, RealignmentState::VoteOnly);
        assert_eq!(
            report.decision.action,
            ValidatorSupervisorAction::EnterVoteOnlyRejoin
        );
        assert!(report.persistent_state.duty_gate.can_vote);
        assert!(!report.persistent_state.duty_gate.can_propose);
        assert!(report
            .transition_notes
            .iter()
            .any(|note| { note == "vote_only_rejoin_requires_persisted_probation_state" }));
    }

    #[test]
    fn supervisor_transition_preserves_previous_failed_closed_state() {
        let report = plan_validator_supervisor_transition(&ValidatorSupervisorTransitionInput {
            previous: Some(persisted_supervisor_state(
                RealignmentState::FailedClosed,
                true,
            )),
            evidence: ValidatorSupervisorEvidence {
                local_finalized_height: 400,
                peer_finalized_height: 400,
                ..ValidatorSupervisorEvidence::default()
            },
        });
        assert!(!report.ok);
        assert_eq!(report.decision.state, RealignmentState::FailedClosed);
        assert_eq!(
            report.decision.action,
            ValidatorSupervisorAction::FailClosedOperatorIntervention
        );
        assert!(!report.persistent_state.duty_gate.can_vote);
        assert!(report
            .decision
            .reasons
            .iter()
            .any(|reason| reason.contains("explicit governed reset")));
    }

    fn supervisor_workspace(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = crate::utils::test_temp_root(format!("synergy-supervisor-{label}-{unique}"));
        fs::create_dir_all(root.join("supervisor")).unwrap();
        fs::write(
            root.join(VALIDATOR_SUPERVISOR_WORKSPACE_MARKER),
            "fixture\n",
        )
        .unwrap();
        root
    }

    fn supervisor_state_path(root: &std::path::Path) -> PathBuf {
        root.join(VALIDATOR_SUPERVISOR_STATE_RELATIVE_PATH)
    }

    fn clean_supervisor_evidence(state: Option<RealignmentState>) -> ValidatorSupervisorEvidence {
        ValidatorSupervisorEvidence {
            validator_id: Some("validator-1".to_string()),
            cluster_id: Some("cluster-1".to_string()),
            evidence_created_at_unix: Some(current_unix_secs()),
            current_state: state,
            local_finalized_height: 500,
            peer_finalized_height: 500,
            ..ValidatorSupervisorEvidence::default()
        }
    }

    fn transition_for(
        previous: Option<ValidatorSupervisorPersistentState>,
        evidence: ValidatorSupervisorEvidence,
    ) -> ValidatorSupervisorTransitionReport {
        plan_validator_supervisor_transition(&ValidatorSupervisorTransitionInput {
            previous,
            evidence,
        })
    }

    fn write_codes(report: &ValidatorSupervisorWriteReport) -> Vec<String> {
        report
            .findings
            .iter()
            .map(|finding| finding.code.clone())
            .collect()
    }

    #[test]
    fn supervisor_write_dry_run_does_not_mutate() {
        let root = supervisor_workspace("dry-run");
        let transition = transition_for(None, clean_supervisor_evidence(None));
        let report = write_validator_supervisor_state(
            &transition,
            &root,
            ValidatorSupervisorWriteOptions {
                dry_run: true,
                apply: false,
            },
        )
        .unwrap();

        assert!(report.ok, "{:?}", report.findings);
        assert_eq!(report.decision, "DRY_RUN_GO");
        assert!(!supervisor_state_path(&root).exists());
    }

    #[test]
    fn supervisor_write_apply_writes_atomically_and_backs_up_previous_state() {
        let root = supervisor_workspace("apply-backup");
        let first = transition_for(None, clean_supervisor_evidence(None));
        write_validator_supervisor_state(
            &first,
            &root,
            ValidatorSupervisorWriteOptions {
                dry_run: false,
                apply: true,
            },
        )
        .unwrap();
        let previous: ValidatorSupervisorPersistentState =
            serde_json::from_slice(&fs::read(supervisor_state_path(&root)).unwrap()).unwrap();
        let second = transition_for(
            Some(previous),
            ValidatorSupervisorEvidence {
                qrpc_degraded: true,
                metrics_degraded: true,
                ..clean_supervisor_evidence(None)
            },
        );
        let report = write_validator_supervisor_state(
            &second,
            &root,
            ValidatorSupervisorWriteOptions {
                dry_run: false,
                apply: true,
            },
        )
        .unwrap();

        assert!(report.ok, "{:?}", report.findings);
        assert!(report.applied);
        assert!(PathBuf::from(report.backup_path.unwrap()).is_file());
        let persisted: ValidatorSupervisorPersistentState =
            serde_json::from_slice(&fs::read(supervisor_state_path(&root)).unwrap()).unwrap();
        assert_eq!(persisted.sequence, 2);
        assert_eq!(persisted.evidence_path, None);
    }

    #[test]
    fn supervisor_write_malformed_previous_state_fails_closed() {
        let root = supervisor_workspace("malformed-previous");
        fs::write(supervisor_state_path(&root), "{not-json}\n").unwrap();
        let transition = transition_for(None, clean_supervisor_evidence(None));
        let report = write_validator_supervisor_state(
            &transition,
            &root,
            ValidatorSupervisorWriteOptions {
                dry_run: false,
                apply: true,
            },
        )
        .unwrap();

        assert!(!report.ok);
        assert!(write_codes(&report).contains(&"supervisor_previous_state_malformed".to_string()));
    }

    #[test]
    fn supervisor_write_requires_monotonic_sequence_and_fresh_evidence() {
        let root = supervisor_workspace("sequence-stale");
        let previous = persisted_supervisor_state(RealignmentState::Active, false);
        fs::write(
            supervisor_state_path(&root),
            serde_json::to_vec_pretty(&previous).unwrap(),
        )
        .unwrap();
        let mut transition = transition_for(Some(previous), clean_supervisor_evidence(None));
        transition.persistent_state.sequence = 7;
        transition.persistent_state.evidence_created_at_unix =
            current_unix_secs() - MAX_SUPERVISOR_EVIDENCE_AGE_SECS - 1;
        let report = write_validator_supervisor_state(
            &transition,
            &root,
            ValidatorSupervisorWriteOptions {
                dry_run: false,
                apply: true,
            },
        )
        .unwrap();

        assert!(!report.ok);
        let codes = write_codes(&report);
        assert!(codes.contains(&"supervisor_sequence_not_monotonic".to_string()));
        assert!(codes.contains(&"supervisor_evidence_stale".to_string()));
    }

    #[test]
    fn supervisor_write_rejects_direct_recovery_or_failed_closed_to_active() {
        for (state, code) in [
            (
                RealignmentState::Quarantined,
                "supervisor_recovery_state_to_active_rejected",
            ),
            (
                RealignmentState::FailedClosed,
                "supervisor_failed_closed_to_active_rejected",
            ),
        ] {
            let root = supervisor_workspace("direct-active");
            let previous =
                persisted_supervisor_state(state, state == RealignmentState::FailedClosed);
            fs::write(
                supervisor_state_path(&root),
                serde_json::to_vec_pretty(&previous).unwrap(),
            )
            .unwrap();
            let mut transition = transition_for(Some(previous), clean_supervisor_evidence(None));
            transition.previous_state = Some(state);
            transition.decision.state = RealignmentState::Active;
            transition.decision.duty_gate = ValidatorDutyGate::for_state(RealignmentState::Active);
            transition.persistent_state.state = RealignmentState::Active;
            transition.persistent_state.lifecycle_state = Some(RealignmentState::Active);
            transition.persistent_state.duty_gate =
                ValidatorDutyGate::for_state(RealignmentState::Active);
            transition.persistent_state.previous_state = Some(state);
            transition.persistent_state.fail_closed = false;
            transition.persistent_state.blocked_reasons = Vec::new();
            transition.persistent_state.safe_to_vote = true;
            transition.persistent_state.safe_to_propose = true;
            transition.persistent_state.safe_to_aggregate_qc = true;
            transition.persistent_state.counts_toward_quorum = true;

            let report = write_validator_supervisor_state(
                &transition,
                &root,
                ValidatorSupervisorWriteOptions {
                    dry_run: false,
                    apply: true,
                },
            )
            .unwrap();
            assert!(!report.ok);
            assert!(write_codes(&report).contains(&code.to_string()));
        }
    }

    #[test]
    fn supervisor_write_verified_rejoin_writes_vote_only() {
        let root = supervisor_workspace("vote-only");
        let previous = persisted_supervisor_state(RealignmentState::EvidencePreserved, false);
        fs::write(
            supervisor_state_path(&root),
            serde_json::to_vec_pretty(&previous).unwrap(),
        )
        .unwrap();
        let transition = transition_for(
            Some(previous),
            ValidatorSupervisorEvidence {
                exact_finalized_head_match: true,
                latest_qc_verified: true,
                no_unresolved_fork_evidence: true,
                ..clean_supervisor_evidence(None)
            },
        );
        let report = write_validator_supervisor_state(
            &transition,
            &root,
            ValidatorSupervisorWriteOptions {
                dry_run: false,
                apply: true,
            },
        )
        .unwrap();

        assert!(report.ok, "{:?}", report.findings);
        let persisted: ValidatorSupervisorPersistentState =
            serde_json::from_slice(&fs::read(supervisor_state_path(&root)).unwrap()).unwrap();
        assert_eq!(persisted.state, RealignmentState::VoteOnly);
        assert!(persisted.safe_to_vote);
        assert!(!persisted.safe_to_propose);
    }

    #[test]
    fn supervisor_write_probation_then_active_only_with_promotion_proof() {
        let root = supervisor_workspace("probation-active");
        let vote_only = persisted_supervisor_state(RealignmentState::VoteOnly, false);
        fs::write(
            supervisor_state_path(&root),
            serde_json::to_vec_pretty(&vote_only).unwrap(),
        )
        .unwrap();
        let probation = transition_for(
            Some(vote_only),
            ValidatorSupervisorEvidence {
                current_state: Some(RealignmentState::VoteOnly),
                exact_finalized_head_match: true,
                latest_qc_verified: true,
                no_unresolved_fork_evidence: true,
                vote_only_finalized_blocks: 1_000,
                vote_only_required_blocks: Some(1_000),
                vote_only_missed_votes: 0,
                ..clean_supervisor_evidence(Some(RealignmentState::VoteOnly))
            },
        );
        assert_eq!(
            probation.persistent_state.state,
            RealignmentState::PendingReactivation
        );
        let report = write_validator_supervisor_state(
            &probation,
            &root,
            ValidatorSupervisorWriteOptions {
                dry_run: false,
                apply: true,
            },
        )
        .unwrap();
        assert!(report.ok, "{:?}", report.findings);
        let persisted: ValidatorSupervisorPersistentState =
            serde_json::from_slice(&fs::read(supervisor_state_path(&root)).unwrap()).unwrap();
        assert_eq!(persisted.state, RealignmentState::PendingReactivation);
        assert!(!persisted.safe_to_propose);

        let active = transition_for(
            Some(persisted),
            ValidatorSupervisorEvidence {
                current_state: Some(RealignmentState::PendingReactivation),
                exact_finalized_head_match: true,
                latest_qc_verified: true,
                no_unresolved_fork_evidence: true,
                proposer_probation_passed: true,
                vote_only_missed_votes: 0,
                ..clean_supervisor_evidence(Some(RealignmentState::PendingReactivation))
            },
        );
        assert_eq!(active.persistent_state.state, RealignmentState::Active);
        let report = write_validator_supervisor_state(
            &active,
            &root,
            ValidatorSupervisorWriteOptions {
                dry_run: false,
                apply: true,
            },
        )
        .unwrap();
        assert!(report.ok, "{:?}", report.findings);
        let persisted: ValidatorSupervisorPersistentState =
            serde_json::from_slice(&fs::read(supervisor_state_path(&root)).unwrap()).unwrap();
        assert_eq!(persisted.state, RealignmentState::Active);
        assert!(persisted.safe_to_vote);
        assert!(persisted.safe_to_propose);
    }

    #[test]
    fn supervisor_maps_validator_status_to_realignment_duty_gate() {
        assert_eq!(
            supervisor_state_for_validator_status(&ValidatorStatus::SelfQuarantinedDivergence),
            RealignmentState::Quarantined
        );
        assert!(
            !supervisor_duty_gate_for_validator_status(&ValidatorStatus::SelfQuarantinedDivergence)
                .can_vote
        );
        assert_eq!(
            supervisor_state_for_validator_status(&ValidatorStatus::RejoiningConsensus),
            RealignmentState::VoteOnly
        );
        let gate = supervisor_duty_gate_for_validator_status(&ValidatorStatus::RejoiningConsensus);
        assert!(gate.can_vote);
        assert!(!gate.can_propose);
    }
}
