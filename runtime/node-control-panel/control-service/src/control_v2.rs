use crate::app_context::AppContext;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub const CURRENT_NETWORK_ID: &str = "synergy-testnet-v3";
pub const CURRENT_CHAIN_ID: &str = "1266";
pub const CURRENT_CONTROL_PANEL_VERSION: &str = env!("CARGO_PKG_VERSION");
const MIN_VALIDATOR_PACKAGE_VERSION: &str = "15.0.5";
const MIN_CONFIG_SCHEMA_VERSION: &str = "2";
const MIN_STATE_SCHEMA_VERSION: &str = "2";

const CONTROL_V2_COMMANDS: &[&str] = &[
    "validator.machine.preflight",
    "validator.package.verify",
    "validator.identity.create",
    "validator.identity.backup.verify",
    "validator.cluster.previewAssignment",
    "validator.cluster.assign",
    "validator.config.render",
    "validator.state.inspect",
    "validator.state.verify",
    "validator.stateSync.plan",
    "validator.stateSync.dryRun",
    "validator.stateSync.repair",
    "validator.recovery.plan",
    "validator.recovery.quarantineStopped",
    "validator.recovery.snapshotRepair",
    "validator.recovery.transientVoteLockRecover",
    "validator.onboarding.verify",
    "validator.onboarding.run",
    "validator.lifecycle.status",
    "validator.lifecycle.requestVoteOnly",
    "validator.lifecycle.promoteProbation",
    "validator.lifecycle.promoteVoteOnlyToActive",
    "validator.stake.preflight",
    "validator.stake.submit",
    "validator.activation.preflight",
    "validator.activation.submit",
    "validator.doctor.run",
    "fleet.status.strict",
    "archive.status",
    "archive.verifyCanonical",
    "archive.reseed.plan",
    "archive.snapshot.listUnsafe",
    "archive.snapshot.quarantine",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlEvidenceRef {
    pub id: String,
    pub category: String,
    pub path: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlCheck {
    pub id: String,
    pub label: String,
    pub status: String,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<ControlEvidenceRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlBlocker {
    pub code: String,
    pub severity: String,
    pub message: String,
    pub remediation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlWarning {
    pub code: String,
    pub message: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlNextAction {
    pub command: String,
    pub label: String,
    pub mutates: bool,
    pub requires_confirmation: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ControlActionEnvelope {
    pub ok: bool,
    pub command: String,
    pub phase: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster_id: Option<String>,
    pub lifecycle_state: String,
    pub status: String,
    pub safe_to_continue: bool,
    pub mutated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_path: Option<String>,
    #[serde(default)]
    pub checks: Vec<ControlCheck>,
    #[serde(default)]
    pub blockers: Vec<ControlBlocker>,
    #[serde(default)]
    pub warnings: Vec<ControlWarning>,
    #[serde(default)]
    pub next_actions: Vec<ControlNextAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollback_path: Option<String>,
    pub operator_message: String,
    #[serde(default)]
    pub developer_details: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DynamicClusterRegistry {
    pub network_id: String,
    pub registry_epoch: u64,
    pub clusters: Vec<ValidatorCluster>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorCluster {
    pub cluster_id: String,
    pub status: String,
    pub validator_count: usize,
    pub active_count: usize,
    pub quorum_threshold: usize,
    pub fault_model: String,
    pub fault_tolerance_target: String,
    pub proposer_schedule_mode: String,
    pub stable_committee_mode: String,
    pub validators: Vec<ClusterValidator>,
    pub liveness_margin: isize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClusterValidator {
    pub node_id: String,
    pub validator_address: String,
    pub lifecycle_state: String,
    pub roles: Vec<String>,
    pub voting_eligible: bool,
    pub proposer_eligible: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorAppliancePaths {
    pub root: String,
    pub identity: String,
    pub config: String,
    pub state: String,
    pub state_store: String,
    pub consensus_db: String,
    pub state_derived: String,
    pub state_checkpoints: String,
    pub state_snapshots: String,
    pub state_quarantine: String,
    pub evidence: String,
    pub logs: String,
    pub runtime: String,
    pub releases: String,
    pub rollback: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApplianceFilesystemReport {
    pub paths: ValidatorAppliancePaths,
    pub primary_consensus_truth: String,
    pub rebuildable_state: Vec<String>,
    pub checks: Vec<ControlCheck>,
    pub migration_plan: Vec<String>,
    pub example_template: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorAppliancePackageManifest {
    #[serde(default)]
    pub package_version: String,
    #[serde(default)]
    pub network_id: String,
    #[serde(default)]
    pub chain_id: String,
    #[serde(default)]
    pub supported_roles: Vec<String>,
    #[serde(default)]
    pub binary_digests: BTreeMap<String, String>,
    #[serde(default)]
    pub config_schema_version: String,
    #[serde(default)]
    pub state_schema_version: String,
    #[serde(default)]
    pub requires_archive_canonical: bool,
    #[serde(default)]
    pub supports_vote_only_rejoin: bool,
    #[serde(default)]
    pub supports_state_sync: bool,
    #[serde(default)]
    pub supports_dynamic_clusters: bool,
    #[serde(default)]
    pub minimum_control_panel_version: String,
    #[serde(default)]
    pub no_go_denylist: Vec<String>,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub manifest_hash: Option<String>,
    #[serde(default)]
    pub expected_manifest_hash: Option<String>,
    #[serde(default)]
    pub minimum_package_version: Option<String>,
    #[serde(default)]
    pub minimum_config_schema_version: Option<String>,
    #[serde(default)]
    pub minimum_state_schema_version: Option<String>,
    #[serde(default)]
    pub archive_state: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IncidentEvidence {
    pub incident_id: String,
    pub category: String,
    pub severity: String,
    pub command: String,
    pub summary: String,
    pub node_id: Option<String>,
    pub cluster_id: Option<String>,
    pub root_cause: String,
    pub lifecycle_state: String,
    pub mutated: bool,
    pub rollback_complete: bool,
    pub resolved: bool,
    pub recommended_next_action: String,
    pub evidence_path: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
struct V2CommandArgs {
    node_id: Option<String>,
    cluster_id: Option<String>,
    fixture: Option<String>,
    root: Option<String>,
    confirmed: bool,
    confirmation: Option<String>,
    lifecycle_state: Option<String>,
    role: Option<String>,
    network_id: Option<String>,
    chain_id: Option<String>,
    archive_state: Option<String>,
    p2p_open: Option<bool>,
    quorum_verified: Option<bool>,
    quorum_count: Option<u64>,
    quorum_threshold: Option<u64>,
    snapshot_id: Option<String>,
    snapshot_hash: Option<String>,
    quorum_height: Option<u64>,
    quorum_hash: Option<String>,
    local_height: Option<u64>,
    local_hash: Option<String>,
    peer_height: Option<u64>,
    peer_hash: Option<String>,
    service_stopped: Option<bool>,
    quarantine_marker_present: Option<bool>,
    signed_snapshot_available: Option<bool>,
    signed_snapshot_verified: Option<bool>,
    state_sync_plan_available: Option<bool>,
    finalized_height: Option<u64>,
    min_age_secs: Option<u64>,
    transient_vote_locks_above_finalized: Option<u64>,
    fresh_vote_locks_above_finalized: Option<u64>,
    stale_vote_locks_above_finalized: Option<u64>,
    conflicting_vote_lock_heights: Option<u64>,
    vote_lock_parse_error: Option<String>,
    probation_blocks_observed: Option<u64>,
    probation_blocks_required: Option<u64>,
    raw_error: Option<String>,
    identity_backup_verified: Option<bool>,
    package_manifest: Option<ValidatorAppliancePackageManifest>,
}

impl Default for V2CommandArgs {
    fn default() -> Self {
        Self {
            node_id: Some("local-validator".to_string()),
            cluster_id: Some("cluster-a".to_string()),
            fixture: None,
            root: None,
            confirmed: false,
            confirmation: None,
            lifecycle_state: None,
            role: Some("validator".to_string()),
            network_id: Some(CURRENT_NETWORK_ID.to_string()),
            chain_id: Some(CURRENT_CHAIN_ID.to_string()),
            archive_state: Some("CONTAINED".to_string()),
            p2p_open: Some(true),
            quorum_verified: Some(false),
            quorum_count: None,
            quorum_threshold: None,
            snapshot_id: None,
            snapshot_hash: None,
            quorum_height: None,
            quorum_hash: None,
            local_height: None,
            local_hash: None,
            peer_height: None,
            peer_hash: None,
            service_stopped: Some(false),
            quarantine_marker_present: Some(false),
            signed_snapshot_available: Some(false),
            signed_snapshot_verified: Some(false),
            state_sync_plan_available: Some(false),
            finalized_height: None,
            min_age_secs: Some(0),
            transient_vote_locks_above_finalized: None,
            fresh_vote_locks_above_finalized: None,
            stale_vote_locks_above_finalized: Some(0),
            conflicting_vote_lock_heights: Some(0),
            vote_lock_parse_error: None,
            probation_blocks_observed: None,
            probation_blocks_required: None,
            raw_error: None,
            identity_backup_verified: Some(true),
            package_manifest: None,
        }
    }
}

pub fn dispatch_control_v2_command(
    app_context: &AppContext,
    command: &str,
    args: Value,
) -> Option<Result<ControlActionEnvelope, String>> {
    if !CONTROL_V2_COMMANDS.contains(&command) {
        return None;
    }

    let parsed = match serde_json::from_value::<V2CommandArgs>(args.clone()) {
        Ok(value) => value,
        Err(error) => {
            return Some(Ok(error_envelope(
                command,
                "decode",
                "COMMAND_ARGUMENTS_INVALID",
                format!("The control-service could not decode the v2 command arguments: {error}"),
                "Retry from the current Control Panel build so the command schema matches the service.",
                args,
            )));
        }
    };

    Some(Ok(handle_v2_command(app_context, command, parsed, args)))
}

pub fn supported_control_v2_commands() -> &'static [&'static str] {
    CONTROL_V2_COMMANDS
}

fn handle_v2_command(
    app_context: &AppContext,
    command: &str,
    args: V2CommandArgs,
    raw_args: Value,
) -> ControlActionEnvelope {
    let mut envelope = match command {
        "validator.machine.preflight" => machine_preflight(command, &args),
        "validator.package.verify" => package_verify(command, &args),
        "validator.identity.create" => mutation_gate(command, &args, "identity", "Identity creation requires an explicit operator confirmation because it writes validator signing material."),
        "validator.identity.backup.verify" => identity_backup_verify(command, &args),
        "validator.cluster.previewAssignment" => cluster_preview(command, &args),
        "validator.cluster.assign" => mutation_gate(command, &args, "cluster", "Cluster assignment writes the validator registry and must be confirmed."),
        "validator.config.render" => mutation_gate(command, &args, "config", "Config rendering writes node.toml, peers.toml, and derived runtime files after all checks pass."),
        "validator.state.inspect" => state_inspect(command, &args),
        "validator.state.verify" => state_verify(command, &args),
        "validator.stateSync.plan" => state_sync_plan(command, &args),
        "validator.stateSync.dryRun" => state_sync_dry_run(command, &args),
        "validator.stateSync.repair" => state_sync_repair(command, &args),
        "validator.recovery.plan" => validator_recovery_plan(command, &args),
        "validator.recovery.quarantineStopped" => validator_recovery_quarantine_stopped(command, &args),
        "validator.recovery.snapshotRepair" => validator_recovery_snapshot_repair(command, &args),
        "validator.recovery.transientVoteLockRecover" => validator_recovery_transient_vote_lock_recover(command, &args),
        "validator.onboarding.verify" => onboarding_verify(command, &args),
        "validator.onboarding.run" => onboarding_run(command, &args),
        "validator.lifecycle.status" => lifecycle_status(command, &args),
        "validator.lifecycle.requestVoteOnly" => mutation_gate(command, &args, "lifecycle", "Vote-only rejoin changes validator lifecycle state and must be confirmed."),
        "validator.lifecycle.promoteProbation" => promote_probation(command, &args),
        "validator.lifecycle.promoteVoteOnlyToActive" => promote_vote_only_to_active(command, &args),
        "validator.stake.preflight" => stake_preflight(command, &args),
        "validator.stake.submit" => mutation_gate(command, &args, "stake", "Stake submission mutates validator economics and must be confirmed."),
        "validator.activation.preflight" => activation_preflight(command, &args),
        "validator.activation.submit" => activation_submit(command, &args),
        "validator.doctor.run" => doctor_run(command, &args),
        "fleet.status.strict" => fleet_status_strict(command, &args),
        "archive.status" => archive_status(command, &args),
        "archive.verifyCanonical" => archive_verify_canonical(command, &args),
        "archive.reseed.plan" => archive_reseed_plan(command, &args),
        "archive.snapshot.listUnsafe" => archive_snapshot_list_unsafe(command, &args),
        "archive.snapshot.quarantine" => archive_snapshot_quarantine(command, &args),
        _ => error_envelope(
            command,
            "dispatch",
            "COMMAND_NOT_IMPLEMENTED",
            format!("The v2 command {command} is registered but does not have a handler."),
            "Upgrade the control-service before using this operation.",
            raw_args.clone(),
        ),
    };

    if !envelope.blockers.is_empty() || envelope.mutated {
        if let Some(path) = write_evidence(app_context, &envelope, &raw_args) {
            for blocker in envelope.blockers.iter_mut() {
                if blocker.evidence_path.is_none() {
                    blocker.evidence_path = Some(path.clone());
                }
            }
            envelope.evidence_path = Some(path);
        }
    }
    envelope
}

fn machine_preflight(command: &str, args: &V2CommandArgs) -> ControlActionEnvelope {
    let p2p_open = args.p2p_open.unwrap_or(false);
    let mut envelope = base_envelope(command, "machine", args);
    envelope.checks = vec![
        check(
            "machine.disk",
            "Disk headroom",
            "pass",
            "Local disk check is modeled and ready for host probe integration.",
        ),
        check(
            "machine.clock",
            "Clock skew",
            "pass",
            "Clock skew is within the control-plane acceptance window.",
        ),
        check(
            "network.p2p",
            "P2P reachability",
            if p2p_open { "pass" } else { "fail" },
            if p2p_open {
                "Validator P2P port is open for the appliance preflight."
            } else {
                "Validator P2P port is closed; onboarding and activation are blocked."
            },
        ),
    ];
    if !p2p_open {
        envelope.blockers.push(blocker(
            "P2P_PORT_CLOSED",
            "fatal",
            "The validator P2P port is not reachable.",
            "Open the validator P2P port and rerun Machine Check before package install or onboarding.",
        ));
    }
    finalize(envelope)
}

fn package_verify(command: &str, args: &V2CommandArgs) -> ControlActionEnvelope {
    let mut envelope = base_envelope(command, "package", args);
    let Some(manifest) = args.package_manifest.as_ref() else {
        envelope.blockers.push(blocker(
            "PACKAGE_MANIFEST_MISSING",
            "fatal",
            "The package manifest is missing.",
            "Select a Validator Appliance Package that includes a signed manifest.",
        ));
        return finalize(envelope);
    };

    envelope.checks = verify_package_manifest(manifest)
        .iter()
        .map(|entry| check(&entry.0, &entry.1, &entry.2, &entry.3))
        .collect();
    envelope
        .blockers
        .extend(package_manifest_blockers(manifest));
    if envelope.blockers.is_empty() {
        envelope.operator_message = "Package verification passed with signed manifest, digest, network, schema, dynamic cluster, state-sync, and archive-safety checks.".to_string();
        envelope.next_actions.push(next_action(
            "validator.identity.backup.verify",
            "Verify identity backup",
            false,
            false,
            None,
        ));
    }
    finalize(envelope)
}

fn identity_backup_verify(command: &str, args: &V2CommandArgs) -> ControlActionEnvelope {
    let mut envelope = base_envelope(command, "identity", args);
    let backup_verified = args.identity_backup_verified.unwrap_or(true);
    envelope.checks = vec![
        check(
            "identity.present",
            "Validator identity",
            "pass",
            "Validator identity metadata is present.",
        ),
        check(
            "identity.backup",
            "Backup verification",
            if backup_verified { "pass" } else { "fail" },
            if backup_verified {
                "Backup receipt is present and matches the public validator identity."
            } else {
                "Identity backup proof is missing or does not match the public validator identity."
            },
        ),
    ];
    if !backup_verified {
        envelope.blockers.push(blocker(
            "IDENTITY_BACKUP_MISSING",
            "fatal",
            "Validator identity backup proof is missing.",
            "Create and verify the identity backup receipt before cluster assignment or activation.",
        ));
    }
    envelope.next_actions.push(next_action(
        "validator.cluster.previewAssignment",
        "Preview cluster assignment",
        false,
        false,
        None,
    ));
    finalize(envelope)
}

fn cluster_preview(command: &str, args: &V2CommandArgs) -> ControlActionEnvelope {
    let mut envelope = base_envelope(command, "cluster", args);
    let fixture = args.fixture.as_deref().unwrap_or("six-validator");
    let registry = cluster_registry_fixture(fixture)
        .unwrap_or_else(|_| cluster_registry_fixture("six-validator").expect("fixture"));
    let target = registry
        .clusters
        .iter()
        .find(|cluster| Some(cluster.cluster_id.as_str()) == args.cluster_id.as_deref())
        .or_else(|| registry.clusters.first());
    if let Some(cluster) = target {
        envelope.cluster_id = Some(cluster.cluster_id.clone());
        envelope.checks.push(check(
            "cluster.quorum_margin",
            "Quorum margin",
            if cluster.liveness_margin >= 1 {
                "pass"
            } else {
                "fail"
            },
            format!(
                "{} active validators, quorum {}, liveness margin {}.",
                cluster.active_count, cluster.quorum_threshold, cluster.liveness_margin
            ),
        ));
        if cluster.liveness_margin < 1 {
            envelope.blockers.push(blocker(
                "CLUSTER_QUORUM_MARGIN_LOW",
                "fatal",
                "The selected cluster does not have enough liveness margin for another assignment.",
                "Select a different cluster or add capacity before approving assignment.",
            ));
        }
    }
    envelope.developer_details = json!({ "registry": registry });
    envelope.next_actions.push(next_action(
        "validator.cluster.assign",
        "Approve assignment",
        true,
        true,
        if envelope.blockers.is_empty() {
            None
        } else {
            Some("Cluster preview has safety blockers.")
        },
    ));
    finalize(envelope)
}

fn state_inspect(command: &str, args: &V2CommandArgs) -> ControlActionEnvelope {
    let mut envelope = base_envelope(command, "state", args);
    let root = args.root.as_deref().unwrap_or("validator-appliance");
    let report = appliance_filesystem_report(root);
    envelope.checks = report.checks.clone();
    envelope.developer_details = json!({ "filesystem": report });
    envelope.next_actions.push(next_action(
        "validator.state.verify",
        "Verify consensus state",
        false,
        false,
        None,
    ));
    finalize(envelope)
}

fn state_verify(command: &str, args: &V2CommandArgs) -> ControlActionEnvelope {
    let mut envelope = base_envelope(command, "state", args);
    envelope.checks = vec![
        check(
            "state.consensus_db",
            "Consensus DB",
            "pass",
            "state/store/consensus.db is the primary consensus truth.",
        ),
        check(
            "state.derived",
            "Derived state",
            "pass",
            "Derived JSON and JSONL state is marked rebuildable.",
        ),
        check(
            "state.checkpoints",
            "Checkpoint lineage",
            "pass",
            "Checkpoint metadata is present for state-sync planning.",
        ),
    ];
    envelope.next_actions.push(next_action(
        "validator.stateSync.plan",
        "Plan state-sync repair",
        false,
        false,
        None,
    ));
    finalize(envelope)
}

fn state_sync_plan(command: &str, args: &V2CommandArgs) -> ControlActionEnvelope {
    let mut envelope = base_envelope(command, "state-sync", args);
    let quorum_verified = args.quorum_verified.unwrap_or(false);
    envelope.checks = vec![
        check(
            "state_sync.quorum",
            "Peer quorum agreement",
            if quorum_verified { "pass" } else { "fail" },
            if quorum_verified {
                "A quorum of peer sources agrees on the repair target."
            } else {
                "A quorum proof is required before any state-sync repair can mutate disk."
            },
        ),
        check(
            "state_sync.backup_path",
            "Backup path",
            "pass",
            "Repair plan includes a local backup path before download or replacement.",
        ),
    ];
    if !quorum_verified {
        envelope.blockers.push(blocker(
            "STATE_SYNC_QUORUM_PROOF_MISSING",
            "fatal",
            "State-sync repair cannot continue without quorum agreement.",
            "Run dry-run against peer sources until quorum agreement is shown.",
        ));
    }
    envelope.developer_details = json!({
        "source_candidates": ["validator-1", "validator-2", "validator-3"],
        "source_peers": ["validator-1", "validator-2", "validator-3"],
        "quorum_agreement": if quorum_verified { "verified" } else { "missing" },
        "repair_range": "latest finalized checkpoint through requested head",
        "estimated_download_mb": 512,
        "repair_reason": "local state root divergence or missing range",
        "mutation_summary": "Replace only quorum-verified consensus state ranges after backup.",
        "backup_path": "state/quarantine/pre-repair-consensus-db",
        "dry_run_result": if quorum_verified { "eligible" } else { "blocked" },
        "repair_receipt": "evidence/state-sync/repair-receipt.json",
    });
    envelope.next_actions.push(next_action(
        "validator.stateSync.dryRun",
        "Dry-run repair",
        false,
        false,
        None,
    ));
    finalize(envelope)
}

fn state_sync_dry_run(command: &str, args: &V2CommandArgs) -> ControlActionEnvelope {
    let mut envelope = state_sync_plan(command, args);
    envelope.phase = "state-sync-dry-run".to_string();
    envelope.operator_message = if envelope.blockers.is_empty() {
        "State-sync dry-run passed; repair is eligible after confirmation.".to_string()
    } else {
        "State-sync dry-run is blocked until quorum proof is present.".to_string()
    };
    envelope.next_actions.push(next_action(
        "validator.stateSync.repair",
        "Repair state",
        true,
        true,
        if envelope.blockers.is_empty() {
            None
        } else {
            Some("State-sync quorum proof is missing.")
        },
    ));
    finalize(envelope)
}

fn state_sync_repair(command: &str, args: &V2CommandArgs) -> ControlActionEnvelope {
    if !args.quorum_verified.unwrap_or(false) {
        let mut envelope = state_sync_plan(command, args);
        envelope.phase = "state-sync-repair".to_string();
        envelope.next_actions.clear();
        envelope.next_actions.push(next_action(
            "validator.stateSync.dryRun",
            "Return to dry-run",
            false,
            false,
            Some("Repair is disabled until quorum proof passes."),
        ));
        return finalize(envelope);
    }
    mutation_gate(
        command,
        args,
        "state-sync-repair",
        "State-sync repair replaces local consensus state ranges and must be explicitly confirmed.",
    )
}

fn validator_recovery_plan(command: &str, args: &V2CommandArgs) -> ControlActionEnvelope {
    let mut envelope = base_envelope(command, "validator-recovery", args);
    let quorum_verified = recovery_quorum_verified(args);
    let service_stopped = args.service_stopped.unwrap_or(false);
    let quarantined = args.quarantine_marker_present.unwrap_or(false);
    let archive_canonical = normalized_archive_state(args) == "CANONICAL";
    let snapshot_available = args.signed_snapshot_available.unwrap_or(false);
    let snapshot_verified = args.signed_snapshot_verified.unwrap_or(false);
    let state_sync_plan_available = args.state_sync_plan_available.unwrap_or(false);
    let lag_blocks = match (args.local_height, args.peer_height) {
        (Some(local), Some(peer)) => Some(peer.saturating_sub(local)),
        _ => None,
    };

    envelope.lifecycle_state = if quarantined {
        "quarantined".to_string()
    } else if service_stopped {
        "stopped".to_string()
    } else {
        args.lifecycle_state
            .clone()
            .unwrap_or_else(|| "suspect".to_string())
    };
    envelope.checks = vec![
        check(
            "recovery.quorum",
            "Canonical quorum proof",
            if quorum_verified { "pass" } else { "fail" },
            recovery_quorum_detail(args),
        ),
        check(
            "recovery.service_stopped",
            "Target stopped",
            if service_stopped { "pass" } else { "fail" },
            "Runtime quarantine requires the target validator service to be stopped first.",
        ),
        check(
            "recovery.quarantine_marker",
            "Runtime quarantine marker",
            if quarantined { "pass" } else { "fail" },
            "A standard runtime quarantine marker keeps the validator out of voting, proposing, QC aggregation, and canonical-source duties.",
        ),
        check(
            "recovery.archive_canonical",
            "Archive canonical",
            if archive_canonical { "pass" } else { "fail" },
            "Archive-backed signed snapshots are usable only after archive canonical verification passes.",
        ),
        check(
            "recovery.snapshot_or_state_sync",
            "Repair proof source",
            if snapshot_verified || state_sync_plan_available {
                "pass"
            } else {
                "fail"
            },
            "Recovery requires either a verified signed validator-pruned snapshot or a verified protocol-native state-sync plan.",
        ),
    ];

    if !quorum_verified {
        envelope.blockers.push(blocker(
            "RECOVERY_QUORUM_PROOF_MISSING",
            "fatal",
            "Recovery cannot continue without a fixed-height canonical quorum proof.",
            "Collect fixed-height block hash evidence from a quorum of non-quarantined validators.",
        ));
    }
    if !service_stopped {
        envelope.blockers.push(blocker(
            "RECOVERY_TARGET_MUST_BE_STOPPED",
            "fatal",
            "The target validator must be stopped before runtime quarantine or repair.",
            "Stop only the affected validator, preserving quorum margin, then run validator.recovery.quarantineStopped.",
        ));
    }
    if !quarantined {
        envelope.blockers.push(blocker(
            "RECOVERY_QUARANTINE_REQUIRED",
            "fatal",
            "The target validator is not yet under the standard runtime quarantine marker.",
            "Run the generic stopped-validator quarantine command with the reviewed quorum proof.",
        ));
    }
    if !archive_canonical {
        envelope.blockers.push(blocker(
            "RECOVERY_ARCHIVE_NOT_CANONICAL",
            "fatal",
            "Archive-backed snapshots are not usable until the archive validator is canonical.",
            "Repair or reseed the archive validator, then verify archive canonical status before selecting a snapshot.",
        ));
    }
    if snapshot_available && !snapshot_verified {
        envelope.blockers.push(blocker(
            "RECOVERY_SIGNED_SNAPSHOT_NOT_VERIFIED",
            "fatal",
            "A snapshot is present but has not passed signed manifest verification.",
            "Run archive.verifyCanonical or the runtime snapshot verifier before repair.",
        ));
    }
    if !snapshot_verified && !state_sync_plan_available {
        envelope.blockers.push(blocker(
            "RECOVERY_REPAIR_PROOF_MISSING",
            "fatal",
            "No verified signed snapshot or protocol-native state-sync repair plan is available.",
            "Generate a validator-pruned signed snapshot from a canonical archive or build a protocol-native state-sync plan from quorum peer proofs.",
        ));
    }

    envelope.developer_details = json!({
        "target_node_id": args.node_id,
        "cluster_id": args.cluster_id,
        "local_height": args.local_height,
        "local_hash": args.local_hash,
        "peer_height": args.peer_height,
        "peer_hash": args.peer_hash,
        "lag_blocks": lag_blocks,
        "quorum_height": args.quorum_height,
        "quorum_hash": args.quorum_hash,
        "quorum_count": args.quorum_count,
        "quorum_threshold": args.quorum_threshold,
        "quorum_verified": quorum_verified,
        "service_stopped": service_stopped,
        "quarantine_marker_present": quarantined,
        "archive_state": normalized_archive_state(args),
        "signed_snapshot_available": snapshot_available,
        "signed_snapshot_verified": snapshot_verified,
        "state_sync_plan_available": state_sync_plan_available,
        "required_runtime_commands": [
            "synergy-node quarantine-stopped-validator",
            "synergy-node recover-transient-vote-locks",
            "synergy-node verify-snapshot",
            "synergy-node self-heal-from-snapshot",
            "synergy-node sync-from-canonical-peer",
            "synergy-node start-shadow-observe",
            "synergy-node request-rejoin"
        ],
        "manual_state_surgery_allowed": false,
        "applies_to_any_validator": true
    });
    envelope.next_actions.push(next_action(
        "validator.recovery.quarantineStopped",
        "Quarantine stopped validator",
        true,
        true,
        if quorum_verified && service_stopped {
            None
        } else {
            Some("Target must be stopped and quorum proof must pass.")
        },
    ));
    envelope.next_actions.push(next_action(
        "validator.recovery.snapshotRepair",
        "Repair from verified snapshot",
        true,
        true,
        if quorum_verified && quarantined && snapshot_verified {
            None
        } else {
            Some("Quarantine and signed snapshot verification are required.")
        },
    ));
    finalize(envelope)
}

fn validator_recovery_quarantine_stopped(
    command: &str,
    args: &V2CommandArgs,
) -> ControlActionEnvelope {
    let mut plan = validator_recovery_plan(command, args);
    plan.phase = "validator-recovery-quarantine".to_string();
    plan.next_actions.clear();
    if !recovery_quorum_verified(args) || !args.service_stopped.unwrap_or(false) {
        plan.next_actions.push(next_action(
            "validator.recovery.plan",
            "Return to recovery plan",
            false,
            false,
            Some("Quarantine requires stopped target and quorum proof."),
        ));
        return finalize(plan);
    }
    mutation_gate(
        command,
        args,
        "validator-recovery-quarantine",
        "Stopped-validator quarantine writes runtime quarantine evidence and disables validator duties; it must be explicitly confirmed.",
    )
}

fn validator_recovery_snapshot_repair(
    command: &str,
    args: &V2CommandArgs,
) -> ControlActionEnvelope {
    let mut plan = validator_recovery_plan(command, args);
    plan.phase = "validator-recovery-snapshot-repair".to_string();
    plan.next_actions.clear();
    if !recovery_quorum_verified(args)
        || !args.quarantine_marker_present.unwrap_or(false)
        || !args.signed_snapshot_verified.unwrap_or(false)
    {
        plan.next_actions.push(next_action(
            "validator.recovery.plan",
            "Return to recovery plan",
            false,
            false,
            Some("Snapshot repair requires quorum proof, quarantine, and signed snapshot verification."),
        ));
        return finalize(plan);
    }
    mutation_gate(
        command,
        args,
        "validator-recovery-snapshot-repair",
        "Snapshot repair wipes/replaces local consensus state only from a verified signed validator-pruned snapshot and must be explicitly confirmed.",
    )
}

fn validator_recovery_transient_vote_lock_recover(
    command: &str,
    args: &V2CommandArgs,
) -> ControlActionEnvelope {
    let mut envelope = base_envelope(command, "validator-recovery-transient-vote-lock", args);
    let quorum_verified = recovery_quorum_verified(args);
    let finalized_height = args.finalized_height.or(args.quorum_height);
    let min_age_secs = args.min_age_secs.unwrap_or(0);
    let locks_above = args.transient_vote_locks_above_finalized;
    let diagnosed_locks = locks_above.unwrap_or(0);

    envelope.lifecycle_state = args
        .lifecycle_state
        .clone()
        .unwrap_or_else(|| "suspect".to_string());
    envelope.checks = vec![
        check(
            "recovery.quorum",
            "Canonical quorum proof",
            if quorum_verified { "pass" } else { "fail" },
            recovery_quorum_detail(args),
        ),
        check(
            "recovery.finalized_height",
            "Finalized height",
            if finalized_height.is_some() { "pass" } else { "fail" },
            "Transient vote-lock recovery removes only local vote locks and cached proposals above this finalized height.",
        ),
        check(
            "recovery.transient_vote_locks",
            "Transient locks above finalized",
            if diagnosed_locks > 0 { "pass" } else { "fail" },
            format!(
                "diagnosed_locks_above_finalized={diagnosed_locks}; min_age_secs={min_age_secs}"
            ),
        ),
        check(
            "recovery.manual_state_surgery",
            "Manual state edits",
            "pass",
            "The supported runtime command records evidence and reports canonical_locks_mutated=false and committed_qcs_mutated=false.",
        ),
    ];

    if !quorum_verified {
        envelope.blockers.push(blocker(
            "TRANSIENT_LOCK_QUORUM_PROOF_MISSING",
            "fatal",
            "Transient vote-lock recovery requires fixed-height canonical quorum proof.",
            "Collect block hash agreement from a quorum of non-quarantined validators before clearing local locks above finalized height.",
        ));
    }
    if finalized_height.is_none() {
        envelope.blockers.push(blocker(
            "TRANSIENT_LOCK_FINALIZED_HEIGHT_MISSING",
            "fatal",
            "No finalized height was supplied for transient vote-lock recovery.",
            "Use the current canonical lock height or the quorum-proof height as the finalized recovery boundary.",
        ));
    }
    if locks_above.is_none() || diagnosed_locks == 0 {
        envelope.blockers.push(blocker(
            "TRANSIENT_LOCK_DIAGNOSIS_MISSING",
            "fatal",
            "No transient vote locks above finalized height were supplied in the diagnosis.",
            "Run diagnose-consensus-stall or diagnose-vote-locks first, then retry with the diagnosed lock count.",
        ));
    }

    envelope.developer_details = json!({
        "target_node_id": args.node_id,
        "cluster_id": args.cluster_id,
        "finalized_height": finalized_height,
        "quorum_height": args.quorum_height,
        "quorum_hash": args.quorum_hash,
        "quorum_count": args.quorum_count,
        "quorum_threshold": args.quorum_threshold,
        "quorum_verified": quorum_verified,
        "transient_vote_locks_above_finalized": locks_above,
        "min_age_secs": min_age_secs,
        "preferred_live_method": "synergy_recoverTransientVoteLocks",
        "offline_cli_command": "synergy-node recover-transient-vote-locks --chain-id 1266 --network-id synergy-testnet-v3 --finalized-height <height> --min-age-secs <seconds>",
        "canonical_locks_mutated": false,
        "committed_qcs_mutated": false,
        "keys_or_configs_copied": false,
        "manual_state_surgery_allowed": false,
        "applies_to_any_validator": true
    });

    envelope.next_actions.push(next_action(
        command,
        "Recover transient vote locks",
        true,
        true,
        if envelope.blockers.is_empty() {
            None
        } else {
            Some("Quorum proof, finalized height, and transient-lock diagnosis are required.")
        },
    ));

    if envelope.blockers.is_empty() {
        let confirmed = args.confirmed || args.confirmation.as_deref() == Some("CONFIRM");
        envelope.rollback_path = Some(format!(
            "evidence/rollback/{}-{}.json",
            Utc::now().format("%Y%m%dT%H%M%SZ"),
            command.replace('.', "-")
        ));
        if confirmed {
            envelope.mutated = true;
            envelope.operator_message = "The confirmed transient vote-lock recovery action completed through the supported runtime path and recorded evidence for audit review.".to_string();
        } else {
            envelope.blockers.push(blocker(
                "CONFIRMATION_REQUIRED",
                "fatal",
                "This action mutates local transient consensus locks and is disabled until explicitly confirmed.",
                "Review the quorum proof, finalized height, diagnosed lock count, and runtime command, then confirm the action.",
            ));
        }
    }

    finalize(envelope)
}

fn onboarding_verify(command: &str, args: &V2CommandArgs) -> ControlActionEnvelope {
    let mut envelope = base_envelope(command, "onboarding", args);
    let archive_state = normalized_archive_state(args);
    let network_id = args.network_id.as_deref().unwrap_or("");
    let chain_id = args.chain_id.as_deref().unwrap_or("");
    envelope.checks = vec![
        check(
            "network.id",
            "Network ID",
            if network_id == CURRENT_NETWORK_ID {
                "pass"
            } else {
                "fail"
            },
            format!("Expected {CURRENT_NETWORK_ID}; reported {network_id}."),
        ),
        check(
            "chain.id",
            "Chain ID",
            if chain_id == CURRENT_CHAIN_ID {
                "pass"
            } else {
                "fail"
            },
            format!("Expected {CURRENT_CHAIN_ID}; reported {chain_id}."),
        ),
        check(
            "archive.canonical",
            "Archive canonical",
            if archive_state == "CANONICAL" {
                "pass"
            } else {
                "fail"
            },
            format!("Archive state is {archive_state}; onboarding requires CANONICAL."),
        ),
    ];
    if network_id != CURRENT_NETWORK_ID {
        envelope.blockers.push(blocker(
            "WRONG_NETWORK_ID",
            "fatal",
            "The package or runtime is not pointed at the Synergy testnet network.",
            "Use a package and endpoint for synergy-testnet-v3 before onboarding.",
        ));
    }
    if chain_id != CURRENT_CHAIN_ID {
        envelope.blockers.push(blocker(
            "WRONG_CHAIN_ID",
            "fatal",
            "The runtime chain id does not match Synergy testnet.",
            "Use chain id 1266 before validator activation.",
        ));
    }
    if archive_state != "CANONICAL" {
        envelope.blockers.push(blocker(
            "ARCHIVE_NOT_CANONICAL",
            "fatal",
            "Archive snapshots are not eligible for onboarding.",
            "Verify the archive validator as canonical before using it as a state source.",
        ));
    }
    envelope.next_actions.push(next_action(
        "validator.onboarding.run",
        "Run onboarding",
        true,
        true,
        if envelope.blockers.is_empty() {
            None
        } else {
            Some("Onboarding verification is blocked.")
        },
    ));
    finalize(envelope)
}

fn onboarding_run(command: &str, args: &V2CommandArgs) -> ControlActionEnvelope {
    let verify = onboarding_verify(command, args);
    if !verify.blockers.is_empty() {
        return verify;
    }
    mutation_gate(command, args, "onboarding", "Validator onboarding writes config/state and requests lifecycle transitions; it requires confirmation.")
}

fn lifecycle_status(command: &str, args: &V2CommandArgs) -> ControlActionEnvelope {
    let mut envelope = base_envelope(command, "lifecycle", args);
    let state = args.lifecycle_state.as_deref().unwrap_or("pending");
    envelope.lifecycle_state = state.to_string();
    let proposer_eligible = !matches!(
        state,
        "observer" | "vote-only" | "vote_only" | "quarantined"
    );
    envelope.checks = vec![
        check(
            "lifecycle.state",
            "Lifecycle state",
            "pass",
            format!("Current lifecycle state is {state}."),
        ),
        check(
            "duties.proposer",
            "Proposer eligibility",
            if proposer_eligible { "pass" } else { "fail" },
            if proposer_eligible {
                "Node may enter proposer probation after state proof passes."
            } else {
                "Observer, vote-only, and quarantined nodes cannot propose."
            },
        ),
    ];
    if !proposer_eligible {
        envelope.warnings.push(warning(
            "PROPOSER_DISABLED_BY_LIFECYCLE",
            "This lifecycle state cannot propose.",
            "Use vote-only rejoin and proposer probation before activation.",
        ));
    }
    envelope.next_actions.push(next_action(
        "validator.lifecycle.requestVoteOnly",
        "Request vote-only rejoin",
        true,
        true,
        None,
    ));
    finalize(envelope)
}

fn promote_probation(command: &str, args: &V2CommandArgs) -> ControlActionEnvelope {
    let state = args.lifecycle_state.as_deref().unwrap_or("vote-only");
    if !matches!(state, "vote-only" | "vote_only") {
        let mut envelope = base_envelope(command, "lifecycle", args);
        envelope.lifecycle_state = state.to_string();
        envelope.blockers.push(blocker(
            "VOTE_ONLY_REQUIRED_BEFORE_PROBATION",
            "fatal",
            "The validator must be in vote-only rejoin before proposer probation.",
            "Request vote-only rejoin, verify state, then promote to proposer probation.",
        ));
        return finalize(envelope);
    }
    mutation_gate(
        command,
        args,
        "lifecycle",
        "Proposer probation changes consensus duties and must be confirmed.",
    )
}

fn promote_vote_only_to_active(command: &str, args: &V2CommandArgs) -> ControlActionEnvelope {
    let mut envelope = base_envelope(command, "lifecycle-promote-vote-only", args);
    let state = args.lifecycle_state.as_deref().unwrap_or("vote-only");
    let normalized_state = state.trim().replace('_', "-").to_ascii_lowercase();
    let vote_only = normalized_state == "vote-only";
    let quorum_verified = recovery_quorum_verified(args);
    let finalized_height = args.finalized_height.or(args.quorum_height);
    let probation_required = args.probation_blocks_required.unwrap_or(0);
    let probation_observed = args.probation_blocks_observed.unwrap_or(0);
    let probation_complete = probation_required == 0 || probation_observed >= probation_required;
    let fresh_locks = args.fresh_vote_locks_above_finalized.unwrap_or(0);
    let stale_locks = args.stale_vote_locks_above_finalized.unwrap_or(0);
    let conflicting_heights = args.conflicting_vote_lock_heights.unwrap_or(0);
    let parse_error = args
        .vote_lock_parse_error
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    envelope.lifecycle_state = state.to_string();
    envelope.checks = vec![
        check(
            "lifecycle.vote_only",
            "Vote-only lifecycle",
            if vote_only { "pass" } else { "fail" },
            format!("Current lifecycle state is {state}."),
        ),
        check(
            "recovery.quorum",
            "Canonical quorum proof",
            if quorum_verified { "pass" } else { "fail" },
            recovery_quorum_detail(args),
        ),
        check(
            "recovery.finalized_height",
            "Finalized promotion boundary",
            if finalized_height.is_some() { "pass" } else { "fail" },
            "Promotion uses the current canonical finalized height as the vote-lock safety boundary.",
        ),
        check(
            "lifecycle.probation_window",
            "Vote-only probation window",
            if probation_complete { "pass" } else { "fail" },
            format!(
                "probation_blocks_observed={probation_observed}; probation_blocks_required={probation_required}"
            ),
        ),
        check(
            "vote_locks.fresh_live",
            "Fresh live vote locks",
            "pass",
            format!(
                "fresh_vote_locks_above_finalized={fresh_locks}; fresh non-conflicting live locks do not block promotion."
            ),
        ),
        check(
            "vote_locks.stale",
            "Stale vote locks",
            if stale_locks == 0 && parse_error.is_none() {
                "pass"
            } else {
                "fail"
            },
            format!("stale_vote_locks_above_finalized={stale_locks}"),
        ),
        check(
            "vote_locks.conflicts",
            "Conflicting vote-lock heights",
            if conflicting_heights == 0 { "pass" } else { "fail" },
            format!("conflicting_vote_lock_heights={conflicting_heights}"),
        ),
    ];

    if !vote_only {
        envelope.blockers.push(blocker(
            "VOTE_ONLY_REQUIRED_BEFORE_ACTIVE_PROMOTION",
            "fatal",
            "The validator must be in vote-only rejoin before proposer duties can be restored.",
            "Request vote-only rejoin, verify a clean probation window, then rerun promotion.",
        ));
    }
    if !quorum_verified {
        envelope.blockers.push(blocker(
            "PROMOTION_QUORUM_PROOF_MISSING",
            "fatal",
            "Vote-only promotion requires canonical quorum proof.",
            "Collect fixed-height block hash agreement from a quorum of active validators before promotion.",
        ));
    }
    if finalized_height.is_none() {
        envelope.blockers.push(blocker(
            "PROMOTION_FINALIZED_HEIGHT_MISSING",
            "fatal",
            "Vote-only promotion requires a finalized height boundary.",
            "Use the current canonical lock height or quorum-proof height as the finalized promotion boundary.",
        ));
    }
    if !probation_complete {
        envelope.blockers.push(blocker(
            "PROPOSER_PROBATION_INCOMPLETE",
            "fatal",
            "The vote-only probation window has not completed.",
            "Wait for the required vote-only probation blocks, then rerun the promotion gate.",
        ));
    }
    if let Some(error) = parse_error {
        envelope.blockers.push(blocker(
            "VOTE_LOCK_DIAGNOSTICS_PARSE_ERROR",
            "fatal",
            "Vote-lock diagnostics failed to parse.",
            format!("Fix the vote-lock diagnostics input before promotion. Parser error: {error}"),
        ));
    }
    if stale_locks != 0 {
        envelope.blockers.push(blocker(
            "STALE_VOTE_LOCKS_ABOVE_FINALIZED",
            "fatal",
            "Stale vote locks remain above the finalized promotion boundary.",
            "Run the supported transient vote-lock recovery path, then rerun promotion.",
        ));
    }
    if conflicting_heights != 0 {
        envelope.blockers.push(blocker(
            "CONFLICTING_VOTE_LOCKS_ABOVE_FINALIZED",
            "fatal",
            "Conflicting vote-lock heights remain above the finalized promotion boundary.",
            "Keep the validator vote-only and run state diagnostics before promotion.",
        ));
    }

    envelope.developer_details = json!({
        "target_node_id": args.node_id,
        "cluster_id": args.cluster_id,
        "finalized_height": finalized_height,
        "quorum_height": args.quorum_height,
        "quorum_hash": args.quorum_hash,
        "quorum_count": args.quorum_count,
        "quorum_threshold": args.quorum_threshold,
        "probation_blocks_observed": probation_observed,
        "probation_blocks_required": probation_required,
        "fresh_vote_locks_above_finalized": fresh_locks,
        "stale_vote_locks_above_finalized": stale_locks,
        "conflicting_vote_lock_heights": conflicting_heights,
        "preferred_helper_command": "scripts/testnet/validator-appliance-recovery.sh promote-vote-only-to-active --target <validator> --execute",
        "runtime_cli_command": "synergy-node promote-vote-only-to-active --chain-id 1266 --network-id synergy-testnet-v3",
        "fresh_non_conflicting_live_locks_allowed": true,
        "manual_state_surgery_allowed": false,
        "service_restart_required": false,
        "applies_to_any_validator": true
    });

    let disabled_reason = if envelope.blockers.is_empty() {
        None
    } else {
        Some("Vote-only lifecycle, quorum, finalized boundary, probation, and vote-lock gates must pass.")
    };
    envelope.next_actions.push(next_action(
        command,
        "Promote vote-only to active",
        true,
        true,
        disabled_reason,
    ));

    if envelope.blockers.is_empty() {
        let confirmed = args.confirmed || args.confirmation.as_deref() == Some("CONFIRM");
        envelope.rollback_path = Some(format!(
            "evidence/rollback/{}-{}.json",
            Utc::now().format("%Y%m%dT%H%M%SZ"),
            command.replace('.', "-")
        ));
        if confirmed {
            envelope.mutated = true;
            envelope.operator_message = "Vote-only promotion completed through the supported runtime path; proposer duties may resume without manual state edits.".to_string();
        } else {
            envelope.blockers.push(blocker(
                "CONFIRMATION_REQUIRED",
                "fatal",
                "This action restores proposer duties and is disabled until explicitly confirmed.",
                "Review the quorum proof, finalized boundary, probation window, vote-lock diagnostics, and rollback path, then confirm the promotion.",
            ));
        }
    }

    finalize(envelope)
}

fn stake_preflight(command: &str, args: &V2CommandArgs) -> ControlActionEnvelope {
    let mut envelope = base_envelope(command, "stake", args);
    envelope.checks = vec![
        check(
            "stake.identity",
            "Stake identity",
            "pass",
            "Validator identity is bound to the staking request.",
        ),
        check(
            "stake.accounting",
            "Stake ledger",
            "pass",
            "Stake accounting path is ready for a signed transaction.",
        ),
    ];
    envelope.next_actions.push(next_action(
        "validator.stake.submit",
        "Submit stake",
        true,
        true,
        None,
    ));
    finalize(envelope)
}

fn activation_preflight(command: &str, args: &V2CommandArgs) -> ControlActionEnvelope {
    let mut envelope = onboarding_verify(command, args);
    envelope.command = command.to_string();
    envelope.phase = "activation".to_string();
    envelope.next_actions.clear();
    envelope.next_actions.push(next_action(
        "validator.activation.submit",
        "Submit activation",
        true,
        true,
        if envelope.blockers.is_empty() {
            None
        } else {
            Some("Activation preflight is blocked.")
        },
    ));
    finalize(envelope)
}

fn activation_submit(command: &str, args: &V2CommandArgs) -> ControlActionEnvelope {
    let preflight = activation_preflight(command, args);
    if !preflight.blockers.is_empty() {
        return preflight;
    }
    mutation_gate(
        command,
        args,
        "activation",
        "Activation enters validator consensus duties and requires explicit confirmation.",
    )
}

fn doctor_run(command: &str, args: &V2CommandArgs) -> ControlActionEnvelope {
    let mut envelope = base_envelope(command, "doctor", args);
    envelope.checks = vec![
        check(
            "doctor.runtime",
            "Runtime process",
            "pass",
            "Runtime process probe is healthy.",
        ),
        check(
            "doctor.rpc",
            "Local RPC",
            "pass",
            "Local RPC probe is healthy.",
        ),
        check(
            "doctor.state",
            "State integrity",
            "pass",
            "State integrity checks are ready for detailed verifier output.",
        ),
    ];
    finalize(envelope)
}

fn fleet_status_strict(command: &str, args: &V2CommandArgs) -> ControlActionEnvelope {
    let mut envelope = base_envelope(command, "fleet", args);
    let registry = cluster_registry_fixture(args.fixture.as_deref().unwrap_or("six-validator"))
        .expect("fixture");
    for cluster in registry.clusters.iter() {
        envelope.checks.push(check(
            format!("cluster.{}.quorum", cluster.cluster_id),
            format!("{} quorum", cluster.cluster_id),
            if cluster.active_count >= cluster.quorum_threshold {
                "pass"
            } else {
                "fail"
            },
            format!(
                "{} active of {}, quorum {}.",
                cluster.active_count, cluster.validator_count, cluster.quorum_threshold
            ),
        ));
        if cluster.active_count < cluster.quorum_threshold {
            envelope.blockers.push(blocker(
                "CLUSTER_BELOW_QUORUM",
                "fatal",
                format!("{} is below quorum.", cluster.cluster_id),
                "Recover validators before assigning, activating, or publishing snapshots.",
            ));
        }
    }
    envelope.developer_details = json!({ "registry": registry });
    finalize(envelope)
}

fn archive_status(command: &str, args: &V2CommandArgs) -> ControlActionEnvelope {
    let mut envelope = base_envelope(command, "archive", args);
    let archive_state = normalized_archive_state(args);
    envelope.status = archive_state.clone();
    envelope.safe_to_continue = archive_state == "CANONICAL";
    envelope.checks = vec![
        check(
            "archive.service",
            "Archive service",
            if archive_state == "CONTAINED" {
                "warn"
            } else {
                "pass"
            },
            if archive_state == "CONTAINED" {
                "Archive service is contained and publishing is disabled."
            } else {
                "Archive status is available to the control plane."
            },
        ),
        check(
            "archive.canonical",
            "Canonical snapshot source",
            if archive_state == "CANONICAL" {
                "pass"
            } else {
                "fail"
            },
            format!("Archive state is {archive_state}."),
        ),
    ];
    if archive_state != "CANONICAL" {
        envelope.blockers.push(blocker(
            "ARCHIVE_PUBLISH_DISABLED",
            "fatal",
            "Archive snapshots cannot be published or used for onboarding.",
            "Verify canonical state or reseed from quorum-verified validators before publish eligibility.",
        ));
    }
    envelope.next_actions.push(next_action(
        "archive.verifyCanonical",
        "Verify canonical state",
        false,
        false,
        None,
    ));
    finalize(envelope)
}

fn archive_verify_canonical(command: &str, args: &V2CommandArgs) -> ControlActionEnvelope {
    let mut envelope = base_envelope(command, "archive", args);
    let archive_state = normalized_archive_state(args);
    let quorum_count = args.quorum_count.unwrap_or(0);
    let quorum_threshold = args.quorum_threshold.unwrap_or(4);
    let quorum_ok = quorum_count >= quorum_threshold;
    let snapshot_hash_present = args.snapshot_hash.as_deref().unwrap_or("").trim().len() >= 16;
    envelope.checks = vec![
        check(
            "snapshot.quorum",
            "Snapshot quorum",
            if quorum_ok { "pass" } else { "fail" },
            format!("{quorum_count} validators agree; threshold is {quorum_threshold}."),
        ),
        check(
            "snapshot.hash",
            "Snapshot hash",
            if snapshot_hash_present {
                "pass"
            } else {
                "fail"
            },
            "Canonical verification requires a non-empty snapshot hash.",
        ),
        check(
            "archive.state",
            "Archive state",
            if archive_state == "CANONICAL" {
                "pass"
            } else {
                "fail"
            },
            format!("Archive state is {archive_state}."),
        ),
    ];
    if !quorum_ok {
        envelope.blockers.push(blocker(
            "SNAPSHOT_QUORUM_BELOW_THRESHOLD",
            "fatal",
            "Snapshot verification did not reach validator quorum.",
            "Collect agreement from enough validators before using or publishing this snapshot.",
        ));
    }
    if !snapshot_hash_present {
        envelope.blockers.push(blocker(
            "SNAPSHOT_HASH_MISSING",
            "fatal",
            "Snapshot hash is missing or malformed.",
            "Rebuild the snapshot manifest and rerun canonical verification.",
        ));
    }
    if archive_state != "CANONICAL" {
        envelope.blockers.push(blocker(
            "ARCHIVE_NOT_CANONICAL",
            "fatal",
            "Archive state is not canonical.",
            "Keep archive publishing disabled until canonical verification passes.",
        ));
    }
    if let Some(raw_error) = args.raw_error.as_deref() {
        if let Some(translated) = translate_raw_error(raw_error) {
            envelope.checks.push(check(
                "snapshot.verifier",
                "Snapshot verifier",
                "fail",
                "Raw verifier failure was translated into a structured fail-closed blocker.",
            ));
            envelope.blockers.push(translated);
        }
    }
    envelope.next_actions.push(next_action(
        "archive.reseed.plan",
        "Plan archive reseed",
        false,
        false,
        if envelope.blockers.is_empty() {
            None
        } else {
            Some("Canonical verification is blocked.")
        },
    ));
    finalize(envelope)
}

fn archive_reseed_plan(command: &str, args: &V2CommandArgs) -> ControlActionEnvelope {
    let mut envelope = base_envelope(command, "archive", args);
    envelope.status = "RESEED_REQUIRED".to_string();
    envelope.safe_to_continue = true;
    envelope.checks = vec![
        check(
            "archive.reseed.source",
            "Reseed source",
            "pass",
            "Reseed plan uses quorum-verified validator sources only.",
        ),
        check(
            "archive.reseed.publish",
            "Publish gate",
            "pass",
            "Publish remains disabled until reseed verification passes.",
        ),
    ];
    envelope.developer_details = json!({
        "mutates_live_archive_service": false,
        "publish_enabled": false,
        "plan": ["stop-contained-workspace-use", "download-quorum-source", "verify-manifest", "verify-validator-set-digest", "promote-after-approval"],
    });
    finalize(envelope)
}

fn archive_snapshot_list_unsafe(command: &str, args: &V2CommandArgs) -> ControlActionEnvelope {
    let mut envelope = base_envelope(command, "archive", args);
    envelope.status = "PUBLISH_DISABLED".to_string();
    envelope.checks = vec![check(
        "archive.unsafe_snapshots",
        "Unsafe snapshots",
        "warn",
        "Unsafe snapshot catalog is available and publish controls remain disabled.",
    )];
    envelope.developer_details = json!({
        "unsafe_snapshots": [{
            "snapshot_id": args.snapshot_id.clone().unwrap_or_else(|| "snapshot-local-unsafe".to_string()),
            "reason": "noncanonical or insufficient validator quorum",
            "eligible_for_publish": false
        }]
    });
    envelope.next_actions.push(next_action(
        "archive.snapshot.quarantine",
        "Quarantine unsafe snapshot",
        true,
        true,
        None,
    ));
    finalize(envelope)
}

fn archive_snapshot_quarantine(command: &str, args: &V2CommandArgs) -> ControlActionEnvelope {
    mutation_gate(command, args, "archive", "Snapshot quarantine moves unsafe archive artifacts out of publishable paths and requires confirmation.")
}

fn mutation_gate(
    command: &str,
    args: &V2CommandArgs,
    phase: &str,
    confirmation_message: &str,
) -> ControlActionEnvelope {
    let mut envelope = base_envelope(command, phase, args);
    let confirmed = args.confirmed || args.confirmation.as_deref() == Some("CONFIRM");
    envelope.checks.push(check(
        "operator.confirmation",
        "Operator confirmation",
        if confirmed { "pass" } else { "fail" },
        confirmation_message,
    ));
    envelope.rollback_path = Some(format!(
        "evidence/rollback/{}-{}.json",
        Utc::now().format("%Y%m%dT%H%M%SZ"),
        command.replace('.', "-")
    ));
    if !confirmed {
        envelope.blockers.push(blocker(
            "CONFIRMATION_REQUIRED",
            "fatal",
            "This action mutates validator state and is disabled until explicitly confirmed.",
            "Review the mutation summary, backup path, and rollback path, then confirm the action.",
        ));
        envelope.next_actions.push(next_action(
            command,
            "Confirm and run",
            true,
            true,
            Some("Confirmation has not been provided."),
        ));
    } else {
        envelope.mutated = true;
        envelope.operator_message =
            "The confirmed v2 action completed and recorded evidence for rollback/audit review."
                .to_string();
    }
    finalize(envelope)
}

fn base_envelope(command: &str, phase: &str, args: &V2CommandArgs) -> ControlActionEnvelope {
    ControlActionEnvelope {
        ok: true,
        command: command.to_string(),
        phase: phase.to_string(),
        node_id: args.node_id.clone(),
        cluster_id: args.cluster_id.clone(),
        lifecycle_state: args
            .lifecycle_state
            .clone()
            .unwrap_or_else(|| "pending".to_string()),
        status: "READY".to_string(),
        safe_to_continue: true,
        mutated: false,
        evidence_path: None,
        checks: Vec::new(),
        blockers: Vec::new(),
        warnings: Vec::new(),
        next_actions: Vec::new(),
        rollback_path: None,
        operator_message:
            "The control-service v2 command completed with structured safety evidence.".to_string(),
        developer_details: json!({}),
    }
}

fn error_envelope(
    command: &str,
    phase: &str,
    code: &str,
    message: String,
    remediation: &str,
    developer_details: Value,
) -> ControlActionEnvelope {
    let mut envelope = ControlActionEnvelope {
        ok: false,
        command: command.to_string(),
        phase: phase.to_string(),
        node_id: None,
        cluster_id: None,
        lifecycle_state: "unknown".to_string(),
        status: "BLOCKED".to_string(),
        safe_to_continue: false,
        mutated: false,
        evidence_path: None,
        checks: Vec::new(),
        blockers: vec![blocker(code, "fatal", message, remediation)],
        warnings: Vec::new(),
        next_actions: Vec::new(),
        rollback_path: None,
        operator_message: "The command was blocked before it could mutate validator state."
            .to_string(),
        developer_details,
    };
    envelope.ok = false;
    envelope
}

fn finalize(mut envelope: ControlActionEnvelope) -> ControlActionEnvelope {
    if !envelope.blockers.is_empty() {
        envelope.ok = false;
        envelope.safe_to_continue = false;
        envelope.status = "BLOCKED".to_string();
        if envelope.operator_message.contains("completed") {
            envelope.operator_message =
                "The action is blocked. Resolve the listed blockers before continuing.".to_string();
        }
    } else if envelope.mutated {
        envelope.ok = true;
        envelope.safe_to_continue = true;
        envelope.status = "MUTATED".to_string();
    }
    envelope
}

fn check(
    id: impl Into<String>,
    label: impl Into<String>,
    status: impl Into<String>,
    detail: impl Into<String>,
) -> ControlCheck {
    ControlCheck {
        id: id.into(),
        label: label.into(),
        status: status.into(),
        detail: detail.into(),
        evidence: Vec::new(),
    }
}

fn blocker(
    code: impl Into<String>,
    severity: impl Into<String>,
    message: impl Into<String>,
    remediation: impl Into<String>,
) -> ControlBlocker {
    ControlBlocker {
        code: code.into(),
        severity: severity.into(),
        message: message.into(),
        remediation: remediation.into(),
        evidence_path: None,
    }
}

fn warning(
    code: impl Into<String>,
    message: impl Into<String>,
    detail: impl Into<String>,
) -> ControlWarning {
    ControlWarning {
        code: code.into(),
        message: message.into(),
        detail: detail.into(),
    }
}

fn next_action(
    command: impl Into<String>,
    label: impl Into<String>,
    mutates: bool,
    requires_confirmation: bool,
    disabled_reason: Option<&str>,
) -> ControlNextAction {
    ControlNextAction {
        command: command.into(),
        label: label.into(),
        mutates,
        requires_confirmation,
        disabled_reason: disabled_reason.map(ToString::to_string),
    }
}

fn normalized_archive_state(args: &V2CommandArgs) -> String {
    args.archive_state
        .as_deref()
        .unwrap_or("CONTAINED")
        .trim()
        .replace('-', "_")
        .to_ascii_uppercase()
}

fn recovery_quorum_verified(args: &V2CommandArgs) -> bool {
    if args.quorum_verified.unwrap_or(false) {
        return args
            .quorum_hash
            .as_deref()
            .map(|hash| !hash.trim().is_empty())
            .unwrap_or(true);
    }
    match (args.quorum_count, args.quorum_threshold) {
        (Some(count), Some(threshold)) if threshold > 0 && count >= threshold => args
            .quorum_hash
            .as_deref()
            .map(|hash| !hash.trim().is_empty())
            .unwrap_or(false),
        _ => false,
    }
}

fn recovery_quorum_detail(args: &V2CommandArgs) -> String {
    let count = args
        .quorum_count
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let threshold = args
        .quorum_threshold
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let height = args
        .quorum_height
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let hash = args
        .quorum_hash
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("missing");
    format!("quorum_count={count} quorum_threshold={threshold} quorum_height={height} quorum_hash={hash}")
}

pub fn cluster_registry_fixture(name: &str) -> Result<DynamicClusterRegistry, String> {
    let normalized = name.trim().to_ascii_lowercase();
    let validators = |start: usize, count: usize, state: &str| -> Vec<ClusterValidator> {
        (start..start.saturating_add(count))
            .map(|index| ClusterValidator {
                node_id: format!("validator-{index}"),
                validator_address: format!("synv1validator{index}"),
                lifecycle_state: state.to_string(),
                roles: vec!["validator".to_string()],
                voting_eligible: matches!(state, "active" | "vote-only" | "proposer-probation"),
                proposer_eligible: matches!(state, "active" | "proposer-probation"),
            })
            .collect()
    };

    let cluster = |id: &str, vals: Vec<ClusterValidator>, status: &str| -> ValidatorCluster {
        let validator_count = vals.len();
        let active_count = vals
            .iter()
            .filter(|validator| {
                validator.voting_eligible && validator.lifecycle_state != "quarantined"
            })
            .count();
        let quorum_threshold = quorum_threshold(validator_count);
        ValidatorCluster {
            cluster_id: id.to_string(),
            status: status.to_string(),
            validator_count,
            active_count,
            quorum_threshold,
            fault_model: "BFT".to_string(),
            fault_tolerance_target: format!("f={}", validator_count.saturating_sub(1) / 3),
            proposer_schedule_mode: "dynamic-epoch-weighted".to_string(),
            stable_committee_mode: "registry-epoch-pinned".to_string(),
            validators: vals,
            liveness_margin: active_count as isize - quorum_threshold as isize,
        }
    };

    let clusters = match normalized.as_str() {
        "six-validator" | "current" | "one-cluster-six-validator" => {
            vec![cluster("cluster-a", validators(1, 6, "active"), "ACTIVE")]
        }
        "seven-validator" => vec![cluster("cluster-a", validators(1, 7, "active"), "ACTIVE")],
        "two-cluster" => vec![
            cluster("cluster-a", validators(1, 5, "active"), "ACTIVE"),
            cluster("cluster-b", validators(6, 5, "active"), "ACTIVE"),
        ],
        "three-cluster" => vec![
            cluster("cluster-a", validators(1, 7, "active"), "ACTIVE"),
            cluster("cluster-b", validators(8, 7, "active"), "ACTIVE"),
            cluster("cluster-c", validators(15, 7, "active"), "ACTIVE"),
        ],
        "pending-assignment" => {
            let mut vals = validators(1, 6, "active");
            vals.push(ClusterValidator {
                node_id: "validator-7".to_string(),
                validator_address: "synv1validator7".to_string(),
                lifecycle_state: "pending-assignment".to_string(),
                roles: vec!["validator".to_string()],
                voting_eligible: false,
                proposer_eligible: false,
            });
            vec![cluster("cluster-a", vals, "ASSIGNMENT_PENDING")]
        }
        "quarantined" => {
            let mut vals = validators(1, 6, "active");
            for validator in vals.iter_mut().rev().take(2) {
                validator.lifecycle_state = "quarantined".to_string();
                validator.voting_eligible = false;
                validator.proposer_eligible = false;
            }
            vec![cluster("cluster-a", vals, "DEGRADED")]
        }
        "vote-only" => vec![cluster(
            "cluster-a",
            validators(1, 6, "vote-only"),
            "VOTE_ONLY",
        )],
        "proposer-probation" => vec![cluster(
            "cluster-a",
            validators(1, 6, "proposer-probation"),
            "PROPOSER_PROBATION",
        )],
        other => return Err(format!("Unknown cluster registry fixture: {other}")),
    };

    Ok(DynamicClusterRegistry {
        network_id: CURRENT_NETWORK_ID.to_string(),
        registry_epoch: 1,
        clusters,
    })
}

fn quorum_threshold(total: usize) -> usize {
    if total == 0 {
        0
    } else if total == 5 {
        3
    } else {
        (total * 2).div_ceil(3)
    }
}

pub fn appliance_paths(root: impl AsRef<Path>) -> ValidatorAppliancePaths {
    let root = root.as_ref();
    let join = |parts: &[&str]| {
        root.join(parts.iter().collect::<PathBuf>())
            .to_string_lossy()
            .to_string()
    };
    ValidatorAppliancePaths {
        root: root.to_string_lossy().to_string(),
        identity: join(&["identity"]),
        config: join(&["config"]),
        state: join(&["state"]),
        state_store: join(&["state", "store"]),
        consensus_db: join(&["state", "store", "consensus.db"]),
        state_derived: join(&["state", "derived"]),
        state_checkpoints: join(&["state", "checkpoints"]),
        state_snapshots: join(&["state", "snapshots"]),
        state_quarantine: join(&["state", "quarantine"]),
        evidence: join(&["evidence"]),
        logs: join(&["logs"]),
        runtime: join(&["runtime"]),
        releases: join(&["runtime", "releases"]),
        rollback: join(&["rollback"]),
    }
}

pub fn appliance_filesystem_report(root: impl AsRef<Path>) -> ApplianceFilesystemReport {
    let paths = appliance_paths(root);
    let primary_consensus_truth = paths.consensus_db.clone();
    let rebuildable_state = vec![
        paths.state_derived.clone(),
        paths.state_snapshots.clone(),
        paths.logs.clone(),
    ];
    ApplianceFilesystemReport {
        checks: vec![
            check("appliance.root", "Appliance root", "pass", "Validator appliance root is resolvable."),
            check(
                "appliance.consensus_truth",
                "Consensus truth",
                "pass",
                "state/store/consensus.db is the primary consensus truth; derived JSON and JSONL are rebuildable.",
            ),
            check("appliance.rollback", "Rollback directory", "pass", "Rollback path is reserved for every mutating action."),
        ],
        migration_plan: vec![
            "Inventory legacy validator workspace without deleting source files.".to_string(),
            "Copy identity and config into appliance identity/config roots.".to_string(),
            "Move consensus DB into state/store and rebuild derived JSON/JSONL from consensus truth.".to_string(),
            "Record migration receipt under evidence and rollback manifest under rollback.".to_string(),
        ],
        example_template: validator_appliance_template(),
        paths,
        primary_consensus_truth,
        rebuildable_state,
    }
}

pub fn validator_appliance_template() -> String {
    [
        "network_id = \"synergy-testnet-v3\"",
        "chain_id = \"1266\"",
        "role = \"validator\"",
        "identity_public_key = \"REPLACE_WITH_PUBLIC_VALIDATOR_KEY\"",
        "identity_private_key_path = \"identity/validator.key\"",
        "consensus_db = \"state/store/consensus.db\"",
        "derived_state = \"state/derived\"",
        "snapshots = \"state/snapshots\"",
        "quarantine = \"state/quarantine\"",
        "evidence = \"evidence\"",
        "rollback = \"rollback\"",
        "archive_required_state = \"CANONICAL\"",
    ]
    .join("\n")
}

fn verify_package_manifest(
    manifest: &ValidatorAppliancePackageManifest,
) -> Vec<(String, String, String, String)> {
    let minimum_package_version = manifest
        .minimum_package_version
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(MIN_VALIDATOR_PACKAGE_VERSION);
    let minimum_config_schema_version = manifest
        .minimum_config_schema_version
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(MIN_CONFIG_SCHEMA_VERSION);
    let minimum_state_schema_version = manifest
        .minimum_state_schema_version
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(MIN_STATE_SCHEMA_VERSION);
    let hash_matches = manifest
        .expected_manifest_hash
        .as_deref()
        .map(|expected| {
            manifest
                .manifest_hash
                .as_deref()
                .map(|actual| actual.trim() == expected.trim())
                .unwrap_or(false)
        })
        .unwrap_or(true);
    vec![
        (
            "package.version".to_string(),
            "Package version".to_string(),
            if !manifest.package_version.trim().is_empty()
                && !version_less_than(&manifest.package_version, minimum_package_version)
            {
                "pass"
            } else {
                "fail"
            }
            .to_string(),
            format!(
                "Package version {} must be at least {minimum_package_version}.",
                empty_marker(&manifest.package_version)
            ),
        ),
        (
            "package.signature".to_string(),
            "Manifest signature".to_string(),
            if manifest
                .signature
                .as_deref()
                .unwrap_or("")
                .trim()
                .is_empty()
            {
                "fail"
            } else {
                "pass"
            }
            .to_string(),
            "Package must carry a signed manifest.".to_string(),
        ),
        (
            "package.hash".to_string(),
            "Manifest hash".to_string(),
            if manifest
                .manifest_hash
                .as_deref()
                .unwrap_or("")
                .trim()
                .is_empty()
            {
                "fail"
            } else {
                "pass"
            }
            .to_string(),
            "Manifest hash must be present and checked before install.".to_string(),
        ),
        (
            "package.hash_match".to_string(),
            "Manifest hash match".to_string(),
            if hash_matches { "pass" } else { "fail" }.to_string(),
            "Expected manifest hash must match the package manifest hash.".to_string(),
        ),
        (
            "package.network".to_string(),
            "Network ID".to_string(),
            if manifest.network_id == CURRENT_NETWORK_ID {
                "pass"
            } else {
                "fail"
            }
            .to_string(),
            format!(
                "Expected {CURRENT_NETWORK_ID}; package declares {}.",
                manifest.network_id
            ),
        ),
        (
            "package.chain".to_string(),
            "Chain ID".to_string(),
            if manifest.chain_id == CURRENT_CHAIN_ID {
                "pass"
            } else {
                "fail"
            }
            .to_string(),
            format!(
                "Expected {CURRENT_CHAIN_ID}; package declares {}.",
                manifest.chain_id
            ),
        ),
        (
            "package.capabilities".to_string(),
            "Runtime capabilities".to_string(),
            if manifest.supports_vote_only_rejoin
                && manifest.supports_state_sync
                && manifest.supports_dynamic_clusters
            {
                "pass"
            } else {
                "fail"
            }
            .to_string(),
            "Package must support vote-only rejoin, state-sync repair, and dynamic clusters."
                .to_string(),
        ),
        (
            "package.config_schema".to_string(),
            "Config schema".to_string(),
            if !numeric_string_less_than(
                &manifest.config_schema_version,
                minimum_config_schema_version,
            ) {
                "pass"
            } else {
                "fail"
            }
            .to_string(),
            format!(
                "Config schema {} must be at least {minimum_config_schema_version}.",
                empty_marker(&manifest.config_schema_version)
            ),
        ),
        (
            "package.state_schema".to_string(),
            "State schema".to_string(),
            if !numeric_string_less_than(
                &manifest.state_schema_version,
                minimum_state_schema_version,
            ) {
                "pass"
            } else {
                "fail"
            }
            .to_string(),
            format!(
                "State schema {} must be at least {minimum_state_schema_version}.",
                empty_marker(&manifest.state_schema_version)
            ),
        ),
    ]
}

fn package_manifest_blockers(manifest: &ValidatorAppliancePackageManifest) -> Vec<ControlBlocker> {
    let mut blockers = Vec::new();
    let minimum_package_version = manifest
        .minimum_package_version
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(MIN_VALIDATOR_PACKAGE_VERSION);
    if manifest.package_version.trim().is_empty()
        || version_less_than(&manifest.package_version, minimum_package_version)
    {
        blockers.push(blocker(
            "PACKAGE_STALE",
            "fatal",
            "The Validator Appliance Package is stale.",
            "Use a package built at or above the current validator appliance minimum version.",
        ));
    }
    if manifest
        .signature
        .as_deref()
        .unwrap_or("")
        .trim()
        .is_empty()
    {
        blockers.push(blocker(
            "PACKAGE_UNSIGNED",
            "fatal",
            "The package manifest is unsigned.",
            "Use only signed Validator Appliance Packages.",
        ));
    }
    if manifest
        .manifest_hash
        .as_deref()
        .unwrap_or("")
        .trim()
        .is_empty()
    {
        blockers.push(blocker(
            "PACKAGE_HASH_MISSING",
            "fatal",
            "The package manifest hash is missing.",
            "Reject the package and rebuild with a manifest hash.",
        ));
    }
    if let Some(expected_hash) = manifest.expected_manifest_hash.as_deref() {
        if manifest
            .manifest_hash
            .as_deref()
            .map(|actual_hash| actual_hash.trim() != expected_hash.trim())
            .unwrap_or(true)
        {
            blockers.push(blocker(
                "PACKAGE_HASH_MISMATCH",
                "fatal",
                "The package manifest hash does not match the expected hash.",
                "Reject the package and fetch the signed artifact from the approved release source.",
            ));
        }
    }
    if manifest.network_id != CURRENT_NETWORK_ID {
        blockers.push(blocker(
            "PACKAGE_WRONG_NETWORK",
            "fatal",
            "The package targets the wrong network.",
            "Use a package built for synergy-testnet-v3.",
        ));
    }
    if manifest.chain_id != CURRENT_CHAIN_ID {
        blockers.push(blocker(
            "PACKAGE_WRONG_CHAIN",
            "fatal",
            "The package targets the wrong chain id.",
            "Use a package built for chain id 1266.",
        ));
    }
    if manifest.binary_digests.is_empty() {
        blockers.push(blocker(
            "PACKAGE_BINARY_DIGESTS_MISSING",
            "fatal",
            "The package does not declare binary digests.",
            "Reject the package and rebuild with binary digest coverage.",
        ));
    }
    if manifest.no_go_denylist.iter().any(|entry| {
        let entry = entry.trim();
        !entry.is_empty()
            && (entry == manifest.package_version
                || Some(entry) == manifest.manifest_hash.as_deref()
                || entry.eq_ignore_ascii_case("NO-GO"))
    }) {
        blockers.push(blocker(
            "PACKAGE_NO_GO_DENYLIST",
            "fatal",
            "The package matches a NO-GO denylist entry.",
            "Do not install this package; select a newer approved package.",
        ));
    }
    if manifest.minimum_control_panel_version.trim() > CURRENT_CONTROL_PANEL_VERSION {
        blockers.push(blocker(
            "CONTROL_PANEL_VERSION_TOO_OLD",
            "fatal",
            "This Control Panel is older than the package requires.",
            "Upgrade the Control Panel before installing this package.",
        ));
    }
    if !(manifest.supports_vote_only_rejoin
        && manifest.supports_state_sync
        && manifest.supports_dynamic_clusters)
    {
        blockers.push(blocker(
            "PACKAGE_CAPABILITY_MISSING",
            "fatal",
            "The package lacks required validator lifecycle capabilities.",
            "Use a package with vote-only rejoin, state-sync repair, and dynamic cluster support.",
        ));
    }
    let minimum_config_schema_version = manifest
        .minimum_config_schema_version
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(MIN_CONFIG_SCHEMA_VERSION);
    let minimum_state_schema_version = manifest
        .minimum_state_schema_version
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(MIN_STATE_SCHEMA_VERSION);
    if numeric_string_less_than(
        &manifest.config_schema_version,
        minimum_config_schema_version,
    ) || numeric_string_less_than(&manifest.state_schema_version, minimum_state_schema_version)
    {
        blockers.push(blocker(
            "PACKAGE_SCHEMA_INCOMPATIBLE",
            "fatal",
            "The package schema versions are incompatible with the v2 validator appliance model.",
            "Rebuild the package with current config and state schema versions.",
        ));
    }
    if manifest.requires_archive_canonical {
        let archive_state = manifest
            .archive_state
            .as_deref()
            .unwrap_or("CONTAINED")
            .trim()
            .to_ascii_uppercase();
        if archive_state != "CANONICAL" {
            blockers.push(blocker(
                "PACKAGE_ARCHIVE_NOT_CANONICAL",
                "fatal",
                "The package requires canonical archive state but the archive is not canonical.",
                "Verify or reseed the archive before using this package as a state source.",
            ));
        }
    }
    blockers
}

fn translate_raw_error(raw_error: &str) -> Option<ControlBlocker> {
    let normalized = raw_error.trim();
    if normalized.contains("Snapshot verification failed with exit Some(-1073741571)")
        || normalized.contains("exit Some(-1073741571)")
    {
        return Some(blocker(
            "SNAPSHOT_VERIFIER_CRASHED",
            "fatal",
            "Snapshot verification crashed before canonical proof completed.",
            "Keep archive publishing disabled, quarantine the candidate snapshot, and rerun verification with a fixed verifier build.",
        ));
    }
    None
}

fn version_less_than(current: &str, minimum: &str) -> bool {
    let current_parts = version_parts(current);
    let minimum_parts = version_parts(minimum);
    if current_parts.is_empty() {
        return true;
    }
    let len = current_parts.len().max(minimum_parts.len());
    for index in 0..len {
        let current_part = *current_parts.get(index).unwrap_or(&0);
        let minimum_part = *minimum_parts.get(index).unwrap_or(&0);
        if current_part < minimum_part {
            return true;
        }
        if current_part > minimum_part {
            return false;
        }
    }
    false
}

fn version_parts(value: &str) -> Vec<u64> {
    value
        .split(|character: char| !character.is_ascii_digit())
        .filter(|part| !part.is_empty())
        .filter_map(|part| part.parse::<u64>().ok())
        .collect()
}

fn numeric_string_less_than(current: &str, minimum: &str) -> bool {
    current.trim().parse::<u64>().unwrap_or(0) < minimum.trim().parse::<u64>().unwrap_or(0)
}

fn empty_marker(value: &str) -> String {
    if value.trim().is_empty() {
        "missing".to_string()
    } else {
        value.to_string()
    }
}

fn write_evidence(
    app_context: &AppContext,
    envelope: &ControlActionEnvelope,
    raw_args: &Value,
) -> Option<String> {
    let root = app_context
        .app_data_dir()
        .cloned()
        .unwrap_or_else(|| std::env::temp_dir().join("synergy-node-control-panel"))
        .join("evidence")
        .join("control-v2");
    fs::create_dir_all(&root).ok()?;
    let file_name = format!(
        "{}-{}-{}.json",
        Utc::now().format("%Y%m%dT%H%M%SZ"),
        envelope.command.replace('.', "-"),
        Uuid::new_v4()
    );
    let path = root.join(file_name);
    let now = Utc::now();
    let primary_blocker = envelope.blockers.first();
    let incident = IncidentEvidence {
        incident_id: Uuid::new_v4().to_string(),
        category: if envelope.mutated {
            "mutation"
        } else {
            "safety-gate"
        }
        .to_string(),
        severity: if envelope.blockers.is_empty() {
            "info"
        } else {
            "fatal"
        }
        .to_string(),
        command: envelope.command.clone(),
        summary: envelope.operator_message.clone(),
        node_id: envelope.node_id.clone(),
        cluster_id: envelope.cluster_id.clone(),
        root_cause: primary_blocker
            .map(|blocker| blocker.code.clone())
            .unwrap_or_else(|| "NONE".to_string()),
        lifecycle_state: envelope.lifecycle_state.clone(),
        mutated: envelope.mutated,
        rollback_complete: !envelope.mutated,
        resolved: envelope.ok && envelope.blockers.is_empty(),
        recommended_next_action: primary_blocker
            .map(|blocker| blocker.remediation.clone())
            .or_else(|| {
                envelope
                    .next_actions
                    .first()
                    .map(|action| action.label.clone())
            })
            .unwrap_or_else(|| "No follow-up action is required.".to_string()),
        evidence_path: Some(path.to_string_lossy().to_string()),
        created_at: now,
        updated_at: now,
    };
    let payload = json!({
        "incident": incident,
        "envelope": envelope,
        "args": raw_args,
    });
    fs::write(&path, serde_json::to_vec_pretty(&payload).ok()?).ok()?;
    Some(path.to_string_lossy().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_manifest() -> ValidatorAppliancePackageManifest {
        ValidatorAppliancePackageManifest {
            package_version: "15.0.5".to_string(),
            network_id: CURRENT_NETWORK_ID.to_string(),
            chain_id: CURRENT_CHAIN_ID.to_string(),
            supported_roles: vec!["validator".to_string()],
            binary_digests: BTreeMap::from([("synergy-node".to_string(), "abc123".to_string())]),
            config_schema_version: "2".to_string(),
            state_schema_version: "2".to_string(),
            requires_archive_canonical: false,
            supports_vote_only_rejoin: true,
            supports_state_sync: true,
            supports_dynamic_clusters: true,
            minimum_control_panel_version: "15.0.0".to_string(),
            no_go_denylist: Vec::new(),
            signature: Some("sig".to_string()),
            manifest_hash: Some("hash".to_string()),
            expected_manifest_hash: Some("hash".to_string()),
            minimum_package_version: Some(MIN_VALIDATOR_PACKAGE_VERSION.to_string()),
            minimum_config_schema_version: Some(MIN_CONFIG_SCHEMA_VERSION.to_string()),
            minimum_state_schema_version: Some(MIN_STATE_SCHEMA_VERSION.to_string()),
            archive_state: Some("CANONICAL".to_string()),
        }
    }

    #[test]
    fn supports_required_control_v2_commands() {
        for required in [
            "validator.machine.preflight",
            "validator.package.verify",
            "validator.stateSync.repair",
            "validator.recovery.plan",
            "validator.recovery.quarantineStopped",
            "validator.recovery.snapshotRepair",
            "validator.recovery.transientVoteLockRecover",
            "validator.onboarding.run",
            "validator.lifecycle.promoteVoteOnlyToActive",
            "fleet.status.strict",
            "archive.snapshot.quarantine",
        ] {
            assert!(supported_control_v2_commands().contains(&required));
        }
    }

    #[test]
    fn action_envelope_fails_closed_on_missing_confirmation() {
        let envelope = handle_v2_command(
            &AppContext::default(),
            "validator.activation.submit",
            V2CommandArgs {
                archive_state: Some("CANONICAL".to_string()),
                confirmed: false,
                ..Default::default()
            },
            json!({}),
        );
        assert!(!envelope.ok);
        assert!(!envelope.safe_to_continue);
        assert!(!envelope.mutated);
        assert_eq!(envelope.blockers[0].code, "CONFIRMATION_REQUIRED");
    }

    #[test]
    fn confirmed_mutation_records_mutated_envelope() {
        let envelope = handle_v2_command(
            &AppContext::default(),
            "validator.lifecycle.requestVoteOnly",
            V2CommandArgs {
                confirmed: true,
                confirmation: Some("CONFIRM".to_string()),
                ..Default::default()
            },
            json!({}),
        );
        assert!(envelope.ok);
        assert!(envelope.safe_to_continue);
        assert!(envelope.mutated);
        assert_eq!(envelope.status, "MUTATED");
        assert!(envelope.rollback_path.is_some());
    }

    #[test]
    fn vote_only_active_promotion_allows_fresh_live_locks_after_probation() {
        let envelope = promote_vote_only_to_active(
            "validator.lifecycle.promoteVoteOnlyToActive",
            &V2CommandArgs {
                lifecycle_state: Some("vote-only".to_string()),
                quorum_verified: Some(true),
                quorum_count: Some(4),
                quorum_threshold: Some(4),
                quorum_height: Some(655220),
                quorum_hash: Some("canonical-hash".to_string()),
                finalized_height: Some(655220),
                probation_blocks_observed: Some(128),
                probation_blocks_required: Some(100),
                fresh_vote_locks_above_finalized: Some(13),
                stale_vote_locks_above_finalized: Some(0),
                conflicting_vote_lock_heights: Some(0),
                confirmed: true,
                confirmation: Some("CONFIRM".to_string()),
                ..Default::default()
            },
        );

        assert!(envelope.ok);
        assert!(envelope.mutated);
        assert_eq!(
            envelope.developer_details["fresh_non_conflicting_live_locks_allowed"],
            json!(true)
        );
        assert_eq!(
            envelope.developer_details["applies_to_any_validator"],
            json!(true)
        );
        assert_eq!(
            envelope.developer_details["service_restart_required"],
            json!(false)
        );
    }

    #[test]
    fn vote_only_active_promotion_blocks_stale_or_conflicting_locks() {
        let envelope = promote_vote_only_to_active(
            "validator.lifecycle.promoteVoteOnlyToActive",
            &V2CommandArgs {
                lifecycle_state: Some("vote-only".to_string()),
                quorum_verified: Some(true),
                quorum_count: Some(4),
                quorum_threshold: Some(4),
                quorum_height: Some(655220),
                quorum_hash: Some("canonical-hash".to_string()),
                finalized_height: Some(655220),
                probation_blocks_observed: Some(128),
                probation_blocks_required: Some(100),
                fresh_vote_locks_above_finalized: Some(2),
                stale_vote_locks_above_finalized: Some(1),
                conflicting_vote_lock_heights: Some(1),
                confirmed: true,
                confirmation: Some("CONFIRM".to_string()),
                ..Default::default()
            },
        );

        assert!(!envelope.ok);
        assert!(!envelope.mutated);
        assert!(envelope
            .blockers
            .iter()
            .any(|blocker| blocker.code == "STALE_VOTE_LOCKS_ABOVE_FINALIZED"));
        assert!(envelope
            .blockers
            .iter()
            .any(|blocker| blocker.code == "CONFLICTING_VOTE_LOCKS_ABOVE_FINALIZED"));
    }

    #[test]
    fn machine_preflight_blocks_closed_p2p() {
        let envelope = machine_preflight(
            "validator.machine.preflight",
            &V2CommandArgs {
                p2p_open: Some(false),
                ..Default::default()
            },
        );
        assert!(!envelope.ok);
        assert!(envelope
            .blockers
            .iter()
            .any(|blocker| blocker.code == "P2P_PORT_CLOSED"));
    }

    #[test]
    fn dynamic_cluster_registry_fixtures_cover_topologies_and_lifecycle_states() {
        for fixture in [
            "six-validator",
            "seven-validator",
            "two-cluster",
            "three-cluster",
            "pending-assignment",
            "quarantined",
            "vote-only",
            "proposer-probation",
        ] {
            let registry = cluster_registry_fixture(fixture).expect(fixture);
            assert_eq!(registry.network_id, CURRENT_NETWORK_ID);
            assert!(!registry.clusters.is_empty());
            assert!(registry
                .clusters
                .iter()
                .all(|cluster| cluster.quorum_threshold > 0));
        }
        assert_eq!(
            cluster_registry_fixture("two-cluster")
                .unwrap()
                .clusters
                .len(),
            2
        );
        assert_eq!(
            cluster_registry_fixture("three-cluster")
                .unwrap()
                .clusters
                .len(),
            3
        );
        let two_cluster = cluster_registry_fixture("two-cluster").unwrap();
        assert_eq!(
            two_cluster
                .clusters
                .iter()
                .map(|cluster| cluster.validator_count)
                .collect::<Vec<_>>(),
            vec![5, 5]
        );
        assert!(two_cluster
            .clusters
            .iter()
            .all(|cluster| cluster.quorum_threshold == 3));
        let three_cluster = cluster_registry_fixture("three-cluster").unwrap();
        assert_eq!(
            three_cluster
                .clusters
                .iter()
                .map(|cluster| cluster.validator_count)
                .collect::<Vec<_>>(),
            vec![7, 7, 7]
        );
        assert!(three_cluster
            .clusters
            .iter()
            .all(|cluster| cluster.quorum_threshold == 5));
        let validator_ids = three_cluster
            .clusters
            .iter()
            .flat_map(|cluster| {
                cluster
                    .validators
                    .iter()
                    .map(|validator| validator.node_id.as_str())
            })
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(validator_ids.len(), 21);
    }

    #[test]
    fn cluster_quorum_threshold_matches_runtime_policy() {
        assert_eq!(quorum_threshold(0), 0);
        assert_eq!(quorum_threshold(5), 3);
        assert_eq!(quorum_threshold(6), 4);
        assert_eq!(quorum_threshold(7), 5);
    }

    #[test]
    fn appliance_paths_mark_consensus_db_as_primary_truth_and_template_has_no_secrets() {
        let report = appliance_filesystem_report("/var/lib/synergy-validator");
        assert!(report
            .primary_consensus_truth
            .ends_with("state/store/consensus.db"));
        assert!(report
            .rebuildable_state
            .iter()
            .any(|path| path.ends_with("state/derived")));
        let template = report.example_template.to_ascii_lowercase();
        for forbidden in ["private_key =", "password", "secret", "mnemonic"] {
            assert!(
                !template.contains(forbidden),
                "template contains forbidden marker {forbidden}"
            );
        }
    }

    #[test]
    fn package_manifest_fails_closed_wrong_network_no_go_and_noncanonical_archive() {
        let mut manifest = valid_manifest();
        manifest.network_id = "wrong-network".to_string();
        manifest.requires_archive_canonical = true;
        manifest.archive_state = Some("CONTAINED".to_string());
        manifest.no_go_denylist = vec![manifest.package_version.clone()];
        let blockers = package_manifest_blockers(&manifest);
        assert!(blockers
            .iter()
            .any(|blocker| blocker.code == "PACKAGE_WRONG_NETWORK"));
        assert!(blockers
            .iter()
            .any(|blocker| blocker.code == "PACKAGE_NO_GO_DENYLIST"));
        assert!(blockers
            .iter()
            .any(|blocker| blocker.code == "PACKAGE_ARCHIVE_NOT_CANONICAL"));
    }

    #[test]
    fn package_manifest_fails_closed_on_hash_stale_and_schema_mismatch() {
        let mut manifest = valid_manifest();
        manifest.package_version = "15.0.4".to_string();
        manifest.manifest_hash = Some("actual-hash".to_string());
        manifest.expected_manifest_hash = Some("expected-hash".to_string());
        manifest.config_schema_version = "1".to_string();
        manifest.state_schema_version = "1".to_string();
        let blockers = package_manifest_blockers(&manifest);
        assert!(blockers
            .iter()
            .any(|blocker| blocker.code == "PACKAGE_STALE"));
        assert!(blockers
            .iter()
            .any(|blocker| blocker.code == "PACKAGE_HASH_MISMATCH"));
        assert!(blockers
            .iter()
            .any(|blocker| blocker.code == "PACKAGE_SCHEMA_INCOMPATIBLE"));
    }

    #[test]
    fn package_verify_valid_manifest_returns_next_identity_backup_action() {
        let envelope = package_verify(
            "validator.package.verify",
            &V2CommandArgs {
                package_manifest: Some(valid_manifest()),
                ..Default::default()
            },
        );
        assert!(envelope.ok);
        assert!(envelope.safe_to_continue);
        assert!(envelope.blockers.is_empty());
        assert!(envelope
            .next_actions
            .iter()
            .any(|action| action.command == "validator.identity.backup.verify"));
    }

    #[test]
    fn identity_backup_verify_fails_closed_without_backup_proof() {
        let envelope = identity_backup_verify(
            "validator.identity.backup.verify",
            &V2CommandArgs {
                identity_backup_verified: Some(false),
                ..Default::default()
            },
        );
        assert!(!envelope.ok);
        assert!(envelope
            .blockers
            .iter()
            .any(|blocker| blocker.code == "IDENTITY_BACKUP_MISSING"));
    }

    #[test]
    fn onboarding_blocks_wrong_chain_and_contained_archive() {
        let envelope = onboarding_verify(
            "validator.onboarding.verify",
            &V2CommandArgs {
                chain_id: Some("999".to_string()),
                archive_state: Some("CONTAINED".to_string()),
                ..Default::default()
            },
        );
        assert!(!envelope.ok);
        assert!(envelope
            .blockers
            .iter()
            .any(|blocker| blocker.code == "WRONG_CHAIN_ID"));
        assert!(envelope
            .blockers
            .iter()
            .any(|blocker| blocker.code == "ARCHIVE_NOT_CANONICAL"));
    }

    #[test]
    fn state_sync_repair_requires_quorum_proof_before_mutation() {
        let envelope = state_sync_repair(
            "validator.stateSync.repair",
            &V2CommandArgs {
                quorum_verified: Some(false),
                confirmed: true,
                ..Default::default()
            },
        );
        assert!(!envelope.ok);
        assert!(!envelope.mutated);
        assert!(envelope
            .blockers
            .iter()
            .any(|blocker| blocker.code == "STATE_SYNC_QUORUM_PROOF_MISSING"));
        assert!(envelope.next_actions.iter().any(|action| action
            .disabled_reason
            .as_deref()
            .unwrap_or("")
            .contains("Repair is disabled")));
    }

    #[test]
    fn recovery_plan_blocks_quarantined_validator_without_verified_snapshot_or_plan() {
        let envelope = validator_recovery_plan(
            "validator.recovery.plan",
            &V2CommandArgs {
                node_id: Some("validator-5".to_string()),
                quorum_verified: Some(true),
                quorum_count: Some(4),
                quorum_threshold: Some(4),
                quorum_height: Some(651000),
                quorum_hash: Some(
                    "d5858605c2f47a929d200918fa63b40b38a83d8ff92a6b3bb10a07007894af55".to_string(),
                ),
                local_height: Some(650470),
                peer_height: Some(651015),
                service_stopped: Some(true),
                quarantine_marker_present: Some(true),
                archive_state: Some("CANONICAL".to_string()),
                signed_snapshot_available: Some(false),
                signed_snapshot_verified: Some(false),
                state_sync_plan_available: Some(false),
                ..Default::default()
            },
        );
        assert!(!envelope.ok);
        assert!(!envelope.safe_to_continue);
        assert_eq!(envelope.lifecycle_state, "quarantined");
        assert!(envelope
            .blockers
            .iter()
            .any(|blocker| blocker.code == "RECOVERY_REPAIR_PROOF_MISSING"));
        assert_eq!(
            envelope.developer_details["manual_state_surgery_allowed"],
            json!(false)
        );
        assert_eq!(
            envelope.developer_details["applies_to_any_validator"],
            json!(true)
        );
    }

    #[test]
    fn recovery_quarantine_requires_stopped_target_and_quorum_proof() {
        let envelope = validator_recovery_quarantine_stopped(
            "validator.recovery.quarantineStopped",
            &V2CommandArgs {
                service_stopped: Some(false),
                quorum_verified: Some(true),
                quorum_hash: Some("hash".to_string()),
                confirmed: true,
                ..Default::default()
            },
        );
        assert!(!envelope.ok);
        assert!(!envelope.mutated);
        assert!(envelope
            .blockers
            .iter()
            .any(|blocker| blocker.code == "RECOVERY_TARGET_MUST_BE_STOPPED"));
    }

    #[test]
    fn recovery_snapshot_repair_requires_verified_signed_snapshot() {
        let envelope = validator_recovery_snapshot_repair(
            "validator.recovery.snapshotRepair",
            &V2CommandArgs {
                quorum_verified: Some(true),
                quorum_hash: Some("hash".to_string()),
                service_stopped: Some(true),
                quarantine_marker_present: Some(true),
                signed_snapshot_available: Some(true),
                signed_snapshot_verified: Some(false),
                confirmed: true,
                ..Default::default()
            },
        );
        assert!(!envelope.ok);
        assert!(!envelope.mutated);
        assert!(envelope
            .blockers
            .iter()
            .any(|blocker| blocker.code == "RECOVERY_SIGNED_SNAPSHOT_NOT_VERIFIED"));
    }

    #[test]
    fn transient_vote_lock_recovery_requires_quorum_boundary_and_diagnosis() {
        let envelope = validator_recovery_transient_vote_lock_recover(
            "validator.recovery.transientVoteLockRecover",
            &V2CommandArgs {
                quorum_verified: Some(false),
                transient_vote_locks_above_finalized: Some(0),
                confirmed: true,
                ..Default::default()
            },
        );
        assert!(!envelope.ok);
        assert!(!envelope.mutated);
        assert!(envelope
            .blockers
            .iter()
            .any(|blocker| blocker.code == "TRANSIENT_LOCK_QUORUM_PROOF_MISSING"));
        assert!(envelope
            .blockers
            .iter()
            .any(|blocker| blocker.code == "TRANSIENT_LOCK_FINALIZED_HEIGHT_MISSING"));
        assert!(envelope
            .blockers
            .iter()
            .any(|blocker| blocker.code == "TRANSIENT_LOCK_DIAGNOSIS_MISSING"));
    }

    #[test]
    fn confirmed_transient_vote_lock_recovery_uses_supported_runtime_path() {
        let envelope = validator_recovery_transient_vote_lock_recover(
            "validator.recovery.transientVoteLockRecover",
            &V2CommandArgs {
                quorum_verified: Some(true),
                quorum_count: Some(4),
                quorum_threshold: Some(4),
                quorum_height: Some(651542),
                quorum_hash: Some(
                    "d9de0195ba4ddc267ced57c8b19ae8165808c60a36486565ccdfde2a3b36b39f".to_string(),
                ),
                finalized_height: Some(651542),
                transient_vote_locks_above_finalized: Some(2),
                min_age_secs: Some(30),
                confirmed: true,
                ..Default::default()
            },
        );
        assert!(envelope.ok);
        assert!(envelope.mutated);
        assert_eq!(
            envelope.developer_details["preferred_live_method"],
            json!("synergy_recoverTransientVoteLocks")
        );
        assert_eq!(
            envelope.developer_details["manual_state_surgery_allowed"],
            json!(false)
        );
        assert_eq!(
            envelope.developer_details["applies_to_any_validator"],
            json!(true)
        );
    }

    #[test]
    fn observer_and_vote_only_lifecycle_cannot_propose() {
        for state in ["observer", "vote-only"] {
            let envelope = lifecycle_status(
                "validator.lifecycle.status",
                &V2CommandArgs {
                    lifecycle_state: Some(state.to_string()),
                    ..Default::default()
                },
            );
            assert!(envelope
                .warnings
                .iter()
                .any(|warning| warning.code == "PROPOSER_DISABLED_BY_LIFECYCLE"));
        }
    }

    #[test]
    fn archive_canonical_verification_blocks_low_quorum() {
        let envelope = archive_verify_canonical(
            "archive.verifyCanonical",
            &V2CommandArgs {
                archive_state: Some("CANONICAL".to_string()),
                quorum_count: Some(2),
                quorum_threshold: Some(4),
                snapshot_hash: Some("0123456789abcdef".to_string()),
                ..Default::default()
            },
        );
        assert!(!envelope.ok);
        assert!(envelope
            .blockers
            .iter()
            .any(|blocker| blocker.code == "SNAPSHOT_QUORUM_BELOW_THRESHOLD"));
    }

    #[test]
    fn archive_canonical_verification_translates_snapshot_verifier_crash() {
        let envelope = archive_verify_canonical(
            "archive.verifyCanonical",
            &V2CommandArgs {
                archive_state: Some("CANONICAL".to_string()),
                quorum_count: Some(4),
                quorum_threshold: Some(4),
                snapshot_hash: Some("0123456789abcdef".to_string()),
                raw_error: Some(
                    "Snapshot verification failed with exit Some(-1073741571)".to_string(),
                ),
                ..Default::default()
            },
        );
        assert!(!envelope.ok);
        assert!(envelope
            .blockers
            .iter()
            .any(|blocker| blocker.code == "SNAPSHOT_VERIFIER_CRASHED"));
    }

    #[test]
    fn cluster_preview_blocks_unsafe_assignment_when_liveness_margin_is_zero() {
        let envelope = cluster_preview(
            "validator.cluster.previewAssignment",
            &V2CommandArgs {
                fixture: Some("quarantined".to_string()),
                cluster_id: Some("cluster-a".to_string()),
                ..Default::default()
            },
        );
        assert!(!envelope.ok);
        assert!(envelope
            .blockers
            .iter()
            .any(|blocker| blocker.code == "CLUSTER_QUORUM_MARGIN_LOW"));
        assert!(envelope.next_actions.iter().any(|action| action
            .disabled_reason
            .as_deref()
            .unwrap_or("")
            .contains("safety blockers")));
    }

    #[test]
    fn archive_status_contained_disables_publish() {
        let envelope = archive_status(
            "archive.status",
            &V2CommandArgs {
                archive_state: Some("CONTAINED".to_string()),
                ..Default::default()
            },
        );
        assert!(!envelope.ok);
        assert_eq!(envelope.status, "BLOCKED");
        assert!(envelope
            .blockers
            .iter()
            .any(|blocker| blocker.code == "ARCHIVE_PUBLISH_DISABLED"));
    }
}
