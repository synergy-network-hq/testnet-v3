use crate::cluster::quorum_threshold;
use crate::synergy_types::{SYNERGY_TESTNET_V3_CHAIN_ID, SYNERGY_TESTNET_V3_NETWORK_ID};
use crate::validator::{canonical_validator_clusters_for_epoch, Validator};
use crate::validator_lifecycle::REQUIRED_VALIDATOR_STAKE_NWEI;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnboardingSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnboardingFinding {
    pub code: String,
    pub severity: OnboardingSeverity,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommunityValidatorPreflightInput {
    pub chain_id: u64,
    pub network_id: String,
    pub validator_id: String,
    pub validator_uma_id: String,
    pub stake_amount_nwei: u128,
    #[serde(default)]
    pub duplicate_validator_id: bool,
    #[serde(default)]
    pub duplicate_validator_uma_id: bool,
    #[serde(default)]
    pub consensus_key_role_verified: bool,
    #[serde(default)]
    pub peer_key_role_verified: bool,
    #[serde(default)]
    pub operator_key_role_verified: bool,
    #[serde(default)]
    pub nat_reachable: bool,
    #[serde(default)]
    pub p2p_port_open: bool,
    #[serde(default)]
    pub discovery_port_open: bool,
    #[serde(default)]
    pub cluster_assignment: Option<u64>,
    pub existing_validator_count: usize,
    pub planned_validator_count: usize,
    #[serde(default)]
    pub rollback_plan_present: bool,
    #[serde(default)]
    pub bundle_manifest_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommunityValidatorPreflightReport {
    pub ok: bool,
    pub decision: String,
    pub dry_run_only: bool,
    pub validator_id: String,
    pub planned_validator_count: usize,
    pub cluster_assignment: Option<u64>,
    pub actions: Vec<String>,
    pub findings: Vec<OnboardingFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommunityValidatorBundleInput {
    pub preflight: CommunityValidatorPreflightInput,
    pub release_binary_digest: String,
    pub network_config_digest: String,
    pub validator_set_digest: String,
    pub checkpoint_manifest_digest: String,
    #[serde(default = "default_workspace_root")]
    pub workspace_root: String,
    #[serde(default = "default_service_user")]
    pub service_user: String,
    #[serde(default)]
    pub include_wireguard_profile: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommunityValidatorBundleFile {
    pub path: String,
    pub kind: String,
    pub sensitive: bool,
    pub required_operator_edit: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommunityValidatorBundleManifest {
    pub ok: bool,
    pub decision: String,
    pub dry_run_only: bool,
    pub validator_id: String,
    pub workspace_root: String,
    pub service_user: String,
    pub release_binary_digest: String,
    pub network_config_digest: String,
    pub validator_set_digest: String,
    pub checkpoint_manifest_digest: String,
    pub files: Vec<CommunityValidatorBundleFile>,
    pub actions: Vec<String>,
    pub findings: Vec<OnboardingFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommunityValidatorDryRunJoinInput {
    pub chain_id: u64,
    pub network_id: String,
    pub validator_id: String,
    #[serde(default)]
    pub observer_sync_complete: bool,
    pub local_finalized_height: u64,
    pub local_finalized_hash: String,
    pub quorum_finalized_height: u64,
    pub quorum_finalized_hash: String,
    pub local_high_qc_height: u64,
    pub local_high_qc_hash: String,
    pub quorum_high_qc_height: u64,
    pub quorum_high_qc_hash: String,
    pub config_digest: String,
    pub expected_config_digest: String,
    pub validator_set_digest: String,
    pub expected_validator_set_digest: String,
    pub binary_digest: String,
    #[serde(default)]
    pub compatible_binary_digests: Vec<String>,
    #[serde(default)]
    pub unresolved_local_fork_evidence: bool,
    #[serde(default)]
    pub approval_record_present: bool,
    #[serde(default)]
    pub vote_only_requested: bool,
    pub proposer_probation_blocks: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommunityValidatorDryRunJoinReport {
    pub ok: bool,
    pub decision: String,
    pub dry_run_only: bool,
    pub validator_id: String,
    pub next_stage: String,
    pub proposer_probation_blocks: u64,
    pub actions: Vec<String>,
    pub findings: Vec<OnboardingFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommunityEnrollmentTokenInput {
    pub chain_id: u64,
    pub network_id: String,
    pub token_id: String,
    pub validator_id: String,
    pub issued_to_uma_id: String,
    pub scope: String,
    pub expires_at_unix: u64,
    pub now_unix: u64,
    #[serde(default)]
    pub issuer_signature_verified: bool,
    #[serde(default)]
    pub revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommunityPackageCompatibilityManifest {
    pub chain_id: u64,
    pub network_id: String,
    pub package_id: String,
    pub validator_id: String,
    pub artifact_decision: String,
    pub appliance_version: String,
    pub runtime_version: String,
    pub target_arch: String,
    pub signed_release_digest: String,
    pub config_schema_version: String,
    #[serde(default)]
    pub includes_secrets: bool,
    #[serde(default)]
    pub archive_snapshot_dependency: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommunityBackupVerificationProof {
    pub backup_manifest_digest: String,
    pub encrypted_backup_digest: String,
    #[serde(default)]
    pub restore_tested: bool,
    pub operator_recovery_contact_hash: String,
    #[serde(default)]
    pub contains_private_key_material: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommunityIdentityBundleInput {
    pub chain_id: u64,
    pub network_id: String,
    pub validator_id: String,
    pub validator_uma_id: String,
    pub enrollment_token_id: String,
    pub identity_manifest_digest: String,
    #[serde(default)]
    pub consensus_key_role_verified: bool,
    #[serde(default)]
    pub peer_key_role_verified: bool,
    #[serde(default)]
    pub operator_key_role_verified: bool,
    #[serde(default)]
    pub backup_proof: Option<CommunityBackupVerificationProof>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommunityClusterAssignmentPreviewInput {
    pub chain_id: u64,
    pub network_id: String,
    pub validator_id: String,
    pub existing_validator_count: usize,
    pub planned_validator_count: usize,
    #[serde(default)]
    pub requested_cluster_id: Option<u64>,
    #[serde(default)]
    pub planned_validator_addresses: Vec<String>,
    #[serde(default)]
    pub assignment_epoch: u64,
    #[serde(default)]
    pub activation_height: Option<u64>,
    #[serde(default)]
    pub activation_effective_height: Option<u64>,
    #[serde(default)]
    pub anti_affinity_passed: bool,
    #[serde(default)]
    pub fault_domain_diversity_passed: bool,
    #[serde(default)]
    pub would_reduce_quorum: bool,
    #[serde(default)]
    pub would_displace_active_validator: bool,
    #[serde(default)]
    pub archive_contained_dependency: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommunityClusterMembershipPreview {
    pub cluster_id: u64,
    pub validator_ids: Vec<String>,
    pub quorum_threshold: usize,
    pub active_liveness_margin: isize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommunityClusterAssignmentPreviewReport {
    pub ok: bool,
    pub decision: String,
    pub dry_run_only: bool,
    pub validator_id: String,
    pub cluster_assignment: Option<u64>,
    pub planned_validator_count: usize,
    pub dynamic_quorum_threshold: usize,
    pub active_liveness_margin: isize,
    pub cluster_memberships: Vec<CommunityClusterMembershipPreview>,
    pub assignment_epoch: u64,
    pub activation_height: Option<u64>,
    pub activation_recorded_height: Option<u64>,
    pub activation_effective_height: Option<u64>,
    pub findings: Vec<OnboardingFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommunityConfigRenderManifestInput {
    pub chain_id: u64,
    pub network_id: String,
    pub validator_id: String,
    pub render_manifest_digest: String,
    pub service_user: String,
    #[serde(default)]
    pub templates_are_examples: bool,
    #[serde(default)]
    pub contains_secrets: bool,
    #[serde(default)]
    pub config_paths: Vec<String>,
    #[serde(default)]
    pub rollback_plan_present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommunityObserverSyncProof {
    #[serde(default)]
    pub observer_sync_complete: bool,
    pub local_finalized_height: u64,
    pub local_finalized_hash: String,
    pub quorum_finalized_height: u64,
    pub quorum_finalized_hash: String,
    pub local_high_qc_height: u64,
    pub local_high_qc_hash: String,
    pub quorum_high_qc_height: u64,
    pub quorum_high_qc_hash: String,
    #[serde(default)]
    pub state_proof_verified: bool,
    #[serde(default)]
    pub archive_contained_dependency: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommunityVoteOnlyEligibilityInput {
    #[serde(default)]
    pub approval_record_present: bool,
    #[serde(default)]
    pub vote_only_requested: bool,
    #[serde(default)]
    pub unresolved_local_fork_evidence: bool,
    #[serde(default)]
    pub proposer_requested: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommunityProposerProbationEligibilityInput {
    pub current_stage: String,
    pub probation_blocks_required: u64,
    pub probation_blocks_completed: u64,
    #[serde(default)]
    pub clean_vote_only_window: bool,
    #[serde(default)]
    pub proposer_requested: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommunityStateProof {
    pub state_root_digest: String,
    pub checkpoint_manifest_digest: String,
    pub committed_qc_digest: String,
    #[serde(default)]
    pub latest_finalized_head_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommunityActivationEligibilityInput {
    pub chain_id: u64,
    pub network_id: String,
    pub validator_id: String,
    pub enrollment_token: CommunityEnrollmentTokenInput,
    pub package_manifest: CommunityPackageCompatibilityManifest,
    pub identity_bundle: CommunityIdentityBundleInput,
    pub cluster_assignment: CommunityClusterAssignmentPreviewInput,
    pub config_render: CommunityConfigRenderManifestInput,
    pub observer_sync: CommunityObserverSyncProof,
    pub vote_only: CommunityVoteOnlyEligibilityInput,
    pub proposer_probation: CommunityProposerProbationEligibilityInput,
    #[serde(default)]
    pub state_proof: Option<CommunityStateProof>,
    #[serde(default)]
    pub archive_contained_dependency: bool,
    #[serde(default)]
    pub activation_requested: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommunityOnboardingGateReport {
    pub ok: bool,
    pub decision: String,
    pub dry_run_only: bool,
    pub gate: String,
    pub validator_id: String,
    pub next_stage: String,
    pub actions: Vec<String>,
    pub findings: Vec<OnboardingFinding>,
}

pub fn evaluate_community_validator_preflight(
    input: &CommunityValidatorPreflightInput,
) -> CommunityValidatorPreflightReport {
    let mut findings = Vec::new();

    if input.chain_id != SYNERGY_TESTNET_V3_CHAIN_ID {
        findings.push(error(
            "wrong_chain_id",
            format!(
                "expected chain_id {} but got {}",
                SYNERGY_TESTNET_V3_CHAIN_ID, input.chain_id
            ),
        ));
    }
    if input.network_id != SYNERGY_TESTNET_V3_NETWORK_ID {
        findings.push(error(
            "wrong_network_id",
            format!(
                "expected network_id {} but got {}",
                SYNERGY_TESTNET_V3_NETWORK_ID, input.network_id
            ),
        ));
    }
    if input.validator_id.trim().is_empty() {
        findings.push(error("missing_validator_id", "validator_id is required"));
    }
    if input.validator_uma_id.trim().is_empty() {
        findings.push(error(
            "missing_validator_uma_id",
            "validator_uma_id is required",
        ));
    }
    if input.duplicate_validator_id {
        findings.push(error(
            "duplicate_validator_id",
            format!("validator_id {} already exists", input.validator_id),
        ));
    }
    if input.duplicate_validator_uma_id {
        findings.push(error(
            "duplicate_validator_uma_id",
            format!("validator UMA {} already exists", input.validator_uma_id),
        ));
    }
    if input.stake_amount_nwei < REQUIRED_VALIDATOR_STAKE_NWEI {
        findings.push(error(
            "insufficient_stake",
            format!(
                "stake {} nwei is below required {} nwei",
                input.stake_amount_nwei, REQUIRED_VALIDATOR_STAKE_NWEI
            ),
        ));
    }
    if !input.consensus_key_role_verified {
        findings.push(error(
            "consensus_key_role_unverified",
            "consensus key role proof is missing or invalid",
        ));
    }
    if !input.peer_key_role_verified {
        findings.push(error(
            "peer_key_role_unverified",
            "peer key role proof is missing or invalid",
        ));
    }
    if !input.operator_key_role_verified {
        findings.push(error(
            "operator_key_role_unverified",
            "operator key role proof is missing or invalid",
        ));
    }
    if !input.nat_reachable {
        findings.push(error(
            "nat_unreachable",
            "candidate validator is not reachable through NAT/firewall checks",
        ));
    }
    if !input.p2p_port_open {
        findings.push(error("p2p_port_closed", "candidate P2P port is not open"));
    }
    if !input.discovery_port_open {
        findings.push(error(
            "discovery_port_closed",
            "candidate discovery port is not open",
        ));
    }
    if input.cluster_assignment.is_none() {
        findings.push(error(
            "cluster_assignment_missing",
            "candidate has no planned cluster assignment",
        ));
    }
    if input.planned_validator_count <= input.existing_validator_count {
        findings.push(error(
            "planned_validator_count_not_expanded",
            format!(
                "planned validator count {} must exceed existing count {} for onboarding",
                input.planned_validator_count, input.existing_validator_count
            ),
        ));
    }
    if !input.rollback_plan_present {
        findings.push(error(
            "rollback_plan_missing",
            "community validator onboarding requires an explicit rollback plan",
        ));
    }
    if input.bundle_manifest_path.is_none() {
        findings.push(warning(
            "bundle_manifest_missing",
            "bundle manifest is not attached; generate it before handoff",
        ));
    }

    let has_errors = findings
        .iter()
        .any(|finding| finding.severity == OnboardingSeverity::Error);
    CommunityValidatorPreflightReport {
        ok: !has_errors,
        decision: if has_errors { "NO_GO" } else { "DRY_RUN_GO" }.to_string(),
        dry_run_only: true,
        validator_id: input.validator_id.clone(),
        planned_validator_count: input.planned_validator_count,
        cluster_assignment: input.cluster_assignment,
        actions: vec![
            "verify candidate identity and Aegis/PQC key-role proofs".to_string(),
            "verify stake is finalized and slashable before activation".to_string(),
            "verify NAT, P2P, and discovery reachability".to_string(),
            "assign validator through dynamic cluster expansion policy".to_string(),
            "generate onboarding bundle and rollback plan for operator review".to_string(),
        ],
        findings,
    }
}

pub fn build_community_validator_bundle_manifest(
    input: &CommunityValidatorBundleInput,
) -> CommunityValidatorBundleManifest {
    let preflight = evaluate_community_validator_preflight(&input.preflight);
    let mut findings = preflight.findings.clone();

    require_non_empty(
        &mut findings,
        "release_binary_digest_missing",
        "signed release binary digest is required",
        &input.release_binary_digest,
    );
    require_non_empty(
        &mut findings,
        "network_config_digest_missing",
        "signed network config digest is required",
        &input.network_config_digest,
    );
    require_non_empty(
        &mut findings,
        "validator_set_digest_missing",
        "validator-set digest is required",
        &input.validator_set_digest,
    );
    require_non_empty(
        &mut findings,
        "checkpoint_manifest_digest_missing",
        "verified checkpoint manifest digest is required",
        &input.checkpoint_manifest_digest,
    );
    require_non_empty(
        &mut findings,
        "workspace_root_missing",
        "workspace root is required",
        &input.workspace_root,
    );
    require_non_empty(
        &mut findings,
        "service_user_missing",
        "dedicated service user is required",
        &input.service_user,
    );

    let has_errors = has_errors(&findings);
    let files = if has_errors {
        Vec::new()
    } else {
        community_bundle_files(&input.workspace_root, input.include_wireguard_profile)
    };

    CommunityValidatorBundleManifest {
        ok: !has_errors,
        decision: if has_errors {
            "NO_GO"
        } else {
            "BUNDLE_DRY_RUN_GO"
        }
        .to_string(),
        dry_run_only: true,
        validator_id: input.preflight.validator_id.clone(),
        workspace_root: input.workspace_root.clone(),
        service_user: input.service_user.clone(),
        release_binary_digest: input.release_binary_digest.clone(),
        network_config_digest: input.network_config_digest.clone(),
        validator_set_digest: input.validator_set_digest.clone(),
        checkpoint_manifest_digest: input.checkpoint_manifest_digest.clone(),
        files,
        actions: vec![
            "create standardized validator workspace from example templates".to_string(),
            "install only the signed release matching release_binary_digest".to_string(),
            "install only the signed network config matching network_config_digest".to_string(),
            "download and verify checkpoint manifest before observer sync".to_string(),
            "keep validator in observer mode until dry-run join gates pass".to_string(),
        ],
        findings,
    }
}

pub fn evaluate_community_validator_dry_run_join(
    input: &CommunityValidatorDryRunJoinInput,
) -> CommunityValidatorDryRunJoinReport {
    let mut findings = Vec::new();

    if input.chain_id != SYNERGY_TESTNET_V3_CHAIN_ID {
        findings.push(error(
            "wrong_chain_id",
            format!(
                "expected chain_id {} but got {}",
                SYNERGY_TESTNET_V3_CHAIN_ID, input.chain_id
            ),
        ));
    }
    if input.network_id != SYNERGY_TESTNET_V3_NETWORK_ID {
        findings.push(error(
            "wrong_network_id",
            format!(
                "expected network_id {} but got {}",
                SYNERGY_TESTNET_V3_NETWORK_ID, input.network_id
            ),
        ));
    }
    if input.validator_id.trim().is_empty() {
        findings.push(error("missing_validator_id", "validator_id is required"));
    }
    if !input.observer_sync_complete {
        findings.push(error(
            "observer_sync_incomplete",
            "candidate must finish observer sync before vote-only rejoin",
        ));
    }
    if input.local_finalized_height != input.quorum_finalized_height
        || !same_trimmed(&input.local_finalized_hash, &input.quorum_finalized_hash)
    {
        findings.push(error(
            "finalized_head_mismatch",
            format!(
                "local finalized {}:{} does not match quorum {}:{}",
                input.local_finalized_height,
                input.local_finalized_hash,
                input.quorum_finalized_height,
                input.quorum_finalized_hash
            ),
        ));
    }
    if input.local_high_qc_height != input.quorum_high_qc_height
        || !same_trimmed(&input.local_high_qc_hash, &input.quorum_high_qc_hash)
    {
        findings.push(error(
            "high_qc_mismatch",
            format!(
                "local high QC {}:{} does not match quorum {}:{}",
                input.local_high_qc_height,
                input.local_high_qc_hash,
                input.quorum_high_qc_height,
                input.quorum_high_qc_hash
            ),
        ));
    }
    if !same_trimmed(&input.config_digest, &input.expected_config_digest) {
        findings.push(error(
            "config_digest_mismatch",
            "candidate config digest does not match signed network config",
        ));
    }
    if !same_trimmed(
        &input.validator_set_digest,
        &input.expected_validator_set_digest,
    ) {
        findings.push(error(
            "validator_set_digest_mismatch",
            "candidate validator-set digest does not match quorum validator set",
        ));
    }
    if input
        .compatible_binary_digests
        .iter()
        .all(|digest| !same_trimmed(digest, &input.binary_digest))
    {
        findings.push(error(
            "binary_digest_not_approved",
            "candidate binary digest is not in the compatible release digest set",
        ));
    }
    if input.unresolved_local_fork_evidence {
        findings.push(error(
            "unresolved_local_fork_evidence",
            "candidate has unresolved fork, lock, or QC evidence",
        ));
    }
    if !input.approval_record_present {
        findings.push(error(
            "approval_record_missing",
            "vote-only rejoin approval record is required",
        ));
    }
    if !input.vote_only_requested {
        findings.push(error(
            "vote_only_not_requested",
            "candidate must request vote-only before proposer eligibility",
        ));
    }
    if input.proposer_probation_blocks == 0 {
        findings.push(error(
            "proposer_probation_missing",
            "proposer probation block count must be greater than zero",
        ));
    }

    let has_errors = has_errors(&findings);
    CommunityValidatorDryRunJoinReport {
        ok: !has_errors,
        decision: if has_errors {
            "NO_GO"
        } else {
            "DRY_RUN_VOTE_ONLY_GO"
        }
        .to_string(),
        dry_run_only: true,
        validator_id: input.validator_id.clone(),
        next_stage: if has_errors {
            "blocked".to_string()
        } else {
            "vote_only".to_string()
        },
        proposer_probation_blocks: input.proposer_probation_blocks,
        actions: vec![
            "enter observer sync only from verified checkpoint evidence".to_string(),
            "request vote-only rejoin after finalized head and high QC match quorum".to_string(),
            "withhold proposer eligibility until probation blocks complete".to_string(),
            "fail closed on digest mismatch or unresolved fork evidence".to_string(),
        ],
        findings,
    }
}

pub fn verify_community_enrollment_token(
    input: &CommunityEnrollmentTokenInput,
) -> CommunityOnboardingGateReport {
    let mut findings = Vec::new();
    validate_testnet_identity(&mut findings, input.chain_id, &input.network_id);
    require_non_empty(
        &mut findings,
        "enrollment_token_id_missing",
        "enrollment token id is required",
        &input.token_id,
    );
    require_non_empty(
        &mut findings,
        "validator_id_missing",
        "validator id is required",
        &input.validator_id,
    );
    require_non_empty(
        &mut findings,
        "issued_to_uma_id_missing",
        "issued-to UMA id is required",
        &input.issued_to_uma_id,
    );
    if !matches!(
        input.scope.trim(),
        "community_validator" | "validator_onboarding"
    ) {
        findings.push(error(
            "enrollment_token_scope_invalid",
            "enrollment token scope must be community_validator or validator_onboarding",
        ));
    }
    if input.expires_at_unix <= input.now_unix {
        findings.push(error(
            "enrollment_token_expired",
            "enrollment token is expired",
        ));
    }
    if !input.issuer_signature_verified {
        findings.push(error(
            "enrollment_token_signature_unverified",
            "enrollment token issuer signature is not verified",
        ));
    }
    if input.revoked {
        findings.push(error(
            "enrollment_token_revoked",
            "enrollment token has been revoked",
        ));
    }
    gate_report(
        "enrollment_token",
        &input.validator_id,
        "identity_bundle",
        vec!["bind enrollment token to the candidate identity bundle".to_string()],
        findings,
    )
}

pub fn verify_community_package_manifest(
    input: &CommunityPackageCompatibilityManifest,
) -> CommunityOnboardingGateReport {
    let mut findings = Vec::new();
    validate_testnet_identity(&mut findings, input.chain_id, &input.network_id);
    for (code, detail, value) in [
        (
            "package_id_missing",
            "validator appliance package id is required",
            &input.package_id,
        ),
        (
            "validator_id_missing",
            "validator id is required",
            &input.validator_id,
        ),
        (
            "appliance_version_missing",
            "appliance version is required",
            &input.appliance_version,
        ),
        (
            "runtime_version_missing",
            "runtime version is required",
            &input.runtime_version,
        ),
        (
            "target_arch_missing",
            "target architecture is required",
            &input.target_arch,
        ),
        (
            "signed_release_digest_missing",
            "signed release digest is required",
            &input.signed_release_digest,
        ),
        (
            "config_schema_version_missing",
            "config schema version is required",
            &input.config_schema_version,
        ),
    ] {
        require_non_empty(&mut findings, code, detail, value);
    }
    if !matches!(
        input.artifact_decision.trim(),
        "GO" | "DRY_RUN_GO" | "APPROVED"
    ) {
        findings.push(error(
            "artifact_no_go",
            "validator appliance artifact decision is not GO",
        ));
    }
    if input.includes_secrets {
        findings.push(error(
            "package_contains_secrets",
            "validator appliance package manifest must not include secrets",
        ));
    }
    if input.archive_snapshot_dependency {
        findings.push(error(
            "package_depends_on_archive_snapshot",
            "validator appliance package cannot depend on archive snapshot state",
        ));
    }
    gate_report(
        "package_compatibility",
        &input.validator_id,
        "cluster_assignment_preview",
        vec!["verify package digest and config schema before install planning".to_string()],
        findings,
    )
}

pub fn verify_community_identity_bundle(
    input: &CommunityIdentityBundleInput,
) -> CommunityOnboardingGateReport {
    let mut findings = Vec::new();
    validate_testnet_identity(&mut findings, input.chain_id, &input.network_id);
    for (code, detail, value) in [
        (
            "validator_id_missing",
            "validator id is required",
            &input.validator_id,
        ),
        (
            "validator_uma_id_missing",
            "validator UMA id is required",
            &input.validator_uma_id,
        ),
        (
            "enrollment_token_id_missing",
            "enrollment token id is required",
            &input.enrollment_token_id,
        ),
        (
            "identity_manifest_digest_missing",
            "identity manifest digest is required",
            &input.identity_manifest_digest,
        ),
    ] {
        require_non_empty(&mut findings, code, detail, value);
    }
    if !input.consensus_key_role_verified {
        findings.push(error(
            "consensus_key_role_unverified",
            "consensus key role proof is missing or invalid",
        ));
    }
    if !input.peer_key_role_verified {
        findings.push(error(
            "peer_key_role_unverified",
            "peer key role proof is missing or invalid",
        ));
    }
    if !input.operator_key_role_verified {
        findings.push(error(
            "operator_key_role_unverified",
            "operator key role proof is missing or invalid",
        ));
    }
    validate_backup_proof(input.backup_proof.as_ref(), &mut findings);
    gate_report(
        "identity_bundle",
        &input.validator_id,
        "package_compatibility",
        vec!["verify identity manifest and backup proof before package handoff".to_string()],
        findings,
    )
}

pub fn preview_community_cluster_assignment(
    input: &CommunityClusterAssignmentPreviewInput,
) -> CommunityClusterAssignmentPreviewReport {
    let mut findings = Vec::new();
    validate_testnet_identity(&mut findings, input.chain_id, &input.network_id);
    require_non_empty(
        &mut findings,
        "validator_id_missing",
        "validator id is required",
        &input.validator_id,
    );
    if input.planned_validator_addresses.is_empty() {
        findings.push(error(
            "planned_validator_addresses_missing",
            "cluster assignment preview requires the planned validator address set",
        ));
    }
    if input.planned_validator_addresses.len() != input.planned_validator_count {
        findings.push(error(
            "planned_validator_addresses_count_mismatch",
            format!(
                "planned validator address count {} must equal planned validator count {}",
                input.planned_validator_addresses.len(),
                input.planned_validator_count
            ),
        ));
    }
    if input
        .planned_validator_addresses
        .iter()
        .any(|address| address.trim().is_empty())
    {
        findings.push(error(
            "planned_validator_address_missing",
            "planned validator addresses must be non-empty",
        ));
    }
    let mut unique_addresses = input.planned_validator_addresses.clone();
    unique_addresses.sort_unstable();
    unique_addresses.dedup();
    if unique_addresses.len() != input.planned_validator_addresses.len() {
        findings.push(error(
            "duplicate_planned_validator_address",
            "planned validator addresses must be unique",
        ));
    }
    if !input
        .planned_validator_addresses
        .iter()
        .any(|address| address == &input.validator_id)
    {
        findings.push(error(
            "validator_id_not_in_planned_set",
            "validator id must be present in the planned validator address set",
        ));
    }
    if input.planned_validator_count <= input.existing_validator_count {
        findings.push(error(
            "planned_validator_count_not_expanded",
            "cluster assignment must expand the validator set",
        ));
    }
    if !input.anti_affinity_passed {
        findings.push(error(
            "anti_affinity_failed",
            "cluster assignment fails anti-affinity checks",
        ));
    }
    if !input.fault_domain_diversity_passed {
        findings.push(error(
            "fault_domain_diversity_failed",
            "cluster assignment fails fault-domain diversity checks",
        ));
    }
    if input.would_reduce_quorum || input.would_displace_active_validator {
        findings.push(error(
            "unsafe_cluster_assignment",
            "cluster assignment would reduce quorum or displace an active validator",
        ));
    }
    if input.archive_contained_dependency {
        findings.push(error(
            "cluster_assignment_archive_dependency",
            "cluster assignment cannot depend on archive-contained evidence",
        ));
    }

    let activation_recorded_height = match input.activation_height {
        Some(activation_height) => {
            match activation_height.checked_add(crate::validator::VALIDATOR_SHADOW_PHASE_BLOCKS) {
                Some(recorded_height) => Some(recorded_height),
                None => {
                    findings.push(error(
                        "activation_height_overflow",
                        "activation height cannot be advanced by the shadow phase",
                    ));
                    None
                }
            }
        }
        None => {
            findings.push(error(
                "activation_height_missing",
                "activation height H is required for cluster assignment preview",
            ));
            None
        }
    };
    let expected_activation_effective_height = activation_recorded_height.and_then(|height| {
        height.checked_add(1).or_else(|| {
            findings.push(error(
                "activation_effective_height_overflow",
                "activation effective height cannot be derived from the shadow completion height",
            ));
            None
        })
    });
    if input.activation_effective_height.is_none() {
        findings.push(error(
            "activation_effective_height_missing",
            "activation effective height H+1001 is required for cluster assignment preview",
        ));
    } else if input.activation_effective_height != expected_activation_effective_height {
        findings.push(error(
            "activation_effective_height_mismatch",
            format!(
                "activation effective height {:?} must equal shadow completion height {:?} plus one",
                input.activation_effective_height, activation_recorded_height
            ),
        ));
    }

    let can_compute_clusters = !input.planned_validator_addresses.is_empty()
        && input.planned_validator_addresses.len() == input.planned_validator_count
        && input
            .planned_validator_addresses
            .iter()
            .all(|address| !address.trim().is_empty())
        && unique_addresses.len() == input.planned_validator_addresses.len();
    let cluster_memberships = if can_compute_clusters {
        let planned_validators = input
            .planned_validator_addresses
            .iter()
            .map(|address| {
                Validator::new(
                    address.clone(),
                    format!("community-preview-key-{address}"),
                    format!("Community preview validator {address}"),
                    0,
                )
            })
            .collect::<Vec<_>>();
        canonical_validator_clusters_for_epoch(&planned_validators, input.assignment_epoch)
            .into_iter()
            .map(|(cluster_id, members)| {
                let validator_ids = members
                    .into_iter()
                    .map(|validator| validator.address)
                    .collect::<Vec<_>>();
                let validator_count = validator_ids.len();
                let cluster_quorum_threshold = quorum_threshold(validator_count);
                CommunityClusterMembershipPreview {
                    cluster_id,
                    validator_ids,
                    quorum_threshold: cluster_quorum_threshold,
                    active_liveness_margin: validator_count as isize
                        - cluster_quorum_threshold as isize,
                }
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let selected_membership = cluster_memberships.iter().find(|membership| {
        membership
            .validator_ids
            .iter()
            .any(|id| id == &input.validator_id)
    });
    if let Some(requested_cluster_id) = input.requested_cluster_id {
        if let Some(membership) = selected_membership {
            if requested_cluster_id != membership.cluster_id {
                findings.push(error(
                    "requested_cluster_assignment_mismatch",
                    format!(
                        "requested cluster {} does not match canonical cluster {}",
                        requested_cluster_id, membership.cluster_id
                    ),
                ));
            }
        }
    }
    let dynamic_quorum_threshold = selected_membership
        .map(|membership| membership.quorum_threshold)
        .unwrap_or_default();
    let active_liveness_margin = selected_membership
        .map(|membership| membership.active_liveness_margin)
        .unwrap_or_default();
    let cluster_assignment = selected_membership.map(|membership| membership.cluster_id);
    let has_errors = has_errors(&findings);
    CommunityClusterAssignmentPreviewReport {
        ok: !has_errors,
        decision: if has_errors {
            "NO_GO"
        } else {
            "CLUSTER_PREVIEW_DRY_RUN_GO"
        }
        .to_string(),
        dry_run_only: true,
        validator_id: input.validator_id.clone(),
        cluster_assignment,
        planned_validator_count: input.planned_validator_count,
        dynamic_quorum_threshold,
        active_liveness_margin,
        cluster_memberships,
        assignment_epoch: input.assignment_epoch,
        activation_height: input.activation_height,
        activation_recorded_height,
        activation_effective_height: input.activation_effective_height,
        findings,
    }
}

pub fn evaluate_community_activation_eligibility(
    input: &CommunityActivationEligibilityInput,
) -> CommunityOnboardingGateReport {
    let mut findings = Vec::new();
    validate_testnet_identity(&mut findings, input.chain_id, &input.network_id);
    require_non_empty(
        &mut findings,
        "validator_id_missing",
        "validator id is required",
        &input.validator_id,
    );

    findings.extend(verify_community_enrollment_token(&input.enrollment_token).findings);
    findings.extend(verify_community_package_manifest(&input.package_manifest).findings);
    findings.extend(verify_community_identity_bundle(&input.identity_bundle).findings);
    findings.extend(
        preview_community_cluster_assignment(&input.cluster_assignment)
            .findings
            .into_iter(),
    );
    validate_config_render_manifest(&input.config_render, &mut findings);
    validate_observer_sync_proof(&input.observer_sync, &mut findings);
    validate_vote_only_eligibility(&input.vote_only, &mut findings);
    validate_proposer_probation(
        &input.proposer_probation,
        input.activation_requested,
        &mut findings,
    );
    validate_state_proof(input.state_proof.as_ref(), &mut findings);

    if input.archive_contained_dependency
        || input.observer_sync.archive_contained_dependency
        || input.package_manifest.archive_snapshot_dependency
        || input.cluster_assignment.archive_contained_dependency
    {
        findings.push(error(
            "activation_blocked_archive_contained_dependency",
            "activation cannot depend on archive-contained or archive snapshot evidence",
        ));
    }

    gate_report(
        "activation_eligibility",
        &input.validator_id,
        "active",
        vec![
            "keep validator vote-only until proposer probation proof is clean".to_string(),
            "activate only after token, package, identity, cluster, config, observer, vote-only, probation, and state proofs all pass".to_string(),
        ],
        findings,
    )
}

fn validate_testnet_identity(
    findings: &mut Vec<OnboardingFinding>,
    chain_id: u64,
    network_id: &str,
) {
    if chain_id != SYNERGY_TESTNET_V3_CHAIN_ID {
        findings.push(error(
            "wrong_chain_id",
            format!(
                "expected chain_id {} but got {}",
                SYNERGY_TESTNET_V3_CHAIN_ID, chain_id
            ),
        ));
    }
    if network_id != SYNERGY_TESTNET_V3_NETWORK_ID {
        findings.push(error(
            "wrong_network_id",
            format!(
                "expected network_id {} but got {}",
                SYNERGY_TESTNET_V3_NETWORK_ID, network_id
            ),
        ));
    }
}

fn validate_backup_proof(
    proof: Option<&CommunityBackupVerificationProof>,
    findings: &mut Vec<OnboardingFinding>,
) {
    let Some(proof) = proof else {
        findings.push(error(
            "backup_proof_missing",
            "identity bundle requires backup verification proof",
        ));
        return;
    };
    require_non_empty(
        findings,
        "backup_manifest_digest_missing",
        "backup manifest digest is required",
        &proof.backup_manifest_digest,
    );
    require_non_empty(
        findings,
        "encrypted_backup_digest_missing",
        "encrypted backup digest is required",
        &proof.encrypted_backup_digest,
    );
    require_non_empty(
        findings,
        "operator_recovery_contact_hash_missing",
        "operator recovery contact hash is required",
        &proof.operator_recovery_contact_hash,
    );
    if !proof.restore_tested {
        findings.push(error(
            "backup_restore_not_tested",
            "backup proof must include restore-test evidence",
        ));
    }
    if proof.contains_private_key_material {
        findings.push(error(
            "backup_proof_contains_private_key_material",
            "backup proof must not embed private key material",
        ));
    }
}

fn validate_config_render_manifest(
    input: &CommunityConfigRenderManifestInput,
    findings: &mut Vec<OnboardingFinding>,
) {
    validate_testnet_identity(findings, input.chain_id, &input.network_id);
    require_non_empty(
        findings,
        "validator_id_missing",
        "validator id is required",
        &input.validator_id,
    );
    require_non_empty(
        findings,
        "config_render_manifest_digest_missing",
        "config render manifest digest is required",
        &input.render_manifest_digest,
    );
    require_non_empty(
        findings,
        "service_user_missing",
        "service user is required",
        &input.service_user,
    );
    if !input.templates_are_examples {
        findings.push(error(
            "config_render_not_example_only",
            "config render manifest must use operator-editable .example templates",
        ));
    }
    if input.contains_secrets {
        findings.push(error(
            "config_render_contains_secrets",
            "config render manifest must not contain secrets",
        ));
    }
    if input.config_paths.is_empty() {
        findings.push(error(
            "config_render_paths_missing",
            "config render manifest must list rendered paths",
        ));
    }
    if input
        .config_paths
        .iter()
        .any(|path| path.contains("/config/") && !path.ends_with(".example"))
    {
        findings.push(error(
            "config_render_contains_live_config_path",
            "operator-editable config render paths must end with .example",
        ));
    }
    if !input.rollback_plan_present {
        findings.push(error(
            "rollback_plan_missing",
            "config render manifest requires rollback plan evidence",
        ));
    }
}

fn validate_observer_sync_proof(
    input: &CommunityObserverSyncProof,
    findings: &mut Vec<OnboardingFinding>,
) {
    if !input.observer_sync_complete {
        findings.push(error(
            "observer_sync_incomplete",
            "observer sync proof is incomplete",
        ));
    }
    if input.local_finalized_height != input.quorum_finalized_height
        || !same_trimmed(&input.local_finalized_hash, &input.quorum_finalized_hash)
    {
        findings.push(error(
            "finalized_head_mismatch",
            "observer finalized head does not match quorum finalized head",
        ));
    }
    if input.local_high_qc_height != input.quorum_high_qc_height
        || !same_trimmed(&input.local_high_qc_hash, &input.quorum_high_qc_hash)
    {
        findings.push(error(
            "high_qc_mismatch",
            "observer high QC does not match quorum high QC",
        ));
    }
    if !input.state_proof_verified {
        findings.push(error(
            "observer_state_proof_unverified",
            "observer sync proof must include verified state proof",
        ));
    }
    if input.archive_contained_dependency {
        findings.push(error(
            "observer_sync_archive_dependency",
            "observer sync cannot use archive-contained evidence",
        ));
    }
}

fn validate_vote_only_eligibility(
    input: &CommunityVoteOnlyEligibilityInput,
    findings: &mut Vec<OnboardingFinding>,
) {
    if !input.approval_record_present {
        findings.push(error(
            "approval_record_missing",
            "vote-only eligibility requires approval record",
        ));
    }
    if !input.vote_only_requested {
        findings.push(error(
            "vote_only_not_requested",
            "vote-only eligibility requires vote-only request",
        ));
    }
    if input.unresolved_local_fork_evidence {
        findings.push(error(
            "unresolved_local_fork_evidence",
            "vote-only eligibility blocks unresolved local fork evidence",
        ));
    }
    if input.proposer_requested {
        findings.push(error(
            "vote_only_cannot_propose",
            "vote-only validator cannot request proposer duties",
        ));
    }
}

fn validate_proposer_probation(
    input: &CommunityProposerProbationEligibilityInput,
    activation_requested: bool,
    findings: &mut Vec<OnboardingFinding>,
) {
    let stage = input.current_stage.trim();
    if stage == "observer" && input.proposer_requested {
        findings.push(error(
            "observer_cannot_propose",
            "observer stage cannot request proposer duties",
        ));
    }
    if stage == "vote_only" && input.proposer_requested {
        findings.push(error(
            "vote_only_cannot_propose",
            "vote-only stage cannot request proposer duties",
        ));
    }
    if input.probation_blocks_required == 0 {
        findings.push(error(
            "proposer_probation_missing",
            "proposer probation block requirement must be greater than zero",
        ));
    }
    if activation_requested && stage != "proposer_probation" {
        findings.push(error(
            "proposer_probation_required",
            "activation requires proposer probation before active state",
        ));
    }
    if activation_requested && input.probation_blocks_completed < input.probation_blocks_required {
        findings.push(error(
            "proposer_probation_required",
            "activation requires completed proposer probation blocks",
        ));
    }
    if activation_requested && !input.clean_vote_only_window {
        findings.push(error(
            "clean_vote_only_window_missing",
            "activation requires clean vote-only/proposer probation evidence",
        ));
    }
}

fn validate_state_proof(
    proof: Option<&CommunityStateProof>,
    findings: &mut Vec<OnboardingFinding>,
) {
    let Some(proof) = proof else {
        findings.push(error(
            "state_proof_missing",
            "activation requires verified latest state proof",
        ));
        return;
    };
    require_non_empty(
        findings,
        "state_root_digest_missing",
        "state root digest is required",
        &proof.state_root_digest,
    );
    require_non_empty(
        findings,
        "checkpoint_manifest_digest_missing",
        "checkpoint manifest digest is required",
        &proof.checkpoint_manifest_digest,
    );
    require_non_empty(
        findings,
        "committed_qc_digest_missing",
        "committed QC digest is required",
        &proof.committed_qc_digest,
    );
    if !proof.latest_finalized_head_verified {
        findings.push(error(
            "state_proof_latest_finalized_head_unverified",
            "state proof must verify latest finalized head",
        ));
    }
}

fn gate_report(
    gate: &'static str,
    validator_id: &str,
    next_stage_when_ok: &'static str,
    actions: Vec<String>,
    findings: Vec<OnboardingFinding>,
) -> CommunityOnboardingGateReport {
    let has_errors = has_errors(&findings);
    CommunityOnboardingGateReport {
        ok: !has_errors,
        decision: if has_errors { "NO_GO" } else { "DRY_RUN_GO" }.to_string(),
        dry_run_only: true,
        gate: gate.to_string(),
        validator_id: validator_id.to_string(),
        next_stage: if has_errors {
            "blocked".to_string()
        } else {
            next_stage_when_ok.to_string()
        },
        actions,
        findings,
    }
}

fn error(code: impl Into<String>, detail: impl Into<String>) -> OnboardingFinding {
    OnboardingFinding {
        code: code.into(),
        severity: OnboardingSeverity::Error,
        detail: detail.into(),
    }
}

fn warning(code: impl Into<String>, detail: impl Into<String>) -> OnboardingFinding {
    OnboardingFinding {
        code: code.into(),
        severity: OnboardingSeverity::Warning,
        detail: detail.into(),
    }
}

fn require_non_empty(
    findings: &mut Vec<OnboardingFinding>,
    code: &'static str,
    detail: &'static str,
    value: &str,
) {
    if value.trim().is_empty() {
        findings.push(error(code, detail));
    }
}

fn has_errors(findings: &[OnboardingFinding]) -> bool {
    findings
        .iter()
        .any(|finding| finding.severity == OnboardingSeverity::Error)
}

fn same_trimmed(left: &str, right: &str) -> bool {
    !left.trim().is_empty() && left.trim() == right.trim()
}

fn default_workspace_root() -> String {
    "/opt/synergy/validator".to_string()
}

fn default_service_user() -> String {
    "synergy-validator".to_string()
}

fn community_bundle_files(
    workspace_root: &str,
    include_wireguard_profile: bool,
) -> Vec<CommunityValidatorBundleFile> {
    let root = workspace_root.trim_end_matches('/');
    let mut files = vec![
        bundle_file(
            format!("{root}/bin/synergy-validator"),
            "signed_binary",
            false,
            false,
        ),
        bundle_file(
            format!("{root}/config/node.toml.example"),
            "config_example",
            false,
            true,
        ),
        bundle_file(
            format!("{root}/config/validator.toml.example"),
            "validator_config_example",
            false,
            true,
        ),
        bundle_file(
            format!("{root}/systemd/synergy-validator.service.example"),
            "systemd_unit_example",
            false,
            true,
        ),
        bundle_file(
            format!("{root}/firewall/validator-ports.example"),
            "firewall_example",
            false,
            true,
        ),
        bundle_file(
            format!("{root}/runbooks/community-validator.md"),
            "runbook",
            false,
            false,
        ),
        bundle_file(
            format!("{root}/status/doctor-checklist.json"),
            "doctor_checklist",
            false,
            false,
        ),
    ];
    if include_wireguard_profile {
        files.push(bundle_file(
            format!("{root}/wireguard/wg0.conf.example"),
            "wireguard_example",
            false,
            true,
        ));
    }
    files
}

fn bundle_file(
    path: String,
    kind: &'static str,
    sensitive: bool,
    required_operator_edit: bool,
) -> CommunityValidatorBundleFile {
    CommunityValidatorBundleFile {
        path,
        kind: kind.to_string(),
        sensitive,
        required_operator_edit,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_input() -> CommunityValidatorPreflightInput {
        CommunityValidatorPreflightInput {
            chain_id: SYNERGY_TESTNET_V3_CHAIN_ID,
            network_id: SYNERGY_TESTNET_V3_NETWORK_ID.to_string(),
            validator_id: "validator-7".to_string(),
            validator_uma_id: "uma-validator-7".to_string(),
            stake_amount_nwei: REQUIRED_VALIDATOR_STAKE_NWEI,
            duplicate_validator_id: false,
            duplicate_validator_uma_id: false,
            consensus_key_role_verified: true,
            peer_key_role_verified: true,
            operator_key_role_verified: true,
            nat_reachable: true,
            p2p_port_open: true,
            discovery_port_open: true,
            cluster_assignment: Some(1),
            existing_validator_count: 6,
            planned_validator_count: 7,
            rollback_plan_present: true,
            bundle_manifest_path: Some("validator-7-bundle.json".to_string()),
        }
    }

    fn finding_codes(report: &CommunityValidatorPreflightReport) -> Vec<String> {
        report
            .findings
            .iter()
            .map(|finding| finding.code.clone())
            .collect()
    }

    #[test]
    fn community_validator_preflight_accepts_valid_dynamic_expansion() {
        let report = evaluate_community_validator_preflight(&valid_input());
        assert!(report.ok, "{:?}", report.findings);
        assert_eq!(report.decision, "DRY_RUN_GO");
        assert_eq!(report.planned_validator_count, 7);
    }

    #[test]
    fn community_validator_preflight_rejects_wrong_chain_and_duplicate_identity() {
        let mut input = valid_input();
        input.chain_id = 999;
        input.duplicate_validator_id = true;
        input.duplicate_validator_uma_id = true;
        let report = evaluate_community_validator_preflight(&input);
        let codes = finding_codes(&report);
        assert!(!report.ok);
        assert!(codes.contains(&"wrong_chain_id".to_string()));
        assert!(codes.contains(&"duplicate_validator_id".to_string()));
        assert!(codes.contains(&"duplicate_validator_uma_id".to_string()));
    }

    #[test]
    fn community_validator_preflight_rejects_insufficient_stake() {
        let mut input = valid_input();
        input.stake_amount_nwei = REQUIRED_VALIDATOR_STAKE_NWEI - 1;
        let report = evaluate_community_validator_preflight(&input);
        assert!(!report.ok);
        assert!(finding_codes(&report).contains(&"insufficient_stake".to_string()));
    }

    #[test]
    fn community_validator_preflight_rejects_bad_keys_and_nat_failure() {
        let mut input = valid_input();
        input.consensus_key_role_verified = false;
        input.peer_key_role_verified = false;
        input.operator_key_role_verified = false;
        input.nat_reachable = false;
        input.p2p_port_open = false;
        input.discovery_port_open = false;
        let report = evaluate_community_validator_preflight(&input);
        let codes = finding_codes(&report);
        assert!(!report.ok);
        assert!(codes.contains(&"consensus_key_role_unverified".to_string()));
        assert!(codes.contains(&"peer_key_role_unverified".to_string()));
        assert!(codes.contains(&"operator_key_role_unverified".to_string()));
        assert!(codes.contains(&"nat_unreachable".to_string()));
        assert!(codes.contains(&"p2p_port_closed".to_string()));
        assert!(codes.contains(&"discovery_port_closed".to_string()));
    }

    #[test]
    fn community_validator_preflight_rejects_missing_cluster_or_rollback() {
        let mut input = valid_input();
        input.cluster_assignment = None;
        input.planned_validator_count = input.existing_validator_count;
        input.rollback_plan_present = false;
        let report = evaluate_community_validator_preflight(&input);
        let codes = finding_codes(&report);
        assert!(!report.ok);
        assert!(codes.contains(&"cluster_assignment_missing".to_string()));
        assert!(codes.contains(&"planned_validator_count_not_expanded".to_string()));
        assert!(codes.contains(&"rollback_plan_missing".to_string()));
    }

    fn valid_bundle_input() -> CommunityValidatorBundleInput {
        CommunityValidatorBundleInput {
            preflight: valid_input(),
            release_binary_digest: "sha256:release".to_string(),
            network_config_digest: "sha256:config".to_string(),
            validator_set_digest: "sha256:validators".to_string(),
            checkpoint_manifest_digest: "sha256:checkpoint".to_string(),
            workspace_root: "/opt/synergy/validator".to_string(),
            service_user: "synergy-validator".to_string(),
            include_wireguard_profile: true,
        }
    }

    #[test]
    fn community_validator_bundle_manifest_is_dry_run_and_secret_free() {
        let manifest = build_community_validator_bundle_manifest(&valid_bundle_input());
        assert!(manifest.ok, "{:?}", manifest.findings);
        assert_eq!(manifest.decision, "BUNDLE_DRY_RUN_GO");
        assert!(manifest.dry_run_only);
        assert!(manifest.files.iter().any(|file| {
            file.path == "/opt/synergy/validator/wireguard/wg0.conf.example"
                && !file.sensitive
                && file.required_operator_edit
        }));
        assert!(manifest.files.iter().all(|file| !file.sensitive));
    }

    #[test]
    fn community_validator_bundle_refuses_failed_preflight_or_missing_digests() {
        let mut input = valid_bundle_input();
        input.preflight.chain_id = 999;
        input.release_binary_digest.clear();
        let manifest = build_community_validator_bundle_manifest(&input);
        let codes: Vec<String> = manifest
            .findings
            .iter()
            .map(|finding| finding.code.clone())
            .collect();
        assert!(!manifest.ok);
        assert!(manifest.files.is_empty());
        assert!(codes.contains(&"wrong_chain_id".to_string()));
        assert!(codes.contains(&"release_binary_digest_missing".to_string()));
    }

    fn valid_join_input() -> CommunityValidatorDryRunJoinInput {
        CommunityValidatorDryRunJoinInput {
            chain_id: SYNERGY_TESTNET_V3_CHAIN_ID,
            network_id: SYNERGY_TESTNET_V3_NETWORK_ID.to_string(),
            validator_id: "validator-7".to_string(),
            observer_sync_complete: true,
            local_finalized_height: 640_000,
            local_finalized_hash: "0xabc".to_string(),
            quorum_finalized_height: 640_000,
            quorum_finalized_hash: "0xabc".to_string(),
            local_high_qc_height: 640_000,
            local_high_qc_hash: "0xqc".to_string(),
            quorum_high_qc_height: 640_000,
            quorum_high_qc_hash: "0xqc".to_string(),
            config_digest: "sha256:config".to_string(),
            expected_config_digest: "sha256:config".to_string(),
            validator_set_digest: "sha256:validators".to_string(),
            expected_validator_set_digest: "sha256:validators".to_string(),
            binary_digest: "sha256:release".to_string(),
            compatible_binary_digests: vec!["sha256:release".to_string()],
            unresolved_local_fork_evidence: false,
            approval_record_present: true,
            vote_only_requested: true,
            proposer_probation_blocks: 32,
        }
    }

    #[test]
    fn community_validator_dry_run_join_allows_vote_only_when_quorum_matches() {
        let report = evaluate_community_validator_dry_run_join(&valid_join_input());
        assert!(report.ok, "{:?}", report.findings);
        assert_eq!(report.decision, "DRY_RUN_VOTE_ONLY_GO");
        assert_eq!(report.next_stage, "vote_only");
        assert_eq!(report.proposer_probation_blocks, 32);
    }

    #[test]
    fn community_validator_dry_run_join_rejects_digest_or_head_mismatch() {
        let mut input = valid_join_input();
        input.local_finalized_hash = "0xwrong".to_string();
        input.config_digest = "sha256:wrong".to_string();
        input.compatible_binary_digests = vec!["sha256:other".to_string()];
        input.unresolved_local_fork_evidence = true;
        let report = evaluate_community_validator_dry_run_join(&input);
        let codes: Vec<String> = report
            .findings
            .iter()
            .map(|finding| finding.code.clone())
            .collect();
        assert!(!report.ok);
        assert_eq!(report.next_stage, "blocked");
        assert!(codes.contains(&"finalized_head_mismatch".to_string()));
        assert!(codes.contains(&"config_digest_mismatch".to_string()));
        assert!(codes.contains(&"binary_digest_not_approved".to_string()));
        assert!(codes.contains(&"unresolved_local_fork_evidence".to_string()));
    }

    #[test]
    fn community_validator_dry_run_join_requires_vote_only_approval_and_probation() {
        let mut input = valid_join_input();
        input.observer_sync_complete = false;
        input.approval_record_present = false;
        input.vote_only_requested = false;
        input.proposer_probation_blocks = 0;
        let report = evaluate_community_validator_dry_run_join(&input);
        let codes: Vec<String> = report
            .findings
            .iter()
            .map(|finding| finding.code.clone())
            .collect();
        assert!(!report.ok);
        assert!(codes.contains(&"observer_sync_incomplete".to_string()));
        assert!(codes.contains(&"approval_record_missing".to_string()));
        assert!(codes.contains(&"vote_only_not_requested".to_string()));
        assert!(codes.contains(&"proposer_probation_missing".to_string()));
    }

    fn valid_enrollment_token() -> CommunityEnrollmentTokenInput {
        CommunityEnrollmentTokenInput {
            chain_id: SYNERGY_TESTNET_V3_CHAIN_ID,
            network_id: SYNERGY_TESTNET_V3_NETWORK_ID.to_string(),
            token_id: "token-validator-7".to_string(),
            validator_id: "validator-7".to_string(),
            issued_to_uma_id: "uma-validator-7".to_string(),
            scope: "community_validator".to_string(),
            expires_at_unix: 2_000,
            now_unix: 1_000,
            issuer_signature_verified: true,
            revoked: false,
        }
    }

    fn valid_package_manifest() -> CommunityPackageCompatibilityManifest {
        CommunityPackageCompatibilityManifest {
            chain_id: SYNERGY_TESTNET_V3_CHAIN_ID,
            network_id: SYNERGY_TESTNET_V3_NETWORK_ID.to_string(),
            package_id: "validator-appliance-v1".to_string(),
            validator_id: "validator-7".to_string(),
            artifact_decision: "GO".to_string(),
            appliance_version: "1.0.0".to_string(),
            runtime_version: "15.0.5".to_string(),
            target_arch: "linux-x86_64".to_string(),
            signed_release_digest: "sha256:release".to_string(),
            config_schema_version: "validator-config-v1".to_string(),
            includes_secrets: false,
            archive_snapshot_dependency: false,
        }
    }

    fn valid_backup_proof() -> CommunityBackupVerificationProof {
        CommunityBackupVerificationProof {
            backup_manifest_digest: "sha256:backup-manifest".to_string(),
            encrypted_backup_digest: "sha256:encrypted-backup".to_string(),
            restore_tested: true,
            operator_recovery_contact_hash: "sha256:contact".to_string(),
            contains_private_key_material: false,
        }
    }

    fn valid_identity_bundle() -> CommunityIdentityBundleInput {
        CommunityIdentityBundleInput {
            chain_id: SYNERGY_TESTNET_V3_CHAIN_ID,
            network_id: SYNERGY_TESTNET_V3_NETWORK_ID.to_string(),
            validator_id: "validator-7".to_string(),
            validator_uma_id: "uma-validator-7".to_string(),
            enrollment_token_id: "token-validator-7".to_string(),
            identity_manifest_digest: "sha256:identity".to_string(),
            consensus_key_role_verified: true,
            peer_key_role_verified: true,
            operator_key_role_verified: true,
            backup_proof: Some(valid_backup_proof()),
        }
    }

    fn valid_cluster_assignment() -> CommunityClusterAssignmentPreviewInput {
        CommunityClusterAssignmentPreviewInput {
            chain_id: SYNERGY_TESTNET_V3_CHAIN_ID,
            network_id: SYNERGY_TESTNET_V3_NETWORK_ID.to_string(),
            validator_id: "validator-7".to_string(),
            existing_validator_count: 6,
            planned_validator_count: 7,
            requested_cluster_id: Some(0),
            planned_validator_addresses: (1..=7)
                .map(|index| format!("validator-{index}"))
                .collect(),
            assignment_epoch: 0,
            activation_height: Some(640_000),
            activation_effective_height: Some(641_001),
            anti_affinity_passed: true,
            fault_domain_diversity_passed: true,
            would_reduce_quorum: false,
            would_displace_active_validator: false,
            archive_contained_dependency: false,
        }
    }

    fn valid_config_render() -> CommunityConfigRenderManifestInput {
        CommunityConfigRenderManifestInput {
            chain_id: SYNERGY_TESTNET_V3_CHAIN_ID,
            network_id: SYNERGY_TESTNET_V3_NETWORK_ID.to_string(),
            validator_id: "validator-7".to_string(),
            render_manifest_digest: "sha256:render".to_string(),
            service_user: "synergy-validator".to_string(),
            templates_are_examples: true,
            contains_secrets: false,
            config_paths: vec![
                "/opt/synergy/validator/config/node.toml.example".to_string(),
                "/opt/synergy/validator/config/validator.toml.example".to_string(),
            ],
            rollback_plan_present: true,
        }
    }

    fn valid_observer_sync() -> CommunityObserverSyncProof {
        CommunityObserverSyncProof {
            observer_sync_complete: true,
            local_finalized_height: 640_000,
            local_finalized_hash: "0xabc".to_string(),
            quorum_finalized_height: 640_000,
            quorum_finalized_hash: "0xabc".to_string(),
            local_high_qc_height: 640_000,
            local_high_qc_hash: "0xqc".to_string(),
            quorum_high_qc_height: 640_000,
            quorum_high_qc_hash: "0xqc".to_string(),
            state_proof_verified: true,
            archive_contained_dependency: false,
        }
    }

    fn valid_vote_only() -> CommunityVoteOnlyEligibilityInput {
        CommunityVoteOnlyEligibilityInput {
            approval_record_present: true,
            vote_only_requested: true,
            unresolved_local_fork_evidence: false,
            proposer_requested: false,
        }
    }

    fn valid_proposer_probation() -> CommunityProposerProbationEligibilityInput {
        CommunityProposerProbationEligibilityInput {
            current_stage: "proposer_probation".to_string(),
            probation_blocks_required: 32,
            probation_blocks_completed: 32,
            clean_vote_only_window: true,
            proposer_requested: false,
        }
    }

    fn valid_state_proof() -> CommunityStateProof {
        CommunityStateProof {
            state_root_digest: "sha256:state-root".to_string(),
            checkpoint_manifest_digest: "sha256:checkpoint".to_string(),
            committed_qc_digest: "sha256:committed-qc".to_string(),
            latest_finalized_head_verified: true,
        }
    }

    fn valid_activation_input() -> CommunityActivationEligibilityInput {
        CommunityActivationEligibilityInput {
            chain_id: SYNERGY_TESTNET_V3_CHAIN_ID,
            network_id: SYNERGY_TESTNET_V3_NETWORK_ID.to_string(),
            validator_id: "validator-7".to_string(),
            enrollment_token: valid_enrollment_token(),
            package_manifest: valid_package_manifest(),
            identity_bundle: valid_identity_bundle(),
            cluster_assignment: valid_cluster_assignment(),
            config_render: valid_config_render(),
            observer_sync: valid_observer_sync(),
            vote_only: valid_vote_only(),
            proposer_probation: valid_proposer_probation(),
            state_proof: Some(valid_state_proof()),
            archive_contained_dependency: false,
            activation_requested: true,
        }
    }

    fn gate_codes(report: &CommunityOnboardingGateReport) -> Vec<String> {
        report
            .findings
            .iter()
            .map(|finding| finding.code.clone())
            .collect()
    }

    #[test]
    fn enrollment_token_rejects_expired_wrong_chain_and_wrong_network() {
        let mut input = valid_enrollment_token();
        input.chain_id = 999;
        input.network_id = "wrong-network".to_string();
        input.now_unix = input.expires_at_unix;
        let report = verify_community_enrollment_token(&input);
        let codes = gate_codes(&report);
        assert!(!report.ok);
        assert!(codes.contains(&"wrong_chain_id".to_string()));
        assert!(codes.contains(&"wrong_network_id".to_string()));
        assert!(codes.contains(&"enrollment_token_expired".to_string()));
    }

    #[test]
    fn package_verify_rejects_no_go_artifact() {
        let mut input = valid_package_manifest();
        input.artifact_decision = "NO_GO".to_string();
        let report = verify_community_package_manifest(&input);
        assert!(!report.ok);
        assert!(gate_codes(&report).contains(&"artifact_no_go".to_string()));
    }

    #[test]
    fn identity_bundle_rejects_missing_backup_proof() {
        let mut input = valid_identity_bundle();
        input.backup_proof = None;
        let report = verify_community_identity_bundle(&input);
        assert!(!report.ok);
        assert!(gate_codes(&report).contains(&"backup_proof_missing".to_string()));
    }

    #[test]
    fn cluster_assignment_preview_rejects_unsafe_assignment() {
        let mut input = valid_cluster_assignment();
        input.would_reduce_quorum = true;
        input.would_displace_active_validator = true;
        let report = preview_community_cluster_assignment(&input);
        let codes: Vec<String> = report
            .findings
            .iter()
            .map(|finding| finding.code.clone())
            .collect();
        assert!(!report.ok);
        assert!(codes.contains(&"unsafe_cluster_assignment".to_string()));
        assert_eq!(report.dynamic_quorum_threshold, 5);
    }

    fn cluster_assignment_for_count(
        validator_count: usize,
        validator_id: &str,
        epoch: u64,
        activation_height: u64,
    ) -> CommunityClusterAssignmentPreviewInput {
        CommunityClusterAssignmentPreviewInput {
            chain_id: SYNERGY_TESTNET_V3_CHAIN_ID,
            network_id: SYNERGY_TESTNET_V3_NETWORK_ID.to_string(),
            validator_id: validator_id.to_string(),
            existing_validator_count: validator_count - 1,
            planned_validator_count: validator_count,
            requested_cluster_id: None,
            planned_validator_addresses: (1..=validator_count)
                .map(|index| format!("validator-{index}"))
                .collect(),
            assignment_epoch: epoch,
            activation_height: Some(activation_height),
            activation_effective_height: Some(activation_height + 1_001),
            anti_affinity_passed: true,
            fault_domain_diversity_passed: true,
            would_reduce_quorum: false,
            would_displace_active_validator: false,
            archive_contained_dependency: false,
        }
    }

    #[test]
    fn cluster_assignment_preview_reports_strict_five_of_six_quorum() {
        let input = cluster_assignment_for_count(6, "validator-6", 12, 70_000);
        let report = preview_community_cluster_assignment(&input);

        assert!(report.ok, "{:?}", report.findings);
        assert_eq!(report.cluster_memberships.len(), 1);
        assert_eq!(report.cluster_memberships[0].validator_ids.len(), 6);
        assert_eq!(report.cluster_memberships[0].quorum_threshold, 5);
        assert_eq!(report.dynamic_quorum_threshold, 5);
        assert_eq!(report.activation_height, Some(70_000));
        assert_eq!(report.activation_recorded_height, Some(71_000));
        assert_eq!(report.activation_effective_height, Some(71_001));
    }

    #[test]
    fn cluster_assignment_preview_reports_strict_seven_of_nine_quorum() {
        let input = cluster_assignment_for_count(9, "validator-9", 12, 80_000);
        let report = preview_community_cluster_assignment(&input);

        assert!(report.ok, "{:?}", report.findings);
        assert_eq!(report.cluster_memberships.len(), 1);
        assert_eq!(report.cluster_memberships[0].validator_ids.len(), 9);
        assert_eq!(report.cluster_memberships[0].quorum_threshold, 7);
        assert_eq!(report.dynamic_quorum_threshold, 7);
    }

    #[test]
    fn cluster_assignment_preview_reports_two_five_validator_clusters_with_four_of_five_quorum() {
        let input = cluster_assignment_for_count(10, "validator-10", 12, 90_000);
        let report = preview_community_cluster_assignment(&input);

        assert!(report.ok, "{:?}", report.findings);
        assert_eq!(report.cluster_memberships.len(), 2);
        assert_eq!(
            report
                .cluster_memberships
                .iter()
                .map(|membership| membership.validator_ids.len())
                .collect::<Vec<_>>(),
            vec![5, 5]
        );
        assert!(report
            .cluster_memberships
            .iter()
            .all(|membership| membership.quorum_threshold == 4));
        assert_eq!(report.dynamic_quorum_threshold, 4);
        assert_eq!(report.active_liveness_margin, 1);
        assert_eq!(
            report
                .cluster_memberships
                .iter()
                .flat_map(|membership| membership.validator_ids.iter())
                .collect::<std::collections::HashSet<_>>()
                .len(),
            10
        );
    }

    #[test]
    fn cluster_assignment_preview_is_deterministic_for_two_cluster_output() {
        let input = cluster_assignment_for_count(10, "validator-10", 27, 100_000);
        let mut reordered = input.clone();
        reordered.planned_validator_addresses.reverse();

        let first = preview_community_cluster_assignment(&input);
        let second = preview_community_cluster_assignment(&reordered);
        let runtime_validators = input
            .planned_validator_addresses
            .iter()
            .map(|address| {
                Validator::new(
                    address.clone(),
                    format!("runtime-preview-key-{address}"),
                    format!("Runtime preview validator {address}"),
                    0,
                )
            })
            .collect::<Vec<_>>();
        let runtime_memberships =
            canonical_validator_clusters_for_epoch(&runtime_validators, input.assignment_epoch)
                .into_iter()
                .map(|(cluster_id, members)| {
                    let validator_ids = members
                        .into_iter()
                        .map(|validator| validator.address)
                        .collect::<Vec<_>>();
                    let validator_count = validator_ids.len();
                    CommunityClusterMembershipPreview {
                        cluster_id,
                        validator_ids,
                        quorum_threshold: quorum_threshold(validator_count),
                        active_liveness_margin: validator_count as isize
                            - quorum_threshold(validator_count) as isize,
                    }
                })
                .collect::<Vec<_>>();

        assert_eq!(first.cluster_memberships, second.cluster_memberships);
        assert_eq!(first.cluster_memberships, runtime_memberships);
        assert_eq!(first.cluster_assignment, second.cluster_assignment);
        assert_eq!(first.dynamic_quorum_threshold, 4);
    }

    #[test]
    fn cluster_assignment_preview_scales_at_runtime_cluster_thresholds() {
        for (validator_count, expected_sizes, expected_quorums) in [
            (11, vec![6, 5], vec![5, 4]),
            (14, vec![7, 7], vec![5, 5]),
            (15, vec![8, 7], vec![6, 5]),
            (20, vec![10, 10], vec![7, 7]),
            (21, vec![7, 7, 7], vec![5, 5, 5]),
            (28, vec![7, 7, 7, 7], vec![5, 5, 5, 5]),
            (34, vec![9, 9, 8, 8], vec![7, 7, 6, 6]),
            (35, vec![7, 7, 7, 7, 7], vec![5, 5, 5, 5, 5]),
            (42, vec![7, 7, 7, 7, 7, 7], vec![5, 5, 5, 5, 5, 5]),
        ] {
            let input = cluster_assignment_for_count(
                validator_count,
                &format!("validator-{validator_count}"),
                33,
                120_000 + validator_count as u64,
            );
            let report = preview_community_cluster_assignment(&input);

            assert!(report.ok, "{validator_count}: {:?}", report.findings);
            assert_eq!(
                report
                    .cluster_memberships
                    .iter()
                    .map(|membership| membership.validator_ids.len())
                    .collect::<Vec<_>>(),
                expected_sizes
            );
            assert_eq!(
                report
                    .cluster_memberships
                    .iter()
                    .map(|membership| membership.quorum_threshold)
                    .collect::<Vec<_>>(),
                expected_quorums
            );
        }
    }

    #[test]
    fn cluster_assignment_preview_rejects_inconsistent_effective_height() {
        let mut input = cluster_assignment_for_count(10, "validator-10", 12, 110_000);
        input.activation_effective_height = Some(111_000);
        let report = preview_community_cluster_assignment(&input);

        assert!(!report.ok);
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.code == "activation_effective_height_mismatch"));
        assert_eq!(report.activation_recorded_height, Some(111_000));
        assert_eq!(report.activation_effective_height, Some(111_000));
    }

    #[test]
    fn activation_blocks_observer_from_proposing() {
        let mut input = valid_activation_input();
        input.proposer_probation.current_stage = "observer".to_string();
        input.proposer_probation.proposer_requested = true;
        let report = evaluate_community_activation_eligibility(&input);
        assert!(!report.ok);
        assert!(gate_codes(&report).contains(&"observer_cannot_propose".to_string()));
    }

    #[test]
    fn activation_blocks_vote_only_from_proposing() {
        let mut input = valid_activation_input();
        input.proposer_probation.current_stage = "vote_only".to_string();
        input.proposer_probation.proposer_requested = true;
        let report = evaluate_community_activation_eligibility(&input);
        assert!(!report.ok);
        assert!(gate_codes(&report).contains(&"vote_only_cannot_propose".to_string()));
    }

    #[test]
    fn activation_requires_probation_before_active() {
        let mut input = valid_activation_input();
        input.proposer_probation.current_stage = "vote_only".to_string();
        input.proposer_probation.probation_blocks_completed = 0;
        let report = evaluate_community_activation_eligibility(&input);
        assert!(!report.ok);
        assert!(gate_codes(&report).contains(&"proposer_probation_required".to_string()));
    }

    #[test]
    fn activation_blocks_archive_contained_dependency() {
        let mut input = valid_activation_input();
        input.archive_contained_dependency = true;
        let report = evaluate_community_activation_eligibility(&input);
        assert!(!report.ok);
        assert!(gate_codes(&report)
            .contains(&"activation_blocked_archive_contained_dependency".to_string()));
    }

    #[test]
    fn activation_blocks_missing_state_proof() {
        let mut input = valid_activation_input();
        input.state_proof = None;
        let report = evaluate_community_activation_eligibility(&input);
        assert!(!report.ok);
        assert!(gate_codes(&report).contains(&"state_proof_missing".to_string()));
    }

    #[test]
    fn activation_allows_only_clean_proof_chain() {
        let report = evaluate_community_activation_eligibility(&valid_activation_input());
        assert!(report.ok, "{:?}", report.findings);
        assert_eq!(report.gate, "activation_eligibility");
        assert_eq!(report.next_stage, "active");
    }
}
