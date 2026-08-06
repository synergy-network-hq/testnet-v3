use std::any::Any;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{self, Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::aegis_tx_tool::{
    decode_aegis_carrier_data, is_legacy_aegis_carrier_transaction, AegisTxSubmissionEnvelope,
};
use crate::config::{
    list_available_templates, load_node_config, load_node_config_from_template, NodeConfig,
    ResolvedConsensusMode,
};
use crate::consensus::cartel_detection::{CartelDetectionEngine, WhistleblowerSystem};
use crate::consensus::consensus_fork;
use crate::consensus::coordinated_finality_observer::{
    coordinated_finality_observer_from_canonical_finalized_genesis,
    install_coordinated_finality_observer, remove_coordinated_finality_observer,
};
use crate::consensus::coordinated_finality_store::CoordinatedFinalityStore;
use crate::consensus::coordinated_round_robin::{
    install_coordinated_consensus_ingress, remove_coordinated_consensus_ingress,
    CoordinatedConsensusEnvelope, CoordinatorState, CoordinatorStateStore,
};
use crate::consensus::coordinated_runtime::{
    CoordinatedBlockBuildContext, CoordinatedRuntime, CoordinatedRuntimeAction,
};
use crate::consensus::dao_governance::{DAOGovernance, SynergyOracle};
use crate::consensus::dual_quorum::{EntropyBeacon, ValidatorRotation};
use crate::consensus::self_realign::{
    expected_genesis_hash, persisted_recovery_state, RealignmentState,
};
use crate::consensus::signing_authority::DurableConsensusSigningAuthority;
use crate::consensus::single_authority_startup::{
    SingleAuthorityStartupPlan, VerifiedConsensusStartup,
};
use crate::consensus::synergy_score::SynergyScoreCalculator;
use crate::consensus::testnet_v3_bootstrap::{
    load_coordinated_round_robin_activation_bootstrap, load_testnet_v3_genesis_bootstrap,
};
use crate::consensus::testnet_v3_finality_context::FinalizedTypedContextProvider;
use crate::consensus::typed_coordinator::{
    begin_typed_consensus_startup_buffer, import_local_genesis_bound_coordinated_signer,
    import_local_genesis_bound_typed_signer, install_typed_coordinator_ingress,
    remove_typed_coordinator_ingress, replay_finalized_execution_state, run_typed_posy_driver,
    set_typed_consensus_startup_phase, P2pTypedConsensusEgress, TypedFinalityContextDigestSource,
    TypedNextHeightContextSource, TypedPosyCoordinator, TypedPosyCoordinatorStartup,
    TypedPosyDriver,
};
use crate::consensus::typed_finality_observer::{
    install_typed_finality_observer, remove_typed_finality_observer, TypedFinalityObserver,
};
use crate::consensus::typed_finality_store::TypedFinalityStore;
use crate::consensus::validator_keys::{
    load_local_validator_keypair_for_height, validator_public_key_with_declared_algorithm,
};
use crate::consensus_parameters::EtdagActivationPermit;
use crate::crypto::pqc::PQCManager;
use crate::etdag::{
    install_etdag_certified_input_ingress, remove_etdag_certified_input_ingress,
    EtdagCertifiedInputIngress, EtdagParameters, EtdagProtectedInputCoordinator,
};
use crate::execution::{
    install_finalized_execution_state_snapshot, publish_finalized_execution_state_snapshot,
    remove_finalized_execution_state_snapshot,
};
use crate::genesis::{canonical_genesis, GenesisDocument};
use crate::logging::{init_logger, LogLevel};
use crate::p2p;
use crate::role_profiles::{resolve_configured_role, NodeRole, RoleProfile};
use crate::rpc;
use crate::rpc::rpc_server::{SHARED_CHAIN, SYNC_MANAGER, TX_POOL};
use crate::sxcp;
use crate::sync::SyncManager;
use crate::synergy_types::{
    CanonicalSerialize, Hash, Height, POSY_PROTOCOL_VERSION, SYNERGY_TESTNET_V3_CHAIN_ID,
    SYNERGY_TESTNET_V3_NETWORK_ID,
};
use crate::telemetry;
use crate::testnet_v3_execution_bootstrap::load_finalized_testnet_v3_genesis_execution_state;
use crate::token::TOKEN_MANAGER;
use crate::transaction::Transaction;
use crate::utils;
use crate::validator::{consensus_membership_validators, ValidatorRegistration, VALIDATOR_MANAGER};
use crate::wallet;
use crate::{info, warn};
use serde::Deserialize;
use serde_json::json;

const OFFLINE_SNAPSHOT_COMMAND_STACK_BYTES: usize = 64 * 1024 * 1024;
/// Network input is untrusted even after the P2P handshake.  Keep typed
/// consensus work bounded independently from the general P2P queue so a peer
/// cannot turn a delayed validator round into unbounded memory consumption.
const TYPED_POSY_INGRESS_CAPACITY: usize = 512;
const COORDINATED_ROUND_ROBIN_INGRESS_CAPACITY: usize = 512;
/// A reset marker is proof that the controller removed *all* mutable consensus
/// history.  These are the locally durable consensus artifacts that must never
/// survive a fresh-genesis launch.  The block-chain journal itself is checked
/// separately against the canonical height-zero Genesis block.
const FRESH_RESET_FORBIDDEN_CONSENSUS_ARTIFACTS: &[&str] = &[
    "coordinated-round-robin-finality.json",
    "coordinated-round-robin-state.json",
    "consensus_signing_authorizations.json",
    "typed-posy-prepared.json",
    "typed-posy-finality.json",
    "typed-posy-finality.prepared.json",
    "timeout-certificates.json",
    "validation-certificates.json",
    "finality-qcs.json",
    "highest-qc.json",
];

struct RoleProcessGuard {
    child: Mutex<Child>,
}

/// Owns the only typed PoSy worker started by a role runtime.  A driver error
/// is captured for the main thread rather than ignored in a detached worker:
/// if the typed scheduling, authenticated ingress, or P2P egress fails, the
/// validator process must stop rather than remain alive with signing disabled
/// or silently fall back to inherited consensus.
struct TypedPosyWorker {
    handle: thread::JoinHandle<()>,
    fatal_error: Arc<Mutex<Option<String>>>,
}

impl TypedPosyWorker {
    fn fatal_error(&self) -> Option<String> {
        self.fatal_error.lock().ok().and_then(|error| error.clone())
    }

    fn join(self) {
        let _ = self.handle.join();
    }
}

/// Owns the only P1 coordinated worker started by a role runtime. Its error
/// is fatal: a validator must never remain available after losing the sole
/// signed assignment/commit lifecycle or its independent finality boundary.
struct CoordinatedRoundRobinWorker {
    handle: thread::JoinHandle<()>,
    fatal_error: Arc<Mutex<Option<String>>>,
}

impl CoordinatedRoundRobinWorker {
    fn fatal_error(&self) -> Option<String> {
        self.fatal_error.lock().ok().and_then(|error| error.clone())
    }

    fn join(self) {
        let _ = self.handle.join();
    }
}

/// The runtime has one and only one consensus worker.  P1's worker is kept
/// separate from typed PoSy so no inherited proposal, QC, VC, TC, vote, or
/// aggregation code can enter a coordinated launch through lifecycle glue.
enum FinalizedConsensusWorker {
    CoordinatedRoundRobin(CoordinatedRoundRobinWorker),
    SingleAuthority(SingleAuthorityWorker),
}

impl FinalizedConsensusWorker {
    fn fatal_error(&self) -> Option<String> {
        match self {
            Self::CoordinatedRoundRobin(worker) => worker.fatal_error(),
            Self::SingleAuthority(worker) => worker.fatal_error(),
        }
    }

    fn join(self) {
        match self {
            Self::CoordinatedRoundRobin(worker) => worker.join(),
            Self::SingleAuthority(worker) => worker.join(),
        }
    }
}

/// Owns the only `single_authority_v1` worker started by a role runtime.
///
/// It carries no ingress channel, no network handle, and no coordinated state:
/// the single-authority driver neither sends nor receives consensus messages.
struct SingleAuthorityWorker {
    handle: thread::JoinHandle<()>,
    fatal_error: Arc<Mutex<Option<String>>>,
}

impl SingleAuthorityWorker {
    fn fatal_error(&self) -> Option<String> {
        self.fatal_error.lock().ok().and_then(|error| error.clone())
    }

    fn join(self) {
        let _ = self.handle.join();
    }
}

#[derive(Debug, Deserialize)]
struct LaunchBlock1TransactionEnvelope {
    #[serde(default)]
    required_block_index: Option<u64>,
    #[serde(default)]
    description: Option<String>,
    transaction: Transaction,
}

#[cfg(unix)]
fn raise_runtime_nofile_limit(min_soft_limit: u64) {
    unsafe {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) != 0 {
            eprintln!("Warning: failed to inspect file descriptor limit");
            return;
        }

        if limit.rlim_cur >= min_soft_limit as libc::rlim_t {
            return;
        }

        let requested = (min_soft_limit as libc::rlim_t).min(limit.rlim_max);
        if requested <= limit.rlim_cur {
            return;
        }

        let updated = libc::rlimit {
            rlim_cur: requested,
            rlim_max: limit.rlim_max,
        };
        if libc::setrlimit(libc::RLIMIT_NOFILE, &updated) != 0 {
            eprintln!(
                "Warning: failed to raise file descriptor limit from {} to {}",
                limit.rlim_cur, requested
            );
        }
    }
}

#[cfg(not(unix))]
fn raise_runtime_nofile_limit(_min_soft_limit: u64) {}

fn read_env_file_value(path: &Path, key: &str) -> Option<String> {
    let contents = fs::read_to_string(path).ok()?;
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let Some((candidate_key, value)) = trimmed.split_once('=') else {
            continue;
        };
        if candidate_key.trim() != key {
            continue;
        }

        let value = value
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .trim()
            .to_string();
        if !value.is_empty() {
            return Some(value);
        }
    }
    None
}

fn candidate_launch_block1_rpc_urls(project_root: &Path) -> Vec<String> {
    let mut candidates = Vec::new();
    for key in [
        "SYNERGY_CORE_RPC_FALLBACK_URL",
        "SYNERGY_RPC_FALLBACK_URL",
        "RPC_FALLBACK_URL",
    ] {
        if let Ok(value) = env::var(key) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                candidates.push(trimmed.to_string());
            }
        }

        if let Some(value) = read_env_file_value(&project_root.join("node.env"), key) {
            candidates.push(value);
        }
    }

    let mut deduped = Vec::new();
    for candidate in candidates {
        if !deduped.contains(&candidate) {
            deduped.push(candidate);
        }
    }
    deduped
}

fn parse_rpc_block_number(value: &serde_json::Value) -> Option<u64> {
    if let Some(number) = value.as_u64() {
        return Some(number);
    }

    let text = value.as_str()?.trim();
    if let Some(hex) = text.strip_prefix("0x") {
        return u64::from_str_radix(hex, 16).ok();
    }
    text.parse::<u64>().ok()
}

fn arg_value(args: &[String], name: &str) -> Option<String> {
    let equals_prefix = format!("{name}=");
    if let Some(value) = args
        .iter()
        .find_map(|arg| arg.strip_prefix(&equals_prefix).map(str::to_string))
    {
        return Some(value);
    }
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
}

fn arg_values(args: &[String], name: &str) -> Vec<String> {
    let equals_prefix = format!("{name}=");
    let mut values = args
        .iter()
        .filter_map(|arg| arg.strip_prefix(&equals_prefix).map(str::to_string))
        .collect::<Vec<_>>();
    values.extend(
        args.windows(2)
            .filter(|pair| pair[0] == name)
            .map(|pair| pair[1].clone()),
    );
    values
}

fn arg_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|arg| arg == name)
}

fn optional_u64_arg(args: &[String], name: &str) -> Result<Option<u64>, String> {
    arg_value(args, name)
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|error| format!("invalid {name}: {error}"))
        })
        .transpose()
}

fn offline_snapshot_command_uses_large_stack(command: &str) -> bool {
    matches!(
        command,
        "create-snapshot"
            | "verify-snapshot"
            | "list-snapshots"
            | "snapshot-catalog"
            | "preflight-upgrade"
            | "self-heal-from-snapshot"
            | "quarantine-stopped-validator"
            | "sync-from-canonical-peer"
            | "start-shadow-observe"
            | "shadow-status"
            | "rejoin-eligibility"
            | "request-rejoin"
    )
}

fn run_offline_snapshot_command_isolated(args: &[String], command: &str) -> Result<bool, String> {
    if !offline_snapshot_command_uses_large_stack(command) {
        return run_offline_snapshot_command(args, command);
    }

    let args = args.to_vec();
    let command = command.to_string();
    thread::Builder::new()
        .name(format!("offline-snapshot-{command}"))
        .stack_size(OFFLINE_SNAPSHOT_COMMAND_STACK_BYTES)
        .spawn(move || run_offline_snapshot_command(&args, &command))
        .map_err(|error| format!("failed to start offline snapshot worker thread: {error}"))?
        .join()
        .map_err(|_| "offline snapshot worker thread panicked".to_string())?
}

fn require_testnet_v3_operator_args(args: &[String]) -> Result<(), String> {
    let chain_id = arg_value(args, "--chain-id")
        .ok_or_else(|| "missing --chain-id 1266".to_string())?
        .parse::<u64>()
        .map_err(|error| format!("invalid --chain-id: {error}"))?;
    if chain_id != SYNERGY_TESTNET_V3_CHAIN_ID {
        return Err(format!(
            "wrong chain_id {chain_id}; expected {SYNERGY_TESTNET_V3_CHAIN_ID}"
        ));
    }
    let network_id = arg_value(args, "--network-id")
        .ok_or_else(|| "missing --network-id synergy-testnet-v3".to_string())?;
    if network_id != SYNERGY_TESTNET_V3_NETWORK_ID {
        return Err(format!(
            "wrong network_id {network_id}; expected {SYNERGY_TESTNET_V3_NETWORK_ID}"
        ));
    }
    let genesis_hash = arg_value(args, "--genesis-hash")
        .ok_or_else(|| format!("missing --genesis-hash {}", expected_genesis_hash()))?;
    if !genesis_hash.eq_ignore_ascii_case(&expected_genesis_hash()) {
        return Err(format!(
            "wrong genesis_hash {genesis_hash}; expected {}",
            expected_genesis_hash()
        ));
    }
    Ok(())
}

fn workspace_appliance_state_store_dir(workspace_path: &Path) -> PathBuf {
    workspace_path.join("state").join("store")
}

fn configure_offline_source_workspace(args: &[String]) -> Result<(), String> {
    configure_offline_source_workspace_inner(args)
}

fn configure_snapshot_verify_source_workspace(args: &[String]) -> Result<(), String> {
    configure_offline_source_workspace_inner(args)
}

fn configure_offline_source_workspace_inner(args: &[String]) -> Result<(), String> {
    let workspace =
        arg_value(args, "--source-workspace").or_else(|| arg_value(args, "--workspace"));
    let Some(workspace) = workspace else {
        return Err(
            "missing --source-workspace <PATH>; refusing ambiguous offline snapshot workspace"
                .to_string(),
        );
    };
    let workspace_path = PathBuf::from(&workspace);
    if !workspace_path.is_dir() {
        return Err(format!(
            "source workspace does not exist or is not a directory: {}",
            workspace_path.display()
        ));
    }
    if !workspace_path.join("config").is_dir() {
        return Err(format!(
            "source workspace is missing config directory: {}",
            workspace_path.display()
        ));
    }
    let appliance_state_store_dir = workspace_appliance_state_store_dir(&workspace_path);
    if !appliance_state_store_dir.is_dir() {
        return Err(format!(
            "source workspace is missing validator appliance state/store directory: {}",
            workspace_path.display()
        ));
    }
    fs::read_dir(&appliance_state_store_dir).map_err(|error| {
        format!(
            "source workspace validator appliance state/store directory is not readable: {}: {error}",
            appliance_state_store_dir.display()
        )
    })?;
    env::set_var("SYNERGY_PROJECT_ROOT", &workspace_path);
    if let Some(config_path) = arg_value(args, "--config") {
        let config_path = PathBuf::from(config_path);
        if !config_path.is_file() {
            return Err(format!(
                "source workspace config file does not exist: {}",
                config_path.display()
            ));
        }
        fs::File::open(&config_path).map_err(|error| {
            format!(
                "source workspace config file is not readable: {}: {error}",
                config_path.display()
            )
        })?;
        env::set_var("SYNERGY_CONFIG_PATH", config_path);
    } else {
        let default_config = workspace_path.join("config/node.toml");
        if !default_config.is_file() {
            return Err(format!(
                "source workspace is missing default config file: {}",
                default_config.display()
            ));
        }
        fs::File::open(&default_config).map_err(|error| {
            format!(
                "source workspace config file is not readable: {}: {error}",
                default_config.display()
            )
        })?;
        env::set_var("SYNERGY_CONFIG_PATH", default_config);
    }
    Ok(())
}

fn print_json_value(value: serde_json::Value) {
    match serde_json::to_string_pretty(&value) {
        Ok(encoded) => println!("{encoded}"),
        Err(error) => {
            eprintln!("failed to serialize JSON response: {error}");
            process::exit(1);
        }
    }
}

fn run_offline_snapshot_command(args: &[String], command: &str) -> Result<bool, String> {
    match command {
        "create-snapshot" => {
            require_testnet_v3_operator_args(args)?;
            configure_offline_source_workspace(args)?;
            let options = crate::consensus::diagnostics::CreateSnapshotOptions {
                source_node_majority_branch_proven: arg_flag(
                    args,
                    "--source-node-majority-branch-proven",
                ),
                source_role: arg_value(args, "--source-role"),
                conflict_height_hash: arg_value(args, "--conflict-height-hash"),
                snapshot_class: arg_value(args, "--snapshot-class"),
                allowed_restore_roles: arg_values(args, "--allowed-role"),
            };
            let report = crate::consensus::diagnostics::create_snapshot_with_options(options)?;
            print_json_value(report);
            Ok(true)
        }
        "verify-snapshot" => {
            require_testnet_v3_operator_args(args)?;
            configure_snapshot_verify_source_workspace(args)?;
            let manifest = arg_value(args, "--manifest")
                .or_else(|| arg_value(args, "--manifest-path"))
                .ok_or_else(|| "verify-snapshot requires --manifest <path>".to_string())?;
            let snapshot_root = arg_value(args, "--snapshot-root");
            let report = crate::consensus::diagnostics::verify_snapshot_with_options(
                &manifest,
                snapshot_root.as_deref(),
                crate::consensus::diagnostics::VerifySnapshotOptions {
                    snapshot_class: arg_value(args, "--snapshot-class"),
                    target_role: arg_value(args, "--target-role"),
                },
            )?;
            print_json_value(report);
            Ok(true)
        }
        "list-snapshots" | "snapshot-catalog" => {
            require_testnet_v3_operator_args(args)?;
            configure_offline_source_workspace(args)?;
            print_json_value(crate::consensus::diagnostics::snapshot_catalog());
            Ok(true)
        }
        "preflight-upgrade" => {
            require_testnet_v3_operator_args(args)?;
            configure_offline_source_workspace(args)?;
            let source_workspace =
                PathBuf::from(arg_value(args, "--source-workspace").ok_or_else(|| {
                    "preflight-upgrade requires --source-workspace <PATH>".to_string()
                })?);
            let options = crate::recovery::ValidatorUpgradePreflightOptions {
                allow_derived_index_rebuild: arg_flag(args, "--allow-derived-index-rebuild"),
                artifact_path: arg_value(args, "--artifact")
                    .or_else(|| arg_value(args, "--upgrade-artifact"))
                    .map(PathBuf::from),
                current_binary_path: arg_value(args, "--current-binary").map(PathBuf::from),
                rollback_binary_path: arg_value(args, "--rollback-binary").map(PathBuf::from),
                config_path: arg_value(args, "--config").map(PathBuf::from),
                validator_set_path: arg_value(args, "--validator-set").map(PathBuf::from),
                archive_status_path: arg_value(args, "--archive-status").map(PathBuf::from),
            };
            let report = crate::recovery::preflight_validator_upgrade(&source_workspace, options)?;
            let ok = report.ok;
            let codes = report
                .findings
                .iter()
                .filter(|finding| {
                    finding.severity == crate::recovery::ValidatorUpgradePreflightSeverity::Error
                })
                .map(|finding| format!("{:?}", finding.code))
                .collect::<Vec<_>>();
            print_json_value(serde_json::to_value(&report).map_err(|error| {
                format!("serialize validator upgrade preflight report: {error}")
            })?);
            if !ok {
                return Err(format!(
                    "validator upgrade preflight refused rollout: {}",
                    codes.join(", ")
                ));
            }
            Ok(true)
        }
        "self-heal-from-snapshot" => {
            require_testnet_v3_operator_args(args)?;
            configure_offline_source_workspace(args)?;
            let manifest = arg_value(args, "--manifest")
                .or_else(|| arg_value(args, "--manifest-path"))
                .ok_or_else(|| "self-heal-from-snapshot requires --manifest <path>".to_string())?;
            let snapshot_root = arg_value(args, "--snapshot-root");
            let report = crate::consensus::diagnostics::self_heal_from_snapshot(
                &manifest,
                snapshot_root.as_deref(),
            )?;
            print_json_value(report);
            Ok(true)
        }
        "quarantine-stopped-validator" => {
            require_testnet_v3_operator_args(args)?;
            configure_offline_source_workspace(args)?;
            let options = crate::consensus::diagnostics::OperatorQuarantineOptions {
                reason: arg_value(args, "--reason"),
                target_stopped: arg_flag(args, "--target-stopped"),
                operator_approved_containment: arg_flag(args, "--operator-approved-containment"),
                quorum_majority_height: optional_u64_arg(args, "--quorum-majority-height")?,
                quorum_majority_hash: arg_value(args, "--quorum-majority-hash"),
                local_conflicting_height: optional_u64_arg(args, "--local-conflicting-height")?,
                local_conflicting_hash: arg_value(args, "--local-conflicting-hash"),
            };
            let report =
                crate::consensus::diagnostics::quarantine_stopped_validator_with_options(options)?;
            print_json_value(report);
            Ok(true)
        }
        "sync-from-canonical-peer" => {
            require_testnet_v3_operator_args(args)?;
            configure_offline_source_workspace(args)?;
            let options = crate::consensus::diagnostics::SyncFromCanonicalPeerOptions {
                canonical_height: optional_u64_arg(args, "--canonical-height")?,
                canonical_hash: arg_value(args, "--canonical-hash"),
                source_peer: arg_value(args, "--source-peer"),
                source_qc_aegis_pqc_verified: arg_flag(args, "--source-qc-aegis-pqc-verified"),
                parent_continuity_verified: arg_flag(args, "--parent-continuity-verified"),
                state_root_matches: arg_flag(args, "--state-root-matches"),
                source_peer_quarantined: !arg_flag(args, "--source-peer-not-quarantined"),
            };
            let report =
                crate::consensus::diagnostics::sync_from_canonical_peer_with_options(options)?;
            print_json_value(report);
            Ok(true)
        }
        "start-shadow-observe" => {
            require_testnet_v3_operator_args(args)?;
            configure_offline_source_workspace(args)?;
            let options = crate::consensus::diagnostics::StartShadowObserveOptions {
                required_blocks: optional_u64_arg(args, "--required-blocks")?,
            };
            let report = crate::consensus::diagnostics::start_shadow_observe_with_options(options)?;
            print_json_value(report);
            Ok(true)
        }
        "shadow-status" => {
            require_testnet_v3_operator_args(args)?;
            configure_offline_source_workspace(args)?;
            print_json_value(crate::consensus::diagnostics::shadow_status());
            Ok(true)
        }
        "rejoin-eligibility" => {
            require_testnet_v3_operator_args(args)?;
            configure_offline_source_workspace(args)?;
            print_json_value(crate::consensus::diagnostics::rejoin_eligibility());
            Ok(true)
        }
        "request-rejoin" => {
            require_testnet_v3_operator_args(args)?;
            configure_offline_source_workspace(args)?;
            let options = crate::consensus::diagnostics::RejoinRequestOptions {
                common_height: optional_u64_arg(args, "--common-height")?,
                common_hash: arg_value(args, "--common-hash"),
                exact_common_height_match: arg_flag(args, "--exact-common-height-match"),
                latest_finalized_qc_aegis_pqc_verified: arg_flag(
                    args,
                    "--latest-finalized-qc-aegis-pqc-verified",
                ),
                state_root_matches: arg_flag(args, "--state-root-matches"),
                rejoin_at_finalized_safe_boundary: arg_flag(
                    args,
                    "--rejoin-at-finalized-safe-boundary",
                ),
                cluster_marks_pending_reactivation: arg_flag(
                    args,
                    "--cluster-marks-pending-reactivation",
                ),
                operator_approved_reactivation: arg_flag(args, "--operator-approved-reactivation"),
                operator_approved_emergency_leader_stall_recovery: arg_flag(
                    args,
                    "--operator-approved-emergency-leader-stall-recovery",
                ),
            };
            let report = crate::consensus::diagnostics::request_rejoin_with_options(options)?;
            print_json_value(report);
            Ok(true)
        }
        "promote-vote-only-to-active" => {
            require_testnet_v3_operator_args(args)?;
            configure_offline_source_workspace(args)?;
            let report = crate::consensus::diagnostics::promote_vote_only_to_active()?;
            print_json_value(report);
            Ok(true)
        }
        "emergency-promote-leader-stall-to-active" => {
            require_testnet_v3_operator_args(args)?;
            configure_offline_source_workspace(args)?;
            let options = crate::consensus::diagnostics::EmergencyLeaderStallPromotionOptions {
                common_height: optional_u64_arg(args, "--common-height")?,
                common_hash: arg_value(args, "--common-hash"),
                exact_common_height_match: arg_flag(args, "--exact-common-height-match"),
                latest_finalized_qc_aegis_pqc_verified: arg_flag(
                    args,
                    "--latest-finalized-qc-aegis-pqc-verified",
                ),
                state_root_matches: arg_flag(args, "--state-root-matches"),
                rejoin_at_finalized_safe_boundary: arg_flag(
                    args,
                    "--rejoin-at-finalized-safe-boundary",
                ),
                cluster_marks_pending_reactivation: arg_flag(
                    args,
                    "--cluster-marks-pending-reactivation",
                ),
                operator_approved_emergency_leader_stall_recovery: arg_flag(
                    args,
                    "--operator-approved-emergency-leader-stall-recovery",
                ),
            };
            let report =
                crate::consensus::diagnostics::emergency_promote_leader_stall_to_active_with_options(
                    options,
                )?;
            print_json_value(report);
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn rpc_block_number(url: &str) -> Option<u64> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .ok()?;
    let response = client
        .post(url)
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "synergy_blockNumber",
            "params": [],
            "id": 1
        }))
        .send()
        .ok()?;
    let payload = response.json::<serde_json::Value>().ok()?;
    parse_rpc_block_number(payload.get("result")?)
}

fn launch_block1_network_has_started(project_root: &Path) -> bool {
    for url in candidate_launch_block1_rpc_urls(project_root) {
        if matches!(rpc_block_number(&url), Some(height) if height > 0) {
            info!(
                "main",
                "Detected live network past genesis before launch block-1 preload",
                "rpc_url" => url
            );
            return true;
        }
    }

    false
}

impl RoleProcessGuard {
    fn new(child: Child) -> Self {
        RoleProcessGuard {
            child: Mutex::new(child),
        }
    }
}

impl Drop for RoleProcessGuard {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.child.lock() {
            let _ = guard.kill();
            let _ = guard.wait();
        }
    }
}

fn resolve_local_validator_address(config: &NodeConfig) -> String {
    let configured = config.node.validator_address.trim();
    if !configured.is_empty() {
        return configured.to_string();
    }

    if let Ok(from_env) = env::var("SYNERGY_VALIDATOR_ADDRESS") {
        let trimmed = from_env.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    if let Ok(from_env) = env::var("NODE_ADDRESS") {
        let trimmed = from_env.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    config.p2p.node_name.clone()
}

fn normalize_socket_address(bind_address: &str, default_port: u16) -> String {
    let trimmed = bind_address.trim();
    let host = trimmed
        .strip_prefix("http://")
        .or_else(|| trimmed.strip_prefix("https://"))
        .unwrap_or(trimmed)
        .trim_end_matches('/')
        .trim();

    if host.is_empty() {
        return format!("127.0.0.1:{default_port}");
    }

    match host {
        "0.0.0.0" => format!("0.0.0.0:{default_port}"),
        "::" | "[::]" => format!("[::]:{default_port}"),
        "::1" | "[::1]" => format!("[::1]:{default_port}"),
        _ if host.starts_with('[') && host.contains("]:") => host.to_string(),
        _ if host.matches(':').count() == 0 => format!("{host}:{default_port}"),
        _ => host.to_string(),
    }
}

fn normalize_client_address(bind_address: &str, default_port: u16) -> String {
    let normalized = normalize_socket_address(bind_address, default_port);

    if let Some(port) = normalized.strip_prefix("0.0.0.0:") {
        return format!("127.0.0.1:{port}");
    }

    if let Some(port) = normalized.strip_prefix("[::]:") {
        return format!("127.0.0.1:{port}");
    }

    normalized
}

fn normalize_rpc_socket_address(bind_address: &str, default_port: u16) -> String {
    normalize_socket_address(bind_address, default_port)
}

fn normalize_rpc_client_address(bind_address: &str, default_port: u16) -> String {
    normalize_client_address(bind_address, default_port)
}

fn rebind_socket_address(bind_address: &str, port: u16) -> String {
    let trimmed = bind_address.trim();
    let host = trimmed
        .strip_prefix("http://")
        .or_else(|| trimmed.strip_prefix("https://"))
        .unwrap_or(trimmed)
        .trim_end_matches('/')
        .trim();

    if host.is_empty() {
        return format!("127.0.0.1:{port}");
    }

    match host {
        "0.0.0.0" => format!("0.0.0.0:{port}"),
        "::" | "[::]" => format!("[::]:{port}"),
        "::1" | "[::1]" => format!("[::1]:{port}"),
        _ if host.starts_with('[') => {
            if let Some((addr, _)) = host.rsplit_once("]:") {
                format!("{addr}]:{port}")
            } else {
                format!("{host}:{port}")
            }
        }
        _ if host.matches(':').count() == 1 => {
            let (candidate_host, candidate_port) = host.rsplit_once(':').unwrap();
            if candidate_port.chars().all(|ch| ch.is_ascii_digit()) {
                format!("{candidate_host}:{port}")
            } else {
                host.to_string()
            }
        }
        _ if host.matches(':').count() == 0 => format!("{host}:{port}"),
        _ => format!("[{host}]:{port}"),
    }
}

fn is_validator_allowed(config: &NodeConfig, validator_address: &str) -> bool {
    if !config.node.strict_validator_allowlist {
        return true;
    }

    config
        .node
        .allowed_validator_addresses
        .iter()
        .any(|allowed| allowed == validator_address)
}

fn role_profile_exposes_rpc(profile: &RoleProfile) -> bool {
    profile.required_ports.iter().any(|port| {
        let normalized = port.to_ascii_lowercase();
        normalized.contains(" rpc") || normalized.contains(" ws") || normalized.starts_with("rpc ")
    })
}

fn role_profile_requires_p2p(profile: &RoleProfile) -> bool {
    profile.service_surface.contains(&"p2p")
        || profile.required_ports.iter().any(|port| {
            let normalized = port.to_ascii_lowercase();
            normalized.contains("p2p")
        })
}

fn should_start_p2p(config: &NodeConfig, profile: Option<&RoleProfile>) -> bool {
    if config.node.bootstrap_only {
        return true;
    }

    match profile {
        Some(profile) => role_profile_requires_p2p(profile),
        None => true,
    }
}

fn should_start_rpc(config: &NodeConfig, profile: Option<&RoleProfile>) -> bool {
    if config.node.bootstrap_only {
        return false;
    }

    let transports_enabled =
        config.rpc.enable_http || config.rpc.enable_ws || config.rpc.enable_grpc;
    if !transports_enabled {
        return false;
    }

    match profile {
        Some(profile) => role_profile_exposes_rpc(profile),
        None => true,
    }
}

fn should_start_metrics(config: &NodeConfig) -> bool {
    config.telemetry.enabled && !config.telemetry.metrics_bind.trim().is_empty()
}

fn should_start_sync(config: &NodeConfig, profile: Option<&RoleProfile>) -> bool {
    if config.node.bootstrap_only {
        return false;
    }

    match profile {
        Some(profile) => role_profile_requires_p2p(profile),
        None => true,
    }
}

fn should_auto_register_validator(config: &NodeConfig, profile: Option<&RoleProfile>) -> bool {
    if config.node.bootstrap_only || !config.node.auto_register_validator {
        return false;
    }

    if !matches!(profile.map(|value| value.role), Some(NodeRole::Validator)) {
        return false;
    }

    if !config.node.strict_validator_allowlist {
        return false;
    }

    let validator_address = resolve_local_validator_address(config);
    is_validator_allowed(config, &validator_address)
}

fn is_validator_profile(profile: Option<&RoleProfile>) -> bool {
    matches!(profile.map(|value| value.role), Some(NodeRole::Validator))
}

/// Waits until every other finalized Genesis validator has a fresh,
/// authenticated status session before starting the first typed round.  The
/// worker treats an empty fanout as fatal, so starting it while P2P is still
/// converging would create a deterministic startup race rather than a safe
/// consensus failure.
fn wait_for_finalized_typed_peer_readiness(
    network: &p2p::networking::P2PNetwork,
    required_remote_validators: usize,
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        let ready = network.get_status_ready_validator_addresses();
        if ready.len() >= required_remote_validators {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for finalized typed PoSy peer readiness: required {required_remote_validators} remote validators, observed {}",
                ready.len()
            ));
        }
        thread::sleep(Duration::from_millis(200));
    }
}

/// Holds the scheduler after every immutable authority, durable store,
/// mailbox, and authenticated peer is ready. A coordinated deployment may
/// release all validators by installing one ML-DSA-87-signed, desired-state
/// and Genesis-bound start command.
fn wait_for_declared_consensus_start_barrier() -> Result<(), String> {
    let paused = env::var("CONSENSUS_START_PAUSED")
        .ok()
        .is_some_and(|value| matches!(value.trim(), "1" | "true" | "TRUE" | "yes" | "YES"));
    if !paused {
        return Ok(());
    }
    let release_file = env::var("SYNERGY_CONSENSUS_START_RELEASE_FILE")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| crate::utils::resolve_data_path("data/consensus-start.release"));
    let desired_state_path = env::var(crate::desired_state::DESIRED_STATE_ENV)
        .map(PathBuf::from)
        .map_err(|_| {
            "consensus start barrier requires the installed desired-state manifest".to_string()
        })?;
    let desired_state_sha256 =
        env::var(crate::desired_state::DESIRED_STATE_SHA256_ENV).map_err(|_| {
            "consensus start barrier requires the verified desired-state digest".to_string()
        })?;
    loop {
        match crate::consensus_start::verify_signed_start_command(
            &release_file,
            &desired_state_path,
            &desired_state_sha256,
        ) {
            Ok(request) => {
                let now_unix_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|error| format!("consensus start clock failure: {error}"))?
                    .as_millis()
                    .min(u64::MAX as u128) as u64;
                if now_unix_ms >= request.activate_unix_ms {
                    return Ok(());
                }
                thread::sleep(Duration::from_millis(
                    request
                        .activate_unix_ms
                        .saturating_sub(now_unix_ms)
                        .min(100),
                ));
            }
            Err(error) if error.contains("No such file") => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(error) => {
                return Err(format!(
                    "verify consensus start release file {}: {error}",
                    release_file.display()
                ))
            }
        }
    }
}

fn local_validator_is_consensus_authorized(config: &NodeConfig) -> bool {
    let validator_address = resolve_local_validator_address(config);
    consensus_membership_validators(VALIDATOR_MANAGER.get_active_validators())
        .iter()
        .any(|validator| validator.address == validator_address)
}

fn should_start_consensus(config: &NodeConfig, profile: Option<&RoleProfile>) -> bool {
    if config.node.bootstrap_only {
        return false;
    }

    if is_validator_profile(profile) {
        return local_validator_is_consensus_authorized(config);
    }

    match profile {
        Some(profile) => profile.service_surface.contains(&"consensus"),
        None => true,
    }
}

/// Public service roles replicate only independently verified finality; they
/// do not start the signing coordinator or load validator custody material.
/// Relayers are the narrow bridge from the validator VPN to the public
/// gateway/indexer tier, while the gateway and indexer remain read-only
/// observers.
fn should_start_typed_finality_observer(
    config: &NodeConfig,
    profile: Option<&RoleProfile>,
) -> bool {
    !matches!(
        config
            .consensus
            .resolve_mode(config.blockchain.chain_id, &config.network.network_id),
        Ok(ResolvedConsensusMode::CoordinatedRoundRobinV1(_))
    ) && !config.node.bootstrap_only
        && matches!(
            profile.map(|value| value.role),
            Some(NodeRole::Relayer | NodeRole::RpcGateway | NodeRole::IndexerExplorer)
        )
}

/// P1 support roles replay the same finalized packages as validators but never
/// construct a coordinator, producer, or signing authority. Keep this mode
/// gate separate from the retired typed observer to prevent an observer from
/// accepting evidence for the wrong finality protocol.
fn should_start_coordinated_finality_observer(
    config: &NodeConfig,
    profile: Option<&RoleProfile>,
) -> bool {
    matches!(
        config
            .consensus
            .resolve_mode(config.blockchain.chain_id, &config.network.network_id),
        Ok(ResolvedConsensusMode::CoordinatedRoundRobinV1(_))
    ) && !config.node.bootstrap_only
        && matches!(
            profile.map(|value| value.role),
            Some(NodeRole::Relayer | NodeRole::RpcGateway | NodeRole::IndexerExplorer)
        )
}

/// The only production consensus-worker selection for Testnet-v3. Keeping
/// this decision independent from worker construction makes the required
/// authorities explicit: an authorized validator needs both live P2P and a
/// successful finalized-Genesis/key/finality preflight. There is intentionally
/// no legacy consensus variant.
#[derive(Debug, Clone, PartialEq, Eq)]
enum FinalizedConsensusDriverStartup {
    Disabled,
    SpawnCoordinatedRoundRobinDriver,
    SpawnSingleAuthorityDriver(Box<SingleAuthorityStartupPlan>),
}

/// Resolves which consensus driver starts.
///
/// Order is fixed and protocol-neutral: the SIGNED consensus binding is
/// resolved FIRST, and only then is protocol-specific preflight applied.
/// `single_authority_v1` has no peers, so its branch requires no P2P network,
/// no discovery, no endpoint refresh, no peer or quorum readiness, no relayer,
/// and no second validator. The coordinated and PoSy branches keep the exact
/// P2P preflight they had before.
///
/// A local configuration value, an environment variable, the presence or
/// absence of P2P, and an old V1 desired-state file may never select or
/// deselect a driver. `signed_startup` is the only input that can select
/// single authority.
fn select_finalized_consensus_driver_startup(
    consensus_enabled: bool,
    p2p_available: bool,
    finalized_input_validation: Option<Result<ResolvedConsensusMode, String>>,
    signed_startup: Option<Result<VerifiedConsensusStartup, String>>,
) -> Result<FinalizedConsensusDriverStartup, String> {
    if !consensus_enabled {
        return Ok(FinalizedConsensusDriverStartup::Disabled);
    }

    // 1. Branch on the verified signed activation before any preflight.
    match signed_startup {
        Some(Err(error)) => {
            return Err(format!(
                "signed consensus activation is invalid; refusing consensus startup: {error}"
            ));
        }
        Some(Ok(VerifiedConsensusStartup::SingleAuthority(plan))) => {
            // No P2P, no peers, no discovery, no quorum, no relayer.
            return Ok(FinalizedConsensusDriverStartup::SpawnSingleAuthorityDriver(
                plan,
            ));
        }
        Some(Ok(VerifiedConsensusStartup::CoordinatedRoundRobin)) => {
            require_p2p_preflight(p2p_available)?;
            return match finalized_input_validation {
                Some(Ok(ResolvedConsensusMode::CoordinatedRoundRobinV1(_))) => {
                    Ok(FinalizedConsensusDriverStartup::SpawnCoordinatedRoundRobinDriver)
                }
                Some(Ok(other)) => Err(format!(
                    "local consensus mode {} disagrees with the signed coordinated activation",
                    local_mode_name(&other)
                )),
                Some(Err(error)) => Err(format!(
                    "finalized consensus inputs are unavailable; refusing consensus startup: {error}"
                )),
                None => Err(
                    "finalized consensus inputs were not validated; refusing consensus startup"
                        .to_string(),
                ),
            };
        }
        None => {}
    }

    // 2. No signed V2 activation is installed. Preserve the existing behavior
    //    exactly, and refuse any locally-requested single-authority start.
    require_p2p_preflight(p2p_available)?;
    match finalized_input_validation {
        Some(Ok(ResolvedConsensusMode::PosyV2_2)) => Err(
            "typed PoSy is disabled in this Chain 1266 release; coordinated_round_robin_v1 is required"
                .to_string(),
        ),
        Some(Ok(ResolvedConsensusMode::SingleAuthorityV1)) => Err(
            "single_authority_v1 requires a verified ML-DSA-87 signed DesiredStateV2 activation; \
             local configuration and environment variables cannot select it"
                .to_string(),
        ),
        Some(Ok(ResolvedConsensusMode::CoordinatedRoundRobinV1(_))) => {
            Ok(FinalizedConsensusDriverStartup::SpawnCoordinatedRoundRobinDriver)
        }
        Some(Err(error)) => Err(format!(
            "finalized consensus inputs are unavailable; refusing consensus startup: {error}"
        )),
        None => Err(
            "finalized consensus inputs were not validated; refusing consensus startup".to_string(),
        ),
    }
}

/// Canonical installed V2 activation artifacts.
const INSTALLED_DESIRED_STATE_V2_PATH: &str = "config/chain1266-desired-state-v2.json";
const INSTALLED_START_AUTHORIZATION_V2_PATH: &str =
    "config/chain1266-start-authorization-v2.json";

/// Loads and fully verifies the installed signed `DesiredStateV2` activation.
///
/// Returns `None` only when no V2 activation artifact is installed at all. A
/// present-but-invalid artifact returns `Some(Err(..))` and fails startup
/// closed; it is never silently ignored in favour of local configuration.
fn resolve_installed_signed_consensus_startup(
    config: &NodeConfig,
) -> Option<Result<VerifiedConsensusStartup, String>> {
    let desired_state_path = crate::utils::resolve_data_path(INSTALLED_DESIRED_STATE_V2_PATH);
    let authorization_path =
        crate::utils::resolve_data_path(INSTALLED_START_AUTHORIZATION_V2_PATH);
    if !desired_state_path.exists() && !authorization_path.exists() {
        return None;
    }
    Some(verify_installed_signed_consensus_startup(
        config,
        &desired_state_path,
        &authorization_path,
    ))
}

fn verify_installed_signed_consensus_startup(
    config: &NodeConfig,
    desired_state_path: &Path,
    authorization_path: &Path,
) -> Result<VerifiedConsensusStartup, String> {
    let desired_state_bytes = fs::read(desired_state_path).map_err(|error| {
        format!(
            "read installed desired state v2 {}: {error}",
            desired_state_path.display()
        )
    })?;
    let signed: crate::desired_state_v2::SignedDesiredStateV2 = serde_json::from_slice(
        &fs::read(authorization_path).map_err(|error| {
            format!(
                "read installed start authorization {}: {error}",
                authorization_path.display()
            )
        })?,
    )
    .map_err(|error| format!("parse installed start authorization: {error}"))?;

    let expectation = build_startup_expectation(config)?;
    crate::consensus::single_authority_startup::resolve_verified_consensus_startup(
        &desired_state_bytes,
        &signed,
        &expectation,
    )
}

fn build_startup_expectation(
    config: &NodeConfig,
) -> Result<crate::consensus::single_authority_startup::StartupExpectation, String> {
    let genesis = crate::genesis::canonical_genesis()?;
    let authority_address = resolve_local_validator_address(config);
    let (authority_public_key, _) = crate::consensus::validator_keys::load_local_validator_keypair(
        &authority_address,
        &VALIDATOR_MANAGER,
    )?;
    Ok(
        crate::consensus::single_authority_startup::StartupExpectation {
            genesis_chain_id: genesis.chain_id(),
            genesis_chain_incarnation: genesis.chain_incarnation(),
            genesis_network_id: crate::synergy_types::SYNERGY_TESTNET_V3_NETWORK_ID.to_string(),
            genesis_hash: genesis.hash().to_string(),
            genesis_directory_namespace: format!(
                "chain-{}/incarnation-{}",
                genesis.chain_id(),
                genesis.chain_incarnation()
            ),
            release_id: config.consensus.release_id.clone(),
            authority_id: config.identity.node_id.clone(),
            authority_public_key_fingerprint: format!(
                "sha256:{}",
                hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&authority_public_key.key_data))
            ),
            authority_key_algorithm: authority_public_key.algorithm,
        },
    )
}

/// Genesis-anchored Chain 1266 startup dispatch.
///
/// The canonical Genesis document decides which start-authorization verifier
/// runs. Incarnation 4 + `coordinated_round_robin_v1` keeps the legacy V1
/// verifier verbatim. Incarnation 5 + `single_authority_v1` is governed
/// exclusively by the ML-DSA-87 signed `DesiredStateV2`; the V1 verifier is
/// never invoked on that path, and a missing or invalid V2 activation fails
/// closed rather than falling back.
fn resolve_chain1266_startup_release_id(
    config: &NodeConfig,
    profile: &'static crate::role_profiles::RoleProfile,
    config_path: &Path,
) -> Result<String, String> {
    use crate::consensus::chain1266_startup_dispatch::{
        dispatch_chain1266_startup, Chain1266StartupDispatch,
    };

    let genesis = crate::genesis::canonical_genesis()?;
    let dispatch = dispatch_chain1266_startup(
        genesis.chain_id(),
        genesis.chain_incarnation(),
        genesis.consensus_protocol(),
    )?;

    match dispatch {
        Chain1266StartupDispatch::SingleAuthorityV2 => {
            verify_chain1266_incarnation5_single_authority_startup(config)
        }
        Chain1266StartupDispatch::CoordinatedV1 | Chain1266StartupDispatch::NonChain1266 => {
            crate::desired_state::verify_chain1266_desired_state(
                profile,
                &config.identity.node_id,
                config_path,
            )
        }
    }
}

/// The incarnation-5 single-authority branch. Reads the installed V2 artifacts
/// and hands them to the one existing V2 verifier plus the launch pins.
fn verify_chain1266_incarnation5_single_authority_startup(
    config: &NodeConfig,
) -> Result<String, String> {
    use crate::consensus::chain1266_startup_dispatch::{
        verify_single_authority_v2_activation, SingleAuthorityLaunchPins,
    };

    let desired_state_path = crate::utils::resolve_data_path(INSTALLED_DESIRED_STATE_V2_PATH);
    let authorization_path =
        crate::utils::resolve_data_path(INSTALLED_START_AUTHORIZATION_V2_PATH);
    if !desired_state_path.exists() || !authorization_path.exists() {
        return Err(format!(
            "single_authority_v1 requires an installed ML-DSA-87 signed DesiredStateV2 \
             activation; expected {} and {}. V1 fallback is forbidden on the incarnation-5 path",
            desired_state_path.display(),
            authorization_path.display()
        ));
    }

    let desired_state_bytes = fs::read(&desired_state_path).map_err(|error| {
        format!(
            "read installed desired state v2 {}: {error}",
            desired_state_path.display()
        )
    })?;
    let signed: crate::desired_state_v2::SignedDesiredStateV2 = serde_json::from_slice(
        &fs::read(&authorization_path).map_err(|error| {
            format!(
                "read installed start authorization {}: {error}",
                authorization_path.display()
            )
        })?,
    )
    .map_err(|error| format!("parse installed start authorization: {error}"))?;

    // The expectation is built from the canonical Genesis, not from the live
    // validator registry: this runs before the registry is seeded, and Genesis
    // is the trusted dispatch anchor. The registry-backed expectation is still
    // applied later by `resolve_installed_signed_consensus_startup` when the
    // consensus driver is selected.
    let expectation = build_genesis_startup_expectation(config)?;
    verify_single_authority_v2_activation(
        &desired_state_bytes,
        &signed,
        &expectation,
        &resolve_local_validator_address(config),
        &SingleAuthorityLaunchPins::incarnation5(),
    )
}

/// Startup expectation derived purely from the canonical Genesis document and
/// the local release statement. Used by the incarnation-5 dispatch branch.
fn build_genesis_startup_expectation(
    config: &NodeConfig,
) -> Result<crate::consensus::single_authority_startup::StartupExpectation, String> {
    use base64::{engine::general_purpose, Engine as _};

    let genesis = crate::genesis::canonical_genesis()?;
    let authority_address = resolve_local_validator_address(config);
    let validator = genesis
        .validators()
        .iter()
        .find(|validator| validator.operator_address == authority_address)
        .ok_or_else(|| {
            format!("Genesis has no validator for the local authority address {authority_address}")
        })?;
    let algorithm = match validator.consensus_key_type.as_str() {
        "ML-DSA-65" => crate::crypto::pqc::PQCAlgorithm::MLDSA65,
        "ML-DSA-87" => crate::crypto::pqc::PQCAlgorithm::MLDSA87,
        other => {
            return Err(format!(
                "Genesis authority {authority_address} declares unsupported consensus key type \
                 {other}"
            ))
        }
    };
    let consensus_public_key = general_purpose::STANDARD
        .decode(&validator.consensus_public_key)
        .map_err(|error| {
            format!("decode Genesis consensus public key for {authority_address}: {error}")
        })?;

    Ok(
        crate::consensus::single_authority_startup::StartupExpectation {
            genesis_chain_id: genesis.chain_id(),
            genesis_chain_incarnation: genesis.chain_incarnation(),
            genesis_network_id: crate::synergy_types::SYNERGY_TESTNET_V3_NETWORK_ID.to_string(),
            genesis_hash: genesis.hash().to_string(),
            genesis_directory_namespace: format!(
                "chain-{}/incarnation-{}",
                genesis.chain_id(),
                genesis.chain_incarnation()
            ),
            release_id: config.consensus.release_id.clone(),
            authority_id: config.identity.node_id.clone(),
            authority_public_key_fingerprint: format!(
                "sha256:{}",
                hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&consensus_public_key))
            ),
            authority_key_algorithm: algorithm,
        },
    )
}

/// The unchanged P2P preflight, applied only to peer-based protocols.
fn require_p2p_preflight(p2p_available: bool) -> Result<(), String> {
    if p2p_available {
        return Ok(());
    }
    Err("finalized consensus requires an active P2P network; refusing consensus startup".to_string())
}

fn local_mode_name(mode: &ResolvedConsensusMode) -> &'static str {
    match mode {
        ResolvedConsensusMode::PosyV2_2 => "posy_v2_2",
        ResolvedConsensusMode::CoordinatedRoundRobinV1(_) => "coordinated_round_robin_v1",
        ResolvedConsensusMode::SingleAuthorityV1 => "single_authority_v1",
    }
}

fn announce_chain1266_coordinated_runtime(config: &NodeConfig) -> Result<(), String> {
    let ResolvedConsensusMode::CoordinatedRoundRobinV1(mode) = config
        .consensus
        .resolve_mode(config.blockchain.chain_id, &config.network.network_id)?
    else {
        return Err("this Chain 1266 release only starts coordinated_round_robin_v1".to_string());
    };
    if mode.coordinator_id != "validator-1"
        || mode.producer_ids
            != [
                "validator-2",
                "validator-3",
                "validator-4",
                "validator-5",
                "validator-6",
            ]
    {
        return Err(
            "coordinated runtime identities do not match Val1 and ordered Val2-Val6".to_string(),
        );
    }
    println!("CHAIN1266_CONSENSUS_ENGINE=coordinated_round_robin_v1");
    println!("CHAIN1266_COORDINATOR=validator-node-01");
    println!(
        "CHAIN1266_PRODUCERS=validator-node-02,validator-node-03,validator-node-04,validator-node-05,validator-node-06"
    );
    println!("CHAIN1266_VOTING_ENABLED=false");
    println!("CHAIN1266_QUORUM_ENABLED=false");
    println!("CHAIN1266_QC_ENABLED=false");
    Ok(())
}

fn resolved_consensus_runtime_preflight(
    config: &NodeConfig,
) -> Result<ResolvedConsensusMode, String> {
    ensure_consensus_pqc_runtime_ready(config)?;
    config
        .consensus
        .resolve_mode(config.blockchain.chain_id, &config.network.network_id)
}

fn should_require_state_sync_before_join(
    config: &NodeConfig,
    profile: Option<&RoleProfile>,
) -> bool {
    if !is_validator_profile(profile) || config.node.bootstrap_only {
        return false;
    }

    if recovery_state_requires_support_sources(persisted_recovery_state()) {
        return true;
    }

    if !config.validator.state_sync_before_join {
        return false;
    }

    if local_validator_is_consensus_authorized(config) {
        return false;
    }

    true
}

fn recovery_state_requires_support_sources(state: Option<RealignmentState>) -> bool {
    state
        .map(|state| state != RealignmentState::Active)
        .unwrap_or(false)
}

fn local_sync_requires_support_sources_for_state(
    validator_profile: bool,
    consensus_duties_disabled: bool,
    onboarding: bool,
    quarantined: bool,
) -> bool {
    validator_profile && (consensus_duties_disabled || onboarding || quarantined)
}

fn local_sync_requires_support_sources(config: &NodeConfig, profile: Option<&RoleProfile>) -> bool {
    let validator_profile = is_validator_profile(profile);
    if !validator_profile || config.node.bootstrap_only {
        return false;
    }

    let consensus_duties_disabled = !local_validator_is_consensus_authorized(config)
        || recovery_state_requires_support_sources(persisted_recovery_state());
    let onboarding = should_require_state_sync_before_join(config, profile);
    let quarantined = crate::consensus::diagnostics::quarantine_status()
        .get("quarantined")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    local_sync_requires_support_sources_for_state(
        validator_profile,
        consensus_duties_disabled,
        onboarding,
        quarantined,
    )
}

fn refresh_sync_source_policy(config: &NodeConfig, profile: Option<&RoleProfile>) -> bool {
    let support_sources_only = local_sync_requires_support_sources(config, profile);
    if let Ok(mut manager) = SYNC_MANAGER.try_lock() {
        manager.set_support_sources_only(support_sources_only);
    }
    support_sources_only
}

fn should_watch_for_validator_activation_consensus(
    config: &NodeConfig,
    profile: Option<&RoleProfile>,
    consensus_enabled: bool,
) -> bool {
    !consensus_enabled && is_validator_profile(profile) && !config.node.bootstrap_only
}

fn ensure_node_config_matches_finalized_consensus_parameters(
    config: &NodeConfig,
    genesis: &GenesisDocument,
) -> Result<(), String> {
    if let ResolvedConsensusMode::CoordinatedRoundRobinV1(mode) = config
        .consensus
        .resolve_mode(config.blockchain.chain_id, &config.network.network_id)?
    {
        let activation = crate::consensus_activation::load_installed_consensus_activation(genesis)
            .map_err(|error| {
                format!("coordinated P1 configuration requires its signed activation: {error}")
            })?;
        let target_block_time_ms = config
            .blockchain
            .block_time
            .checked_mul(1_000)
            .ok_or_else(|| "node blockchain block time overflows milliseconds".to_string())?;
        if config.consensus.algorithm != mode.consensus_version
            || config.consensus.block_time_secs.saturating_mul(1_000)
                != mode.target_block_interval_ms
            || target_block_time_ms != mode.target_block_interval_ms
            || activation.manifest.consensus_mode != mode.consensus_version
            || activation.manifest.coordinator_id != mode.coordinator_id
            || activation.manifest.producer_ids != mode.producer_ids
            || activation.manifest.producer_turn_timeout_ms != mode.producer_turn_timeout_ms
        {
            return Err(
                "node coordinated P1 configuration disagrees with its signed activation"
                    .to_string(),
            );
        }
        return Ok(());
    }
    // `single_authority_v1` carries no epoch/cluster/quorum profile: its
    // authoritative consensus bindings live in the ML-DSA-87 signed
    // DesiredStateV2, already verified by
    // `chain1266_startup_dispatch::verify_single_authority_v2_activation`.
    // The PoSy-shaped parameter cross-checks do not apply, exactly as in
    // `genesis::load_candidate_consensus_parameters`.
    if matches!(
        config
            .consensus
            .resolve_mode(config.blockchain.chain_id, &config.network.network_id)?,
        ResolvedConsensusMode::SingleAuthorityV1
    ) {
        return Ok(());
    }
    let parameters = genesis.consensus_parameters().ok_or_else(|| {
        "canonical Testnet-v3 Genesis has no finalized consensus parameter manifest".to_string()
    })?;
    match &parameters.manifest {
        crate::consensus_parameters::FinalizedConsensusParameterManifest::PosyV2_2(manifest) => {
            ensure_node_config_matches_posy_parameters(config, manifest)
        }
        crate::consensus_parameters::FinalizedConsensusParameterManifest::CoordinatedRoundRobinV1(
            manifest,
        ) => ensure_node_config_matches_coordinated_p1_parameters(config, manifest),
    }
}

fn ensure_node_config_matches_posy_parameters(
    config: &NodeConfig,
    manifest: &crate::consensus_parameters::ConsensusParameterManifest,
) -> Result<(), String> {
    let epoch_length = manifest
        .epoch_length_slots
        .ok_or_else(|| "finalized consensus parameters have no epoch length".to_string())?;
    let block_time_ms = config
        .consensus
        .block_time_secs
        .checked_mul(1_000)
        .ok_or_else(|| "node consensus block time overflows milliseconds".to_string())?;
    let blockchain_block_time_ms = config
        .blockchain
        .block_time
        .checked_mul(1_000)
        .ok_or_else(|| "node blockchain block time overflows milliseconds".to_string())?;
    if config.blockchain.chain_id != manifest.chain_id.0
        || config.network.id != manifest.chain_id.0
        || config.network.network_id != manifest.network_id.0
    {
        return Err(
            "node chain or network configuration disagrees with finalized consensus parameters"
                .to_string(),
        );
    }
    if config.consensus.algorithm.trim() != manifest.protocol_version
        || config.consensus.algorithm.trim() != POSY_PROTOCOL_VERSION
    {
        return Err(
            "node consensus protocol identifier disagrees with finalized consensus parameters"
                .to_string(),
        );
    }
    if block_time_ms != manifest.target_block_time_ms
        || blockchain_block_time_ms != manifest.target_block_time_ms
        || config.consensus.target_block_time_ms != manifest.target_block_time_ms
    {
        return Err(format!(
            "node block-time configuration disagrees with finalized {} ms target",
            manifest.target_block_time_ms
        ));
    }
    if config.consensus.epoch_length != epoch_length
        || config.consensus.vrf_seed_epoch_interval != epoch_length
    {
        return Err(format!(
            "node epoch configuration disagrees with finalized {epoch_length}-slot epoch"
        ));
    }
    if u64::try_from(config.consensus.validator_cluster_size).ok()
        != Some(manifest.initial_cluster_validator_count)
        || u64::try_from(config.consensus.min_validators).ok()
            != Some(manifest.initial_cluster_validator_count)
        || u64::try_from(config.consensus.validator_vote_threshold).ok()
            != Some(manifest.initial_availability_quorum)
    {
        return Err(format!(
            "node validator cluster size disagrees with finalized initial cluster size {}",
            manifest.initial_cluster_validator_count
        ));
    }
    let configured_stage_timeouts = (
        config.consensus.proposal_timeout_ms,
        config.consensus.prevote_timeout_ms,
        config.consensus.precommit_timeout_ms,
        config.consensus.max_round_timeout_ms,
    );
    let finalized_stage_timeouts = (
        manifest.proposal_timeout_ms,
        manifest.prevote_timeout_ms,
        manifest.precommit_timeout_ms,
        manifest.max_round_timeout_ms,
    );
    if configured_stage_timeouts != finalized_stage_timeouts {
        return Err(
            "node stage-timeout configuration disagrees with finalized consensus parameters"
                .to_string(),
        );
    }
    Ok(())
}

fn ensure_node_config_matches_coordinated_p1_parameters(
    config: &NodeConfig,
    manifest: &crate::consensus_parameters::CoordinatedRoundRobinParameterManifest,
) -> Result<(), String> {
    manifest.validate_finalized()?;
    let block_time_ms = config
        .consensus
        .block_time_secs
        .checked_mul(1_000)
        .ok_or_else(|| "node consensus block time overflows milliseconds".to_string())?;
    let blockchain_block_time_ms = config
        .blockchain
        .block_time
        .checked_mul(1_000)
        .ok_or_else(|| "node blockchain block time overflows milliseconds".to_string())?;
    if config.blockchain.chain_id != manifest.chain_id.0
        || config.network.id != manifest.chain_id.0
        || config.network.network_id != manifest.network_id.0
    {
        return Err(
            "node chain or network configuration disagrees with finalized coordinated P1 parameters"
                .to_string(),
        );
    }
    if config.consensus.algorithm.trim() != manifest.protocol_version
        || config.consensus.mode.trim() != manifest.protocol_version
    {
        return Err(
            "node consensus protocol identifier or mode disagrees with finalized coordinated P1 parameters"
                .to_string(),
        );
    }
    if block_time_ms != manifest.target_block_time_ms
        || blockchain_block_time_ms != manifest.target_block_time_ms
        || config.consensus.target_block_time_ms != manifest.target_block_time_ms
    {
        return Err(format!(
            "node block-time configuration disagrees with finalized {} ms coordinated P1 target",
            manifest.target_block_time_ms
        ));
    }
    let resolved = config
        .consensus
        .coordinated_round_robin_config(config.blockchain.chain_id, &config.network.network_id)?;
    let bound = &manifest.coordinated_round_robin;
    if resolved.consensus_version != manifest.protocol_version
        || resolved.coordinator_id != bound.coordinator_id
        || resolved.producer_ids != bound.producer_ids
        || resolved.producer_turn_timeout_ms != bound.producer_turn_timeout_ms
        || resolved.target_block_interval_ms != manifest.target_block_time_ms
    {
        return Err(
            "node coordinated P1 rotation configuration disagrees with the finalized Genesis parameters"
                .to_string(),
        );
    }
    Ok(())
}

/// Starts the sole Testnet-v3 consensus worker after all of its immutable
/// authorities have been constructed from finalized Genesis.  The generic
/// context sources are intentionally supplied by the finalized-chain layer;
/// this role runtime never creates a finality digest, synthesizes an epoch
/// transition, or accepts a candidate Genesis input.
///
/// Installation is transactional from the node's perspective.  If either
/// process-global P2P ingress cannot be installed, no worker is spawned and
/// any ingress already installed by this call is removed.  On normal shutdown
/// or any worker failure both global dispatch points are removed before the
/// worker returns, so later P2P messages cannot be queued for an old signer.
fn spawn_typed_posy_driver<D, H>(
    coordinator: TypedPosyCoordinator,
    protected_inputs: EtdagProtectedInputCoordinator,
    finality_digest_source: D,
    next_height_source: H,
    etdag_activation_permit: Option<EtdagActivationPermit>,
    etdag_ingress: Option<EtdagCertifiedInputIngress>,
    network: Arc<p2p::networking::P2PNetwork>,
    running: Arc<AtomicBool>,
) -> Result<TypedPosyWorker, String>
where
    D: TypedFinalityContextDigestSource + 'static,
    H: TypedNextHeightContextSource + 'static,
{
    let initial_execution_state = coordinator.finalized_execution_state_snapshot();
    let readiness_network = Arc::clone(&network);
    // Build the driver before exposing either P2P ingress.  A failure here
    // must not leave an inbound path pointing at a partially initialized
    // signer.
    let mut driver = TypedPosyDriver::new(
        coordinator,
        protected_inputs,
        P2pTypedConsensusEgress::new(network),
        finality_digest_source,
        next_height_source,
    )
    .map_err(|error| format!("typed PoSy driver construction failed: {error}"))?;
    set_typed_consensus_startup_phase("RECOVERY_VALIDATED");

    if let Some(permit) = etdag_activation_permit.as_ref() {
        driver
            .configure_etdag_activation(permit)
            .map_err(|error| format!("configure typed PoSy ETDAG activation: {error}"))?;
    }

    match (etdag_activation_permit, etdag_ingress) {
        (Some(permit), Some(ingress)) => install_etdag_certified_input_ingress(permit, ingress)
            .map_err(|error| format!("install ETDAG certified-input ingress: {error}"))?,
        (None, None) => {}
        _ => {
            return Err(
                "typed PoSy runtime received an incomplete ETDAG activation capability".to_string(),
            )
        }
    }
    if let Err(error) = install_finalized_execution_state_snapshot(initial_execution_state) {
        let _ = remove_etdag_certified_input_ingress();
        return Err(format!(
            "install finalized execution-state snapshot: {error}"
        ));
    }
    let receiver = match install_typed_coordinator_ingress(TYPED_POSY_INGRESS_CAPACITY) {
        Ok(receiver) => receiver,
        Err(error) => {
            let _ = remove_etdag_certified_input_ingress();
            remove_finalized_execution_state_snapshot();
            return Err(format!("install typed PoSy ingress: {error}"));
        }
    };
    set_typed_consensus_startup_phase("MAILBOX_READY");
    let required_remote_validators = driver.required_remote_validator_count();
    if let Err(error) =
        wait_for_finalized_typed_peer_readiness(&readiness_network, required_remote_validators)
    {
        let _ = remove_typed_coordinator_ingress();
        let _ = remove_etdag_certified_input_ingress();
        remove_finalized_execution_state_snapshot();
        return Err(error);
    }
    set_typed_consensus_startup_phase("PEERS_READY");
    if env::var("CONSENSUS_START_PAUSED")
        .ok()
        .is_some_and(|value| matches!(value.trim(), "1" | "true" | "TRUE" | "yes" | "YES"))
    {
        set_typed_consensus_startup_phase("PAUSED_READY");
    }
    if let Err(error) = wait_for_declared_consensus_start_barrier() {
        let _ = remove_typed_coordinator_ingress();
        let _ = remove_etdag_certified_input_ingress();
        remove_finalized_execution_state_snapshot();
        return Err(format!("consensus start barrier rejected release: {error}"));
    }
    set_typed_consensus_startup_phase("RUNNING");

    let fatal_error = Arc::new(Mutex::new(None));
    let worker_error = Arc::clone(&fatal_error);
    let worker_running = Arc::clone(&running);
    let handle = match thread::Builder::new()
        .name("typed-posy-driver".to_string())
        .spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run_typed_posy_driver(&mut driver, &receiver, &worker_running)
            }));
            let failure = match result {
                Ok(Ok(_)) => None,
                Ok(Err(error)) => Some(error),
                Err(_) => Some("typed PoSy driver worker panicked".to_string()),
            };
            if let Some(error) = failure {
                eprintln!("Finalized typed PoSy worker failed closed: {error}");
                if let Ok(mut slot) = worker_error.lock() {
                    *slot = Some(error);
                }
                // The main role loop observes this and exits non-zero.  Do
                // not leave any worker alive to sign after a fatal consensus
                // source or transport failure.
                worker_running.store(false, Ordering::Release);
            }
            let _ = remove_typed_coordinator_ingress();
            let _ = remove_etdag_certified_input_ingress();
            remove_finalized_execution_state_snapshot();
        }) {
        Ok(handle) => handle,
        Err(error) => {
            let _ = remove_typed_coordinator_ingress();
            let _ = remove_etdag_certified_input_ingress();
            remove_finalized_execution_state_snapshot();
            return Err(format!("spawn typed PoSy driver worker: {error}"));
        }
    };

    Ok(TypedPosyWorker {
        handle,
        fatal_error,
    })
}

struct FinalizedCoordinatedRuntimeInputs {
    runtime: CoordinatedRuntime,
    block_context: CoordinatedBlockBuildContext,
    config: crate::consensus::coordinated_round_robin::CoordinatedRoundRobinConfig,
}

/// Builds the P1 runtime exclusively from canonical Genesis, the finalized
/// six-validator set, and the local finalized consensus key. It has no
/// candidate-Genesis, legacy-chain, generated-key, or typed-PoSy fallback.
fn build_finalized_coordinated_runtime_inputs(
    config: &NodeConfig,
) -> Result<FinalizedCoordinatedRuntimeInputs, String> {
    let mode = config
        .consensus
        .resolve_mode(config.blockchain.chain_id, &config.network.network_id)?;
    let ResolvedConsensusMode::CoordinatedRoundRobinV1(coordinated_config) = mode else {
        return Err(
            "coordinated runtime construction requires coordinated_round_robin_v1".to_string(),
        );
    };
    let genesis = canonical_genesis()
        .map_err(|error| format!("coordinated runtime cannot load canonical Genesis: {error}"))?;
    let activation = crate::consensus_activation::load_installed_consensus_activation(genesis)
        .map_err(|error| {
            format!("coordinated runtime rejects its signed immutable-Genesis activation: {error}")
        })?;
    if activation.manifest.consensus_mode != coordinated_config.consensus_version
        || activation.manifest.coordinator_id != coordinated_config.coordinator_id
        || activation.manifest.producer_ids != coordinated_config.producer_ids
        || activation.manifest.producer_turn_timeout_ms
            != coordinated_config.producer_turn_timeout_ms
        || coordinated_config.target_block_interval_ms
            != crate::consensus_parameters::COORDINATED_P1_TARGET_BLOCK_TIME_MS
    {
        return Err(
            "coordinated runtime configuration disagrees with its signed P1 activation authority"
                .to_string(),
        );
    }
    let bootstrap =
        load_coordinated_round_robin_activation_bootstrap(genesis).map_err(|error| {
            format!("coordinated runtime cannot derive immutable-Genesis P1 bootstrap: {error}")
        })?;
    // The P1 committed-block header carries the exact canonical manifest root,
    // not a compatibility `ProtocolConfig` assembled for the retired engine.
    let protocol_config_hash = activation.root;
    let genesis_execution_state = load_finalized_testnet_v3_genesis_execution_state(genesis)
        .map_err(|error| {
            format!("coordinated runtime requires finalized Genesis execution state: {error}")
        })?;
    let deployed_genesis_state_root = genesis
        .value()
        .get("execution")
        .and_then(|execution| execution.get("genesis_execution_state_root"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "finalized Genesis omits execution.genesis_execution_state_root".to_string())
        .and_then(|root| {
            Hash::from_hex(root).map_err(|error| {
                format!("finalized Genesis execution state root is not canonical: {error}")
            })
        })?;
    let genesis_anchor = Hash::from_hex(genesis.hash())
        .map_err(|error| format!("canonical Genesis hash is not a coordinated anchor: {error}"))?;
    let genesis_timestamp_ms = genesis
        .timestamp()
        .checked_mul(1_000)
        .ok_or_else(|| "canonical Genesis timestamp milliseconds overflow".to_string())?;

    let validator_address = resolve_local_validator_address(config);
    ensure_local_validator_record_available(&validator_address)?;
    let (public_key, private_key) =
        load_local_validator_keypair_for_height(0, &validator_address, &VALIDATOR_MANAGER)
            .map_err(|error| {
                format!(
                    "coordinated runtime cannot load canonical local consensus signing key: {error}"
                )
            })?;
    let (signer, local_validator_id) = import_local_genesis_bound_coordinated_signer(
        &bootstrap,
        &validator_address,
        public_key,
        private_key,
    )
    .map_err(|error| format!("coordinated runtime rejects local signer: {error}"))?;
    let initial_state = CoordinatorState::from_migration_anchor(
        0,
        genesis_anchor,
        bootstrap.genesis_transition_root,
    )
    .map_err(|error| {
        format!("coordinated runtime cannot create the Genesis anchor state: {error}")
    })?;
    let state_store = CoordinatorStateStore::at_path(crate::utils::resolve_data_path(
        "data/coordinated-round-robin-state.json",
    ))
    .map_err(|error| format!("coordinated runtime state store initialization failed: {error}"))?;
    // A controlled reset wipes this exact controller-managed data root.  Do
    // not permit an environment-selected finality location that could retain
    // old block data outside the release-bound deletion manifest.
    let finality_store = CoordinatedFinalityStore::at_path(
        crate::utils::resolve_data_path("data/coordinated-round-robin-finality.json"),
        genesis_anchor,
        deployed_genesis_state_root,
        Height(1),
    )
    .map_err(|error| format!("coordinated finality store initialization failed: {error}"))?;
    let runtime = CoordinatedRuntime::new(
        coordinated_config.clone(),
        &bootstrap.validator_set,
        bootstrap.verifier,
        local_validator_id,
        signer,
        DurableConsensusSigningAuthority::process_wide(),
        state_store,
        initial_state,
        finality_store,
        genesis_execution_state,
    )
    .map_err(|error| format!("coordinated runtime startup rejected: {error}"))?;
    let block_context = CoordinatedBlockBuildContext {
        genesis_anchor,
        genesis_timestamp_ms,
        protocol_config_hash,
        cryptographic_profile_root: bootstrap.cryptographic_profile_root,
    };
    block_context
        .validate()
        .map_err(|error| format!("coordinated block context is invalid: {error}"))?;
    Ok(FinalizedCoordinatedRuntimeInputs {
        runtime,
        block_context,
        config: coordinated_config,
    })
}

fn broadcast_coordinated_to_reachable_validators(
    network: &p2p::networking::P2PNetwork,
    message: &crate::p2p::messages::CoordinatedConsensusMessage,
) -> Result<(), String> {
    let _sent = network.broadcast_coordinated_consensus(message)?;
    Ok(())
}

fn publish_coordinated_finalized_execution_state(
    runtime: &CoordinatedRuntime,
) -> Result<(), String> {
    if !publish_finalized_execution_state_snapshot(runtime.execution_state()) {
        return Err(
            "coordinated finality cannot publish without its installed execution snapshot"
                .to_string(),
        );
    }
    Ok(())
}

/// Publishes a read-only P1 lifecycle snapshot after a durable state
/// transition.  The missed-turn total is derived from the signed assignment
/// sequence rather than the coordinator-local event list, so every validator
/// reports the same count after receiving a replacement assignment.
fn publish_coordinated_runtime_telemetry(
    runtime: &CoordinatedRuntime,
    config: &crate::consensus::coordinated_round_robin::CoordinatedRoundRobinConfig,
) {
    let state = runtime.coordinator_state();
    let (assigned_height, assigned_producer_round, assigned_producer_id) = state
        .pending_assignment
        .as_ref()
        .map(|assignment| {
            (
                assignment.height,
                assignment.producer_round,
                assignment.assigned_producer_id.clone(),
            )
        })
        .unwrap_or_else(|| {
            (
                state.next_height(),
                state.pending_round,
                config
                    .producer_at(state.producer_cursor)
                    .unwrap_or_default()
                    .to_string(),
            )
        });
    let (finalized_producer_id, finalized_producer_round) = state
        .last_commit
        .as_ref()
        .map(|commit| (commit.producer_id.clone(), commit.producer_round))
        .unwrap_or_default();
    telemetry::publish_coordinated_consensus_telemetry(
        telemetry::CoordinatedConsensusTelemetrySnapshot {
            active: true,
            finalized_height: state.last_finalized_height,
            finalized_block_id: state.last_finalized_block_hash.to_hex(),
            finalized_producer_id,
            finalized_producer_round,
            assigned_height,
            assigned_producer_round,
            assigned_producer_id,
            missed_turns_total: state
                .assignment_sequence
                .saturating_sub(state.last_finalized_height),
        },
    );
}

/// Recovers only the exact, authenticated Aegis envelopes submitted through
/// the ordinary RPC/P2P transaction pool. The legacy carrier is merely the
/// transport envelope: P1 signs and executes its contained typed transaction,
/// never the carrier representation. Sorting canonical bytes makes a local
/// producer's selection stable across a retry/restart with the same pool.
fn select_coordinated_transaction_admissions() -> Result<Vec<AegisTxSubmissionEnvelope>, String> {
    let pool = TX_POOL
        .lock()
        .map_err(|_| "coordinated transaction pool lock is poisoned".to_string())?
        .clone();
    let mut admissions = Vec::new();
    for transaction in &pool {
        if !is_legacy_aegis_carrier_transaction(transaction) {
            continue;
        }
        let data = transaction
            .data
            .as_deref()
            .ok_or_else(|| "Aegis carrier transaction omitted carrier data".to_string())?;
        let admission = decode_aegis_carrier_data(data)
            .map_err(|error| format!("decode coordinated transaction admission: {error}"))?;
        admissions.push(admission);
    }
    admissions.sort_by(|left, right| {
        left.transaction
            .canonical_bytes()
            .unwrap_or_default()
            .cmp(&right.transaction.canonical_bytes().unwrap_or_default())
    });
    Ok(admissions)
}

fn maybe_broadcast_local_coordinated_proposal(
    runtime: &mut CoordinatedRuntime,
    block_context: &CoordinatedBlockBuildContext,
    coordinator_id: &str,
    network: &p2p::networking::P2PNetwork,
) -> Result<(), String> {
    let Some(assignment) = runtime.pending_assignment().cloned() else {
        return Ok(());
    };
    if assignment.assigned_producer_id != runtime.local_validator_id().0 {
        return Ok(());
    }
    let admissions = select_coordinated_transaction_admissions()?;
    let block = runtime.build_assigned_block(&assignment, block_context, &admissions)?;
    let (proposal, block) =
        match runtime.sign_assigned_producer_block(&assignment, block, admissions) {
            Ok(value) => value,
            Err(error) if error.contains("CONSENSUS_SIGNING_CONFLICT") => {
                // A stale durable slot may never authorize a second subject. Leave
                // the producer online as a follower and let Val1 time out this turn.
                return Ok(());
            }
            Err(error) => return Err(error),
        };
    network.send_coordinated_consensus_to_validator(
        coordinator_id,
        &crate::p2p::messages::CoordinatedConsensusMessage::ProposedBlock {
            assignment,
            proposal,
            block,
        },
    )
}

fn issue_or_rebroadcast_coordinated_assignment(
    runtime: &mut CoordinatedRuntime,
    block_context: &CoordinatedBlockBuildContext,
    network: &p2p::networking::P2PNetwork,
) -> Result<(), String> {
    let assignment = match runtime.pending_assignment().cloned() {
        Some(assignment) => assignment,
        None => {
            runtime.issue_signed_assignment(runtime.next_assignment_timestamp(block_context)?)?
        }
    };
    broadcast_coordinated_to_reachable_validators(
        network,
        &crate::p2p::messages::CoordinatedConsensusMessage::ProducerAssignment { assignment },
    )
}

fn request_next_coordinated_finality(
    runtime: &CoordinatedRuntime,
    config: &crate::consensus::coordinated_round_robin::CoordinatedRoundRobinConfig,
    network: &p2p::networking::P2PNetwork,
) -> Result<(), String> {
    let start_height = runtime.coordinator_state().next_height();
    let end_height = start_height.saturating_add(
        (crate::p2p::messages::MAX_COORDINATED_CONSENSUS_SYNC_RANGE_BLOCKS as u64)
            .saturating_sub(1),
    );
    network.send_coordinated_consensus_to_validator(
        &config.coordinator_id,
        &crate::p2p::messages::CoordinatedConsensusMessage::GetCommittedBlockRange {
            start_height,
            end_height,
        },
    )
}

fn run_coordinated_round_robin_driver(
    runtime: &mut CoordinatedRuntime,
    block_context: &CoordinatedBlockBuildContext,
    config: &crate::consensus::coordinated_round_robin::CoordinatedRoundRobinConfig,
    receiver: &mpsc::Receiver<CoordinatedConsensusEnvelope>,
    network: &p2p::networking::P2PNetwork,
    running: &AtomicBool,
) -> Result<(), String> {
    let mut producer_deadline = None;
    let mut next_assignment_due = None;
    let mut finality_sync_pending = false;
    if runtime.is_local_coordinator() {
        issue_or_rebroadcast_coordinated_assignment(runtime, block_context, network)?;
        producer_deadline =
            Some(Instant::now() + Duration::from_millis(config.producer_turn_timeout_ms));
    } else {
        // On restart the local producer retransmits only its exact durable
        // envelope for a still-pending assignment; it cannot invent a new
        // proposal subject.
        maybe_broadcast_local_coordinated_proposal(
            runtime,
            block_context,
            &config.coordinator_id,
            network,
        )?;
        // A restarted follower may be behind the live assignment stream.
        // Request one authenticated committed package at a time; a missing
        // successor receives an empty response and leaves the worker active.
        finality_sync_pending = true;
        let _ = request_next_coordinated_finality(runtime, config, network);
    }
    publish_coordinated_runtime_telemetry(runtime, config);

    while running.load(Ordering::Acquire) {
        let now = Instant::now();
        if runtime.is_local_coordinator() {
            if let Some(due) = next_assignment_due {
                if now >= due {
                    issue_or_rebroadcast_coordinated_assignment(runtime, block_context, network)?;
                    producer_deadline = Some(
                        Instant::now() + Duration::from_millis(config.producer_turn_timeout_ms),
                    );
                    next_assignment_due = None;
                }
            }
        }

        match receiver.recv_timeout(Duration::from_millis(50)) {
            Ok(envelope) => {
                let received_assignment = matches!(
                    &envelope.message,
                    crate::p2p::messages::CoordinatedConsensusMessage::ProducerAssignment { .. }
                );
                let deferred_assignment = matches!(
                    &envelope.message,
                    crate::p2p::messages::CoordinatedConsensusMessage::ProducerAssignment { assignment }
                        if assignment.height > runtime.coordinator_state().next_height()
                );
                let received_finality_response = matches!(
                    &envelope.message,
                    crate::p2p::messages::CoordinatedConsensusMessage::CommittedBlock { .. }
                        | crate::p2p::messages::CoordinatedConsensusMessage::CommittedBlockRange { .. }
                );
                let received_empty_finality_range = matches!(
                    &envelope.message,
                    crate::p2p::messages::CoordinatedConsensusMessage::CommittedBlockRange { packages }
                        if packages.is_empty()
                );
                let expected_finality_height = runtime.coordinator_state().next_height();
                let deferred_finality = match &envelope.message {
                    crate::p2p::messages::CoordinatedConsensusMessage::CommittedBlock {
                        package,
                    } => package.block.header.height.0 > expected_finality_height,
                    crate::p2p::messages::CoordinatedConsensusMessage::CommittedBlockRange {
                        packages,
                    } => packages
                        .first()
                        .map(|package| package.block.header.height.0 > expected_finality_height)
                        .unwrap_or(false),
                    _ => false,
                };
                if deferred_finality {
                    // A live broadcast can be ahead of this follower. Do not
                    // append it out of order; continue the one-block sync.
                    finality_sync_pending = true;
                    let _ = request_next_coordinated_finality(runtime, config, network);
                    continue;
                }
                let action = runtime
                    .handle_authenticated_message(&envelope.authenticated_peer, envelope.message)?;
                match action {
                    CoordinatedRuntimeAction::None => {}
                    CoordinatedRuntimeAction::BroadcastCommitted(package) => {
                        broadcast_coordinated_to_reachable_validators(
                            network,
                            &crate::p2p::messages::CoordinatedConsensusMessage::CommittedBlock {
                                package,
                            },
                        )?;
                        publish_coordinated_finalized_execution_state(runtime)?;
                        producer_deadline = None;
                        next_assignment_due = Some(
                            Instant::now() + Duration::from_millis(config.target_block_interval_ms),
                        );
                    }
                    CoordinatedRuntimeAction::Respond(message) => {
                        network.send_coordinated_consensus_to_validator(
                            envelope.authenticated_peer.validator_id.0.as_str(),
                            &message,
                        )?;
                    }
                }
                if received_assignment {
                    maybe_broadcast_local_coordinated_proposal(
                        runtime,
                        block_context,
                        &config.coordinator_id,
                        network,
                    )?;
                }
                if deferred_assignment {
                    finality_sync_pending = true;
                    let _ = request_next_coordinated_finality(runtime, config, network);
                }
                if received_empty_finality_range {
                    finality_sync_pending = false;
                } else if finality_sync_pending && received_finality_response {
                    let _ = request_next_coordinated_finality(runtime, config, network);
                }
                publish_coordinated_finalized_execution_state(runtime)?;
                publish_coordinated_runtime_telemetry(runtime, config);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err("coordinated consensus ingress disconnected".to_string())
            }
        }

        // A proposal already queued by the authenticated P2P reader is still
        // for Val1's durable current assignment. Process it before the
        // timeout path makes that exact subject stale; an idle receiver still
        // advances the producer turn under the configured deadline.
        if runtime.is_local_coordinator() {
            if let Some(deadline) = producer_deadline {
                if Instant::now() >= deadline && runtime.pending_assignment().is_some() {
                    let replacement_timestamp =
                        runtime.timeout_replacement_assignment_timestamp(block_context)?;
                    let assignment = runtime.skip_producer_turn_and_issue_assignment(
                        "producer timeout",
                        replacement_timestamp,
                    )?;
                    broadcast_coordinated_to_reachable_validators(
                        network,
                        &crate::p2p::messages::CoordinatedConsensusMessage::ProducerAssignment {
                            assignment,
                        },
                    )?;
                    publish_coordinated_runtime_telemetry(runtime, config);
                    producer_deadline = Some(
                        Instant::now() + Duration::from_millis(config.producer_turn_timeout_ms),
                    );
                }
            }
        }
    }
    Ok(())
}

/// The `single_authority_v1` block-production loop.
///
/// One authority, one block per height, at the signed target block time. There
/// is no coordinator, producer, assignment, proposal, vote, certificate,
/// quorum, round, cluster, view change, catch-up, peer, or relayer here, and no
/// consensus ingress channel exists for this path to read from.
fn run_single_authority_driver(
    driver: &mut crate::consensus::single_authority_driver::SingleAuthorityDriver,
    target_block_time_ms: u64,
    running: &AtomicBool,
) -> Result<(), String> {
    let interval = Duration::from_millis(target_block_time_ms.max(1));
    let mut next_due = Instant::now();
    while running.load(Ordering::Acquire) {
        let now = Instant::now();
        if now < next_due {
            thread::sleep(std::cmp::min(next_due - now, Duration::from_millis(50)));
            continue;
        }
        // Transaction selection is wired to the canonical admission pool. The
        // driver re-admits every carrier it is handed, so this only supplies a
        // body: block construction, signing, execution and finality are
        // unchanged, and an empty pool still produces a full finalization
        // cycle over an empty canonical block.
        let selected = drain_single_authority_admission_pool();
        let block = driver.produce_next_block(selected)?;
        publish_single_authority_finalized_execution_state(driver)?;
        next_due = Instant::now() + interval;
        let _ = block;
    }
    Ok(())
}

/// Takes the currently admitted transactions for the next single-authority
/// block. Bounded per height so one oversized batch cannot stall production.
fn drain_single_authority_admission_pool() -> Vec<crate::transaction::Transaction> {
    const MAX_TRANSACTIONS_PER_BLOCK: usize = 256;

    let Ok(mut pool) = crate::rpc::rpc_server::TX_POOL.lock() else {
        return Vec::new();
    };
    if pool.is_empty() {
        return Vec::new();
    }
    let take = pool.len().min(MAX_TRANSACTIONS_PER_BLOCK);
    pool.drain(..take).collect()
}

fn publish_single_authority_finalized_execution_state(
    driver: &crate::consensus::single_authority_driver::SingleAuthorityDriver,
) -> Result<(), String> {
    // The snapshot is INSTALLED once, by `spawn_single_authority_driver`,
    // before the loop begins. Every subsequent finalized height PUBLISHES into
    // that live slot; re-installing would be refused and would kill the driver
    // immediately after the first block.
    if publish_finalized_execution_state_snapshot(driver.execution_state()) {
        Ok(())
    } else {
        Err(
            "publish single-authority execution-state snapshot: no finalized snapshot is installed"
                .to_string(),
        )
    }
}

/// Durable single-authority paths, derived from the SIGNED namespace so a
/// stale incarnation directory can never be opened.
fn single_authority_durable_paths(
    plan: &SingleAuthorityStartupPlan,
) -> crate::consensus::single_authority_startup::SingleAuthorityDurablePaths {
    let root = crate::utils::resolve_data_path(&format!(
        "data/consensus/{}",
        plan.directory_namespace.replace('/', "-")
    ));
    crate::consensus::single_authority_startup::SingleAuthorityDurablePaths {
        finality_log_path: root.join("single-authority-finality.log"),
        finality_head_path: root.join("single-authority-finality.head.json"),
        signing_journal_path: root.join("single-authority-signing-journal.json"),
        committed_block_log_path: root.join("single-authority-committed-blocks.ndjson"),
        execution_state_path: root.join("single-authority-execution-state.json"),
        receipt_log_path: root.join("single-authority-receipts.ndjson"),
    }
}

/// Builds the driver inputs from the VERIFIED plan. Nothing coordinated is
/// constructed, instantiated, or read on this path.
fn build_single_authority_runtime_inputs(
    config: &NodeConfig,
    plan: &SingleAuthorityStartupPlan,
) -> Result<
    crate::consensus::single_authority_driver::SingleAuthorityRuntimeInputs,
    String,
> {
    let genesis = crate::genesis::canonical_genesis()?;
    if genesis.hash() != plan.genesis_hash {
        return Err(
            "canonical Genesis hash disagrees with the signed single-authority activation"
                .to_string(),
        );
    }
    let genesis_execution_state =
        crate::testnet_v3_execution_bootstrap::load_finalized_testnet_v3_genesis_execution_state(
            genesis,
        )?;

    let authority_address = resolve_local_validator_address(config);
    let (authority_public_key, authority_private_key) =
        crate::consensus::validator_keys::load_local_validator_keypair(
            &authority_address,
            &VALIDATOR_MANAGER,
        )?;
    if authority_public_key.algorithm != crate::crypto::pqc::PQCAlgorithm::MLDSA65 {
        return Err(format!(
            "single-authority block signing requires ML-DSA-65, found {:?}",
            authority_public_key.algorithm
        ));
    }
    let fingerprint = format!(
        "sha256:{}",
        hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&authority_public_key.key_data))
    );
    if fingerprint != plan.authority_public_key_fingerprint {
        return Err(
            "local authority key fingerprint disagrees with the signed activation".to_string(),
        );
    }

    let paths = single_authority_durable_paths(plan);
    crate::consensus::single_authority_startup::require_durable_binding_agreement(plan, &paths)?;

    Ok(
        crate::consensus::single_authority_driver::SingleAuthorityRuntimeInputs {
            chain_id: plan.chain_id,
            chain_incarnation: plan.chain_incarnation,
            network_id: plan.network_id.clone(),
            release_id: plan.release_id.clone(),
            authority_id: plan.authority_id.clone(),
            authority_key_id: format!("{}-block-key", plan.authority_id),
            authority_public_key,
            authority_private_key,
            authority_public_key_fingerprint: plan.authority_public_key_fingerprint.clone(),
            target_block_time_ms: plan.target_block_time_ms,
            genesis_hash: plan.genesis_hash.clone(),
            directory_namespace: plan.directory_namespace.clone(),
            finality_log_path: paths.finality_log_path,
            finality_head_path: paths.finality_head_path,
            signing_journal_path: paths.signing_journal_path,
            committed_block_log_path: paths.committed_block_log_path,
            execution_state_path: paths.execution_state_path,
            receipt_log_path: paths.receipt_log_path,
            genesis_execution_state,
        },
    )
}

/// Starts the single-authority worker. It takes no network handle and installs
/// no consensus ingress: this protocol has no peers.
fn spawn_single_authority_driver(
    config: &NodeConfig,
    plan: &SingleAuthorityStartupPlan,
    running: Arc<AtomicBool>,
) -> Result<SingleAuthorityWorker, String> {
    let inputs = build_single_authority_runtime_inputs(config, plan)?;
    let target_block_time_ms = inputs.target_block_time_ms;
    let mut driver =
        crate::consensus::single_authority_driver::SingleAuthorityDriver::start(inputs)?;
    install_finalized_execution_state_snapshot(driver.execution_state().clone())
        .map_err(|error| format!("install single-authority execution-state snapshot: {error}"))?;

    let fatal_error = Arc::new(Mutex::new(None));
    let worker_error = Arc::clone(&fatal_error);
    let worker_running = Arc::clone(&running);
    let handle = match thread::Builder::new()
        .name("single-authority-driver".to_string())
        .spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run_single_authority_driver(
                    &mut driver,
                    target_block_time_ms,
                    &worker_running,
                )
            }));
            let failure = match result {
                Ok(Ok(())) => None,
                Ok(Err(error)) => Some(error),
                Err(_) => Some("single-authority worker panicked".to_string()),
            };
            if let Some(error) = failure {
                eprintln!("Single-authority worker failed closed: {error}");
                if let Ok(mut slot) = worker_error.lock() {
                    *slot = Some(error);
                }
                worker_running.store(false, Ordering::Release);
            }
            remove_finalized_execution_state_snapshot();
        }) {
        Ok(handle) => handle,
        Err(error) => {
            remove_finalized_execution_state_snapshot();
            return Err(format!("spawn single-authority worker: {error}"));
        }
    };
    Ok(SingleAuthorityWorker {
        handle,
        fatal_error,
    })
}

fn spawn_coordinated_round_robin_driver(
    config: &NodeConfig,
    network: Arc<p2p::networking::P2PNetwork>,
    running: Arc<AtomicBool>,
) -> Result<CoordinatedRoundRobinWorker, String> {
    telemetry::clear_coordinated_consensus_telemetry();
    let inputs = build_finalized_coordinated_runtime_inputs(config)?;
    let initial_execution_state = inputs.runtime.execution_state().clone();
    install_finalized_execution_state_snapshot(initial_execution_state)
        .map_err(|error| format!("install coordinated execution-state snapshot: {error}"))?;
    let receiver =
        match install_coordinated_consensus_ingress(COORDINATED_ROUND_ROBIN_INGRESS_CAPACITY) {
            Ok(receiver) => receiver,
            Err(error) => {
                remove_finalized_execution_state_snapshot();
                return Err(format!("install coordinated consensus ingress: {error}"));
            }
        };
    if let Err(error) = wait_for_declared_consensus_start_barrier() {
        let _ = remove_coordinated_consensus_ingress();
        remove_finalized_execution_state_snapshot();
        return Err(format!("consensus start barrier rejected release: {error}"));
    }

    let fatal_error = Arc::new(Mutex::new(None));
    let worker_error = Arc::clone(&fatal_error);
    let worker_running = Arc::clone(&running);
    let handle = match thread::Builder::new()
        .name("coordinated-round-robin-driver".to_string())
        .spawn(move || {
            let mut runtime = inputs.runtime;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run_coordinated_round_robin_driver(
                    &mut runtime,
                    &inputs.block_context,
                    &inputs.config,
                    &receiver,
                    &network,
                    &worker_running,
                )
            }));
            let failure = match result {
                Ok(Ok(())) => None,
                Ok(Err(error)) => Some(error),
                Err(_) => Some("coordinated round-robin worker panicked".to_string()),
            };
            if let Some(error) = failure {
                eprintln!("Coordinated round-robin worker failed closed: {error}");
                if let Ok(mut slot) = worker_error.lock() {
                    *slot = Some(error);
                }
                worker_running.store(false, Ordering::Release);
            }
            let _ = remove_coordinated_consensus_ingress();
            remove_finalized_execution_state_snapshot();
            telemetry::clear_coordinated_consensus_telemetry();
        }) {
        Ok(handle) => handle,
        Err(error) => {
            let _ = remove_coordinated_consensus_ingress();
            remove_finalized_execution_state_snapshot();
            telemetry::clear_coordinated_consensus_telemetry();
            return Err(format!("spawn coordinated round-robin worker: {error}"));
        }
    };
    Ok(CoordinatedRoundRobinWorker {
        handle,
        fatal_error,
    })
}

// The inherited ProofOfSynergy/DualQuorum loop deliberately has no production
// entry point.  Keep the assertion helper test-only: production validator
// startup below owns only `spawn_finalized_typed_posy_driver`.
#[cfg(test)]
fn attempt_inherited_consensus_engine() -> Result<(), String> {
    Err(
        "POSY_V2_2_OPERATIONAL_COORDINATOR_NOT_READY: the inherited ProofOfSynergy/DualQuorumConsensus loop is disabled; refusing validator signing until the finalized typed driver lifecycle is installed"
            .to_string(),
    )
}

/// Builds the only signing-capable typed PoSy coordinator startup input from
/// the canonical finalized Genesis document and the local canonical validator
/// key loader.  This function intentionally has no candidate-Genesis,
/// generated-key, legacy-consensus, or P2P-address fallback.
///
/// It does not itself start the mailbox worker: the operational driver must
/// atomically pair the worker with deterministic ETDAG scheduling and typed
/// P2P egress.  Starting an inbound-only signer would make the node appear
/// live while omitting its required proposal/vote/timeout lifecycle.
fn build_finalized_typed_posy_coordinator(
    config: &NodeConfig,
) -> Result<TypedPosyCoordinator, String> {
    let genesis = canonical_genesis()
        .map_err(|error| format!("typed PoSy startup cannot load canonical Genesis: {error}"))?;
    let genesis_bootstrap = load_testnet_v3_genesis_bootstrap(genesis).map_err(|error| {
        format!("typed PoSy startup cannot derive finalized Genesis bootstrap: {error}")
    })?;
    let consensus_parameters = genesis.consensus_parameters().cloned().ok_or_else(|| {
        "typed PoSy startup requires a finalized consensus parameter binding in canonical Genesis"
            .to_string()
    })?;
    consensus_parameters
        .require_genesis_binding()
        .map_err(|error| {
            format!("typed PoSy startup refuses a non-Genesis-bound parameter manifest: {error}")
        })?;
    consensus_parameters
        .require_posy_manifest()
        .map_err(|error| format!("typed PoSy startup rejects non-PoSy parameters: {error}"))?;

    // This restoration refuses the candidate/pre-approval path and verifies
    // the embedded ceremony snapshot, its roots, deployed contracts, and
    // balances before any signing authority can exist.
    let genesis_execution_state = load_finalized_testnet_v3_genesis_execution_state(genesis)
        .map_err(|error| {
            format!("typed PoSy startup requires finalized Genesis execution state: {error}")
        })?;
    let genesis_anchor = Hash::from_hex(genesis.hash())
        .map_err(|error| format!("canonical Genesis hash is not a typed anchor: {error}"))?;
    let deployed_genesis_state_root = genesis
        .value()
        .get("execution")
        .and_then(|execution| execution.get("genesis_execution_state_root"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "finalized Genesis omits execution.genesis_execution_state_root".to_string())
        .and_then(|root| {
            Hash::from_hex(root).map_err(|error| {
                format!("finalized Genesis execution state root is not canonical: {error}")
            })
        })?;

    let validator_address = resolve_local_validator_address(config);
    ensure_local_validator_record_available(&validator_address)?;
    let (public_key, private_key) =
        load_local_validator_keypair_for_height(0, &validator_address, &VALIDATOR_MANAGER)
            .map_err(|error| {
                format!(
                    "typed PoSy startup cannot load canonical local consensus signing key: {error}"
                )
            })?;
    let (signer, local_validator_id) = import_local_genesis_bound_typed_signer(
        &genesis_bootstrap,
        &validator_address,
        public_key,
        private_key,
    )
    .map_err(|error| format!("typed PoSy startup rejects local signer: {error}"))?;
    let finality_store = TypedFinalityStore::for_genesis_anchor(genesis_anchor)
        .map_err(|error| format!("typed PoSy finality store initialization failed: {error}"))?;
    // A recovered context tells the coordinator where to resume consensus,
    // but contract RPC must also reconstruct the exact state at that tip.  Do
    // this before installing a signer or an RPC snapshot; any root mismatch
    // turns startup into a fail-closed recovery error.
    let execution_state = replay_finalized_execution_state(
        genesis_execution_state,
        &finality_store.recover().map_err(|error| {
            format!("typed PoSy finalized execution replay cannot load store: {error}")
        })?,
    )
    .map_err(|error| format!("typed PoSy finalized execution replay rejected startup: {error}"))?;
    // A restart may only resume at the deterministic successor of the durable
    // typed-QC tip.  The provider rejects a store from another Genesis,
    // malformed continuations, and epoch-transition state that lacks its
    // separate verified topology-installation payload.
    let recovered_context = FinalizedTypedContextProvider::new(
        genesis_bootstrap.clone(),
        consensus_parameters.protocol_config.clone(),
        finality_store.clone(),
        deployed_genesis_state_root,
    )
    .and_then(|provider| provider.recover_next_context())
    .map_err(|error| format!("typed PoSy finalized-context recovery rejected startup: {error}"))?;

    TypedPosyCoordinatorStartup {
        genesis_bootstrap,
        consensus_parameters,
        signer,
        local_validator_id,
        genesis_anchor,
        deployed_genesis_state_root,
        execution_state,
        etdag_parameters: EtdagParameters::default(),
        finality_store,
    }
    .build_with_finalized_context(recovered_context)
    .map_err(|error| format!("typed PoSy finalized coordinator startup rejected: {error}"))
}

/// Public, finalized-only inputs for the operational driver.  This stays
/// private to the role runtime so no RPC, P2P, or legacy consensus caller can
/// obtain a signer or override the recovered finality context.
struct FinalizedTypedPosyRuntimeInputs {
    coordinator: TypedPosyCoordinator,
    protected_inputs: EtdagProtectedInputCoordinator,
    finality_digest_source: FinalizedTypedContextProvider,
    next_height_source: FinalizedTypedContextProvider,
    etdag_activation_permit: Option<EtdagActivationPermit>,
    etdag_ingress: Option<EtdagCertifiedInputIngress>,
}

fn resolve_finalized_etdag_startup_activation(
    consensus_parameters: &crate::consensus_parameters::LoadedConsensusParameters,
    epoch: crate::synergy_types::Epoch,
) -> Result<Option<EtdagActivationPermit>, String> {
    match consensus_parameters.require_etdag_activation_at_epoch(epoch) {
        Ok(permit) => Ok(Some(permit)),
        Err(error)
            if error.contains(crate::consensus_parameters::ERR_ETDAG_DEFERRED)
                || error.contains(crate::consensus_parameters::ERR_ETDAG_PREMATURE_ACTIVATION) =>
        {
            // ETDAG is intentionally inactive.  The typed core consensus
            // driver remains operational on its deterministic empty-block
            // path; no plaintext transaction path is enabled here.
            Ok(None)
        }
        Err(error) => Err(format!("typed PoSy ETDAG activation is invalid: {error}")),
    }
}

fn build_finalized_typed_posy_runtime_inputs(
    config: &NodeConfig,
) -> Result<FinalizedTypedPosyRuntimeInputs, String> {
    let coordinator = build_finalized_typed_posy_coordinator(config)?;
    let genesis = canonical_genesis().map_err(|error| {
        format!("typed PoSy driver cannot reload canonical finalized Genesis: {error}")
    })?;
    let bootstrap = load_testnet_v3_genesis_bootstrap(genesis).map_err(|error| {
        format!("typed PoSy driver cannot derive finalized Genesis bootstrap: {error}")
    })?;
    let consensus_parameters = genesis.consensus_parameters().cloned().ok_or_else(|| {
        "typed PoSy driver requires a finalized consensus parameter binding in canonical Genesis"
            .to_string()
    })?;
    consensus_parameters
        .require_genesis_binding()
        .map_err(|error| {
            format!("typed PoSy driver rejects a non-Genesis-bound parameter manifest: {error}")
        })?;
    consensus_parameters
        .require_posy_manifest()
        .map_err(|error| format!("typed PoSy driver rejects non-PoSy parameters: {error}"))?;
    let deployed_genesis_state_root = genesis
        .value()
        .get("execution")
        .and_then(|execution| execution.get("genesis_execution_state_root"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "finalized Genesis omits execution.genesis_execution_state_root".to_string())
        .and_then(|root| {
            Hash::from_hex(root).map_err(|error| {
                format!("finalized Genesis execution state root is not canonical: {error}")
            })
        })?;
    let genesis_anchor = Hash::from_hex(genesis.hash())
        .map_err(|error| format!("canonical Genesis hash is not a typed anchor: {error}"))?;
    let finality_store = TypedFinalityStore::for_genesis_anchor(genesis_anchor)
        .map_err(|error| format!("typed PoSy finality store initialization failed: {error}"))?;
    let local_context = coordinator.local_context().clone();
    let protocol_config = consensus_parameters.protocol_config.clone();
    // ETDAG preparation artifacts are intentionally not an activation
    // authority.  The applied schema-v2 Genesis has no ETDAG activation
    // record, so ETDAG P2P ingress remains absent while the typed core
    // consensus driver starts on its deterministic empty-block path.  A
    // future schema-v3 finalized manifest may issue the permit only at its
    // declared non-genesis epoch boundary.
    let etdag_activation_permit = resolve_finalized_etdag_startup_activation(
        &consensus_parameters,
        local_context.height_context.epoch,
    )?;

    // Construct independent provider values for the read-only ETDAG digest
    // source, the stateful next-height source, and the startup ingress.  Each
    // has identical canonical inputs and independently validates the durable
    // typed finality sequence; none can borrow or mutate the coordinator.
    let provider = || {
        FinalizedTypedContextProvider::new(
            bootstrap.clone(),
            protocol_config.clone(),
            finality_store.clone(),
            deployed_genesis_state_root,
        )
        .map_err(|error| format!("typed PoSy finalized-context provider rejected startup: {error}"))
    };
    let protected_inputs = EtdagProtectedInputCoordinator::process_wide();
    let etdag_ingress = if etdag_activation_permit.is_some() {
        let ingress_digest = provider()?
            .canonical_finality_context_digest(&local_context)
            .map_err(|error| {
                format!("typed PoSy ETDAG ingress context rejected startup: {error}")
            })?;
        Some(
            EtdagCertifiedInputIngress::new(
                protected_inputs.clone(),
                local_context.height_context.clone(),
                ingress_digest,
                bootstrap.verifier.clone(),
                bootstrap.validator_set.clone(),
                bootstrap.cluster_map.clone(),
                protocol_config.clone(),
                EtdagParameters::default(),
            )
            .map_err(|error| format!("typed PoSy ETDAG ingress rejected startup: {error}"))?,
        )
    } else {
        None
    };

    Ok(FinalizedTypedPosyRuntimeInputs {
        coordinator,
        protected_inputs,
        finality_digest_source: provider()?,
        next_height_source: provider()?,
        etdag_activation_permit,
        etdag_ingress,
    })
}

fn spawn_finalized_typed_posy_driver(
    config: &NodeConfig,
    network: Arc<p2p::networking::P2PNetwork>,
    running: Arc<AtomicBool>,
) -> Result<TypedPosyWorker, String> {
    let inputs = build_finalized_typed_posy_runtime_inputs(config)?;
    spawn_typed_posy_driver(
        inputs.coordinator,
        inputs.protected_inputs,
        inputs.finality_digest_source,
        inputs.next_height_source,
        inputs.etdag_activation_permit,
        inputs.etdag_ingress,
        network,
        running,
    )
}

fn ensure_consensus_pqc_runtime_ready(config: &NodeConfig) -> Result<(), String> {
    if config.blockchain.chain_id != 1266 || config.network.id != 1266 {
        return Err(format!(
            "validator consensus requires Testnet chain_id 1266, found blockchain.chain_id={} network.id={}",
            config.blockchain.chain_id, config.network.id
        ));
    }
    if config.network.network_id != "synergy-testnet-v3" {
        return Err(format!(
            "validator consensus requires network_id synergy-testnet-v3, found {}",
            config.network.network_id
        ));
    }
    let mode = config
        .consensus
        .resolve_mode(config.blockchain.chain_id, &config.network.network_id)?;
    if config.consensus.allow_genesis_status_bypass {
        return Err("validator consensus refuses genesis status bypass configuration".to_string());
    }
    let genesis = canonical_genesis()
        .map_err(|error| format!("validator consensus cannot load canonical Genesis: {error}"))?;
    load_testnet_v3_genesis_bootstrap(genesis).map_err(|error| {
        format!(
            "validator consensus canonical Genesis is not a valid Testnet-v3 bootstrap: {error}"
        )
    })?;
    ensure_local_validator_consensus_key_bound(config)?;
    match mode {
        ResolvedConsensusMode::PosyV2_2 => {
            // Constructing the coordinator proves the local key, immutable
            // Genesis anchor, parameter root, ceremony execution snapshot,
            // and typed finality boundary agree before it requests signing.
            let _coordinator = build_finalized_typed_posy_coordinator(config)?;
        }
        ResolvedConsensusMode::CoordinatedRoundRobinV1(_) => {
            // P1 has its own separate runtime, finality, and signing journals.
            // Do not construct typed PoSy as a preflight side effect.
        }
        ResolvedConsensusMode::SingleAuthorityV1 => {
            // Single authority never runs this peer-based preflight: it has no
            // peers, and its own startup gate is the signed V2 activation.
        }
    }
    Ok(())
}

/// A controlled fresh-genesis reset creates `.reset_flag` only after the fleet
/// controller has removed every chain-derived root.  Do not let that marker
/// merely skip sync: prove the in-memory chain contains the one canonical
/// genesis block before the flag is consumed.  Otherwise a partial or manual
/// reset could resume a stale nonzero history while logging a misleading
/// "fresh" start.
fn ensure_fresh_genesis_reset_state(
    blockchain: &Arc<Mutex<crate::block::BlockChain>>,
) -> Result<(), String> {
    ensure_fresh_reset_has_no_consensus_history(&crate::utils::resolve_data_path("data"))?;
    let canonical = canonical_genesis().map_err(|error| {
        format!("fresh-reset verification cannot load canonical genesis: {error}")
    })?;
    let chain = blockchain
        .lock()
        .map_err(|_| "fresh-reset verification cannot lock shared chain".to_string())?;
    if chain.chain.len() != 1 {
        return Err(format!(
            "fresh-reset marker requires exactly one genesis block, found {} blocks",
            chain.chain.len()
        ));
    }
    let genesis = chain
        .last()
        .ok_or_else(|| "fresh-reset marker found an empty shared chain".to_string())?;
    if genesis.block_index != 0
        || genesis.hash != canonical.hash()
        || !genesis.transactions.is_empty()
        || !genesis.validate()
    {
        return Err(
            "fresh-reset marker does not resolve to the immutable canonical genesis state"
                .to_string(),
        );
    }
    Ok(())
}

/// The reset marker comes only from the controlled fleet reset.  Reject it if
/// any durable finality, coordinator, or signing history remains: accepting a
/// marker in that state could make the next process appear to restart at
/// height zero while still being bound by an earlier chain incarnation.
fn ensure_fresh_reset_has_no_consensus_history(data_root: &Path) -> Result<(), String> {
    for artifact in FRESH_RESET_FORBIDDEN_CONSENSUS_ARTIFACTS {
        let path = data_root.join(artifact);
        if path.exists() {
            return Err(format!(
                "fresh-reset marker refuses stale consensus history at {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn ensure_local_validator_consensus_key_bound(config: &NodeConfig) -> Result<(), String> {
    let validator_address = resolve_local_validator_address(config);
    ensure_local_validator_record_available(&validator_address)?;

    let consensus_members =
        consensus_membership_validators(VALIDATOR_MANAGER.get_active_validators());
    if !consensus_members
        .iter()
        .any(|validator| validator.address == validator_address)
    {
        return Err(format!(
            "local validator {validator_address} is not ACTIVE in canonical Testnet consensus membership"
        ));
    }

    let preflight_height = match consensus_fork::active_consensus_fork_migration() {
        Ok(Some(migration)) => migration.fork_height,
        Ok(None) => 0,
        Err(error) => {
            return Err(format!(
                "local validator {validator_address} cannot load consensus fork metadata: {error}"
            ));
        }
    };

    load_local_validator_keypair_for_height(preflight_height, &validator_address, &VALIDATOR_MANAGER)
        .map(|_| ())
        .map_err(|error| {
            format!(
                "local validator {validator_address} cannot load a canonical Aegis PQC consensus signing key for height {preflight_height}: {error}"
            )
        })
}

fn ensure_local_validator_record_available(validator_address: &str) -> Result<(), String> {
    if VALIDATOR_MANAGER.get_validator(validator_address).is_some() {
        return Ok(());
    }

    let genesis = canonical_genesis().map_err(|error| {
        format!("failed to load canonical genesis for validator preflight: {error}")
    })?;
    let Some(initial_validator) = genesis
        .validators()
        .iter()
        .find(|validator| validator.operator_address == validator_address)
    else {
        return Err(format!(
            "local validator {validator_address} is not present in finalized validator registry or canonical Testnet genesis"
        ));
    };

    let consensus_public_key = validator_public_key_with_declared_algorithm(
        &initial_validator.operator_address,
        &initial_validator.consensus_public_key,
        &initial_validator.consensus_key_type,
    )
    .map_err(|error| {
        format!(
            "canonical validator {} has invalid consensus public key: {error}",
            initial_validator.operator_address
        )
    })?;

    VALIDATOR_MANAGER
        .register_validator(ValidatorRegistration {
            address: initial_validator.operator_address.clone(),
            public_key: consensus_public_key,
            name: initial_validator.moniker.clone(),
            stake_amount: initial_validator.stake_nwei,
            submitted_at: now_ts(),
            registration_tx_hash: "genesis".to_string(),
        })
        .map_err(|error| {
            format!("failed to register canonical validator {validator_address}: {error}")
        })?;
    VALIDATOR_MANAGER
        .approve_validator(validator_address)
        .map_err(|error| {
            format!("failed to activate canonical validator {validator_address}: {error}")
        })?;
    VALIDATOR_MANAGER.update_validator_stake(validator_address, initial_validator.stake_nwei);
    Ok(())
}

fn ensure_genesis_validator_membership_available() -> Result<usize, String> {
    let genesis = canonical_genesis().map_err(|error| {
        format!("failed to load canonical genesis for validator membership preflight: {error}")
    })?;
    let validator_addresses = genesis
        .validators()
        .iter()
        .map(|validator| validator.operator_address.clone())
        .collect::<Vec<_>>();
    if validator_addresses.is_empty() {
        return Err("canonical Testnet genesis contains no validators".to_string());
    }

    for validator_address in &validator_addresses {
        ensure_local_validator_record_available(validator_address)?;
    }

    let active_validators =
        consensus_membership_validators(VALIDATOR_MANAGER.get_active_validators());
    for validator_address in &validator_addresses {
        if !active_validators
            .iter()
            .any(|validator| validator.address == *validator_address)
        {
            return Err(format!(
                "canonical Genesis validator {validator_address} is not ACTIVE after membership preload"
            ));
        }
    }

    Ok(validator_addresses.len())
}

fn normalize_expected_profile(
    config: &mut NodeConfig,
    expected_profile: Option<&'static RoleProfile>,
) -> Result<Option<&'static RoleProfile>, String> {
    if let Some(expected_profile) = expected_profile {
        if config.identity.role.trim().is_empty() {
            config.identity.role = expected_profile.role_id.to_string();
        }

        if config.role.compiled_profile.trim().is_empty() {
            config.role.compiled_profile = expected_profile.compiled_profile.to_string();
        }
    }

    let resolved = resolve_configured_role(&config.identity.role, &config.role.compiled_profile)?;
    if let (Some(expected_profile), Some(actual_profile)) = (expected_profile, resolved) {
        if actual_profile.role != expected_profile.role {
            return Err(format!(
                "This binary is bound to '{}' but the configuration resolves to '{}'",
                expected_profile.compiled_profile, actual_profile.compiled_profile
            ));
        }
    }

    Ok(resolved.or(expected_profile))
}

fn print_usage(binary_name: &str, expected_profile: Option<&RoleProfile>) {
    eprintln!("Synergy Testnet Node");
    if let Some(profile) = expected_profile {
        eprintln!(
            "Role-bound build: {} ({})",
            profile.display_name, profile.compiled_profile
        );
    } else {
        eprintln!("Multi-role build: dynamic role selection");
    }
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("    {binary_name} <SUBCOMMAND> [OPTIONS]");
    eprintln!();
    eprintln!("SUBCOMMANDS:");
    eprintln!("    init                  Initialize configuration directory");
    eprintln!("    start                 Start the node");
    eprintln!("    stop                  Stop the running node");
    eprintln!("    restart               Restart the node");
    eprintln!("    status                Check node status");
    eprintln!("    logs                  View node logs");
    eprintln!("    keygen                Generate PQC keypair with address (for control panel)");
    eprintln!("    generate-keypair      Generate a new PQC keypair");
    eprintln!("    register              Register node as validator");
    eprintln!("    sync                  Check network connectivity or sync");
    eprintln!("    create-snapshot       Create signed snapshot offline from source workspace");
    eprintln!("    verify-snapshot       Verify signed snapshot manifest and files");
    eprintln!("    list-snapshots        List signed snapshot catalog for source workspace");
    eprintln!("    preflight-upgrade     Refuse unsafe validator binary rollout from local state invariants");
    eprintln!("    self-heal-from-snapshot");
    eprintln!(
        "                          Restore a quarantined node from a verified signed snapshot"
    );
    eprintln!("    quarantine-stopped-validator");
    eprintln!(
        "                          Operator-approved quarantine marker for an already stopped stale validator"
    );
    eprintln!("    sync-from-canonical-peer");
    eprintln!(
        "                          Record verified canonical head match after snapshot restore"
    );
    eprintln!("    start-shadow-observe Start shadow observation after verified head match");
    eprintln!("    shadow-status        Report shadow observation status");
    eprintln!("    rejoin-eligibility   Report rejoin eligibility gates");
    eprintln!(
        "    request-rejoin       Request vote-only rejoin after exact QC-backed safety proofs"
    );
    eprintln!("    promote-vote-only-to-active");
    eprintln!("                          Restore proposer duties after vote-only probation");
    eprintln!("    emergency-promote-leader-stall-to-active");
    eprintln!(
        "                          Restore proposer duties after all-validator leader-stall proof"
    );
    eprintln!("    list-templates        List all available node templates");
    eprintln!("    version               Display version information");
    eprintln!();
    eprintln!("SNAPSHOT OPTIONS:");
    eprintln!(
        "    --chain-id 1266 --network-id synergy-testnet-v3 --genesis-hash {}",
        expected_genesis_hash()
    );
    eprintln!("    --source-workspace <PATH>  Source workspace for offline create/list/verify");
    eprintln!("    --source-node-majority-branch-proven");
    eprintln!("    --source-role VALIDATOR");
    eprintln!("    --snapshot-class validator-pruned|support-relayer|support-rpc|support-observer|indexer-replay|indexer-full|archive-full|archive-bootstrap");
    eprintln!("    --allowed-role <role> [--allowed-role <role> ...]");
    eprintln!("    --target-role <role>");
    eprintln!("    --manifest <PATH> [--snapshot-root <DIR>]");
    eprintln!("    --artifact <PATH> --current-binary <PATH> --rollback-binary <PATH> --validator-set <PATH> --archive-status <PATH> [--allow-derived-index-rebuild]");
    eprintln!("    --target-stopped --operator-approved-containment --quorum-majority-height <H> --quorum-majority-hash <HASH>");
    eprintln!("    --canonical-height <H> --canonical-hash <HASH> --source-qc-aegis-pqc-verified --parent-continuity-verified --state-root-matches --source-peer-not-quarantined");
    eprintln!("    --required-blocks <N>");
    eprintln!("    --common-height <H> --common-hash <HASH> --exact-common-height-match --latest-finalized-qc-aegis-pqc-verified --state-root-matches --rejoin-at-finalized-safe-boundary --cluster-marks-pending-reactivation [--operator-approved-emergency-leader-stall-recovery]");
    eprintln!();
    eprintln!("START OPTIONS:");
    eprintln!("    --node-type <TYPE>    Specify the node type (uses templates/<TYPE>.toml)");
    eprintln!("    --config <PATH>       Path to custom configuration file");
    eprintln!();
    eprintln!("LOGS OPTIONS:");
    eprintln!("    --follow, -f          Follow log output");
    eprintln!("    --lines <N>           Number of lines to show (default: 50)");
    eprintln!();
    eprintln!("EXAMPLES:");
    eprintln!("    {binary_name} start --config config/node.toml");
    eprintln!("    {binary_name} keygen --output ./keys --class 1");
    eprintln!("    {binary_name} sync --config config/node.toml --network testnet --check-only");
}

struct ActiveRoleServices {
    service_names: Vec<String>,
    keep_alive: Vec<Box<dyn Any>>,
    worker_threads: Vec<thread::JoinHandle<()>>,
}

impl ActiveRoleServices {
    fn new(profile: &RoleProfile) -> Self {
        Self {
            service_names: profile
                .service_surface
                .iter()
                .map(|value| value.to_string())
                .collect(),
            keep_alive: Vec::new(),
            worker_threads: Vec::new(),
        }
    }

    fn retain<T: 'static>(&mut self, value: T) {
        self.keep_alive.push(Box::new(value));
    }

    fn spawn_worker<F>(&mut self, job: F)
    where
        F: FnOnce() + Send + 'static,
    {
        self.worker_threads.push(thread::spawn(job));
    }
}

fn write_status_file(path: &Path, payload: serde_json::Value) {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(bytes) = serde_json::to_vec_pretty(&payload) {
        let _ = fs::write(path, bytes);
    }
}

fn rpc_bind_url(config: &NodeConfig) -> String {
    format!(
        "http://{}",
        normalize_rpc_client_address(&config.rpc.bind_address, config.rpc.http_port)
    )
}

fn atlas_service_envs_with_overrides(
    synergy_env: String,
    database_url: String,
    source_rpc_url: Option<String>,
    fallback_rpc_url: Option<String>,
) -> Vec<(&'static str, String)> {
    let mut envs = vec![
        ("NODE_ENV", "production".to_string()),
        ("SYNERGY_ENV", synergy_env),
        ("DATABASE_URL", database_url),
    ];

    if let Some(value) = source_rpc_url.filter(|value| !value.trim().is_empty()) {
        envs.push(("SYNERGY_CORE_RPC_URL", value));
    }

    if let Some(value) = fallback_rpc_url.filter(|value| !value.trim().is_empty()) {
        envs.push(("SYNERGY_CORE_RPC_FALLBACK_URL", value));
    }

    envs
}

fn atlas_service_envs(synergy_env: String, database_url: String) -> Vec<(&'static str, String)> {
    atlas_service_envs_with_overrides(
        synergy_env,
        database_url,
        env::var("SYNERGY_CORE_RPC_URL").ok(),
        env::var("SYNERGY_CORE_RPC_FALLBACK_URL").ok(),
    )
}

fn ensure_logs_dir() -> PathBuf {
    let logs_dir = PathBuf::from("data").join("logs");
    let _ = fs::create_dir_all(&logs_dir);
    logs_dir
}

fn spawn_node_process(
    name: &str,
    working_dir: &Path,
    script: &Path,
    envs: &[(&str, String)],
) -> Result<RoleProcessGuard, String> {
    if !script.is_file() {
        return Err(format!("Missing script: {}", script.display()));
    }

    let logs_dir = ensure_logs_dir();
    let stdout_path = logs_dir.join(format!("{name}.out"));
    let stderr_path = logs_dir.join(format!("{name}.err"));
    let stdout = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(stdout_path)
        .map_err(|error| format!("Failed to open {name} stdout log: {error}"))?;
    let stderr = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(stderr_path)
        .map_err(|error| format!("Failed to open {name} stderr log: {error}"))?;

    let mut command = Command::new("node");
    command
        .arg(script)
        .current_dir(working_dir)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));

    for (key, value) in envs {
        command.env(key, value);
    }

    let child = command
        .spawn()
        .map_err(|error| format!("Failed to start {name}: {error}"))?;
    Ok(RoleProcessGuard::new(child))
}

fn run_node_script(
    name: &str,
    working_dir: &Path,
    script: &Path,
    envs: &[(&str, String)],
) -> Result<(), String> {
    if !script.is_file() {
        return Err(format!("Missing script: {}", script.display()));
    }

    let mut command = Command::new("node");
    command.arg(script).current_dir(working_dir);
    for (key, value) in envs {
        command.env(key, value);
    }

    let status = command
        .status()
        .map_err(|error| format!("Failed to run {name}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{name} exited with status {status}"))
    }
}

fn resolve_synergy_atlas_root(runtime_root: &Path) -> Option<PathBuf> {
    let local = runtime_root.join("synergy-atlas");
    if local.exists() {
        return Some(local);
    }

    runtime_root
        .parent()
        .map(|parent| parent.join("synergy-atlas"))
        .filter(|candidate| candidate.exists())
}

fn resolve_node_entrypoint(package_root: &Path) -> Option<PathBuf> {
    let primary = package_root.join("dist").join("index.js");
    if primary.exists() {
        return Some(primary);
    }

    let nested = package_root.join("dist").join("src").join("index.js");
    if nested.exists() {
        return Some(nested);
    }

    None
}

fn infer_synergy_env(config: &NodeConfig) -> &'static str {
    let name = config.network.name.to_ascii_lowercase();
    if name.contains("testnet") {
        "testnet"
    } else {
        "mainnet"
    }
}

fn now_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn candidate_launch_block1_transaction_paths(project_root: &Path) -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    if let Ok(raw_path) = env::var("SYNERGY_BLOCK1_TRANSACTION_PATH") {
        let trimmed = raw_path.trim();
        if !trimmed.is_empty() {
            candidates.push(PathBuf::from(trimmed));
        }
    }

    candidates.push(
        project_root
            .join("config")
            .join("launch-block1-transaction.json"),
    );
    candidates.push(project_root.join("launch-block1-transaction.json"));

    let mut deduped = Vec::new();
    for candidate in candidates {
        if !deduped.contains(&candidate) {
            deduped.push(candidate);
        }
    }

    deduped
}

fn find_launch_block1_transaction_path(project_root: &Path) -> Option<PathBuf> {
    candidate_launch_block1_transaction_paths(project_root)
        .into_iter()
        .find(|candidate| candidate.is_file())
}

fn maybe_preload_launch_block1_transaction(
    project_root: &Path,
    blockchain: &Arc<Mutex<crate::block::BlockChain>>,
) -> Result<(), String> {
    let current_height = blockchain
        .lock()
        .unwrap()
        .last()
        .map(|block| block.block_index)
        .unwrap_or(0);

    if current_height != 0 {
        return Ok(());
    }

    let Some(path) = find_launch_block1_transaction_path(project_root) else {
        return Ok(());
    };

    if launch_block1_network_has_started(project_root) {
        info!(
            "main",
            "Skipping historical launch block-1 transaction envelope because the network is already past genesis",
            "path" => path.display().to_string()
        );
        return Ok(());
    }

    let contents = fs::read_to_string(&path).map_err(|error| {
        format!(
            "Failed to read launch block-1 transaction envelope {}: {}",
            path.display(),
            error
        )
    })?;
    let envelope: LaunchBlock1TransactionEnvelope =
        serde_json::from_str(&contents).map_err(|error| {
            format!(
                "Failed to parse launch block-1 transaction envelope {}: {}",
                path.display(),
                error
            )
        })?;

    let required_block_index = envelope.required_block_index.unwrap_or(1);
    if required_block_index != 1 {
        return Err(format!(
            "Launch block-1 transaction envelope {} requires block {} instead of block 1",
            path.display(),
            required_block_index
        ));
    }

    let validation = envelope.transaction.validate();
    if !validation.is_valid {
        let error_message = validation
            .error_message
            .unwrap_or_else(|| "unknown validation error".to_string());
        return Err(format!(
            "Launch block-1 transaction envelope {} failed validation: {}",
            path.display(),
            error_message
        ));
    }

    let required_balance = envelope.transaction.amount.saturating_add(
        envelope
            .transaction
            .get_total_network_fee_u64()
            .unwrap_or(u64::MAX),
    );
    let sender_balance = TOKEN_MANAGER.get_balance(&envelope.transaction.sender, "SNRG");
    if sender_balance < required_balance {
        return Err(format!(
            "Launch block-1 transaction sender {} has insufficient SNRG balance: need {}, have {}",
            envelope.transaction.sender, required_balance, sender_balance
        ));
    }

    let tx_hash = envelope.transaction.hash();
    let description = envelope
        .description
        .clone()
        .unwrap_or_else(|| "Deterministic launch transaction".to_string());
    let mut pool = TX_POOL.lock().unwrap();
    if pool.iter().any(|transaction| transaction.hash() == tx_hash) {
        info!(
            "main",
            "Launch block-1 transaction already present in local mempool",
            "path" => path.display().to_string(),
            "tx_hash" => tx_hash,
            "description" => description
        );
        return Ok(());
    }

    pool.push(envelope.transaction);
    info!(
        "main",
        "Preloaded deterministic launch block-1 transaction",
        "path" => path.display().to_string(),
        "tx_hash" => tx_hash,
        "description" => description
    );
    Ok(())
}

#[cfg(test)]
mod launch_block1_tests {
    use super::*;
    use crate::block::{Block, BlockChain};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;

    fn temp_project_root(test_name: &str) -> PathBuf {
        let unique = format!(
            "synergy-role-runtime-{test_name}-{}-{}",
            std::process::id(),
            now_ts()
        );
        let path = crate::utils::test_temp_root(unique);
        fs::create_dir_all(path.join("config")).unwrap();
        path
    }

    fn write_launch_envelope(project_root: &Path, transaction_json: &str) {
        let path = project_root
            .join("config")
            .join("launch-block1-transaction.json");
        let envelope = format!(
            r#"{{"description":"test","required_block_index":1,"transaction":{transaction_json}}}"#
        );
        fs::write(path, envelope).unwrap();
    }

    fn write_node_env(project_root: &Path, key: &str, value: &str) {
        fs::write(project_root.join("node.env"), format!("{key}={value}\n")).unwrap();
    }

    fn spawn_block_number_rpc(height: u64) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut request = [0_u8; 1024];
                let _ = stream.read(&mut request);
                let body = format!(r#"{{"jsonrpc":"2.0","result":{height},"id":1}}"#);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        format!("http://{address}")
    }

    fn signed_transaction_json(timestamp: u64) -> String {
        format!(
            r#"{{
                "sender":"synv1sender",
                "receiver":"synw1receiver",
                "amount":1,
                "nonce":0,
                "signature":[1,2,3],
                "timestamp":{timestamp},
                "gas_price":1,
                "gas_limit":21000,
                "data":null,
                "signature_algorithm":"mldsa87"
            }}"#
        )
    }

    #[test]
    fn expired_launch_block1_envelope_does_not_block_recovery() {
        let project_root = temp_project_root("expired-launch-envelope");
        write_launch_envelope(&project_root, &signed_transaction_json(1));
        let rpc_url = spawn_block_number_rpc(42);
        write_node_env(&project_root, "RPC_FALLBACK_URL", &rpc_url);
        let blockchain = Arc::new(Mutex::new(BlockChain::new()));

        let result = maybe_preload_launch_block1_transaction(&project_root, &blockchain);

        assert!(result.is_ok());
        let _ = fs::remove_dir_all(project_root);
    }

    #[test]
    fn expired_launch_block1_envelope_fails_before_network_launch() {
        let project_root = temp_project_root("expired-launch-envelope-before-launch");
        write_launch_envelope(&project_root, &signed_transaction_json(1));
        let blockchain = Arc::new(Mutex::new(BlockChain::new()));

        let result = maybe_preload_launch_block1_transaction(&project_root, &blockchain);

        assert!(result
            .unwrap_err()
            .contains("Transaction timestamp is too old"));
        let _ = fs::remove_dir_all(project_root);
    }

    #[test]
    fn malformed_launch_block1_envelope_still_fails_hard() {
        let project_root = temp_project_root("malformed-launch-envelope");
        let invalid_sender = signed_transaction_json(now_ts()).replace("synv1sender", "");
        write_launch_envelope(&project_root, &invalid_sender);
        let blockchain = Arc::new(Mutex::new(BlockChain::new()));

        let result = maybe_preload_launch_block1_transaction(&project_root, &blockchain);

        assert!(result
            .unwrap_err()
            .contains("Sender address cannot be empty"));
        let _ = fs::remove_dir_all(project_root);
    }

    #[test]
    fn launch_block1_envelope_is_ignored_after_genesis() {
        let project_root = temp_project_root("post-launch-envelope");
        write_launch_envelope(&project_root, &signed_transaction_json(1));
        let mut chain = BlockChain::new();
        chain.add_block(Block::new(
            1,
            vec![],
            "genesis".to_string(),
            "validator".to_string(),
            0,
        ));
        let blockchain = Arc::new(Mutex::new(chain));

        let result = maybe_preload_launch_block1_transaction(&project_root, &blockchain);

        assert!(result.is_ok());
        let _ = fs::remove_dir_all(project_root);
    }

    #[test]
    fn fresh_reset_marker_requires_exactly_the_canonical_genesis_block() {
        let blockchain = Arc::new(Mutex::new(BlockChain::new()));
        blockchain
            .lock()
            .expect("test shared chain lock")
            .genesis()
            .expect("canonical genesis");

        ensure_fresh_genesis_reset_state(&blockchain)
            .expect("a fresh reset may consume only canonical genesis state");
    }

    #[test]
    fn fresh_reset_marker_rejects_stale_coordinated_finality_history() {
        let project_root = temp_project_root("fresh-reset-stale-coordinated-history");
        let data_root = project_root.join("data");
        fs::create_dir_all(&data_root).expect("create isolated data root");
        let stale_finality = data_root.join("coordinated-round-robin-finality.json");
        fs::write(&stale_finality, b"stale coordinated history")
            .expect("write stale coordinated finality");

        let error = ensure_fresh_reset_has_no_consensus_history(&data_root)
            .expect_err("fresh-reset marker must reject retained coordinated finality");

        assert!(error.contains("coordinated-round-robin-finality.json"));
        let _ = fs::remove_dir_all(project_root);
    }

    #[test]
    fn fresh_reset_marker_rejects_any_nonzero_block_history() {
        let blockchain = Arc::new(Mutex::new(BlockChain::new()));
        let mut chain = blockchain.lock().expect("test shared chain lock");
        chain.genesis().expect("canonical genesis");
        let genesis = chain.last().expect("genesis block").clone();
        chain.add_block(Block::new_with_timestamp(
            1,
            Vec::new(),
            genesis.hash,
            "validator-2".to_string(),
            1,
            1,
        ));
        drop(chain);

        let error = ensure_fresh_genesis_reset_state(&blockchain)
            .expect_err("fresh-reset marker must not retain block data");
        assert!(error.contains("exactly one genesis block"));
    }
}

fn start_role_local_services(
    profile: Option<&'static RoleProfile>,
    config: &NodeConfig,
    running: &Arc<AtomicBool>,
) -> ActiveRoleServices {
    let Some(profile) = profile else {
        return ActiveRoleServices {
            service_names: vec![],
            keep_alive: vec![],
            worker_threads: vec![],
        };
    };

    let mut active = ActiveRoleServices::new(profile);

    match profile.role {
        NodeRole::Committee => {
            let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
            let entropy_beacon = Arc::new(Mutex::new(EntropyBeacon::new(Arc::clone(&pqc_manager))));
            let rotation = ValidatorRotation::new(VALIDATOR_MANAGER.clone(), entropy_beacon);
            rotation.rotate_validators();
            active.retain(pqc_manager);
            active.retain(rotation);
        }
        NodeRole::AuditValidator => {
            let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
            let synergy_calculator = Arc::new(SynergyScoreCalculator::new(
                VALIDATOR_MANAGER.clone(),
                Arc::clone(&pqc_manager),
            ));
            let cartel_engine =
                CartelDetectionEngine::new(VALIDATOR_MANAGER.clone(), synergy_calculator);
            let whistleblower = WhistleblowerSystem::new(Arc::clone(&pqc_manager));
            active.retain(pqc_manager);
            active.retain(cartel_engine);
            active.retain(whistleblower);
        }
        NodeRole::Relayer => {
            let relayer_address = if config.identity.address.trim().is_empty() {
                config.identity.node_id.clone()
            } else {
                config.identity.address.clone()
            };
            let public_key = relayer_address.clone();
            let _ = sxcp::register_relayer(&relayer_address, &public_key);
            let heartbeat_address = relayer_address.clone();
            let heartbeat_running = Arc::clone(running);
            active.spawn_worker(move || {
                while heartbeat_running.load(Ordering::SeqCst) {
                    let _ = sxcp::heartbeat_relayer(&heartbeat_address);
                    thread::sleep(Duration::from_secs(30));
                }
            });
        }
        NodeRole::Oracle => {
            let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
            let synergy_calculator = Arc::new(SynergyScoreCalculator::new(
                VALIDATOR_MANAGER.clone(),
                Arc::clone(&pqc_manager),
            ));
            let oracle = SynergyOracle::new(synergy_calculator, pqc_manager);
            active.retain(oracle);
        }
        NodeRole::UmaCoordinator => {
            active.retain("uma-coordinator-service".to_string());
        }
        NodeRole::CrossChainVerifier => {
            active.retain("cross-chain-verifier-service".to_string());
        }
        NodeRole::SynqExecution => {
            active.retain("synq-execution-service".to_string());
        }
        NodeRole::AnalyticsSimulation => {
            active.retain("analytics-and-simulation-service".to_string());
        }
        NodeRole::AegisCryptography => {
            active.retain("aegis-cryptography-service".to_string());
            active.retain(PQCManager::new());
        }
        NodeRole::GovernanceAuditor | NodeRole::TreasuryController | NodeRole::SecurityCouncil => {
            let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
            let synergy_calculator = Arc::new(SynergyScoreCalculator::new(
                VALIDATOR_MANAGER.clone(),
                Arc::clone(&pqc_manager),
            ));
            let governance = DAOGovernance::new(
                VALIDATOR_MANAGER.clone(),
                synergy_calculator,
                Arc::clone(&pqc_manager),
            );
            active.retain(pqc_manager);
            active.retain(governance);
        }
        NodeRole::DataAvailability => {
            active.retain("data-availability-service".to_string());
        }
        NodeRole::RpcGateway => {
            let bind_url = rpc_bind_url(config);
            let status_path = PathBuf::from("data").join("rpc-gateway.json");
            let running = Arc::clone(running);
            active.spawn_worker(move || {
                while running.load(Ordering::SeqCst) {
                    let mut payload = json!({
                        "ok": false,
                        "timestamp": now_ts(),
                        "rpc_url": bind_url,
                        "block_number": null,
                        "sync_state": null,
                        "local_height": null,
                        "network_height": null,
                        "peer_count": null,
                        "error": null
                    });

                    if let Some(network) = p2p::get_p2p_network() {
                        let mut manager = SYNC_MANAGER.lock().unwrap();
                        manager.attach_network(Arc::clone(&network));
                        let _ = manager.discover_network_height();
                        if manager.local_height < manager.get_network_height() {
                            let _ = manager.start_sync();
                        }

                        payload["ok"] = json!(true);
                        payload["sync_state"] = json!(format!("{:?}", manager.get_state()));
                        payload["local_height"] = json!(manager.local_height);
                        payload["network_height"] = json!(manager.get_network_height());
                        payload["block_number"] = json!(manager.local_height);
                        payload["peer_count"] = json!(manager.peers.len());
                        payload["progress_pct"] = json!(manager.get_progress_percentage());
                    } else {
                        payload["error"] = json!("p2p network unavailable");
                    }

                    write_status_file(&status_path, payload);
                    thread::sleep(Duration::from_secs(10));
                }
            });
        }
        NodeRole::IndexerExplorer => {
            let runtime_root = utils::get_runtime_root();
            let Some(runtime_root) = runtime_root else {
                eprintln!(
                    "Indexer/Explorer role requires a runtime root with config/ and bundled synergy-atlas assets."
                );
                return active;
            };

            let Some(atlas_root) = resolve_synergy_atlas_root(&runtime_root) else {
                eprintln!(
                    "Indexer/Explorer role requires synergy-atlas directory near the node runtime."
                );
                return active;
            };

            if Command::new("node").arg("--version").output().is_err() {
                eprintln!("Indexer/Explorer role requires Node.js available on PATH.");
                return active;
            }

            let database_url = match env::var("DATABASE_URL") {
                Ok(value) => value,
                Err(_) => {
                    eprintln!("Indexer/Explorer role requires DATABASE_URL for Postgres.");
                    return active;
                }
            };

            let synergy_env = infer_synergy_env(config).to_string();
            let indexer_dir = atlas_root.join("indexer");
            let backend_dir = atlas_root.join("backend");
            let Some(indexer_script) = resolve_node_entrypoint(&indexer_dir) else {
                eprintln!("Indexer/Explorer role could not find an Atlas indexer entrypoint.");
                return active;
            };
            let Some(backend_script) = resolve_node_entrypoint(&backend_dir) else {
                eprintln!("Indexer/Explorer role could not find an Atlas backend entrypoint.");
                return active;
            };
            let indexer_migrate = indexer_dir.join("scripts").join("migrate.js");
            let backend_migrate = backend_dir.join("scripts").join("migrate.js");

            // Atlas defaults to the canonical public core RPC for the current
            // environment. Preserve only explicit overrides; do not force the
            // local explorer node RPC, because its synced block store does not
            // guarantee authoritative wallet/stake query state.
            let base_envs = atlas_service_envs(synergy_env, database_url);

            if let Err(error) = run_node_script(
                "atlas-indexer-migrate",
                &indexer_dir,
                &indexer_migrate,
                &base_envs,
            ) {
                eprintln!("Failed to run indexer migrations: {error}");
                return active;
            }

            if let Err(error) = run_node_script(
                "atlas-backend-migrate",
                &backend_dir,
                &backend_migrate,
                &base_envs,
            ) {
                eprintln!("Failed to run explorer backend migrations: {error}");
                return active;
            }

            match spawn_node_process("atlas-indexer", &indexer_dir, &indexer_script, &base_envs) {
                Ok(guard) => active.retain(guard),
                Err(error) => eprintln!("Failed to start indexer: {error}"),
            }

            match spawn_node_process("atlas-backend", &backend_dir, &backend_script, &base_envs) {
                Ok(guard) => active.retain(guard),
                Err(error) => eprintln!("Failed to start explorer backend: {error}"),
            }
        }
        NodeRole::ObserverLight => {
            let status_path = PathBuf::from("data").join("observer-light.json");
            let running = Arc::clone(running);
            active.spawn_worker(move || {
                while running.load(Ordering::SeqCst) {
                    let mut payload = json!({
                        "ok": false,
                        "timestamp": now_ts(),
                        "error": "p2p network unavailable"
                    });

                    if let Some(network) = p2p::get_p2p_network() {
                        let mut manager = SYNC_MANAGER.lock().unwrap();
                        manager.attach_network(Arc::clone(&network));
                        let _ = manager.discover_network_height();
                        if manager.local_height < manager.get_network_height() {
                            let _ = manager.start_sync();
                        }

                        payload = json!({
                            "ok": true,
                            "timestamp": now_ts(),
                            "state": format!("{:?}", manager.get_state()),
                            "local_height": manager.local_height,
                            "network_height": manager.get_network_height(),
                            "sync_start_height": manager.get_sync_start_height(),
                            "progress_pct": manager.get_progress_percentage(),
                            "peer_count": manager.peers.len()
                        });
                    }

                    write_status_file(&status_path, payload);
                    thread::sleep(Duration::from_secs(15));
                }
            });
        }
        _ => {}
    }

    active
}

fn write_role_runtime_report(
    binary_name: &str,
    config: &NodeConfig,
    profile: Option<&RoleProfile>,
    p2p_enabled: bool,
    rpc_enabled: bool,
    consensus_enabled: bool,
    active_services: &ActiveRoleServices,
) {
    let report_dir = PathBuf::from("data");
    if fs::create_dir_all(&report_dir).is_err() {
        return;
    }

    let report = json!({
        "binary": binary_name,
        "generated_at": now_ts(),
        "node_id": config.identity.node_id,
        "role_id": profile.map(|value| value.role_id),
        "compiled_profile": profile.map(|value| value.compiled_profile),
        "authority_plane": profile.map(|value| format!("{:?}", value.authority_plane)),
        "service_surface": active_services.service_names,
        "p2p_enabled": p2p_enabled,
        "rpc_enabled": rpc_enabled,
        "consensus_enabled": consensus_enabled,
        "bootstrap_only": config.node.bootstrap_only,
        "ports": {
            "p2p": config.network.p2p_port,
            "rpc": config.network.rpc_port,
            "ws": config.network.ws_port,
        },
    });

    let report_path = report_dir.join("role-runtime.json");
    if let Ok(bytes) = serde_json::to_vec_pretty(&report) {
        let _ = fs::write(report_path, bytes);
    }
}

pub fn run(binary_name: &'static str, expected_profile: Option<&'static RoleProfile>) {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage(binary_name, expected_profile);
        process::exit(1);
    }

    let subcommand = &args[1];
    match run_offline_snapshot_command_isolated(&args, subcommand) {
        Ok(true) => return,
        Ok(false) => {}
        Err(error) => {
            eprintln!("{subcommand} failed closed: {error}");
            process::exit(1);
        }
    }

    match subcommand.as_str() {
        "init" => {
            let config_dir = PathBuf::from("config");
            if !config_dir.exists() {
                fs::create_dir_all(&config_dir).expect("Failed to create config directory");
                println!("Created config directory.");
            } else {
                println!("Config directory already exists.");
            }
        }
        "start" => {
            let mut node_type: Option<String> = None;
            let mut config_path: Option<String> = None;

            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--node-type" => {
                        if i + 1 < args.len() {
                            node_type = Some(args[i + 1].clone());
                            i += 2;
                        } else {
                            eprintln!("Error: --node-type requires a value");
                            process::exit(1);
                        }
                    }
                    "--config" => {
                        if i + 1 < args.len() {
                            config_path = Some(args[i + 1].clone());
                            i += 2;
                        } else {
                            eprintln!("Error: --config requires a value");
                            process::exit(1);
                        }
                    }
                    _ => {
                        eprintln!("Error: Unknown option '{}'", args[i]);
                        print_usage(binary_name, expected_profile);
                        process::exit(1);
                    }
                }
            }

            let effective_config_path = config_path
                .as_deref()
                .map(PathBuf::from)
                .or_else(|| env::var("SYNERGY_CONFIG_PATH").ok().map(PathBuf::from))
                .unwrap_or_else(|| PathBuf::from("config/node.toml"));
            let mut config = if let Some(path) = config_path {
                match load_node_config(Some(&path)) {
                    Ok(config) => config,
                    Err(e) => {
                        eprintln!("Failed to load configuration from '{}': {}", path, e);
                        process::exit(1);
                    }
                }
            } else if let Some(node_type_val) = node_type {
                match load_node_config_from_template(&node_type_val) {
                    Ok(config) => {
                        println!(
                            "Loading node configuration from template: {}",
                            node_type_val
                        );
                        config
                    }
                    Err(e) => {
                        eprintln!("Failed to load template '{}': {}", node_type_val, e);
                        eprintln!(
                            "\nRun '{binary_name} list-templates' to see available templates."
                        );
                        process::exit(1);
                    }
                }
            } else {
                match load_node_config(None) {
                    Ok(config) => config,
                    Err(e) => {
                        eprintln!("Failed to load configuration: {}", e);
                        eprintln!("\nTip: Use --node-type <TYPE> to specify a node type");
                        eprintln!("     or --config <PATH> to specify a custom config file");
                        process::exit(1);
                    }
                }
            };

            let role_profile = match normalize_expected_profile(&mut config, expected_profile) {
                Ok(profile) => profile,
                Err(error) => {
                    eprintln!("Failed to validate node role/profile binding: {error}");
                    process::exit(1);
                }
            };
            let desired_role_profile = role_profile.unwrap_or_else(|| {
                eprintln!(
                    "Failed to validate Chain 1266 desired state: node role/profile is unresolved"
                );
                process::exit(1);
            });
            // Startup dispatch is anchored on the canonical Genesis, never on
            // local configuration or environment variables. Incarnation 4 with
            // coordinated_round_robin_v1 keeps the unchanged legacy V1
            // verifier; incarnation 5 with single_authority_v1 is governed
            // exclusively by the ML-DSA-87 signed DesiredStateV2 and must never
            // invoke or accept V1.
            let release_id = resolve_chain1266_startup_release_id(
                &config,
                desired_role_profile,
                &effective_config_path,
            )
            .unwrap_or_else(|error| {
                eprintln!("Failed to validate Chain 1266 desired state: {error}");
                process::exit(1);
            });

            raise_runtime_nofile_limit(8192);

            let log_level = LogLevel::from_str(&config.logging.log_level).unwrap_or(LogLevel::Info);
            init_logger(
                log_level,
                config.logging.enable_console,
                config.logging.log_file.clone(),
                config.logging.max_file_size,
                config.logging.max_files,
            );

            info!("main", "Synergy testnet node starting...");
            info!(
                "main",
                "Configuration loaded successfully",
                "network" => config.network.name.clone(),
                "consensus" => config.consensus.algorithm.clone()
            );
            info!(
                "main",
                "Validated role-bound runtime profile and desired state",
                "role_id" => desired_role_profile.role_id,
                "compiled_profile" => desired_role_profile.compiled_profile,
                "authority_plane" => format!("{:?}", desired_role_profile.authority_plane),
                "binary" => binary_name,
                "release_id" => release_id
            );

            env::set_var(
                "SYNERGY_CONSENSUS_BLOCK_TIME_SECS",
                config.consensus.block_time_secs.to_string(),
            );
            env::set_var(
                "SYNERGY_CONSENSUS_EPOCH_LENGTH",
                config.consensus.epoch_length.to_string(),
            );
            env::set_var(
                "SYNERGY_CONSENSUS_MIN_VALIDATORS",
                config.consensus.min_validators.to_string(),
            );
            env::set_var("SYNERGY_NODE_ROLE_ID", config.identity.role.clone());
            env::set_var(
                "SYNERGY_COMPILED_PROFILE",
                config.role.compiled_profile.clone(),
            );

            let project_root = utils::validate_project_root().unwrap_or_else(|e| {
                eprintln!("Failed to determine writable project root: {}", e);
                process::exit(1);
            });
            env::set_var("SYNERGY_PROJECT_ROOT", &project_root);

            let data_dir = project_root.join("data");
            let logs_dir = data_dir.join("logs");
            let chain_dir = data_dir.join("chain");

            info!(
                "main",
                "Project root validated",
                "root" => project_root.display().to_string()
            );

            std::fs::create_dir_all(&data_dir).expect("Failed to create data directory");
            std::fs::create_dir_all(&logs_dir).expect("Failed to create logs directory");
            std::fs::create_dir_all(&chain_dir).expect("Failed to create chain directory");

            let genesis = canonical_genesis().unwrap_or_else(|error| {
                eprintln!("Failed to load canonical genesis: {}", error);
                process::exit(1);
            });
            ensure_node_config_matches_finalized_consensus_parameters(&config, genesis)
                .unwrap_or_else(|error| {
                    eprintln!(
                        "Node configuration rejected by finalized consensus parameters: {error}"
                    );
                    process::exit(1);
                });
            // Genesis validators must be present in the in-memory canonical
            // registry before P2P constructs its typed PoSy handshake.  The
            // handshake proves possession of the Genesis-assigned ML-DSA-65
            // key and therefore cannot bootstrap registration itself.
            //
            // Without this ordering, every Genesis validator starts with an
            // empty process-local registry, rejects every peer as
            // "validator ... is not registered", and then waits forever for
            // state sync from peers it cannot authenticate.
            if is_validator_profile(role_profile) && !config.node.bootstrap_only {
                let validator_address = resolve_local_validator_address(&config);
                let active_validator_count = ensure_genesis_validator_membership_available()
                    .unwrap_or_else(|error| {
                        eprintln!("Validator Genesis membership preflight failed closed: {error}");
                        process::exit(1);
                    });
                info!(
                    "main",
                    "Canonical Genesis validator membership loaded before P2P",
                    "validator_address" => validator_address,
                    "active_validator_count" => active_validator_count as u64
                );
            }
            info!(
                "main",
                "Canonical genesis loaded",
                "path" => genesis.path().display().to_string(),
                "hash" => genesis.hash().to_string()
            );
            let blockchain = Arc::clone(&SHARED_CHAIN);

            wallet::init_testnet_wallets();
            {
                let token_manager = TOKEN_MANAGER.clone();
                let token_state_path = crate::token::token_state_path();
                let token_state_loaded = match token_manager.load_state(&token_state_path) {
                    Ok(_) => true,
                    Err(e) => {
                        info!(
                            "main",
                            "No saved token state found (using genesis allocations)",
                            "error" => e.to_string()
                        );
                        false
                    }
                };
                let dag_state_loaded = crate::dag::DagState::load_from_default_path().is_some();
                let chain_snapshot = if token_state_loaded && dag_state_loaded {
                    None
                } else {
                    let chain_guard = blockchain.lock().unwrap();
                    Some(chain_guard.clone())
                };

                if dag_state_loaded {
                    info!(
                        "main",
                        "Loaded saved DAG state; skipping full chain DAG rebuild"
                    );
                } else if let Some(chain_snapshot) = chain_snapshot.as_ref() {
                    crate::dag::rebuild_global_from_chain(chain_snapshot);
                }

                if token_state_loaded {
                    info!(
                        "main",
                        "Loaded saved token state; skipping full chain token replay"
                    );
                } else if let Some(chain_snapshot) = chain_snapshot.as_ref() {
                    let (replayed, replay_failed) =
                        token_manager.replay_chain_transactions(chain_snapshot);
                    if replayed > 0 || replay_failed > 0 {
                        info!(
                            "main",
                            "Replayed chain transactions into token state",
                            "replayed" => replayed,
                            "failed" => replay_failed
                        );
                        if let Err(e) = token_manager.save_state(&token_state_path) {
                            warn!(
                                "main",
                                "Failed to persist replayed token state",
                                "error" => e.to_string()
                            );
                        }
                    }
                }
                if let Err(e) = token_manager.ensure_rewards_pool_funded() {
                    eprintln!("Warning: Failed to initialize rewards pool: {}", e);
                }
            }

            if let Err(error) = maybe_preload_launch_block1_transaction(&project_root, &blockchain)
            {
                eprintln!(
                    "Failed to preload deterministic launch block-1 transaction: {}",
                    error
                );
                process::exit(1);
            }

            info!("main", "Starting the node...");

            let pid = std::process::id();
            let pid_path = crate::utils::resolve_data_path("data/synergy-testnet.pid");
            if let Err(e) = fs::write(&pid_path, pid.to_string()) {
                eprintln!("Warning: Failed to write PID file: {}", e);
            }

            let process_start_time = SystemTime::now();
            let consensus_enabled = should_start_consensus(&config, role_profile);
            let coordinated_mode_selected = matches!(
                config
                    .consensus
                    .resolve_mode(config.blockchain.chain_id, &config.network.network_id),
                Ok(ResolvedConsensusMode::CoordinatedRoundRobinV1(_))
            );
            if consensus_enabled && is_validator_profile(role_profile) && !coordinated_mode_selected
            {
                begin_typed_consensus_startup_buffer(TYPED_POSY_INGRESS_CAPACITY)
                    .unwrap_or_else(|error| {
                        eprintln!(
                            "Consensus startup failed closed before P2P listener activation: {error}"
                        );
                        process::exit(1);
                    });
                set_typed_consensus_startup_phase("BUFFERING_AUTHENTICATED_P2P");
            }

            let p2p_enabled = should_start_p2p(&config, role_profile);
            let typed_finality_observer_enabled =
                should_start_typed_finality_observer(&config, role_profile);
            let coordinated_finality_observer_enabled =
                should_start_coordinated_finality_observer(&config, role_profile);
            if (typed_finality_observer_enabled || coordinated_finality_observer_enabled)
                && !p2p_enabled
            {
                eprintln!(
                    "Service startup failed closed: finalized-only observer roles require active P2P"
                );
                process::exit(1);
            }
            if typed_finality_observer_enabled {
                let observer = TypedFinalityObserver::from_canonical_finalized_genesis()
                    .unwrap_or_else(|error| {
                        eprintln!(
                            "Service startup failed closed: cannot initialize verified typed finality observer: {error}"
                        );
                        process::exit(1);
                    });
                install_typed_finality_observer(observer).unwrap_or_else(|error| {
                    eprintln!(
                        "Service startup failed closed: cannot install typed finality observer ingress: {error}"
                    );
                    process::exit(1);
                });
            }
            if coordinated_finality_observer_enabled {
                let coordinated_config = match config
                    .consensus
                    .resolve_mode(config.blockchain.chain_id, &config.network.network_id)
                {
                    Ok(ResolvedConsensusMode::CoordinatedRoundRobinV1(coordinated_config)) => {
                        coordinated_config
                    }
                    Ok(ResolvedConsensusMode::PosyV2_2)
                    | Ok(ResolvedConsensusMode::SingleAuthorityV1)
                    | Err(_) => {
                        eprintln!(
                            "Service startup failed closed: coordinated finality observer selected without a valid P1 configuration"
                        );
                        process::exit(1);
                    }
                };
                let observer = coordinated_finality_observer_from_canonical_finalized_genesis(
                    coordinated_config,
                )
                .unwrap_or_else(|error| {
                    eprintln!(
                        "Service startup failed closed: cannot initialize verified coordinated finality observer: {error}"
                    );
                    process::exit(1);
                });
                install_coordinated_finality_observer(observer).unwrap_or_else(|error| {
                    eprintln!(
                        "Service startup failed closed: cannot install coordinated finality observer ingress: {error}"
                    );
                    process::exit(1);
                });
            }
            let p2p_network = if p2p_enabled {
                let network = p2p::start_p2p_network(
                    Arc::clone(&blockchain),
                    &config.p2p.listen_address,
                    &config,
                );
                info!(
                    "main",
                    "P2P network started",
                    "listen_address" => config.p2p.listen_address.clone()
                );
                Some(network)
            } else {
                info!(
                    "main",
                    "P2P network disabled for this node profile",
                    "role" => config.identity.role.clone()
                );
                None
            };

            let rpc_enabled = should_start_rpc(&config, role_profile);
            if rpc_enabled {
                let rpc_bind_address =
                    normalize_rpc_socket_address(&config.rpc.bind_address, config.rpc.http_port);
                let ws_bind_address = if config.rpc.enable_ws {
                    Some(rebind_socket_address(&rpc_bind_address, config.rpc.ws_port))
                } else {
                    None
                };
                let cors_enabled = config.rpc.cors_enabled;
                let cors_origins = config.rpc.cors_origins.clone();
                let _rpc_handle = std::thread::spawn(move || {
                    rpc::rpc_server::start_rpc_server(
                        &rpc_bind_address,
                        ws_bind_address,
                        cors_enabled,
                        cors_origins,
                    );
                });

                // Wait until the RPC listener is actually accepting connections before
                // allowing the consensus engine to start.  This prevents a race where
                // the consensus engine (or the desktop app) tries to reach the RPC
                // endpoint before it has finished binding, producing "fetch failed" errors.
                let rpc_port = config.rpc.http_port;
                let rpc_ready_addr = format!("127.0.0.1:{}", rpc_port);
                let rpc_ready_deadline = std::time::Instant::now() + Duration::from_secs(10);
                loop {
                    if std::net::TcpStream::connect(&rpc_ready_addr).is_ok() {
                        info!("main", "RPC server ready", "port" => rpc_port);
                        break;
                    }
                    if std::time::Instant::now() >= rpc_ready_deadline {
                        eprintln!(
                            "Warning: RPC server did not become ready within 10 s on port {}; proceeding anyway",
                            rpc_port
                        );
                        break;
                    }
                    thread::sleep(Duration::from_millis(50));
                }
            } else {
                info!(
                    "main",
                    "RPC server disabled for this node profile",
                    "bootstrap_only" => config.node.bootstrap_only,
                    "enable_http" => config.rpc.enable_http,
                    "enable_ws" => config.rpc.enable_ws,
                    "enable_grpc" => config.rpc.enable_grpc
                );
            }

            let support_sources_only = refresh_sync_source_policy(&config, role_profile);
            info!(
                "main",
                "Configured local sync source policy",
                "support_sources_only" => support_sources_only,
                "validator_profile" => is_validator_profile(role_profile)
            );

            let metrics_enabled = should_start_metrics(&config);
            if metrics_enabled {
                let metrics_bind_address =
                    normalize_socket_address(&config.telemetry.metrics_bind, 6030);
                let metrics_ready_addr =
                    normalize_client_address(&config.telemetry.metrics_bind, 6030);
                let metrics_config = config.clone();
                let _metrics_handle = std::thread::spawn(move || {
                    telemetry::start_metrics_server(
                        &metrics_bind_address,
                        metrics_config,
                        process_start_time,
                    );
                });

                let metrics_ready_deadline = std::time::Instant::now() + Duration::from_secs(5);
                loop {
                    if std::net::TcpStream::connect(&metrics_ready_addr).is_ok() {
                        info!("main", "Metrics server ready", "bind_address" => metrics_ready_addr.clone());
                        break;
                    }
                    if std::time::Instant::now() >= metrics_ready_deadline {
                        eprintln!(
                            "Warning: metrics server did not become ready within 5 s on {}; proceeding anyway",
                            metrics_ready_addr
                        );
                        break;
                    }
                    thread::sleep(Duration::from_millis(50));
                }
            } else {
                info!(
                    "main",
                    "Metrics server disabled",
                    "enabled" => config.telemetry.enabled,
                    "metrics_bind" => config.telemetry.metrics_bind.clone()
                );
            }

            info!(
                "main",
                "Node initialized",
                "bootstrap_only" => config.node.bootstrap_only,
                "rpc_enabled" => rpc_enabled,
                "p2p_enabled" => p2p_enabled,
                "metrics_enabled" => metrics_enabled,
                "rpc_port" => config.rpc.http_port,
                "metrics_bind" => config.telemetry.metrics_bind.clone(),
                "p2p_address" => config.p2p.listen_address.clone(),
                "consensus" => config.consensus.algorithm.clone()
            );

            let reset_flag_path = crate::utils::resolve_data_path("data/.reset_flag");
            let should_sync = !reset_flag_path.exists();
            let sync_required_before_join =
                should_require_state_sync_before_join(&config, role_profile);

            if coordinated_mode_selected && consensus_enabled && is_validator_profile(role_profile)
            {
                if should_sync {
                    info!(
                        "main",
                        "Skipping generic legacy sync for coordinated consensus; the signed coordinated finality store is the only recovery authority"
                    );
                } else {
                    ensure_fresh_genesis_reset_state(&blockchain).unwrap_or_else(|error| {
                        eprintln!(
                            "Fresh-genesis reset failed closed before coordinated consensus startup: {error}"
                        );
                        process::exit(1);
                    });
                    std::fs::remove_file(&reset_flag_path).ok();
                    info!(
                        "main",
                        "Starting coordinated consensus from the verified block-0 Genesis reset",
                        "height" => 0
                    );
                }
            } else if !should_start_sync(&config, role_profile) {
                info!("main", "Chain sync disabled for this node profile");
            } else if should_sync {
                let mut sync_attempt = 1_u64;
                loop {
                    let sync_result = {
                        let mut manager = SYNC_MANAGER.lock().unwrap();
                        if let Some(network) = &p2p_network {
                            manager.attach_network(Arc::clone(network));
                        }
                        manager.start_sync()
                    };
                    match sync_result {
                        Ok(_) => {
                            let current_height = blockchain
                                .lock()
                                .unwrap()
                                .last()
                                .map(|b| b.block_index)
                                .unwrap_or(0);
                            info!("main", "Sync complete", "height" => current_height);
                            break;
                        }
                        Err(err) if sync_required_before_join => {
                            let retry_delay_secs = std::cmp::min(30, sync_attempt * 5);
                            eprintln!(
                                "State sync before validator join failed on attempt {}; retrying in {} s: {}",
                                sync_attempt, retry_delay_secs, err
                            );
                            info!(
                                "main",
                                "State sync before validator join is required; delaying self-registration and consensus",
                                "attempt" => sync_attempt,
                                "retry_delay_secs" => retry_delay_secs
                            );
                            thread::sleep(Duration::from_secs(retry_delay_secs));
                            sync_attempt = sync_attempt.saturating_add(1);
                        }
                        Err(err) => {
                            eprintln!("Warning: Sync failed before consensus: {}", err);
                            break;
                        }
                    }
                }
            } else {
                ensure_fresh_genesis_reset_state(&blockchain).unwrap_or_else(|error| {
                    eprintln!(
                        "Fresh-genesis reset failed closed before consensus startup: {error}"
                    );
                    process::exit(1);
                });
                std::fs::remove_file(&reset_flag_path).ok();
                info!(
                    "main",
                    "Starting fresh after reset - skipping network sync",
                    "height" => 0
                );
            }

            if should_auto_register_validator(&config, role_profile) {
                let validator_address = resolve_local_validator_address(&config);
                if !is_validator_allowed(&config, &validator_address) {
                    info!(
                        "main",
                        "Skipping self-registration because validator is not in allowlist",
                        "validator_address" => validator_address.clone()
                    );
                } else {
                    let validator_manager = VALIDATOR_MANAGER.clone();
                    let is_registered = validator_manager
                        .get_validator(&validator_address)
                        .is_some();
                    let is_pending = validator_manager.is_pending(&validator_address);

                    if !is_registered && !is_pending {
                        info!(
                            "main",
                            "Validator self-registration requires the explicit funding and activation workflow",
                            "address" => validator_address.clone(),
                            "required_stake_snrg" => 50_000u64
                        );
                    }
                }
            } else {
                info!(
                    "main",
                    "Auto validator registration disabled for this node profile"
                );
            }

            // The consensus worker and every role-local worker share this one
            // shutdown signal. A consensus failure clears it before any
            // legacy path could be considered, and the role loop exits.
            let running = Arc::new(AtomicBool::new(true));
            // The signed activation decides the protocol before any
            // protocol-specific preflight or announcement runs.
            let signed_consensus_startup = consensus_enabled
                .then(|| resolve_installed_signed_consensus_startup(&config))
                .flatten();
            let signed_single_authority = matches!(
                signed_consensus_startup,
                Some(Ok(VerifiedConsensusStartup::SingleAuthority(_)))
            );
            if consensus_enabled && !signed_single_authority {
                announce_chain1266_coordinated_runtime(&config).unwrap_or_else(|error| {
                    eprintln!("Consensus startup failed closed: {error}");
                    process::exit(1);
                });
            }
            let initial_consensus_startup = select_finalized_consensus_driver_startup(
                consensus_enabled,
                p2p_network.is_some(),
                (consensus_enabled && !signed_single_authority)
                    .then(|| resolved_consensus_runtime_preflight(&config)),
                signed_consensus_startup,
            );
            let mut consensus_worker = match initial_consensus_startup {
                Ok(FinalizedConsensusDriverStartup::Disabled) => {
                    info!(
                        "main",
                        "Consensus engine disabled for this node profile",
                        "bootstrap_only" => config.node.bootstrap_only,
                        "role" => config.identity.role.clone(),
                        "validator_address" => resolve_local_validator_address(&config)
                    );
                    None
                }
                Ok(FinalizedConsensusDriverStartup::SpawnCoordinatedRoundRobinDriver) => {
                    info!(
                        "main",
                        "Starting coordinated round-robin consensus worker",
                        "algorithm" => config.consensus.algorithm.clone()
                    );
                    let network = match p2p_network.as_ref().cloned() {
                        Some(network) => network,
                        None => {
                            eprintln!(
                                "Consensus startup failed closed: coordinated round-robin requires an active P2P network"
                            );
                            process::exit(1);
                        }
                    };
                    match spawn_coordinated_round_robin_driver(
                        &config,
                        network,
                        Arc::clone(&running),
                    ) {
                        Ok(worker) => Some(FinalizedConsensusWorker::CoordinatedRoundRobin(worker)),
                        Err(error) => {
                            eprintln!("Consensus startup failed closed: {error}");
                            process::exit(1);
                        }
                    }
                }
                Ok(FinalizedConsensusDriverStartup::SpawnSingleAuthorityDriver(plan)) => {
                    info!(
                        "main",
                        "Starting single-authority consensus worker",
                        "protocol" => "single_authority_v1",
                        "authority_id" => plan.authority_id.clone(),
                        "chain_incarnation" => plan.chain_incarnation,
                        "target_block_time_ms" => plan.target_block_time_ms
                    );
                    // No network handle, no ingress, no peers.
                    match spawn_single_authority_driver(&config, &plan, Arc::clone(&running)) {
                        Ok(worker) => Some(FinalizedConsensusWorker::SingleAuthority(worker)),
                        Err(error) => {
                            eprintln!("Consensus startup failed closed: {error}");
                            process::exit(1);
                        }
                    }
                }
                Err(error) => {
                    eprintln!("Consensus startup failed closed: {error}");
                    process::exit(1);
                }
            };
            let watch_for_activation_consensus = should_watch_for_validator_activation_consensus(
                &config,
                role_profile,
                consensus_enabled,
            );

            let role_services = start_role_local_services(role_profile, &config, &running);
            write_role_runtime_report(
                binary_name,
                &config,
                role_profile,
                p2p_enabled,
                rpc_enabled,
                consensus_enabled,
                &role_services,
            );

            info!("main", "Node is running. Press Ctrl+C to stop.");

            let shutdown_flag = Arc::clone(&running);
            ctrlc::set_handler(move || {
                println!("\nReceived shutdown signal...");
                shutdown_flag.store(false, Ordering::SeqCst);
            })
            .expect("Error setting Ctrl-C handler");

            while running.load(Ordering::SeqCst) {
                refresh_sync_source_policy(&config, role_profile);
                if let Some(worker) = consensus_worker.as_ref() {
                    if let Some(error) = worker.fatal_error() {
                        eprintln!("Finalized consensus worker failed closed: {error}");
                        running.store(false, Ordering::SeqCst);
                        continue;
                    }
                }
                if consensus_worker.is_none()
                    && watch_for_activation_consensus
                    && local_validator_is_consensus_authorized(&config)
                {
                    info!(
                        "main",
                        "Validator activation observed; starting finalized consensus worker",
                        "validator_address" => resolve_local_validator_address(&config)
                    );
                    let activation_signed_startup =
                        resolve_installed_signed_consensus_startup(&config);
                    let activation_single_authority = matches!(
                        activation_signed_startup,
                        Some(Ok(VerifiedConsensusStartup::SingleAuthority(_)))
                    );
                    match select_finalized_consensus_driver_startup(
                        true,
                        p2p_network.is_some(),
                        (!activation_single_authority)
                            .then(|| resolved_consensus_runtime_preflight(&config)),
                        activation_signed_startup,
                    ) {
                        Ok(FinalizedConsensusDriverStartup::SpawnSingleAuthorityDriver(plan)) => {
                            consensus_worker =
                                match spawn_single_authority_driver(
                                    &config,
                                    &plan,
                                    Arc::clone(&running),
                                ) {
                                    Ok(worker) => {
                                        Some(FinalizedConsensusWorker::SingleAuthority(worker))
                                    }
                                    Err(error) => {
                                        eprintln!("Consensus activation failed closed: {error}");
                                        process::exit(1);
                                    }
                                };
                        }
                        Ok(FinalizedConsensusDriverStartup::SpawnCoordinatedRoundRobinDriver) => {
                            let network = match p2p_network.as_ref().cloned() {
                                Some(network) => network,
                                None => {
                                    eprintln!(
                                        "Consensus activation failed closed: coordinated round-robin requires an active P2P network"
                                    );
                                    process::exit(1);
                                }
                            };
                            consensus_worker = match spawn_coordinated_round_robin_driver(
                                &config,
                                network,
                                Arc::clone(&running),
                            ) {
                                Ok(worker) => {
                                    Some(FinalizedConsensusWorker::CoordinatedRoundRobin(worker))
                                }
                                Err(error) => {
                                    eprintln!("Consensus activation failed closed: {error}");
                                    process::exit(1);
                                }
                            };
                        }
                        Ok(FinalizedConsensusDriverStartup::Disabled) => {
                            eprintln!(
                                "Consensus activation failed closed: authorized validator did not select a finalized consensus worker"
                            );
                            process::exit(1);
                        }
                        Err(error) => {
                            eprintln!("Consensus activation failed closed: {error}");
                            process::exit(1);
                        }
                    }
                    refresh_sync_source_policy(&config, role_profile);
                    write_role_runtime_report(
                        binary_name,
                        &config,
                        role_profile,
                        p2p_enabled,
                        rpc_enabled,
                        true,
                        &role_services,
                    );
                }
                std::thread::sleep(Duration::from_secs(1));
            }

            for handle in role_services.worker_threads {
                let _ = handle.join();
            }

            let consensus_worker_failure = consensus_worker
                .as_ref()
                .and_then(FinalizedConsensusWorker::fatal_error);
            if let Some(consensus_worker) = consensus_worker {
                consensus_worker.join();
            }
            if typed_finality_observer_enabled {
                if let Err(error) = remove_typed_finality_observer() {
                    warn!(
                        "main",
                        "Could not remove typed finality observer ingress during shutdown",
                        "error" => error
                    );
                }
            }
            if coordinated_finality_observer_enabled {
                if let Err(error) = remove_coordinated_finality_observer() {
                    warn!(
                        "main",
                        "Could not remove coordinated finality observer ingress during shutdown",
                        "error" => error
                    );
                }
            }
            fs::remove_file(&pid_path).ok();
            if let Some(error) = consensus_worker_failure {
                eprintln!("Finalized consensus worker failed closed: {error}");
                process::exit(1);
            }
            info!("main", "Node shutdown gracefully");
        }
        "keygen" | "generate-keypair" => {
            use crate::address::generate_class_based_address;
            use base64::{engine::general_purpose, Engine as _};
            use pqcrypto_falcon::falcon1024;
            use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};

            let mut output_dir: Option<PathBuf> = None;
            let mut node_class: Option<u8> = None;

            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--output" => {
                        if i + 1 < args.len() {
                            output_dir = Some(PathBuf::from(&args[i + 1]));
                            i += 2;
                        } else {
                            eprintln!("Error: --output requires a path");
                            process::exit(1);
                        }
                    }
                    "--class" => {
                        if i + 1 < args.len() {
                            node_class = args[i + 1].parse().ok();
                            if node_class.is_none()
                                || node_class.unwrap() < 1
                                || node_class.unwrap() > 5
                            {
                                eprintln!("Error: --class must be a number between 1 and 5");
                                process::exit(1);
                            }
                            i += 2;
                        } else {
                            eprintln!("Error: --class requires a number (1-5)");
                            process::exit(1);
                        }
                    }
                    _ => {
                        eprintln!("Error: Unknown option '{}'", args[i]);
                        process::exit(1);
                    }
                }
            }

            let (pk, sk) = falcon1024::keypair();
            let public_key_b64 = general_purpose::STANDARD.encode(pk.as_bytes());
            let private_key_b64 = general_purpose::STANDARD.encode(sk.as_bytes());

            let address = if let Some(class) = node_class {
                generate_class_based_address(pk.as_bytes(), class)
            } else {
                String::new()
            };

            if let Some(ref output_path) = output_dir {
                if let Err(e) = fs::create_dir_all(output_path) {
                    eprintln!("Failed to create output directory: {}", e);
                    process::exit(1);
                }

                let public_key_path = output_path.join("public.key");
                if let Err(e) = fs::write(&public_key_path, &public_key_b64) {
                    eprintln!("Failed to write public key: {}", e);
                    process::exit(1);
                }

                let private_key_path = output_path.join("private.key");
                if let Err(e) = fs::write(&private_key_path, &private_key_b64) {
                    eprintln!("Failed to write private key: {}", e);
                    process::exit(1);
                }
            }

            if !address.is_empty() {
                println!("{}", address);
            } else {
                eprintln!("Error: --class is required to generate an address");
                process::exit(1);
            }
        }
        "status" => {
            let config = match load_node_config(None) {
                Ok(config) => config,
                Err(e) => {
                    eprintln!("Failed to load configuration: {}", e);
                    process::exit(1);
                }
            };

            let log_level = LogLevel::from_str(&config.logging.log_level).unwrap_or(LogLevel::Info);
            init_logger(
                log_level,
                config.logging.enable_console,
                config.logging.log_file.clone(),
                config.logging.max_file_size,
                config.logging.max_files,
            );

            info!("main", "Node status: Online");
        }
        "list-templates" => {
            println!("Available Node Templates:");
            println!();
            match list_available_templates() {
                Ok(templates) => {
                    if templates.is_empty() {
                        println!("  No templates found in 'templates/' directory");
                    } else {
                        for (idx, template) in templates.iter().enumerate() {
                            println!("  {}. {}", idx + 1, template);
                        }
                        println!();
                        println!("Usage: {binary_name} start --node-type <template-name>");
                    }
                }
                Err(e) => {
                    eprintln!("Failed to list templates: {}", e);
                    process::exit(1);
                }
            }
        }
        "stop" => {
            println!("Stopping Synergy testnet node...");

            let pid_file = "data/synergy-testnet.pid";
            if !PathBuf::from(pid_file).exists() {
                eprintln!("Error: PID file not found. Is the node running?");
                process::exit(1);
            }

            match fs::read_to_string(pid_file) {
                Ok(pid_str) => match pid_str.trim().parse::<i32>() {
                    Ok(pid) => {
                        #[cfg(unix)]
                        {
                            use std::process::Command;
                            match Command::new("kill").arg(pid.to_string()).status() {
                                Ok(_) => {
                                    println!("Node stopped successfully (PID: {})", pid);
                                    fs::remove_file(pid_file).ok();
                                }
                                Err(e) => {
                                    eprintln!("Failed to stop node: {}", e);
                                    process::exit(1);
                                }
                            }
                        }
                        #[cfg(not(unix))]
                        {
                            eprintln!("Stop command is only supported on Unix systems");
                            process::exit(1);
                        }
                    }
                    Err(e) => {
                        eprintln!("Error parsing PID file: {}", e);
                        process::exit(1);
                    }
                },
                Err(e) => {
                    eprintln!("Error reading PID file: {}", e);
                    process::exit(1);
                }
            }
        }
        "restart" => {
            println!("Restarting Synergy testnet node...");

            let pid_file = "data/synergy-testnet.pid";
            if PathBuf::from(pid_file).exists() {
                println!("Stopping running node...");
                #[cfg(unix)]
                {
                    if let Ok(pid_str) = fs::read_to_string(pid_file) {
                        if let Ok(pid) = pid_str.trim().parse::<i32>() {
                            use std::process::Command;
                            Command::new("kill").arg(pid.to_string()).status().ok();
                            fs::remove_file(pid_file).ok();
                            std::thread::sleep(Duration::from_secs(2));
                        }
                    }
                }
            }

            println!("Starting node...");
            println!("Please run: {binary_name} start [OPTIONS]");
        }
        "logs" => {
            let mut follow = false;
            let mut lines = 50;

            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--follow" | "-f" => {
                        follow = true;
                        i += 1;
                    }
                    "--lines" => {
                        if i + 1 < args.len() {
                            lines = args[i + 1].parse().unwrap_or(50);
                            i += 2;
                        } else {
                            eprintln!("Error: --lines requires a value");
                            process::exit(1);
                        }
                    }
                    _ => {
                        eprintln!("Error: Unknown option '{}'", args[i]);
                        print_usage(binary_name, expected_profile);
                        process::exit(1);
                    }
                }
            }

            let log_file = "data/logs/synergy-node.log";
            if !PathBuf::from(log_file).exists() {
                eprintln!("Error: Log file not found at {}", log_file);
                process::exit(1);
            }

            if follow {
                #[cfg(unix)]
                {
                    use std::process::Command;
                    let _ = Command::new("tail")
                        .arg("-f")
                        .arg("-n")
                        .arg(lines.to_string())
                        .arg(log_file)
                        .status();
                }
                #[cfg(not(unix))]
                {
                    eprintln!("Follow mode is only supported on Unix systems");
                    process::exit(1);
                }
            } else {
                #[cfg(unix)]
                {
                    use std::process::Command;
                    let _ = Command::new("tail")
                        .arg("-n")
                        .arg(lines.to_string())
                        .arg(log_file)
                        .status();
                }
                #[cfg(not(unix))]
                {
                    match fs::read_to_string(log_file) {
                        Ok(content) => {
                            let log_lines: Vec<&str> = content.lines().collect();
                            let start = if log_lines.len() > lines {
                                log_lines.len() - lines
                            } else {
                                0
                            };
                            for line in &log_lines[start..] {
                                println!("{}", line);
                            }
                        }
                        Err(e) => {
                            eprintln!("Error reading log file: {}", e);
                            process::exit(1);
                        }
                    }
                }
            }
        }
        "register" => {
            let mut address: Option<String> = None;
            let mut key_path: Option<String> = None;

            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--config" => {
                        if i + 1 < args.len() {
                            i += 2;
                        } else {
                            eprintln!("Error: --config requires a path");
                            process::exit(1);
                        }
                    }
                    "--address" => {
                        if i + 1 < args.len() {
                            address = Some(args[i + 1].clone());
                            i += 2;
                        } else {
                            eprintln!("Error: --address requires an address");
                            process::exit(1);
                        }
                    }
                    "--key" => {
                        if i + 1 < args.len() {
                            key_path = Some(args[i + 1].clone());
                            i += 2;
                        } else {
                            eprintln!("Error: --key requires a path");
                            process::exit(1);
                        }
                    }
                    _ => {
                        eprintln!("Error: Unknown option '{}'", args[i]);
                        process::exit(1);
                    }
                }
            }

            let _ = (address, key_path);
            eprintln!(
                "Error: legacy direct validator registration is disabled on Synergy Testnet chain 1266. Use the on-chain validator activation flow: bind Aegis PQC keys, submit and finalize a 50,000 SNRG stake lock, sync/replay/shadow, then activate at a finalized epoch boundary."
            );
            process::exit(1);
        }
        "sync" => {
            let mut config_path: Option<String> = None;
            let mut network = "testnet".to_string();
            let mut check_only = false;

            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--config" => {
                        if i + 1 < args.len() {
                            config_path = Some(args[i + 1].clone());
                            i += 2;
                        } else {
                            eprintln!("Error: --config requires a path");
                            process::exit(1);
                        }
                    }
                    "--network" => {
                        if i + 1 < args.len() {
                            network = args[i + 1].clone();
                            i += 2;
                        } else {
                            eprintln!("Error: --network requires a name");
                            process::exit(1);
                        }
                    }
                    "--check-only" => {
                        check_only = true;
                        i += 1;
                    }
                    _ => {
                        eprintln!("Error: Unknown option '{}'", args[i]);
                        process::exit(1);
                    }
                }
            }

            let config = if let Some(path) = config_path {
                match load_node_config(Some(&path)) {
                    Ok(cfg) => cfg,
                    Err(e) => {
                        eprintln!("Failed to load configuration: {}", e);
                        process::exit(1);
                    }
                }
            } else {
                match load_node_config(None) {
                    Ok(cfg) => cfg,
                    Err(e) => {
                        eprintln!("Failed to load configuration: {}", e);
                        process::exit(1);
                    }
                }
            };

            println!("Starting sync runner for {}", network);

            let blockchain = Arc::clone(&SHARED_CHAIN);
            let p2p_network = p2p::start_p2p_network(
                Arc::clone(&blockchain),
                &config.p2p.listen_address,
                &config,
            );

            let mut cli_sync_manager = SyncManager::new(Arc::clone(&blockchain));
            let role_profile =
                resolve_configured_role(&config.identity.role, &config.role.compiled_profile)
                    .ok()
                    .flatten();
            cli_sync_manager.set_support_sources_only(local_sync_requires_support_sources(
                &config,
                role_profile,
            ));
            cli_sync_manager.attach_network(Arc::clone(&p2p_network));

            if check_only {
                match cli_sync_manager.discover_network_height() {
                    Ok(network_height) => {
                        let local_height = blockchain
                            .lock()
                            .unwrap()
                            .last()
                            .map(|b| b.block_index)
                            .unwrap_or(0);
                        println!(
                            "Local height: {}, network height: {}",
                            local_height, network_height
                        );
                        if local_height >= network_height {
                            println!("Node is already synced.");
                        } else {
                            println!(
                                "Node is behind by {} blocks.",
                                network_height.saturating_sub(local_height)
                            );
                        }
                    }
                    Err(err) => {
                        eprintln!("Failed to determine network height: {}", err);
                        process::exit(1);
                    }
                }
            } else {
                println!("Starting fast sync to catch up...");
                if let Err(err) = cli_sync_manager.start_sync() {
                    eprintln!("Sync error: {}", err);
                    process::exit(1);
                }
                let current_height = blockchain
                    .lock()
                    .unwrap()
                    .last()
                    .map(|b| b.block_index)
                    .unwrap_or(0);
                println!("Sync complete! Current block height: {}", current_height);
            }
        }
        "version" | "--version" | "-v" => {
            println!("Synergy Testnet Node v{}", env!("CARGO_PKG_VERSION"));
            println!("Binary: {}", binary_name);
            if let Some(profile) = expected_profile {
                println!(
                    "Profile: {} ({})",
                    profile.display_name, profile.compiled_profile
                );
            }
            println!("Build OS: {}", std::env::consts::OS);
        }
        "help" | "--help" | "-h" => {
            print_usage(binary_name, expected_profile);
        }
        _ => {
            eprintln!("Unknown subcommand: {}", subcommand);
            eprintln!();
            print_usage(binary_name, expected_profile);
            process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NodeConfig;
    use crate::genesis::load_genesis_from_path;
    use std::fs;
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    static COORDINATED_POOL_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    struct EnvRestore {
        project_root: Option<String>,
        config_path: Option<String>,
    }

    impl EnvRestore {
        fn capture() -> Self {
            Self {
                project_root: env::var("SYNERGY_PROJECT_ROOT").ok(),
                config_path: env::var("SYNERGY_CONFIG_PATH").ok(),
            }
        }
    }

    impl Drop for EnvRestore {
        fn drop(&mut self) {
            match &self.project_root {
                Some(value) => env::set_var("SYNERGY_PROJECT_ROOT", value),
                None => env::remove_var("SYNERGY_PROJECT_ROOT"),
            }
            match &self.config_path {
                Some(value) => env::set_var("SYNERGY_CONFIG_PATH", value),
                None => env::remove_var("SYNERGY_CONFIG_PATH"),
            }
        }
    }

    fn unique_test_workspace(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after UNIX epoch")
            .as_nanos();
        crate::utils::test_temp_root(format!(
            "synergy-role-runtime-{name}-{}-{nonce}",
            process::id()
        ))
    }

    #[test]
    fn production_role_runtime_cannot_start_inherited_consensus_loop() {
        let error = attempt_inherited_consensus_engine()
            .expect_err("legacy consensus must remain unreachable in production role runtime");
        assert!(error.contains("POSY_V2_2_OPERATIONAL_COORDINATOR_NOT_READY"));
        assert!(error.contains("inherited ProofOfSynergy/DualQuorumConsensus loop is disabled"));
    }

    #[test]
    fn production_role_runtime_has_no_inherited_consensus_constructor() {
        let source = include_str!("role_runtime.rs");
        let inherited_dual_quorum_constructor = ["DualQuorumConsensus", "::"].concat();
        let inherited_posy_constructor = ["ProofOfSynergy", "::new"].concat();
        let inherited_role_startup = ["spawn_consensus_engine", "("].concat();

        assert!(
            !source.contains(&inherited_dual_quorum_constructor),
            "the production role runtime must not construct the inherited DualQuorum engine"
        );
        assert!(
            !source.contains(&inherited_posy_constructor),
            "the production role runtime must not construct an inherited PoSy loop"
        );
        assert!(
            !source.contains(&inherited_role_startup),
            "the production role runtime must not retain the legacy consensus startup path"
        );
        // Built by concatenation so this assertion cannot match its own source
        // text, exactly as the three checks above do.
        let typed_dispatcher_variant =
            ["FinalizedConsensusDriverStartup", "::", "SpawnFinalizedTypedDriver"].concat();
        assert!(
            !source.contains(&typed_dispatcher_variant),
            "the production role runtime must not expose a typed PoSy dispatcher variant"
        );
        assert!(
            source.contains("spawn_coordinated_round_robin_driver("),
            "the production role runtime must retain the separate P1 coordinated-driver entry point"
        );
    }

    #[test]
    fn only_relayer_gateway_and_indexer_start_non_signing_typed_finality_observer() {
        let config = NodeConfig::default();
        assert!(should_start_typed_finality_observer(
            &config,
            Some(NodeRole::Relayer.profile())
        ));
        assert!(should_start_typed_finality_observer(
            &config,
            Some(NodeRole::RpcGateway.profile())
        ));
        assert!(should_start_typed_finality_observer(
            &config,
            Some(NodeRole::IndexerExplorer.profile())
        ));
        assert!(!should_start_typed_finality_observer(
            &config,
            Some(NodeRole::Validator.profile())
        ));
        assert!(!should_start_typed_finality_observer(
            &config,
            Some(NodeRole::ArchiveValidator.profile())
        ));
    }

    #[test]
    fn only_support_roles_start_non_signing_coordinated_finality_observer() {
        let mut config = NodeConfig::default();
        config.consensus.mode =
            crate::consensus::coordinated_round_robin::COORDINATED_ROUND_ROBIN_V1.to_string();
        config.consensus.coordinator_id = "validator-1".to_string();
        config.consensus.producer_ids = (2..=6).map(|index| format!("validator-{index}")).collect();
        assert!(should_start_coordinated_finality_observer(
            &config,
            Some(NodeRole::Relayer.profile())
        ));
        assert!(should_start_coordinated_finality_observer(
            &config,
            Some(NodeRole::RpcGateway.profile())
        ));
        assert!(should_start_coordinated_finality_observer(
            &config,
            Some(NodeRole::IndexerExplorer.profile())
        ));
        assert!(!should_start_coordinated_finality_observer(
            &config,
            Some(NodeRole::Validator.profile())
        ));
    }

    #[test]
    fn authorized_validator_with_p2p_rejects_finalized_typed_driver() {
        let address = "synv1typeddriverstarttest";
        let _ = VALIDATOR_MANAGER.register_validator(ValidatorRegistration {
            address: address.to_string(),
            public_key: "test-typed-driver-start-key".to_string(),
            name: "typed driver startup gate".to_string(),
            stake_amount: 50_000_000_000_000,
            submitted_at: now_ts(),
            registration_tx_hash: "test-typed-driver-start".to_string(),
        });
        let _ = VALIDATOR_MANAGER.approve_validator(address);
        VALIDATOR_MANAGER.update_validator_stake(address, 50_000_000_000_000);

        let mut config = NodeConfig::default();
        config.node.validator_address = address.to_string();

        let consensus_enabled =
            should_start_consensus(&config, Some(NodeRole::Validator.profile()));
        let error = select_finalized_consensus_driver_startup(
            consensus_enabled,
            true,
            Some(Ok(ResolvedConsensusMode::PosyV2_2)),
            None,
        )
        .expect_err("the P1-only release must reject typed startup");

        assert!(error.contains("typed PoSy is disabled"));
    }

    #[test]
    fn finalized_typed_driver_startup_fails_closed_without_p2p_or_finalized_inputs() {
        let no_p2p = select_finalized_consensus_driver_startup(
            true,
            false,
            Some(Ok(ResolvedConsensusMode::PosyV2_2)),
            None,
        )
        .expect_err("consensus startup without P2P must fail closed");
        assert!(no_p2p.contains("active P2P network"));

        let invalid_finalized_inputs = select_finalized_consensus_driver_startup(
            true,
            true,
            Some(Err("missing canonical finality context".to_string())),
            None,
        )
        .expect_err("consensus startup with invalid finalized inputs must fail closed");
        assert!(invalid_finalized_inputs.contains("missing canonical finality context"));
    }

    #[test]
    fn node_config_must_match_the_genesis_bound_parameter_manifest() {
        let genesis = load_genesis_from_path(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../genesis.testnet-v3.identity-assigned.json"),
        )
        .unwrap();
        let config = NodeConfig::default();
        ensure_node_config_matches_finalized_consensus_parameters(&config, &genesis).unwrap();

        let mut wrong_epoch = config.clone();
        wrong_epoch.consensus.epoch_length = 1_001;
        assert!(
            ensure_node_config_matches_finalized_consensus_parameters(&wrong_epoch, &genesis)
                .unwrap_err()
                .contains("epoch configuration")
        );

        let mut wrong_block_time = config.clone();
        wrong_block_time.consensus.block_time_secs = 3;
        assert!(ensure_node_config_matches_finalized_consensus_parameters(
            &wrong_block_time,
            &genesis
        )
        .unwrap_err()
        .contains("block-time configuration"));

        let mut wrong_protocol = config.clone();
        wrong_protocol.consensus.algorithm = "ProofOfSynergy".to_string();
        assert!(ensure_node_config_matches_finalized_consensus_parameters(
            &wrong_protocol,
            &genesis
        )
        .unwrap_err()
        .contains("protocol identifier"));

        let mut wrong_stage_timeout = config.clone();
        wrong_stage_timeout.consensus.precommit_timeout_ms = 1_501;
        assert!(ensure_node_config_matches_finalized_consensus_parameters(
            &wrong_stage_timeout,
            &genesis
        )
        .unwrap_err()
        .contains("stage-timeout configuration"));

        let mut wrong_cluster = config;
        wrong_cluster.consensus.validator_cluster_size = 7;
        assert!(ensure_node_config_matches_finalized_consensus_parameters(
            &wrong_cluster,
            &genesis
        )
        .unwrap_err()
        .contains("cluster size"));
    }

    #[test]
    fn applied_genesis_selects_core_only_driver_with_etdag_inactive() {
        let genesis = load_genesis_from_path(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../genesis.testnet-v3.identity-assigned.json"),
        )
        .unwrap();
        let parameters = genesis
            .consensus_parameters()
            .expect("applied Genesis must retain its consensus parameter binding");
        assert!(resolve_finalized_etdag_startup_activation(
            parameters,
            crate::synergy_types::Epoch(0),
        )
        .unwrap()
        .is_none());
    }

    fn snapshot_args(extra: &[&str]) -> Vec<String> {
        let mut args = vec![
            "synergy-testnet".to_string(),
            "create-snapshot".to_string(),
            "--chain-id".to_string(),
            "1266".to_string(),
            "--network-id".to_string(),
            "synergy-testnet-v3".to_string(),
            "--genesis-hash".to_string(),
            expected_genesis_hash(),
        ];
        args.extend(extra.iter().map(|arg| (*arg).to_string()));
        args
    }

    fn quarantine_args(extra: &[&str]) -> Vec<String> {
        let mut args = vec![
            "synergy-testnet".to_string(),
            "quarantine-stopped-validator".to_string(),
            "--chain-id".to_string(),
            "1266".to_string(),
            "--network-id".to_string(),
            "synergy-testnet-v3".to_string(),
            "--genesis-hash".to_string(),
            expected_genesis_hash(),
        ];
        args.extend(extra.iter().map(|arg| (*arg).to_string()));
        args
    }

    fn lifecycle_args(command: &str, extra: &[&str]) -> Vec<String> {
        let mut args = vec![
            "synergy-testnet".to_string(),
            command.to_string(),
            "--chain-id".to_string(),
            "1266".to_string(),
            "--network-id".to_string(),
            "synergy-testnet-v3".to_string(),
            "--genesis-hash".to_string(),
            expected_genesis_hash(),
        ];
        args.extend(extra.iter().map(|arg| (*arg).to_string()));
        args
    }

    #[test]
    fn snapshot_operator_args_require_chain_id_1264() {
        let missing = vec![
            "synergy-testnet".to_string(),
            "create-snapshot".to_string(),
            "--network-id".to_string(),
            "synergy-testnet-v3".to_string(),
        ];
        let error =
            require_testnet_v3_operator_args(&missing).expect_err("chain id must be required");
        assert!(error.contains("--chain-id 1266"));

        let wrong = vec![
            "synergy-testnet".to_string(),
            "create-snapshot".to_string(),
            "--chain-id".to_string(),
            "1263".to_string(),
            "--network-id".to_string(),
            "synergy-testnet-v3".to_string(),
        ];
        let error = require_testnet_v3_operator_args(&wrong).expect_err("wrong chain id must fail");
        assert!(error.contains("expected 1266"));
    }

    #[test]
    fn snapshot_operator_args_require_network_id() {
        let args = vec![
            "synergy-testnet".to_string(),
            "create-snapshot".to_string(),
            "--chain-id".to_string(),
            "1266".to_string(),
            "--network-id".to_string(),
            "synergy-testnet-v1".to_string(),
            "--genesis-hash".to_string(),
            expected_genesis_hash(),
        ];
        let error =
            require_testnet_v3_operator_args(&args).expect_err("wrong network must fail closed");
        assert!(error.contains("expected synergy-testnet-v3"));
    }

    #[test]
    fn snapshot_operator_args_require_genesis_hash() {
        let args = vec![
            "synergy-testnet".to_string(),
            "create-snapshot".to_string(),
            "--chain-id".to_string(),
            "1266".to_string(),
            "--network-id".to_string(),
            "synergy-testnet-v3".to_string(),
            "--genesis-hash".to_string(),
            "wrong".to_string(),
        ];
        let error =
            require_testnet_v3_operator_args(&args).expect_err("wrong genesis must fail closed");
        // Must name the CURRENT canonical genesis, never the retired v2 hash.
        assert!(error.contains(&expected_genesis_hash()));
        assert!(!error.contains("f79011f2"));
    }

    #[test]
    fn snapshot_operator_args_accept_equals_form() {
        let args = vec![
            "synergy-testnet".to_string(),
            "create-snapshot".to_string(),
            "--chain-id=1266".to_string(),
            "--network-id=synergy-testnet-v3".to_string(),
            format!("--genesis-hash={}", expected_genesis_hash()),
        ];
        require_testnet_v3_operator_args(&args).expect("equals form should be accepted");
    }

    #[test]
    fn offline_snapshot_commands_run_on_explicit_large_stack() {
        for command in [
            "create-snapshot",
            "verify-snapshot",
            "list-snapshots",
            "snapshot-catalog",
            "preflight-upgrade",
            "self-heal-from-snapshot",
            "quarantine-stopped-validator",
            "sync-from-canonical-peer",
            "start-shadow-observe",
            "shadow-status",
            "rejoin-eligibility",
            "request-rejoin",
        ] {
            assert!(
                offline_snapshot_command_uses_large_stack(command),
                "{command} must use the large-stack offline worker"
            );
        }

        assert!(!offline_snapshot_command_uses_large_stack("start"));
        assert!(!offline_snapshot_command_uses_large_stack("sync"));
    }

    #[test]
    fn snapshot_source_workspace_is_required_for_offline_commands() {
        let args = snapshot_args(&[]);
        let error = configure_offline_source_workspace(&args)
            .expect_err("ambiguous workspace must fail closed");
        assert!(error.contains("missing --source-workspace"));
    }

    #[test]
    fn operator_quarantine_rejects_ambiguous_workspace() {
        let args = quarantine_args(&[
            "--target-stopped",
            "--operator-approved-containment",
            "--quorum-majority-height",
            "87892",
            "--quorum-majority-hash",
            "majority-hash",
        ]);
        let error = run_offline_snapshot_command(&args, "quarantine-stopped-validator")
            .expect_err("ambiguous workspace must fail closed");
        assert!(error.contains("missing --source-workspace"));
    }

    #[test]
    fn role_runtime_exposes_recovery_lifecycle_commands_with_workspace_guard() {
        for command in [
            "preflight-upgrade",
            "sync-from-canonical-peer",
            "start-shadow-observe",
            "shadow-status",
            "rejoin-eligibility",
            "request-rejoin",
        ] {
            let args = lifecycle_args(command, &[]);
            let error = run_offline_snapshot_command(&args, command)
                .expect_err("recognized lifecycle command must fail closed before mutation");
            assert!(
                error.contains("missing --source-workspace"),
                "{command} returned unexpected error: {error}"
            );
        }
    }

    #[test]
    fn operator_quarantine_rejects_workspace_without_validator_state_store() {
        let workspace = unique_test_workspace("operator-quarantine-missing-state-store");
        let config_dir = workspace.join("config");
        fs::create_dir_all(&config_dir).expect("config directory should be created");
        fs::write(config_dir.join("node.toml"), b"[node]\n")
            .expect("node config should be written");
        let args = quarantine_args(&[
            "--source-workspace",
            workspace.to_str().expect("workspace path should be UTF-8"),
            "--target-stopped",
            "--operator-approved-containment",
            "--quorum-majority-height",
            "87892",
            "--quorum-majority-hash",
            "majority-hash",
        ]);

        let error = run_offline_snapshot_command(&args, "quarantine-stopped-validator")
            .expect_err("workspace without appliance state/store directory must fail closed");

        assert!(error.contains("missing validator appliance state/store directory"));
        fs::remove_dir_all(&workspace).expect("test workspace should clean up");
    }

    #[test]
    fn snapshot_source_workspace_requires_config_and_state_store() {
        let workspace = unique_test_workspace("missing-state-store");
        let config_dir = workspace.join("config");
        fs::create_dir_all(&config_dir).expect("config directory should be created");
        fs::write(config_dir.join("node.toml"), b"[node]\n")
            .expect("node config should be written");

        let args = snapshot_args(&[
            "--source-workspace",
            workspace.to_str().expect("workspace path should be UTF-8"),
        ]);
        let error = configure_offline_source_workspace(&args)
            .expect_err("missing appliance state/store must fail");
        assert!(error.contains("missing validator appliance state/store directory"));

        fs::remove_dir_all(&workspace).expect("test workspace should clean up");
    }

    #[test]
    fn snapshot_source_workspace_requires_concrete_config() {
        let workspace = unique_test_workspace("missing-config-file");
        fs::create_dir_all(workspace.join("config")).expect("config directory should be created");
        fs::create_dir_all(workspace.join("state").join("store"))
            .expect("validator appliance state store should be created");

        let args = snapshot_args(&[
            "--source-workspace",
            workspace.to_str().expect("workspace path should be UTF-8"),
        ]);
        let error =
            configure_offline_source_workspace(&args).expect_err("missing config file must fail");
        assert!(error.contains("missing default config file"));

        fs::remove_dir_all(&workspace).expect("test workspace should clean up");
    }

    #[test]
    fn snapshot_source_workspace_sets_offline_environment() {
        let _guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("environment lock should not be poisoned");
        let _restore = EnvRestore::capture();
        let workspace = unique_test_workspace("valid");
        let config_dir = workspace.join("config");
        fs::create_dir_all(&config_dir).expect("config directory should be created");
        fs::create_dir_all(workspace.join("state").join("store"))
            .expect("validator appliance state store should be created");
        let config_path = config_dir.join("node.toml");
        fs::write(&config_path, b"[node]\n").expect("node config should be written");

        let args = snapshot_args(&[
            "--source-workspace",
            workspace.to_str().expect("workspace path should be UTF-8"),
        ]);
        configure_offline_source_workspace(&args).expect("valid workspace should configure");

        assert_eq!(
            env::var("SYNERGY_PROJECT_ROOT").expect("project root env should be set"),
            workspace.to_string_lossy()
        );
        assert_eq!(
            env::var("SYNERGY_CONFIG_PATH").expect("config env should be set"),
            config_path.to_string_lossy()
        );

        fs::remove_dir_all(&workspace).expect("test workspace should clean up");
    }

    #[test]
    fn snapshot_verify_accepts_validator_appliance_state_store() {
        let _guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("environment lock should not be poisoned");
        let _restore = EnvRestore::capture();
        let workspace = unique_test_workspace("validator-appliance-state-store");
        let config_dir = workspace.join("config");
        fs::create_dir_all(&config_dir).expect("config directory should be created");
        fs::create_dir_all(workspace.join("state").join("store"))
            .expect("validator appliance state store should be created");
        let config_path = config_dir.join("node.toml");
        fs::write(&config_path, b"[node]\n").expect("node config should be written");

        let args = snapshot_args(&[
            "--source-workspace",
            workspace.to_str().expect("workspace path should be UTF-8"),
        ]);
        configure_snapshot_verify_source_workspace(&args)
            .expect("snapshot verification should accept validator appliance state/store");

        assert_eq!(
            env::var("SYNERGY_PROJECT_ROOT").expect("project root env should be set"),
            workspace.to_string_lossy()
        );
        assert_eq!(
            env::var("SYNERGY_CONFIG_PATH").expect("config env should be set"),
            config_path.to_string_lossy()
        );

        fs::remove_dir_all(&workspace).expect("test workspace should clean up");
    }

    #[test]
    fn expected_profile_populates_blank_config() {
        let mut config = NodeConfig::default();
        let profile = NodeRole::Validator.profile();

        let resolved = normalize_expected_profile(&mut config, Some(profile))
            .expect("expected profile should bind")
            .expect("profile should resolve");

        assert_eq!(config.identity.role, "validator");
        assert_eq!(config.role.compiled_profile, "validator_node");
        assert_eq!(resolved.role, NodeRole::Validator);
    }

    #[test]
    fn expected_profile_rejects_mismatch() {
        let mut config = NodeConfig::default();
        config.identity.role = "oracle".to_string();
        config.role.compiled_profile = "oracle_node".to_string();

        let error = normalize_expected_profile(&mut config, Some(NodeRole::Validator.profile()))
            .expect_err("mismatched profile should fail");

        assert!(error.contains("validator_node"));
        assert!(error.contains("oracle_node"));
    }

    #[test]
    fn rpc_gateway_profile_starts_p2p() {
        assert!(role_profile_requires_p2p(NodeRole::RpcGateway.profile()));
    }

    #[test]
    fn relayer_profile_starts_p2p() {
        assert!(role_profile_requires_p2p(NodeRole::Relayer.profile()));
    }

    #[test]
    fn indexer_explorer_profile_starts_p2p_and_sync() {
        let config = NodeConfig::default();
        let profile = NodeRole::IndexerExplorer.profile();

        assert!(role_profile_requires_p2p(profile));
        assert!(should_start_p2p(&config, Some(profile)));
        assert!(should_start_sync(&config, Some(profile)));
    }

    #[test]
    fn public_auto_register_validator_requires_state_sync_before_join() {
        let mut config = NodeConfig::default();
        config.validator.state_sync_before_join = true;
        config.node.auto_register_validator = true;

        assert!(should_require_state_sync_before_join(
            &config,
            Some(NodeRole::Validator.profile())
        ));
    }

    #[test]
    fn public_validator_requires_state_sync_before_join() {
        let mut config = NodeConfig::default();
        config.validator.state_sync_before_join = true;
        config.node.auto_register_validator = false;
        config.node.validator_address = "synv1candidate".to_string();
        config.node.strict_validator_allowlist = true;
        config.node.allowed_validator_addresses = vec!["synv1genesis".to_string()];

        assert!(should_require_state_sync_before_join(
            &config,
            Some(NodeRole::Validator.profile())
        ));
        assert!(local_sync_requires_support_sources(
            &config,
            Some(NodeRole::Validator.profile())
        ));
    }

    #[test]
    fn sync_source_policy_follows_authoritative_local_duty_state() {
        assert!(local_sync_requires_support_sources_for_state(
            true, true, false, false
        ));
        assert!(local_sync_requires_support_sources_for_state(
            true, false, true, false
        ));
        assert!(local_sync_requires_support_sources_for_state(
            true, false, false, true
        ));
        assert!(!local_sync_requires_support_sources_for_state(
            true, false, false, false
        ));
        assert!(!local_sync_requires_support_sources_for_state(
            false, true, true, true
        ));
    }

    #[test]
    fn persisted_vote_only_recovery_requires_support_sources_after_restart() {
        assert!(recovery_state_requires_support_sources(Some(
            RealignmentState::VoteOnly
        )));
        assert!(!recovery_state_requires_support_sources(Some(
            RealignmentState::Active
        )));
    }

    #[test]
    fn activation_transition_clears_support_source_restriction() {
        let before_activation =
            local_sync_requires_support_sources_for_state(true, true, true, false);
        let after_activation =
            local_sync_requires_support_sources_for_state(true, false, false, false);

        assert!(before_activation);
        assert!(!after_activation);
    }

    #[test]
    fn quarantine_transition_reenables_support_source_restriction() {
        let active = local_sync_requires_support_sources_for_state(true, false, false, false);
        let quarantined = local_sync_requires_support_sources_for_state(true, false, false, true);

        assert!(!active);
        assert!(quarantined);
    }

    #[test]
    fn public_validator_does_not_start_consensus_before_activation() {
        let mut config = NodeConfig::default();
        config.node.validator_address = "synv1candidate".to_string();
        config.node.strict_validator_allowlist = true;
        config.node.allowed_validator_addresses = vec!["synv1genesis".to_string()];

        assert!(!should_start_consensus(
            &config,
            Some(NodeRole::Validator.profile())
        ));
    }

    #[test]
    fn allowlisted_validator_waits_for_active_membership_before_consensus() {
        let mut config = NodeConfig::default();
        config.node.validator_address = "synv1genesis".to_string();
        config.node.strict_validator_allowlist = true;
        config.node.allowed_validator_addresses = vec!["synv1genesis".to_string()];

        assert!(!should_start_consensus(
            &config,
            Some(NodeRole::Validator.profile())
        ));
    }

    #[test]
    fn active_validator_starts_consensus() {
        let address = "synv1activeconsensusgate";
        let _ = VALIDATOR_MANAGER.register_validator(ValidatorRegistration {
            address: address.to_string(),
            public_key: "test-active-consensus-key".to_string(),
            name: "active consensus gate".to_string(),
            stake_amount: 50_000_000_000_000,
            submitted_at: now_ts(),
            registration_tx_hash: "test-active-consensus-gate".to_string(),
        });
        let _ = VALIDATOR_MANAGER.approve_validator(address);
        VALIDATOR_MANAGER.update_validator_stake(address, 50_000_000_000_000);

        let mut config = NodeConfig::default();
        config.node.validator_address = address.to_string();
        config.node.strict_validator_allowlist = true;
        config.node.allowed_validator_addresses = vec![address.to_string()];

        assert!(should_start_consensus(
            &config,
            Some(NodeRole::Validator.profile())
        ));
        assert!(!local_sync_requires_support_sources(
            &config,
            Some(NodeRole::Validator.profile())
        ));
    }

    #[test]
    fn active_validator_not_on_stale_strict_allowlist_starts_consensus() {
        let address = "synv1activebutnotallowlisted";
        let _ = VALIDATOR_MANAGER.register_validator(ValidatorRegistration {
            address: address.to_string(),
            public_key: "test-active-not-allowlisted-key".to_string(),
            name: "active not allowlisted".to_string(),
            stake_amount: 50_000_000_000_000,
            submitted_at: now_ts(),
            registration_tx_hash: "test-active-not-allowlisted".to_string(),
        });
        let _ = VALIDATOR_MANAGER.approve_validator(address);
        VALIDATOR_MANAGER.update_validator_stake(address, 50_000_000_000_000);

        let mut config = NodeConfig::default();
        config.node.validator_address = address.to_string();
        config.node.strict_validator_allowlist = true;
        config.node.allowed_validator_addresses = vec!["synv1canonicalactive".to_string()];
        config.validator.state_sync_before_join = true;

        assert!(should_start_consensus(
            &config,
            Some(NodeRole::Validator.profile())
        ));
        assert!(!should_require_state_sync_before_join(
            &config,
            Some(NodeRole::Validator.profile())
        ));
    }

    #[test]
    fn validator_auto_registration_requires_strict_allowlist() {
        let mut config = NodeConfig::default();
        config.node.auto_register_validator = true;
        config.node.validator_address = "synv1candidate".to_string();
        config.node.strict_validator_allowlist = false;
        config.node.allowed_validator_addresses = vec!["synv1candidate".to_string()];

        assert!(!should_auto_register_validator(
            &config,
            Some(NodeRole::Validator.profile())
        ));
    }

    #[test]
    fn validator_auto_registration_requires_local_address_on_allowlist() {
        let mut config = NodeConfig::default();
        config.node.auto_register_validator = true;
        config.node.validator_address = "synv1candidate".to_string();
        config.node.strict_validator_allowlist = true;
        config.node.allowed_validator_addresses = vec!["synv1genesis".to_string()];

        assert!(!should_auto_register_validator(
            &config,
            Some(NodeRole::Validator.profile())
        ));

        config.node.allowed_validator_addresses = vec!["synv1candidate".to_string()];
        assert!(should_auto_register_validator(
            &config,
            Some(NodeRole::Validator.profile())
        ));
    }

    #[test]
    fn allowlisted_non_active_validator_still_requires_join_sync_gate() {
        let mut config = NodeConfig::default();
        config.validator.state_sync_before_join = true;
        config.node.auto_register_validator = false;
        config.node.validator_address = "synv1genesis".to_string();
        config.node.strict_validator_allowlist = true;
        config.node.allowed_validator_addresses = vec!["synv1genesis".to_string()];

        assert!(should_require_state_sync_before_join(
            &config,
            Some(NodeRole::Validator.profile())
        ));
    }

    #[test]
    fn validator_waits_for_activation_before_consensus() {
        let mut config = NodeConfig::default();
        config.node.validator_address = "synv1candidate".to_string();
        config.node.strict_validator_allowlist = true;
        config.node.allowed_validator_addresses = vec!["synv1genesis".to_string()];

        let consensus_enabled =
            should_start_consensus(&config, Some(NodeRole::Validator.profile()));
        assert!(!consensus_enabled);
        assert!(should_watch_for_validator_activation_consensus(
            &config,
            Some(NodeRole::Validator.profile()),
            consensus_enabled,
        ));
    }

    #[test]
    fn registered_non_active_validator_waits_for_activation_before_consensus() {
        let address = "synv1registeredpendingconsensusgate";
        let _ = VALIDATOR_MANAGER.register_validator(ValidatorRegistration {
            address: address.to_string(),
            public_key: "test-pending-consensus-key".to_string(),
            name: "pending consensus gate".to_string(),
            stake_amount: 50_000_000_000_000,
            submitted_at: now_ts(),
            registration_tx_hash: "test-pending-consensus-gate".to_string(),
        });

        let mut config = NodeConfig::default();
        config.node.validator_address = address.to_string();
        config.node.strict_validator_allowlist = true;
        config.node.allowed_validator_addresses = vec!["synv1genesis".to_string()];

        let consensus_enabled =
            should_start_consensus(&config, Some(NodeRole::Validator.profile()));
        assert!(!consensus_enabled);
        assert!(should_watch_for_validator_activation_consensus(
            &config,
            Some(NodeRole::Validator.profile()),
            consensus_enabled,
        ));
    }

    #[test]
    fn consensus_preflight_rejects_validator_without_canonical_record() {
        let mut config = NodeConfig::default();
        config.node.validator_address = "synv1missingpreflight".to_string();

        let error = ensure_local_validator_consensus_key_bound(&config)
            .expect_err("validator without canonical record must fail preflight");

        assert!(error.contains("not present in finalized validator registry"));
    }

    #[test]
    fn coordinated_mode_selects_its_own_worker_not_typed_posy() {
        let coordinated = crate::consensus::coordinated_round_robin::CoordinatedRoundRobinConfig {
            chain_id: 1266,
            network_id: "synergy-testnet-v3".to_string(),
            consensus_version:
                crate::consensus::coordinated_round_robin::COORDINATED_ROUND_ROBIN_V1.to_string(),
            coordinator_id: "validator-1".to_string(),
            producer_ids: vec![
                "validator-2".to_string(),
                "validator-3".to_string(),
                "validator-4".to_string(),
                "validator-5".to_string(),
                "validator-6".to_string(),
            ],
            target_block_interval_ms: 2_000,
            producer_turn_timeout_ms: 4_000,
        };
        let startup = select_finalized_consensus_driver_startup(
            true,
            true,
            Some(Ok(ResolvedConsensusMode::CoordinatedRoundRobinV1(
                coordinated,
            ))),
            None,
        )
        .expect("a coordinated configuration must select its dedicated worker");
        assert_eq!(
            startup,
            FinalizedConsensusDriverStartup::SpawnCoordinatedRoundRobinDriver
        );
    }

    fn single_authority_plan() -> SingleAuthorityStartupPlan {
        use crate::consensus::single_authority_startup::*;
        SingleAuthorityStartupPlan {
            chain_id: LAUNCH_CHAIN_ID,
            chain_incarnation: LAUNCH_CHAIN_INCARNATION,
            network_id: LAUNCH_NETWORK_ID.to_string(),
            release_id: "chain1266-single-authority-rc1".to_string(),
            directory_namespace: "chain-1266/incarnation-5".to_string(),
            genesis_hash: "e25f4d99ec61e7c2db362549e6d950391ee13c7c21f4e51c6bbd051f063cd4e8"
                .to_string(),
            authority_id: LAUNCH_AUTHORITY_ID.to_string(),
            authority_public_key_fingerprint: "sha256:authority-node-01".to_string(),
            target_block_time_ms: LAUNCH_TARGET_BLOCK_TIME_MS,
            authority_start_height: 1,
        }
    }

    fn signed_single_authority() -> Option<Result<VerifiedConsensusStartup, String>> {
        Some(Ok(VerifiedConsensusStartup::SingleAuthority(Box::new(
            single_authority_plan(),
        ))))
    }

    /// D01. A valid signed single-authority activation selects its driver.
    #[test]
    fn d01_signed_single_authority_activation_selects_the_single_authority_driver() {
        let startup = select_finalized_consensus_driver_startup(
            true,
            true,
            None,
            signed_single_authority(),
        )
        .expect("a signed single-authority activation must select its driver");
        assert_eq!(
            startup,
            FinalizedConsensusDriverStartup::SpawnSingleAuthorityDriver(Box::new(
                single_authority_plan()
            ))
        );
    }

    /// D02/D03. Single authority starts with no P2P service and with P2P
    /// explicitly unavailable. It requires no peers, discovery, endpoint
    /// refresh, peer/quorum readiness, relayer, or second validator.
    #[test]
    fn d02_single_authority_starts_without_any_p2p_service() {
        let startup =
            select_finalized_consensus_driver_startup(true, false, None, signed_single_authority())
                .expect("single authority must not require a P2P network");
        assert!(matches!(
            startup,
            FinalizedConsensusDriverStartup::SpawnSingleAuthorityDriver(_)
        ));
    }

    #[test]
    fn d03_single_authority_starts_when_p2p_is_explicitly_unavailable() {
        // Even when the locally resolved mode is unavailable AND P2P is down,
        // the signed binding still selects single authority.
        let startup = select_finalized_consensus_driver_startup(
            true,
            false,
            Some(Err("P2P transport is unavailable".to_string())),
            signed_single_authority(),
        )
        .expect("single authority ignores P2P and local mode resolution");
        assert!(matches!(
            startup,
            FinalizedConsensusDriverStartup::SpawnSingleAuthorityDriver(_)
        ));
    }

    /// D04. P2P availability does not change the selected mode.
    #[test]
    fn d04_p2p_availability_does_not_change_the_single_authority_selection() {
        let with_p2p =
            select_finalized_consensus_driver_startup(true, true, None, signed_single_authority())
                .expect("with p2p");
        let without_p2p =
            select_finalized_consensus_driver_startup(true, false, None, signed_single_authority())
                .expect("without p2p");
        assert_eq!(with_p2p, without_p2p);
    }

    /// D05. Coordinated mode without P2P fails exactly as before.
    #[test]
    fn d05_coordinated_mode_without_p2p_fails_exactly_as_before() {
        let coordinated = crate::consensus::coordinated_round_robin::CoordinatedRoundRobinConfig {
            chain_id: 1266,
            network_id: "synergy-testnet-v3".to_string(),
            consensus_version:
                crate::consensus::coordinated_round_robin::COORDINATED_ROUND_ROBIN_V1.to_string(),
            coordinator_id: "validator-1".to_string(),
            producer_ids: (2..=6).map(|index| format!("validator-{index}")).collect(),
            target_block_interval_ms: 2_000,
            producer_turn_timeout_ms: 4_000,
        };
        // Unsigned path.
        let error = select_finalized_consensus_driver_startup(
            true,
            false,
            Some(Ok(ResolvedConsensusMode::CoordinatedRoundRobinV1(
                coordinated.clone(),
            ))),
            None,
        )
        .expect_err("coordinated without P2P must fail closed");
        assert!(error.contains("active P2P network"), "{error}");

        // Signed coordinated path keeps the same preflight.
        let error = select_finalized_consensus_driver_startup(
            true,
            false,
            Some(Ok(ResolvedConsensusMode::CoordinatedRoundRobinV1(
                coordinated,
            ))),
            Some(Ok(VerifiedConsensusStartup::CoordinatedRoundRobin)),
        )
        .expect_err("signed coordinated without P2P must fail closed");
        assert!(error.contains("active P2P network"), "{error}");
    }

    /// D06. PoSy mode without P2P fails exactly as before.
    #[test]
    fn d06_posy_mode_without_p2p_fails_exactly_as_before() {
        let error = select_finalized_consensus_driver_startup(
            true,
            false,
            Some(Ok(ResolvedConsensusMode::PosyV2_2)),
            None,
        )
        .expect_err("PoSy without P2P must fail closed");
        assert!(error.contains("active P2P network"), "{error}");

        let error = select_finalized_consensus_driver_startup(
            true,
            true,
            Some(Ok(ResolvedConsensusMode::PosyV2_2)),
            None,
        )
        .expect_err("PoSy is disabled in this release");
        assert!(error.contains("typed PoSy is disabled"), "{error}");
    }

    /// D07. A configuration/environment-only request for single authority is
    /// rejected: only a verified signed activation can select it.
    #[test]
    fn d07_environment_only_single_authority_request_is_rejected() {
        let mut config = NodeConfig::default();
        config.consensus.mode =
            crate::consensus::single_authority_finality_store::SINGLE_AUTHORITY_CONSENSUS_PROTOCOL
                .to_string();
        let resolved = config
            .consensus
            .resolve_mode(1266, "synergy-testnet-v3")
            .expect("the mode parses");
        assert_eq!(resolved, ResolvedConsensusMode::SingleAuthorityV1);

        let error =
            select_finalized_consensus_driver_startup(true, true, Some(Ok(resolved)), None)
                .expect_err("configuration alone must not select single authority");
        assert!(
            error.contains("requires a verified ML-DSA-87 signed DesiredStateV2 activation"),
            "{error}"
        );
    }

    /// An invalid signed activation fails closed rather than falling back to
    /// local configuration.
    #[test]
    fn d07b_invalid_signed_activation_never_falls_back_to_local_configuration() {
        let coordinated = crate::consensus::coordinated_round_robin::CoordinatedRoundRobinConfig {
            chain_id: 1266,
            network_id: "synergy-testnet-v3".to_string(),
            consensus_version:
                crate::consensus::coordinated_round_robin::COORDINATED_ROUND_ROBIN_V1.to_string(),
            coordinator_id: "validator-1".to_string(),
            producer_ids: (2..=6).map(|index| format!("validator-{index}")).collect(),
            target_block_interval_ms: 2_000,
            producer_turn_timeout_ms: 4_000,
        };
        let error = select_finalized_consensus_driver_startup(
            true,
            true,
            Some(Ok(ResolvedConsensusMode::CoordinatedRoundRobinV1(
                coordinated,
            ))),
            Some(Err("start authorization signature verification failed".to_string())),
        )
        .expect_err("a broken signed activation must fail closed");
        assert!(
            error.contains("signed consensus activation is invalid"),
            "{error}"
        );
    }

    /// D14. The single-authority branch constructs no coordinated input.
    #[test]
    fn d14_single_authority_dispatch_constructs_no_coordinated_input() {
        let startup =
            select_finalized_consensus_driver_startup(true, false, None, signed_single_authority())
                .expect("single authority");
        let rendered = format!("{startup:?}").to_ascii_lowercase();
        for forbidden in [
            "peer",
            "vote",
            "qc",
            "quorum",
            "coordinator",
            "producer",
            "certificate",
            "round",
            "cluster",
            "relayer",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "single-authority dispatch leaked `{forbidden}`: {rendered}"
            );
        }
    }

    #[test]
    fn coordinated_producer_recovers_and_canonically_orders_rpc_aegis_admissions() {
        let _guard = COORDINATED_POOL_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("coordinated pool test lock");
        let first = crate::aegis_tx_tool::sign_with_new_aegis_transaction_key(
            crate::aegis_tx_tool::AegisTxBuildOptions::default(),
        )
        .expect("first signed Aegis transaction");
        let mut second_options = crate::aegis_tx_tool::AegisTxBuildOptions::default();
        second_options.nonce = 1;
        let second = crate::aegis_tx_tool::sign_with_new_aegis_transaction_key(second_options)
            .expect("second signed Aegis transaction");

        let saved = TX_POOL.lock().expect("transaction pool lock").clone();
        {
            let mut pool = TX_POOL.lock().expect("transaction pool lock");
            pool.clear();
            pool.push(second.rpc_transaction);
            pool.push(first.rpc_transaction);
        }
        let admissions = select_coordinated_transaction_admissions()
            .expect("recover exact Aegis admissions from the RPC pool");
        *TX_POOL.lock().expect("transaction pool lock") = saved;

        assert_eq!(admissions.len(), 2);
        assert!(admissions.windows(2).all(|pair| {
            pair[0]
                .transaction
                .canonical_bytes()
                .expect("canonical first transaction")
                <= pair[1]
                    .transaction
                    .canonical_bytes()
                    .expect("canonical second transaction")
        }));
    }

    #[test]
    fn rpc_bind_address_normalizes_host_only_socket_inputs() {
        assert_eq!(
            normalize_rpc_socket_address("0.0.0.0", 5640),
            "0.0.0.0:5640"
        );
        assert_eq!(
            normalize_rpc_socket_address("127.0.0.1", 5640),
            "127.0.0.1:5640"
        );
        assert_eq!(normalize_socket_address("0.0.0.0", 6030), "0.0.0.0:6030");
    }

    #[test]
    fn rpc_bind_url_uses_loopback_for_wildcard_bind_addresses() {
        let mut config = NodeConfig::default();
        config.rpc.bind_address = "0.0.0.0".to_string();
        config.rpc.http_port = 5647;

        assert_eq!(rpc_bind_url(&config), "http://127.0.0.1:5647");
    }

    #[test]
    fn client_address_uses_loopback_for_wildcard_metrics_bind() {
        assert_eq!(
            normalize_client_address("0.0.0.0:6030", 6030),
            "127.0.0.1:6030"
        );
    }
}
