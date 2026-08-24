use std::any::Any;
use std::collections::BTreeMap;
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
use crate::consensus::posy::LocalConsensusContext;
use crate::consensus::self_realign::{
    expected_genesis_hash, persisted_recovery_state, RealignmentState,
};
use crate::consensus::signing_authority::DurableConsensusSigningAuthority;
#[cfg(test)]
use crate::consensus::simplified_posy::FailClosedSimplifiedTransitionAuthorityVerifier;
use crate::consensus::simplified_posy::{
    install_simplified_consensus_ingress, install_simplified_target_admission_producer_handler,
    load_genesis_bound_simplified_activation, prepare_simplified_target_admission_h3,
    remove_simplified_consensus_ingress, remove_simplified_target_admission_producer_handler,
    run_simplified_posy_driver, select_consensus_profile_at_height,
    select_consensus_profile_from_verified_v3_transition, validate_simplified_driver_activation,
    ConsensusProfileAtHeight, ConsensusSignatureVerifier, DurableSimplifiedEpochTransitionStore,
    DurableSimplifiedFinalitySink, DurableSimplifiedIngressKemRegistrySource,
    DurableSimplifiedPosyStore, DurableSimplifiedProposalMaterialStore,
    DurableSimplifiedProtectedExecutionTransitionAuthorityVerifier,
    DurableSimplifiedProtectedMaterialAuthority,
    DurableSimplifiedProtectedMaterialAuthorityConfiguration,
    DurableVerifiedSimplifiedProposalSource, FinalizedBlockRecord, GenesisFinalityReference,
    P2pSimplifiedConsensusEgress, QuorumCertificateReference, SimplifiedActivatedMaterialAdapter,
    SimplifiedCoreMaterialAdapter, SimplifiedCoreMaterialConfiguration, SimplifiedDriverTiming,
    SimplifiedEpochContext, SimplifiedFinalityEnvironment, SimplifiedFinalityParent,
    SimplifiedParentFeeMarketState, SimplifiedPosyDriver, SimplifiedPreviousEpochFinalityReplay,
    SimplifiedProtectedMaterialAdapter, SimplifiedProtectedMaterialConfiguration,
    SimplifiedTargetAdmissionConfiguration, SimplifiedTargetAdmissionOutput,
    SimplifiedTargetAdmissionProducer, SimplifiedTransitionAuthorityVerifier,
    VerifiedSimplifiedEpochTransition,
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
    TypedNextHeightAuthority, TypedNextHeightContextSource, TypedPosyCoordinator,
    TypedPosyCoordinatorStartup, TypedPosyDriver,
};
use crate::consensus::typed_finality_observer::{
    install_typed_finality_observer, remove_typed_finality_observer, TypedFinalityObserver,
};
use crate::consensus::typed_finality_store::{TypedFinalityRecord, TypedFinalityStore};
use crate::consensus::validator_keys::{
    load_local_validator_keypair_for_height, validator_public_key_with_declared_algorithm,
};
use crate::consensus_parameters::{ConsensusParameterRoot, EtdagActivationPermit};
use crate::crypto::aegis_pqvm::{
    AegisPqKeyLifecycleRecord, AegisPqvmKeyRegistry, AegisPqvmSigner, AegisPqvmVerifier,
};
use crate::crypto::pqc::{PQCAlgorithm, PQCManager, PQCPublicKey};
use crate::etdag::{
    install_etdag_certified_input_ingress, install_schedule_neutral_etdag_certified_input_ingress,
    remove_etdag_certified_input_ingress, EtdagCertifiedInputIngress, EtdagParameters,
    EtdagProtectedInputCoordinator, EtdagScheduleNeutralCertifiedInputIngress,
};
use crate::execution::{
    install_finalized_execution_state_snapshot, publish_finalized_execution_state_snapshot,
    remove_finalized_execution_state_snapshot,
};
use crate::genesis::{
    canonical_genesis, load_genesis_bound_etdag_governance, simplified_genesis_runtime_metadata,
    GenesisDocument, SimplifiedGenesisRuntimeMetadata,
};
use crate::logging::{init_logger, LogLevel};
use crate::p2p;
use crate::role_profiles::{resolve_configured_role, NodeRole, RoleProfile};
use crate::rpc;
use crate::rpc::rpc_server::{SHARED_CHAIN, SYNC_MANAGER, TX_POOL};
use crate::sxcp;
use crate::sync::SyncManager;
use crate::synergy_types::{
    AegisPqKeyId, AegisPqKeyRole, BlockHeader, CanonicalSerialize, ClusterMap, Hash, Height,
    ValidatorId, ValidatorSet, SYNERGY_TESTNET_V3_CHAIN_ID, TESTNET_V3_CANONICAL_NETWORK_ID,
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
const SIMPLIFIED_POSY_INGRESS_CAPACITY: usize = 512;

struct RoleProcessGuard {
    child: Mutex<Child>,
}

/// Owns the selected finalized PoSy worker started by a role runtime. A driver error
/// is captured for the main thread rather than ignored in a detached worker:
/// if scheduling, authenticated ingress, or P2P egress fails, the
/// validator process must stop rather than remain alive with signing disabled
/// or silently fall back to inherited consensus.
struct FinalizedPosyWorker {
    handle: thread::JoinHandle<()>,
    auxiliary_handles: Vec<thread::JoinHandle<()>>,
    fatal_error: Arc<Mutex<Option<String>>>,
}

impl FinalizedPosyWorker {
    fn fatal_error(&self) -> Option<String> {
        self.fatal_error.lock().ok().and_then(|error| error.clone())
    }

    fn join(self) {
        let _ = self.handle.join();
        for handle in self.auxiliary_handles {
            let _ = handle.join();
        }
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

/// The runtime owns at most one finalized-consensus worker.  A simplified
/// worker can never fall back to a prior engine: any fatal error terminates
/// the shared role-runtime loop.
enum FinalizedConsensusWorker {
    CoordinatedRoundRobin(CoordinatedRoundRobinWorker),
    Simplified(FinalizedPosyWorker),
}

impl FinalizedConsensusWorker {
    fn fatal_error(&self) -> Option<String> {
        match self {
            Self::CoordinatedRoundRobin(worker) => worker.fatal_error(),
            Self::Simplified(worker) => worker.fatal_error(),
        }
    }

    fn join(self) {
        match self {
            Self::CoordinatedRoundRobin(worker) => worker.join(),
            Self::Simplified(worker) => worker.join(),
        }
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
        .ok_or_else(|| format!("missing --network-id {TESTNET_V3_CANONICAL_NETWORK_ID}"))?;
    if network_id != TESTNET_V3_CANONICAL_NETWORK_ID {
        return Err(format!(
            "wrong network_id {network_id}; expected {TESTNET_V3_CANONICAL_NETWORK_ID}"
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

fn simplified_v3_startup_peer_readiness(
    validator_set: &ValidatorSet,
) -> Result<
    (
        usize,
        std::collections::BTreeSet<crate::synergy_types::ValidatorId>,
    ),
    String,
> {
    let frozen_validator_ids = validator_set
        .validators
        .iter()
        .map(|validator| validator.validator_id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let validator_count = frozen_validator_ids.len();
    if validator_count == 0 {
        return Err("simplified v3 frozen validator set is empty".to_string());
    }
    let strict_count_quorum = validator_count
        .checked_mul(2)
        .ok_or_else(|| "simplified v3 validator count quorum overflow".to_string())?
        / 3
        + 1;
    let required_remote_validators = strict_count_quorum
        .checked_sub(1)
        .ok_or_else(|| "simplified v3 remote readiness quorum underflow".to_string())?;
    Ok((required_remote_validators, frozen_validator_ids))
}

fn ready_frozen_simplified_validator_count(
    ready_validator_ids: &std::collections::BTreeSet<crate::synergy_types::ValidatorId>,
    frozen_validator_ids: &std::collections::BTreeSet<crate::synergy_types::ValidatorId>,
) -> usize {
    ready_validator_ids
        .intersection(frozen_validator_ids)
        .count()
}

/// Waits until the finalized profile's required remote validators have fresh,
/// authenticated status sessions before starting the first typed round. The
/// simplified v3 caller supplies the immutable per-epoch validator IDs and the
/// strict count quorum for that frozen set, minus the local validator.
fn wait_for_finalized_typed_peer_readiness(
    network: &p2p::networking::P2PNetwork,
    required_remote_validators: usize,
    frozen_simplified_validator_ids: Option<
        &std::collections::BTreeSet<crate::synergy_types::ValidatorId>,
    >,
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        let ready_count = frozen_simplified_validator_ids.map_or_else(
            || network.get_status_ready_validator_addresses().len(),
            |frozen| {
                let ready_validator_ids = network.get_status_ready_simplified_validator_ids(frozen);
                ready_frozen_simplified_validator_count(&ready_validator_ids, frozen)
            },
        );
        if ready_count >= required_remote_validators {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for finalized typed PoSy peer readiness: required {required_remote_validators} remote validators, observed {}",
                ready_count
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
    should_start_consensus_for_finalized_profile(config, profile, None)
}

fn should_start_consensus_for_finalized_profile(
    config: &NodeConfig,
    profile: Option<&RoleProfile>,
    finalized_profile: Option<&ConsensusProfileAtHeight>,
) -> bool {
    if config.node.bootstrap_only {
        return false;
    }

    if is_validator_profile(profile) {
        if let Some(ConsensusProfileAtHeight::PosySimplifiedV3 { validator_set, .. }) =
            finalized_profile
        {
            let validator_address = resolve_local_validator_address(config);
            return validator_set.validators.iter().any(|validator| {
                validator.validator_uma_id.0 == validator_address
                    && validator.is_active_for_epoch(validator_set.epoch)
            });
        }
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

/// The only production consensus-worker selection for the fresh Testnet-v3
/// genesis.  A validator needs live P2P and an immutable, genesis-bound v3
/// profile; v2 and coordinated paths are deliberately not fallbacks.
#[derive(Debug, Clone, PartialEq, Eq)]
enum FinalizedConsensusDriverStartup {
    Disabled,
    SpawnSimplifiedV3Driver {
        epoch_context: SimplifiedEpochContext,
        validator_set: ValidatorSet,
    },
}

fn select_finalized_consensus_driver_startup(
    consensus_enabled: bool,
    p2p_available: bool,
    finalized_input_validation: Option<Result<ConsensusProfileAtHeight, String>>,
) -> Result<FinalizedConsensusDriverStartup, String> {
    if !consensus_enabled {
        return Ok(FinalizedConsensusDriverStartup::Disabled);
    }
    if !p2p_available {
        return Err(
            "finalized consensus requires an active P2P network; refusing consensus startup"
                .to_string(),
        );
    }

    match finalized_input_validation {
        Some(Ok(ConsensusProfileAtHeight::PosySimplifiedV3 {
            epoch_context,
            validator_set,
        })) => Ok(FinalizedConsensusDriverStartup::SpawnSimplifiedV3Driver {
            epoch_context,
            validator_set,
        }),
        Some(Err(error)) => Err(format!(
            "finalized simplified PoSy inputs are unavailable; refusing consensus startup: {error}"
        )),
        None => Err(
            "finalized simplified PoSy inputs were not validated; refusing consensus startup"
                .to_string(),
        ),
    }
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
    let parameters = genesis.consensus_parameters().ok_or_else(|| {
        "canonical Testnet-v3 Genesis has no finalized consensus parameter manifest".to_string()
    })?;
    match &parameters.manifest {
        crate::consensus_parameters::FinalizedConsensusParameterManifest::SimplifiedPoSyV3(
            manifest,
        ) => ensure_node_config_matches_simplified_posy_parameters(config, manifest),
        _ => Err(
            "this release accepts only the finalized fresh testnet-v3 posy/3.0 manifest"
                .to_string(),
        ),
    }
}

fn ensure_node_config_matches_simplified_posy_parameters(
    config: &NodeConfig,
    manifest: &crate::posy_simplified_parameters::SimplifiedConsensusParameterManifest,
) -> Result<(), String> {
    use crate::consensus::simplified_posy::POSY_SIMPLIFIED_PROTOCOL_VERSION;

    manifest.require_activatable()?;
    let target_block_time_ms = config
        .blockchain
        .block_time
        .checked_mul(1_000)
        .ok_or_else(|| "node blockchain block time overflows milliseconds".to_string())?;
    let consensus_block_time_ms = config
        .consensus
        .block_time_secs
        .checked_mul(1_000)
        .ok_or_else(|| "node consensus block time overflows milliseconds".to_string())?;
    if config.blockchain.chain_id != manifest.chain_id.0
        || config.network.id != manifest.chain_id.0
        || config.network.network_id != manifest.network_id.0
        || config.consensus.algorithm != POSY_SIMPLIFIED_PROTOCOL_VERSION
        || config.consensus.mode != "posy_simplified_v3"
        || !config.consensus.coordinator_id.is_empty()
        || !config.consensus.producer_ids.is_empty()
        || target_block_time_ms != manifest.target_block_time_ms
        || consensus_block_time_ms != manifest.target_block_time_ms
        || config.consensus.target_block_time_ms != manifest.target_block_time_ms
        || config.consensus.epoch_length != manifest.epoch_length_blocks
        || config.consensus.vrf_seed_epoch_interval != manifest.epoch_length_blocks
        || u64::try_from(config.consensus.validator_cluster_size).ok()
            != Some(manifest.active_validator_count)
        || u64::try_from(config.consensus.min_validators).ok()
            != Some(manifest.active_validator_count)
        || u64::try_from(config.consensus.validator_vote_threshold).ok()
            != Some(manifest.required_distinct_signers)
        || config.consensus.proposal_timeout_ms != manifest.proposal_timeout_ms
        // Legacy TOML exposes two vote-phase fields.  Fresh simplified PoSy
        // has exactly one VOTE phase, so both aliases must agree with the one
        // immutable manifest timeout and are never used as separate stages.
        || config.consensus.prevote_timeout_ms != manifest.vote_timeout_ms
        || config.consensus.precommit_timeout_ms != manifest.vote_timeout_ms
        || config.consensus.max_round_timeout_ms != manifest.max_round_timeout_ms
    {
        return Err(
            "node configuration disagrees with the finalized fresh simplified PoSy manifest"
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
) -> Result<FinalizedPosyWorker, String>
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
    if let Err(error) = wait_for_finalized_typed_peer_readiness(
        &readiness_network,
        required_remote_validators,
        None,
    ) {
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

    Ok(FinalizedPosyWorker {
        handle,
        auxiliary_handles: Vec::new(),
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
        parent_fee_market: None,
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
    next_height_source: ActivationGuardedTypedNextHeightSource,
    etdag_activation_permit: Option<EtdagActivationPermit>,
    etdag_ingress: Option<EtdagCertifiedInputIngress>,
}

/// Prevents an already-running v2.2 worker from signing across a finalized
/// v3 boundary. Startup selection is not enough: a process may begin before
/// the declared height and remain alive until the predecessor QC is durable.
/// The next-height authority is the last possible signing boundary, so it
/// stops v2.2 before a v3-height context can be installed.
struct ActivationGuardedTypedNextHeightSource {
    inner: FinalizedTypedContextProvider,
    simplified_activation_height: Option<Height>,
}

fn ensure_v2_successor_precedes_simplified_activation(
    finalized_height: Height,
    simplified_activation_height: Option<Height>,
) -> Result<(), String> {
    let next_height = finalized_height
        .0
        .checked_add(1)
        .map(Height)
        .ok_or_else(|| "typed PoSy finalized height overflows".to_string())?;
    if simplified_activation_height.is_some_and(|activation| next_height.0 >= activation.0) {
        return Err(format!(
            "POSY_V3_ACTIVATION_BOUNDARY_REACHED: finalized v2.2 height {} requires restart into the Genesis-bound simplified driver at height {}",
            finalized_height.0, next_height.0
        ));
    }
    Ok(())
}

impl TypedNextHeightContextSource for ActivationGuardedTypedNextHeightSource {
    fn next_authority(
        &mut self,
        finalized: &TypedFinalityRecord,
        current: &LocalConsensusContext,
    ) -> Result<TypedNextHeightAuthority, String> {
        ensure_v2_successor_precedes_simplified_activation(
            finalized.height,
            self.simplified_activation_height,
        )?;
        self.inner.next_authority(finalized, current)
    }
}

fn resolve_finalized_etdag_startup_activation(
    consensus_parameters: &crate::consensus_parameters::LoadedConsensusParameters,
    epoch: crate::synergy_types::Epoch,
    governed_genesis_binding: Option<&crate::etdag_governance::EtdagGovernedGenesisBinding>,
) -> Result<Option<EtdagActivationPermit>, String> {
    if consensus_parameters
        .require_simplified_posy_manifest()
        .is_ok()
    {
        let binding = governed_genesis_binding.ok_or_else(|| {
            "fresh simplified PoSy ETDAG startup requires its governed Genesis binding".to_string()
        })?;
        return crate::consensus_parameters::issue_etdag_governed_genesis_permit(binding)
            .map(Some)
            .map_err(|error| {
                format!("fresh simplified PoSy ETDAG Genesis binding is invalid: {error}")
            });
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SimplifiedMaterialMode {
    Core,
    Protected,
}

fn select_simplified_material_mode(
    etdag_activation_permit: Option<&EtdagActivationPermit>,
) -> SimplifiedMaterialMode {
    match etdag_activation_permit {
        Some(_) => SimplifiedMaterialMode::Protected,
        None => SimplifiedMaterialMode::Core,
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
    let simplified_activation_height = load_genesis_bound_simplified_activation(genesis.value())?
        .map(|activation| Height(activation.activation_height));
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
        None,
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
        next_height_source: ActivationGuardedTypedNextHeightSource {
            inner: provider()?,
            simplified_activation_height,
        },
        etdag_activation_permit,
        etdag_ingress,
    })
}

fn spawn_finalized_typed_posy_driver(
    config: &NodeConfig,
    network: Arc<p2p::networking::P2PNetwork>,
    running: Arc<AtomicBool>,
) -> Result<FinalizedPosyWorker, String> {
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

struct SimplifiedCryptoAuthority {
    signer: AegisPqvmSigner,
    target_admission_signer: AegisPqvmSigner,
    verifier: AegisPqvmVerifier,
    local_validator_id: ValidatorId,
    local_key_id: AegisPqKeyId,
}

fn simplified_epoch_state_path(epoch_context_root: Hash) -> PathBuf {
    crate::utils::resolve_data_path(&format!(
        "data/posy-v3-consensus/{}/safety-state.json",
        epoch_context_root.to_hex()
    ))
}

fn simplified_epoch_transition_path(previous_epoch_context_root: Hash) -> PathBuf {
    crate::utils::resolve_data_path(&format!(
        "data/posy-v3-consensus/{}/next-epoch-transition.json",
        previous_epoch_context_root.to_hex()
    ))
}

fn load_local_verified_simplified_transition<V, A, F>(
    selected_epoch_context: &SimplifiedEpochContext,
    selected_validator_set: &ValidatorSet,
    authority_verifier: &A,
    verifier_factory: F,
) -> Result<VerifiedSimplifiedEpochTransition, String>
where
    V: ConsensusSignatureVerifier,
    A: SimplifiedTransitionAuthorityVerifier,
    F: FnOnce(&SimplifiedEpochContext, &ValidatorSet) -> Result<V, String>,
{
    let anchor = selected_epoch_context
        .v3_transition_anchor
        .as_ref()
        .ok_or_else(|| "selected simplified epoch has no v3 transition anchor".to_string())?;
    let store = DurableSimplifiedEpochTransitionStore::at_path(simplified_epoch_transition_path(
        anchor.previous_epoch_context_root,
    ));
    let transition = store
        .load_with_consensus_verifier_factory(
            authority_verifier,
            |previous_context, previous_set| {
                if previous_context.root()? != anchor.previous_epoch_context_root {
                    return Err(
                        "durable v3 transition substituted a different previous context root"
                            .to_string(),
                    );
                }
                verifier_factory(previous_context, previous_set)
            },
        )
        .map_err(|error| {
            format!(
                "load and reverify durable v3 transition {}: {error}",
                store.path().display()
            )
        })?;
    if transition.next_epoch_context() != selected_epoch_context
        || transition.next_validator_set() != selected_validator_set
    {
        return Err(
            "durable v3 transition does not equal the selected epoch context and validator set"
                .to_string(),
        );
    }
    Ok(transition)
}

fn load_next_local_verified_simplified_transition<V, A>(
    previous_epoch_context: &SimplifiedEpochContext,
    previous_validator_set: &ValidatorSet,
    consensus_verifier: &V,
    authority_verifier: &A,
) -> Result<VerifiedSimplifiedEpochTransition, String>
where
    V: ConsensusSignatureVerifier,
    A: SimplifiedTransitionAuthorityVerifier,
{
    let store = DurableSimplifiedEpochTransitionStore::at_path(simplified_epoch_transition_path(
        previous_epoch_context.root()?,
    ));
    let transition =
        load_verified_simplified_transition_store(&store, consensus_verifier, authority_verifier)?;
    if transition.previous_epoch_context() != previous_epoch_context
        || transition.previous_validator_set() != previous_validator_set
    {
        return Err(
            "durable v3 transition substituted a different previous epoch authority".to_string(),
        );
    }
    Ok(transition)
}

fn load_verified_simplified_transition_store<V, A>(
    store: &DurableSimplifiedEpochTransitionStore,
    consensus_verifier: &V,
    authority_verifier: &A,
) -> Result<VerifiedSimplifiedEpochTransition, String>
where
    V: ConsensusSignatureVerifier,
    A: SimplifiedTransitionAuthorityVerifier,
{
    store
        .load(consensus_verifier, authority_verifier)
        .map_err(|error| {
            format!(
                "load and reverify durable v3 transition {}: {error}",
                store.path().display()
            )
        })
}

fn build_simplified_consensus_verifier(
    epoch_context: &SimplifiedEpochContext,
    validator_set: &ValidatorSet,
) -> Result<AegisPqvmVerifier, String> {
    epoch_context.validate_against(validator_set)?;
    let active_set = validator_set.active_for_epoch(epoch_context.epoch);
    let roles = vec![
        AegisPqKeyRole::ConsensusProposer,
        AegisPqKeyRole::ConsensusVote,
        AegisPqKeyRole::EpochTransition,
    ];
    let mut registry = AegisPqvmKeyRegistry::default();
    for validator in &active_set.validators {
        registry
            .register_public_key_with_lifecycle(
                PQCPublicKey {
                    algorithm: PQCAlgorithm::MLDSA65,
                    key_data: validator.consensus_public_key.key_bytes.clone(),
                    key_id: validator.consensus_public_key.key_id.0.clone(),
                    created_at: 0,
                },
                AegisPqKeyLifecycleRecord {
                    uma_id: validator.validator_uma_id.0.clone(),
                    key_id: validator.consensus_public_key.key_id.clone(),
                    roles: roles.clone(),
                    active_from_epoch: epoch_context.epoch,
                    active_until_epoch: Some(epoch_context.epoch),
                    revoked_from_epoch: None,
                },
            )
            .map_err(|error| format!("register frozen v3 verifier key: {error}"))?;
    }
    AegisPqvmVerifier::initialize_required(registry)
        .map_err(|error| format!("initialize simplified Aegis verifier: {error}"))
}

fn build_simplified_crypto_authority(
    config: &NodeConfig,
    epoch_context: &SimplifiedEpochContext,
    validator_set: &ValidatorSet,
) -> Result<SimplifiedCryptoAuthority, String> {
    epoch_context.validate_against(validator_set)?;
    let active_set = validator_set.active_for_epoch(epoch_context.epoch);
    let validator_address = resolve_local_validator_address(config);
    let local = active_set
        .validators
        .iter()
        .find(|validator| validator.validator_uma_id.0 == validator_address)
        .ok_or_else(|| {
            format!("local validator {validator_address} is absent from the frozen v3 epoch set")
        })?;
    let (public_key, private_key) = load_local_validator_keypair_for_height(
        epoch_context.epoch_start_height.0,
        &validator_address,
        &VALIDATOR_MANAGER,
    )
    .map_err(|error| format!("load frozen v3 local consensus key: {error}"))?;
    if public_key.algorithm != PQCAlgorithm::MLDSA65
        || private_key.algorithm != PQCAlgorithm::MLDSA65
        || public_key.key_id != local.consensus_public_key.key_id.0
        || private_key.public_key_id != public_key.key_id
        || public_key.key_data != local.consensus_public_key.key_bytes
    {
        return Err(
            "local ML-DSA-65 keypair does not match the frozen v3 validator record".to_string(),
        );
    }

    // The canonical key loader already binds the private key to the local
    // validator record. Recheck it against the exact frozen public key before
    // the v3 signer becomes reachable.
    let mut key_check = PQCManager::new();
    let challenge = b"SYNERGY_POSY_SIMPLIFIED_LOCAL_KEY_BINDING_V1";
    let signature = key_check
        .sign(&private_key, challenge)
        .map_err(|_| "simplified local consensus key self-test failed".to_string())?;
    if !key_check
        .verify(&public_key, &signature, challenge)
        .map_err(|_| "simplified local consensus key verification failed".to_string())?
    {
        return Err(
            "simplified local private key does not match the frozen public key".to_string(),
        );
    }

    let roles = vec![
        AegisPqKeyRole::ConsensusProposer,
        AegisPqKeyRole::ConsensusVote,
        AegisPqKeyRole::EpochTransition,
    ];
    let mut signer = AegisPqvmSigner::initialize_required()
        .map_err(|error| format!("initialize simplified Aegis signer: {error}"))?;
    let mut target_admission_signer = AegisPqvmSigner::initialize_required()
        .map_err(|error| format!("initialize simplified target-admission signer: {error}"))?;
    let target_admission_key_id = target_admission_signer
        .register_existing_keypair(
            &local.validator_uma_id.0,
            public_key.clone(),
            private_key.clone(),
            roles.clone(),
            epoch_context.epoch,
        )
        .map_err(|error| format!("import simplified target-admission key: {error}"))?;
    let local_key_id = signer
        .register_existing_keypair(
            &local.validator_uma_id.0,
            public_key,
            private_key,
            roles.clone(),
            epoch_context.epoch,
        )
        .map_err(|error| format!("import simplified local consensus key: {error}"))?;
    if local_key_id != local.consensus_public_key.key_id {
        return Err("simplified signer registered a different frozen key ID".to_string());
    }
    if target_admission_key_id != local_key_id {
        return Err(
            "simplified target-admission signer registered a different frozen key ID".to_string(),
        );
    }

    let verifier = build_simplified_consensus_verifier(epoch_context, validator_set)?;

    Ok(SimplifiedCryptoAuthority {
        signer,
        target_admission_signer,
        verifier,
        local_validator_id: local.validator_id.clone(),
        local_key_id,
    })
}

fn fresh_simplified_genesis_anchor_authorities(
    epoch_context: &SimplifiedEpochContext,
) -> Result<(SimplifiedFinalityParent, FinalizedBlockRecord), String> {
    let genesis = canonical_genesis().map_err(|error| {
        format!("fresh simplified finality cannot load canonical Genesis: {error}")
    })?;
    let activation = load_genesis_bound_simplified_activation(genesis.value())?
        .ok_or_else(|| "fresh simplified finality has no Genesis activation binding".to_string())?;
    if activation.derive_fresh_genesis_epoch_context()? != *epoch_context {
        return Err(
            "fresh simplified finality context does not equal the canonical Genesis activation"
                .to_string(),
        );
    }
    let genesis_hash = Hash::from_hex(genesis.hash())
        .map_err(|error| format!("fresh simplified Genesis hash is invalid: {error}"))?;
    let reference = GenesisFinalityReference::from_canonical_genesis_hash(genesis_hash);
    let parent = SimplifiedFinalityParent::genesis(reference.clone())?;
    let finalized = FinalizedBlockRecord::from_genesis(reference)?;
    Ok((parent, finalized))
}

fn fresh_simplified_genesis_cryptographic_profile_root(
    genesis: &GenesisDocument,
    metadata: &SimplifiedGenesisRuntimeMetadata,
) -> Result<Hash, String> {
    let payload = serde_json::to_vec(&json!({
        "genesis_hash": genesis.hash(),
        "consensus_signature_algorithm": crate::synergy_types::TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM,
        "aegis_pqvm_version": metadata.aegis_pqvm_version,
        "dag_version": metadata.dag_version,
    }))
    .map_err(|error| format!("serialize fresh simplified cryptographic profile: {error}"))?;
    Ok(Hash::from_domain_bytes(
        "SYNERGY_POSY_SIMPLIFIED_FRESH_GENESIS_CRYPTOGRAPHIC_PROFILE_V1",
        &payload,
    ))
}

struct SimplifiedV3TransitionRuntimeFinality {
    sink: DurableSimplifiedFinalitySink,
    certified_parent_header: BlockHeader,
    boundary_execution_state: crate::execution::ExecutionState,
    previous_replay: SimplifiedPreviousEpochFinalityReplay,
}

fn simplified_target_admission_wire_message(
    output: SimplifiedTargetAdmissionOutput,
) -> (
    Height,
    crate::p2p::messages::SimplifiedTargetAdmissionMessage,
) {
    match output {
        SimplifiedTargetAdmissionOutput::Vote(request) => (
            request.context.target_height,
            crate::p2p::messages::SimplifiedTargetAdmissionMessage::Vote { request },
        ),
        SimplifiedTargetAdmissionOutput::CertifiedPackage(package) => (
            package.context.target_height,
            crate::p2p::messages::SimplifiedTargetAdmissionMessage::CertifiedPackage { package },
        ),
    }
}

fn run_simplified_target_admission_worker(
    initial_outputs: Vec<SimplifiedTargetAdmissionOutput>,
    network: &p2p::networking::P2PNetwork,
    frozen_validator_ids: &std::collections::BTreeSet<ValidatorId>,
    running: &AtomicBool,
) -> Result<(), String> {
    const PREPARE_INTERVAL: Duration = Duration::from_millis(500);
    const REBROADCAST_INTERVAL: Duration = Duration::from_secs(5);

    let mut pending_outputs = initial_outputs;
    let mut last_broadcast = BTreeMap::<(Height, Hash), Instant>::new();
    while running.load(Ordering::Acquire) {
        if pending_outputs.is_empty() {
            match prepare_simplified_target_admission_h3() {
                Ok(outputs) => pending_outputs = outputs,
                Err(error) if error.contains("producer is busy; ingress rejected") => {
                    thread::sleep(PREPARE_INTERVAL);
                    continue;
                }
                Err(error) => return Err(error),
            }
        }

        let now = Instant::now();
        for output in pending_outputs.drain(..) {
            let (target_height, message) = simplified_target_admission_wire_message(output);
            let canonical = serde_json::to_vec(&message)
                .map_err(|error| format!("serialize target-admission output: {error}"))?;
            let message_id = Hash::from_domain_bytes(
                "SYNERGY_POSY_SIMPLIFIED_TARGET_ADMISSION_WIRE_V1",
                &canonical,
            );
            last_broadcast.retain(|(height, _), _| *height == target_height);
            if last_broadcast
                .get(&(target_height, message_id))
                .is_some_and(|last| now.saturating_duration_since(*last) < REBROADCAST_INTERVAL)
            {
                continue;
            }
            let sent =
                network.broadcast_simplified_target_admission(&message, frozen_validator_ids)?;
            if sent > 0 {
                last_broadcast.insert((target_height, message_id), now);
            }
        }
        thread::sleep(PREPARE_INTERVAL);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_simplified_v3_transition_runtime_finality(
    transition: VerifiedSimplifiedEpochTransition,
    material_store: DurableSimplifiedProposalMaterialStore,
    cluster_map: ClusterMap,
    consensus_verifier: AegisPqvmVerifier,
    etdag_parameters: EtdagParameters,
    typed_boundary_execution_state: crate::execution::ExecutionState,
) -> Result<SimplifiedV3TransitionRuntimeFinality, String> {
    build_simplified_v3_transition_runtime_finality_at_depth(
        transition,
        material_store,
        cluster_map,
        consensus_verifier,
        etdag_parameters,
        typed_boundary_execution_state,
        0,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_simplified_v3_transition_runtime_finality_at_depth(
    transition: VerifiedSimplifiedEpochTransition,
    material_store: DurableSimplifiedProposalMaterialStore,
    cluster_map: ClusterMap,
    consensus_verifier: AegisPqvmVerifier,
    etdag_parameters: EtdagParameters,
    typed_boundary_execution_state: crate::execution::ExecutionState,
    depth: usize,
) -> Result<SimplifiedV3TransitionRuntimeFinality, String> {
    if depth >= 1_024 {
        return Err("durable v3 transition replay chain exceeds 1024 epochs".to_string());
    }
    let previous_context = transition.previous_epoch_context();
    let previous_set = transition.previous_validator_set();
    let previous_cluster_map = ClusterMap::derive_from_finalized_epoch_seed(
        &previous_set.active_for_epoch(previous_context.epoch),
        previous_context.finalized_epoch_seed_root,
    )?;
    let previous_consensus_verifier =
        build_simplified_consensus_verifier(previous_context, previous_set)?;
    let previous_material_store =
        DurableSimplifiedProposalMaterialStore::for_epoch(previous_context.root()?)?;
    let previous_sink = if previous_context.v3_transition_anchor.is_some() {
        let previous_anchor = previous_context
            .v3_transition_anchor
            .as_ref()
            .ok_or_else(|| {
                "transition context unexpectedly lost its previous-epoch anchor".to_string()
            })?;
        let authority_store = DurableSimplifiedProposalMaterialStore::for_epoch(
            previous_anchor.previous_epoch_context_root,
        )?;
        let authority_verifier =
            DurableSimplifiedProtectedExecutionTransitionAuthorityVerifier::new(authority_store);
        let previous_transition = load_local_verified_simplified_transition(
            previous_context,
            previous_set,
            &authority_verifier,
            build_simplified_consensus_verifier,
        )?;
        build_simplified_v3_transition_runtime_finality_at_depth(
            previous_transition,
            previous_material_store.clone(),
            previous_cluster_map.clone(),
            previous_consensus_verifier.clone(),
            etdag_parameters.clone(),
            typed_boundary_execution_state,
            depth.saturating_add(1),
        )?
        .sink
    } else {
        let (_, previous_anchor_finalized) =
            fresh_simplified_genesis_anchor_authorities(previous_context)?;
        let previous_environment = SimplifiedFinalityEnvironment {
            epoch_context: previous_context.clone(),
            validator_set: previous_set.clone(),
            cluster_map: previous_cluster_map.clone(),
            etdag_parameters: etdag_parameters.clone(),
            consensus_verifier: previous_consensus_verifier.clone(),
            etdag_verifier: previous_consensus_verifier.clone(),
            anchor_finalized: previous_anchor_finalized,
            anchor_finalized_fee_market: None,
            boundary_execution_state: typed_boundary_execution_state,
        };
        DurableSimplifiedFinalitySink::for_epoch(
            previous_material_store.clone(),
            previous_environment,
        )?
    };
    let expected_finalized =
        FinalizedBlockRecord::from_quorum_certificate(QuorumCertificateReference {
            height: transition.finalized_seed().height,
            block_id: transition.finalized_seed().block_id.clone(),
            qc_id: transition.finalized_seed().qc_id,
        })?;
    if previous_sink.current_finalized() != &expected_finalized {
        return Err(
            "previous simplified finality WAL does not reach the transition's exact finalized seed"
                .to_string(),
        );
    }
    let finalized_seed_material =
        previous_material_store.load(transition.finalized_seed().qc_id)?;
    if finalized_seed_material.candidate_subject.context.height
        != transition.finalized_seed().height
        || finalized_seed_material.candidate_subject.block_id
            != transition.finalized_seed().block_id
        || finalized_seed_material.canonical_block.candidate_id()?
            != transition.finalized_seed().block_id
    {
        return Err(
            "previous material store does not contain the transition's exact finalized fee boundary"
                .to_string(),
        );
    }
    let anchor_finalized_fee_market = Some(SimplifiedParentFeeMarketState::from_verified_header(
        &finalized_seed_material.canonical_block.header,
    )?);
    let certified_parent_material =
        previous_material_store.load(transition.certified_parent().qc_id)?;
    if certified_parent_material.candidate_subject.context.height
        != transition.certified_parent().height
        || certified_parent_material.candidate_subject.block_id
            != transition.certified_parent().block_id
        || certified_parent_material.canonical_block.candidate_id()?
            != transition.certified_parent().block_id
    {
        return Err(
            "previous material store does not contain the transition's exact certified parent"
                .to_string(),
        );
    }

    let boundary_execution_state = previous_sink.execution_state().clone();
    let environment = SimplifiedFinalityEnvironment {
        epoch_context: transition.next_epoch_context().clone(),
        validator_set: transition.next_validator_set().clone(),
        cluster_map,
        etdag_parameters: etdag_parameters.clone(),
        consensus_verifier: consensus_verifier.clone(),
        etdag_verifier: consensus_verifier,
        anchor_finalized: expected_finalized,
        anchor_finalized_fee_market,
        boundary_execution_state: boundary_execution_state.clone(),
    };
    let previous_replay = SimplifiedPreviousEpochFinalityReplay {
        material_store: previous_material_store,
        cluster_map: previous_cluster_map,
        etdag_parameters,
        consensus_verifier: previous_consensus_verifier.clone(),
        etdag_verifier: previous_consensus_verifier,
    };
    let sink = DurableSimplifiedFinalitySink::for_epoch_from_verified_v3_transition(
        material_store,
        environment,
        transition,
        previous_replay.clone(),
    )?;
    Ok(SimplifiedV3TransitionRuntimeFinality {
        sink,
        certified_parent_header: certified_parent_material.canonical_block.header,
        boundary_execution_state,
        previous_replay,
    })
}

/// Starts the authenticated simplified v3 driver from finalized activation
/// state. The Genesis-committed governed ETDAG artifacts issue the protected
/// adapter capability; no default or deferred compatibility path exists.
/// Consensus and ingress share the same durable material/finality authority.
fn spawn_finalized_simplified_posy_driver(
    config: &NodeConfig,
    epoch_context: SimplifiedEpochContext,
    validator_set: ValidatorSet,
    network: Arc<p2p::networking::P2PNetwork>,
    running: Arc<AtomicBool>,
) -> Result<FinalizedPosyWorker, String> {
    let genesis = canonical_genesis().map_err(|error| {
        format!("simplified driver cannot load canonical finalized Genesis: {error}")
    })?;
    let activation = load_genesis_bound_simplified_activation(genesis.value())?
        .ok_or_else(|| "simplified driver selected without a Genesis activation".to_string())?;
    let transition_authority_verifier = epoch_context
        .v3_transition_anchor
        .as_ref()
        .map(|anchor| {
            DurableSimplifiedProposalMaterialStore::for_epoch(anchor.previous_epoch_context_root)
                .map(DurableSimplifiedProtectedExecutionTransitionAuthorityVerifier::new)
        })
        .transpose()?;
    let verified_transition = if epoch_context.v3_transition_anchor.is_some() {
        epoch_context.validate_against(&validator_set)?;
        Some(load_local_verified_simplified_transition(
            &epoch_context,
            &validator_set,
            transition_authority_verifier.as_ref().ok_or_else(|| {
                "simplified transition has no durable finalized-execution authority verifier"
                    .to_string()
            })?,
            build_simplified_consensus_verifier,
        )?)
    } else {
        validate_simplified_driver_activation(&activation, &epoch_context, &validator_set)?;
        None
    };
    let consensus_parameters = genesis.consensus_parameters().cloned().ok_or_else(|| {
        "simplified driver requires finalized Genesis consensus parameters".to_string()
    })?;
    consensus_parameters.require_genesis_binding()?;
    let simplified_parameters = consensus_parameters.require_simplified_posy_manifest()?;
    let governed_etdag = load_genesis_bound_etdag_governance(genesis.value())?;
    let etdag_activation_permit = resolve_finalized_etdag_startup_activation(
        &consensus_parameters,
        epoch_context.epoch,
        Some(&governed_etdag),
    )?;
    crate::gas::install_governed_fee_schedule(
        governed_etdag
            .fee_schedule_artifact
            .manifest
            .fee_schedule
            .clone(),
    )?;
    crate::gas::install_governed_fee_market_params(
        governed_etdag
            .fee_schedule_artifact
            .manifest
            .fee_market_params,
    )?;
    let material_mode = select_simplified_material_mode(etdag_activation_permit.as_ref());
    let genesis_execution_state = load_finalized_testnet_v3_genesis_execution_state(genesis)
        .map_err(|error| format!("load finalized Genesis execution state: {error}"))?;
    let genesis_runtime_metadata = simplified_genesis_runtime_metadata(genesis.value())?;
    let cryptographic_profile_root =
        fresh_simplified_genesis_cryptographic_profile_root(genesis, &genesis_runtime_metadata)?;
    let genesis_timestamp_ms = genesis
        .timestamp()
        .checked_mul(1_000)
        .ok_or_else(|| "fresh simplified Genesis timestamp milliseconds overflow".to_string())?;

    let active_set = validator_set.active_for_epoch(epoch_context.epoch);
    let cluster_map = ClusterMap::derive_from_finalized_epoch_seed(
        &active_set,
        epoch_context.finalized_epoch_seed_root,
    )?;
    let crypto = build_simplified_crypto_authority(config, &epoch_context, &validator_set)?;
    let material_store = DurableSimplifiedProposalMaterialStore::for_epoch(epoch_context.root()?)?;
    // The runtime executes the exact canonical parameters whose SHA3-512
    // root is bound into Genesis; a Rust default is never an activation
    // authority and cannot silently substitute for governance policy.
    let etdag_parameters = governed_etdag
        .parameter_artifact
        .manifest
        .parameters
        .clone();
    let transition_for_driver = verified_transition.clone();
    let transition_for_protected_authority = verified_transition.clone();
    let (
        anchor_parent,
        anchor_finalized,
        finalization_sink,
        finality_boundary_execution_state,
        previous_finality_replay,
        epoch_start_timestamp_ms,
        runtime_metadata,
    ) = if let Some(transition) = verified_transition {
        let anchor_parent =
            SimplifiedFinalityParent::quorum_certificate(transition.certified_parent().clone())?;
        let anchor_finalized =
            FinalizedBlockRecord::from_quorum_certificate(QuorumCertificateReference {
                height: transition.finalized_seed().height,
                block_id: transition.finalized_seed().block_id.clone(),
                qc_id: transition.finalized_seed().qc_id,
            })?;
        let runtime_finality = build_simplified_v3_transition_runtime_finality(
            transition,
            material_store.clone(),
            cluster_map.clone(),
            crypto.verifier.clone(),
            etdag_parameters.clone(),
            genesis_execution_state.clone(),
        )?;
        let header = runtime_finality.certified_parent_header;
        let runtime_metadata = SimplifiedGenesisRuntimeMetadata {
            app_version: header.app_version,
            execution_version: header.execution_version,
            dag_version: header.dag_version,
            aegis_pqvm_version: header.aegis_pqvm_version.clone(),
        };
        if runtime_metadata != genesis_runtime_metadata {
            return Err(
                "simplified v3 transition parent header does not match the frozen Genesis runtime versions"
                    .to_string(),
            );
        }
        let epoch_start_timestamp_ms = header
            .timestamp_ms_consensus_bounded
            .checked_add(simplified_parameters.target_block_time_ms)
            .ok_or_else(|| "simplified epoch start timestamp overflows".to_string())?;
        (
            anchor_parent,
            anchor_finalized,
            runtime_finality.sink,
            runtime_finality.boundary_execution_state,
            Some(runtime_finality.previous_replay),
            epoch_start_timestamp_ms,
            runtime_metadata,
        )
    } else {
        let (anchor_parent, anchor_finalized) =
            fresh_simplified_genesis_anchor_authorities(&epoch_context)?;
        let finality_environment = SimplifiedFinalityEnvironment {
            epoch_context: epoch_context.clone(),
            validator_set: validator_set.clone(),
            cluster_map: cluster_map.clone(),
            etdag_parameters: etdag_parameters.clone(),
            consensus_verifier: crypto.verifier.clone(),
            etdag_verifier: crypto.verifier.clone(),
            anchor_finalized: anchor_finalized.clone(),
            anchor_finalized_fee_market: None,
            boundary_execution_state: genesis_execution_state.clone(),
        };
        let sink =
            DurableSimplifiedFinalitySink::for_epoch(material_store.clone(), finality_environment)?;
        let epoch_start_timestamp_ms = genesis_timestamp_ms
            .checked_add(simplified_parameters.target_block_time_ms)
            .ok_or_else(|| "fresh simplified epoch start timestamp overflows".to_string())?;
        (
            anchor_parent,
            anchor_finalized,
            sink,
            genesis_execution_state,
            None,
            epoch_start_timestamp_ms,
            genesis_runtime_metadata,
        )
    };
    let protected_authority_configuration = (material_mode == SimplifiedMaterialMode::Protected)
        .then(
            || -> Result<DurableSimplifiedProtectedMaterialAuthorityConfiguration, String> {
                let anchor_finalized_fee_market =
                    match anchor_finalized.quorum_certificate_reference() {
                        None => None,
                        Some(reference) => {
                            let previous = previous_finality_replay.as_ref().ok_or_else(|| {
                            "non-Genesis simplified boundary has no previous-epoch fee authority"
                                .to_string()
                        })?;
                            let material = previous.material_store.load(reference.qc_id)?;
                            if material.stable_candidate_id != reference.qc_id
                                || material.candidate_subject.context.height != reference.height
                                || material.candidate_subject.block_id != reference.block_id
                                || material.canonical_block.candidate_id()? != reference.block_id
                            {
                                return Err(
                                "simplified boundary fee material does not match its finalized QC"
                                    .to_string(),
                            );
                            }
                            Some(SimplifiedParentFeeMarketState::from_verified_header(
                                &material.canonical_block.header,
                            )?)
                        }
                    };
                Ok(DurableSimplifiedProtectedMaterialAuthorityConfiguration {
                    epoch_context: epoch_context.clone(),
                    validator_set: validator_set.clone(),
                    cluster_map: cluster_map.clone(),
                    etdag_parameters: etdag_parameters.clone(),
                    consensus_verifier: crypto.verifier.clone(),
                    etdag_verifier: crypto.verifier.clone(),
                    anchor_finalized: anchor_finalized.clone(),
                    anchor_finalized_fee_market,
                    boundary_execution_state: finality_boundary_execution_state,
                })
            },
        )
        .transpose()?;
    let protected_authority = protected_authority_configuration
        .map(
            |configuration| match (transition_for_protected_authority, previous_finality_replay) {
                (Some(transition), Some(previous)) => {
                    DurableSimplifiedProtectedMaterialAuthority::new_from_verified_v3_transition(
                        finalization_sink.directory().to_path_buf(),
                        material_store.clone(),
                        configuration,
                        transition,
                        previous,
                    )
                }
                (None, None) => DurableSimplifiedProtectedMaterialAuthority::new(
                    finalization_sink.directory().to_path_buf(),
                    material_store.clone(),
                    configuration,
                ),
                _ => Err(
                    "protected material transition capability and replay inputs are incomplete"
                        .to_string(),
                ),
            },
        )
        .transpose()?;
    let initial_execution_state = finalization_sink.execution_state().clone();
    let target_block_time_ms = simplified_parameters.target_block_time_ms;
    let consensus_parameter_root =
        ConsensusParameterRoot::from_hex(&epoch_context.consensus_parameter_root)?;
    let protected_inputs = EtdagProtectedInputCoordinator::process_wide();
    let material_adapter: SimplifiedActivatedMaterialAdapter<
        DurableSimplifiedProtectedMaterialAuthority,
    > = if material_mode == SimplifiedMaterialMode::Protected {
        SimplifiedActivatedMaterialAdapter::Protected(SimplifiedProtectedMaterialAdapter::new(
            epoch_context.clone(),
            protected_inputs.clone(),
            SimplifiedProtectedMaterialConfiguration {
                verifier: crypto.verifier.clone(),
                validator_set: validator_set.clone(),
                etdag_cluster_map: cluster_map.clone(),
                consensus_parameter_root,
                etdag_parameters: etdag_parameters.clone(),
                cryptographic_profile_root,
                epoch_start_timestamp_ms,
                target_block_time_ms,
                app_version: runtime_metadata.app_version,
                execution_version: runtime_metadata.execution_version,
                dag_version: runtime_metadata.dag_version,
                aegis_pqvm_version: runtime_metadata.aegis_pqvm_version.clone(),
            },
            protected_authority
                .as_ref()
                .ok_or_else(|| "protected material authority is unavailable".to_string())?
                .clone(),
        )?)
    } else {
        SimplifiedActivatedMaterialAdapter::Core(SimplifiedCoreMaterialAdapter::new(
            epoch_context.clone(),
            SimplifiedCoreMaterialConfiguration {
                validator_set: validator_set.clone(),
                cluster_map: cluster_map.clone(),
                execution_state: initial_execution_state.clone(),
                parent_fee_market: None,
                cryptographic_profile_root,
                epoch_start_timestamp_ms,
                target_block_time_ms,
                app_version: runtime_metadata.app_version,
                execution_version: runtime_metadata.execution_version,
                dag_version: runtime_metadata.dag_version,
                aegis_pqvm_version: runtime_metadata.aegis_pqvm_version.clone(),
            },
        )?)
    };
    let schedule_neutral_etdag_ingress = if material_mode == SimplifiedMaterialMode::Protected {
        Some(EtdagScheduleNeutralCertifiedInputIngress::new(
            protected_inputs.clone(),
            Arc::new(
                protected_authority
                    .as_ref()
                    .ok_or_else(|| "protected material authority is unavailable".to_string())?
                    .clone(),
            ),
            crypto.verifier.clone(),
            validator_set.clone(),
            cluster_map.clone(),
            consensus_parameter_root,
            etdag_parameters.clone(),
        )?)
    } else {
        None
    };
    let target_admission_runtime = if material_mode == SimplifiedMaterialMode::Protected {
        let configuration = SimplifiedTargetAdmissionConfiguration {
            epoch_context: epoch_context.clone(),
            validator_set: validator_set.clone(),
            cluster_map: cluster_map.clone(),
            verifier: crypto.verifier.clone(),
            cryptographic_profile_root,
        };
        let frozen_validator_ids = validator_set
            .active_for_epoch(epoch_context.epoch)
            .validators
            .into_iter()
            .map(|validator| validator.validator_id)
            .collect::<std::collections::BTreeSet<_>>();
        let mut producer = SimplifiedTargetAdmissionProducer::new_process_wide(
            configuration,
            crypto.local_validator_id.clone(),
            Arc::new(Mutex::new(crypto.target_admission_signer)),
            Box::new(
                protected_authority
                    .as_ref()
                    .ok_or_else(|| "protected material authority is unavailable".to_string())?
                    .clone(),
            ),
            Box::new(DurableSimplifiedIngressKemRegistrySource::process_wide(
                epoch_context.root()?,
            )?),
        )?;
        // This is a startup preflight as well as the first durable production
        // step. An active protected profile must not start unless the exact
        // public H+3 ML-KEM registry is already provisioned.
        let initial_outputs = producer.prepare_h3()?;
        Some((producer, initial_outputs, frozen_validator_ids))
    } else {
        None
    };
    let proposal_source = DurableVerifiedSimplifiedProposalSource::new(
        epoch_context.clone(),
        material_store,
        material_adapter,
    )?;
    let egress =
        P2pSimplifiedConsensusEgress::new(Arc::clone(&network), &epoch_context, &validator_set)?;
    let state_store =
        DurableSimplifiedPosyStore::at_path(simplified_epoch_state_path(epoch_context.root()?));
    let timing = SimplifiedDriverTiming::from_activation(&activation)?;
    let mut driver = if let Some(transition) = transition_for_driver {
        SimplifiedPosyDriver::new_from_verified_v3_transition(
            transition,
            crypto.local_validator_id,
            crypto.local_key_id,
            state_store,
            DurableConsensusSigningAuthority::process_wide(),
            crypto.signer,
            crypto.verifier,
            proposal_source,
            egress,
            finalization_sink,
            timing,
        )?
    } else {
        SimplifiedPosyDriver::new(
            epoch_context,
            validator_set,
            crypto.local_validator_id,
            crypto.local_key_id,
            state_store,
            anchor_parent,
            DurableConsensusSigningAuthority::process_wide(),
            crypto.signer,
            crypto.verifier,
            proposal_source,
            egress,
            finalization_sink,
            timing,
        )?
    };

    let etdag_ingress_installed = match (etdag_activation_permit, schedule_neutral_etdag_ingress) {
        (Some(permit), Some(ingress)) => {
            install_schedule_neutral_etdag_certified_input_ingress(permit, ingress).map_err(
                |error| format!("install simplified schedule-neutral ETDAG ingress: {error}"),
            )?;
            true
        }
        (None, None) => false,
        _ => {
            return Err(
                "simplified runtime received an incomplete ETDAG activation capability".to_string(),
            )
        }
    };
    if let Err(error) = install_finalized_execution_state_snapshot(initial_execution_state) {
        if etdag_ingress_installed {
            let _ = remove_etdag_certified_input_ingress();
        }
        return Err(format!("install simplified execution snapshot: {error}"));
    }
    let receiver = match install_simplified_consensus_ingress(SIMPLIFIED_POSY_INGRESS_CAPACITY) {
        Ok(receiver) => receiver,
        Err(error) => {
            if etdag_ingress_installed {
                let _ = remove_etdag_certified_input_ingress();
            }
            remove_finalized_execution_state_snapshot();
            return Err(format!("install simplified consensus ingress: {error}"));
        }
    };

    let fatal_error = Arc::new(Mutex::new(None));
    let mut auxiliary_handles = Vec::new();
    if let Some((producer, initial_outputs, frozen_validator_ids)) = target_admission_runtime {
        if let Err(error) = install_simplified_target_admission_producer_handler(producer) {
            let _ = remove_simplified_consensus_ingress();
            if etdag_ingress_installed {
                let _ = remove_etdag_certified_input_ingress();
            }
            remove_finalized_execution_state_snapshot();
            return Err(format!(
                "install simplified target-admission producer: {error}"
            ));
        }
        let target_worker_error = Arc::clone(&fatal_error);
        let target_worker_running = Arc::clone(&running);
        let target_network = Arc::clone(&network);
        let target_handle = match thread::Builder::new()
            .name("simplified-posy-target-admission".to_string())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run_simplified_target_admission_worker(
                        initial_outputs,
                        &target_network,
                        &frozen_validator_ids,
                        &target_worker_running,
                    )
                }));
                let failure = match result {
                    Ok(Ok(_)) => None,
                    Ok(Err(error)) => Some(error),
                    Err(_) => Some("simplified target-admission worker panicked".to_string()),
                };
                if let Some(error) = failure {
                    eprintln!("Simplified target-admission worker failed closed: {error}");
                    if let Ok(mut slot) = target_worker_error.lock() {
                        if slot.is_none() {
                            *slot = Some(error);
                        }
                    }
                    target_worker_running.store(false, Ordering::Release);
                }
                let _ = remove_simplified_target_admission_producer_handler();
            }) {
            Ok(handle) => handle,
            Err(error) => {
                let _ = remove_simplified_target_admission_producer_handler();
                let _ = remove_simplified_consensus_ingress();
                if etdag_ingress_installed {
                    let _ = remove_etdag_certified_input_ingress();
                }
                remove_finalized_execution_state_snapshot();
                return Err(format!("spawn simplified target-admission worker: {error}"));
            }
        };
        auxiliary_handles.push(target_handle);
    }

    let worker_error = Arc::clone(&fatal_error);
    let worker_running = Arc::clone(&running);
    let handle = match thread::Builder::new()
        .name("simplified-posy-driver".to_string())
        .spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run_simplified_posy_driver(&mut driver, &receiver, &worker_running)
            }));
            let failure = match result {
                Ok(Ok(_)) => None,
                Ok(Err(error)) => Some(error),
                Err(_) => Some("simplified PoSy driver worker panicked".to_string()),
            };
            if let Some(error) = failure {
                eprintln!("Finalized simplified PoSy worker failed closed: {error}");
                if let Ok(mut slot) = worker_error.lock() {
                    *slot = Some(error);
                }
                worker_running.store(false, Ordering::Release);
            }
            let _ = remove_simplified_consensus_ingress();
            if etdag_ingress_installed {
                let _ = remove_etdag_certified_input_ingress();
            }
            remove_finalized_execution_state_snapshot();
        }) {
        Ok(handle) => handle,
        Err(error) => {
            running.store(false, Ordering::Release);
            for auxiliary_handle in auxiliary_handles.drain(..) {
                let _ = auxiliary_handle.join();
            }
            let _ = remove_simplified_consensus_ingress();
            if etdag_ingress_installed {
                let _ = remove_etdag_certified_input_ingress();
            }
            remove_finalized_execution_state_snapshot();
            return Err(format!("spawn simplified PoSy driver worker: {error}"));
        }
    };
    Ok(FinalizedPosyWorker {
        handle,
        auxiliary_handles,
        fatal_error,
    })
}

/// Resolves the only consensus profile authorized for the durable next
/// height. Fresh canonical Genesis supplies the complete block-one authority;
/// restart advancement is derived only from verified simplified finality.
/// Nothing in this path reads an activation environment variable, wall clock,
/// typed-finality store, or local preference.
fn resolve_finalized_consensus_profile() -> Result<ConsensusProfileAtHeight, String> {
    let genesis = canonical_genesis()
        .map_err(|error| format!("consensus profile cannot load canonical Genesis: {error}"))?;
    let activation = load_genesis_bound_simplified_activation(genesis.value())?
        .ok_or_else(|| "canonical Genesis is missing simplified PoSy activation".to_string())?;
    let selected = select_consensus_profile_at_height(Height(1), Some(&activation))?;
    let ConsensusProfileAtHeight::PosySimplifiedV3 {
        mut epoch_context,
        mut validator_set,
    } = selected;

    // Once simplified safety state exists, its fully verified durable QC head
    // is the only authority for the next consensus height. Walk only adjacent,
    // fully verified v3 transitions; a fresh chain never imports an earlier
    // consensus engine's finality.
    for _ in 0..1_024 {
        let state_store =
            DurableSimplifiedPosyStore::at_path(simplified_epoch_state_path(epoch_context.root()?));
        if !state_store.path().exists() {
            return Ok(ConsensusProfileAtHeight::PosySimplifiedV3 {
                epoch_context,
                validator_set,
            });
        }
        let simplified_next_height = state_store.load(&epoch_context)?.next_height()?;
        if epoch_context.contains_height(simplified_next_height) {
            return Ok(ConsensusProfileAtHeight::PosySimplifiedV3 {
                epoch_context,
                validator_set,
            });
        }
        if simplified_next_height.0
            != epoch_context
                .epoch_end_height
                .0
                .checked_add(1)
                .ok_or_else(|| "simplified epoch end height overflows".to_string())?
        {
            return Err(
                "durable simplified safety state advanced beyond its frozen epoch without an adjacent transition"
                    .to_string(),
            );
        }

        let consensus_verifier =
            build_simplified_consensus_verifier(&epoch_context, &validator_set)?;
        let authority_store =
            DurableSimplifiedProposalMaterialStore::for_epoch(epoch_context.root()?)?;
        let authority_verifier =
            DurableSimplifiedProtectedExecutionTransitionAuthorityVerifier::new(authority_store);
        let transition = load_next_local_verified_simplified_transition(
            &epoch_context,
            &validator_set,
            &consensus_verifier,
            &authority_verifier,
        )?;
        let next = select_consensus_profile_from_verified_v3_transition(
            simplified_next_height,
            &transition,
        )?;
        let ConsensusProfileAtHeight::PosySimplifiedV3 {
            epoch_context: next_context,
            validator_set: next_set,
        } = next;
        epoch_context = next_context;
        validator_set = next_set;
    }
    Err("durable simplified transition chain exceeds 1024 epochs".to_string())
}

fn validate_simplified_frozen_identity_authority<F>(
    epoch_context: &SimplifiedEpochContext,
    validator_set: &ValidatorSet,
    genesis_validator_set: Option<&ValidatorSet>,
    signed_transport_for: F,
) -> Result<(), String>
where
    F: Fn(&str) -> Option<String>,
{
    if *validator_set != validator_set.canonicalized() {
        return Err("frozen simplified validator set is not canonical".to_string());
    }
    epoch_context.validate_against(validator_set)?;
    if epoch_context.v3_transition_anchor.is_some() {
        // Constructing the verifier rechecks every frozen Aegis key and its
        // exact UMA/epoch lifecycle. Membership itself comes only from the
        // verified transition; the mutable validator manager is not queried.
        let _verifier = build_simplified_consensus_verifier(epoch_context, validator_set)?;
        for validator in &validator_set
            .active_for_epoch(epoch_context.epoch)
            .validators
        {
            let address = validator.validator_uma_id.0.trim();
            if address.is_empty() {
                return Err(format!(
                    "transition validator {} has no frozen UMA identity",
                    validator.validator_id.0
                ));
            }
            let transport = signed_transport_for(address).ok_or_else(|| {
                format!(
                    "transition validator {} ({address}) has no coordinator-signed transport",
                    validator.validator_id.0
                )
            })?;
            if transport.trim().is_empty() {
                return Err(format!(
                    "transition validator {} ({address}) has an empty signed transport",
                    validator.validator_id.0
                ));
            }
        }
        return Ok(());
    }

    // Preserve the one-time v2->v3 activation authority: every identity and
    // consensus key must still equal the immutable Genesis bootstrap.
    let genesis_validator_set = genesis_validator_set.ok_or_else(|| {
        "initial simplified epoch requires the Genesis validator authority".to_string()
    })?;
    for frozen in &validator_set.validators {
        let transport = genesis_validator_set
            .validators
            .iter()
            .find(|validator| validator.validator_id == frozen.validator_id)
            .ok_or_else(|| {
                format!(
                    "frozen v3 validator {} has no Genesis-authenticated transport identity",
                    frozen.validator_id.0
                )
            })?;
        if transport.validator_uma_id != frozen.validator_uma_id
            || transport.consensus_public_key != frozen.consensus_public_key
        {
            return Err(format!(
                "frozen v3 validator {} does not match its Genesis-authenticated UMA/key binding",
                frozen.validator_id.0
            ));
        }
    }
    Ok(())
}

fn ensure_finalized_consensus_profile_ready(
    config: &NodeConfig,
) -> Result<ConsensusProfileAtHeight, String> {
    let profile = resolve_finalized_consensus_profile()?;
    let ConsensusProfileAtHeight::PosySimplifiedV3 {
        epoch_context,
        validator_set,
    } = &profile;
    if epoch_context.v3_transition_anchor.is_some() {
        validate_simplified_frozen_identity_authority(
            epoch_context,
            validator_set,
            None,
            p2p::validator_transport_registry::validator_transport_for,
        )?;
    } else {
        // The initial membership authority is the activation record already
        // committed by canonical Genesis.  It must not be reinterpreted
        // through the retired Testnet-v3 bootstrap (which carries an old
        // chain's membership and transport topology).
        validate_simplified_frozen_identity_authority(
            epoch_context,
            validator_set,
            Some(validator_set),
            |_| None,
        )?;
    }
    let validator_address = resolve_local_validator_address(config);
    ensure_local_validator_record_available(&validator_address)?;
    let (_, local_private_key) = load_local_validator_keypair_for_height(
        epoch_context.epoch_start_height.0,
        &validator_address,
        &VALIDATOR_MANAGER,
    )
    .map_err(|error| {
        format!("simplified PoSy startup cannot load the canonical local ML-DSA-65 key: {error}")
    })?;
    let local = validator_set
        .validators
        .iter()
        .find(|validator| validator.validator_uma_id.0 == validator_address)
        .ok_or_else(|| {
            format!(
                "local validator {validator_address} is absent from the frozen v3 epoch context"
            )
        })?;
    if local_private_key.public_key_id != local.consensus_public_key.key_id.0 {
        return Err(
            "local validator private key does not match the frozen v3 consensus key".to_string(),
        );
    }
    Ok(profile)
}

fn ensure_consensus_pqc_runtime_ready(config: &NodeConfig) -> Result<(), String> {
    if config.blockchain.chain_id != 1266 || config.network.id != 1266 {
        return Err(format!(
            "validator consensus requires Testnet chain_id 1266, found blockchain.chain_id={} network.id={}",
            config.blockchain.chain_id, config.network.id
        ));
    }
    if config.network.network_id != TESTNET_V3_CANONICAL_NETWORK_ID {
        return Err(format!(
            "validator consensus requires network_id {TESTNET_V3_CANONICAL_NETWORK_ID}, found {}",
            config.network.network_id,
        ));
    }
    let mode = config
        .consensus
        .resolve_mode(config.blockchain.chain_id, &config.network.network_id)?;
    if config.consensus.allow_genesis_status_bypass {
        return Err("validator consensus refuses genesis status bypass configuration".to_string());
    }
    match mode {
        ResolvedConsensusMode::PosySimplifiedV3 => {
            let genesis = canonical_genesis().map_err(|error| {
                format!("validator consensus cannot load canonical Genesis: {error}")
            })?;
            let activation = load_genesis_bound_simplified_activation(genesis.value())?
                .ok_or_else(|| {
                    "validator consensus canonical Genesis lacks fresh simplified activation"
                        .to_string()
                })?;
            if activation.manifest.protocol_version
                != crate::consensus::simplified_posy::POSY_SIMPLIFIED_PROTOCOL_VERSION
            {
                return Err("validator consensus activation does not select posy/3.0".to_string());
            }
        }
        ResolvedConsensusMode::CoordinatedRoundRobinV1(_) => {
            return Err(
                "fresh Testnet-v3 consensus refuses coordinated-round-robin runtime selection"
                    .to_string(),
            );
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
    eprintln!("    preflight-release     Verify the complete signed release binding without opening state");
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
        "    --chain-id 1266 --network-id testnet --genesis-hash {}",
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
        "start" | "preflight-release" => {
            let preflight_only = subcommand == "preflight-release";
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
            let release_id = crate::desired_state::verify_chain1266_desired_state(
                desired_role_profile,
                &config.identity.node_id,
                &effective_config_path,
            )
            .unwrap_or_else(|error| {
                eprintln!("Failed to validate Chain 1266 desired state: {error}");
                process::exit(1);
            });

            if preflight_only {
                let genesis = canonical_genesis().unwrap_or_else(|error| {
                    eprintln!("Release preflight cannot load canonical Genesis: {error}");
                    process::exit(1);
                });
                ensure_node_config_matches_finalized_consensus_parameters(&config, genesis)
                    .unwrap_or_else(|error| {
                        eprintln!(
                            "Release preflight configuration disagrees with Genesis: {error}"
                        );
                        process::exit(1);
                    });
                resolved_consensus_runtime_preflight(&config).unwrap_or_else(|error| {
                    eprintln!("Release preflight consensus profile failed closed: {error}");
                    process::exit(1);
                });
                ensure_genesis_validator_membership_available().unwrap_or_else(|error| {
                    eprintln!("Release preflight cannot load Genesis membership: {error}");
                    process::exit(1);
                });
                if !local_validator_is_consensus_authorized(&config) {
                    eprintln!(
                        "Release preflight local validator is not active in the Genesis-bound set"
                    );
                    process::exit(1);
                }
                let validator_address = resolve_local_validator_address(&config);
                crate::consensus::validator_keys::load_local_validator_keypair(
                    &validator_address,
                    &VALIDATOR_MANAGER,
                )
                .unwrap_or_else(|error| {
                    eprintln!("Release preflight consensus custody check failed: {error}");
                    process::exit(1);
                });
                println!(
                    "CHAIN1266_ROLE_RELEASE_PREFLIGHT_VERIFIED release_id={} node_id={} validator_address={} profile={}",
                    release_id,
                    config.identity.node_id,
                    validator_address,
                    desired_role_profile.compiled_profile
                );
                return;
            }

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
                    Ok(ResolvedConsensusMode::PosySimplifiedV3) | Err(_) => {
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

            // Resolve immutable consensus authority before membership gating.
            // At v3 the frozen epoch context, not mutable v2 state,
            // decides whether this local validator may load signing custody.
            let finalized_profile_authority =
                if is_validator_profile(role_profile) && !config.node.bootstrap_only {
                    Some(
                        resolve_finalized_consensus_profile().unwrap_or_else(|error| {
                            eprintln!("Consensus profile selection failed closed: {error}");
                            process::exit(1);
                        }),
                    )
                } else {
                    None
                };
            let consensus_enabled = should_start_consensus_for_finalized_profile(
                &config,
                role_profile,
                finalized_profile_authority.as_ref(),
            );
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
            let initial_consensus_startup = select_finalized_consensus_driver_startup(
                consensus_enabled,
                p2p_network.is_some(),
                consensus_enabled.then(|| ensure_finalized_consensus_profile_ready(&config)),
            );
            if consensus_enabled && is_validator_profile(role_profile) {
                let (required_remote_validators, frozen_validator_ids) =
                    match initial_consensus_startup.as_ref() {
                        Ok(FinalizedConsensusDriverStartup::SpawnSimplifiedV3Driver {
                            validator_set,
                            ..
                        }) => {
                            let (required_remote_validators, frozen_validator_ids) =
                                simplified_v3_startup_peer_readiness(validator_set)
                                    .unwrap_or_else(|error| {
                                        eprintln!(
                                            "Consensus startup failed closed: invalid simplified v3 peer readiness policy: {error}"
                                        );
                                        process::exit(1);
                                    });
                            (required_remote_validators, Some(frozen_validator_ids))
                        }
                        _ => (genesis.validators().len().checked_sub(1).unwrap_or(0), None),
                    };
                let network = p2p_network.as_ref().unwrap_or_else(|| {
                    eprintln!(
                        "Consensus startup failed closed: finalized typed PoSy requires an active P2P network"
                    );
                    process::exit(1);
                });
                info!(
                    "main",
                    "Waiting for finalized typed PoSy peer readiness",
                    "required_remote_validators" => required_remote_validators as u64
                );
                wait_for_finalized_typed_peer_readiness(
                    network,
                    required_remote_validators,
                    frozen_validator_ids.as_ref(),
                )
                .unwrap_or_else(|error| {
                    eprintln!("Consensus startup failed closed: {error}");
                    process::exit(1);
                });
            }
            let consensus_worker = match initial_consensus_startup {
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
                Ok(FinalizedConsensusDriverStartup::SpawnSimplifiedV3Driver {
                    epoch_context,
                    validator_set,
                }) => {
                    info!(
                        "main",
                        "Starting finalized simplified PoSy consensus worker",
                        "epoch" => epoch_context.epoch.0,
                        "validator_count" => validator_set.validators.len() as u64
                    );
                    let network = match p2p_network.as_ref().cloned() {
                        Some(network) => network,
                        None => {
                            eprintln!(
                                "Consensus startup failed closed: simplified PoSy requires an active P2P network"
                            );
                            process::exit(1);
                        }
                    };
                    match spawn_finalized_simplified_posy_driver(
                        &config,
                        epoch_context,
                        validator_set,
                        network,
                        Arc::clone(&running),
                    ) {
                        Ok(worker) => Some(FinalizedConsensusWorker::Simplified(worker)),
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
            // Fresh simplified PoSy membership is immutable for its epoch.
            // A mutable validator-manager activation must never start a
            // legacy or substitute worker after this point.
            let watch_for_activation_consensus = false;

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
                if consensus_worker.is_none() && watch_for_activation_consensus {
                    eprintln!(
                        "Consensus activation failed closed: mutable validator activation is retired; restart with a governed simplified epoch context"
                    );
                    running.store(false, Ordering::SeqCst);
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
                match generate_class_based_address(pk.as_bytes(), class) {
                    Ok(address) => address,
                    Err(error) => {
                        eprintln!("Error: generated key cannot own a canonical validator address: {error}");
                        process::exit(1);
                    }
                }
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
    use crate::consensus::simplified_posy::{
        test_simplified_transition_proof, TestSimplifiedConsensusVerifier,
        TestSimplifiedTransitionAuthorityVerifier,
    };
    use crate::genesis::load_genesis_from_path;
    use std::fs;
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    static COORDINATED_POOL_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn simplified_readiness_validator_ids(
        validator_ids: &[&str],
    ) -> std::collections::BTreeSet<crate::synergy_types::ValidatorId> {
        validator_ids
            .iter()
            .map(|validator_id| crate::synergy_types::ValidatorId((*validator_id).to_string()))
            .collect()
    }

    fn simplified_readiness_validator_set(validator_ids: &[&str]) -> ValidatorSet {
        ValidatorSet {
            epoch: crate::synergy_types::Epoch(9),
            validators: validator_ids
                .iter()
                .enumerate()
                .map(|(index, validator_id)| {
                    let key = crate::synergy_types::AegisPqPublicKey {
                        key_id: crate::synergy_types::AegisPqKeyId(format!(
                            "startup-readiness-key-{index}"
                        )),
                        algorithm: crate::synergy_types::TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM
                            .to_string(),
                        key_bytes: vec![
                            7;
                            crate::synergy_types::TESTNET_V3_MLDSA65_PUBLIC_KEY_BYTES
                        ],
                    };
                    crate::synergy_types::ValidatorRecord {
                        validator_id: crate::synergy_types::ValidatorId(
                            (*validator_id).to_string(),
                        ),
                        validator_uma_id: crate::synergy_types::UmaId(format!(
                            "uma:startup-readiness-{index}"
                        )),
                        consensus_public_key: key.clone(),
                        peer_public_key: key.clone(),
                        operator_public_key: key,
                        voting_weight: 1,
                        status: crate::synergy_types::ValidatorStatus::Active,
                        cluster_id: crate::synergy_types::ClusterId(0),
                        activation_epoch: crate::synergy_types::Epoch(9),
                    }
                })
                .collect(),
        }
    }

    struct EnvRestore {
        project_root: Option<String>,
        config_path: Option<String>,
        data_path: Option<String>,
    }

    impl EnvRestore {
        fn capture() -> Self {
            Self {
                project_root: env::var("SYNERGY_PROJECT_ROOT").ok(),
                config_path: env::var("SYNERGY_CONFIG_PATH").ok(),
                data_path: env::var("SYNERGY_DATA_PATH").ok(),
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
            match &self.data_path {
                Some(value) => env::set_var("SYNERGY_DATA_PATH", value),
                None => env::remove_var("SYNERGY_DATA_PATH"),
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
    fn later_v3_transition_loader_reverifies_restart_and_rejects_substitution() {
        let _env_guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("environment lock");
        let _restore = EnvRestore::capture();
        let data_root = unique_test_workspace("v3-transition-loader");
        env::set_var("SYNERGY_DATA_PATH", &data_root);

        let proof = test_simplified_transition_proof();
        let verified = proof
            .verify(
                &TestSimplifiedConsensusVerifier,
                &TestSimplifiedTransitionAuthorityVerifier,
            )
            .expect("test transition verifies");
        let selected_context = verified.next_epoch_context().clone();
        let selected_set = verified.next_validator_set().clone();
        let path = simplified_epoch_transition_path(
            verified
                .previous_epoch_context()
                .root()
                .expect("previous root"),
        );
        let store = DurableSimplifiedEpochTransitionStore::at_path(&path);
        store
            .install_or_load(
                &proof,
                &TestSimplifiedConsensusVerifier,
                &TestSimplifiedTransitionAuthorityVerifier,
            )
            .expect("install durable transition");

        let load = || {
            load_local_verified_simplified_transition(
                &selected_context,
                &selected_set,
                &TestSimplifiedTransitionAuthorityVerifier,
                |_previous_context, _previous_set| Ok(TestSimplifiedConsensusVerifier),
            )
        };
        let first = load().expect("startup loads verified transition");
        let restarted = load().expect("restart reverifies the same transition");
        assert_eq!(
            first.transition_subject_root(),
            restarted.transition_subject_root()
        );
        assert_eq!(first.certified_parent(), restarted.certified_parent());
        assert_eq!(first.finalized_seed(), restarted.finalized_seed());

        let mut substituted = proof.clone();
        substituted.authority_evidence.push(0xff);
        fs::write(
            &path,
            substituted
                .canonical_record_bytes()
                .expect("canonical substituted proof"),
        )
        .expect("replace temporary transition proof");
        let error = load().expect_err("substituted authority must be rejected");
        assert!(error.contains("transition subject is not committed by finalized execution"));

        fs::write(
            &path,
            proof.canonical_record_bytes().expect("canonical proof"),
        )
        .expect("restore temporary transition proof");
        let production_error = load_local_verified_simplified_transition(
            &selected_context,
            &selected_set,
            &FailClosedSimplifiedTransitionAuthorityVerifier,
            |_previous_context, _previous_set| Ok(TestSimplifiedConsensusVerifier),
        )
        .expect_err("production authority must remain unavailable");
        assert!(production_error
            .contains("disabled until finalized execution supplies a transition-commitment proof"));
    }

    #[test]
    fn verified_five_to_seven_profile_uses_frozen_keys_and_signed_transports() {
        let proof = test_simplified_transition_proof();
        let verified = proof
            .verify(
                &TestSimplifiedConsensusVerifier,
                &TestSimplifiedTransitionAuthorityVerifier,
            )
            .expect("test transition verifies");
        assert_eq!(verified.previous_validator_set().validators.len(), 5);
        assert_eq!(verified.next_validator_set().validators.len(), 7);
        let previous_ids = verified
            .previous_validator_set()
            .validators
            .iter()
            .map(|validator| validator.validator_id.clone())
            .collect::<std::collections::BTreeSet<_>>();
        let newly_onboarded = verified
            .next_validator_set()
            .validators
            .iter()
            .filter(|validator| !previous_ids.contains(&validator.validator_id))
            .collect::<Vec<_>>();
        assert_eq!(newly_onboarded.len(), 2);

        let mut transports = verified
            .next_validator_set()
            .validators
            .iter()
            .enumerate()
            .map(|(index, validator)| {
                (
                    validator.validator_uma_id.0.clone(),
                    format!("10.69.10.{}:5622", index + 1),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        let validate =
            |set: &ValidatorSet, transports: &std::collections::BTreeMap<String, String>| {
                validate_simplified_frozen_identity_authority(
                    verified.next_epoch_context(),
                    set,
                    None,
                    |address| transports.get(address).cloned(),
                )
            };
        validate(verified.next_validator_set(), &transports)
            .expect("transition-frozen 5->7 set with signed transports is accepted");

        let missing_address = newly_onboarded[0].validator_uma_id.0.clone();
        let missing_transport = transports
            .remove(&missing_address)
            .expect("new validator transport exists");
        let missing_error = validate(verified.next_validator_set(), &transports)
            .expect_err("new validator without a signed transport must fail");
        assert!(missing_error.contains("has no coordinator-signed transport"));

        transports.insert(
            "uma:substituted-onboarding-validator".to_string(),
            missing_transport,
        );
        let substituted_transport_error = validate(verified.next_validator_set(), &transports)
            .expect_err("a transport under a substituted UMA must fail");
        assert!(substituted_transport_error.contains("has no coordinator-signed transport"));

        transports.insert(missing_address, "10.69.10.6:5622".to_string());
        let mut substituted_key_set = verified.next_validator_set().clone();
        substituted_key_set
            .validators
            .iter_mut()
            .find(|validator| validator.validator_id == newly_onboarded[1].validator_id)
            .expect("second new validator")
            .consensus_public_key
            .key_bytes[0] ^= 0xff;
        let key_error = validate(&substituted_key_set, &transports)
            .expect_err("a substituted frozen consensus key must fail");
        assert!(key_error.contains("validator") || key_error.contains("context"));

        let mut substituted_uma_set = verified.next_validator_set().clone();
        substituted_uma_set
            .validators
            .iter_mut()
            .find(|validator| validator.validator_id == newly_onboarded[1].validator_id)
            .expect("second new validator")
            .validator_uma_id =
            crate::synergy_types::UmaId("uma:substituted-frozen-identity".to_string());
        let uma_error = validate(&substituted_uma_set.canonicalized(), &transports)
            .expect_err("a substituted frozen UMA must fail");
        assert!(uma_error.contains("validator") || uma_error.contains("context"));
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
        assert!(
            !source.contains("FinalizedConsensusDriverStartup::SpawnFinalizedTypedDriver"),
            "the production role runtime must not expose a typed PoSy dispatcher variant"
        );
        assert!(
            source.contains("spawn_coordinated_round_robin_driver("),
            "the production role runtime must retain the separate P1 coordinated-driver entry point"
        );
        assert!(
            source.contains("spawn_finalized_simplified_posy_driver("),
            "the production role runtime must retain the finalized simplified-driver entry point"
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
    fn finalized_simplified_driver_startup_fails_closed_without_p2p_or_finalized_inputs() {
        let no_p2p = select_finalized_consensus_driver_startup(
            true,
            false,
            Some(Err("missing canonical fresh-genesis authority".to_string())),
        )
        .expect_err("consensus startup without P2P must fail closed");
        assert!(no_p2p.contains("active P2P network"));

        let invalid_finalized_inputs = select_finalized_consensus_driver_startup(
            true,
            true,
            Some(Err("missing canonical finality context".to_string())),
        )
        .expect_err("consensus startup with invalid finalized inputs must fail closed");
        assert!(invalid_finalized_inputs.contains("missing canonical finality context"));
    }

    #[test]
    fn fresh_runtime_rejects_coordinator_mode_before_genesis_io() {
        let mut config = NodeConfig::default();
        config.consensus.mode =
            crate::consensus::coordinated_round_robin::COORDINATED_ROUND_ROBIN_V1.to_string();
        config.consensus.coordinator_id = "validator-01".to_string();
        config.consensus.producer_ids = vec![
            "validator-02".to_string(),
            "validator-03".to_string(),
            "validator-04".to_string(),
            "validator-05".to_string(),
            "validator-06".to_string(),
        ];

        let error = resolved_consensus_runtime_preflight(&config)
            .expect_err("fresh Testnet-v3 must reject coordinator mode before Genesis I/O");
        assert!(error.contains("refuses coordinated-round-robin runtime selection"));
    }

    #[test]
    fn finalized_v3_profile_selects_only_the_simplified_driver() {
        let roots = Hash::from_domain_bytes("role-runtime-v3", b"selector");
        let context = SimplifiedEpochContext {
            schema_version: 1,
            chain_id: crate::synergy_types::ChainId::synergy_testnet_v3(),
            network_id: crate::synergy_types::NetworkId::synergy_testnet_v3(),
            protocol_version: "posy/3.0".to_string(),
            epoch: crate::synergy_types::Epoch(9),
            epoch_start_height: Height(9_001),
            epoch_end_height: Height(10_000),
            finalized_epoch_seed_root: roots,
            v2_boundary_anchor: None,
            v3_transition_anchor: None,
            consensus_parameter_root: "11".repeat(64),
            active_validator_set_root: roots,
            validator_consensus_key_root: roots,
            frozen_voting_weight_root: roots,
            leader_lease_blocks: 10,
            leader_ring: Vec::new(),
            leader_ring_root: roots,
        };
        let frozen_address = "uma:frozen-v3-role-test";
        let key = crate::synergy_types::AegisPqPublicKey {
            key_id: crate::synergy_types::AegisPqKeyId("frozen-v3-role-key".to_string()),
            algorithm: crate::synergy_types::TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM.to_string(),
            key_bytes: vec![7; crate::synergy_types::TESTNET_V3_MLDSA65_PUBLIC_KEY_BYTES],
        };
        let validators = ValidatorSet {
            epoch: crate::synergy_types::Epoch(9),
            validators: vec![crate::synergy_types::ValidatorRecord {
                validator_id: crate::synergy_types::ValidatorId(
                    "frozen-v3-role-validator".to_string(),
                ),
                validator_uma_id: crate::synergy_types::UmaId(frozen_address.to_string()),
                consensus_public_key: key.clone(),
                peer_public_key: key.clone(),
                operator_public_key: key,
                voting_weight: 1,
                status: crate::synergy_types::ValidatorStatus::Active,
                cluster_id: crate::synergy_types::ClusterId(0),
                activation_epoch: crate::synergy_types::Epoch(9),
            }],
        };
        let profile = ConsensusProfileAtHeight::PosySimplifiedV3 {
            epoch_context: context.clone(),
            validator_set: validators.clone(),
        };
        let mut config = NodeConfig::default();
        config.node.validator_address = frozen_address.to_string();
        assert!(should_start_consensus_for_finalized_profile(
            &config,
            Some(NodeRole::Validator.profile()),
            Some(&profile),
        ));
        config.node.validator_address = "uma:not-in-frozen-v3".to_string();
        assert!(!should_start_consensus_for_finalized_profile(
            &config,
            Some(NodeRole::Validator.profile()),
            Some(&profile),
        ));
        let startup =
            select_finalized_consensus_driver_startup(true, true, Some(Ok(profile))).unwrap();
        assert_eq!(
            startup,
            FinalizedConsensusDriverStartup::SpawnSimplifiedV3Driver {
                epoch_context: context,
                validator_set: validators,
            }
        );
    }

    #[test]
    fn simplified_v3_startup_readiness_derives_two_remotes_for_four_validators() {
        let validator_ids = ["validator-1", "validator-2", "validator-3", "validator-4"];
        let validator_set = simplified_readiness_validator_set(&validator_ids);

        assert_eq!(
            simplified_v3_startup_peer_readiness(&validator_set).unwrap(),
            (2, simplified_readiness_validator_ids(&validator_ids))
        );
    }

    #[test]
    fn simplified_v3_startup_readiness_derives_three_remotes_for_five_validators() {
        let validator_ids = [
            "validator-1",
            "validator-2",
            "validator-3",
            "validator-4",
            "validator-5",
        ];
        let validator_set = simplified_readiness_validator_set(&validator_ids);

        assert_eq!(
            simplified_v3_startup_peer_readiness(&validator_set).unwrap(),
            (3, simplified_readiness_validator_ids(&validator_ids))
        );
    }

    #[test]
    fn simplified_v3_startup_readiness_derives_four_remotes_for_seven_validators() {
        let validator_ids = [
            "validator-1",
            "validator-2",
            "validator-3",
            "validator-4",
            "validator-5",
            "validator-6",
            "validator-7",
        ];
        let validator_set = simplified_readiness_validator_set(&validator_ids);

        assert_eq!(
            simplified_v3_startup_peer_readiness(&validator_set).unwrap(),
            (4, simplified_readiness_validator_ids(&validator_ids))
        );
    }

    #[test]
    fn simplified_v3_startup_readiness_does_not_count_outsiders() {
        let frozen_validator_ids = simplified_readiness_validator_ids(&[
            "validator-1",
            "validator-2",
            "validator-3",
            "validator-4",
            "validator-5",
        ]);
        let ready_validator_ids =
            simplified_readiness_validator_ids(&["validator-1", "validator-2", "outsider"]);

        assert_eq!(
            ready_frozen_simplified_validator_count(&ready_validator_ids, &frozen_validator_ids),
            2
        );
    }

    #[test]
    fn simplified_v3_startup_readiness_rejects_insufficient_frozen_remotes() {
        let validator_ids = [
            "validator-1",
            "validator-2",
            "validator-3",
            "validator-4",
            "validator-5",
        ];
        let validator_set = simplified_readiness_validator_set(&validator_ids);
        let (required_remote_validators, frozen_validator_ids) =
            simplified_v3_startup_peer_readiness(&validator_set).unwrap();
        let ready_validator_ids =
            simplified_readiness_validator_ids(&["validator-1", "validator-2"]);

        assert!(
            ready_frozen_simplified_validator_count(&ready_validator_ids, &frozen_validator_ids)
                < required_remote_validators
        );
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
        let permit = resolve_finalized_etdag_startup_activation(
            parameters,
            crate::synergy_types::Epoch(0),
            None,
        )
        .unwrap();
        assert!(permit.is_none());
        assert_eq!(
            select_simplified_material_mode(permit.as_ref()),
            SimplifiedMaterialMode::Core
        );
    }

    #[test]
    fn finalized_etdag_permit_selects_only_the_protected_material_mode() {
        let permit = EtdagActivationPermit::test_only();
        assert_eq!(
            select_simplified_material_mode(Some(&permit)),
            SimplifiedMaterialMode::Protected
        );
    }

    fn snapshot_args(extra: &[&str]) -> Vec<String> {
        let mut args = vec![
            "synergy-testnet".to_string(),
            "create-snapshot".to_string(),
            "--chain-id".to_string(),
            "1266".to_string(),
            "--network-id".to_string(),
            "testnet".to_string(),
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
            "testnet".to_string(),
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
            "testnet".to_string(),
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
            "testnet".to_string(),
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
            "testnet".to_string(),
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
        assert!(error.contains("expected testnet"));
    }

    #[test]
    fn snapshot_operator_args_require_genesis_hash() {
        let args = vec![
            "synergy-testnet".to_string(),
            "create-snapshot".to_string(),
            "--chain-id".to_string(),
            "1266".to_string(),
            "--network-id".to_string(),
            "testnet".to_string(),
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
            "--network-id=testnet".to_string(),
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
