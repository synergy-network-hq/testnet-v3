use std::any::Any;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{self, Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::config::{
    list_available_templates, load_node_config, load_node_config_from_template, NodeConfig,
};
use crate::consensus::cartel_detection::{CartelDetectionEngine, WhistleblowerSystem};
use crate::consensus::consensus_algorithm::ProofOfSynergy;
use crate::consensus::consensus_fork;
use crate::consensus::dao_governance::{DAOGovernance, SynergyOracle};
use crate::consensus::dual_quorum::{EntropyBeacon, ValidatorRotation};
use crate::consensus::self_realign::{
    persisted_recovery_state, RealignmentState, EXPECTED_GENESIS_HASH,
};
use crate::consensus::synergy_score::SynergyScoreCalculator;
use crate::consensus::validator_keys::{
    load_local_validator_keypair_for_height, validator_public_key_with_declared_algorithm,
};
use crate::crypto::pqc::PQCManager;
use crate::genesis::canonical_genesis;
use crate::logging::{init_logger, LogLevel};
use crate::p2p;
use crate::role_profiles::{resolve_configured_role, NodeRole, RoleProfile};
use crate::rpc;
use crate::rpc::rpc_server::{SHARED_CHAIN, SYNC_MANAGER, TX_POOL};
use crate::sxcp;
use crate::sync::SyncManager;
use crate::synergy_types::{SYNERGY_TESTNET_V3_CHAIN_ID, SYNERGY_TESTNET_V3_NETWORK_ID};
use crate::telemetry;
use crate::token::TOKEN_MANAGER;
use crate::transaction::Transaction;
use crate::utils;
use crate::validator::{consensus_membership_validators, ValidatorRegistration, VALIDATOR_MANAGER};
use crate::wallet;
use crate::{info, warn};
use serde::Deserialize;
use serde_json::json;

const OFFLINE_SNAPSHOT_COMMAND_STACK_BYTES: usize = 64 * 1024 * 1024;

struct RoleProcessGuard {
    child: Mutex<Child>,
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
        .ok_or_else(|| "missing --chain-id 1264".to_string())?
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
        .ok_or_else(|| format!("missing --genesis-hash {EXPECTED_GENESIS_HASH}"))?;
    if !genesis_hash.eq_ignore_ascii_case(EXPECTED_GENESIS_HASH) {
        return Err(format!(
            "wrong genesis_hash {genesis_hash}; expected {EXPECTED_GENESIS_HASH}"
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

fn spawn_consensus_engine() -> thread::JoinHandle<()> {
    thread::spawn(|| {
        let mut consensus = ProofOfSynergy::new();
        consensus.initialize();
        consensus.execute();
    })
}

fn ensure_consensus_pqc_runtime_ready(config: &NodeConfig) -> Result<(), String> {
    if config.blockchain.chain_id != 1264 || config.network.id != 1264 {
        return Err(format!(
            "validator consensus requires Testnet chain_id 1264, found blockchain.chain_id={} network.id={}",
            config.blockchain.chain_id, config.network.id
        ));
    }
    if config.network.network_id != "synergy-testnet-v3" {
        return Err(format!(
            "validator consensus requires network_id synergy-testnet-v3, found {}",
            config.network.network_id
        ));
    }
    if config.consensus.allow_genesis_status_bypass {
        return Err("validator consensus refuses genesis status bypass configuration".to_string());
    }
    ensure_local_validator_consensus_key_bound(config)
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
        "    --chain-id 1264 --network-id synergy-testnet-v3 --genesis-hash {}",
        EXPECTED_GENESIS_HASH
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
        let path = std::env::temp_dir().join(unique);
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
                "signature_algorithm":"fndsa"
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
            if let Some(profile) = role_profile {
                info!(
                    "main",
                    "Validated role-bound runtime profile",
                    "role_id" => profile.role_id,
                    "compiled_profile" => profile.compiled_profile,
                    "authority_plane" => format!("{:?}", profile.authority_plane),
                    "binary" => binary_name
                );
            }

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
            if let Err(e) = fs::write("data/synergy-testnet.pid", pid.to_string()) {
                eprintln!("Warning: Failed to write PID file: {}", e);
            }

            let process_start_time = SystemTime::now();

            let p2p_enabled = should_start_p2p(&config, role_profile);
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

            let consensus_enabled = should_start_consensus(&config, role_profile);
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

            let reset_flag_path = "data/.reset_flag";
            let should_sync = !std::path::Path::new(reset_flag_path).exists();
            let sync_required_before_join =
                should_require_state_sync_before_join(&config, role_profile);

            if !should_start_sync(&config, role_profile) {
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
                std::fs::remove_file(reset_flag_path).ok();
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

            let mut consensus_handle = if !consensus_enabled {
                info!(
                    "main",
                    "Consensus engine disabled for this node profile",
                    "bootstrap_only" => config.node.bootstrap_only,
                    "role" => config.identity.role.clone(),
                    "validator_address" => resolve_local_validator_address(&config)
                );
                None
            } else {
                if let Err(error) = ensure_consensus_pqc_runtime_ready(&config) {
                    eprintln!("Consensus startup failed closed: {error}");
                    process::exit(1);
                }
                info!(
                    "main",
                    "Starting consensus engine",
                    "algorithm" => config.consensus.algorithm.clone()
                );
                Some(spawn_consensus_engine())
            };
            let watch_for_activation_consensus = should_watch_for_validator_activation_consensus(
                &config,
                role_profile,
                consensus_enabled,
            );

            let running = Arc::new(AtomicBool::new(true));
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
                if consensus_handle.is_none()
                    && watch_for_activation_consensus
                    && local_validator_is_consensus_authorized(&config)
                {
                    info!(
                        "main",
                        "Validator activation observed; starting consensus engine",
                        "validator_address" => resolve_local_validator_address(&config)
                    );
                    if let Err(error) = ensure_consensus_pqc_runtime_ready(&config) {
                        eprintln!("Consensus activation failed closed: {error}");
                        process::exit(1);
                    }
                    consensus_handle = Some(spawn_consensus_engine());
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

            info!("main", "Node shutdown gracefully");
            fs::remove_file("data/synergy-testnet.pid").ok();

            for handle in role_services.worker_threads {
                let _ = handle.join();
            }

            if let Some(consensus_handle) = consensus_handle {
                consensus_handle.join().ok();
            }
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
                "Error: legacy direct validator registration is disabled on Synergy Testnet chain 1264. Use the on-chain validator activation flow: bind Aegis PQC keys, submit and finalize a 50,000 SNRG stake lock, sync/replay/shadow, then activate at a finalized epoch boundary."
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
    use std::fs;
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

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
        env::temp_dir().join(format!(
            "synergy-role-runtime-{name}-{}-{nonce}",
            process::id()
        ))
    }

    fn snapshot_args(extra: &[&str]) -> Vec<String> {
        let mut args = vec![
            "synergy-testnet".to_string(),
            "create-snapshot".to_string(),
            "--chain-id".to_string(),
            "1264".to_string(),
            "--network-id".to_string(),
            "synergy-testnet-v3".to_string(),
            "--genesis-hash".to_string(),
            EXPECTED_GENESIS_HASH.to_string(),
        ];
        args.extend(extra.iter().map(|arg| (*arg).to_string()));
        args
    }

    fn quarantine_args(extra: &[&str]) -> Vec<String> {
        let mut args = vec![
            "synergy-testnet".to_string(),
            "quarantine-stopped-validator".to_string(),
            "--chain-id".to_string(),
            "1264".to_string(),
            "--network-id".to_string(),
            "synergy-testnet-v3".to_string(),
            "--genesis-hash".to_string(),
            EXPECTED_GENESIS_HASH.to_string(),
        ];
        args.extend(extra.iter().map(|arg| (*arg).to_string()));
        args
    }

    fn lifecycle_args(command: &str, extra: &[&str]) -> Vec<String> {
        let mut args = vec![
            "synergy-testnet".to_string(),
            command.to_string(),
            "--chain-id".to_string(),
            "1264".to_string(),
            "--network-id".to_string(),
            "synergy-testnet-v3".to_string(),
            "--genesis-hash".to_string(),
            EXPECTED_GENESIS_HASH.to_string(),
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
        assert!(error.contains("--chain-id 1264"));

        let wrong = vec![
            "synergy-testnet".to_string(),
            "create-snapshot".to_string(),
            "--chain-id".to_string(),
            "1263".to_string(),
            "--network-id".to_string(),
            "synergy-testnet-v3".to_string(),
        ];
        let error = require_testnet_v3_operator_args(&wrong).expect_err("wrong chain id must fail");
        assert!(error.contains("expected 1264"));
    }

    #[test]
    fn snapshot_operator_args_require_network_id() {
        let args = vec![
            "synergy-testnet".to_string(),
            "create-snapshot".to_string(),
            "--chain-id".to_string(),
            "1264".to_string(),
            "--network-id".to_string(),
            "synergy-testnet-v1".to_string(),
            "--genesis-hash".to_string(),
            EXPECTED_GENESIS_HASH.to_string(),
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
            "1264".to_string(),
            "--network-id".to_string(),
            "synergy-testnet-v3".to_string(),
            "--genesis-hash".to_string(),
            "wrong".to_string(),
        ];
        let error =
            require_testnet_v3_operator_args(&args).expect_err("wrong genesis must fail closed");
        assert!(error.contains("expected f79011f2"));
    }

    #[test]
    fn snapshot_operator_args_accept_equals_form() {
        let args = vec![
            "synergy-testnet".to_string(),
            "create-snapshot".to_string(),
            "--chain-id=1264".to_string(),
            "--network-id=synergy-testnet-v3".to_string(),
            format!("--genesis-hash={EXPECTED_GENESIS_HASH}"),
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
