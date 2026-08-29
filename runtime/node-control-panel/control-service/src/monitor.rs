use crate::app_context::AppContext;
use crate::testnet_agent_service::{
    TestnetAgentControlRequest, TestnetAgentControlResponse, TestnetAgentHealth, TESTNET_AGENT_PORT,
};
use crate::validator_operations::{
    aggregate_validator_statuses, DiagnosticSnapshotResult, HostPreflightStatus,
    StructuredLogsResponse, ValidatorLifecycleRequest, ValidatorLifecycleResult,
    ValidatorOperationsClusterStatus, ValidatorOperationsStatus,
};
use chrono::Utc;
use futures_util::future::join_all;
use reqwest::{Client, StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Write};
use std::mem;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DEFAULT_VALIDATOR_VPN_COORDINATOR_URL: &str = "https://vpn-coordinator.synergy-network.io";
const INNERNET_VALIDATOR_ADDRESS_PREFIX: &str = "10.70.10";
const INNERNET_RELAYER_ADDRESS_PREFIX: &str = "10.70.20";

fn validator_quorum_threshold(total_validators: usize) -> usize {
    if total_validators == 0 {
        0
    } else {
        // Smallest q satisfying 3*q > 2*n, without multiplication overflow.
        total_validators - (total_validators - 1) / 3
    }
}

fn validator_cluster_count(total_validators: usize) -> usize {
    if total_validators == 0 {
        0
    } else if total_validators < 10 {
        1
    } else if total_validators < 21 {
        2
    } else {
        total_validators / 7
    }
}

fn validator_largest_cluster_size(total_validators: usize) -> usize {
    let cluster_count = validator_cluster_count(total_validators);
    if cluster_count == 0 {
        0
    } else {
        total_validators.div_ceil(cluster_count)
    }
}

fn validator_network_cluster_quorum_threshold(total_validators: usize) -> usize {
    validator_quorum_threshold(validator_largest_cluster_size(total_validators))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorNode {
    pub node_slot_id: String,
    pub node_alias: String,
    pub role_group: String,
    pub role: String,
    pub node_type: String,
    pub operator: Option<String>,
    pub device: Option<String>,
    pub host: String,
    pub management_host: Option<String>,
    pub rpc_port: u16,
    pub p2p_port: u16,
    pub ws_port: u16,
    pub grpc_port: u16,
    pub discovery_port: u16,
    pub rpc_url: String,
    pub node_address: Option<String>,
    pub physical_machine_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorNodeStatus {
    pub node: MonitorNode,
    pub status: String,
    pub online: bool,
    #[serde(default)]
    pub active_physical_machine_id: Option<String>,
    #[serde(default)]
    pub active_management_host: Option<String>,
    pub block_height: Option<u64>,
    pub average_block_time_secs: Option<f64>,
    pub throughput_tps: Option<f64>,
    pub peer_count: Option<u64>,
    pub syncing: Option<bool>,
    pub response_ms: u64,
    pub error: Option<String>,
    pub last_checked_utc: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorSnapshot {
    pub inventory_path: String,
    pub captured_at_utc: String,
    pub total_nodes: usize,
    pub online_nodes: usize,
    pub offline_nodes: usize,
    pub syncing_nodes: usize,
    pub highest_block: Option<u64>,
    pub average_block_time_secs: Option<f64>,
    pub throughput_tps: Option<f64>,
    pub nodes: Vec<MonitorNodeStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MonitorRpcDiagnostics {
    pub node_info: Option<Value>,
    pub node_status: Option<Value>,
    pub sync_status: Option<Value>,
    pub latest_block: Option<Value>,
    pub peer_info: Option<Value>,
    pub validator_activity: Option<Value>,
    pub token_balance: Option<Value>,
    pub staking_info: Option<Value>,
    pub staked_balance: Option<Value>,
    pub synergy_score_breakdown: Option<Value>,
    pub relayer_set: Option<Value>,
    pub attestations: Option<Value>,
    pub divergence_status: Option<Value>,
    pub quarantine_status: Option<Value>,
    pub self_heal_status: Option<Value>,
    pub snapshot_catalog: Option<Value>,
    pub shadow_status: Option<Value>,
    pub rejoin_eligibility: Option<Value>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorControlCapabilities {
    pub enabled: bool,
    pub start_configured: bool,
    pub stop_configured: bool,
    pub restart_configured: bool,
    pub status_configured: bool,
    pub setup_configured: bool,
    pub export_logs_configured: bool,
    pub view_chain_data_configured: bool,
    pub export_chain_data_configured: bool,
    /// True when the node can be reached via the testnet-agent or a configured
    /// SSH command, meaning the `sync_node` action (nodectl sync) is available.
    pub sync_node_configured: bool,
    /// True when the orchestrator `deploy_agent` action is available for this node,
    /// meaning the agent binary can be pushed and restarted via SSH.  Always uses
    /// the orchestrator path (never the agent itself) so it works even when the
    /// remote agent is missing or running an outdated binary.
    pub update_agent_configured: bool,
    pub custom_actions: Vec<MonitorControlAction>,
    pub configuration_hint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorControlAction {
    pub key: String,
    pub label: String,
    pub description: String,
    pub category: String,
    pub configured: bool,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorAtlasLinks {
    pub enabled: bool,
    pub base_url: Option<String>,
    pub home_url: Option<String>,
    pub transactions_url: Option<String>,
    pub wallets_url: Option<String>,
    pub contracts_url: Option<String>,
    pub latest_block_url: Option<String>,
    pub latest_transaction_url: Option<String>,
    pub latest_transaction_hash: Option<String>,
    pub node_wallet_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorNodeDetails {
    pub inventory_path: String,
    pub captured_at_utc: String,
    pub status: MonitorNodeStatus,
    pub protocol_profile: Value,
    pub economics_profile: Value,
    pub role_diagnostics: Value,
    pub role_notes: Vec<String>,
    pub role_execution: MonitorRoleExecution,
    pub role_operations: Vec<MonitorControlAction>,
    pub rpc: MonitorRpcDiagnostics,
    pub atlas: MonitorAtlasLinks,
    pub control: MonitorControlCapabilities,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorRoleExecution {
    pub overall_status: String,
    pub summary: String,
    pub checks: Vec<MonitorExecutionCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorExecutionCheck {
    pub key: String,
    pub label: String,
    pub status: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorControlResult {
    pub node_slot_id: String,
    pub action: String,
    pub success: bool,
    pub exit_code: i32,
    pub command: String,
    pub stdout: String,
    pub stderr: String,
    pub executed_at_utc: String,
}

#[derive(Debug, Clone, Default)]
struct NodeControlCommands {
    start: Option<String>,
    stop: Option<String>,
    restart: Option<String>,
    status: Option<String>,
    setup: Option<String>,
    export_logs: Option<String>,
    view_chain_data: Option<String>,
    export_chain_data: Option<String>,
    custom_actions: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorExportResult {
    pub node_slot_id: String,
    pub file_path: String,
    pub bytes: usize,
    pub exported_at_utc: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorOperatorProfile {
    pub operator_id: String,
    pub display_name: String,
    pub role: String,
    pub enabled: bool,
    pub created_at_utc: String,
    pub updated_at_utc: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorOperatorInput {
    pub operator_id: String,
    pub display_name: String,
    pub role: String,
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorSshProfile {
    pub profile_id: String,
    pub label: String,
    pub ssh_user: String,
    pub ssh_port: u16,
    pub ssh_key_path: Option<String>,
    pub remote_root: Option<String>,
    pub strict_host_key_checking: Option<String>,
    pub extra_ssh_args: Option<String>,
    pub created_at_utc: String,
    pub updated_at_utc: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorSshProfileInput {
    pub profile_id: String,
    pub label: String,
    pub ssh_user: String,
    pub ssh_port: Option<u16>,
    pub ssh_key_path: Option<String>,
    pub remote_root: Option<String>,
    pub strict_host_key_checking: Option<String>,
    pub extra_ssh_args: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorSshBinding {
    #[serde(alias = "machine_id")]
    pub node_slot_id: String,
    pub profile_id: String,
    pub host_override: Option<String>,
    pub remote_dir_override: Option<String>,
    pub updated_at_utc: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorSshBindingInput {
    pub node_slot_id: String,
    pub profile_id: String,
    pub host_override: Option<String>,
    pub remote_dir_override: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorRolePermissions {
    pub role: String,
    pub can_control_nodes: bool,
    pub can_run_bulk_actions: bool,
    pub can_manage_security: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorSecurityState {
    pub workspace_path: String,
    pub inventory_path: String,
    pub active_operator_id: String,
    pub active_role: String,
    pub operators: Vec<MonitorOperatorProfile>,
    pub ssh_profiles: Vec<MonitorSshProfile>,
    #[serde(default, alias = "machine_bindings")]
    pub ssh_bindings: Vec<MonitorSshBinding>,
    pub role_permissions: Vec<MonitorRolePermissions>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorSetupStatus {
    pub required_wizard_version: u32,
    pub completed: bool,
    pub completed_wizard_version: u32,
    pub completed_at_utc: Option<String>,
    pub physical_machine_id: Option<String>,
    #[serde(default)]
    pub claimed_node_slot_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorLocalMachineIdentity {
    pub detected: bool,
    pub management_host: Option<String>,
    pub physical_machine_id: Option<String>,
    #[serde(default, alias = "logical_machine_ids")]
    pub node_slot_ids: Vec<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorBulkControlResult {
    pub scope: String,
    pub action: String,
    pub requested_nodes: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub executed_at_utc: String,
    pub results: Vec<MonitorControlResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorAgentReachability {
    pub physical_machine_id: String,
    pub management_host: String,
    pub node_slot_ids: Vec<String>,
    pub reachable: bool,
    pub response_ms: u64,
    pub version: Option<String>,
    pub workspace_path: Option<String>,
    pub local_management_host: Option<String>,
    pub supported_actions: Vec<String>,
    pub checked_at_utc: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorAgentSnapshot {
    pub captured_at_utc: String,
    pub total_agents: usize,
    pub reachable_agents: usize,
    pub unreachable_agents: usize,
    pub agents: Vec<MonitorAgentReachability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorTerminalCommandResult {
    pub success: bool,
    pub exit_code: i32,
    pub command: String,
    pub cwd: String,
    pub stdout: String,
    pub stderr: String,
    pub executed_at_utc: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct MonitorSetupState {
    #[serde(default)]
    completed: bool,
    #[serde(default)]
    wizard_version: u32,
    #[serde(default)]
    completed_at_utc: Option<String>,
    #[serde(default)]
    physical_machine_id: Option<String>,
    #[serde(default)]
    claimed_node_slot_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MonitorSecurityConfig {
    version: u32,
    active_operator_id: String,
    operators: Vec<MonitorOperatorProfile>,
    ssh_profiles: Vec<MonitorSshProfile>,
    #[serde(default, alias = "machine_bindings")]
    ssh_bindings: Vec<MonitorSshBinding>,
    #[serde(default)]
    setup: MonitorSetupState,
}

pub fn get_monitor_inventory_path() -> Result<String, String> {
    resolve_inventory_path().map(|path| path.to_string_lossy().to_string())
}

pub fn get_monitor_workspace_path() -> Result<String, String> {
    let workspace = resolve_monitor_workspace_path()?;
    Ok(workspace.to_string_lossy().to_string())
}

pub fn get_monitor_user_manual_markdown() -> Result<String, String> {
    let workspace = resolve_monitor_workspace_path()?;
    let manual_path = workspace.join(MONITOR_USER_MANUAL_RELATIVE);
    if !manual_path.is_file() {
        return Err(format!(
            "User manual not found at {}. Run monitor_initialize_workspace and ensure bundled resources include {}.",
            manual_path.display(),
            MONITOR_USER_MANUAL_RELATIVE
        ));
    }

    fs::read_to_string(&manual_path).map_err(|error| {
        format!(
            "Failed to read user manual {}: {error}",
            manual_path.display()
        )
    })
}

pub fn monitor_initialize_workspace_from_context(
    app_context: &AppContext,
) -> Result<String, String> {
    let workspace = ensure_monitor_workspace_with_context(app_context)?;
    Ok(workspace.to_string_lossy().to_string())
}

pub fn monitor_ensure_ssh_keypair_from_context(app_context: &AppContext) -> Result<String, String> {
    let workspace = ensure_monitor_workspace_with_context(app_context)?;
    let ssh_dir = workspace.join("keys/ssh");
    fs::create_dir_all(&ssh_dir).map_err(|error| {
        format!(
            "Failed to create SSH key directory {}: {error}",
            ssh_dir.display()
        )
    })?;

    let private_key = ssh_dir.join("ops_ed25519");
    let public_key = ssh_dir.join("ops_ed25519.pub");
    if private_key.is_file() && public_key.is_file() {
        return Ok(private_key.to_string_lossy().to_string());
    }

    #[cfg(target_os = "windows")]
    let candidate_commands = {
        let default_path = PathBuf::from(r"C:\Windows\System32\OpenSSH\ssh-keygen.exe");
        if default_path.is_file() {
            vec![default_path]
        } else {
            vec![PathBuf::from("ssh-keygen")]
        }
    };

    #[cfg(not(target_os = "windows"))]
    let candidate_commands = vec![PathBuf::from("ssh-keygen")];

    let private_key_arg = private_key.to_string_lossy().to_string();
    for command_path in candidate_commands {
        let output = ProcessCommand::new(&command_path)
            .args([
                "-t",
                "ed25519",
                "-a",
                "64",
                "-f",
                &private_key_arg,
                "-C",
                "testnet-ops",
                "-N",
                "",
            ])
            .output();

        match output {
            Ok(output) if output.status.success() => {
                return Ok(private_key.to_string_lossy().to_string());
            }
            Ok(_) => continue,
            Err(_) => continue,
        }
    }

    Err(
        "Failed to generate the local SSH keypair. Ensure OpenSSH ssh-keygen is installed and available on this machine."
            .to_string(),
    )
}

pub fn get_monitor_security_state() -> Result<MonitorSecurityState, String> {
    load_monitor_security_state()
}

pub async fn get_monitor_agent_snapshot() -> Result<MonitorAgentSnapshot, String> {
    let inventory_path = resolve_inventory_path()?;
    let nodes = load_inventory_nodes(&inventory_path)?;
    let machine_topology = build_inventory_machine_topology(&nodes);

    let mut machine_targets = HashMap::<String, (String, Vec<String>)>::new();
    for node in nodes {
        let physical_machine_id = if node.physical_machine_id.trim().is_empty() {
            node.node_slot_id.clone()
        } else {
            node.physical_machine_id.clone()
        };
        let management_host = machine_topology
            .get(&physical_machine_id.to_ascii_lowercase())
            .map(|entry| entry.management_host.clone())
            .or_else(|| {
                let host = node.host.trim();
                if is_private_management_ip(host) {
                    Some(host.to_string())
                } else {
                    None
                }
            })
            .unwrap_or_default();

        let entry = machine_targets
            .entry(physical_machine_id)
            .or_insert_with(|| (management_host.clone(), Vec::new()));
        if entry.0.is_empty() && !management_host.is_empty() {
            entry.0 = management_host.clone();
        }
        entry.1.push(node.node_slot_id.clone());
    }

    let mut targets = machine_targets
        .into_iter()
        .map(
            |(physical_machine_id, (management_host, mut node_slot_ids))| {
                node_slot_ids.sort();
                (physical_machine_id, management_host, node_slot_ids)
            },
        )
        .collect::<Vec<_>>();
    targets.sort_by(|a, b| a.0.cmp(&b.0));

    let client = Client::builder()
        .timeout(Duration::from_secs(3))
        .connect_timeout(Duration::from_secs(2))
        .build()
        .unwrap_or_else(|_| Client::new());

    let probes =
        targets
            .into_iter()
            .map(|(physical_machine_id, management_host, node_slot_ids)| {
                let client = client.clone();
                async move {
                    let checked_at_utc = Utc::now().to_rfc3339();
                    if management_host.trim().is_empty() {
                        return MonitorAgentReachability {
                            physical_machine_id,
                            management_host,
                            node_slot_ids,
                            reachable: false,
                            response_ms: 0,
                            version: None,
                            workspace_path: None,
                            local_management_host: None,
                            supported_actions: Vec::new(),
                            checked_at_utc,
                            error: Some(
                                "No inventory address resolved for this machine.".to_string(),
                            ),
                        };
                    }

                    let endpoint = format!("http://{management_host}:{TESTNET_AGENT_PORT}/health");
                    let started = Instant::now();
                    match client.get(&endpoint).send().await {
                        Ok(response) => {
                            let response_ms = started.elapsed().as_millis() as u64;
                            let status = response.status();
                            if !status.is_success() {
                                let body = response.text().await.unwrap_or_default();
                                return MonitorAgentReachability {
                                    physical_machine_id,
                                    management_host,
                                    node_slot_ids,
                                    reachable: false,
                                    response_ms,
                                    version: None,
                                    workspace_path: None,
                                    local_management_host: None,
                                    supported_actions: Vec::new(),
                                    checked_at_utc,
                                    error: Some(format!(
                                        "HTTP {} from agent health endpoint{}",
                                        status,
                                        if body.trim().is_empty() {
                                            String::new()
                                        } else {
                                            format!(": {}", truncate_text(body.trim(), 220))
                                        }
                                    )),
                                };
                            }

                            match response.json::<TestnetAgentHealth>().await {
                                Ok(payload) => {
                                    let mut installed_node_slot_ids = payload
                                        .node_slot_ids
                                        .into_iter()
                                        .map(|value| value.trim().to_ascii_lowercase())
                                        .filter(|value| !value.is_empty())
                                        .collect::<Vec<_>>();
                                    installed_node_slot_ids.dedup();

                                    MonitorAgentReachability {
                                        physical_machine_id: payload
                                            .physical_machine_id
                                            .filter(|value| !value.trim().is_empty())
                                            .unwrap_or(physical_machine_id),
                                        management_host,
                                        node_slot_ids: installed_node_slot_ids,
                                        reachable: true,
                                        response_ms,
                                        version: Some(payload.version),
                                        workspace_path: Some(payload.workspace_path),
                                        local_management_host: payload.local_management_host,
                                        supported_actions: payload.supported_actions,
                                        checked_at_utc,
                                        error: None,
                                    }
                                }
                                Err(error) => MonitorAgentReachability {
                                    physical_machine_id,
                                    management_host,
                                    node_slot_ids,
                                    reachable: false,
                                    response_ms,
                                    version: None,
                                    workspace_path: None,
                                    local_management_host: None,
                                    supported_actions: Vec::new(),
                                    checked_at_utc,
                                    error: Some(format!(
                                        "Failed to decode agent health payload: {error}"
                                    )),
                                },
                            }
                        }
                        Err(error) => MonitorAgentReachability {
                            physical_machine_id,
                            management_host,
                            node_slot_ids,
                            reachable: false,
                            response_ms: started.elapsed().as_millis() as u64,
                            version: None,
                            workspace_path: None,
                            local_management_host: None,
                            supported_actions: Vec::new(),
                            checked_at_utc,
                            error: Some(error.to_string()),
                        },
                    }
                }
            });

    let agents = join_all(probes).await;
    let reachable_agents = agents.iter().filter(|entry| entry.reachable).count();
    let total_agents = agents.len();

    Ok(MonitorAgentSnapshot {
        captured_at_utc: Utc::now().to_rfc3339(),
        total_agents,
        reachable_agents,
        unreachable_agents: total_agents.saturating_sub(reachable_agents),
        agents,
    })
}

#[derive(Debug, Clone)]
struct RuntimeNodePlacement {
    physical_machine_id: String,
    management_host: String,
}

async fn load_runtime_node_placements() -> HashMap<String, RuntimeNodePlacement> {
    let Ok(snapshot) = get_monitor_agent_snapshot().await else {
        return HashMap::new();
    };

    let mut placements = HashMap::new();
    for agent in snapshot.agents {
        if !agent.reachable || agent.management_host.trim().is_empty() {
            continue;
        }
        for node_slot_id in agent.node_slot_ids {
            placements.insert(
                node_slot_id.to_ascii_lowercase(),
                RuntimeNodePlacement {
                    physical_machine_id: agent.physical_machine_id.clone(),
                    management_host: agent.management_host.clone(),
                },
            );
        }
    }

    placements
}

fn apply_runtime_probe_target(
    mut node: MonitorNode,
    placement: Option<&RuntimeNodePlacement>,
) -> MonitorNode {
    if let Some(runtime) = placement {
        let management_host = runtime.management_host.trim();
        if !management_host.is_empty() {
            node.host = management_host.to_string();
            node.management_host = Some(management_host.to_string());
            node.rpc_url = build_rpc_url(management_host, node.rpc_port);
        }
    }
    node
}

fn stamp_runtime_host_override(
    overrides: &mut HashMap<String, String>,
    node_slot_id: &str,
    management_host: &str,
) {
    let node = node_slot_id.trim().to_ascii_lowercase();
    if node.is_empty() || management_host.trim().is_empty() {
        return;
    }

    let node_snake = node.replace('-', "_");
    let resolved_host = management_host.trim().to_string();
    overrides.insert(node.clone(), resolved_host.clone());
    overrides.insert(node_snake.clone(), resolved_host.clone());
    overrides.insert(format!("{node_snake}_host"), resolved_host.clone());
    overrides.insert(format!("{node_snake}_management_host"), resolved_host);
}

async fn augment_host_overrides_with_runtime_placements(overrides: &mut HashMap<String, String>) {
    let placements = load_runtime_node_placements().await;
    for (node_slot_id, placement) in placements {
        stamp_runtime_host_override(overrides, &node_slot_id, &placement.management_host);
    }
}

fn effective_machine_id_for_node(
    node: &MonitorNode,
    host_overrides: &HashMap<String, String>,
) -> String {
    let fallback = canonical_management_host_for_physical_machine(&node.physical_machine_id)
        .unwrap_or_else(|| node.host.clone());
    let resolved_host = resolve_management_host_override(
        host_overrides,
        &node.node_slot_id,
        &node.node_alias,
        fallback,
    );

    physical_machine_for_management_host(&resolved_host)
        .unwrap_or_else(|| node.physical_machine_id.clone())
}

pub fn monitor_get_setup_status() -> Result<MonitorSetupStatus, String> {
    let config = load_security_config()?;
    Ok(build_monitor_setup_status(&config))
}

pub fn monitor_detect_local_machine_identity() -> Result<MonitorLocalMachineIdentity, String> {
    if let Some(machine_id) = detect_local_machine_id_override() {
        let node_slot_ids = logical_nodes_for_physical_machine(&machine_id)?;
        return Ok(MonitorLocalMachineIdentity {
            detected: true,
            management_host: None,
            physical_machine_id: Some(machine_id.clone()),
            node_slot_ids,
            message: format!("Detected local machine via SYNERGY_MACHINE_ID={machine_id}."),
        });
    }

    let maybe_management_host = detect_local_management_host();
    let Some(management_host) = maybe_management_host else {
        return Ok(MonitorLocalMachineIdentity {
            detected: false,
            management_host: None,
            physical_machine_id: None,
            node_slot_ids: Vec::new(),
            message: "No local machine identity was detected. Set SYNERGY_MACHINE_ID or SYNERGY_MACHINE_ADDRESS to bind this control panel to a machine.".to_string(),
        });
    };

    let maybe_machine = physical_machine_for_management_host(&management_host);
    let Some(physical_machine_id) = maybe_machine else {
        return Ok(MonitorLocalMachineIdentity {
            detected: false,
            management_host: Some(management_host.clone()),
            physical_machine_id: None,
            node_slot_ids: Vec::new(),
            message: format!(
                "Detected local address {management_host}, but it does not map to any physical_machine_id in node-inventory.csv."
            ),
        });
    };

    let node_slot_ids = logical_nodes_for_physical_machine(&physical_machine_id)?;

    Ok(MonitorLocalMachineIdentity {
        detected: true,
        management_host: Some(management_host.clone()),
        physical_machine_id: Some(physical_machine_id.clone()),
        node_slot_ids,
        message: format!(
            "Detected local address {management_host}; mapped to {physical_machine_id}."
        ),
    })
}

fn detect_local_machine_id_override() -> Option<String> {
    std::env::var("SYNERGY_MACHINE_ID")
        .ok()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
}

async fn local_agent_health_check() -> Result<TestnetAgentHealth, String> {
    let client = Client::builder()
        .timeout(Duration::from_secs(2))
        .connect_timeout(Duration::from_secs(1))
        .build()
        .unwrap_or_else(|_| Client::new());
    let response = client
        .get(format!("http://127.0.0.1:{TESTNET_AGENT_PORT}/health"))
        .send()
        .await
        .map_err(|error| format!("Local testnet agent health request failed: {error}"))?
        .error_for_status()
        .map_err(|error| {
            format!("Local testnet agent health endpoint returned an error: {error}")
        })?;
    response
        .json::<TestnetAgentHealth>()
        .await
        .map_err(|error| format!("Failed to decode local testnet agent health payload: {error}"))
}

pub async fn monitor_mark_setup_complete(
    physical_machine_id: String,
    node_slot_ids: Option<Vec<String>>,
) -> Result<MonitorSetupStatus, String> {
    let mut config = load_security_config()?;
    let actor = resolve_active_operator(&config)?;
    enforce_security_admin(&actor)?;

    let normalized_machine = physical_machine_id.trim().to_ascii_lowercase();
    if normalized_machine.is_empty() {
        return Err("physical_machine_id is required (machine-01..machine-13)".to_string());
    }

    let workspace = resolve_monitor_workspace_path()?;
    validate_monitor_workspace_assets(&workspace)?;

    let identity = monitor_detect_local_machine_identity()?;
    if !identity.detected {
        return Err(format!(
            "Setup cannot be marked complete: local machine identity was not detected. {}",
            identity.message
        ));
    }
    let detected_machine_id = identity.physical_machine_id.clone().ok_or_else(|| {
        "Setup cannot be marked complete: local physical machine identity is unavailable."
            .to_string()
    })?;
    if !detected_machine_id.eq_ignore_ascii_case(&normalized_machine) {
        return Err(format!(
            "Setup cannot be marked complete: local machine identity resolved to {}, not {}.",
            detected_machine_id, normalized_machine
        ));
    }
    let health = local_agent_health_check().await?;
    if health.status.trim().to_ascii_lowercase() != "ok" {
        return Err(
            "Setup cannot be marked complete: local testnet agent health is not OK.".to_string(),
        );
    }

    let mut claimed_node_slot_ids = node_slot_ids
        .unwrap_or_default()
        .into_iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    claimed_node_slot_ids.sort();
    claimed_node_slot_ids.dedup();

    if claimed_node_slot_ids.is_empty() {
        claimed_node_slot_ids = logical_nodes_for_physical_machine(&normalized_machine)?;
    }

    let missing_bindings = claimed_node_slot_ids
        .iter()
        .filter(|node_slot_id| {
            !config
                .ssh_bindings
                .iter()
                .any(|binding| binding.node_slot_id.eq_ignore_ascii_case(node_slot_id))
        })
        .cloned()
        .collect::<Vec<_>>();
    if !missing_bindings.is_empty() {
        return Err(format!(
            "Setup cannot be marked complete: missing SSH bindings for {}",
            missing_bindings.join(", ")
        ));
    }

    let now = Utc::now().to_rfc3339();
    config.setup.completed = true;
    config.setup.wizard_version = MONITOR_SETUP_WIZARD_VERSION;
    config.setup.completed_at_utc = Some(now.clone());
    config.setup.physical_machine_id = Some(normalized_machine.clone());
    config.setup.claimed_node_slot_ids = claimed_node_slot_ids.clone();
    save_security_config(&config)?;

    append_audit_event(json!({
        "event_type": "setup.completed",
        "actor_operator_id": actor.operator_id,
        "physical_machine_id": normalized_machine,
        "logical_nodes": claimed_node_slot_ids.iter().map(|s| s.to_string()).collect::<Vec<String>>(),
        "wizard_version": MONITOR_SETUP_WIZARD_VERSION,
        "timestamp_utc": now,
    }))?;

    Ok(build_monitor_setup_status(&config))
}

pub fn monitor_set_active_operator(operator_id: String) -> Result<MonitorSecurityState, String> {
    let mut config = load_security_config()?;
    let requested = operator_id.trim();
    if requested.is_empty() {
        return Err("operator_id is required".to_string());
    }

    let exists = config
        .operators
        .iter()
        .any(|operator| operator.enabled && operator.operator_id.eq_ignore_ascii_case(requested));
    if !exists {
        return Err(format!("Operator not found or disabled: {requested}"));
    }

    config.active_operator_id = requested.to_string();
    save_security_config(&config)?;
    append_audit_event(json!({
        "event_type": "security.active_operator_changed",
        "operator_id": requested,
        "timestamp_utc": Utc::now().to_rfc3339(),
    }))?;
    load_monitor_security_state()
}

pub fn monitor_upsert_operator(
    input: MonitorOperatorInput,
) -> Result<MonitorSecurityState, String> {
    let mut config = load_security_config()?;
    let actor = resolve_active_operator(&config)?;
    enforce_security_admin(&actor)?;

    let operator_id = sanitize_identifier(&input.operator_id);
    if operator_id.is_empty() {
        return Err("operator_id is required".to_string());
    }

    let display_name = input.display_name.trim();
    if display_name.is_empty() {
        return Err("display_name is required".to_string());
    }

    let role = normalize_operator_role(&input.role)?;
    let now = Utc::now().to_rfc3339();
    let enabled = input.enabled.unwrap_or(true);

    if let Some(existing) = config
        .operators
        .iter_mut()
        .find(|operator| operator.operator_id.eq_ignore_ascii_case(&operator_id))
    {
        existing.display_name = display_name.to_string();
        existing.role = role.clone();
        existing.enabled = enabled;
        existing.updated_at_utc = now.clone();
    } else {
        config.operators.push(MonitorOperatorProfile {
            operator_id: operator_id.clone(),
            display_name: display_name.to_string(),
            role: role.clone(),
            enabled,
            created_at_utc: now.clone(),
            updated_at_utc: now.clone(),
        });
    }

    if config.active_operator_id.trim().is_empty() {
        config.active_operator_id = operator_id.clone();
    }

    save_security_config(&config)?;
    append_audit_event(json!({
        "event_type": "security.operator_upserted",
        "actor_operator_id": actor.operator_id,
        "operator_id": operator_id,
        "role": role,
        "enabled": enabled,
        "timestamp_utc": now,
    }))?;
    load_monitor_security_state()
}

pub fn monitor_delete_operator(operator_id: String) -> Result<MonitorSecurityState, String> {
    let mut config = load_security_config()?;
    let actor = resolve_active_operator(&config)?;
    enforce_security_admin(&actor)?;

    let target = sanitize_identifier(&operator_id);
    if target.is_empty() {
        return Err("operator_id is required".to_string());
    }

    let before = config.operators.len();
    config
        .operators
        .retain(|operator| !operator.operator_id.eq_ignore_ascii_case(&target));
    if config.operators.is_empty() {
        return Err("At least one operator must remain".to_string());
    }
    if config.operators.len() == before {
        return Err(format!("Operator not found: {target}"));
    }

    if config.active_operator_id.eq_ignore_ascii_case(&target) {
        if let Some(fallback) = config.operators.iter().find(|operator| operator.enabled) {
            config.active_operator_id = fallback.operator_id.clone();
        }
    }

    save_security_config(&config)?;
    append_audit_event(json!({
        "event_type": "security.operator_deleted",
        "actor_operator_id": actor.operator_id,
        "operator_id": target,
        "timestamp_utc": Utc::now().to_rfc3339(),
    }))?;
    load_monitor_security_state()
}

pub fn monitor_upsert_ssh_profile(
    input: MonitorSshProfileInput,
) -> Result<MonitorSecurityState, String> {
    let mut config = load_security_config()?;
    let actor = resolve_active_operator(&config)?;
    enforce_security_admin(&actor)?;

    let profile_id = sanitize_identifier(&input.profile_id);
    if profile_id.is_empty() {
        return Err("profile_id is required".to_string());
    }

    let label = input.label.trim();
    if label.is_empty() {
        return Err("label is required".to_string());
    }

    let ssh_user = input.ssh_user.trim();
    if ssh_user.is_empty() {
        return Err("ssh_user is required".to_string());
    }

    let ssh_port = input.ssh_port.unwrap_or(22);
    let now = Utc::now().to_rfc3339();
    let normalize_opt = |value: &Option<String>| -> Option<String> {
        value
            .as_ref()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .map(|value| value.to_string())
    };

    if let Some(existing) = config
        .ssh_profiles
        .iter_mut()
        .find(|profile| profile.profile_id.eq_ignore_ascii_case(&profile_id))
    {
        existing.label = label.to_string();
        existing.ssh_user = ssh_user.to_string();
        existing.ssh_port = ssh_port;
        existing.ssh_key_path = normalize_opt(&input.ssh_key_path);
        existing.remote_root = normalize_remote_root_opt(&input.remote_root);
        existing.strict_host_key_checking = normalize_opt(&input.strict_host_key_checking);
        existing.extra_ssh_args = normalize_opt(&input.extra_ssh_args);
        existing.updated_at_utc = now.clone();
    } else {
        config.ssh_profiles.push(MonitorSshProfile {
            profile_id: profile_id.clone(),
            label: label.to_string(),
            ssh_user: ssh_user.to_string(),
            ssh_port,
            ssh_key_path: normalize_opt(&input.ssh_key_path),
            remote_root: normalize_remote_root_opt(&input.remote_root),
            strict_host_key_checking: normalize_opt(&input.strict_host_key_checking),
            extra_ssh_args: normalize_opt(&input.extra_ssh_args),
            created_at_utc: now.clone(),
            updated_at_utc: now.clone(),
        });
    }

    save_security_config(&config)?;
    append_audit_event(json!({
        "event_type": "security.ssh_profile_upserted",
        "actor_operator_id": actor.operator_id,
        "profile_id": profile_id,
        "timestamp_utc": now,
    }))?;
    load_monitor_security_state()
}

pub fn monitor_delete_ssh_profile(profile_id: String) -> Result<MonitorSecurityState, String> {
    let mut config = load_security_config()?;
    let actor = resolve_active_operator(&config)?;
    enforce_security_admin(&actor)?;

    let target = sanitize_identifier(&profile_id);
    if target.is_empty() {
        return Err("profile_id is required".to_string());
    }

    let before_profiles = config.ssh_profiles.len();
    config
        .ssh_profiles
        .retain(|profile| !profile.profile_id.eq_ignore_ascii_case(&target));
    if config.ssh_profiles.len() == before_profiles {
        return Err(format!("SSH profile not found: {target}"));
    }
    config
        .ssh_bindings
        .retain(|binding| !binding.profile_id.eq_ignore_ascii_case(&target));

    save_security_config(&config)?;
    append_audit_event(json!({
        "event_type": "security.ssh_profile_deleted",
        "actor_operator_id": actor.operator_id,
        "profile_id": target,
        "timestamp_utc": Utc::now().to_rfc3339(),
    }))?;
    load_monitor_security_state()
}

pub fn monitor_assign_ssh_binding(
    input: MonitorSshBindingInput,
) -> Result<MonitorSecurityState, String> {
    let mut config = load_security_config()?;
    let actor = resolve_active_operator(&config)?;
    enforce_security_admin(&actor)?;

    let node_slot_id = input.node_slot_id.trim().to_string();
    if node_slot_id.is_empty() {
        return Err("node_slot_id is required".to_string());
    }
    let profile_id = sanitize_identifier(&input.profile_id);
    if profile_id.is_empty() {
        return Err("profile_id is required".to_string());
    }

    let profile_exists = config
        .ssh_profiles
        .iter()
        .any(|profile| profile.profile_id.eq_ignore_ascii_case(&profile_id));
    if !profile_exists {
        return Err(format!("SSH profile not found: {profile_id}"));
    }

    let now = Utc::now().to_rfc3339();
    let validated_host_override =
        validate_host_override_for_binding(&node_slot_id, &input.host_override)?;

    if let Some(existing) = config
        .ssh_bindings
        .iter_mut()
        .find(|binding| binding.node_slot_id.eq_ignore_ascii_case(&node_slot_id))
    {
        existing.profile_id = profile_id.clone();
        existing.host_override = validated_host_override.clone();
        existing.remote_dir_override =
            normalize_remote_dir_override(&node_slot_id, &input.remote_dir_override);
        existing.updated_at_utc = now.clone();
    } else {
        config.ssh_bindings.push(MonitorSshBinding {
            node_slot_id: node_slot_id.clone(),
            profile_id: profile_id.clone(),
            host_override: validated_host_override,
            remote_dir_override: normalize_remote_dir_override(
                &node_slot_id,
                &input.remote_dir_override,
            ),
            updated_at_utc: now.clone(),
        });
    }

    save_security_config(&config)?;
    append_audit_event(json!({
        "event_type": "security.ssh_binding_upserted",
        "actor_operator_id": actor.operator_id,
        "node_slot_id": node_slot_id,
        "profile_id": profile_id,
        "timestamp_utc": now,
    }))?;
    load_monitor_security_state()
}

pub fn monitor_remove_ssh_binding(node_slot_id: String) -> Result<MonitorSecurityState, String> {
    let mut config = load_security_config()?;
    let actor = resolve_active_operator(&config)?;
    enforce_security_admin(&actor)?;

    let target = node_slot_id.trim();
    if target.is_empty() {
        return Err("node_slot_id is required".to_string());
    }

    let before = config.ssh_bindings.len();
    config
        .ssh_bindings
        .retain(|binding| !binding.node_slot_id.eq_ignore_ascii_case(target));
    if config.ssh_bindings.len() == before {
        return Err(format!("No SSH binding found for target: {target}"));
    }

    save_security_config(&config)?;
    append_audit_event(json!({
        "event_type": "security.ssh_binding_removed",
        "actor_operator_id": actor.operator_id,
        "node_slot_id": target,
        "timestamp_utc": Utc::now().to_rfc3339(),
    }))?;
    load_monitor_security_state()
}

pub async fn get_monitor_snapshot() -> Result<MonitorSnapshot, String> {
    let inventory_path = resolve_inventory_path()?;
    let nodes = load_inventory_nodes(&inventory_path)?;
    let runtime_placements = load_runtime_node_placements().await;

    let probes = nodes
        .into_iter()
        .map(|node| {
            let placement = runtime_placements
                .get(&node.node_slot_id.to_ascii_lowercase())
                .cloned();
            async move {
                let mut status =
                    probe_node(apply_runtime_probe_target(node, placement.as_ref())).await;
                status.active_physical_machine_id = placement
                    .as_ref()
                    .map(|entry| entry.physical_machine_id.clone());
                status.active_management_host = placement
                    .as_ref()
                    .map(|entry| entry.management_host.clone());
                status
            }
        })
        .collect::<Vec<_>>();
    let mut statuses = join_all(probes).await;

    let highest_block = statuses.iter().filter_map(|n| n.block_height).max();
    if let Some(network_head) = highest_block {
        for status in &mut statuses {
            let Some(local_height) = status.block_height else {
                continue;
            };
            let lag = network_head.saturating_sub(local_height);
            if lag > 1 {
                status.syncing = Some(true);
                if status.online {
                    status.status = "syncing".to_string();
                }
            } else if status.online && status.syncing.is_none() {
                status.syncing = Some(false);
            }
        }
    }

    let total_nodes = statuses.len();
    let online_nodes = statuses.iter().filter(|n| n.online).count();
    let offline_nodes = total_nodes.saturating_sub(online_nodes);
    let syncing_nodes = statuses.iter().filter(|n| n.syncing == Some(true)).count();
    let average_block_time_secs = preferred_network_average(&statuses, highest_block, |status| {
        status.average_block_time_secs
    });
    let throughput_tps =
        preferred_network_average(&statuses, highest_block, |status| status.throughput_tps);

    Ok(MonitorSnapshot {
        inventory_path: inventory_path.to_string_lossy().to_string(),
        captured_at_utc: Utc::now().to_rfc3339(),
        total_nodes,
        online_nodes,
        offline_nodes,
        syncing_nodes,
        highest_block,
        average_block_time_secs,
        throughput_tps,
        nodes: statuses,
    })
}

pub async fn monitor_bulk_node_control(
    action: String,
    scope: Option<String>,
) -> Result<MonitorBulkControlResult, String> {
    let normalized_action = normalize_action_key(&action);
    if normalized_action.is_empty() {
        return Err("Control action is empty".to_string());
    }

    let inventory_path = resolve_inventory_path()?;
    let nodes = load_inventory_nodes(&inventory_path)?;
    let scope_value = scope.unwrap_or_else(|| "all".to_string());
    let mut selected = select_nodes_for_scope(&nodes, &scope_value);
    if normalized_action == "sync_node" {
        let bootstrap_validator_ids = nodes
            .iter()
            .filter(|node| is_bootstrap_consensus_validator(node))
            .map(|node| node.node_slot_id.trim().to_ascii_lowercase())
            .collect::<HashSet<_>>();
        selected.retain(|node_slot_id| {
            !bootstrap_validator_ids.contains(&node_slot_id.trim().to_ascii_lowercase())
        });
    }
    if selected.is_empty() {
        return Err(if normalized_action == "sync_node" {
            format!("No sync-eligible non-validator nodes match scope '{scope_value}'")
        } else {
            format!("No nodes match scope '{scope_value}'")
        });
    }
    let ordered = order_nodes_for_bulk_action(&nodes, selected, &normalized_action);

    let config = load_security_config()?;
    let operator = resolve_active_operator(&config)?;
    if !role_allows_control(&operator.role, &normalized_action) {
        append_audit_event(json!({
            "event_type": "control.bulk.denied",
            "operator_id": operator.operator_id,
            "operator_role": operator.role,
            "scope": scope_value,
            "action": normalized_action,
            "timestamp_utc": Utc::now().to_rfc3339(),
        }))?;
        return Err(format!(
            "RBAC denied: role '{}' cannot execute action '{}'",
            operator.role, normalized_action
        ));
    }

    let mut results = Vec::new();
    let phase_map = nodes
        .iter()
        .map(|node| {
            (
                node.node_slot_id.to_ascii_lowercase(),
                bulk_action_phase(&normalized_action, node),
            )
        })
        .collect::<HashMap<_, _>>();
    let mut grouped = Vec::<(u8, Vec<String>)>::new();
    for node_slot_id in ordered {
        let current_phase = phase_map
            .get(&node_slot_id.to_ascii_lowercase())
            .copied()
            .unwrap_or(2);
        if let Some((phase, phase_nodes)) = grouped.last_mut() {
            if *phase == current_phase {
                phase_nodes.push(node_slot_id);
                continue;
            }
        }
        grouped.push((current_phase, vec![node_slot_id]));
    }

    let mut previous_phase = None;
    for (current_phase, phase_nodes) in grouped {
        if let Some(previous) = previous_phase {
            if previous != current_phase {
                if let Some(pause) = bulk_action_pause(&normalized_action, current_phase) {
                    tokio::time::sleep(pause).await;
                }
            }
        }

        let phase_results = join_all(phase_nodes.iter().map(|node_slot_id| async {
            match execute_monitor_node_control(node_slot_id, &normalized_action, &operator, "bulk")
                .await
            {
                Ok(result) => result,
                Err(error) => {
                    let executed_at_utc = Utc::now().to_rfc3339();
                    let failure = MonitorControlResult {
                        node_slot_id: node_slot_id.clone(),
                        action: normalized_action.clone(),
                        success: false,
                        exit_code: -1,
                        command: "N/A".to_string(),
                        stdout: String::new(),
                        stderr: truncate_text(error.trim(), 6000),
                        executed_at_utc: executed_at_utc.clone(),
                    };
                    let _ = append_audit_event(json!({
                        "event_type": "control.node.failed",
                        "mode": "bulk",
                        "operator_id": operator.operator_id,
                        "operator_role": operator.role,
                        "node_slot_id": failure.node_slot_id,
                        "action": failure.action,
                        "success": false,
                        "exit_code": failure.exit_code,
                        "command": failure.command,
                        "stderr": failure.stderr,
                        "timestamp_utc": executed_at_utc,
                    }));
                    failure
                }
            }
        }))
        .await;

        results.extend(phase_results);
        previous_phase = Some(current_phase);
    }

    let succeeded = results.iter().filter(|result| result.success).count();
    let failed = results.len().saturating_sub(succeeded);

    // After a bulk reset_chain, attempt to notify the explorer/indexer to reindex
    // from genesis so it doesn't show stale chain data.
    if normalized_action == "reset_chain" && succeeded > 0 {
        if let Err(warning) = reset_explorer_index().await {
            eprintln!("Explorer reset warning (non-blocking): {warning}");
        }
    }

    append_audit_event(json!({
        "event_type": "control.bulk.completed",
        "operator_id": operator.operator_id,
        "operator_role": operator.role,
        "scope": scope_value,
        "action": normalized_action,
        "requested_nodes": results.len(),
        "succeeded": succeeded,
        "failed": failed,
        "timestamp_utc": Utc::now().to_rfc3339(),
    }))?;

    Ok(MonitorBulkControlResult {
        scope: scope_value,
        action: normalized_action,
        requested_nodes: results.len(),
        succeeded,
        failed,
        executed_at_utc: Utc::now().to_rfc3339(),
        results,
    })
}

fn resolve_hosts_env_path() -> Result<PathBuf, String> {
    let inventory_path = resolve_inventory_path()?;
    inventory_path
        .parent()
        .map(|parent| parent.join("hosts.env"))
        .filter(|candidate| candidate.is_file())
        .ok_or_else(|| {
            "Unable to resolve testnet/runtime/hosts.env from the active monitor workspace."
                .to_string()
        })
}

fn read_hosts_env_value(key: &str) -> Option<String> {
    let path = resolve_hosts_env_path().ok()?;
    let contents = fs::read_to_string(path).ok()?;

    contents.lines().find_map(|raw_line| {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }

        let stripped = line.strip_prefix("export ").unwrap_or(line).trim();
        let (raw_key, raw_value) = stripped.split_once('=')?;
        if raw_key.trim() != key {
            return None;
        }

        let value = raw_value
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .trim()
            .to_string();
        if value.is_empty() {
            None
        } else {
            Some(value)
        }
    })
}

fn resolve_process_or_hosts_env_value(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(|| read_hosts_env_value(key))
}

async fn send_explorer_reset_request(endpoint: &str, reason: &str) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|error| format!("Failed to build HTTP client: {error}"))?;

    let response = client
        .post(endpoint)
        .json(&serde_json::json!({
            "action": "reindex_from_genesis",
            "reason": reason,
            "timestamp_utc": chrono::Utc::now().to_rfc3339(),
        }))
        .send()
        .await
        .map_err(|error| format!("Explorer reset request failed: {error}"))?;

    if response.status().is_success() {
        eprintln!("Explorer reindex-from-genesis request sent successfully to {endpoint}");
        Ok(())
    } else {
        Err(format!(
            "Explorer reset returned HTTP {}: {}",
            response.status(),
            response.text().await.unwrap_or_default()
        ))
    }
}

fn send_explorer_reset_via_orchestrator(endpoint: &str, reason: &str) -> Result<(), String> {
    let inventory_path = resolve_inventory_path()?;
    let script_path = resolve_orchestrator_script_path(&inventory_path).ok_or_else(|| {
        "Unable to resolve scripts/testnet/remote-node-orchestrator.sh for explorer reset fallback."
            .to_string()
    })?;
    let hosts_env_path = resolve_hosts_env_path()
        .ok()
        .map(|path| path.to_string_lossy().to_string());
    let remote_node = resolve_process_or_hosts_env_value("SYNERGY_EXPLORER_RESET_REMOTE_NODE")
        .unwrap_or_else(|| "node-01".to_string());
    let base_command = build_orchestrator_command(
        &script_path,
        hosts_env_path.as_deref(),
        &remote_node,
        "explorer_reset",
    );
    let command = format!(
        "SYNERGY_EXPLORER_RESET_ENDPOINT={} SYNERGY_EXPLORER_RESET_REASON={} {}",
        shell_quote(endpoint),
        shell_quote(reason),
        base_command
    );
    let (exit_code, stdout, stderr) = run_shell_command(&command)?;
    if exit_code == 0 {
        eprintln!(
            "Explorer reindex-from-genesis request sent via orchestrator fallback on {remote_node}"
        );
        return Ok(());
    }

    let mut detail = Vec::new();
    if !stdout.trim().is_empty() {
        detail.push(format!("stdout: {}", truncate_text(stdout.trim(), 1200)));
    }
    if !stderr.trim().is_empty() {
        detail.push(format!("stderr: {}", truncate_text(stderr.trim(), 1200)));
    }
    Err(format!(
        "Explorer reset orchestrator fallback failed on {remote_node} (exit {exit_code}){}",
        if detail.is_empty() {
            String::new()
        } else {
            format!(": {}", detail.join(" | "))
        }
    ))
}

/// Notify the explorer/indexer service to reindex from genesis after a chain reset.
/// Reads the endpoint from SYNERGY_EXPLORER_RESET_ENDPOINT env var or hosts.env.
/// This is a best-effort, non-blocking call — if the explorer is unreachable or
/// the endpoint is not configured, the chain reset still succeeds.
async fn reset_explorer_index() -> Result<(), String> {
    let endpoint = resolve_process_or_hosts_env_value("SYNERGY_EXPLORER_RESET_ENDPOINT")
        .ok_or_else(|| {
            "SYNERGY_EXPLORER_RESET_ENDPOINT not configured. Explorer must be reindexed manually. \
             See Explorer-Reset-Integration-Guide.md for setup instructions."
                .to_string()
        })?;
    let reason = "chain_reset";

    match send_explorer_reset_request(&endpoint, reason).await {
        Ok(()) => Ok(()),
        Err(direct_error) => match send_explorer_reset_via_orchestrator(&endpoint, reason) {
            Ok(()) => {
                eprintln!(
                    "Explorer reset direct request failed ({direct_error}); orchestrator fallback succeeded."
                );
                Ok(())
            }
            Err(fallback_error) => Err(format!(
                "Explorer reset failed via direct request ({direct_error}) and orchestrator fallback ({fallback_error})"
            )),
        },
    }
}

pub async fn get_monitor_node_details(node_slot_id: String) -> Result<MonitorNodeDetails, String> {
    let inventory_path = resolve_inventory_path()?;
    let nodes = load_inventory_nodes(&inventory_path)?;
    let runtime_placements = load_runtime_node_placements().await;

    let node = nodes
        .iter()
        .find(|candidate| {
            candidate.node_slot_id.eq_ignore_ascii_case(&node_slot_id)
                || candidate.node_alias.eq_ignore_ascii_case(&node_slot_id)
        })
        .cloned()
        .ok_or_else(|| format!("Node not found in inventory: {node_slot_id}"))?;
    let runtime_placement = runtime_placements
        .get(&node.node_slot_id.to_ascii_lowercase())
        .cloned();
    let probe_target = apply_runtime_probe_target(node.clone(), runtime_placement.as_ref());

    let mut node_status = probe_node(probe_target.clone()).await;
    node_status.active_physical_machine_id = runtime_placement
        .as_ref()
        .map(|entry| entry.physical_machine_id.clone());
    node_status.active_management_host = runtime_placement
        .as_ref()
        .map(|entry| entry.management_host.clone());

    let client = Client::builder()
        .timeout(Duration::from_millis(750))
        .connect_timeout(Duration::from_millis(750))
        .build()
        .unwrap_or_else(|_| Client::new());

    let rpc_url = probe_target.rpc_url.clone();
    let (
        node_info_result,
        node_status_result,
        sync_status_result,
        latest_block_result,
        peer_info_result,
        validator_activity_result,
        relayer_set_result,
        attestations_result,
        divergence_status_result,
        quarantine_status_result,
        self_heal_status_result,
        snapshot_catalog_result,
        shadow_status_result,
        rejoin_eligibility_result,
    ) = tokio::join!(
        rpc_call(&client, &rpc_url, "synergy_nodeInfo", json!([])),
        rpc_call(&client, &rpc_url, "synergy_getNodeStatus", json!([])),
        rpc_call(&client, &rpc_url, "synergy_getSyncStatus", json!([])),
        rpc_call(&client, &rpc_url, "synergy_getLatestBlock", json!([])),
        rpc_call(&client, &rpc_url, "synergy_getPeerInfo", json!([])),
        rpc_call(&client, &rpc_url, "synergy_getValidatorActivity", json!([])),
        rpc_call(&client, &rpc_url, "synergy_getRelayerSet", json!([])),
        rpc_call(
            &client,
            &rpc_url,
            "synergy_getAttestations",
            json!([25_u64])
        ),
        rpc_call(&client, &rpc_url, "synergy_getDivergenceStatus", json!([])),
        rpc_call(&client, &rpc_url, "synergy_getQuarantineStatus", json!([])),
        rpc_call(&client, &rpc_url, "synergy_getSelfHealStatus", json!([])),
        rpc_call(&client, &rpc_url, "synergy_getSnapshotCatalog", json!([])),
        rpc_call(&client, &rpc_url, "synergy_getShadowStatus", json!([])),
        rpc_call(&client, &rpc_url, "synergy_getRejoinEligibility", json!([])),
    );

    let mut rpc = MonitorRpcDiagnostics::default();
    rpc.node_info = node_info_result.clone().ok();
    rpc.node_status = node_status_result.clone().ok();
    rpc.sync_status = sync_status_result.clone().ok();
    rpc.latest_block = latest_block_result.clone().ok();
    rpc.peer_info = peer_info_result.clone().ok();
    rpc.validator_activity = validator_activity_result.clone().ok();
    rpc.relayer_set = relayer_set_result.clone().ok();
    rpc.attestations = attestations_result.clone().ok();
    rpc.divergence_status = divergence_status_result.clone().ok();
    rpc.quarantine_status = quarantine_status_result.clone().ok();
    rpc.self_heal_status = self_heal_status_result.clone().ok();
    rpc.snapshot_catalog = snapshot_catalog_result.clone().ok();
    rpc.shadow_status = shadow_status_result.clone().ok();
    rpc.rejoin_eligibility = rejoin_eligibility_result.clone().ok();

    if let Some(address) = node
        .node_address
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let (
            token_balance_result,
            staking_info_result,
            staked_balance_result,
            synergy_score_breakdown_result,
        ) = tokio::join!(
            rpc_call(
                &client,
                &rpc_url,
                "synergy_getTokenBalance",
                json!([address, "SNRG"])
            ),
            rpc_call(
                &client,
                &rpc_url,
                "synergy_getStakingInfo",
                json!([address])
            ),
            rpc_call(
                &client,
                &rpc_url,
                "synergy_getStakedBalance",
                json!([address, "SNRG"])
            ),
            rpc_call(
                &client,
                &rpc_url,
                "synergy_getSynergyScoreBreakdown",
                json!([address])
            ),
        );

        rpc.token_balance = token_balance_result.clone().ok();
        rpc.staking_info = staking_info_result.clone().ok();
        rpc.staked_balance = staked_balance_result.clone().ok();
        rpc.synergy_score_breakdown = synergy_score_breakdown_result.clone().ok();

        if let Err(err) = token_balance_result.as_ref() {
            rpc.errors.push(format!("synergy_getTokenBalance: {err}"));
        }
        if let Err(err) = staking_info_result.as_ref() {
            rpc.errors.push(format!("synergy_getStakingInfo: {err}"));
        }
        if let Err(err) = staked_balance_result.as_ref() {
            rpc.errors.push(format!("synergy_getStakedBalance: {err}"));
        }
        if let Err(err) = synergy_score_breakdown_result.as_ref() {
            rpc.errors
                .push(format!("synergy_getSynergyScoreBreakdown: {err}"));
        }
    }

    if let Err(err) = node_info_result.as_ref() {
        rpc.errors.push(format!("synergy_nodeInfo: {err}"));
    }
    if let Err(err) = node_status_result.as_ref() {
        rpc.errors.push(format!("synergy_getNodeStatus: {err}"));
    }
    if let Err(err) = sync_status_result.as_ref() {
        rpc.errors.push(format!("synergy_getSyncStatus: {err}"));
    }
    if let Err(err) = latest_block_result.as_ref() {
        rpc.errors.push(format!("synergy_getLatestBlock: {err}"));
    }
    if let Err(err) = peer_info_result.as_ref() {
        rpc.errors.push(format!("synergy_getPeerInfo: {err}"));
    }
    if let Err(err) = validator_activity_result.as_ref() {
        rpc.errors
            .push(format!("synergy_getValidatorActivity: {err}"));
    }
    if let Err(err) = relayer_set_result.as_ref() {
        rpc.errors.push(format!("synergy_getRelayerSet: {err}"));
    }
    if let Err(err) = attestations_result.as_ref() {
        rpc.errors.push(format!("synergy_getAttestations: {err}"));
    }
    if let Err(err) = divergence_status_result.as_ref() {
        rpc.errors
            .push(format!("synergy_getDivergenceStatus: {err}"));
    }
    if let Err(err) = quarantine_status_result.as_ref() {
        rpc.errors
            .push(format!("synergy_getQuarantineStatus: {err}"));
    }
    if let Err(err) = self_heal_status_result.as_ref() {
        rpc.errors.push(format!("synergy_getSelfHealStatus: {err}"));
    }
    if let Err(err) = snapshot_catalog_result.as_ref() {
        rpc.errors
            .push(format!("synergy_getSnapshotCatalog: {err}"));
    }
    if let Err(err) = shadow_status_result.as_ref() {
        rpc.errors.push(format!("synergy_getShadowStatus: {err}"));
    }
    if let Err(err) = rejoin_eligibility_result.as_ref() {
        rpc.errors
            .push(format!("synergy_getRejoinEligibility: {err}"));
    }

    let (role_diagnostics, role_notes) = build_role_diagnostics(&node_status, &rpc);
    let role_execution = build_role_execution(&node_status, &rpc);
    let protocol_profile = load_protocol_profile(&inventory_path, &node.node_slot_id);
    let economics_profile = load_economics_profile(&inventory_path, &node, &rpc);

    let host_overrides = load_hosts_overrides(&inventory_path);
    let control_commands = resolve_control_commands(
        &host_overrides,
        &node.node_slot_id,
        &node.node_alias,
        &node.physical_machine_id,
        &inventory_path,
    );
    let role_operations = build_role_operations(&node_status, &control_commands);
    let atlas = build_atlas_links(&host_overrides, &node_status, &rpc);
    let control = build_control_capabilities(&control_commands);

    Ok(MonitorNodeDetails {
        inventory_path: inventory_path.to_string_lossy().to_string(),
        captured_at_utc: Utc::now().to_rfc3339(),
        status: node_status,
        protocol_profile,
        economics_profile,
        role_diagnostics,
        role_notes,
        role_execution,
        role_operations,
        rpc,
        atlas,
        control,
    })
}

pub async fn monitor_node_control(
    node_slot_id: String,
    action: String,
) -> Result<MonitorControlResult, String> {
    let normalized_action = normalize_action_key(&action);
    if normalized_action.is_empty() {
        return Err("Control action is empty".to_string());
    }

    let config = load_security_config()?;
    let operator = resolve_active_operator(&config)?;
    if !role_allows_control(&operator.role, &normalized_action) {
        append_audit_event(json!({
            "event_type": "control.single.denied",
            "operator_id": operator.operator_id,
            "operator_role": operator.role,
            "node_slot_id": node_slot_id,
            "action": normalized_action,
            "timestamp_utc": Utc::now().to_rfc3339(),
        }))?;
        return Err(format!(
            "RBAC denied: role '{}' cannot execute action '{}'",
            operator.role, normalized_action
        ));
    }

    execute_monitor_node_control(&node_slot_id, &normalized_action, &operator, "single").await
}

fn validator_operations_agent_token() -> Result<String, String> {
    std::env::var("SYNERGY_TESTNET_AGENT_TOKEN")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            "SYNERGY_TESTNET_AGENT_TOKEN is required for validator operations.".to_string()
        })
}

fn validator_operations_nodes(nodes: &[MonitorNode]) -> Vec<MonitorNode> {
    let mut validators = nodes
        .iter()
        .filter(|node| is_bootstrap_consensus_validator(node))
        .cloned()
        .collect::<Vec<_>>();
    validators.sort_by(|left, right| {
        monitor_node_slot_number(left)
            .unwrap_or(u8::MAX)
            .cmp(&monitor_node_slot_number(right).unwrap_or(u8::MAX))
            .then(left.node_slot_id.cmp(&right.node_slot_id))
    });
    validators.truncate(5);
    validators
}

fn validator_operations_node<'a>(
    nodes: &'a [MonitorNode],
    node_slot_id: &str,
) -> Result<&'a MonitorNode, String> {
    nodes
        .iter()
        .find(|node| {
            is_bootstrap_consensus_validator(node)
                && (node.node_slot_id.eq_ignore_ascii_case(node_slot_id)
                    || node.node_alias.eq_ignore_ascii_case(node_slot_id))
        })
        .ok_or_else(|| format!("Validator not found in inventory: {node_slot_id}"))
}

fn validator_operations_agent_url(
    node: &MonitorNode,
    host_overrides: &HashMap<String, String>,
    suffix: &str,
) -> Result<String, String> {
    let base = agent_endpoint_for_node(node, host_overrides).ok_or_else(|| {
        format!(
            "No management endpoint is configured for {}.",
            node.node_slot_id
        )
    })?;
    let mut url = Url::parse(&base)
        .map_err(|_| format!("Invalid management endpoint for {}.", node.node_slot_id))?;
    let (path_suffix, query) = suffix
        .split_once('?')
        .map_or((suffix, None), |(path, query)| (path, Some(query)));
    url.set_path(&format!(
        "/v1/validator-operations/nodes/{}/{}",
        node.node_slot_id, path_suffix
    ));
    url.set_query(query);
    Ok(url.to_string())
}

fn validator_operations_agent_client() -> Result<Client, String> {
    Client::builder()
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|error| format!("Failed to create validator operations client: {error}"))
}

async fn validator_operations_agent_get<T: for<'de> Deserialize<'de>>(
    node: &MonitorNode,
    host_overrides: &HashMap<String, String>,
    operator: &MonitorOperatorProfile,
    suffix: &str,
    scope: &str,
) -> Result<T, String> {
    let token = validator_operations_agent_token()?;
    let url = validator_operations_agent_url(node, host_overrides, suffix)?;
    let response = validator_operations_agent_client()?
        .get(url)
        .bearer_auth(token)
        .header("x-synergy-operator-id", &operator.operator_id)
        .header("x-synergy-operator-scopes", scope)
        .send()
        .await
        .map_err(|error| {
            format!(
                "Validator operations agent unavailable for {}: {error}",
                node.node_slot_id
            )
        })?;
    if !response.status().is_success() {
        return Err(format!(
            "Validator operations agent returned {} for {}.",
            response.status(),
            node.node_slot_id
        ));
    }
    response.json::<T>().await.map_err(|error| {
        format!(
            "Invalid validator operations response for {}: {error}",
            node.node_slot_id
        )
    })
}

async fn validator_operations_agent_post<B: Serialize, T: for<'de> Deserialize<'de>>(
    node: &MonitorNode,
    host_overrides: &HashMap<String, String>,
    operator: &MonitorOperatorProfile,
    suffix: &str,
    scope: &str,
    body: &B,
) -> Result<T, String> {
    let token = validator_operations_agent_token()?;
    let url = validator_operations_agent_url(node, host_overrides, suffix)?;
    let response = validator_operations_agent_client()?
        .post(url)
        .bearer_auth(token)
        .header("x-synergy-operator-id", &operator.operator_id)
        .header("x-synergy-operator-scopes", scope)
        .json(body)
        .send()
        .await
        .map_err(|error| {
            format!(
                "Validator operations agent unavailable for {}: {error}",
                node.node_slot_id
            )
        })?;
    if !response.status().is_success() {
        return Err(format!(
            "Validator operations agent returned {} for {}.",
            response.status(),
            node.node_slot_id
        ));
    }
    response.json::<T>().await.map_err(|error| {
        format!(
            "Invalid validator operations response for {}: {error}",
            node.node_slot_id
        )
    })
}

async fn validator_operations_context() -> Result<
    (
        Vec<MonitorNode>,
        HashMap<String, String>,
        MonitorOperatorProfile,
    ),
    String,
> {
    let inventory_path = resolve_inventory_path()?;
    let nodes = load_inventory_nodes(&inventory_path)?;
    let mut host_overrides = load_hosts_overrides(&inventory_path);
    augment_host_overrides_with_runtime_placements(&mut host_overrides).await;
    let operator = resolve_active_operator(&load_security_config()?)?;
    Ok((nodes, host_overrides, operator))
}

pub async fn monitor_validator_operations_cluster_status(
) -> Result<ValidatorOperationsClusterStatus, String> {
    let (nodes, host_overrides, operator) = validator_operations_context().await?;
    let validators = validator_operations_nodes(&nodes);
    if validators.len() != 5 {
        return Err(format!(
            "Expected five validator inventory entries, discovered {}.",
            validators.len()
        ));
    }
    let futures = validators.iter().map(|node| {
        validator_operations_agent_get::<ValidatorOperationsStatus>(
            node,
            &host_overrides,
            &operator,
            "status",
            "validator.operations.read",
        )
    });
    let results = join_all(futures).await;
    let mut statuses = Vec::new();
    let mut unavailable = Vec::new();
    for (node, result) in validators.iter().zip(results) {
        match result {
            Ok(status) => statuses.push(status),
            Err(_) => unavailable.push(node.node_slot_id.clone()),
        }
    }
    Ok(aggregate_validator_statuses(statuses, unavailable))
}

pub async fn monitor_validator_operations_status(
    node_slot_id: String,
) -> Result<ValidatorOperationsStatus, String> {
    let (nodes, host_overrides, operator) = validator_operations_context().await?;
    let node = validator_operations_node(&nodes, &node_slot_id)?;
    validator_operations_agent_get(
        node,
        &host_overrides,
        &operator,
        "status",
        "validator.operations.read",
    )
    .await
}

pub async fn monitor_validator_operations_preflight(
    node_slot_id: String,
) -> Result<HostPreflightStatus, String> {
    let (nodes, host_overrides, operator) = validator_operations_context().await?;
    let node = validator_operations_node(&nodes, &node_slot_id)?;
    validator_operations_agent_get(
        node,
        &host_overrides,
        &operator,
        "preflight",
        "validator.operations.read",
    )
    .await
}

pub async fn monitor_validator_operations_logs(
    node_slot_id: String,
    limit: Option<usize>,
) -> Result<StructuredLogsResponse, String> {
    let (nodes, host_overrides, operator) = validator_operations_context().await?;
    let node = validator_operations_node(&nodes, &node_slot_id)?;
    let suffix = format!("logs?limit={}", limit.unwrap_or(200).clamp(1, 500));
    validator_operations_agent_get(
        node,
        &host_overrides,
        &operator,
        &suffix,
        "validator.operations.read",
    )
    .await
}

pub async fn monitor_validator_operations_lifecycle(
    node_slot_id: String,
    request: ValidatorLifecycleRequest,
) -> Result<ValidatorLifecycleResult, String> {
    let (nodes, host_overrides, operator) = validator_operations_context().await?;
    let node = validator_operations_node(&nodes, &node_slot_id)?;
    let action = request.action.as_nodectl_action();
    if !role_allows_control(&operator.role, action) {
        append_audit_event(
            json!({"event_type":"validator.operations.lifecycle.denied","operator_id":operator.operator_id,"node_slot_id":node.node_slot_id,"action":action,"timestamp_utc":Utc::now().to_rfc3339()}),
        )?;
        return Err(format!(
            "RBAC denied: role '{}' cannot execute action '{}'",
            operator.role, action
        ));
    }
    append_audit_event(
        json!({"event_type":"validator.operations.lifecycle.authorized","operator_id":operator.operator_id,"node_slot_id":node.node_slot_id,"action":action,"timestamp_utc":Utc::now().to_rfc3339()}),
    )?;
    let result = validator_operations_agent_post(
        node,
        &host_overrides,
        &operator,
        "control",
        "validator.operations.control",
        &request,
    )
    .await;
    append_audit_event(
        json!({"event_type":"validator.operations.lifecycle.completed","operator_id":operator.operator_id,"node_slot_id":node.node_slot_id,"action":action,"success":result.is_ok(),"timestamp_utc":Utc::now().to_rfc3339()}),
    )?;
    result
}

pub async fn monitor_validator_operations_snapshot(
    node_slot_id: String,
) -> Result<DiagnosticSnapshotResult, String> {
    let (nodes, host_overrides, operator) = validator_operations_context().await?;
    let node = validator_operations_node(&nodes, &node_slot_id)?;
    if !role_allows_control(&operator.role, "export_logs") {
        append_audit_event(
            json!({"event_type":"validator.operations.snapshot.denied","operator_id":operator.operator_id,"node_slot_id":node.node_slot_id,"timestamp_utc":Utc::now().to_rfc3339()}),
        )?;
        return Err(
            "RBAC denied: diagnostic snapshot capture requires node-control permission."
                .to_string(),
        );
    }
    append_audit_event(
        json!({"event_type":"validator.operations.snapshot.authorized","operator_id":operator.operator_id,"node_slot_id":node.node_slot_id,"timestamp_utc":Utc::now().to_rfc3339()}),
    )?;
    let result = validator_operations_agent_post(
        node,
        &host_overrides,
        &operator,
        "diagnostic-snapshots",
        "validator.operations.snapshot",
        &json!({}),
    )
    .await;
    append_audit_event(
        json!({"event_type":"validator.operations.snapshot.completed","operator_id":operator.operator_id,"node_slot_id":node.node_slot_id,"success":result.is_ok(),"timestamp_utc":Utc::now().to_rfc3339()}),
    )?;
    result
}

pub async fn monitor_update_local_agent_from_context(
    node_slot_id: String,
    app_context: &AppContext,
) -> Result<MonitorControlResult, String> {
    let inventory_path = resolve_inventory_path()?;
    let nodes = load_inventory_nodes(&inventory_path)?;
    let node = nodes
        .iter()
        .find(|candidate| {
            candidate.node_slot_id.eq_ignore_ascii_case(&node_slot_id)
                || candidate.node_alias.eq_ignore_ascii_case(&node_slot_id)
        })
        .cloned()
        .ok_or_else(|| format!("Node not found in inventory: {node_slot_id}"))?;

    let identity = monitor_detect_local_machine_identity()?;
    if !identity.detected {
        return Err(format!(
            "Local testnet-agent self-update is only available on the target machine. {}",
            identity.message
        ));
    }

    let local_machine_id = identity
        .physical_machine_id
        .clone()
        .ok_or_else(|| "Local physical machine identity is unavailable.".to_string())?;
    if !node
        .physical_machine_id
        .eq_ignore_ascii_case(local_machine_id.as_str())
    {
        return Err(format!(
            "Node {} belongs to {}, but this control panel is running on {}. Open the control panel on the target machine to update its local testnet agent without SSH.",
            node.node_slot_id, node.physical_machine_id, local_machine_id
        ));
    }

    let installed_binary =
        crate::agent::force_update_local_testnet_agent_from_context(app_context).await?;
    Ok(MonitorControlResult {
        node_slot_id: node.node_slot_id.clone(),
        action: "update_agent".to_string(),
        success: true,
        exit_code: 0,
        command: "local testnet agent self-update".to_string(),
        stdout: format!(
            "Updated the local testnet agent for {} on {} using the bundled resource binary at {}.",
            node.node_slot_id,
            node.physical_machine_id,
            installed_binary.display()
        ),
        stderr: String::new(),
        executed_at_utc: Utc::now().to_rfc3339(),
    })
}

/// Timeout applied to every terminal command. Long-running installer scripts
/// (e.g. Windows `install_and_start.ps1`) can block indefinitely when the
/// spawned node process inherits Rust's stdout/stderr pipe handles. Five
/// minutes is generous for any legitimate setup step; if it is exceeded the
/// command is killed and an error is returned so the autopilot can surface the
/// failure rather than leaving the UI frozen.
const TERMINAL_COMMAND_TIMEOUT_SECS: u64 = 300;

pub async fn monitor_run_terminal_command(
    command: String,
    cwd: Option<String>,
) -> Result<MonitorTerminalCommandResult, String> {
    let trimmed = command.trim().to_string();
    if trimmed.is_empty() {
        return Err("command is required".to_string());
    }

    let effective_cwd = if let Some(candidate) = cwd
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        let path = PathBuf::from(candidate);
        if !path.is_dir() {
            return Err(format!(
                "cwd does not exist or is not a directory: {candidate}"
            ));
        }
        path
    } else {
        std::env::current_dir()
            .map_err(|error| format!("Failed to resolve current dir: {error}"))?
    };

    let trimmed_clone = trimmed.clone();
    let cwd_clone = effective_cwd.clone();

    // Spawn the blocking `.output()` call onto a dedicated thread so that the
    // async runtime is not stalled, then race it against a timeout. This also
    // means a hung process will be killed (via the JoinHandle being dropped)
    // rather than keeping a desktop worker thread permanently occupied.
    let output_result = tokio::time::timeout(
        tokio::time::Duration::from_secs(TERMINAL_COMMAND_TIMEOUT_SECS),
        tokio::task::spawn_blocking(move || {
            build_terminal_process(&trimmed_clone).and_then(|mut process| {
                process
                    .current_dir(&cwd_clone)
                    .output()
                    .map_err(|error| format!("Failed to execute command '{trimmed_clone}': {error}"))
            })
        }),
    )
    .await
    .map_err(|_| {
        format!(
            "Command timed out after {TERMINAL_COMMAND_TIMEOUT_SECS}s (possible hung process): {trimmed}"
        )
    })?
    .map_err(|join_error| format!("Command task panicked: {join_error}"))?;

    let output = output_result?;

    let success = output.status.success();
    let exit_code = output.status.code().unwrap_or(if success { 0 } else { 1 });
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    Ok(MonitorTerminalCommandResult {
        success,
        exit_code,
        command: trimmed.to_string(),
        cwd: effective_cwd.to_string_lossy().to_string(),
        stdout: truncate_text(stdout.trim_end(), 50000),
        stderr: truncate_text(stderr.trim_end(), 50000),
        executed_at_utc: Utc::now().to_rfc3339(),
    })
}

fn build_terminal_process(command: &str) -> Result<ProcessCommand, String> {
    #[cfg(target_os = "windows")]
    {
        return build_windows_terminal_process(command);
    }

    #[cfg(not(target_os = "windows"))]
    {
        let mut cmd = ProcessCommand::new("bash");
        cmd.arg("-lc").arg(command);
        Ok(cmd)
    }
}

#[cfg(target_os = "windows")]
fn build_windows_terminal_process(command: &str) -> Result<ProcessCommand, String> {
    let tokens = split_command_arguments(command)?;
    if let Some(executable) = tokens.first() {
        let normalized = executable.to_ascii_lowercase();
        if matches!(
            normalized.as_str(),
            "powershell" | "powershell.exe" | "pwsh" | "pwsh.exe"
        ) {
            let mut cmd = ProcessCommand::new(executable);
            if tokens.len() > 1 {
                cmd.args(tokens.iter().skip(1));
            }
            return Ok(cmd);
        }
    }

    let mut cmd = ProcessCommand::new("cmd");
    cmd.arg("/C").arg(command);
    Ok(cmd)
}

#[allow(dead_code)]
fn split_command_arguments(command: &str) -> Result<Vec<String>, String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut active_quote = None;

    for ch in command.chars() {
        match active_quote {
            Some(quote) if ch == quote => active_quote = None,
            Some(_) => current.push(ch),
            None if ch == '"' || ch == '\'' => active_quote = Some(ch),
            None if ch.is_whitespace() => {
                if !current.is_empty() {
                    tokens.push(mem::take(&mut current));
                }
            }
            None => current.push(ch),
        }
    }

    if let Some(quote) = active_quote {
        return Err(format!(
            "Unterminated quoted argument in command: missing closing {quote}"
        ));
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    if tokens.is_empty() {
        return Err("command is required".to_string());
    }

    Ok(tokens)
}

#[cfg(test)]
mod terminal_command_tests {
    use super::{
        agent_error_requires_ssh_fallback, ensure_monitor_workspace_with_context,
        load_inventory_nodes, load_node_address_map, logical_nodes_for_physical_machine,
        physical_machine_for_binding_target, preferred_control_plane_host,
        preferred_public_inventory_host, resolve_host_override, resolve_inventory_path,
        split_command_arguments, validator_cluster_count, validator_largest_cluster_size,
        validator_network_cluster_quorum_threshold, validator_operations_nodes,
        validator_quorum_threshold, validator_vpn_identity_for_monitor_node,
        validator_vpn_monitor_coordinator_url, MonitorNode, DEFAULT_VALIDATOR_VPN_COORDINATOR_URL,
        MONITOR_WORKSPACE_ENV,
    };
    use crate::app_context::AppContext;
    use once_cell::sync::Lazy;
    use std::collections::HashMap;
    use std::ffi::OsString;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, MutexGuard};
    use tempfile::TempDir;

    static MONITOR_ENV_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<OsString>,
    }

    struct CurrentDirGuard {
        previous: PathBuf,
    }

    impl EnvVarGuard {
        fn set_value(key: &'static str, value: &str) -> Self {
            let previous = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, previous }
        }

        fn set_path(key: &'static str, value: &Path) -> Self {
            let previous = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, previous }
        }

        fn remove(key: &'static str) -> Self {
            let previous = std::env::var_os(key);
            std::env::remove_var(key);
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(previous) = &self.previous {
                std::env::set_var(self.key, previous);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    impl CurrentDirGuard {
        fn set(path: &Path) -> Self {
            let previous = std::env::current_dir().expect("current dir should resolve");
            std::env::set_current_dir(path).expect("current dir should update");
            Self { previous }
        }
    }

    impl Drop for CurrentDirGuard {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.previous);
        }
    }

    fn monitor_env_lock() -> MutexGuard<'static, ()> {
        MONITOR_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn monitor_fixture_inventory_path() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/monitor/node-inventory.test.csv")
    }

    #[test]
    fn loads_packaged_node_addresses_before_legacy_generated_key_map() {
        let temp = TempDir::new().expect("monitor runtime directory");
        let inventory_path = temp.path().join("node-inventory.csv");
        fs::write(&inventory_path, "node_slot_id,node_alias\n").expect("inventory fixture");
        fs::create_dir_all(temp.path().join("keys")).expect("legacy keys directory");
        fs::write(
            temp.path().join("node-addresses.csv"),
            "node_slot_id,node_alias,role,node_type,address_class,address\nNode-REL3,relayer3,relayer,relayer,2,synv2canonical\n",
        )
        .expect("packaged address map");
        fs::write(
            temp.path().join("keys/node-addresses.csv"),
            "node_slot_id,node_alias,role,node_type,address_class,address\nNode-REL3,relayer3,relayer,relayer,2,synv2stale\n",
        )
        .expect("legacy address map");

        let addresses = load_node_address_map(&inventory_path);

        assert_eq!(
            addresses.get("node-rel3"),
            Some(&"synv2canonical".to_string())
        );
    }

    #[test]
    fn falls_back_to_legacy_generated_node_address_map_for_existing_workspaces() {
        let temp = TempDir::new().expect("monitor runtime directory");
        let inventory_path = temp.path().join("node-inventory.csv");
        fs::write(&inventory_path, "node_slot_id,node_alias\n").expect("inventory fixture");
        fs::create_dir_all(temp.path().join("keys")).expect("legacy keys directory");
        fs::write(
            temp.path().join("keys/node-addresses.csv"),
            "node_slot_id,node_alias,role,node_type,address_class,address\nNode-REL3,relayer3,relayer,relayer,2,synv2legacy\n",
        )
        .expect("legacy address map");

        let addresses = load_node_address_map(&inventory_path);

        assert_eq!(addresses.get("node-rel3"), Some(&"synv2legacy".to_string()));
    }

    #[test]
    fn validator_vpn_monitor_coordinator_url_uses_dns_default_without_env() {
        let _lock = monitor_env_lock();
        let _agent_url = EnvVarGuard::remove("VALIDATOR_VPN_COORDINATOR_URL");
        let _synergy_url = EnvVarGuard::remove("SYNERGY_VALIDATOR_VPN_COORDINATOR_URL");

        assert_eq!(
            validator_vpn_monitor_coordinator_url().as_deref(),
            Some(DEFAULT_VALIDATOR_VPN_COORDINATOR_URL)
        );
    }

    #[test]
    fn validator_quorum_threshold_matches_cluster_policy() {
        assert_eq!(validator_quorum_threshold(0), 0);
        assert_eq!(validator_quorum_threshold(5), 4);
        assert_eq!(validator_quorum_threshold(6), 5);
        assert_eq!(validator_quorum_threshold(7), 5);
    }

    #[test]
    fn validator_network_quorum_uses_largest_balanced_cluster() {
        for (validators, clusters, largest_cluster, quorum) in [
            (0, 0, 0, 0),
            (6, 1, 6, 5),
            (9, 1, 9, 7),
            (10, 2, 5, 4),
            (15, 2, 8, 6),
            (20, 2, 10, 7),
            (21, 3, 7, 5),
            (27, 3, 9, 7),
            (28, 4, 7, 5),
            (29, 4, 8, 6),
            (35, 5, 7, 5),
        ] {
            assert_eq!(validator_cluster_count(validators), clusters);
            assert_eq!(validator_largest_cluster_size(validators), largest_cluster);
            assert_eq!(
                validator_network_cluster_quorum_threshold(validators),
                quorum
            );
        }
    }

    #[test]
    fn validator_vpn_monitor_coordinator_url_prefers_installer_env() {
        let _lock = monitor_env_lock();
        let _agent_url = EnvVarGuard::remove("VALIDATOR_VPN_COORDINATOR_URL");
        let _synergy_url = EnvVarGuard::set_value(
            "SYNERGY_VALIDATOR_VPN_COORDINATOR_URL",
            "https://installer-vpn.example",
        );

        assert_eq!(
            validator_vpn_monitor_coordinator_url().as_deref(),
            Some("https://installer-vpn.example")
        );
    }

    fn monitor_vpn_test_node(role: &str, slot: u8) -> MonitorNode {
        let node_name = format!("{role}-{slot}");
        MonitorNode {
            node_slot_id: node_name.clone(),
            node_alias: node_name.clone(),
            role_group: role.to_string(),
            role: role.to_string(),
            node_type: role.to_string(),
            operator: None,
            device: None,
            host: node_name.clone(),
            management_host: None,
            rpc_port: 5640,
            p2p_port: 5620,
            ws_port: 5660,
            grpc_port: 5640,
            discovery_port: 5680,
            rpc_url: format!("http://{node_name}:5640"),
            node_address: None,
            physical_machine_id: node_name,
        }
    }

    #[test]
    fn validator_operations_discovery_selects_exactly_five_consensus_validators() {
        let mut nodes = (2..=6)
            .map(|slot| {
                let mut node = monitor_vpn_test_node("validator", slot);
                node.role_group = "consensus".to_string();
                node.node_type = "validator".to_string();
                node
            })
            .collect::<Vec<_>>();
        nodes.push(monitor_vpn_test_node("relayer", 1));
        let selected = validator_operations_nodes(&nodes);
        assert_eq!(selected.len(), 5);
        assert_eq!(
            selected
                .iter()
                .map(|node| node.node_slot_id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "validator-2",
                "validator-3",
                "validator-4",
                "validator-5",
                "validator-6"
            ]
        );
    }

    #[test]
    fn monitor_validator_vpn_identity_uses_innernet_validator_subnet() {
        for (slot, expected_id) in [(1, "bootstrap-validator-1"), (7, "validator-7")] {
            let identity =
                validator_vpn_identity_for_monitor_node(&monitor_vpn_test_node("validator", slot))
                    .expect("validator should receive a VPN identity");
            assert_eq!(identity.0, expected_id);
            assert_eq!(identity.1, format!("10.70.10.{slot}/32"));
            assert!(!identity.1.starts_with("10.69."));
        }
    }

    #[test]
    fn monitor_relayer_vpn_identity_uses_innernet_relayer_subnet() {
        let identity =
            validator_vpn_identity_for_monitor_node(&monitor_vpn_test_node("relayer", 3))
                .expect("bootstrap relayer should receive a VPN identity");

        assert_eq!(identity.0, "bootstrap-relayer-3");
        assert_eq!(identity.1, "10.70.20.3/32");
        assert!(!identity.1.starts_with("10.69."));
    }

    fn with_monitor_fixture_inventory(test: impl FnOnce()) {
        let _lock = monitor_env_lock();
        let temp = TempDir::new().expect("monitor temp home");
        let _home = EnvVarGuard::set_path("HOME", temp.path());
        let _user_profile = EnvVarGuard::set_path("USERPROFILE", temp.path());
        let _workspace =
            EnvVarGuard::set_path(MONITOR_WORKSPACE_ENV, &temp.path().join("workspace"));
        let _inventory = EnvVarGuard::set_path(
            "SYNERGY_MONITOR_INVENTORY",
            &monitor_fixture_inventory_path(),
        );
        test();
    }

    #[test]
    fn monitor_workspace_honors_explicit_coordinator_workspace_env() {
        let _lock = monitor_env_lock();
        let temp = TempDir::new().expect("monitor temp workspace");
        let workspace = temp.path().join("coordinator-monitor-workspace");
        let _home = EnvVarGuard::set_path("HOME", temp.path());
        let _user_profile = EnvVarGuard::set_path("USERPROFILE", temp.path());
        let _workspace = EnvVarGuard::set_path(MONITOR_WORKSPACE_ENV, &workspace);

        let resolved = ensure_monitor_workspace_with_context(&AppContext::from_env())
            .expect("coordinator workspace should initialize");

        assert_eq!(resolved, workspace);
    }

    #[test]
    fn monitor_workspace_refreshes_validator_vpn_bundle_assets() {
        let _lock = monitor_env_lock();
        let temp = TempDir::new().expect("monitor temp workspace");
        let resource_root = temp.path().join("resources");
        let workspace = temp.path().join("workspace");

        fs::create_dir_all(resource_root.join("testnet/runtime/configs")).expect("configs dir");
        fs::create_dir_all(resource_root.join("testnet/runtime/installers"))
            .expect("installers dir");
        fs::create_dir_all(resource_root.join("testnet/runtime/validator-vpn"))
            .expect("validator vpn dir");
        fs::create_dir_all(resource_root.join("binaries")).expect("binaries dir");
        fs::create_dir_all(resource_root.join("guides")).expect("guides dir");

        fs::write(
            resource_root.join("testnet/runtime/node-inventory.csv"),
            "role_id,host,ssh_alias\nvalidator-1,localhost,local\n",
        )
        .expect("inventory");
        fs::write(
            resource_root.join("testnet/runtime/hosts.env.example"),
            "SYNERGY_MONITOR_INVENTORY=testnet/runtime/node-inventory.csv\n",
        )
        .expect("hosts env example");
        fs::write(
            resource_root.join("testnet/runtime/validator-vpn/validator-vpn-coordinator.env"),
            "SYNERGY_VALIDATOR_VPN_COORDINATOR_URL=https://vpn-coordinator.synergy-network.io\n",
        )
        .expect("validator vpn coordinator env");
        fs::write(
            resource_root.join("guides/SYNERGY_TESTNET_CONTROL_PANEL_USER_MANUAL.md"),
            "# User Manual\n",
        )
        .expect("manual");
        fs::write(
            resource_root.join("testnet/runtime/workspace-manifest.json"),
            r#"{
  "workspace_resource_version": "test",
  "required_paths": [
    "testnet/runtime/workspace-manifest.json",
    "testnet/runtime/validator-vpn/validator-vpn-coordinator.env"
  ]
}
"#,
        )
        .expect("manifest");

        let _home = EnvVarGuard::set_path("HOME", temp.path());
        let _user_profile = EnvVarGuard::set_path("USERPROFILE", temp.path());
        let _resource_root = EnvVarGuard::set_path("SYNERGY_RESOURCE_ROOT", &resource_root);
        let _workspace = EnvVarGuard::set_path(MONITOR_WORKSPACE_ENV, &workspace);

        let resolved = ensure_monitor_workspace_with_context(&AppContext::from_env())
            .expect("workspace should initialize from resource root");

        assert_eq!(resolved, workspace);
        let copied_env = fs::read_to_string(
            workspace.join("testnet/runtime/validator-vpn/validator-vpn-coordinator.env"),
        )
        .expect("validator vpn env should copy to monitor workspace");
        assert_eq!(
            copied_env,
            "SYNERGY_VALIDATOR_VPN_COORDINATOR_URL=https://vpn-coordinator.synergy-network.io\n"
        );
    }

    #[test]
    fn splits_powershell_file_command_with_windows_path() {
        let tokens = split_command_arguments(
            r#"powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Users\blueiris\.synergy-node-control-panel\monitor-workspace\testnet\runtime\installers\node-12\install_and_start.ps1""#,
        )
        .expect("command should parse");

        assert_eq!(
            tokens,
            vec![
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                r"C:\Users\blueiris\.synergy-node-control-panel\monitor-workspace\testnet\runtime\installers\node-12\install_and_start.ps1",
            ]
        );
    }

    #[test]
    fn keeps_powershell_command_payload_as_single_argument() {
        let tokens = split_command_arguments(
            r#"powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem 'keys/ssh' -Force | Format-Table -AutoSize Name,Length,LastWriteTime""#,
        )
        .expect("command should parse");

        assert_eq!(
            tokens,
            vec![
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                "Get-ChildItem 'keys/ssh' -Force | Format-Table -AutoSize Name,Length,LastWriteTime",
            ]
        );
    }

    #[test]
    fn stale_agent_action_errors_trigger_ssh_fallback() {
        assert!(agent_error_requires_ssh_fallback(
            r#"{"error":"Unsupported testnet agent action: sync_node"}"#
        ));
        assert!(agent_error_requires_ssh_fallback(
            "Unsupported testnet agent action: sync_node"
        ));
        assert!(!agent_error_requires_ssh_fallback(
            r#"{"error":"agent access restricted to loopback or approved management networks"}"#
        ));
    }

    #[test]
    fn binding_targets_follow_current_topology() {
        with_monitor_fixture_inventory(|| {
            assert_eq!(
                physical_machine_for_binding_target("Validator-01"),
                Some("validator-01".to_string())
            );
            assert_eq!(
                physical_machine_for_binding_target("Node-RPC"),
                Some("node-rpc".to_string())
            );
            assert_eq!(
                physical_machine_for_binding_target("Node-0A"),
                Some("node-0a".to_string())
            );
        });
    }

    #[test]
    fn logical_nodes_follow_current_topology() {
        with_monitor_fixture_inventory(|| {
            assert_eq!(
                logical_nodes_for_physical_machine("Validator-01")
                    .expect("Validator-01 should resolve"),
                vec!["validator-01"]
            );
            assert_eq!(
                logical_nodes_for_physical_machine("Node-RPC").expect("Node-RPC should resolve"),
                vec!["node-rpc"]
            );
            assert_eq!(
                logical_nodes_for_physical_machine("Node-0A").expect("Node-0A should resolve"),
                vec!["node-0a"]
            );
        });
    }

    #[test]
    fn monitor_fixture_inventory_loads_without_workbook_credentials() {
        with_monitor_fixture_inventory(|| {
            let inventory_path =
                resolve_inventory_path().expect("fixture inventory should resolve");
            assert_eq!(inventory_path, monitor_fixture_inventory_path());

            let nodes =
                load_inventory_nodes(&inventory_path).expect("fixture inventory should load");
            assert_eq!(nodes.len(), 3);
            assert!(nodes.iter().any(|node| {
                node.node_alias == "Validator-01"
                    && node.physical_machine_id == "validator-01"
                    && node.host == "203.0.113.11"
                    && node.management_host.as_deref() == Some("198.51.100.11")
            }));
        });
    }

    #[test]
    fn missing_monitor_inventory_reports_operator_remediation() {
        let _lock = monitor_env_lock();
        let temp = TempDir::new().expect("monitor temp home");
        let workspace = temp
            .path()
            .join("workspace-without-inventory")
            .join("missing");
        let _home = EnvVarGuard::set_path("HOME", temp.path());
        let _user_profile = EnvVarGuard::set_path("USERPROFILE", temp.path());
        let _workspace = EnvVarGuard::set_path(MONITOR_WORKSPACE_ENV, &workspace);
        let _inventory = EnvVarGuard::set_path(
            "SYNERGY_MONITOR_INVENTORY",
            &temp.path().join("missing.csv"),
        );
        let _cwd = CurrentDirGuard::set(temp.path());

        let error = resolve_inventory_path().expect_err("missing inventory should fail");
        assert!(
            error.contains("Set SYNERGY_MONITOR_INVENTORY"),
            "missing inventory error should explain remediation, got: {error}"
        );
    }

    #[test]
    fn invalid_monitor_inventory_reports_required_column() {
        let _lock = monitor_env_lock();
        let temp = TempDir::new().expect("monitor temp home");
        let inventory_path = temp.path().join("node-inventory.csv");
        std::fs::write(
            &inventory_path,
            "node_slot_id,node_alias,role_group,role,node_type,p2p_port,rpc_port,ws_port,grpc_port,discovery_port\n\
             validator-01,Validator-01,validator,validator,validator,5620,5640,5660,5640,5680\n",
        )
        .expect("invalid fixture should write");

        let error =
            load_inventory_nodes(&inventory_path).expect_err("inventory without host should fail");
        assert!(
            error.contains("required column 'host'"),
            "invalid inventory should report the missing required column, got: {error}"
        );
    }

    #[test]
    fn prefers_real_machine_address_for_generated_control_plane_host() {
        assert_eq!(
            preferred_control_plane_host(
                "10.50.0.7",
                "10.50.0.7",
                "62.146.182.208",
                "192.168.11.98"
            ),
            "192.168.11.98"
        );
    }

    #[test]
    fn prefers_management_host_over_public_validator_ip_for_control_plane_host() {
        assert_eq!(
            preferred_control_plane_host(
                "62.146.182.207",
                "192.168.11.228",
                "62.146.182.207",
                "192.168.11.228",
            ),
            "192.168.11.228"
        );
    }

    #[test]
    fn preserves_public_validator_ip_for_inventory_host() {
        assert_eq!(
            preferred_public_inventory_host(
                "62.146.182.207",
                "192.168.11.228",
                "62.146.182.207",
                "192.168.11.228",
                "machine-01",
            ),
            "62.146.182.207"
        );
    }

    #[test]
    fn host_override_prefers_non_overlay_management_host() {
        let overrides = HashMap::from([
            ("node_12_host".to_string(), "192.168.11.98".to_string()),
            (
                "node_12_management_host".to_string(),
                "192.168.11.99".to_string(),
            ),
        ]);

        assert_eq!(
            resolve_host_override(
                &overrides,
                "node-12",
                "interop-04",
                "192.168.11.98".to_string(),
            ),
            "192.168.11.99"
        );
    }
}

pub fn monitor_apply_testnet_topology_from_context(
    app_context: &AppContext,
) -> Result<String, String> {
    let workspace = ensure_monitor_workspace_with_context(app_context)?;
    apply_monitor_testnet_topology(&workspace)
}

fn apply_monitor_testnet_topology(workspace: &Path) -> Result<String, String> {
    let inventory_path = workspace.join("testnet/runtime/node-inventory.csv");
    sanitize_inventory_hosts(&inventory_path)?;

    let mut warnings = Vec::new();

    let hosts_env_path = workspace.join("testnet/runtime/hosts.env");
    generate_monitor_hosts_env(&workspace, &inventory_path, &hosts_env_path)?;

    // Re-render base configs from the refreshed inventory so bundled installer templates do
    // not keep shipping stale node roles, machine mappings, or bootstrap topology.
    let render_configs_script = workspace.join("scripts/testnet/render-configs.sh");
    if render_configs_script.is_file() {
        match ProcessCommand::new("bash")
            .arg(render_configs_script.to_string_lossy().to_string())
            .arg(hosts_env_path.to_string_lossy().to_string())
            .current_dir(&workspace)
            .output()
        {
            Ok(output) => {
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                    if stderr.is_empty() {
                        warnings.push(
                            "config render step failed; using previously extracted config templates"
                                .to_string(),
                        );
                    } else {
                        warnings.push(format!(
                            "config render step skipped ({stderr}); using previously extracted config templates"
                        ));
                    }
                }
            }
            Err(error) => warnings.push(format!(
                "config render step skipped ({error}); using previously extracted config templates"
            )),
        }
    }

    let installers_dir = workspace.join("testnet/runtime/installers");

    let entries = load_monitor_hosts_env_entries(&inventory_path)?;
    for entry in entries {
        let installer_dir = installers_dir.join(&entry.node_slot_id);
        if !installer_dir.is_dir() {
            continue;
        }
        let control_plane_host = preferred_control_plane_host(
            &entry.host,
            &entry.management_host,
            &entry.public_ip,
            &entry.local_ip,
        );
        if control_plane_host.is_empty() {
            continue;
        }
        apply_topology_to_installer_node_env(&installer_dir.join("node.env"), &control_plane_host)?;
        apply_topology_to_installer_node_toml(
            &installer_dir.join("config/node.toml"),
            &control_plane_host,
        )?;
    }

    let mut message = format!(
        "Applied 13-machine testnet topology to {} and installer configs; hosts.env refreshed.",
        inventory_path.display()
    );
    if !warnings.is_empty() {
        message.push(' ');
        message.push_str(&warnings.join(" "));
    }
    Ok(message)
}

pub async fn monitor_export_node_data(node_slot_id: String) -> Result<MonitorExportResult, String> {
    let details = get_monitor_node_details(node_slot_id.clone()).await?;
    let exported_at_utc = Utc::now().to_rfc3339();

    let inventory_path = PathBuf::from(&details.inventory_path);
    let export_root = inventory_path
        .parent()
        .map(|parent| parent.join("reports").join("node-monitor-exports"))
        .unwrap_or_else(|| PathBuf::from("reports/node-monitor-exports"));
    fs::create_dir_all(&export_root).map_err(|e| {
        format!(
            "Failed to create export directory {}: {}",
            export_root.display(),
            e
        )
    })?;

    let file_stem = format!(
        "{}-node-snapshot-{}",
        sanitize_filename_fragment(&details.status.node.node_slot_id),
        Utc::now().format("%Y%m%dT%H%M%SZ")
    );
    let output_path = export_root.join(format!("{file_stem}.json"));

    let payload = json!({
        "exported_at_utc": exported_at_utc,
        "node_slot_id": details.status.node.node_slot_id,
        "node_alias": details.status.node.node_alias,
        "inventory_path": details.inventory_path,
        "details": details,
    });

    let encoded = serde_json::to_vec_pretty(&payload).map_err(|e| {
        format!(
            "Failed to serialize node export payload for {}: {}",
            node_slot_id, e
        )
    })?;
    fs::write(&output_path, &encoded).map_err(|e| {
        format!(
            "Failed to write node export file {}: {}",
            output_path.display(),
            e
        )
    })?;

    Ok(MonitorExportResult {
        node_slot_id: details.status.node.node_slot_id,
        file_path: output_path.to_string_lossy().to_string(),
        bytes: encoded.len(),
        exported_at_utc,
    })
}

fn resolve_inventory_path() -> Result<PathBuf, String> {
    if let Ok(path) = std::env::var("SYNERGY_MONITOR_INVENTORY") {
        let candidate = PathBuf::from(path);
        if candidate.is_file() {
            return Ok(candidate);
        }
        return Err(format!(
            "Unable to resolve node-inventory.csv at {}. Set SYNERGY_MONITOR_INVENTORY to an absolute path to your inventory file.",
            candidate.display()
        ));
    }

    if let Ok(workspace) = resolve_monitor_workspace_path() {
        let workspace_inventory = workspace.join("testnet/runtime/node-inventory.csv");
        if workspace_inventory.is_file() {
            return Ok(workspace_inventory);
        }
    }

    let mut candidates = Vec::new();

    if let Ok(current_dir) = std::env::current_dir() {
        candidates.extend(discovery_candidates_from_base(&current_dir));
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            candidates.extend(discovery_candidates_from_base(exe_dir));
            candidates.push(exe_dir.join("../Resources/testnet/runtime/node-inventory.csv"));
            candidates.push(
                exe_dir.join("../Resources/_up_/_up_/_up_/testnet/runtime/node-inventory.csv"),
            );
        }
    }

    candidates
        .into_iter()
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| {
            "Unable to resolve node-inventory.csv. Set SYNERGY_MONITOR_INVENTORY to an absolute path to your inventory file.".to_string()
        })
}

fn discovery_candidates_from_base(base: &Path) -> Vec<PathBuf> {
    let mut output = Vec::new();
    output.push(base.join("testnet/runtime/node-inventory.csv"));
    output.push(base.join("node-inventory.csv"));

    for ancestor in base.ancestors().take(10) {
        output.push(ancestor.join("testnet/runtime/node-inventory.csv"));
    }

    output
}

fn load_inventory_nodes(inventory_path: &Path) -> Result<Vec<MonitorNode>, String> {
    let content = fs::read_to_string(inventory_path).map_err(|e| {
        format!(
            "Failed to read inventory file {}: {}",
            inventory_path.display(),
            e
        )
    })?;

    let mut lines = content.lines().filter(|line| !line.trim().is_empty());
    let header = lines
        .next()
        .ok_or_else(|| "Inventory file is empty".to_string())?;
    let header_cols = header
        .split(',')
        .map(|cell| cell.trim().trim_start_matches('\u{feff}').to_string())
        .collect::<Vec<_>>();
    let index_map = header_cols
        .iter()
        .enumerate()
        .map(|(idx, name)| (name.clone(), idx))
        .collect::<HashMap<_, _>>();

    let resolve_column = |aliases: &[&str]| -> Option<usize> {
        aliases
            .iter()
            .find_map(|name| index_map.get(*name).copied())
    };

    let hosts_overrides = load_hosts_overrides(inventory_path);
    let node_addresses = load_node_address_map(inventory_path);
    let runtime_dir = inventory_path
        .parent()
        .ok_or_else(|| "Inventory file is missing a parent directory".to_string())?;

    let Some(node_slot_idx) = resolve_column(&["node_slot_id", "machine_id"]) else {
        return Err("Inventory header missing required column 'node_slot_id'".to_string());
    };
    let Some(node_alias_idx) = resolve_column(&["node_alias", "node_id"]) else {
        return Err("Inventory header missing required column 'node_alias'".to_string());
    };
    let Some(role_group_idx) = resolve_column(&["role_group"]) else {
        return Err("Inventory header missing required column 'role_group'".to_string());
    };
    let Some(role_idx) = resolve_column(&["role"]) else {
        return Err("Inventory header missing required column 'role'".to_string());
    };
    let Some(node_type_idx) = resolve_column(&["node_type"]) else {
        return Err("Inventory header missing required column 'node_type'".to_string());
    };
    let Some(p2p_port_idx) = resolve_column(&["p2p_port"]) else {
        return Err("Inventory header missing required column 'p2p_port'".to_string());
    };
    let Some(rpc_port_idx) = resolve_column(&["rpc_port"]) else {
        return Err("Inventory header missing required column 'rpc_port'".to_string());
    };
    let Some(ws_port_idx) = resolve_column(&["ws_port"]) else {
        return Err("Inventory header missing required column 'ws_port'".to_string());
    };
    let Some(grpc_port_idx) = resolve_column(&["grpc_port"]) else {
        return Err("Inventory header missing required column 'grpc_port'".to_string());
    };
    let Some(discovery_port_idx) = resolve_column(&["discovery_port"]) else {
        return Err("Inventory header missing required column 'discovery_port'".to_string());
    };
    let Some(host_idx) = resolve_column(&["host"]) else {
        return Err("Inventory header missing required column 'host'".to_string());
    };
    let management_host_idx = resolve_column(&["management_host"]);
    let rpc_target_idx = resolve_column(&[
        "public_rpc_url",
        "rpc_url",
        "public_rpc_host",
        "rpc_host",
        "public_host",
    ]);
    let physical_machine_idx = resolve_column(&["physical_machine_id", "physical_machine"]);
    let operator_idx = resolve_column(&["operator"]);
    let device_idx = resolve_column(&["device"]);

    let mut nodes = Vec::new();

    for (line_number, line) in lines.enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }

        let cells = trimmed
            .split(',')
            .map(|cell| cell.trim().to_string())
            .collect::<Vec<_>>();
        if cells.len() < header_cols.len() {
            continue;
        }

        let get = |index: usize| -> String { cells.get(index).cloned().unwrap_or_default() };

        let node_slot_id = get(node_slot_idx);
        let node_alias = get(node_alias_idx);
        let host_from_inventory = get(host_idx);
        let host = resolve_host_override(
            &hosts_overrides,
            &node_slot_id,
            &node_alias,
            host_from_inventory.clone(),
        );

        let parse_port = |value: String, label: &str| -> Result<u16, String> {
            value.parse::<u16>().map_err(|_| {
                format!(
                    "Invalid {label} value '{value}' in inventory at line {}",
                    line_number + 2
                )
            })
        };

        let rpc_port = parse_port(get(rpc_port_idx), "rpc_port")?;
        let p2p_port = parse_port(get(p2p_port_idx), "p2p_port")?;
        let ws_port = parse_port(get(ws_port_idx), "ws_port")?;
        let grpc_port = parse_port(get(grpc_port_idx), "grpc_port")?;
        let discovery_port = parse_port(get(discovery_port_idx), "discovery_port")?;

        let rpc_target = rpc_target_idx
            .map(&get)
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        let rpc_url = rpc_target
            .as_deref()
            .map(|target| build_rpc_url(target, rpc_port))
            .unwrap_or_else(|| build_rpc_url(&host, rpc_port));

        let physical_machine_id = physical_machine_idx.map(&get).unwrap_or_default();
        let management_host = management_host_idx
            .map(&get)
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        let operator = operator_idx
            .map(&get)
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        let device = device_idx
            .map(&get)
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());

        nodes.push(MonitorNode {
            node_address: node_addresses
                .get(&node_slot_id.to_lowercase())
                .cloned()
                .or_else(|| fallback_node_address(runtime_dir, &node_slot_id)),
            physical_machine_id: if physical_machine_id.is_empty() {
                node_slot_id.clone()
            } else {
                physical_machine_id
            },
            node_slot_id,
            node_alias,
            role_group: get(role_group_idx),
            role: get(role_idx),
            node_type: get(node_type_idx),
            operator,
            device,
            host,
            management_host,
            rpc_port,
            p2p_port,
            ws_port,
            grpc_port,
            discovery_port,
            rpc_url,
        });
    }

    if nodes.is_empty() {
        return Err("No nodes were loaded from inventory".to_string());
    }

    Ok(nodes)
}

#[derive(Debug, Clone)]
struct InventoryBindingTarget {
    node_slot_id: String,
    node_alias: String,
    physical_machine_id: String,
}

fn load_inventory_binding_targets(inventory_path: &Path) -> Vec<InventoryBindingTarget> {
    let Ok(content) = fs::read_to_string(inventory_path) else {
        return Vec::new();
    };

    let mut lines = content.lines().filter(|line| !line.trim().is_empty());
    let Some(header) = lines.next() else {
        return Vec::new();
    };

    let header_cols = header
        .split(',')
        .map(|cell| cell.trim().trim_start_matches('\u{feff}').to_string())
        .collect::<Vec<_>>();
    let index_map = header_cols
        .iter()
        .enumerate()
        .map(|(idx, name)| (name.clone(), idx))
        .collect::<HashMap<_, _>>();

    let resolve_column = |aliases: &[&str]| -> Option<usize> {
        aliases
            .iter()
            .find_map(|name| index_map.get(*name).copied())
    };

    let Some(node_slot_idx) = resolve_column(&["node_slot_id", "machine_id"]) else {
        return Vec::new();
    };
    let Some(node_alias_idx) = resolve_column(&["node_alias", "node_id"]) else {
        return Vec::new();
    };
    let physical_machine_idx = resolve_column(&["physical_machine_id", "physical_machine"]);

    let mut targets = Vec::new();

    for line in lines {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }

        let cells = trimmed
            .split(',')
            .map(|cell| cell.trim().to_string())
            .collect::<Vec<_>>();
        if cells.len() < header_cols.len() {
            continue;
        }

        let node_slot_id = cells.get(node_slot_idx).cloned().unwrap_or_default();
        let node_alias = cells.get(node_alias_idx).cloned().unwrap_or_default();
        if node_slot_id.is_empty() || node_alias.is_empty() {
            continue;
        }

        let physical_machine_id = physical_machine_idx
            .and_then(|idx| cells.get(idx))
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| node_slot_id.clone());

        targets.push(InventoryBindingTarget {
            node_slot_id,
            node_alias,
            physical_machine_id,
        });
    }

    targets
}

fn load_hosts_overrides(inventory_path: &Path) -> HashMap<String, String> {
    let mut output = HashMap::new();
    let inventory_targets = load_inventory_binding_targets(inventory_path);
    if let Some(parent) = inventory_path.parent() {
        let hosts_file = parent.join("hosts.env");
        if hosts_file.is_file() {
            if let Ok(content) = fs::read_to_string(&hosts_file) {
                for raw_line in content.lines() {
                    let line = raw_line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }

                    let stripped = line.strip_prefix("export ").unwrap_or(line).trim();
                    let Some((raw_key, raw_value)) = stripped.split_once('=') else {
                        continue;
                    };

                    let key = raw_key.trim().to_lowercase();
                    let value = raw_value
                        .trim()
                        .trim_matches('"')
                        .trim_matches('\'')
                        .trim()
                        .to_string();

                    if !key.is_empty() && !value.is_empty() {
                        output.insert(key, value);
                    }
                }
            }
        }
    }

    // Security ssh bindings (if configured) override hosts.env for control and diagnostics.
    if let Ok(config) = load_security_config() {
        for binding in config.ssh_bindings {
            let Some(host_override) = binding
                .host_override
                .as_ref()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
            else {
                continue;
            };
            let targets = expand_binding_targets(binding.node_slot_id.as_str(), &inventory_targets);
            if targets.is_empty() {
                continue;
            }
            for target in targets {
                let target_snake = target.replace('-', "_");
                output.insert(target.clone(), host_override.clone());
                output.insert(target_snake.clone(), host_override.clone());
                output.insert(format!("{target_snake}_host"), host_override.clone());
            }
        }
    }

    output
}

fn binding_matches_target(
    binding_id: &str,
    node_slot_id: &str,
    node_alias: &str,
    physical_machine_id: &str,
) -> bool {
    binding_id.eq_ignore_ascii_case(node_slot_id)
        || binding_id.eq_ignore_ascii_case(node_alias)
        || binding_id.eq_ignore_ascii_case(physical_machine_id)
}

fn expand_binding_targets(
    binding_id: &str,
    inventory_targets: &[InventoryBindingTarget],
) -> Vec<String> {
    let normalized = binding_id.trim();
    if normalized.is_empty() {
        return Vec::new();
    }

    let mut targets = HashSet::new();
    targets.insert(normalized.to_ascii_lowercase());

    for target in inventory_targets {
        if binding_matches_target(
            normalized,
            &target.node_slot_id,
            &target.node_alias,
            &target.physical_machine_id,
        ) {
            targets.insert(target.node_slot_id.to_ascii_lowercase());
            targets.insert(target.node_alias.to_ascii_lowercase());
            targets.insert(target.physical_machine_id.to_ascii_lowercase());
        }
    }

    let mut ordered = targets.into_iter().collect::<Vec<_>>();
    ordered.sort();
    ordered
}

fn load_node_address_map(inventory_path: &Path) -> HashMap<String, String> {
    let mut output = HashMap::new();
    let Some(runtime_dir) = inventory_path.parent() else {
        return output;
    };

    // Installer bundles keep the canonical inventory beside node-inventory.csv. Older
    // workspaces generated the same map under keys/, so retain that fallback for resume.
    let Some(address_file) = [
        runtime_dir.join("node-addresses.csv"),
        runtime_dir.join("keys/node-addresses.csv"),
    ]
    .into_iter()
    .find(|candidate| candidate.is_file()) else {
        return output;
    };

    let Ok(content) = fs::read_to_string(&address_file) else {
        return output;
    };

    for line in content.lines().skip(1) {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let cells = trimmed
            .split(',')
            .map(|value| value.trim().to_string())
            .collect::<Vec<_>>();
        if cells.len() < 6 {
            continue;
        }

        let node_slot_id = cells[0].to_lowercase();
        let address = cells[5].to_string();
        if !node_slot_id.is_empty() && !address.is_empty() {
            output.insert(node_slot_id, address);
        }
    }

    output
}

fn fallback_node_address(runtime_dir: &Path, node_slot_id: &str) -> Option<String> {
    let candidates = [
        runtime_dir
            .join("keys")
            .join(node_slot_id)
            .join("address.txt"),
        runtime_dir
            .join("installers")
            .join(node_slot_id)
            .join("keys/address.txt"),
    ];

    for candidate in candidates {
        let Ok(raw) = fs::read_to_string(&candidate) else {
            continue;
        };
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    None
}

fn resolve_host_override(
    overrides: &HashMap<String, String>,
    node_slot_id: &str,
    node_alias: &str,
    fallback: String,
) -> String {
    let machine = node_slot_id.to_lowercase();
    let node = node_alias.to_lowercase();
    let machine_snake = machine.replace('-', "_");
    let node_snake = node.replace('-', "_");
    let fallback_key = fallback.to_lowercase();

    let candidate_keys = [
        format!("{}_management_host", machine_snake),
        format!("{}_management_host", node_snake),
        format!("{}_internal_host", machine_snake),
        format!("{}_internal_host", node_snake),
        format!("{}_p2p_host", machine_snake),
        format!("{}_p2p_host", node_snake),
        machine.clone(),
        machine_snake.clone(),
        format!("{}_host", machine_snake),
        node.clone(),
        node_snake.clone(),
        format!("{}_host", node_snake),
        fallback_key,
    ];

    for key in candidate_keys {
        if let Some(value) = overrides.get(&key) {
            return value.clone();
        }
    }

    fallback
}

fn resolve_management_host_override(
    overrides: &HashMap<String, String>,
    node_slot_id: &str,
    node_alias: &str,
    fallback: String,
) -> String {
    let machine = node_slot_id.to_lowercase().replace('-', "_");
    let node = node_alias.to_lowercase().replace('-', "_");

    for key in [
        format!("{machine}_management_host"),
        format!("{node}_management_host"),
        format!("{machine}_internal_host"),
        format!("{node}_internal_host"),
        format!("{machine}_p2p_host"),
        format!("{node}_p2p_host"),
    ] {
        if let Some(value) = overrides.get(&key) {
            return value.clone();
        }
    }

    fallback
}

fn build_rpc_url(host: &str, rpc_port: u16) -> String {
    let trimmed = host.trim().trim_end_matches('/');
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        if has_explicit_port(trimmed) {
            trimmed.to_string()
        } else {
            format!("{trimmed}:{rpc_port}")
        }
    } else {
        format!("http://{trimmed}:{rpc_port}")
    }
}

fn toml_integer(value: Option<&toml::Value>) -> Option<i64> {
    value.and_then(|entry| match entry {
        toml::Value::Integer(number) => Some(*number),
        toml::Value::String(raw) => raw.trim().parse::<i64>().ok(),
        _ => None,
    })
}

fn toml_float(value: Option<&toml::Value>) -> Option<f64> {
    value.and_then(|entry| match entry {
        toml::Value::Float(number) => Some(*number),
        toml::Value::Integer(number) => Some(*number as f64),
        toml::Value::String(raw) => raw.trim().parse::<f64>().ok(),
        _ => None,
    })
}

fn toml_bool(value: Option<&toml::Value>) -> Option<bool> {
    value.and_then(|entry| match entry {
        toml::Value::Boolean(flag) => Some(*flag),
        toml::Value::String(raw) => {
            let normalized = raw.trim().to_ascii_lowercase();
            match normalized.as_str() {
                "true" | "yes" | "on" | "1" => Some(true),
                "false" | "no" | "off" | "0" => Some(false),
                _ => None,
            }
        }
        _ => None,
    })
}

fn toml_string(value: Option<&toml::Value>) -> Option<String> {
    value.and_then(|entry| match entry {
        toml::Value::String(raw) => Some(raw.clone()),
        toml::Value::Integer(number) => Some(number.to_string()),
        toml::Value::Float(number) => Some(number.to_string()),
        toml::Value::Boolean(flag) => Some(flag.to_string()),
        _ => None,
    })
}

fn toml_string_array(value: Option<&toml::Value>) -> Vec<String> {
    value
        .and_then(|entry| entry.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| toml_string(Some(item)))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn protocol_profile_path(inventory_path: &Path, node_slot_id: &str) -> Option<PathBuf> {
    let base_dir = inventory_path.parent()?;
    let installer_path = base_dir
        .join("installers")
        .join(node_slot_id)
        .join("config/node.toml");
    if installer_path.is_file() {
        return Some(installer_path);
    }

    let config_path = base_dir
        .join("configs")
        .join(format!("{node_slot_id}.toml"));
    if config_path.is_file() {
        return Some(config_path);
    }

    None
}

fn load_protocol_profile(inventory_path: &Path, node_slot_id: &str) -> Value {
    let Some(config_path) = protocol_profile_path(inventory_path, node_slot_id) else {
        return json!({
            "loaded": false,
            "node_slot_id": node_slot_id,
            "reason": "node.toml not found",
        });
    };

    let Ok(content) = fs::read_to_string(&config_path) else {
        return json!({
            "loaded": false,
            "node_slot_id": node_slot_id,
            "source_path": config_path.to_string_lossy(),
            "reason": "node.toml could not be read",
        });
    };

    let Ok(parsed) = toml::from_str::<toml::Value>(&content) else {
        return json!({
            "loaded": false,
            "node_slot_id": node_slot_id,
            "source_path": config_path.to_string_lossy(),
            "reason": "node.toml could not be parsed",
        });
    };

    let consensus = parsed.get("consensus");
    let network = parsed.get("network");
    let blockchain = parsed.get("blockchain");
    let node_section = parsed.get("node");
    let snapshots = parsed.get("snapshots");
    let reward_weighting = consensus.and_then(|section| section.get("reward_weighting"));
    let bootnodes = toml_string_array(network.and_then(|section| section.get("bootnodes")));

    json!({
        "loaded": true,
        "node_slot_id": node_slot_id,
        "source_path": config_path.to_string_lossy(),
        "algorithm": toml_string(consensus.and_then(|section| section.get("algorithm"))),
        "chain_name": toml_string(network.and_then(|section| section.get("name"))),
        "network_id": toml_integer(network.and_then(|section| section.get("id"))),
        "chain_id": toml_integer(blockchain.and_then(|section| section.get("chain_id"))),
        "block_time_secs": toml_integer(consensus.and_then(|section| section.get("block_time_secs")))
            .or_else(|| toml_integer(blockchain.and_then(|section| section.get("block_time")))),
        "epoch_length": toml_integer(consensus.and_then(|section| section.get("epoch_length"))),
        "validator_cluster_size": toml_integer(consensus.and_then(|section| section.get("validator_cluster_size"))),
        "max_validators": toml_integer(consensus.and_then(|section| section.get("max_validators"))),
        "synergy_score_decay_rate": toml_float(consensus.and_then(|section| section.get("synergy_score_decay_rate"))),
        "vrf_enabled": toml_bool(consensus.and_then(|section| section.get("vrf_enabled"))),
        "vrf_seed_epoch_interval": toml_integer(consensus.and_then(|section| section.get("vrf_seed_epoch_interval"))),
        "max_synergy_points_per_epoch": toml_integer(consensus.and_then(|section| section.get("max_synergy_points_per_epoch"))),
        "max_tasks_per_validator": toml_integer(consensus.and_then(|section| section.get("max_tasks_per_validator"))),
        "snapshot_interval_blocks": toml_integer(snapshots.and_then(|section| section.get("interval_blocks"))),
        "snapshotting_enabled": toml_bool(snapshots.and_then(|section| section.get("enabled"))),
        "validator_address": toml_string(node_section.and_then(|section| section.get("validator_address"))),
        "bootnode_count": bootnodes.len(),
        "bootnodes": bootnodes,
        "reward_weighting": reward_weighting
            .and_then(|section| serde_json::to_value(section).ok())
            .unwrap_or(Value::Null),
    })
}

fn parse_value_as_f64(value: Option<&Value>) -> Option<f64> {
    match value {
        Some(Value::Number(number)) => number.as_f64(),
        Some(Value::String(raw)) => raw.trim().parse::<f64>().ok(),
        _ => None,
    }
}

fn parse_value_as_u128(value: Option<&Value>) -> Option<u128> {
    match value {
        Some(Value::Number(number)) => number.as_u64().map(u128::from),
        Some(Value::String(raw)) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                None
            } else if let Some(hex) = trimmed
                .strip_prefix("0x")
                .or_else(|| trimmed.strip_prefix("0X"))
            {
                u128::from_str_radix(hex, 16).ok()
            } else {
                trimmed.parse::<u128>().ok()
            }
        }
        _ => None,
    }
}

fn nwei_to_snrg(value: u128) -> f64 {
    value as f64 / 1_000_000_000.0
}

fn format_u128(value: u128) -> String {
    value.to_string()
}

fn token_balance_nwei(value: Option<&Value>) -> Option<u128> {
    let payload = value?;
    parse_value_as_u128(Some(payload))
        .or_else(|| parse_value_as_u128(payload.get("balance")))
        .or_else(|| parse_value_as_u128(payload.get("amount")))
        .or_else(|| parse_value_as_u128(payload.get("token_balance")))
}

fn staking_entries(value: Option<&Value>) -> Vec<Value> {
    value
        .and_then(|entry| entry.as_array())
        .cloned()
        .unwrap_or_default()
}

fn is_unknown_method_value(value: Option<&Value>) -> bool {
    value
        .and_then(|entry| entry.as_str())
        .map(|entry| entry.eq_ignore_ascii_case("Unknown method"))
        .unwrap_or(false)
}

fn genesis_profile_path(inventory_path: &Path, node_slot_id: &str) -> Option<PathBuf> {
    let base_dir = inventory_path.parent()?;
    let shared_path = base_dir
        .join("configs")
        .join("genesis")
        .join("genesis.json");
    if shared_path.is_file() {
        return Some(shared_path);
    }

    let installer_path = base_dir
        .join("installers")
        .join(node_slot_id)
        .join("config/genesis.json");
    if installer_path.is_file() {
        return Some(installer_path);
    }

    None
}

fn load_economics_profile(
    inventory_path: &Path,
    node: &MonitorNode,
    rpc: &MonitorRpcDiagnostics,
) -> Value {
    let address = node
        .node_address
        .as_deref()
        .map(str::trim)
        .unwrap_or_default()
        .to_string();
    if address.is_empty() {
        return json!({
            "loaded": false,
            "node_slot_id": node.node_slot_id,
            "node_alias": node.node_alias,
            "reason": "node address not set",
        });
    }

    let genesis_path = genesis_profile_path(inventory_path, &node.node_slot_id);
    let (genesis, genesis_gap) = match genesis_path.as_ref() {
        Some(path) => match fs::read_to_string(path) {
            Ok(content) => match serde_json::from_str::<Value>(&content) {
                Ok(parsed) => {
                    let token_symbol = parsed
                        .get("token_symbol")
                        .and_then(|value| value.as_str())
                        .unwrap_or("SNRG");
                    let allocation = parsed
                        .get("genesis_allocations")
                        .and_then(|value| value.as_array())
                        .and_then(|entries| {
                            entries.iter().find(|entry| {
                                entry
                                    .get("address")
                                    .and_then(|value| value.as_str())
                                    .map(|candidate| candidate.eq_ignore_ascii_case(&address))
                                    .unwrap_or(false)
                            })
                        });

                    let value = if let Some(allocation) = allocation {
                        let balance_raw =
                            parse_value_as_u128(allocation.get("balance")).unwrap_or(0);
                        let stake_raw = parse_value_as_u128(allocation.get("stake")).unwrap_or(0);
                        let liquid_raw = balance_raw.saturating_sub(stake_raw);
                        json!({
                            "loaded": true,
                            "matched": true,
                            "source_path": path.to_string_lossy(),
                            "token_symbol": token_symbol,
                            "allocation_type": allocation.get("type").and_then(|value| value.as_str()),
                            "description": allocation.get("description").and_then(|value| value.as_str()),
                            "balance_raw": format_u128(balance_raw),
                            "stake_raw": format_u128(stake_raw),
                            "liquid_raw": format_u128(liquid_raw),
                            "balance_snrg": nwei_to_snrg(balance_raw),
                            "stake_snrg": nwei_to_snrg(stake_raw),
                            "liquid_snrg": nwei_to_snrg(liquid_raw),
                        })
                    } else {
                        json!({
                            "loaded": true,
                            "matched": false,
                            "source_path": path.to_string_lossy(),
                            "token_symbol": token_symbol,
                        })
                    };

                    let gap = if allocation.is_none() {
                        Some(
                            "Genesis allocation for this node address was not found in the current genesis file."
                                .to_string(),
                        )
                    } else {
                        None
                    };
                    (value, gap)
                }
                Err(_) => (
                    json!({
                        "loaded": false,
                        "source_path": path.to_string_lossy(),
                        "reason": "genesis.json could not be parsed",
                    }),
                    Some("Genesis allocation file could not be parsed.".to_string()),
                ),
            },
            Err(_) => (
                json!({
                    "loaded": false,
                    "source_path": path.to_string_lossy(),
                    "reason": "genesis.json could not be read",
                }),
                Some(
                    "Genesis allocation file could not be read from the current workspace."
                        .to_string(),
                ),
            ),
        },
        None => (
            json!({
                "loaded": false,
                "reason": "genesis.json not found",
            }),
            Some("Genesis allocation file is not present in the current workspace.".to_string()),
        ),
    };

    let staking_entries = staking_entries(rpc.staking_info.as_ref());
    let total_earned_raw: u128 = staking_entries
        .iter()
        .filter_map(|entry| parse_value_as_u128(entry.get("rewards_earned")))
        .sum();
    let pending_rewards_raw: u128 = staking_entries
        .iter()
        .filter_map(|entry| parse_value_as_u128(entry.get("pending_rewards")))
        .sum();
    let staking_amount_from_entries: u128 = staking_entries
        .iter()
        .filter_map(|entry| parse_value_as_u128(entry.get("amount")))
        .sum();
    let staked_balance_raw =
        token_balance_nwei(rpc.staked_balance.as_ref()).unwrap_or(staking_amount_from_entries);
    let wallet_balance_raw = token_balance_nwei(rpc.token_balance.as_ref()).unwrap_or(0);

    let now = current_unix_seconds();
    let seconds_per_year = 365.0 * 24.0 * 3600.0;
    let mut weighted_apy_sum = 0.0;
    let mut total_weight = 0.0;
    for entry in &staking_entries {
        let amount = parse_value_as_u128(entry.get("amount")).unwrap_or(0);
        let rewards = parse_value_as_u128(entry.get("rewards_earned")).unwrap_or(0);
        let stake_start = parse_value_as_u64(entry.get("stake_start")).unwrap_or(0);
        if amount == 0 || rewards == 0 || stake_start == 0 || now <= stake_start {
            continue;
        }

        let elapsed = (now - stake_start) as f64;
        if elapsed <= 0.0 {
            continue;
        }

        let rate = rewards as f64 / amount as f64;
        let annualized = (rate / (elapsed / seconds_per_year)) * 100.0;
        weighted_apy_sum += annualized * amount as f64;
        total_weight += amount as f64;
    }

    let estimated_apy = if total_weight > 0.0 {
        let candidate = weighted_apy_sum / total_weight;
        if candidate.is_finite() {
            Some(candidate.min(1500.0))
        } else {
            None
        }
    } else {
        None
    };

    let commission_rate = staking_entries
        .iter()
        .find_map(|entry| parse_value_as_f64(entry.get("commission_rate")));
    let reward_history = staking_entries
        .iter()
        .filter_map(|entry| {
            let timestamp = parse_value_as_u64(entry.get("stake_start"))
                .or_else(|| parse_value_as_u64(entry.get("last_updated")))
                .unwrap_or(now);
            let amount_raw = parse_value_as_u128(entry.get("rewards_earned")).unwrap_or(0);
            let block_number = parse_value_as_u64(entry.get("last_block")).unwrap_or(0);
            let reward_type = entry
                .get("reward_type")
                .and_then(|value| value.as_str())
                .unwrap_or("validator");
            if amount_raw == 0 && block_number == 0 {
                return None;
            }
            Some(json!({
                "timestamp": timestamp,
                "amount_raw": format_u128(amount_raw),
                "amount_snrg": nwei_to_snrg(amount_raw),
                "block_number": block_number,
                "reward_type": reward_type,
            }))
        })
        .collect::<Vec<_>>();

    let synergy_breakdown = rpc
        .synergy_score_breakdown
        .as_ref()
        .cloned()
        .unwrap_or(Value::Null);
    let synergy_multiplier = parse_value_as_f64(
        rpc.synergy_score_breakdown
            .as_ref()
            .and_then(|value| value.get("multiplier")),
    );
    let synergy_components = rpc
        .synergy_score_breakdown
        .as_ref()
        .and_then(|value| value.get("components"))
        .cloned()
        .unwrap_or(Value::Null);

    let genesis_total_snrg = parse_value_as_f64(genesis.get("balance_snrg"));
    let live_total_position_snrg = Some(nwei_to_snrg(wallet_balance_raw + staked_balance_raw));
    let net_position_delta_snrg = match (live_total_position_snrg, genesis_total_snrg) {
        (Some(live_total), Some(genesis_total)) => Some(live_total - genesis_total),
        _ => None,
    };

    let token_balance_available =
        rpc.token_balance.is_some() && !is_unknown_method_value(rpc.token_balance.as_ref());
    let staking_info_available =
        rpc.staking_info.is_some() && !is_unknown_method_value(rpc.staking_info.as_ref());
    let staked_balance_available =
        rpc.staked_balance.is_some() && !is_unknown_method_value(rpc.staked_balance.as_ref());
    let synergy_breakdown_available = rpc.synergy_score_breakdown.is_some()
        && !is_unknown_method_value(rpc.synergy_score_breakdown.as_ref());

    let mut telemetry_gaps = Vec::new();
    if !token_balance_available {
        telemetry_gaps
            .push("Live wallet balance is not exposed by the current RPC surface.".to_string());
    }
    if !staking_info_available {
        telemetry_gaps.push("Historical rewards and staking-entry detail are not exposed by the current RPC surface.".to_string());
    }
    if !staked_balance_available {
        telemetry_gaps.push("Live staked balance is falling back to staking-entry totals because the dedicated RPC is not exposed.".to_string());
    }
    if !synergy_breakdown_available {
        telemetry_gaps.push(
            "Synergy multiplier and score components are not exposed by the current RPC surface."
                .to_string(),
        );
    }
    if let Some(gap) = genesis_gap {
        telemetry_gaps.push(gap);
    }

    json!({
        "loaded": true,
        "node_slot_id": node.node_slot_id,
        "node_alias": node.node_alias,
        "node_address": address,
        "token_symbol": genesis
            .get("token_symbol")
            .and_then(|value| value.as_str())
            .unwrap_or("SNRG"),
        "decimals": 9,
        "genesis": genesis,
        "live": {
            "wallet_balance_raw": format_u128(wallet_balance_raw),
            "wallet_balance_snrg": nwei_to_snrg(wallet_balance_raw),
            "staked_balance_raw": format_u128(staked_balance_raw),
            "staked_balance_snrg": nwei_to_snrg(staked_balance_raw),
            "current_total_position_snrg": live_total_position_snrg,
            "historical_earned_raw": format_u128(total_earned_raw),
            "historical_earned_snrg": nwei_to_snrg(total_earned_raw),
            "pending_rewards_raw": format_u128(pending_rewards_raw),
            "pending_rewards_snrg": nwei_to_snrg(pending_rewards_raw),
            "estimated_apy": estimated_apy,
            "commission_rate": commission_rate,
            "staking_entry_count": staking_entries.len(),
            "reward_history": reward_history,
            "net_position_delta_snrg": net_position_delta_snrg,
            "synergy_multiplier": synergy_multiplier,
            "synergy_breakdown": synergy_breakdown,
            "synergy_components": synergy_components,
        },
        "telemetry": {
            "token_balance_available": token_balance_available,
            "staking_info_available": staking_info_available,
            "staked_balance_available": staked_balance_available,
            "synergy_breakdown_available": synergy_breakdown_available,
            "telemetry_gaps": telemetry_gaps,
        },
    })
}

fn has_explicit_port(host: &str) -> bool {
    let without_scheme = host.split("://").nth(1).unwrap_or(host);
    let authority = without_scheme
        .split('/')
        .next()
        .unwrap_or(without_scheme)
        .trim();

    if authority.starts_with('[') {
        authority.contains("]:")
    } else if let Some((_, port)) = authority.rsplit_once(':') {
        !port.is_empty() && port.chars().all(|c| c.is_ascii_digit())
    } else {
        false
    }
}

async fn probe_node(node: MonitorNode) -> MonitorNodeStatus {
    let client = Client::builder()
        .timeout(Duration::from_millis(750))
        .connect_timeout(Duration::from_millis(750))
        .build()
        .unwrap_or_else(|_| Client::new());

    let started = Instant::now();
    let rpc_url = node.rpc_url.clone();

    let (
        node_info_result,
        node_status_result,
        latest_block_result,
        block_result_primary,
        block_result_alt,
        peer_result,
        sync_result,
    ) = tokio::join!(
        rpc_call(&client, &rpc_url, "synergy_nodeInfo", json!([])),
        rpc_call(&client, &rpc_url, "synergy_getNodeStatus", json!([])),
        rpc_call(&client, &rpc_url, "synergy_getLatestBlock", json!([])),
        rpc_call(&client, &rpc_url, "synergy_getBlockNumber", json!([])),
        rpc_call(&client, &rpc_url, "synergy_blockNumber", json!([])),
        rpc_call(&client, &rpc_url, "synergy_getPeerInfo", json!([])),
        rpc_call(&client, &rpc_url, "synergy_getSyncStatus", json!([])),
    );

    let node_info = node_info_result.as_ref().ok();
    let block_height = block_result_primary
        .as_ref()
        .ok()
        .and_then(parse_block_height)
        .or_else(|| block_result_alt.as_ref().ok().and_then(parse_block_height))
        .or_else(|| node_info.and_then(parse_block_height));

    let peer_count = extract_peer_count(node_info).or_else(|| {
        peer_result
            .as_ref()
            .ok()
            .and_then(|value| extract_peer_count(Some(value)))
    });

    let syncing = extract_syncing(node_info).or_else(|| {
        sync_result
            .as_ref()
            .ok()
            .and_then(|value| extract_syncing(Some(value)))
            .or_else(|| sync_result.as_ref().ok().and_then(|value| value.as_bool()))
    });
    let average_block_time_secs = node_status_result
        .as_ref()
        .ok()
        .and_then(|value| extract_average_block_time(Some(value)))
        .or_else(|| node_info.and_then(|value| extract_average_block_time(Some(value))));
    let latest_block_tx_count = latest_block_result
        .as_ref()
        .ok()
        .and_then(|value| extract_transaction_count(Some(value)));
    let throughput_tps = match (average_block_time_secs, latest_block_tx_count) {
        (Some(block_time), Some(tx_count)) if block_time.is_finite() && block_time > 0.0 => {
            Some(tx_count as f64 / block_time)
        }
        _ => None,
    };

    let mut errors = Vec::new();
    if let Err(err) = &node_info_result {
        errors.push(format!("nodeInfo: {err}"));
    }
    if let Err(err) = &node_status_result {
        errors.push(format!("getNodeStatus: {err}"));
    }
    if let Err(err) = &latest_block_result {
        errors.push(format!("getLatestBlock: {err}"));
    }
    if let Err(err) = &block_result_primary {
        errors.push(format!("getBlockNumber: {err}"));
    }
    if let Err(err) = &peer_result {
        errors.push(format!("getPeerInfo: {err}"));
    }
    if let Err(err) = &sync_result {
        errors.push(format!("getSyncStatus: {err}"));
    }

    // Determine online by checking whether the node exposes any substantive RPC data
    // (node info, block height, or peer count).  `sync_result.is_ok()` is intentionally
    // excluded: the indexer node (node-14) keeps its HTTP server alive after the process
    // is stopped, so a successful sync-status response alone is not a reliable liveness
    // signal — it would cause the node to appear "syncing" even when stopped.
    let online = node_info.is_some()
        || block_height.is_some()
        || peer_count.is_some()
        || block_result_alt.is_ok();

    let status = if !online {
        "offline".to_string()
    } else if syncing == Some(true) {
        "syncing".to_string()
    } else {
        "online".to_string()
    };

    MonitorNodeStatus {
        node,
        status,
        online,
        active_physical_machine_id: None,
        active_management_host: None,
        block_height,
        average_block_time_secs,
        throughput_tps,
        peer_count,
        syncing,
        response_ms: started.elapsed().as_millis() as u64,
        error: if online || errors.is_empty() {
            None
        } else {
            Some(errors.join(" | "))
        },
        last_checked_utc: Utc::now().to_rfc3339(),
    }
}

async fn rpc_call(
    client: &Client,
    rpc_url: &str,
    method: &str,
    params: Value,
) -> Result<Value, String> {
    let payload = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params
    });

    match rpc_call_once(client, rpc_url, &payload).await {
        Ok(value) => Ok(value),
        Err(primary_error) => {
            if let Some(loopback_url) = maybe_local_loopback_rpc_url(rpc_url) {
                if loopback_url != rpc_url {
                    return rpc_call_once(client, &loopback_url, &payload)
                        .await
                        .map_err(|fallback_error| {
                            format!("{primary_error} | fallback {loopback_url}: {fallback_error}")
                        });
                }
            }
            Err(primary_error)
        }
    }
}

async fn rpc_call_once(client: &Client, rpc_url: &str, payload: &Value) -> Result<Value, String> {
    let response = client
        .post(rpc_url)
        .json(payload)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status().as_u16()));
    }

    let json_response = response.json::<Value>().await.map_err(|e| e.to_string())?;
    if let Some(err) = json_response.get("error") {
        return Err(err.to_string());
    }

    json_response
        .get("result")
        .cloned()
        .ok_or_else(|| "Missing result field".to_string())
}

fn maybe_local_loopback_rpc_url(rpc_url: &str) -> Option<String> {
    let local_management_host = detect_local_management_host()?;
    let mut parsed = Url::parse(rpc_url).ok()?;
    let host = parsed.host_str()?;
    if host != local_management_host {
        return None;
    }
    parsed.set_host(Some("127.0.0.1")).ok()?;
    Some(parsed.to_string())
}

fn parse_block_height(value: &Value) -> Option<u64> {
    match value {
        Value::Number(number) => number.as_u64(),
        Value::String(raw) => parse_u64(raw),
        Value::Object(map) => {
            let keys = [
                "block_height",
                "height",
                "latest_block",
                "current_block_height",
                "current_height",
                "blockNumber",
            ];
            keys.iter()
                .find_map(|key| map.get(*key))
                .and_then(parse_block_height)
        }
        _ => None,
    }
}

fn extract_peer_count(value: Option<&Value>) -> Option<u64> {
    let value = value?;
    match value {
        Value::Array(items) => Some(items.len() as u64),
        Value::Number(number) => number.as_u64(),
        Value::String(raw) => parse_u64(raw),
        Value::Object(map) => {
            let keys = [
                "peer_count",
                "peers",
                "total_peers",
                "count",
                "network_peers",
            ];
            keys.iter()
                .find_map(|key| map.get(*key))
                .and_then(|candidate| {
                    if let Some(array) = candidate.as_array() {
                        Some(array.len() as u64)
                    } else {
                        extract_peer_count(Some(candidate))
                    }
                })
        }
        _ => None,
    }
}

fn extract_syncing(value: Option<&Value>) -> Option<bool> {
    let value = value?;
    match value {
        Value::Bool(flag) => Some(*flag),
        Value::String(raw) => {
            let normalized = raw.trim().to_lowercase();
            match normalized.as_str() {
                "true" | "syncing" => Some(true),
                "false" | "synced" | "idle" => Some(false),
                _ => None,
            }
        }
        Value::Object(map) => {
            let keys = [
                "syncing",
                "is_syncing",
                "synced",
                "is_synced",
                "sync_status",
            ];
            for key in keys {
                if let Some(candidate) = map.get(key) {
                    if key == "synced" || key == "is_synced" {
                        if let Some(flag) = extract_syncing(Some(candidate)) {
                            return Some(!flag);
                        }
                    } else if let Some(flag) = extract_syncing(Some(candidate)) {
                        return Some(flag);
                    }
                }
            }
            None
        }
        _ => None,
    }
}

fn extract_average_block_time(value: Option<&Value>) -> Option<f64> {
    let value = value?;
    match value {
        Value::Number(number) => number.as_f64(),
        Value::String(raw) => raw.trim().parse::<f64>().ok(),
        Value::Object(map) => {
            let keys = [
                "average_block_time",
                "avg_block_time",
                "block_time",
                "block_time_secs",
            ];
            keys.iter()
                .find_map(|key| map.get(*key))
                .and_then(|candidate| extract_average_block_time(Some(candidate)))
        }
        _ => None,
    }
    .filter(|value| value.is_finite() && *value > 0.0)
}

fn extract_transaction_count(value: Option<&Value>) -> Option<u64> {
    let value = value?;
    match value {
        Value::Array(items) => Some(items.len() as u64),
        Value::Number(number) => number.as_u64(),
        Value::String(raw) => parse_u64(raw),
        Value::Object(map) => {
            let collection_keys = ["transactions", "txs", "items", "results"];
            for key in collection_keys {
                if let Some(candidate) = map.get(key) {
                    if let Some(count) = extract_transaction_count(Some(candidate)) {
                        return Some(count);
                    }
                }
            }

            let count_keys = [
                "transaction_count",
                "tx_count",
                "count",
                "total_transactions",
            ];
            count_keys
                .iter()
                .find_map(|key| map.get(*key))
                .and_then(|candidate| extract_transaction_count(Some(candidate)))
        }
        _ => None,
    }
}

fn average_values(values: impl IntoIterator<Item = f64>) -> Option<f64> {
    let mut total = 0.0;
    let mut count = 0usize;
    for value in values.into_iter().filter(|value| value.is_finite()) {
        total += value;
        count += 1;
    }
    if count == 0 {
        None
    } else {
        Some(total / count as f64)
    }
}

fn preferred_network_average(
    statuses: &[MonitorNodeStatus],
    highest_block: Option<u64>,
    selector: impl Fn(&MonitorNodeStatus) -> Option<f64>,
) -> Option<f64> {
    if let Some(network_head) = highest_block {
        if let Some(value) = average_values(statuses.iter().filter_map(|status| {
            (status.online && status.block_height == Some(network_head))
                .then(|| selector(status))
                .flatten()
        })) {
            return Some(value);
        }
    }

    average_values(
        statuses
            .iter()
            .filter_map(|status| status.online.then(|| selector(status)).flatten()),
    )
}

fn parse_u64(raw: &str) -> Option<u64> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16).ok();
    }

    trimmed.parse::<u64>().ok()
}

fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn parse_value_as_u64(value: Option<&Value>) -> Option<u64> {
    match value {
        Some(Value::Number(number)) => number.as_u64(),
        Some(Value::String(raw)) => parse_u64(raw),
        _ => None,
    }
}

fn parse_value_as_bool(value: Option<&Value>) -> Option<bool> {
    match value {
        Some(Value::Bool(flag)) => Some(*flag),
        Some(Value::String(raw)) => {
            let normalized = raw.trim().to_ascii_lowercase();
            match normalized.as_str() {
                "true" | "yes" | "on" | "1" => Some(true),
                "false" | "no" | "off" | "0" => Some(false),
                _ => None,
            }
        }
        _ => None,
    }
}

fn add_execution_check(
    checks: &mut Vec<MonitorExecutionCheck>,
    key: &str,
    label: &str,
    status: &str,
    detail: impl Into<String>,
) {
    checks.push(MonitorExecutionCheck {
        key: key.to_string(),
        label: label.to_string(),
        status: status.to_string(),
        detail: detail.into(),
    });
}

fn summarize_execution(checks: &[MonitorExecutionCheck]) -> MonitorRoleExecution {
    let fail_count = checks.iter().filter(|check| check.status == "fail").count();
    let warn_count = checks.iter().filter(|check| check.status == "warn").count();
    let pass_count = checks.iter().filter(|check| check.status == "pass").count();

    let overall_status = if fail_count > 0 {
        "critical"
    } else if warn_count > 0 {
        "degraded"
    } else if pass_count > 0 {
        "healthy"
    } else {
        "unknown"
    };

    let summary = format!(
        "{} checks passed, {} warning(s), {} failure(s).",
        pass_count, warn_count, fail_count
    );

    MonitorRoleExecution {
        overall_status: overall_status.to_string(),
        summary,
        checks: checks.to_vec(),
    }
}

fn find_local_relayer_entry<'a>(
    rpc: &'a MonitorRpcDiagnostics,
    address: &str,
) -> Option<&'a Value> {
    if address.is_empty() {
        return None;
    }

    rpc.relayer_set
        .as_ref()
        .and_then(|value| value.get("relayers"))
        .and_then(|value| value.as_array())
        .and_then(|items| {
            items.iter().find(|candidate| {
                candidate
                    .get("address")
                    .and_then(|value| value.as_str())
                    .map(|candidate_address| candidate_address.eq_ignore_ascii_case(address))
                    .unwrap_or(false)
            })
        })
}

fn normalize_identifier(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase()
}

fn identifier_matches(candidate: &str, expected: &str) -> bool {
    if candidate.eq_ignore_ascii_case(expected) {
        return true;
    }

    let normalized_candidate = normalize_identifier(candidate);
    let normalized_expected = normalize_identifier(expected);
    !normalized_candidate.is_empty() && normalized_candidate == normalized_expected
}

fn push_alias(aliases: &mut Vec<String>, candidate: Option<&str>) {
    let Some(candidate) = candidate.map(str::trim).filter(|value| !value.is_empty()) else {
        return;
    };

    if aliases
        .iter()
        .any(|existing| identifier_matches(existing, candidate))
    {
        return;
    }

    aliases.push(candidate.to_string());
}

fn collect_validator_aliases(
    status: &MonitorNodeStatus,
    rpc: &MonitorRpcDiagnostics,
) -> Vec<String> {
    let mut aliases = Vec::new();
    push_alias(
        &mut aliases,
        rpc.node_info
            .as_ref()
            .and_then(|value| value.get("name"))
            .and_then(|value| value.as_str()),
    );
    push_alias(&mut aliases, Some(status.node.node_alias.as_str()));
    push_alias(&mut aliases, Some(status.node.node_slot_id.as_str()));
    aliases
}

fn find_local_validator_entry<'a>(
    status: &MonitorNodeStatus,
    rpc: &'a MonitorRpcDiagnostics,
) -> Option<&'a Value> {
    let address = status.node.node_address.clone().unwrap_or_default();
    let aliases = collect_validator_aliases(status, rpc);

    rpc.validator_activity
        .as_ref()
        .and_then(|value| value.get("validators"))
        .and_then(|value| value.as_array())
        .and_then(|validators| {
            validators.iter().find(|validator| {
                let address_match = validator
                    .get("address")
                    .and_then(|value| value.as_str())
                    .map(|candidate| !address.is_empty() && identifier_matches(candidate, &address))
                    .unwrap_or(false);
                let name_match = validator
                    .get("name")
                    .and_then(|value| value.as_str())
                    .map(|candidate| {
                        aliases
                            .iter()
                            .any(|alias| identifier_matches(candidate, alias))
                    })
                    .unwrap_or(false);
                address_match || name_match
            })
        })
}

fn extract_latest_block_signature_algorithms(rpc: &MonitorRpcDiagnostics) -> Vec<String> {
    let mut algorithms = Vec::new();
    let Some(block) = rpc.latest_block.as_ref() else {
        return algorithms;
    };

    let transactions = block
        .get("transactions")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();

    for tx in transactions {
        if let Some(algo) = tx
            .get("signature_algorithm")
            .and_then(|value| value.as_str())
            .map(|value| value.to_ascii_lowercase())
        {
            if !algorithms.iter().any(|existing| existing == &algo) {
                algorithms.push(algo);
            }
        }
    }

    algorithms
}

fn build_role_execution(
    status: &MonitorNodeStatus,
    rpc: &MonitorRpcDiagnostics,
) -> MonitorRoleExecution {
    let mut checks = Vec::new();
    let role_group = status.node.role_group.to_ascii_lowercase();
    let role = status.node.role.to_ascii_lowercase();
    let node_type = status.node.node_type.to_ascii_lowercase();
    let address = status.node.node_address.clone().unwrap_or_default();
    let now_ts = current_unix_seconds();

    if status.online {
        add_execution_check(
            &mut checks,
            "rpc_reachability",
            "RPC Reachability",
            "pass",
            format!("Node responded in {} ms.", status.response_ms),
        );
    } else {
        add_execution_check(
            &mut checks,
            "rpc_reachability",
            "RPC Reachability",
            "fail",
            "Node did not respond to monitor RPC probes.",
        );
        return summarize_execution(&checks);
    }

    if role_group == "interop"
        || role.contains("relayer")
        || role.contains("witness")
        || role.contains("oracle")
        || node_type.contains("relayer")
        || node_type.contains("cross-chain")
    {
        let relayer_entry = find_local_relayer_entry(rpc, &address);
        let relayer_registered = relayer_entry.is_some();
        let strict_relayer_registration = role.contains("relayer") || node_type.contains("relayer");

        if relayer_registered {
            add_execution_check(
                &mut checks,
                "sxcp_registration",
                "SXCP Relayer Registration",
                "pass",
                "Node address is present in the active relayer set.",
            );
        } else if strict_relayer_registration {
            add_execution_check(
                &mut checks,
                "sxcp_registration",
                "SXCP Relayer Registration",
                "fail",
                "Relayer-role node is not registered in synergy_getRelayerSet.",
            );
        } else {
            add_execution_check(
                &mut checks,
                "sxcp_registration",
                "SXCP Relayer Registration",
                "warn",
                "Node is not in relayer set. This may be acceptable if this interop role does not self-register.",
            );
        }

        if let Some(entry) = relayer_entry {
            let active = parse_value_as_bool(entry.get("active")).unwrap_or(false);
            let slashed = parse_value_as_bool(entry.get("slashed")).unwrap_or(false);
            let last_heartbeat = parse_value_as_u64(entry.get("last_heartbeat")).unwrap_or(0);
            let heartbeat_age = now_ts.saturating_sub(last_heartbeat);
            let attestation_count = parse_value_as_u64(entry.get("attestation_count")).unwrap_or(0);

            add_execution_check(
                &mut checks,
                "sxcp_active_flag",
                "Relayer Active Flag",
                if active { "pass" } else { "fail" },
                if active {
                    "Relayer active flag is true.".to_string()
                } else {
                    "Relayer active flag is false.".to_string()
                },
            );

            add_execution_check(
                &mut checks,
                "sxcp_slashed_flag",
                "Relayer Slashing Status",
                if slashed { "fail" } else { "pass" },
                if slashed {
                    "Relayer is marked slashed in SXCP state.".to_string()
                } else {
                    "Relayer is not slashed.".to_string()
                },
            );

            let heartbeat_status = if heartbeat_age <= 120 {
                "pass"
            } else if heartbeat_age <= 300 {
                "warn"
            } else {
                "fail"
            };
            add_execution_check(
                &mut checks,
                "sxcp_heartbeat_freshness",
                "Relayer Heartbeat Freshness",
                heartbeat_status,
                format!("Last heartbeat seen {} seconds ago.", heartbeat_age),
            );

            add_execution_check(
                &mut checks,
                "sxcp_attestation_count",
                "Relayer Attestation Production",
                if attestation_count > 0 {
                    "pass"
                } else {
                    "warn"
                },
                if attestation_count > 0 {
                    format!("Relayer has produced {} attestations.", attestation_count)
                } else {
                    "No attestations produced by this relayer yet.".to_string()
                },
            );
        }

        let network_attestations = extract_attestation_count(rpc.attestations.as_ref());
        add_execution_check(
            &mut checks,
            "sxcp_network_attestations",
            "SXCP Network Attestation Flow",
            if network_attestations > 0 {
                "pass"
            } else {
                "warn"
            },
            format!(
                "Monitor observed {} total attestation(s).",
                network_attestations
            ),
        );

        add_execution_check(
            &mut checks,
            "p2p_connectivity",
            "P2P Connectivity",
            if status.peer_count.unwrap_or(0) > 0 {
                "pass"
            } else {
                "warn"
            },
            format!(
                "Peer count currently reported as {}.",
                status.peer_count.unwrap_or(0)
            ),
        );

        return summarize_execution(&checks);
    }

    if role_group == "consensus"
        || role_group == "governance"
        || role.contains("validator")
        || node_type == "validator"
    {
        let local_validator = find_local_validator_entry(status, rpc);
        let strict_validator_presence = role_group == "consensus" || role.contains("validator");
        let sync_complete = matches!(status.syncing, Some(false));

        if local_validator.is_some() {
            add_execution_check(
                &mut checks,
                "validator_registry_presence",
                "Validator Registry Presence",
                "pass",
                "Node address appears in active validator activity.",
            );
        } else if strict_validator_presence && sync_complete {
            add_execution_check(
                &mut checks,
                "validator_registry_presence",
                "Validator Registry Presence",
                "fail",
                "Consensus/validator node is missing from active validator set.",
            );
        } else if strict_validator_presence {
            add_execution_check(
                &mut checks,
                "validator_registry_presence",
                "Validator Registry Presence",
                "warn",
                "Node is still syncing; validator-set membership may not appear until sync completes.",
            );
        } else {
            add_execution_check(
                &mut checks,
                "validator_registry_presence",
                "Validator Registry Presence",
                "warn",
                "Node is not present in validator activity; governance roles may still be operational.",
            );
        }

        if let Some(validator) = local_validator {
            let stake_amount = parse_value_as_u64(validator.get("stake_amount")).unwrap_or(0);
            let blocks_produced = parse_value_as_u64(validator.get("blocks_produced")).unwrap_or(0);
            add_execution_check(
                &mut checks,
                "validator_stake",
                "Validator Stake",
                if stake_amount > 0 { "pass" } else { "fail" },
                format!("Stake amount reported: {} nWei.", stake_amount),
            );
            add_execution_check(
                &mut checks,
                "validator_block_production",
                "Validator Block Production",
                if blocks_produced > 0 { "pass" } else { "warn" },
                format!("Blocks produced reported: {}.", blocks_produced),
            );
        }

        add_execution_check(
            &mut checks,
            "consensus_sync_state",
            "Consensus Sync State",
            if status.syncing == Some(false) {
                "pass"
            } else {
                "warn"
            },
            format!("Syncing flag: {}.", status.syncing.unwrap_or(true)),
        );
        add_execution_check(
            &mut checks,
            "consensus_peer_connectivity",
            "Consensus Peer Connectivity",
            if status.peer_count.unwrap_or(0) > 0 {
                "pass"
            } else {
                "warn"
            },
            format!(
                "Peer count currently reported as {}.",
                status.peer_count.unwrap_or(0)
            ),
        );

        return summarize_execution(&checks);
    }

    if role_group == "pqc" || role.contains("pqc") || node_type.contains("pqc") {
        let has_pqc_prefix = address.to_ascii_lowercase().starts_with("synv2");
        add_execution_check(
            &mut checks,
            "pqc_address_class",
            "PQC Address Class",
            if has_pqc_prefix { "pass" } else { "warn" },
            if has_pqc_prefix {
                "Address prefix indicates Class-II/PQC identity (synv2...).".to_string()
            } else {
                "Address prefix is not synv2; verify that this node is using the intended PQC class address.".to_string()
            },
        );

        let signature_algorithms = extract_latest_block_signature_algorithms(rpc);
        let has_pqc_signatures = signature_algorithms.iter().any(|algo| {
            algo.contains("fndsa") || algo.contains("mldsa") || algo.contains("slhdsa")
        });
        add_execution_check(
            &mut checks,
            "pqc_signature_surface",
            "Observed PQC Signature Surface",
            if has_pqc_signatures { "pass" } else { "warn" },
            if signature_algorithms.is_empty() {
                "No signature algorithm metadata was observed in latest block payload.".to_string()
            } else {
                format!(
                    "Observed signature algorithms: {}.",
                    signature_algorithms.join(", ")
                )
            },
        );

        add_execution_check(
            &mut checks,
            "pqc_sync_and_peers",
            "PQC Runtime Connectivity",
            if status.peer_count.unwrap_or(0) > 0 && status.syncing == Some(false) {
                "pass"
            } else {
                "warn"
            },
            format!(
                "Peer count={}, syncing={}.",
                status.peer_count.unwrap_or(0),
                status.syncing.unwrap_or(true)
            ),
        );

        add_execution_check(
            &mut checks,
            "pqc_telemetry_gap",
            "PQC Node-Specific Telemetry",
            "warn",
            "Current RPC surface does not expose dedicated PQC verification counters yet; this check is inferred from observable runtime state.",
        );

        return summarize_execution(&checks);
    }

    let service_role = role_group == "services"
        || node_type.contains("rpc")
        || node_type.contains("indexer")
        || node_type.contains("observer");

    if service_role {
        let latency = status.response_ms;
        let latency_status = if latency <= 750 {
            "pass"
        } else if latency <= 1500 {
            "warn"
        } else {
            "fail"
        };
        add_execution_check(
            &mut checks,
            "service_rpc_latency",
            "Service RPC Latency",
            latency_status,
            format!("Measured RPC response latency is {} ms.", latency),
        );

        add_execution_check(
            &mut checks,
            "service_sync_state",
            "Service Sync State",
            if status.syncing == Some(false) {
                "pass"
            } else {
                "warn"
            },
            format!("Syncing flag: {}.", status.syncing.unwrap_or(true)),
        );

        add_execution_check(
            &mut checks,
            "service_peer_connectivity",
            "Service Peer Connectivity",
            if status.peer_count.unwrap_or(0) > 0 {
                "pass"
            } else {
                "warn"
            },
            format!(
                "Peer count currently reported as {}.",
                status.peer_count.unwrap_or(0)
            ),
        );

        if node_type.contains("indexer") {
            add_execution_check(
                &mut checks,
                "service_indexer_block_visibility",
                "Indexer Block Visibility",
                if status.block_height.unwrap_or(0) > 0 {
                    "pass"
                } else {
                    "warn"
                },
                format!(
                    "Indexer-reported block height is {}.",
                    status.block_height.unwrap_or(0)
                ),
            );
        }

        return summarize_execution(&checks);
    }

    add_execution_check(
        &mut checks,
        "generic_runtime",
        "Generic Runtime Health",
        "pass",
        format!(
            "Node is online with block height {:?}, peers {:?}, syncing {:?}.",
            status.block_height, status.peer_count, status.syncing
        ),
    );
    summarize_execution(&checks)
}

fn build_role_diagnostics(
    status: &MonitorNodeStatus,
    rpc: &MonitorRpcDiagnostics,
) -> (Value, Vec<String>) {
    let group = status.node.role_group.to_ascii_lowercase();
    let role = status.node.role.to_ascii_lowercase();
    let node_type = status.node.node_type.to_ascii_lowercase();
    let address = status.node.node_address.clone().unwrap_or_default();

    if group == "interop"
        || role.contains("relayer")
        || role.contains("witness")
        || role.contains("oracle")
        || node_type.contains("relayer")
        || node_type.contains("cross-chain")
        || node_type.contains("witness")
        || node_type.contains("oracle")
    {
        let relayer_entries = extract_relayer_entries(rpc.relayer_set.as_ref());
        let relayer_count = relayer_entries.len();
        let local_registered = if address.is_empty() {
            None
        } else {
            Some(relayer_entries.iter().any(|entry| {
                entry
                    .get("address")
                    .and_then(|value| value.as_str())
                    .map(|candidate| candidate.eq_ignore_ascii_case(&address))
                    .unwrap_or(false)
            }))
        };

        let attestation_count = extract_attestation_count(rpc.attestations.as_ref());
        let diagnostic = json!({
            "domain": "SXCP Interop",
            "local_address": if address.is_empty() { Value::Null } else { Value::String(address.clone()) },
            "relayer_set_size": relayer_count,
            "local_relayer_registered": local_registered,
            "recent_attestations": attestation_count,
            "rpc_endpoint": status.node.rpc_url,
            "target_role": status.node.role,
        });

        let notes = vec![
            "Interop nodes are expected to maintain relayer liveness and produce attestations for cross-chain proofs.".to_string(),
            "If relayer registration is false, run SXCP relayer registration before expecting traffic.".to_string(),
        ];

        return (diagnostic, notes);
    }

    if group == "consensus"
        || group == "governance"
        || role.contains("validator")
        || node_type == "validator"
    {
        let validators = rpc
            .validator_activity
            .as_ref()
            .and_then(|value| value.get("validators"))
            .and_then(|value| value.as_array())
            .cloned()
            .unwrap_or_default();

        let local_validator = find_local_validator_entry(status, rpc);

        let diagnostic = json!({
            "domain": "Consensus/Governance",
            "local_address": if address.is_empty() { Value::Null } else { Value::String(address.clone()) },
            "active_validator_count": validators.len(),
            "local_validator": local_validator.cloned(),
            "latest_block": status.block_height,
            "peer_count": status.peer_count,
            "syncing": status.syncing,
        });

        let notes = vec![
            "Consensus/governance nodes should maintain steady peer count and progress in block production.".to_string(),
            "If the local validator is null, verify the canonical validator list and validator peer mesh first; auto-registration is only relevant for newly onboarded validators.".to_string(),
        ];

        return (diagnostic, notes);
    }

    if node_type.contains("pqc") || role.contains("pqc") || group == "pqc" {
        let diagnostic = json!({
            "domain": "PQC Services",
            "cryptography_profile": "FN-DSA-1024 + ML-KEM-1024 (network standard)",
            "node_address": if address.is_empty() { Value::Null } else { Value::String(address.clone()) },
            "syncing": status.syncing,
            "latest_block": status.block_height,
            "peer_count": status.peer_count,
            "rpc_endpoint": status.node.rpc_url,
        });

        let notes = vec![
            "PQC nodes are expected to remain online for signature verification and post-quantum trust services.".to_string(),
            "Track latency and peer connectivity because PQC services are coordination-sensitive under load.".to_string(),
        ];

        return (diagnostic, notes);
    }

    let diagnostic = json!({
        "domain": "Infrastructure Services",
        "node_type": status.node.node_type,
        "role": status.node.role,
        "rpc_endpoint": status.node.rpc_url,
        "latest_block": status.block_height,
        "peer_count": status.peer_count,
        "syncing": status.syncing,
    });

    let notes = vec![
        "Service nodes should keep RPC health stable and avoid prolonged sync lag.".to_string(),
        "Use detail diagnostics to validate this role's runtime behavior before load testing."
            .to_string(),
    ];

    (diagnostic, notes)
}

fn extract_relayer_entries(value: Option<&Value>) -> Vec<Value> {
    let Some(value) = value else {
        return Vec::new();
    };

    if let Some(entries) = value.as_array() {
        return entries.clone();
    }

    if let Some(entries) = value.get("relayers").and_then(|item| item.as_array()) {
        return entries.clone();
    }

    if let Some(entries) = value
        .get("active_relayers")
        .and_then(|item| item.as_array())
    {
        return entries.clone();
    }

    Vec::new()
}

fn extract_attestation_count(value: Option<&Value>) -> usize {
    let Some(value) = value else {
        return 0;
    };

    if let Some(entries) = value.as_array() {
        return entries.len();
    }

    if let Some(entries) = value.get("attestations").and_then(|item| item.as_array()) {
        return entries.len();
    }

    value
        .get("count")
        .and_then(|item| item.as_u64())
        .unwrap_or(0) as usize
}

fn resolve_control_commands(
    overrides: &HashMap<String, String>,
    node_slot_id: &str,
    node_alias: &str,
    physical_machine_id: &str,
    inventory_path: &Path,
) -> NodeControlCommands {
    let machine = node_slot_id.to_ascii_lowercase().replace('-', "_");
    let node = node_alias.to_ascii_lowercase().replace('-', "_");

    let resolve = |action: &str| -> Option<String> {
        let keys = [
            format!("{}_{}_cmd", machine, action),
            format!("{}_{}_cmd", node, action),
            format!("{}_{}_command", machine, action),
            format!("{}_{}_command", node, action),
        ];

        for key in keys {
            if let Some(value) = overrides.get(&key) {
                return Some(value.clone());
            }
        }

        None
    };

    let mut custom_actions = HashMap::new();
    let custom_prefixes = [
        format!("{}_action_", machine),
        format!("{}_action_", node),
        format!("{}_custom_", machine),
        format!("{}_custom_", node),
        "action_".to_string(),
        "custom_".to_string(),
    ];

    for (key, value) in overrides {
        for prefix in &custom_prefixes {
            let Some(remainder) = key.strip_prefix(prefix.as_str()) else {
                continue;
            };
            let action_slug = remainder
                .strip_suffix("_cmd")
                .or_else(|| remainder.strip_suffix("_command"));
            let Some(action_slug) = action_slug else {
                continue;
            };
            let action_key = normalize_action_key(action_slug);
            if action_key.is_empty() {
                continue;
            }
            custom_actions
                .entry(action_key)
                .or_insert_with(|| value.clone());
        }
    }

    let mut commands = NodeControlCommands {
        start: resolve("start"),
        stop: resolve("stop"),
        restart: resolve("restart"),
        status: resolve("status"),
        setup: resolve("setup"),
        export_logs: resolve("export_logs"),
        view_chain_data: resolve("view_chain_data"),
        export_chain_data: resolve("export_chain_data"),
        custom_actions,
    };

    if let Some(orchestrator_script) = resolve_orchestrator_script_path(inventory_path) {
        let hosts_env_path = inventory_path
            .parent()
            .map(|parent| parent.join("hosts.env"))
            .filter(|candidate| candidate.is_file())
            .map(|candidate| candidate.to_string_lossy().to_string());

        let command_for = |operation: &str| {
            build_orchestrator_command(
                orchestrator_script.as_str(),
                hosts_env_path.as_deref(),
                node_slot_id,
                operation,
            )
        };

        // Always prefer the runtime-resolved orchestrator path so hosts.env does not pin
        // control actions to stale absolute paths from a different OS/machine.
        commands.start = Some(command_for("start"));
        commands.stop = Some(command_for("stop"));
        commands.restart = Some(command_for("restart"));
        commands.status = Some(command_for("status"));
        commands.setup = Some(command_for("setup_node"));
        commands.export_logs = Some(command_for("export_logs"));
        commands.view_chain_data = Some(command_for("view_chain_data"));
        commands.export_chain_data = Some(command_for("export_chain_data"));

        let default_custom_actions = [
            // Core lifecycle
            ("install_node", "install_node"),
            ("bootstrap_node", "bootstrap_node"),
            ("reset_chain", "reset_chain"),
            ("node_logs", "logs"),
            // Sync — downloads all missing blocks from peers without starting the node.
            // Goes through the agent first; this SSH fallback is the safety net for nodes
            // whose agent binary is absent or too old to advertise `sync_node`.
            ("sync_node", "sync_node"),
            // Validator VPN — agent-driven, non-consensus operations for applying
            // the latest signed validator/relayer VPN peer snapshot.
            ("validator_vpn_status", "validator_vpn_status"),
            ("validator_vpn_apply_latest", "validator_vpn_apply_latest"),
            ("validator_vpn_poll", "validator_vpn_poll"),
            // Agent management — always routed through orchestrator (SSH), never via
            // the agent itself, so it works even when the remote agent is absent or stale.
            ("update_agent", "deploy_agent"),
            // Class I — Consensus
            ("rotate_vrf_key", "rotate_vrf_key"),
            ("verify_archive_integrity", "verify_archive_integrity"),
            // Class II — Interoperability
            ("flush_relay_queue", "flush_relay_queue"),
            ("force_feed_update", "force_feed_update"),
            // Class III — Intelligence & Computation
            ("drain_compute_queue", "drain_compute_queue"),
            ("reload_models", "reload_models"),
            ("rotate_pqc_keys", "rotate_pqc_keys"),
            ("run_pqc_benchmark", "run_pqc_benchmark"),
            ("trigger_da_sample", "trigger_da_sample"),
            // Class V — Service & Support
            ("reindex_from_height", "reindex_from_height"),
        ];

        for (action_key, operation) in default_custom_actions {
            commands
                .custom_actions
                .insert(action_key.to_string(), command_for(operation));
        }

        if let Some(recovery_script) =
            resolve_validator_appliance_recovery_script_path(inventory_path)
        {
            commands.custom_actions.insert(
                "validator_wait_promote_vote_only".to_string(),
                format!(
                    "builtin:validator_wait_promote_vote_only:{}",
                    recovery_script
                ),
            );
            commands.custom_actions.insert(
                "validator_mesh_reconnect".to_string(),
                format!("builtin:validator_mesh_reconnect:{}", recovery_script),
            );
            commands.custom_actions.insert(
                "validator_state_diagnostics".to_string(),
                format!("builtin:validator_state_diagnostics:{}", recovery_script),
            );
            commands.custom_actions.insert(
                "validator_chain_body_repair".to_string(),
                format!("builtin:validator_chain_body_repair:{}", recovery_script),
            );
        }
    }

    apply_security_ssh_profile(node_slot_id, node_alias, physical_machine_id, &mut commands);

    commands
}

fn build_control_capabilities(commands: &NodeControlCommands) -> MonitorControlCapabilities {
    let start_configured = commands.start.is_some();
    let stop_configured = commands.stop.is_some();
    let restart_configured = commands.restart.is_some();
    let status_configured = commands.status.is_some();
    let setup_configured = commands.setup.is_some();
    let export_logs_configured = commands.export_logs.is_some();
    let view_chain_data_configured = commands.view_chain_data.is_some();
    let export_chain_data_configured = commands.export_chain_data.is_some();
    // sync_node runs `nodectl sync` via the agent (or SSH fallback); it is
    // available whenever the node has a start command configured, since both
    // go through the same nodectl script.
    let sync_node_configured = start_configured;

    // Node-type-specific shell actions are surfaced in role_operations, not here.
    // `update_agent` gets its own dedicated UI button, so exclude it from the
    // generic custom_actions list as well.
    let role_operation_keys: &[&str] = &[
        "rotate_vrf_key",
        "verify_archive_integrity",
        "flush_relay_queue",
        "force_feed_update",
        "drain_compute_queue",
        "reload_models",
        "rotate_pqc_keys",
        "run_pqc_benchmark",
        "trigger_da_sample",
        "reindex_from_height",
        "update_agent",
        "validator_wait_promote_vote_only",
        "validator_mesh_reconnect",
        "validator_state_diagnostics",
        "validator_chain_body_repair",
    ];

    let update_agent_configured = commands.custom_actions.contains_key("update_agent");

    let mut custom_actions = commands
        .custom_actions
        .keys()
        .filter(|key| !role_operation_keys.contains(&key.as_str()))
        .cloned()
        .map(|key| MonitorControlAction {
            label: humanize_action_label(&key),
            description: "Custom operation configured via hosts.env command mapping.".to_string(),
            category: "custom".to_string(),
            configured: true,
            source: "hosts.env".to_string(),
            key,
        })
        .collect::<Vec<_>>();
    custom_actions.sort_by(|a, b| a.label.cmp(&b.label));

    let enabled = start_configured
        || stop_configured
        || restart_configured
        || status_configured
        || setup_configured
        || export_logs_configured
        || view_chain_data_configured
        || export_chain_data_configured
        || sync_node_configured
        || !custom_actions.is_empty();

    let configuration_hint = if enabled {
        "Remote control is enabled for this node (hosts.env mappings and/or bundled orchestrator defaults).".to_string()
    } else {
        "Add MACHINE_XX_START_CMD / STOP_CMD / RESTART_CMD / STATUS_CMD plus optional SETUP/EXPORT_LOGS/VIEW_CHAIN_DATA/EXPORT_CHAIN_DATA entries in testnet/runtime/hosts.env, or ship bundled orchestration resources with the app.".to_string()
    };

    MonitorControlCapabilities {
        enabled,
        start_configured,
        stop_configured,
        restart_configured,
        status_configured,
        setup_configured,
        export_logs_configured,
        view_chain_data_configured,
        export_chain_data_configured,
        sync_node_configured,
        update_agent_configured,
        custom_actions,
        configuration_hint,
    }
}

fn build_role_operations(
    status: &MonitorNodeStatus,
    commands: &NodeControlCommands,
) -> Vec<MonitorControlAction> {
    let node_type = status.node.node_type.to_ascii_lowercase();
    let mut operations = Vec::new();

    let push_rpc = |key: &str,
                    label: &str,
                    description: &str,
                    category: &str,
                    ops: &mut Vec<MonitorControlAction>| {
        ops.push(MonitorControlAction {
            key: key.to_string(),
            label: label.to_string(),
            description: description.to_string(),
            category: category.to_string(),
            configured: true,
            source: "rpc".to_string(),
        });
    };

    let push_shell = |key: &str,
                      label: &str,
                      description: &str,
                      category: &str,
                      cmds: &NodeControlCommands,
                      ops: &mut Vec<MonitorControlAction>| {
        let configured = cmds.custom_actions.contains_key(key);
        ops.push(MonitorControlAction {
            key: key.to_string(),
            label: label.to_string(),
            description: description.to_string(),
            category: category.to_string(),
            configured,
            source: if configured {
                "orchestrator".to_string()
            } else {
                "unavailable".to_string()
            },
        });
    };

    // ── Common operations for every node ────────────────────────────────
    push_rpc(
        "rpc:get_node_status",
        "RPC Node Status",
        "Fetch node runtime status directly over JSON-RPC.",
        "runtime",
        &mut operations,
    );
    push_rpc(
        "rpc:get_sync_status",
        "RPC Sync Status",
        "Fetch sync state and verify this node is not drifting.",
        "runtime",
        &mut operations,
    );
    push_rpc(
        "rpc:get_peer_info",
        "RPC Peer Info",
        "Fetch connected peers and gossip visibility.",
        "runtime",
        &mut operations,
    );
    push_rpc(
        "rpc:get_latest_block",
        "Latest Block",
        "Fetch the latest block from this node.",
        "runtime",
        &mut operations,
    );

    // ── Class I — Consensus nodes ───────────────────────────────────────
    // Validator
    if node_type == "validator" {
        push_rpc(
            "rpc:get_validator_activity",
            "Validator Activity",
            "Inspect validator stake, blocks produced, epoch participation, and synergy score.",
            "consensus",
            &mut operations,
        );
        push_rpc(
            "rpc:get_validators",
            "Validator Set",
            "Fetch the active validator set and verify this node's membership.",
            "consensus",
            &mut operations,
        );
        push_rpc(
            "rpc:get_determinism_digest",
            "Determinism Digest",
            "Compare state root hash across validators for fork detection.",
            "consensus",
            &mut operations,
        );
        push_rpc(
            "rpc:get_epoch_info",
            "Epoch Info",
            "Fetch current epoch number, progress, and time remaining.",
            "consensus",
            &mut operations,
        );
        push_rpc(
            "rpc:get_staking_info",
            "Staking Info",
            "Check staked SNRG amount, rewards earned, and slashing history.",
            "consensus",
            &mut operations,
        );
        push_shell(
            "rotate_vrf_key",
            "Rotate VRF Key",
            "Generate and register a new VRF keypair for committee selection.",
            "consensus",
            &commands,
            &mut operations,
        );
        push_shell(
            "validator_wait_promote_vote_only",
            "Promote Vote-only",
            "Check vote-only probation height and run the supported proposer promotion when eligible.",
            "consensus",
            &commands,
            &mut operations,
        );
        push_shell(
            "validator_mesh_reconnect",
            "Mesh Reconnect",
            "Restart validator networking stack and collect mesh + qRPC evidence before and after reconnect.",
            "consensus",
            &commands,
            &mut operations,
        );
        push_shell(
            "validator_state_diagnostics",
            "State Diagnostics",
            "Collect diagnostics used for generic validator-recovery triage.",
            "consensus",
            &commands,
            &mut operations,
        );
        push_shell(
            "validator_chain_body_repair",
            "Chain-Body Repair",
            "Run generic committed-block chain-body repair with evidence logging.",
            "consensus",
            &commands,
            &mut operations,
        );
        push_shell(
            "validator_vpn_status",
            "VPN Status",
            "Inspect the validator VPN interface, WireGuard tooling, and applied snapshot generation.",
            "network",
            &commands,
            &mut operations,
        );
        push_shell(
            "validator_vpn_apply_latest",
            "Apply VPN Snapshot",
            "Apply the latest signed validator VPN peer snapshot without starting consensus.",
            "network",
            &commands,
            &mut operations,
        );
        push_shell(
            "validator_vpn_poll",
            "Poll VPN Snapshot",
            "Fetch and apply a newer validator VPN peer snapshot when one is available.",
            "network",
            &commands,
            &mut operations,
        );
    }

    // Committee
    if node_type == "committee" {
        push_rpc(
            "rpc:get_validator_activity",
            "Committee Activity",
            "Inspect committee member participation and voting record.",
            "consensus",
            &mut operations,
        );
        push_rpc(
            "rpc:get_validators",
            "Validator Set",
            "Fetch the active validator set and verify committee membership.",
            "consensus",
            &mut operations,
        );
        push_rpc(
            "rpc:get_determinism_digest",
            "Determinism Digest",
            "Compare state root hash for consensus consistency.",
            "consensus",
            &mut operations,
        );
        push_rpc(
            "rpc:get_committee_status",
            "Committee Status",
            "Fetch current committee composition and rotation schedule.",
            "consensus",
            &mut operations,
        );
        push_rpc(
            "rpc:get_epoch_info",
            "Epoch Info",
            "Fetch current epoch number and committee rotation progress.",
            "consensus",
            &mut operations,
        );
    }

    // Archive Validator
    if node_type == "archive-validator" || node_type == "archive_validator" {
        push_rpc(
            "rpc:get_validator_activity",
            "Validator Activity",
            "Inspect archive validator stake and block production.",
            "consensus",
            &mut operations,
        );
        push_rpc(
            "rpc:get_validators",
            "Validator Set",
            "Verify archive validator is in the active set.",
            "consensus",
            &mut operations,
        );
        push_rpc(
            "rpc:get_archive_status",
            "Archive Status",
            "Check archive completeness, oldest retained block, and storage usage.",
            "consensus",
            &mut operations,
        );
        push_rpc(
            "rpc:get_determinism_digest",
            "Determinism Digest",
            "Validate full-history state consistency.",
            "consensus",
            &mut operations,
        );
        push_shell(
            "verify_archive_integrity",
            "Verify Archive Integrity",
            "Run integrity check across all retained chain data.",
            "consensus",
            &commands,
            &mut operations,
        );
    }

    // Audit Validator
    if node_type == "audit-validator" || node_type == "audit_validator" {
        push_rpc(
            "rpc:get_validator_activity",
            "Validator Activity",
            "Inspect audit validator participation and attestations.",
            "consensus",
            &mut operations,
        );
        push_rpc(
            "rpc:get_validators",
            "Validator Set",
            "Verify audit validator is in the active set.",
            "consensus",
            &mut operations,
        );
        push_rpc(
            "rpc:get_audit_report",
            "Audit Report",
            "Fetch latest audit findings: fork anomalies, state mismatches, invalid transitions.",
            "consensus",
            &mut operations,
        );
        push_rpc(
            "rpc:get_determinism_digest",
            "Determinism Digest",
            "Cross-validate state proofs against other validators.",
            "consensus",
            &mut operations,
        );
    }

    // ── Class II — Interoperability nodes ────────────────────────────────
    // Relayer
    if node_type == "relayer" {
        push_rpc(
            "rpc:get_sxcp_status",
            "SXCP Protocol Status",
            "Check SXCP relayer quorum, heartbeat window, and protocol health.",
            "interop",
            &mut operations,
        );
        push_rpc(
            "rpc:get_relayer_set",
            "Relayer Set",
            "Fetch registered relayers and their active/slashed status.",
            "interop",
            &mut operations,
        );
        push_rpc(
            "rpc:get_relayer_health",
            "Relayer Health",
            "Inspect this relayer's liveness, message throughput, and heartbeat metrics.",
            "interop",
            &mut operations,
        );
        push_rpc(
            "rpc:get_attestations",
            "Recent Attestations",
            "Fetch recent SXCP cross-chain attestations relayed by this node.",
            "interop",
            &mut operations,
        );
        push_rpc(
            "rpc:get_relay_queue",
            "Relay Queue",
            "Check pending cross-chain messages awaiting relay.",
            "interop",
            &mut operations,
        );
        push_shell(
            "flush_relay_queue",
            "Flush Relay Queue",
            "Force-submit all pending relay messages.",
            "interop",
            &commands,
            &mut operations,
        );
        push_shell(
            "validator_vpn_status",
            "VPN Status",
            "Inspect the validator VPN interface, WireGuard tooling, and applied snapshot generation.",
            "network",
            &commands,
            &mut operations,
        );
        push_shell(
            "validator_vpn_apply_latest",
            "Apply VPN Snapshot",
            "Apply the latest signed validator VPN peer snapshot without restarting the relayer.",
            "network",
            &commands,
            &mut operations,
        );
        push_shell(
            "validator_vpn_poll",
            "Poll VPN Snapshot",
            "Fetch and apply a newer validator VPN peer snapshot when one is available.",
            "network",
            &commands,
            &mut operations,
        );
    }

    // Witness
    if node_type == "witness" {
        push_rpc(
            "rpc:get_sxcp_status",
            "SXCP Protocol Status",
            "Check SXCP protocol health from the witness perspective.",
            "interop",
            &mut operations,
        );
        push_rpc(
            "rpc:get_witness_status",
            "Witness Status",
            "Fetch witness attestation count, challenge responses, and uptime.",
            "interop",
            &mut operations,
        );
        push_rpc(
            "rpc:get_attestations",
            "Recent Attestations",
            "Fetch cross-chain attestations co-signed by this witness.",
            "interop",
            &mut operations,
        );
        push_rpc(
            "rpc:get_relayer_health",
            "Relayer Health",
            "Cross-check relayer health from the witness vantage point.",
            "interop",
            &mut operations,
        );
    }

    // Oracle
    if node_type == "oracle" {
        push_rpc(
            "rpc:get_sxcp_status",
            "SXCP Protocol Status",
            "Check SXCP oracle feed health and quorum.",
            "interop",
            &mut operations,
        );
        push_rpc(
            "rpc:get_oracle_feeds",
            "Oracle Feeds",
            "Fetch active price feeds, data sources, and last update timestamps.",
            "interop",
            &mut operations,
        );
        push_rpc(
            "rpc:get_oracle_health",
            "Oracle Health",
            "Check feed freshness, deviation alerts, and source availability.",
            "interop",
            &mut operations,
        );
        push_shell(
            "force_feed_update",
            "Force Feed Update",
            "Trigger an immediate oracle price feed refresh.",
            "interop",
            &commands,
            &mut operations,
        );
    }

    // UMA Coordinator
    if node_type == "uma-coordinator" || node_type == "uma_coordinator" {
        push_rpc(
            "rpc:get_sxcp_status",
            "SXCP Protocol Status",
            "Check SXCP health and UMA routing status.",
            "interop",
            &mut operations,
        );
        push_rpc(
            "rpc:get_uma_routing_table",
            "UMA Routing Table",
            "Fetch the Universal Meta-Address resolution table and peer mappings.",
            "interop",
            &mut operations,
        );
        push_rpc(
            "rpc:get_uma_resolution_stats",
            "UMA Resolution Stats",
            "Check address resolution throughput, cache hit rate, and latency.",
            "interop",
            &mut operations,
        );
        push_rpc(
            "rpc:get_relayer_set",
            "Relayer Set",
            "Inspect relayer connectivity for cross-chain UMA resolution.",
            "interop",
            &mut operations,
        );
    }

    // Cross-Chain Verifier
    if node_type == "cross-chain-verifier" || node_type == "cross_chain_verifier" {
        push_rpc(
            "rpc:get_sxcp_status",
            "SXCP Protocol Status",
            "Check SXCP verification pipeline health.",
            "interop",
            &mut operations,
        );
        push_rpc(
            "rpc:get_verification_queue",
            "Verification Queue",
            "Fetch pending cross-chain proofs awaiting verification.",
            "interop",
            &mut operations,
        );
        push_rpc(
            "rpc:get_attestations",
            "Recent Attestations",
            "Fetch attestations verified by this node.",
            "interop",
            &mut operations,
        );
        push_rpc(
            "rpc:get_verification_stats",
            "Verification Stats",
            "Check proof verification throughput, rejection rate, and latency.",
            "interop",
            &mut operations,
        );
    }

    // ── Class III — Intelligence & Computation nodes ────────────────────
    // Compute
    if node_type == "compute" {
        push_rpc(
            "rpc:get_compute_tasks",
            "Compute Tasks",
            "Fetch active and queued compute tasks assigned to this node.",
            "compute",
            &mut operations,
        );
        push_rpc(
            "rpc:get_compute_metrics",
            "Compute Metrics",
            "Check CPU/GPU utilization, task throughput, and queue depth.",
            "compute",
            &mut operations,
        );
        push_rpc(
            "rpc:get_determinism_digest",
            "Determinism Digest",
            "Validate deterministic compute output consistency.",
            "compute",
            &mut operations,
        );
        push_shell(
            "drain_compute_queue",
            "Drain Queue",
            "Stop accepting new tasks and finish active ones gracefully.",
            "compute",
            &commands,
            &mut operations,
        );
    }

    // AI Inference
    if node_type == "ai-inference" || node_type == "ai_inference" {
        push_rpc(
            "rpc:get_inference_status",
            "Inference Status",
            "Check loaded models, GPU memory, and inference throughput.",
            "compute",
            &mut operations,
        );
        push_rpc(
            "rpc:get_compute_tasks",
            "Inference Queue",
            "Fetch pending and active inference requests.",
            "compute",
            &mut operations,
        );
        push_rpc(
            "rpc:get_model_registry",
            "Model Registry",
            "List loaded AI models, versions, and readiness state.",
            "compute",
            &mut operations,
        );
        push_shell(
            "reload_models",
            "Reload Models",
            "Hot-reload AI model weights without restarting the node.",
            "compute",
            &commands,
            &mut operations,
        );
    }

    // PQC Crypto
    if node_type == "pqc-crypto" || node_type == "pqc_crypto" {
        push_rpc(
            "rpc:get_pqc_status",
            "PQC Status",
            "Check Aegis PQC suite status: ML-KEM-512, Dilithium-3, SLH-DSA, FN-DSA availability.",
            "pqc",
            &mut operations,
        );
        push_rpc(
            "rpc:get_pqc_key_inventory",
            "Key Inventory",
            "Fetch PQC keypair inventory and expiration schedules.",
            "pqc",
            &mut operations,
        );
        push_rpc(
            "rpc:get_determinism_digest",
            "Determinism Digest",
            "Validate PQC signature state consistency across the network.",
            "pqc",
            &mut operations,
        );
        push_shell(
            "rotate_pqc_keys",
            "Rotate PQC Keys",
            "Trigger PQC key rotation using the Aegis suite.",
            "pqc",
            &commands,
            &mut operations,
        );
        push_shell(
            "run_pqc_benchmark",
            "Run PQC Benchmark",
            "Benchmark PQC signing and verification performance.",
            "pqc",
            &commands,
            &mut operations,
        );
    }

    // Data Availability
    if node_type == "data-availability" || node_type == "data_availability" {
        push_rpc(
            "rpc:get_da_status",
            "DA Layer Status",
            "Check data availability layer health, sampling rate, and blob count.",
            "compute",
            &mut operations,
        );
        push_rpc(
            "rpc:get_da_storage_stats",
            "DA Storage Stats",
            "Fetch blob storage utilization, retention window, and pruning state.",
            "compute",
            &mut operations,
        );
        push_rpc(
            "rpc:get_da_sampling_results",
            "DA Sampling",
            "Fetch recent data availability sampling results and attestations.",
            "compute",
            &mut operations,
        );
        push_shell(
            "trigger_da_sample",
            "Trigger DA Sample",
            "Force an immediate data availability sampling round.",
            "compute",
            &commands,
            &mut operations,
        );
    }

    // GPU Node (dedicated GPU acceleration)
    if node_type == "gpu-node" || node_type == "gpu_node" {
        push_rpc(
            "rpc:get_compute_tasks",
            "GPU Tasks",
            "Fetch active and queued GPU compute tasks.",
            "compute",
            &mut operations,
        );
        push_rpc(
            "rpc:get_compute_metrics",
            "GPU Metrics",
            "Check GPU utilization, VRAM usage, temperature, and throughput.",
            "compute",
            &mut operations,
        );
        push_rpc(
            "rpc:get_inference_status",
            "Inference Status",
            "Check GPU inference pipeline health and loaded models.",
            "compute",
            &mut operations,
        );
    }

    // ── Class IV — Governance & Treasury nodes ──────────────────────────
    // Governance Auditor
    if node_type == "governance-auditor" || node_type == "governance_auditor" {
        push_rpc(
            "rpc:get_governance_proposals",
            "Active Proposals",
            "Fetch active governance proposals and voting status.",
            "governance",
            &mut operations,
        );
        push_rpc(
            "rpc:get_governance_audit_log",
            "Audit Log",
            "Review governance action audit trail and compliance events.",
            "governance",
            &mut operations,
        );
        push_rpc(
            "rpc:get_staking_info",
            "Staking Info",
            "Check governance auditor staking bond and slashing status.",
            "governance",
            &mut operations,
        );
    }

    // Treasury Controller
    if node_type == "treasury-controller" || node_type == "treasury_controller" {
        push_rpc(
            "rpc:get_treasury_balance",
            "Treasury Balance",
            "Fetch current treasury SNRG balance and recent disbursements.",
            "governance",
            &mut operations,
        );
        push_rpc(
            "rpc:get_treasury_transactions",
            "Treasury Transactions",
            "List recent treasury inflows, outflows, and pending approvals.",
            "governance",
            &mut operations,
        );
        push_rpc(
            "rpc:get_staking_info",
            "Staking Info",
            "Check treasury controller staking bond status.",
            "governance",
            &mut operations,
        );
    }

    // Security Council
    if node_type == "security-council" || node_type == "security_council" {
        push_rpc(
            "rpc:get_security_alerts",
            "Security Alerts",
            "Fetch active security alerts, threat detections, and incident reports.",
            "governance",
            &mut operations,
        );
        push_rpc(
            "rpc:get_slashing_events",
            "Slashing Events",
            "Review recent slashing events and penalty enforcement.",
            "governance",
            &mut operations,
        );
        push_rpc(
            "rpc:get_governance_proposals",
            "Active Proposals",
            "Fetch governance proposals requiring security council review.",
            "governance",
            &mut operations,
        );
        push_rpc(
            "rpc:get_network_stats",
            "Network Stats",
            "Monitor network-wide health metrics for anomaly detection.",
            "governance",
            &mut operations,
        );
    }

    // ── Class V — Service & Support nodes ───────────────────────────────
    // RPC Gateway
    if node_type == "rpc-gateway" || node_type == "rpc_gateway" {
        push_rpc(
            "rpc:get_network_stats",
            "Network Stats",
            "Fetch RPC-facing throughput, request rate, and error rate.",
            "services",
            &mut operations,
        );
        push_rpc(
            "rpc:get_all_wallets",
            "Wallet Inventory",
            "Fetch known wallet list for developer tooling.",
            "services",
            &mut operations,
        );
        push_rpc(
            "rpc:get_rpc_method_stats",
            "RPC Method Stats",
            "Check per-method call counts, latency percentiles, and error rates.",
            "services",
            &mut operations,
        );
        push_rpc(
            "rpc:get_rate_limit_status",
            "Rate Limit Status",
            "Fetch current rate limit configuration and active throttles.",
            "services",
            &mut operations,
        );
    }

    // Indexer
    if node_type == "indexer" {
        push_rpc(
            "rpc:get_network_stats",
            "Network Stats",
            "Fetch network throughput and block propagation metrics.",
            "services",
            &mut operations,
        );
        push_rpc(
            "rpc:get_indexer_status",
            "Indexer Status",
            "Check indexing progress, head lag, and indexed block height.",
            "services",
            &mut operations,
        );
        push_rpc(
            "rpc:get_indexer_stats",
            "Indexer Stats",
            "Fetch transaction indexing throughput and query performance.",
            "services",
            &mut operations,
        );
        push_shell(
            "reindex_from_height",
            "Reindex from Height",
            "Trigger a reindex starting from a specific block height.",
            "services",
            &commands,
            &mut operations,
        );
    }

    // Observer
    if node_type == "observer" {
        push_rpc(
            "rpc:get_network_stats",
            "Network Stats",
            "Fetch network-wide health metrics and block propagation.",
            "services",
            &mut operations,
        );
        push_rpc(
            "rpc:get_all_wallets",
            "Wallet Inventory",
            "Fetch wallet state for read-only observation.",
            "services",
            &mut operations,
        );
        push_rpc(
            "rpc:get_observer_status",
            "Observer Status",
            "Check observer sync height, peer count, and read-only mode status.",
            "services",
            &mut operations,
        );
    }

    let mut custom_ops = commands
        .custom_actions
        .keys()
        .cloned()
        .map(|key| MonitorControlAction {
            label: humanize_action_label(&key),
            description: "Custom machine action configured in hosts.env.".to_string(),
            category: "custom".to_string(),
            configured: true,
            source: "hosts.env".to_string(),
            key,
        })
        .collect::<Vec<_>>();
    custom_ops.sort_by(|a, b| a.label.cmp(&b.label));
    operations.extend(custom_ops);
    operations
}

fn build_atlas_links(
    overrides: &HashMap<String, String>,
    status: &MonitorNodeStatus,
    rpc: &MonitorRpcDiagnostics,
) -> MonitorAtlasLinks {
    let node_slot_id = status.node.node_slot_id.as_str();
    let node_alias = status.node.node_alias.as_str();

    let base_url = resolve_override_value(overrides, node_slot_id, node_alias, "atlas_base_url")
        .or_else(|| resolve_override_value(overrides, node_slot_id, node_alias, "atlas_url"))
        .or_else(|| resolve_override_value(overrides, node_slot_id, node_alias, "atlas_home_url"))
        .or_else(|| resolve_override_value(overrides, node_slot_id, node_alias, "explorer_url"))
        .or_else(|| {
            resolve_override_value(
                overrides,
                node_slot_id,
                node_alias,
                "synergy_explorer_endpoint",
            )
        })
        .or_else(|| std::env::var("SYNERGY_ATLAS_BASE_URL").ok())
        .or_else(|| std::env::var("SYNERGY_EXPLORER_ENDPOINT").ok())
        .or_else(|| Some("https://testnet-explorer.synergy-network.io".to_string()))
        .map(|value| value.trim().trim_end_matches('/').to_string())
        .filter(|value| !value.is_empty());

    let enabled = base_url.is_some();
    let home_url = base_url.clone();
    // Atlas is a hash-router app (`#/...`), so deep links must target hash routes.
    let transactions_url = base_url
        .as_ref()
        .map(|base| join_url(base, "#/transactions"));
    let wallets_url = base_url.as_ref().map(|base| join_url(base, "#/wallet"));
    let contracts_url = base_url.as_ref().map(|base| join_url(base, "#/contracts"));

    let latest_block = status
        .block_height
        .or_else(|| rpc.latest_block.as_ref().and_then(parse_block_height));
    let latest_block_url = match (base_url.as_ref(), latest_block) {
        (Some(base), Some(height)) => Some(join_url(base, format!("#/block/{height}").as_str())),
        _ => None,
    };

    let latest_transaction_hash = extract_latest_transaction_hash(rpc.latest_block.as_ref());
    let latest_transaction_url = match (base_url.as_ref(), latest_transaction_hash.as_ref()) {
        (Some(base), Some(hash)) => Some(join_url(base, format!("#/tx/{hash}").as_str())),
        _ => None,
    };

    let node_wallet_url = match (base_url.as_ref(), status.node.node_address.as_ref()) {
        (Some(base), Some(address)) if !address.trim().is_empty() => Some(join_url(
            base,
            format!("#/address/{}", address.trim()).as_str(),
        )),
        _ => None,
    };

    MonitorAtlasLinks {
        enabled,
        base_url,
        home_url,
        transactions_url,
        wallets_url,
        contracts_url,
        latest_block_url,
        latest_transaction_url,
        latest_transaction_hash,
        node_wallet_url,
    }
}

fn resolve_override_value(
    overrides: &HashMap<String, String>,
    node_slot_id: &str,
    node_alias: &str,
    key_name: &str,
) -> Option<String> {
    let machine = node_slot_id.to_ascii_lowercase().replace('-', "_");
    let node = node_alias.to_ascii_lowercase().replace('-', "_");
    let target = key_name.to_ascii_lowercase().replace('-', "_");

    let keys = [
        format!("{}_{}", machine, target),
        format!("{}_{}", node, target),
        target,
    ];

    for key in keys {
        if let Some(value) = overrides.get(&key) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }

    None
}

fn resolve_control_action_command(commands: &NodeControlCommands, action: &str) -> Option<String> {
    match action {
        "start" => commands.start.clone(),
        "stop" => commands.stop.clone(),
        "restart" => commands.restart.clone(),
        "status" => commands.status.clone(),
        "setup" => commands.setup.clone(),
        "export_logs" => commands.export_logs.clone(),
        "view_chain_data" => commands.view_chain_data.clone(),
        "export_chain_data" => commands.export_chain_data.clone(),
        _ => commands.custom_actions.get(action).cloned(),
    }
}

enum AgentControlAttempt {
    Completed(MonitorControlResult),
    Unavailable,
}

fn agent_supports_action(action: &str) -> bool {
    matches!(
        action,
        "start"
            | "stop"
            | "restart"
            | "status"
            | "setup"
            | "setup_node"
            | "install_node"
            | "bootstrap_node"
            | "reset_chain"
            | "sync_node"
            | "logs"
            | "node_logs"
            | "validator_vpn_status"
            | "validator_vpn_prepare"
            | "validator_vpn_apply_latest"
            | "validator_vpn_poll"
    )
}

fn agent_endpoint_for_node(
    node: &MonitorNode,
    host_overrides: &HashMap<String, String>,
) -> Option<String> {
    let fallback = canonical_management_host_for_physical_machine(&node.physical_machine_id)
        .unwrap_or_else(|| node.host.clone());
    let host = resolve_management_host_override(
        host_overrides,
        &node.node_slot_id,
        &node.node_alias,
        fallback,
    );
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(format!("http://{trimmed}:{TESTNET_AGENT_PORT}"))
}

/// Actions that involve stopping/starting a node binary (chain reset, install, setup)
/// can take 60-300 seconds — far beyond the default 12 s. Use a long timeout so the
/// HTTP request waits for the agent to finish instead of timing out and triggering the
/// SSH fallback (which uses Rob-specific hardcoded paths and would fail on other machines).
fn agent_request_timeout(action: &str) -> Duration {
    match action {
        "reset_chain" | "install_node" | "bootstrap_node" | "setup_node" | "setup" | "start"
        | "restart" => Duration::from_secs(7200),
        // sync_node downloads all missing blocks — can take hours for a cold node.
        // Set to 2 hours to match the default PRESTART_SYNC_TIMEOUT_SECS in nodectl.sh.
        "sync_node" => Duration::from_secs(7200),
        "validator_vpn_apply_latest" | "validator_vpn_poll" => Duration::from_secs(120),
        _ => Duration::from_secs(30),
    }
}

fn agent_phase_is_terminal(phase: Option<&str>) -> bool {
    matches!(
        phase.unwrap_or_default(),
        "completed"
            | "failed"
            | "process_alive"
            | "pid_written"
            | "spawn_failed"
            | "status_complete"
            | "sync_complete"
            | "sync_failed"
            | "reset_complete"
            | "reset_failed"
            | "validator_vpn_status_complete"
            | "validator_vpn_prepare_complete"
            | "validator_vpn_prepare_failed"
            | "validator_vpn_apply_complete"
            | "validator_vpn_apply_failed"
    )
}

fn validator_vpn_monitor_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn validator_vpn_monitor_coordinator_url() -> Option<String> {
    validator_vpn_monitor_env("VALIDATOR_VPN_COORDINATOR_URL")
        .or_else(|| validator_vpn_monitor_env("SYNERGY_VALIDATOR_VPN_COORDINATOR_URL"))
        .or_else(|| Some(DEFAULT_VALIDATOR_VPN_COORDINATOR_URL.to_string()))
}

fn validator_vpn_monitor_public_key() -> Option<String> {
    validator_vpn_monitor_env("VALIDATOR_VPN_COORDINATOR_PUBLIC_KEY")
        .or_else(|| validator_vpn_monitor_env("SYNERGY_VALIDATOR_VPN_COORDINATOR_PUBLIC_KEY"))
}

fn monitor_node_slot_number(node: &MonitorNode) -> Option<u8> {
    [
        node.node_slot_id.as_str(),
        node.node_alias.as_str(),
        node.host.as_str(),
        node.physical_machine_id.as_str(),
    ]
    .iter()
    .find_map(|value| {
        let lower = value.trim().to_ascii_lowercase();
        let digits = lower
            .chars()
            .rev()
            .take_while(|ch| ch.is_ascii_digit())
            .collect::<String>()
            .chars()
            .rev()
            .collect::<String>();
        if digits.is_empty() {
            return None;
        }
        let has_known_prefix = lower.contains("genval-")
            || lower.contains("validator-")
            || lower.contains("validator ")
            || lower.contains("synergy-val")
            || lower.contains("relayer-")
            || lower.contains("relayer ")
            || lower.contains("synergy-relayer");
        if !has_known_prefix {
            return None;
        }
        digits.parse::<u8>().ok().filter(|slot| *slot > 0)
    })
}

fn validator_vpn_identity_for_monitor_node(node: &MonitorNode) -> Option<(String, String)> {
    let slot = monitor_node_slot_number(node)?;
    let node_type = node.node_type.trim().to_ascii_lowercase();
    let role = node.role.trim().to_ascii_lowercase();
    let alias = node.node_alias.trim().to_ascii_lowercase();
    let is_validator = node_type == "validator" || role == "validator" || alias.contains("val");
    let is_relayer = node_type == "relayer" || role == "relayer" || alias.contains("relayer");

    if is_validator {
        if slot <= 6 {
            Some((
                format!("bootstrap-validator-{slot}"),
                format!("{INNERNET_VALIDATOR_ADDRESS_PREFIX}.{slot}/32"),
            ))
        } else {
            Some((
                format!("validator-{slot}"),
                format!("{INNERNET_VALIDATOR_ADDRESS_PREFIX}.{slot}/32"),
            ))
        }
    } else if is_relayer && slot <= 3 {
        Some((
            format!("bootstrap-relayer-{slot}"),
            format!("{INNERNET_RELAYER_ADDRESS_PREFIX}.{slot}/32"),
        ))
    } else {
        None
    }
}

async fn try_execute_monitor_agent_control(
    node: &MonitorNode,
    action: &str,
    host_overrides: &HashMap<String, String>,
) -> AgentControlAttempt {
    let Some(base_url) = agent_endpoint_for_node(node, host_overrides) else {
        return AgentControlAttempt::Unavailable;
    };

    let client = Client::builder()
        .timeout(agent_request_timeout(action))
        .connect_timeout(Duration::from_secs(2))
        .build()
        .unwrap_or_else(|_| Client::new());

    let vpn_identity = if matches!(action, "validator_vpn_apply_latest" | "validator_vpn_poll") {
        validator_vpn_identity_for_monitor_node(node)
    } else {
        None
    };

    let request = TestnetAgentControlRequest {
        node_slot_id: node.node_slot_id.clone(),
        action: action.to_string(),
        target_reason: None,
        target_url: if vpn_identity.is_some() {
            validator_vpn_monitor_coordinator_url()
        } else {
            None
        },
        vpn_node_id: vpn_identity.as_ref().map(|identity| identity.0.clone()),
        vpn_ip: vpn_identity.as_ref().map(|identity| identity.1.clone()),
        vpn_public_key: if vpn_identity.is_some() {
            validator_vpn_monitor_public_key()
        } else {
            None
        },
    };

    let response = match client
        .post(format!("{base_url}/v1/control"))
        .json(&request)
        .send()
        .await
    {
        Ok(response) => response,
        Err(_) => return AgentControlAttempt::Unavailable,
    };

    if response.status() == StatusCode::NOT_FOUND
        || response.status() == StatusCode::METHOD_NOT_ALLOWED
    {
        return AgentControlAttempt::Unavailable;
    }

    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    if agent_error_requires_ssh_fallback(&text) {
        return AgentControlAttempt::Unavailable;
    }
    let result = if let Ok(payload) = serde_json::from_str::<TestnetAgentControlResponse>(&text) {
        let payload = if let Some(job_id) = payload.job_id.clone() {
            if agent_phase_is_terminal(payload.phase.as_deref()) {
                payload
            } else {
                match poll_monitor_agent_job(&client, &base_url, &job_id, action).await {
                    Ok(polled) => polled,
                    Err(error) => TestnetAgentControlResponse {
                        node_slot_id: payload.node_slot_id.clone(),
                        action: payload.action.clone(),
                        success: false,
                        exit_code: 1,
                        stdout: String::new(),
                        stderr: error,
                        transport: payload.transport.clone(),
                        executed_at_utc: Utc::now().to_rfc3339(),
                        phase: Some("failed".to_string()),
                        job_id: Some(job_id),
                        process_alive: None,
                    },
                }
            }
        } else {
            payload
        };

        let mut stdout = truncate_text(payload.stdout.trim(), 6000);
        if let Some(phase) = payload.phase.as_deref() {
            if !phase.is_empty() {
                if !stdout.is_empty() {
                    stdout.push('\n');
                }
                stdout.push_str(&format!("PHASE: {phase}"));
            }
        }
        if let Some(process_alive) = payload.process_alive {
            if !stdout.is_empty() {
                stdout.push('\n');
            }
            stdout.push_str(&format!("PROCESS_ALIVE: {process_alive}"));
        }

        MonitorControlResult {
            node_slot_id: payload.node_slot_id,
            action: payload.action,
            success: payload.success,
            exit_code: payload.exit_code,
            command: payload.transport,
            stdout,
            stderr: truncate_text(payload.stderr.trim(), 6000),
            executed_at_utc: payload.executed_at_utc,
        }
    } else {
        MonitorControlResult {
            node_slot_id: node.node_slot_id.clone(),
            action: action.to_string(),
            success: status.is_success(),
            exit_code: if status.is_success() { 0 } else { 1 },
            command: "testnet-agent".to_string(),
            stdout: if status.is_success() {
                truncate_text(text.trim(), 6000)
            } else {
                String::new()
            },
            stderr: if status.is_success() {
                String::new()
            } else {
                truncate_text(text.trim(), 6000)
            },
            executed_at_utc: Utc::now().to_rfc3339(),
        }
    };

    if !result.success
        && (agent_error_requires_ssh_fallback(&result.stderr)
            || agent_error_requires_ssh_fallback(&result.stdout))
    {
        return AgentControlAttempt::Unavailable;
    }

    AgentControlAttempt::Completed(result)
}

async fn poll_monitor_agent_job(
    client: &Client,
    base_url: &str,
    job_id: &str,
    action: &str,
) -> Result<TestnetAgentControlResponse, String> {
    let deadline = Instant::now() + agent_request_timeout(action);
    loop {
        if Instant::now() >= deadline {
            return Err(format!("Timed out waiting for agent control job {job_id}"));
        }

        let response = client
            .get(format!("{base_url}/v1/control/jobs/{job_id}"))
            .send()
            .await
            .map_err(|error| format!("Failed to poll agent control job {job_id}: {error}"))?;
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(format!(
                "Agent control job {job_id} returned HTTP {}: {}",
                status,
                truncate_text(text.trim(), 600)
            ));
        }

        let payload =
            serde_json::from_str::<TestnetAgentControlResponse>(&text).map_err(|error| {
                format!("Failed to decode agent control job {job_id} payload: {error}")
            })?;
        if agent_phase_is_terminal(payload.phase.as_deref()) {
            return Ok(payload);
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

fn agent_error_requires_ssh_fallback(text: &str) -> bool {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return false;
    }

    if trimmed.contains("Unsupported testnet agent action") {
        return true;
    }

    serde_json::from_str::<Value>(trimmed)
        .ok()
        .and_then(|payload| {
            payload
                .get("error")
                .and_then(Value::as_str)
                .map(|error| error.contains("Unsupported testnet agent action"))
        })
        .unwrap_or(false)
}

fn resolve_rpc_control_call(action: &str) -> Option<(&'static str, Value)> {
    let rpc_action = action.strip_prefix("rpc:")?;
    match rpc_action {
        // ── Common ──────────────────────────────────────────────────────
        "get_node_status" | "node_status" => Some(("synergy_getNodeStatus", json!([]))),
        "get_sync_status" | "sync_status" => Some(("synergy_getSyncStatus", json!([]))),
        "get_peer_info" | "peer_info" => Some(("synergy_getPeerInfo", json!([]))),
        "get_latest_block" | "latest_block" => Some(("synergy_getLatestBlock", json!([]))),
        "get_network_stats" | "network_stats" => Some(("synergy_getNetworkStats", json!([]))),
        "get_all_wallets" | "all_wallets" => Some(("synergy_getAllWallets", json!([]))),

        // ── Class I — Consensus ─────────────────────────────────────────
        "get_validator_activity" | "validator_activity" => {
            Some(("synergy_getValidatorActivity", json!([])))
        }
        "get_validators" | "validators" => Some(("synergy_getValidators", json!([]))),
        "get_determinism_digest" | "determinism_digest" => {
            Some(("synergy_getDeterminismDigest", json!([])))
        }
        "get_epoch_info" | "epoch_info" => Some(("synergy_getEpochInfo", json!([]))),
        "get_staking_info" | "staking_info" => Some(("synergy_getStakingInfo", json!([]))),
        "get_committee_status" | "committee_status" => {
            Some(("synergy_getCommitteeStatus", json!([])))
        }
        "get_archive_status" | "archive_status" => Some(("synergy_getArchiveStatus", json!([]))),
        "get_audit_report" | "audit_report" => Some(("synergy_getAuditReport", json!([]))),
        "get_divergence_status" | "divergence_status" => {
            Some(("synergy_getDivergenceStatus", json!([])))
        }
        "get_quarantine_status" | "quarantine_status" => {
            Some(("synergy_getQuarantineStatus", json!([])))
        }
        "get_self_heal_status" | "self_heal_status" => {
            Some(("synergy_getSelfHealStatus", json!([])))
        }
        "get_snapshot_catalog" | "snapshot_catalog" => {
            Some(("synergy_getSnapshotCatalog", json!([])))
        }
        "get_shadow_status" | "shadow_status" => Some(("synergy_getShadowStatus", json!([]))),
        "get_rejoin_eligibility" | "rejoin_eligibility" => {
            Some(("synergy_getRejoinEligibility", json!([])))
        }

        // ── Class II — Interoperability ─────────────────────────────────
        "get_sxcp_status" | "sxcp_status" => Some(("synergy_getSxcpStatus", json!([]))),
        "get_relayer_set" | "relayer_set" => Some(("synergy_getRelayerSet", json!([]))),
        "get_relayer_health" | "relayer_health" => Some(("synergy_getRelayerHealth", json!([]))),
        "get_attestations" | "attestations" => Some(("synergy_getAttestations", json!([25_u64]))),
        "get_relay_queue" | "relay_queue" => Some(("synergy_getRelayQueue", json!([]))),
        "get_witness_status" | "witness_status" => Some(("synergy_getWitnessStatus", json!([]))),
        "get_oracle_feeds" | "oracle_feeds" => Some(("synergy_getOracleFeeds", json!([]))),
        "get_oracle_health" | "oracle_health" => Some(("synergy_getOracleHealth", json!([]))),
        "get_uma_routing_table" | "uma_routing_table" => {
            Some(("synergy_getUmaRoutingTable", json!([])))
        }
        "get_uma_resolution_stats" | "uma_resolution_stats" => {
            Some(("synergy_getUmaResolutionStats", json!([])))
        }
        "get_verification_queue" | "verification_queue" => {
            Some(("synergy_getVerificationQueue", json!([])))
        }
        "get_verification_stats" | "verification_stats" => {
            Some(("synergy_getVerificationStats", json!([])))
        }

        // ── Class III — Intelligence & Computation ──────────────────────
        "get_compute_tasks" | "compute_tasks" => Some(("synergy_getComputeTasks", json!([]))),
        "get_compute_metrics" | "compute_metrics" => Some(("synergy_getComputeMetrics", json!([]))),
        "get_inference_status" | "inference_status" => {
            Some(("synergy_getInferenceStatus", json!([])))
        }
        "get_model_registry" | "model_registry" => Some(("synergy_getModelRegistry", json!([]))),
        "get_pqc_status" | "pqc_status" => Some(("synergy_getPqcStatus", json!([]))),
        "get_pqc_key_inventory" | "pqc_key_inventory" => {
            Some(("synergy_getPqcKeyInventory", json!([])))
        }
        "get_da_status" | "da_status" => Some(("synergy_getDaStatus", json!([]))),
        "get_da_storage_stats" | "da_storage_stats" => {
            Some(("synergy_getDaStorageStats", json!([])))
        }
        "get_da_sampling_results" | "da_sampling_results" => {
            Some(("synergy_getDaSamplingResults", json!([])))
        }

        // ── Class IV — Governance & Treasury ────────────────────────────
        "get_governance_proposals" | "governance_proposals" => {
            Some(("synergy_getGovernanceProposals", json!([])))
        }
        "get_governance_audit_log" | "governance_audit_log" => {
            Some(("synergy_getGovernanceAuditLog", json!([])))
        }
        "get_treasury_balance" | "treasury_balance" => {
            Some(("synergy_getTreasuryBalance", json!([])))
        }
        "get_treasury_transactions" | "treasury_transactions" => {
            Some(("synergy_getTreasuryTransactions", json!([])))
        }
        "get_security_alerts" | "security_alerts" => Some(("synergy_getSecurityAlerts", json!([]))),
        "get_slashing_events" | "slashing_events" => Some(("synergy_getSlashingEvents", json!([]))),

        // ── Class V — Service & Support ─────────────────────────────────
        "get_rpc_method_stats" | "rpc_method_stats" => {
            Some(("synergy_getRpcMethodStats", json!([])))
        }
        "get_rate_limit_status" | "rate_limit_status" => {
            Some(("synergy_getRateLimitStatus", json!([])))
        }
        "get_indexer_status" | "indexer_status" => Some(("synergy_getIndexerStatus", json!([]))),
        "get_indexer_stats" | "indexer_stats" => Some(("synergy_getIndexerStats", json!([]))),
        "get_observer_status" | "observer_status" => Some(("synergy_getObserverStatus", json!([]))),

        _ => None,
    }
}

fn normalize_action_key(value: &str) -> String {
    let raw = value.trim();
    if raw.is_empty() {
        return String::new();
    }

    let lowered = raw.to_ascii_lowercase();
    if let Some(rpc_action) = lowered.strip_prefix("rpc:") {
        let normalized = normalize_action_fragment(rpc_action);
        if normalized.is_empty() {
            String::new()
        } else {
            format!("rpc:{normalized}")
        }
    } else {
        normalize_action_fragment(&lowered)
    }
}

fn normalize_action_fragment(value: &str) -> String {
    let mut output = String::new();
    let mut previous_separator = false;

    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            output.push(ch.to_ascii_lowercase());
            previous_separator = false;
        } else if !previous_separator {
            output.push('_');
            previous_separator = true;
        }
    }

    output.trim_matches('_').to_string()
}

fn join_url(base: &str, path: &str) -> String {
    let trimmed_base = base.trim().trim_end_matches('/');
    let trimmed_path = path.trim().trim_start_matches('/');
    if trimmed_path.is_empty() {
        trimmed_base.to_string()
    } else {
        format!("{trimmed_base}/{trimmed_path}")
    }
}

fn extract_latest_transaction_hash(value: Option<&Value>) -> Option<String> {
    let block = value?;
    let transactions = block
        .get("transactions")
        .and_then(|candidate| candidate.as_array())?;

    for transaction in transactions {
        let hash = transaction
            .get("hash")
            .or_else(|| transaction.get("tx_hash"))
            .or_else(|| transaction.get("transaction_hash"))
            .or_else(|| transaction.get("id"))
            .and_then(|candidate| candidate.as_str())
            .map(str::trim)
            .filter(|candidate| !candidate.is_empty());
        if let Some(hash) = hash {
            return Some(hash.to_string());
        }
    }

    None
}

fn humanize_action_label(key: &str) -> String {
    let has_rpc_prefix = key.starts_with("rpc:");
    let raw = key.strip_prefix("rpc:").unwrap_or(key);
    let tokens = raw
        .split('_')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            let Some(first) = chars.next() else {
                return String::new();
            };
            let mut token = String::new();
            token.push(first.to_ascii_uppercase());
            token.push_str(chars.as_str());
            token
        })
        .collect::<Vec<_>>();

    let label = if tokens.is_empty() {
        "Action".to_string()
    } else {
        tokens.join(" ")
    };

    if has_rpc_prefix {
        format!("RPC {label}")
    } else {
        label
    }
}

fn sanitize_filename_fragment(value: &str) -> String {
    let mut output = String::new();
    let mut previous_separator = false;

    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            output.push(ch.to_ascii_lowercase());
            previous_separator = false;
        } else if !previous_separator {
            output.push('_');
            previous_separator = true;
        }
    }

    let output = output.trim_matches('_').to_string();
    if output.is_empty() {
        "node".to_string()
    } else {
        output
    }
}

fn resolve_orchestrator_script_path(inventory_path: &Path) -> Option<String> {
    if let Ok(override_path) = std::env::var("SYNERGY_MONITOR_ORCHESTRATOR") {
        let candidate = PathBuf::from(override_path.trim());
        if candidate.is_file() {
            return Some(candidate.to_string_lossy().to_string());
        }
    }

    let mut candidates = Vec::new();

    if let Some(runtime_dir) = inventory_path.parent() {
        if let Some(testnet_dir) = runtime_dir.parent() {
            if let Some(root_dir) = testnet_dir.parent() {
                candidates.push(root_dir.join("scripts/testnet/remote-node-orchestrator.sh"));
            }
        }
    }

    if let Ok(current_dir) = std::env::current_dir() {
        for ancestor in current_dir.ancestors().take(10) {
            candidates.push(ancestor.join("scripts/testnet/remote-node-orchestrator.sh"));
        }
    }

    if let Ok(executable) = std::env::current_exe() {
        if let Some(exe_dir) = executable.parent() {
            candidates
                .push(exe_dir.join("../Resources/scripts/testnet/remote-node-orchestrator.sh"));
            candidates
                .push(exe_dir.join("../../Resources/scripts/testnet/remote-node-orchestrator.sh"));
            candidates.push(
                exe_dir.join(
                    "../Resources/_up_/_up_/_up_/scripts/testnet/remote-node-orchestrator.sh",
                ),
            );
        }
    }

    candidates
        .into_iter()
        .find(|candidate| candidate.is_file())
        .map(|candidate| candidate.to_string_lossy().to_string())
}

fn resolve_validator_appliance_recovery_script_path(inventory_path: &Path) -> Option<String> {
    if let Ok(override_path) = std::env::var("SYNERGY_VALIDATOR_APPLIANCE_RECOVERY") {
        let candidate = PathBuf::from(override_path.trim());
        if candidate.is_file() {
            return Some(candidate.to_string_lossy().to_string());
        }
    }

    let mut candidates = Vec::new();

    if let Some(runtime_dir) = inventory_path.parent() {
        if let Some(testnet_dir) = runtime_dir.parent() {
            if let Some(root_dir) = testnet_dir.parent() {
                candidates.push(root_dir.join("scripts/testnet/validator-appliance-recovery.sh"));
            }
        }
    }

    if let Ok(current_dir) = std::env::current_dir() {
        for ancestor in current_dir.ancestors().take(10) {
            candidates.push(ancestor.join("scripts/testnet/validator-appliance-recovery.sh"));
        }
    }

    if let Ok(executable) = std::env::current_exe() {
        if let Some(exe_dir) = executable.parent() {
            candidates
                .push(exe_dir.join("../Resources/scripts/testnet/validator-appliance-recovery.sh"));
            candidates.push(
                exe_dir.join("../../Resources/scripts/testnet/validator-appliance-recovery.sh"),
            );
            candidates.push(exe_dir.join(
                "../Resources/_up_/_up_/_up_/scripts/testnet/validator-appliance-recovery.sh",
            ));
        }
    }

    candidates
        .into_iter()
        .find(|candidate| candidate.is_file())
        .map(|candidate| candidate.to_string_lossy().to_string())
}

fn resolve_node_machine_credentials_path() -> PathBuf {
    resolve_process_or_hosts_env_value("SYNERGY_NODE_MACHINE_CREDENTIALS")
        .or_else(|| resolve_process_or_hosts_env_value("SYNERGY_NODE_CREDENTIALS_WORKBOOK"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/Users/devpup/Desktop/node-machine-credentials.xlsx"))
}

fn resolve_validator_recovery_target(
    overrides: &HashMap<String, String>,
    node: &MonitorNode,
) -> String {
    let machine = node.node_slot_id.to_ascii_lowercase().replace('-', "_");
    let alias = node.node_alias.to_ascii_lowercase().replace('-', "_");
    for key in [
        format!("{machine}_validator_recovery_target"),
        format!("{alias}_validator_recovery_target"),
        format!("{machine}_workbook_node"),
        format!("{alias}_workbook_node"),
        format!("{machine}_node_credentials_name"),
        format!("{alias}_node_credentials_name"),
    ] {
        if let Some(value) = overrides
            .get(&key)
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
        {
            return value;
        }
    }
    if !node.node_alias.trim().is_empty() {
        node.node_alias.trim().to_string()
    } else {
        node.node_slot_id.trim().to_string()
    }
}

fn parse_validator_wait_promote_rejoin_height(action: &str) -> Result<u64, String> {
    let prefix = "validator_wait_promote_vote_only";
    let Some(raw_height) = action
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_prefix('_'))
    else {
        return Err(
            "Promote Vote-only requires a rejoin height. Enter the height recorded in the vote-only rejoin proof.".to_string(),
        );
    };
    raw_height.parse::<u64>().map_err(|_| {
        format!(
            "Invalid vote-only rejoin height '{raw_height}'. Enter a numeric finalized height from the rejoin proof."
        )
    })
}

fn build_orchestrator_command(
    script_path: &str,
    hosts_env_path: Option<&str>,
    node_slot_id: &str,
    operation: &str,
) -> String {
    let mut parts = Vec::new();
    if let Some(hosts_env_path) = hosts_env_path {
        parts.push(format!(
            "SYNERGY_MONITOR_HOSTS_ENV={}",
            shell_quote(hosts_env_path)
        ));
    }

    parts.push("bash".to_string());
    parts.push(shell_quote(script_path));
    parts.push(shell_quote(node_slot_id));
    parts.push(shell_quote(operation));
    parts.join(" ")
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

const MONITOR_WORKSPACE_ENV: &str = "SYNERGY_MONITOR_WORKSPACE";
const MONITOR_SECURITY_CONFIG_RELATIVE: &str = "config/security.json";
const MONITOR_AUDIT_LOG_RELATIVE: &str = "audit/control-actions.jsonl";
const MONITOR_USER_MANUAL_RELATIVE: &str = "guides/SYNERGY_TESTNET_CONTROL_PANEL_USER_MANUAL.md";
const MONITOR_WORKSPACE_MANIFEST_RELATIVE: &str = "testnet/runtime/workspace-manifest.json";
const MONITOR_SETUP_WIZARD_VERSION: u32 = 3;
const MONITOR_HOSTS_BACKUP_RETENTION: usize = 5;

#[derive(Debug, Clone, Deserialize)]
struct MonitorWorkspaceManifest {
    workspace_resource_version: String,
    #[serde(default)]
    required_paths: Vec<String>,
}

pub fn ensure_monitor_workspace_with_context(app_context: &AppContext) -> Result<PathBuf, String> {
    let workspace_root = preferred_workspace_root_for_context(app_context);
    fs::create_dir_all(&workspace_root).map_err(|error| {
        format!(
            "Failed to create monitor workspace {}: {error}",
            workspace_root.display()
        )
    })?;

    // Prefer this writable workspace for all monitor runtime state.
    std::env::set_var(
        MONITOR_WORKSPACE_ENV,
        workspace_root.to_string_lossy().to_string(),
    );

    migrate_legacy_workspace_if_needed(app_context, &workspace_root)?;
    extract_bundled_resources_to_workspace(app_context, &workspace_root)?;
    ensure_security_config_exists(&workspace_root)?;
    validate_monitor_workspace_assets(&workspace_root)?;

    let inventory_path = workspace_root.join("testnet/runtime/node-inventory.csv");
    if inventory_path.is_file() {
        std::env::set_var(
            "SYNERGY_MONITOR_INVENTORY",
            inventory_path.to_string_lossy().to_string(),
        );
    }

    Ok(workspace_root)
}

fn preferred_workspace_root() -> PathBuf {
    dirs::home_dir()
        .or_else(dirs::data_dir)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".synergy-node-control-panel")
        .join("monitor-workspace")
}

fn preferred_workspace_root_for_context(app_context: &AppContext) -> PathBuf {
    if let Ok(path) = std::env::var(MONITOR_WORKSPACE_ENV) {
        let candidate = PathBuf::from(path.trim());
        if !candidate.as_os_str().is_empty() {
            return candidate;
        }
    }

    if let Some(app_data_dir) = app_context.app_data_dir() {
        return app_data_dir.join("monitor-workspace");
    }

    preferred_workspace_root()
}

fn legacy_workspace_roots(app_context: &AppContext) -> Vec<PathBuf> {
    let mut roots = Vec::new();

    if let Some(home_dir) = dirs::home_dir().or_else(dirs::data_dir) {
        let legacy_testnet_workspace = format!(".synergy-{}-control-panel", "testnet");
        roots.push(
            home_dir
                .join(legacy_testnet_workspace)
                .join("monitor-workspace"),
        );
        roots.push(
            home_dir
                .join(".synergy-node-monitor")
                .join("monitor-workspace"),
        );
    }

    if let Some(app_data_dir) = app_context.app_data_dir() {
        roots.push(app_data_dir.join("monitor-workspace"));
    }

    roots
}

fn migrate_legacy_workspace_if_needed(
    app_context: &AppContext,
    workspace_root: &Path,
) -> Result<(), String> {
    let target_inventory = workspace_root.join("testnet/runtime/node-inventory.csv");
    if target_inventory.is_file() {
        return Ok(());
    }

    for legacy_root in legacy_workspace_roots(app_context) {
        if legacy_root == workspace_root || !legacy_root.is_dir() {
            continue;
        }

        copy_directory_recursive(&legacy_root, workspace_root)?;
        break;
    }

    Ok(())
}

fn extract_bundled_resources_to_workspace(
    app_context: &AppContext,
    workspace_root: &Path,
) -> Result<(), String> {
    let relative_paths = [
        "testnet/runtime/node-inventory.csv",
        "testnet/runtime/hosts.env.example",
        "testnet/runtime/keys",
        "testnet/runtime/configs",
        "testnet/runtime/installers",
        "testnet/runtime/validator-vpn",
        MONITOR_WORKSPACE_MANIFEST_RELATIVE,
        "binaries",
        "scripts/testnet",
        "scripts/cleanup",
        "scripts/reset-testnet.sh",
        "guides/SYNERGY_TESTNET_CONTROL_PANEL_USER_MANUAL.md",
    ];

    let roots = discover_workspace_source_roots(app_context);
    for relative in relative_paths {
        if let Some(source) = roots
            .iter()
            .map(|root| root.join(relative))
            .find(|candidate| candidate.exists())
        {
            let destination = workspace_root.join(relative);
            copy_path_if_missing_or_directory(&source, &destination)?;
        }
    }

    // Always refresh the user manual so Help content updates for existing installs.
    if let Some(source) = roots
        .iter()
        .map(|root| root.join(MONITOR_USER_MANUAL_RELATIVE))
        .find(|candidate| candidate.exists())
    {
        let destination = workspace_root.join(MONITOR_USER_MANUAL_RELATIVE);
        copy_file_force(&source, &destination)?;
    }

    // Always refresh critical orchestration scripts so existing installs receive runtime fixes.
    let always_refresh = [
        "testnet/runtime/node-inventory.csv",
        "scripts/testnet/remote-node-orchestrator.sh",
        "scripts/testnet/generate-monitor-hosts-env.sh",
        "scripts/testnet/render-configs.sh",
        "scripts/testnet/reset-testnet.sh",
        MONITOR_WORKSPACE_MANIFEST_RELATIVE,
    ];
    for relative in always_refresh {
        if let Some(source) = roots
            .iter()
            .map(|root| root.join(relative))
            .find(|candidate| candidate.exists())
        {
            let destination = workspace_root.join(relative);
            copy_file_force(&source, &destination)?;
        }
    }

    let always_refresh_dirs = [
        "testnet/runtime/configs",
        "testnet/runtime/keys",
        "testnet/runtime/validator-vpn",
        "binaries",
        "scripts/cleanup",
    ];
    for relative in always_refresh_dirs {
        if let Some(source) = roots
            .iter()
            .map(|root| root.join(relative))
            .find(|candidate| candidate.is_dir())
        {
            let destination = workspace_root.join(relative);
            copy_directory_force(&source, &destination)?;
        }
    }

    // Always refresh installer bundle assets so existing workspaces receive corrected
    // machine metadata even when a full installer regeneration is skipped.
    if let Some(source_installers) = roots
        .iter()
        .map(|root| root.join("testnet/runtime/installers"))
        .find(|candidate| candidate.is_dir())
    {
        let destination_installers = workspace_root.join("testnet/runtime/installers");
        refresh_installer_bundle_assets(&source_installers, &destination_installers)?;
    }

    let inventory_path = workspace_root.join("testnet/runtime/node-inventory.csv");
    if !inventory_path.is_file() {
        return Err(format!(
            "Workspace initialization failed: {} not found after extraction",
            inventory_path.display()
        ));
    }

    let hosts_env = workspace_root.join("testnet/runtime/hosts.env");
    if !hosts_env.is_file() {
        if let Err(generate_error) =
            generate_monitor_hosts_env(workspace_root, &inventory_path, &hosts_env)
        {
            let example = workspace_root.join("testnet/runtime/hosts.env.example");
            if example.is_file() {
                if let Some(parent) = hosts_env.parent() {
                    fs::create_dir_all(parent).map_err(|error| {
                        format!(
                            "Failed to create hosts.env parent directory {}: {error}",
                            parent.display()
                        )
                    })?;
                }
                fs::copy(&example, &hosts_env).map_err(|error| {
                    format!(
                        "Failed to copy {} to {} after hosts.env generation failed ({}): {error}",
                        example.display(),
                        hosts_env.display(),
                        generate_error
                    )
                })?;
            } else {
                return Err(generate_error);
            }
        }
    }

    validate_monitor_workspace_assets(workspace_root)?;
    Ok(())
}

fn validate_monitor_workspace_assets(workspace_root: &Path) -> Result<(), String> {
    let manifest_path = workspace_root.join(MONITOR_WORKSPACE_MANIFEST_RELATIVE);
    let manifest = load_workspace_manifest(&manifest_path)?;

    for relative in &manifest.required_paths {
        let path = workspace_root.join(relative);
        if !path.exists() {
            return Err(format!(
                "Workspace is missing required bundled asset {} (resource version {}). Reinstall or refresh the control panel bundle.",
                path.display(),
                manifest.workspace_resource_version
            ));
        }
    }

    let required_files = [
        "testnet/runtime/node-inventory.csv",
        "testnet/runtime/hosts.env.example",
        "guides/SYNERGY_TESTNET_CONTROL_PANEL_USER_MANUAL.md",
    ];
    for relative in required_files {
        let path = workspace_root.join(relative);
        if !path.is_file() {
            return Err(format!("Workspace file is missing: {}", path.display()));
        }
    }

    let required_dirs = [
        "testnet/runtime/configs",
        "testnet/runtime/installers",
        "binaries",
    ];
    for relative in required_dirs {
        let path = workspace_root.join(relative);
        if !path.is_dir() {
            return Err(format!(
                "Workspace directory is missing: {}",
                path.display()
            ));
        }
    }

    Ok(())
}

fn load_workspace_manifest(path: &Path) -> Result<MonitorWorkspaceManifest, String> {
    let raw = fs::read_to_string(path).map_err(|error| {
        format!(
            "Failed to read workspace manifest {}: {error}",
            path.display()
        )
    })?;
    serde_json::from_str(&raw).map_err(|error| {
        format!(
            "Failed to parse workspace manifest {}: {error}",
            path.display()
        )
    })
}

fn discover_workspace_source_roots(app_context: &AppContext) -> Vec<PathBuf> {
    dedupe_paths(app_context.resource_roots().to_vec())
}

fn dedupe_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut output = Vec::new();
    for path in paths {
        if output.iter().any(|existing: &PathBuf| existing == &path) {
            continue;
        }
        output.push(path);
    }
    output
}

fn copy_path_if_missing_or_directory(source: &Path, destination: &Path) -> Result<(), String> {
    if source.is_dir() {
        copy_directory_recursive(source, destination)?;
        return Ok(());
    }

    if destination.is_file() {
        return Ok(());
    }

    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "Failed to create destination parent directory {}: {error}",
                parent.display()
            )
        })?;
    }

    fs::copy(source, destination).map_err(|error| {
        format!(
            "Failed to copy {} to {}: {error}",
            source.display(),
            destination.display()
        )
    })?;
    sync_unix_permissions_from_source(source, destination).map_err(|error| {
        format!(
            "Failed to preserve permissions on {}: {error}",
            destination.display()
        )
    })?;
    Ok(())
}

fn copy_file_force(source: &Path, destination: &Path) -> Result<(), String> {
    if !source.is_file() {
        return Err(format!(
            "Expected file source but found non-file path: {}",
            source.display()
        ));
    }

    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "Failed to create destination parent directory {}: {error}",
                parent.display()
            )
        })?;
    }

    copy_file_atomic(source, destination).map_err(|error| {
        format!(
            "Failed to copy {} to {}: {error}",
            source.display(),
            destination.display()
        )
    })?;
    Ok(())
}

// Replace files via temp+rename so active node executables can be refreshed
// without opening the destination path for writing first.
fn copy_file_atomic(source: &Path, destination: &Path) -> Result<(), io::Error> {
    let destination_name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("copy-target");
    let temp_name = format!(
        ".{}.tmp-{}-{}",
        destination_name,
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or_default()
    );
    let temp_path = destination.with_file_name(temp_name);

    let copy_result = (|| -> Result<(), io::Error> {
        fs::copy(source, &temp_path)?;
        match fs::rename(&temp_path, destination) {
            Ok(()) => Ok(()),
            Err(rename_error) => {
                #[cfg(target_os = "windows")]
                {
                    if destination.exists() {
                        let _ = fs::remove_file(destination);
                        if let Ok(()) = fs::rename(&temp_path, destination) {
                            return Ok(());
                        }
                    }
                }
                Err(rename_error)
            }
        }
    })();

    if copy_result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }

    copy_result?;
    sync_unix_permissions_from_source(source, destination)?;
    Ok(())
}

fn copy_directory_recursive(source: &Path, destination: &Path) -> Result<(), String> {
    fs::create_dir_all(destination).map_err(|error| {
        format!(
            "Failed to create directory {}: {error}",
            destination.display()
        )
    })?;

    let entries = fs::read_dir(source)
        .map_err(|error| format!("Failed to read directory {}: {error}", source.display()))?;

    for entry in entries {
        let entry = entry.map_err(|error| {
            format!(
                "Failed to read directory entry in {}: {error}",
                source.display()
            )
        })?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if source_path.is_dir() {
            copy_directory_recursive(&source_path, &destination_path)?;
        } else if !destination_path.exists() {
            if let Some(parent) = destination_path.parent() {
                fs::create_dir_all(parent).map_err(|error| {
                    format!("Failed to create directory {}: {error}", parent.display())
                })?;
            }
            fs::copy(&source_path, &destination_path).map_err(|error| {
                format!(
                    "Failed to copy {} to {}: {error}",
                    source_path.display(),
                    destination_path.display()
                )
            })?;
            sync_unix_permissions_from_source(&source_path, &destination_path).map_err(
                |error| {
                    format!(
                        "Failed to preserve permissions on {}: {error}",
                        destination_path.display()
                    )
                },
            )?;
        }
    }

    Ok(())
}

fn copy_directory_force(source: &Path, destination: &Path) -> Result<(), String> {
    fs::create_dir_all(destination).map_err(|error| {
        format!(
            "Failed to create directory {}: {error}",
            destination.display()
        )
    })?;

    let entries = fs::read_dir(source)
        .map_err(|error| format!("Failed to read directory {}: {error}", source.display()))?;

    for entry in entries {
        let entry = entry.map_err(|error| {
            format!(
                "Failed to read directory entry in {}: {error}",
                source.display()
            )
        })?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if source_path.is_dir() {
            copy_directory_force(&source_path, &destination_path)?;
        } else {
            if let Some(parent) = destination_path.parent() {
                fs::create_dir_all(parent).map_err(|error| {
                    format!("Failed to create directory {}: {error}", parent.display())
                })?;
            }
            copy_file_atomic(&source_path, &destination_path).map_err(|error| {
                format!(
                    "Failed to copy {} to {}: {error}",
                    source_path.display(),
                    destination_path.display()
                )
            })?;
        }
    }

    Ok(())
}

fn sync_unix_permissions_from_source(source: &Path, destination: &Path) -> Result<(), io::Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = fs::metadata(source)?.permissions().mode();
        fs::set_permissions(destination, fs::Permissions::from_mode(mode))?;
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn staged_binary_path(destination: &Path) -> PathBuf {
    let file_name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("binary");
    destination.with_file_name(format!("{file_name}.pending"))
}

fn try_stage_locked_windows_binary(source: &Path, destination: &Path, error: &io::Error) -> bool {
    #[cfg(target_os = "windows")]
    {
        let is_windows_executable = destination
            .extension()
            .and_then(|entry| entry.to_str())
            .map(|entry| entry.eq_ignore_ascii_case("exe"))
            .unwrap_or(false);
        if is_windows_executable
            && destination.exists()
            && error.kind() == io::ErrorKind::PermissionDenied
        {
            let staged_path = staged_binary_path(destination);
            if copy_file_atomic(source, &staged_path).is_ok() {
                return true;
            }
        }
    }

    let _ = source;
    let _ = destination;
    let _ = error;
    false
}

fn copy_file_force_or_stage_locked_binary(source: &Path, destination: &Path) -> Result<(), String> {
    if !source.is_file() {
        return Err(format!(
            "Expected file source but found non-file path: {}",
            source.display()
        ));
    }

    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "Failed to create destination parent directory {}: {error}",
                parent.display()
            )
        })?;
    }

    match copy_file_atomic(source, destination) {
        Ok(()) => Ok(()),
        Err(error) if try_stage_locked_windows_binary(source, destination, &error) => Ok(()),
        Err(error) => Err(format!(
            "Failed to copy {} to {}: {error}",
            source.display(),
            destination.display()
        )),
    }
}

fn refresh_installer_bin_directory(source: &Path, destination: &Path) -> Result<(), String> {
    fs::create_dir_all(destination).map_err(|error| {
        format!(
            "Failed to create directory {}: {error}",
            destination.display()
        )
    })?;

    let entries = fs::read_dir(source)
        .map_err(|error| format!("Failed to read directory {}: {error}", source.display()))?;

    for entry in entries {
        let entry = entry.map_err(|error| {
            format!(
                "Failed to read directory entry in {}: {error}",
                source.display()
            )
        })?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if source_path.is_dir() {
            copy_directory_force(&source_path, &destination_path)?;
        } else {
            copy_file_force_or_stage_locked_binary(&source_path, &destination_path)?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&destination_path, fs::Permissions::from_mode(0o755));
            }
        }
    }

    Ok(())
}

fn refresh_installer_bundle_assets(
    source_installers: &Path,
    destination_installers: &Path,
) -> Result<(), String> {
    fs::create_dir_all(destination_installers).map_err(|error| {
        format!(
            "Failed to create installers directory {}: {error}",
            destination_installers.display()
        )
    })?;

    let entries = fs::read_dir(source_installers).map_err(|error| {
        format!(
            "Failed to read installers directory {}: {error}",
            source_installers.display()
        )
    })?;

    let file_names = [
        "install_and_start.sh",
        "nodectl.sh",
        "install_and_start.ps1",
        "nodectl.ps1",
        "node.env",
        "README.txt",
        "COMMANDS.txt",
        "BINARY_STATUS.txt",
    ];
    let directory_names = ["config", "keys", "bin"];

    for entry in entries {
        let entry = entry.map_err(|error| {
            format!(
                "Failed to read installer entry in {}: {error}",
                source_installers.display()
            )
        })?;
        let source_machine_dir = entry.path();
        if !source_machine_dir.is_dir() {
            continue;
        }

        let destination_machine_dir = destination_installers.join(entry.file_name());
        fs::create_dir_all(&destination_machine_dir).map_err(|error| {
            format!(
                "Failed to create destination installer directory {}: {error}",
                destination_machine_dir.display()
            )
        })?;

        for file_name in file_names {
            let source_file = source_machine_dir.join(file_name);
            if !source_file.is_file() {
                continue;
            }

            let destination_file = destination_machine_dir.join(file_name);
            copy_file_force(&source_file, &destination_file)?;

            #[cfg(unix)]
            if file_name.ends_with(".sh") {
                use std::os::unix::fs::PermissionsExt;
                let mut permissions = fs::metadata(&destination_file)
                    .map_err(|error| {
                        format!(
                            "Failed to read script metadata {}: {error}",
                            destination_file.display()
                        )
                    })?
                    .permissions();
                permissions.set_mode(0o755);
                fs::set_permissions(&destination_file, permissions).map_err(|error| {
                    format!(
                        "Failed to set script permissions {}: {error}",
                        destination_file.display()
                    )
                })?;
            }
        }

        for dir_name in directory_names {
            let source_dir = source_machine_dir.join(dir_name);
            if !source_dir.is_dir() {
                continue;
            }
            let destination_dir = destination_machine_dir.join(dir_name);
            if dir_name == "bin" {
                refresh_installer_bin_directory(&source_dir, &destination_dir)?;
            } else {
                copy_directory_force(&source_dir, &destination_dir)?;
            }
        }
    }

    Ok(())
}

fn resolve_monitor_workspace_path() -> Result<PathBuf, String> {
    if let Ok(path) = std::env::var(MONITOR_WORKSPACE_ENV) {
        let candidate = PathBuf::from(path.trim());
        if !candidate.as_os_str().is_empty() {
            fs::create_dir_all(&candidate).map_err(|error| {
                format!(
                    "Failed to create monitor workspace directory {}: {error}",
                    candidate.display()
                )
            })?;
            return Ok(candidate);
        }
    }

    let default = preferred_workspace_root();
    fs::create_dir_all(&default).map_err(|error| {
        format!(
            "Failed to create default monitor workspace {}: {error}",
            default.display()
        )
    })?;
    std::env::set_var(MONITOR_WORKSPACE_ENV, default.to_string_lossy().to_string());
    Ok(default)
}

fn is_obsolete_overlay_host(value: &str) -> bool {
    let Ok(ip) = value.trim().parse::<Ipv4Addr>() else {
        return false;
    };
    let octets = ip.octets();
    octets[0] == 10 && octets[1] == 50 && octets[2] == 0
}

fn preferred_public_inventory_host(
    host: &str,
    management_host: &str,
    public_ip: &str,
    local_ip: &str,
    physical_machine_id: &str,
) -> String {
    for candidate in [host, local_ip, management_host, public_ip] {
        let trimmed = candidate.trim();
        if !trimmed.is_empty() && !is_obsolete_overlay_host(trimmed) {
            return trimmed.to_string();
        }
    }

    let fallback = physical_machine_id.trim();
    if !fallback.is_empty() {
        return fallback.to_string();
    }

    String::new()
}

fn preferred_management_host(
    host: &str,
    management_host: &str,
    public_ip: &str,
    local_ip: &str,
    physical_machine_id: &str,
) -> String {
    for candidate in [management_host, local_ip, public_ip, host] {
        let trimmed = candidate.trim();
        if !trimmed.is_empty() && !is_obsolete_overlay_host(trimmed) {
            return trimmed.to_string();
        }
    }

    let fallback = physical_machine_id.trim();
    if !fallback.is_empty() {
        return fallback.to_string();
    }

    String::new()
}

fn sanitize_inventory_hosts(inventory_path: &Path) -> Result<(), String> {
    let content = fs::read_to_string(inventory_path).map_err(|error| {
        format!(
            "Failed to read node inventory {}: {error}",
            inventory_path.display()
        )
    })?;
    let mut lines = content.lines();
    let header_line = lines
        .next()
        .ok_or_else(|| format!("Inventory file is empty: {}", inventory_path.display()))?;
    let headers = header_line
        .split(',')
        .map(|value| value.trim().to_string())
        .collect::<Vec<_>>();

    let resolve_index = |name: &str| -> Result<usize, String> {
        headers
            .iter()
            .position(|value| value.eq_ignore_ascii_case(name))
            .ok_or_else(|| format!("Column '{name}' missing in {}", inventory_path.display()))
    };

    let physical_machine_idx = resolve_index("physical_machine_id")?;
    let host_idx = resolve_index("host")?;
    let management_host_idx = resolve_index("management_host")?;
    let public_ip_idx = resolve_index("public_ip")?;
    let local_ip_idx = resolve_index("local_ip")?;

    let mut rewritten = Vec::new();
    rewritten.push(header_line.to_string());

    for row in lines {
        if row.trim().is_empty() {
            continue;
        }
        let mut values = row
            .split(',')
            .map(|value| value.trim().trim_end_matches('\r').to_string())
            .collect::<Vec<_>>();
        let get = |index: usize| values.get(index).cloned().unwrap_or_default();
        let resolved_host = preferred_public_inventory_host(
            &get(host_idx),
            &get(management_host_idx),
            &get(public_ip_idx),
            &get(local_ip_idx),
            &get(physical_machine_idx),
        );
        let resolved_management_host = preferred_management_host(
            &get(host_idx),
            &get(management_host_idx),
            &get(public_ip_idx),
            &get(local_ip_idx),
            &get(physical_machine_idx),
        );
        if !resolved_host.is_empty() {
            if host_idx < values.len() {
                values[host_idx] = resolved_host.clone();
            }
        }
        if !resolved_management_host.is_empty() && management_host_idx < values.len() {
            values[management_host_idx] = resolved_management_host;
        }
        rewritten.push(values.join(","));
    }

    let mut encoded = rewritten.join("\n");
    if !encoded.ends_with('\n') {
        encoded.push('\n');
    }
    fs::write(inventory_path, encoded).map_err(|error| {
        format!(
            "Failed to write node inventory {}: {error}",
            inventory_path.display()
        )
    })?;
    Ok(())
}

#[derive(Debug)]
struct MonitorHostsEnvEntry {
    node_slot_id: String,
    node_alias: String,
    role_group: String,
    role: String,
    node_type: String,
    host: String,
    management_host: String,
    public_ip: String,
    local_ip: String,
}

fn preferred_control_plane_host(
    host: &str,
    management_host: &str,
    public_ip: &str,
    local_ip: &str,
) -> String {
    preferred_management_host(host, management_host, public_ip, local_ip, "")
}

fn generate_monitor_hosts_env(
    workspace_root: &Path,
    inventory_path: &Path,
    output_path: &Path,
) -> Result<(), String> {
    let entries = load_monitor_hosts_env_entries(inventory_path)?;
    let orchestrator_script = workspace_root
        .join("scripts/testnet/remote-node-orchestrator.sh")
        .to_string_lossy()
        .replace('\\', "/");
    let orchestrator_script = shell_quote(&orchestrator_script);

    let mut lines = vec![
        format!(
            "# Auto-generated by Synergy Node Control Panel on {}",
            Utc::now().format("%Y-%m-%dT%H:%M:%SZ")
        ),
        "# This file powers the Synergy Node Control Panel app remote orchestration workflow."
            .to_string(),
        "#".to_string(),
        "# Global SSH defaults used by remote-node-orchestrator.sh:".to_string(),
        "SYNERGY_TESTNET_SSH_USER=ops".to_string(),
        "SYNERGY_TESTNET_SSH_PORT=22".to_string(),
        "# Optional global SSH private key path:".to_string(),
        "# SYNERGY_TESTNET_SSH_KEY=/Users/you/.ssh/id_ed25519".to_string(),
        String::new(),
        "# Explorer bridge used by control panel Atlas links:".to_string(),
        "ATLAS_BASE_URL=https://testnet-explorer.synergy-network.io".to_string(),
        "SYNERGY_EXPLORER_RESET_ENDPOINT=https://testnet-atlas-api.synergy-network.io/v1/admin/reindex-from-genesis".to_string(),
        String::new(),
    ];

    let operations = [
        ("START_CMD", "start"),
        ("STOP_CMD", "stop"),
        ("RESTART_CMD", "restart"),
        ("STATUS_CMD", "status"),
        ("SETUP_CMD", "setup_node"),
        ("EXPORT_LOGS_CMD", "export_logs"),
        ("VIEW_CHAIN_DATA_CMD", "view_chain_data"),
        ("EXPORT_CHAIN_DATA_CMD", "export_chain_data"),
        ("ACTION_INSTALL_NODE_CMD", "install_node"),
        ("ACTION_BOOTSTRAP_NODE_CMD", "bootstrap_node"),
        ("ACTION_NODE_LOGS_CMD", "logs"),
        ("ACTION_RESET_CHAIN_CMD", "reset_chain"),
    ];

    for entry in entries {
        let node_slot_key = entry.node_slot_id.to_ascii_uppercase().replace('-', "_");
        let control_plane_host = preferred_control_plane_host(
            &entry.host,
            &entry.management_host,
            &entry.public_ip,
            &entry.local_ip,
        );

        lines.push(
            "# -----------------------------------------------------------------------------"
                .to_string(),
        );
        lines.push(format!(
            "# {} ({} | {} | {} | {})",
            entry.node_slot_id, entry.node_alias, entry.role_group, entry.role, entry.node_type
        ));
        lines.push(format!("{node_slot_key}_HOST={control_plane_host}"));
        lines.push(format!(
            "{node_slot_key}_MANAGEMENT_HOST={}",
            entry.management_host
        ));
        lines.push(format!("{node_slot_key}_SSH_USER=ops"));
        lines.push(format!("{node_slot_key}_SSH_PORT=22"));
        lines.push(format!("# {node_slot_key}_SSH_KEY="));
        lines.push(format!(
            "# {node_slot_key}_REMOTE_DIR=/opt/synergy/{}",
            entry.node_slot_id
        ));
        lines.push(String::new());

        for &(env_key, operation) in &operations {
            let command = format!("{orchestrator_script} {} {}", entry.node_slot_id, operation);
            lines.push(format!(r#"{node_slot_key}_{env_key}="{command}""#));
        }
        lines.push(String::new());
    }

    let mut encoded = lines.join("\n");
    if !encoded.ends_with('\n') {
        encoded.push('\n');
    }

    write_file_with_backup_if_changed(output_path, &encoded)
}

fn load_monitor_hosts_env_entries(
    inventory_path: &Path,
) -> Result<Vec<MonitorHostsEnvEntry>, String> {
    let content = fs::read_to_string(inventory_path).map_err(|error| {
        format!(
            "Failed to read node inventory {}: {error}",
            inventory_path.display()
        )
    })?;
    let mut lines = content.lines();
    let header_line = lines
        .next()
        .ok_or_else(|| format!("Inventory file is empty: {}", inventory_path.display()))?;
    let headers = header_line
        .split(',')
        .map(|value| value.trim().to_string())
        .collect::<Vec<_>>();

    let resolve_index = |name: &str| -> Result<usize, String> {
        headers
            .iter()
            .position(|value| value.eq_ignore_ascii_case(name))
            .ok_or_else(|| format!("Column '{name}' missing in {}", inventory_path.display()))
    };

    let slot_idx = resolve_index("node_slot_id")?;
    let alias_idx = resolve_index("node_alias")?;
    let role_group_idx = resolve_index("role_group")?;
    let role_idx = resolve_index("role")?;
    let node_type_idx = resolve_index("node_type")?;
    let host_idx = resolve_index("host")?;
    let management_host_idx = resolve_index("management_host")?;
    let public_ip_idx = resolve_index("public_ip")?;
    let local_ip_idx = resolve_index("local_ip")?;

    let mut entries = Vec::new();
    for row in lines {
        if row.trim().is_empty() {
            continue;
        }

        let values = row
            .split(',')
            .map(|value| value.trim().trim_end_matches('\r').to_string())
            .collect::<Vec<_>>();
        let read = |index: usize| values.get(index).cloned().unwrap_or_default();
        let node_slot_id = read(slot_idx);
        if node_slot_id.is_empty() {
            continue;
        }

        entries.push(MonitorHostsEnvEntry {
            node_slot_id,
            node_alias: read(alias_idx),
            role_group: read(role_group_idx),
            role: read(role_idx),
            node_type: read(node_type_idx),
            host: read(host_idx),
            management_host: read(management_host_idx),
            public_ip: read(public_ip_idx),
            local_ip: read(local_ip_idx),
        });
    }

    Ok(entries)
}

fn write_file_with_backup_if_changed(path: &Path, content: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "Failed to create parent directory {}: {error}",
                parent.display()
            )
        })?;
    }

    let existing = if path.is_file() {
        Some(
            fs::read_to_string(path)
                .map_err(|error| format!("Failed to read {}: {error}", path.display()))?,
        )
    } else {
        None
    };

    if existing.as_deref() == Some(content) {
        return Ok(());
    }

    if path.is_file() {
        let backup = PathBuf::from(format!(
            "{}.bak.{}",
            path.to_string_lossy(),
            Utc::now().format("%Y%m%dT%H%M%SZ")
        ));
        fs::copy(path, &backup).map_err(|error| {
            format!(
                "Failed to back up {} to {}: {error}",
                path.display(),
                backup.display()
            )
        })?;
        prune_backup_files(path, MONITOR_HOSTS_BACKUP_RETENTION)?;
    }

    fs::write(path, content)
        .map_err(|error| format!("Failed to write {}: {error}", path.display()))?;
    Ok(())
}

fn prune_backup_files(path: &Path, retention: usize) -> Result<(), String> {
    if retention == 0 {
        return Ok(());
    }

    let Some(parent) = path.parent() else {
        return Ok(());
    };
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return Ok(());
    };
    let prefix = format!("{file_name}.bak.");

    let mut backups = fs::read_dir(parent)
        .map_err(|error| {
            format!(
                "Failed to read backup directory {}: {error}",
                parent.display()
            )
        })?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let entry_path = entry.path();
            let entry_name = entry.file_name();
            let entry_name = entry_name.to_string_lossy();
            if entry_name.starts_with(&prefix) {
                Some(entry_path)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    backups.sort();

    if backups.len() <= retention {
        return Ok(());
    }

    let remove_count = backups.len() - retention;
    for backup in backups.into_iter().take(remove_count) {
        fs::remove_file(&backup).map_err(|error| {
            format!("Failed to remove old backup {}: {error}", backup.display())
        })?;
    }

    Ok(())
}

fn apply_topology_to_installer_node_env(path: &Path, management_host: &str) -> Result<(), String> {
    if !path.is_file() {
        return Ok(());
    }
    let content = fs::read_to_string(path)
        .map_err(|error| format!("Failed to read installer env {}: {error}", path.display()))?;
    let mut lines = content
        .lines()
        .map(|line| line.to_string())
        .collect::<Vec<_>>();

    let mut rpc_port: Option<String> = None;
    for line in &lines {
        let trimmed = line.trim();
        if trimmed.starts_with("RPC_PORT=") {
            rpc_port = trimmed
                .split_once('=')
                .map(|(_, value)| value.trim().to_string());
        }
    }
    let rpc_bind = format!(
        "{management_host}:{}",
        rpc_port.clone().unwrap_or_else(|| "5640".to_string())
    );

    upsert_key_value_line(&mut lines, "MONITOR_HOST", management_host);
    upsert_key_value_line(&mut lines, "MANAGEMENT_HOST", management_host);
    upsert_key_value_line(&mut lines, "CHAIN_ID", "1266");
    upsert_key_value_line(&mut lines, "NETWORK_ID", "synergy-testnet");
    upsert_key_value_line(&mut lines, "SYNERGY_CHAIN_ID", "1266");
    upsert_key_value_line(&mut lines, "SYNERGY_NETWORK_ID", "synergy-testnet");
    upsert_key_value_line(&mut lines, "SYNERGY_CONFIG_PATH", "config/node.toml");
    upsert_key_value_line(&mut lines, "RPC_BIND_ADDRESS", &rpc_bind);
    upsert_key_value_line(&mut lines, "SYNERGY_RPC_BIND_ADDRESS", &rpc_bind);

    let mut encoded = lines.join("\n");
    if !encoded.ends_with('\n') {
        encoded.push('\n');
    }
    fs::write(path, encoded)
        .map_err(|error| format!("Failed to write installer env {}: {error}", path.display()))?;
    Ok(())
}

fn apply_topology_to_installer_node_toml(path: &Path, management_host: &str) -> Result<(), String> {
    if !path.is_file() {
        return Ok(());
    }
    let content = fs::read_to_string(path).map_err(|error| {
        format!(
            "Failed to read installer config {}: {error}",
            path.display()
        )
    })?;
    let mut lines = content
        .lines()
        .map(|line| line.to_string())
        .collect::<Vec<_>>();

    let mut rpc_port = "5640".to_string();
    for line in &lines {
        let trimmed = line.trim();
        if trimmed.starts_with("rpc_port =") {
            if let Some((_, value)) = trimmed.split_once('=') {
                rpc_port = value.trim().trim_matches('"').to_string();
            }
        }
    }

    replace_or_append_line(
        &mut lines,
        "bind_address =",
        format!("bind_address = \"{management_host}:{rpc_port}\""),
    );

    let mut encoded = lines.join("\n");
    if !encoded.ends_with('\n') {
        encoded.push('\n');
    }
    fs::write(path, encoded).map_err(|error| {
        format!(
            "Failed to write installer config {}: {error}",
            path.display()
        )
    })?;
    Ok(())
}

fn upsert_key_value_line(lines: &mut Vec<String>, key: &str, value: &str) {
    let prefix = format!("{key}=");
    if let Some(index) = lines
        .iter()
        .position(|line| line.trim_start().starts_with(&prefix))
    {
        lines[index] = format!("{key}={value}");
    } else {
        lines.push(format!("{key}={value}"));
    }
}

fn replace_or_append_line(lines: &mut Vec<String>, line_prefix: &str, replacement: String) {
    if let Some(index) = lines
        .iter()
        .position(|line| line.trim_start().starts_with(line_prefix))
    {
        lines[index] = replacement;
    } else {
        lines.push(replacement);
    }
}

fn security_config_path() -> Result<PathBuf, String> {
    let workspace = resolve_monitor_workspace_path()?;
    Ok(workspace.join(MONITOR_SECURITY_CONFIG_RELATIVE))
}

fn ensure_security_config_exists(workspace: &Path) -> Result<(), String> {
    let path = workspace.join(MONITOR_SECURITY_CONFIG_RELATIVE);
    if path.is_file() {
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "Failed to create security config directory {}: {error}",
                parent.display()
            )
        })?;
    }

    let now = Utc::now().to_rfc3339();
    let default_config = MonitorSecurityConfig {
        version: 1,
        active_operator_id: "local_admin".to_string(),
        operators: vec![MonitorOperatorProfile {
            operator_id: "local_admin".to_string(),
            display_name: "Local Admin".to_string(),
            role: "admin".to_string(),
            enabled: true,
            created_at_utc: now.clone(),
            updated_at_utc: now,
        }],
        ssh_profiles: Vec::new(),
        ssh_bindings: Vec::new(),
        setup: MonitorSetupState::default(),
    };

    let encoded = serde_json::to_vec_pretty(&default_config)
        .map_err(|error| format!("Failed to serialize default security config: {error}"))?;
    fs::write(&path, encoded).map_err(|error| {
        format!(
            "Failed to write security config {}: {error}",
            path.display()
        )
    })?;
    Ok(())
}

fn is_legacy_local_installers_path(value: &str) -> bool {
    value.contains("/testnet/runtime/installers")
        || value.contains("\\testnet\\runtime\\installers")
}

fn normalize_remote_root_opt(value: &Option<String>) -> Option<String> {
    let trimmed = value
        .as_ref()
        .map(|entry| entry.trim())
        .filter(|entry| !entry.is_empty())
        .map(|entry| entry.to_string());
    let Some(raw) = trimmed else {
        return None;
    };
    if is_legacy_local_installers_path(&raw) {
        Some("/opt/synergy".to_string())
    } else {
        Some(raw)
    }
}

fn normalize_remote_dir_override(node_slot_id: &str, value: &Option<String>) -> Option<String> {
    let trimmed = value
        .as_ref()
        .map(|entry| entry.trim())
        .filter(|entry| !entry.is_empty())
        .map(|entry| entry.to_string());
    let Some(raw) = trimmed else {
        return None;
    };
    if is_legacy_local_installers_path(&raw) {
        Some(format!("/opt/synergy/{}", node_slot_id.trim()))
    } else {
        Some(raw)
    }
}

fn normalize_host_override_opt(value: &Option<String>) -> Option<String> {
    value
        .as_ref()
        .map(|entry| entry.trim())
        .filter(|entry| !entry.is_empty())
        .map(|entry| entry.to_string())
}

fn validate_host_override_for_binding(
    binding_target: &str,
    host_override: &Option<String>,
) -> Result<Option<String>, String> {
    let normalized = normalize_host_override_opt(host_override);
    let Some(value) = normalized.as_ref() else {
        return Ok(None);
    };

    let Some(physical_machine_id) = physical_machine_for_binding_target(binding_target) else {
        return Ok(normalized);
    };
    let Some(expected_management_host) =
        canonical_management_host_for_physical_machine(&physical_machine_id)
    else {
        return Ok(normalized);
    };

    if is_private_management_ip(value)
        && !value.eq_ignore_ascii_case(expected_management_host.as_str())
    {
        return Err(format!(
            "Invalid host override for {binding_target}: got {value}, expected {expected_management_host}."
        ));
    }

    Ok(normalized)
}

fn migrate_host_override_for_binding(
    binding_target: &str,
    host_override: &Option<String>,
) -> Option<String> {
    let normalized = normalize_host_override_opt(host_override);
    let Some(value) = normalized.as_ref() else {
        return None;
    };

    let Some(physical_machine_id) = physical_machine_for_binding_target(binding_target) else {
        return normalized;
    };
    let Some(expected_management_host) =
        canonical_management_host_for_physical_machine(&physical_machine_id)
    else {
        return normalized;
    };

    if is_private_management_ip(value)
        && !value.eq_ignore_ascii_case(expected_management_host.as_str())
    {
        return Some(expected_management_host);
    }

    normalized
}

fn load_security_config() -> Result<MonitorSecurityConfig, String> {
    let path = security_config_path()?;
    if !path.is_file() {
        let workspace = resolve_monitor_workspace_path()?;
        ensure_security_config_exists(&workspace)?;
    }

    let content = fs::read_to_string(&path)
        .map_err(|error| format!("Failed to read security config {}: {error}", path.display()))?;
    let mut config: MonitorSecurityConfig = serde_json::from_str(&content).map_err(|error| {
        format!(
            "Failed to parse security config {}: {error}",
            path.display()
        )
    })?;

    let mut migrated = false;
    for profile in config.ssh_profiles.iter_mut() {
        let normalized = normalize_remote_root_opt(&profile.remote_root);
        if normalized != profile.remote_root {
            profile.remote_root = normalized;
            profile.updated_at_utc = Utc::now().to_rfc3339();
            migrated = true;
        }
    }

    for binding in config.ssh_bindings.iter_mut() {
        let normalized_host_override =
            migrate_host_override_for_binding(&binding.node_slot_id, &binding.host_override);
        if normalized_host_override != binding.host_override {
            binding.host_override = normalized_host_override;
            binding.updated_at_utc = Utc::now().to_rfc3339();
            migrated = true;
        }
        let normalized =
            normalize_remote_dir_override(&binding.node_slot_id, &binding.remote_dir_override);
        if normalized != binding.remote_dir_override {
            binding.remote_dir_override = normalized;
            binding.updated_at_utc = Utc::now().to_rfc3339();
            migrated = true;
        }
    }

    if config.operators.is_empty() {
        let now = Utc::now().to_rfc3339();
        config.operators.push(MonitorOperatorProfile {
            operator_id: "local_admin".to_string(),
            display_name: "Local Admin".to_string(),
            role: "admin".to_string(),
            enabled: true,
            created_at_utc: now.clone(),
            updated_at_utc: now,
        });
        config.active_operator_id = "local_admin".to_string();
        migrated = true;
    }

    if migrated {
        save_security_config(&config)?;
    }

    Ok(config)
}

fn save_security_config(config: &MonitorSecurityConfig) -> Result<(), String> {
    let path = security_config_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "Failed to create security config parent {}: {error}",
                parent.display()
            )
        })?;
    }
    let encoded = serde_json::to_vec_pretty(config)
        .map_err(|error| format!("Failed to serialize security config: {error}"))?;
    fs::write(&path, encoded).map_err(|error| {
        format!(
            "Failed to write security config {}: {error}",
            path.display()
        )
    })?;
    Ok(())
}

fn load_monitor_security_state() -> Result<MonitorSecurityState, String> {
    let config = load_security_config()?;
    let active = resolve_active_operator(&config)?;
    let workspace_path = resolve_monitor_workspace_path()?;
    let inventory_path = resolve_inventory_path()?;
    let role_permissions = vec![
        role_permissions_for("admin"),
        role_permissions_for("operator"),
        role_permissions_for("viewer"),
    ];
    Ok(MonitorSecurityState {
        workspace_path: workspace_path.to_string_lossy().to_string(),
        inventory_path: inventory_path.to_string_lossy().to_string(),
        active_operator_id: active.operator_id.clone(),
        active_role: active.role.clone(),
        operators: config.operators.clone(),
        ssh_profiles: config.ssh_profiles.clone(),
        ssh_bindings: config.ssh_bindings.clone(),
        role_permissions,
    })
}

fn build_monitor_setup_status(config: &MonitorSecurityConfig) -> MonitorSetupStatus {
    let claimed_node_slot_ids = config
        .setup
        .claimed_node_slot_ids
        .iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();

    let normalized_machine_id = config
        .setup
        .physical_machine_id
        .as_ref()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty());

    let has_required_bindings = !claimed_node_slot_ids.is_empty()
        && claimed_node_slot_ids.iter().all(|node_slot_id| {
            config
                .ssh_bindings
                .iter()
                .any(|binding| binding.node_slot_id.eq_ignore_ascii_case(node_slot_id))
        });

    let claims_align_with_machine = normalized_machine_id
        .as_ref()
        .map(|physical_machine_id| {
            logical_nodes_for_physical_machine(physical_machine_id)
                .map(|expected_node_slot_ids| {
                    claimed_node_slot_ids.iter().all(|node_slot_id| {
                        expected_node_slot_ids
                            .iter()
                            .any(|expected| expected.eq_ignore_ascii_case(node_slot_id))
                    })
                })
                .unwrap_or(false)
        })
        .unwrap_or(false);

    let local_identity_matches_machine = normalized_machine_id
        .as_ref()
        .and_then(|physical_machine_id| {
            monitor_detect_local_machine_identity()
                .ok()
                .and_then(|identity| identity.physical_machine_id)
                .map(|detected| detected.eq_ignore_ascii_case(physical_machine_id))
        })
        .unwrap_or(false);

    let completed = config.setup.completed
        && config.setup.wizard_version >= MONITOR_SETUP_WIZARD_VERSION
        && config.setup.completed_at_utc.is_some()
        && normalized_machine_id.is_some()
        && !claimed_node_slot_ids.is_empty()
        && has_required_bindings
        && claims_align_with_machine
        && local_identity_matches_machine;

    MonitorSetupStatus {
        required_wizard_version: MONITOR_SETUP_WIZARD_VERSION,
        completed,
        completed_wizard_version: config.setup.wizard_version,
        completed_at_utc: config.setup.completed_at_utc.clone(),
        physical_machine_id: normalized_machine_id,
        claimed_node_slot_ids,
    }
}

#[derive(Debug, Clone)]
struct InventoryMachineTopology {
    physical_machine_id: String,
    management_host: String,
    node_slot_ids: Vec<String>,
}

fn node_slot_ordinal(node_slot_id: &str) -> u16 {
    node_slot_id
        .chars()
        .filter(char::is_ascii_digit)
        .collect::<String>()
        .parse::<u16>()
        .unwrap_or(u16::MAX)
}

fn build_inventory_machine_topology(
    nodes: &[MonitorNode],
) -> HashMap<String, InventoryMachineTopology> {
    let mut topology = HashMap::<String, InventoryMachineTopology>::new();

    for node in nodes {
        let physical_machine_id = node.physical_machine_id.trim().to_ascii_lowercase();
        if physical_machine_id.is_empty() {
            continue;
        }

        let node_slot_id = node.node_slot_id.trim().to_ascii_lowercase();
        let management_host = node
            .management_host
            .as_ref()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty() && !is_obsolete_overlay_host(value))
            .or_else(|| {
                let host = node.host.trim();
                (!host.is_empty() && !is_obsolete_overlay_host(host)).then(|| host.to_string())
            })
            .unwrap_or_default();

        let entry = topology
            .entry(physical_machine_id.clone())
            .or_insert_with(|| InventoryMachineTopology {
                physical_machine_id: physical_machine_id.clone(),
                management_host: management_host.clone(),
                node_slot_ids: Vec::new(),
            });

        if entry.management_host.is_empty() && !management_host.is_empty() {
            entry.management_host = management_host;
        }

        if !node_slot_id.is_empty()
            && !entry
                .node_slot_ids
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(&node_slot_id))
        {
            entry.node_slot_ids.push(node_slot_id);
        }
    }

    for entry in topology.values_mut() {
        entry.node_slot_ids.sort_by(|left, right| {
            match node_slot_ordinal(left).cmp(&node_slot_ordinal(right)) {
                std::cmp::Ordering::Equal => left.cmp(right),
                ordering => ordering,
            }
        });
    }

    topology
}

fn load_inventory_machine_topology() -> Result<HashMap<String, InventoryMachineTopology>, String> {
    let inventory_path = resolve_inventory_path()?;
    let content = fs::read_to_string(&inventory_path).map_err(|error| {
        format!(
            "Failed to read inventory file {}: {error}",
            inventory_path.display()
        )
    })?;

    let mut lines = content.lines().filter(|line| !line.trim().is_empty());
    let header = lines
        .next()
        .ok_or_else(|| format!("Inventory file is empty: {}", inventory_path.display()))?;
    let header_cols = header
        .split(',')
        .map(|cell| cell.trim().trim_start_matches('\u{feff}').to_string())
        .collect::<Vec<_>>();
    let index_map = header_cols
        .iter()
        .enumerate()
        .map(|(idx, name)| (name.clone(), idx))
        .collect::<HashMap<_, _>>();

    let resolve_column = |aliases: &[&str], label: &str| -> Result<usize, String> {
        aliases
            .iter()
            .find_map(|name| index_map.get(*name).copied())
            .ok_or_else(|| format!("Inventory header missing required column '{label}'"))
    };

    let node_slot_idx = resolve_column(&["node_slot_id", "machine_id"], "node_slot_id")?;
    let host_idx = resolve_column(&["host"], "host")?;
    let management_host_idx = resolve_column(&["management_host"], "management_host")?;
    let public_ip_idx = resolve_column(&["public_ip"], "public_ip")?;
    let local_ip_idx = resolve_column(&["local_ip"], "local_ip")?;
    let physical_machine_idx = resolve_column(
        &["physical_machine_id", "physical_machine"],
        "physical_machine_id",
    )?;

    let mut topology = HashMap::<String, InventoryMachineTopology>::new();
    for raw_line in lines {
        let trimmed = raw_line.trim();
        if trimmed.starts_with('#') {
            continue;
        }

        let cells = trimmed
            .split(',')
            .map(|cell| cell.trim().to_string())
            .collect::<Vec<_>>();
        if cells.len() < header_cols.len() {
            continue;
        }

        let get = |index: usize| -> String { cells.get(index).cloned().unwrap_or_default() };
        let node_slot_id = get(node_slot_idx).to_ascii_lowercase();
        let physical_machine_id = get(physical_machine_idx).to_ascii_lowercase();
        if node_slot_id.is_empty() || physical_machine_id.is_empty() {
            continue;
        }

        let management_host = preferred_management_host(
            &get(host_idx),
            &get(management_host_idx),
            &get(public_ip_idx),
            &get(local_ip_idx),
            &physical_machine_id,
        );
        let entry = topology
            .entry(physical_machine_id.clone())
            .or_insert_with(|| InventoryMachineTopology {
                physical_machine_id: physical_machine_id.clone(),
                management_host: String::new(),
                node_slot_ids: Vec::new(),
            });

        if entry.management_host.is_empty() && !management_host.is_empty() {
            entry.management_host = management_host;
        }

        if !entry
            .node_slot_ids
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(&node_slot_id))
        {
            entry.node_slot_ids.push(node_slot_id);
        }
    }

    for entry in topology.values_mut() {
        entry.node_slot_ids.sort_by(|left, right| {
            match node_slot_ordinal(left).cmp(&node_slot_ordinal(right)) {
                std::cmp::Ordering::Equal => left.cmp(right),
                ordering => ordering,
            }
        });
    }

    if topology.is_empty() {
        return Err(format!(
            "No machine topology rows loaded from {}",
            inventory_path.display()
        ));
    }

    Ok(topology)
}

fn canonical_management_host_for_physical_machine(machine_id: &str) -> Option<String> {
    let normalized_machine = machine_id.trim().to_ascii_lowercase();
    if normalized_machine.is_empty() {
        return None;
    }

    load_inventory_machine_topology().ok().and_then(|topology| {
        topology.get(&normalized_machine).and_then(|entry| {
            let management_host = entry.management_host.trim();
            if management_host.is_empty() {
                None
            } else {
                Some(management_host.to_string())
            }
        })
    })
}

fn logical_nodes_for_physical_machine(physical_machine_id: &str) -> Result<Vec<String>, String> {
    let normalized_machine = physical_machine_id.trim().to_ascii_lowercase();
    if normalized_machine.is_empty() {
        return Err("physical_machine_id is required".to_string());
    }

    let topology = load_inventory_machine_topology()?;
    topology
        .get(&normalized_machine)
        .map(|entry| entry.node_slot_ids.clone())
        .ok_or_else(|| {
            let known = topology
                .values()
                .map(|entry| entry.physical_machine_id.clone())
                .collect::<Vec<_>>();
            format!(
                "Unknown physical_machine_id '{}'. Known machines: {}.",
                physical_machine_id,
                known.join(", ")
            )
        })
}

fn physical_machine_for_binding_target(binding_target: &str) -> Option<String> {
    let normalized_target = binding_target.trim().to_ascii_lowercase();
    if normalized_target.is_empty() {
        return None;
    }

    let topology = load_inventory_machine_topology().ok()?;
    if topology.contains_key(&normalized_target) {
        return Some(normalized_target);
    }

    topology.values().find_map(|entry| {
        entry
            .node_slot_ids
            .iter()
            .any(|node_slot_id| node_slot_id.eq_ignore_ascii_case(&normalized_target))
            .then(|| entry.physical_machine_id.clone())
    })
}

fn physical_machine_for_management_host(management_host: &str) -> Option<String> {
    let target_management_host = management_host.trim();
    if target_management_host.is_empty() {
        return None;
    }

    let inventory_path = resolve_inventory_path().ok()?;
    let content = fs::read_to_string(&inventory_path).ok()?;
    let mut lines = content.lines().filter(|line| !line.trim().is_empty());
    let header = lines.next()?;
    let header_cols = header
        .split(',')
        .map(|cell| cell.trim().trim_start_matches('\u{feff}').to_string())
        .collect::<Vec<_>>();
    let index_map = header_cols
        .iter()
        .enumerate()
        .map(|(idx, name)| (name.clone(), idx))
        .collect::<HashMap<_, _>>();

    let resolve_column = |aliases: &[&str]| -> Option<usize> {
        aliases
            .iter()
            .find_map(|name| index_map.get(*name).copied())
    };

    let physical_machine_idx = resolve_column(&["physical_machine_id", "physical_machine"])?;
    let address_columns = [
        resolve_column(&["management_host"]),
        resolve_column(&["host"]),
        resolve_column(&["public_ip"]),
        resolve_column(&["local_ip"]),
    ];

    for raw_line in lines {
        let trimmed = raw_line.trim();
        if trimmed.starts_with('#') {
            continue;
        }

        let cells = trimmed
            .split(',')
            .map(|cell| cell.trim().to_string())
            .collect::<Vec<_>>();
        if cells.len() < header_cols.len() {
            continue;
        }

        let get = |index: usize| -> String { cells.get(index).cloned().unwrap_or_default() };
        if address_columns
            .iter()
            .flatten()
            .map(|index| get(*index))
            .any(|value| !value.is_empty() && value.eq_ignore_ascii_case(target_management_host))
        {
            let physical_machine_id = get(physical_machine_idx);
            if !physical_machine_id.is_empty() {
                return Some(physical_machine_id.to_ascii_lowercase());
            }
        }
    }

    None
}

fn detect_local_management_host() -> Option<String> {
    for env_key in ["SYNERGY_MACHINE_ADDRESS", "SYNERGY_MACHINE_MANAGEMENT_HOST"] {
        if let Ok(override_ip) = std::env::var(env_key) {
            let trimmed = override_ip.trim().to_string();
            if trimmed.parse::<Ipv4Addr>().is_ok() {
                return Some(trimmed);
            }
        }
    }

    let candidates = detect_management_host_from_system_commands();
    let matched = candidates
        .iter()
        .find(|ip| physical_machine_for_management_host(ip).is_some())
        .cloned();
    if matched.is_some() {
        return matched;
    }

    let private_candidate = candidates
        .iter()
        .find(|ip| is_private_management_ip(ip))
        .cloned();
    if private_candidate.is_some() {
        return private_candidate;
    }

    candidates.into_iter().next()
}

fn detect_management_host_from_system_commands() -> Vec<String> {
    let command_sets: Vec<Vec<&str>> = if cfg!(target_os = "windows") {
        // PowerShell is the most reliable way to enumerate IPs on Windows because
        // it returns clean, one-IP-per-line output without locale-dependent labels.
        // ipconfig is kept as a secondary fallback for environments where PowerShell
        // is restricted.
        vec![
            vec![
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-NetIPAddress -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress",
            ],
            vec!["cmd", "/C", "ipconfig"],
        ]
    } else {
        vec![
            vec!["bash", "-lc", "ip -o -4 addr show 2>/dev/null || true"],
            vec!["bash", "-lc", "ifconfig 2>/dev/null || true"],
        ]
    };

    for parts in command_sets {
        if parts.is_empty() {
            continue;
        }
        let mut command = ProcessCommand::new(parts[0]);
        if parts.len() > 1 {
            command.args(&parts[1..]);
        }
        let output = command.output().ok();
        let Some(output) = output else {
            continue;
        };

        let combined = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let ips = find_management_host_in_text(&combined);
        if !ips.is_empty() {
            return ips;
        }
    }

    Vec::new()
}

fn find_management_host_in_text(text: &str) -> Vec<String> {
    let mut matches = HashSet::new();
    for raw_token in text
        .split(|ch: char| !(ch.is_ascii_digit() || ch == '.' || ch == '/'))
        .filter(|token| !token.is_empty())
    {
        let candidate = raw_token.split('/').next().unwrap_or_default();
        let Ok(ip) = candidate.parse::<Ipv4Addr>() else {
            continue;
        };
        if !ip.is_loopback() && !ip.is_link_local() {
            matches.insert(candidate.to_string());
        }
    }
    let mut entries = matches.into_iter().collect::<Vec<_>>();
    entries.sort();
    entries
}

fn is_private_management_ip(value: &str) -> bool {
    let Ok(ip) = value.parse::<Ipv4Addr>() else {
        return false;
    };
    ip.is_loopback()
        || ip.is_private()
        || (ip.octets()[0] == 100 && (ip.octets()[1] & 0b1100_0000) == 0b0100_0000)
}

fn resolve_active_operator(
    config: &MonitorSecurityConfig,
) -> Result<MonitorOperatorProfile, String> {
    if let Some(active) = config.operators.iter().find(|operator| {
        operator.enabled
            && operator
                .operator_id
                .eq_ignore_ascii_case(&config.active_operator_id)
    }) {
        return Ok(active.clone());
    }
    if let Some(fallback) = config.operators.iter().find(|operator| operator.enabled) {
        return Ok(fallback.clone());
    }
    Err("No enabled operators configured. Configure at least one admin operator.".to_string())
}

fn normalize_operator_role(value: &str) -> Result<String, String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "admin" | "operator" | "viewer" => Ok(normalized),
        _ => Err("role must be one of: admin, operator, viewer".to_string()),
    }
}

fn enforce_security_admin(operator: &MonitorOperatorProfile) -> Result<(), String> {
    if operator.role.eq_ignore_ascii_case("admin") {
        Ok(())
    } else {
        Err(format!(
            "RBAC denied: role '{}' cannot manage security/SSH profiles",
            operator.role
        ))
    }
}

fn role_permissions_for(role: &str) -> MonitorRolePermissions {
    match role {
        "admin" => MonitorRolePermissions {
            role: "admin".to_string(),
            can_control_nodes: true,
            can_run_bulk_actions: true,
            can_manage_security: true,
        },
        "operator" => MonitorRolePermissions {
            role: "operator".to_string(),
            can_control_nodes: true,
            can_run_bulk_actions: true,
            can_manage_security: false,
        },
        _ => MonitorRolePermissions {
            role: "viewer".to_string(),
            can_control_nodes: false,
            can_run_bulk_actions: false,
            can_manage_security: false,
        },
    }
}

fn role_allows_control(role: &str, action: &str) -> bool {
    let normalized_role = role.trim().to_ascii_lowercase();
    let normalized_action = normalize_action_key(action);
    if normalized_role == "admin" {
        return true;
    }
    if normalized_role == "viewer" {
        return false;
    }
    if normalized_role != "operator" {
        return false;
    }

    if normalized_action.starts_with("rpc:") {
        return true;
    }

    let admin_only = [
        "install_node",
        "bootstrap_node",
        "reset_chain",
        "rotate_vrf_key",
        "validator_mesh_reconnect",
        "validator_chain_body_repair",
        "rotate_pqc_keys",
        "flush_relay_queue",
        "drain_compute_queue",
        "reindex_from_height",
        "validator_wait_promote_vote_only",
    ];
    !admin_only.iter().any(|admin_action| {
        normalized_action == *admin_action
            || normalized_action
                .strip_prefix(admin_action)
                .map(|rest| rest.starts_with('_'))
                .unwrap_or(false)
    })
}

fn apply_security_ssh_profile(
    node_slot_id: &str,
    node_alias: &str,
    physical_machine_id: &str,
    commands: &mut NodeControlCommands,
) {
    let Ok(config) = load_security_config() else {
        return;
    };

    let binding = config.ssh_bindings.iter().find(|binding| {
        binding_matches_target(
            binding.node_slot_id.as_str(),
            node_slot_id,
            node_alias,
            physical_machine_id,
        )
    });

    // Resolve SSH profile: prefer the machine-specific binding's profile;
    // fall back to the first available profile so machines without an explicit
    // binding still receive SSH credentials for remote orchestration (e.g. the
    // global reset command targeting all nodes, not just the locally-bound one).
    let profile_id = binding.map(|b| b.profile_id.as_str()).unwrap_or("");
    let profile = if !profile_id.is_empty() {
        config
            .ssh_profiles
            .iter()
            .find(|profile| profile.profile_id.eq_ignore_ascii_case(profile_id))
    } else {
        config.ssh_profiles.first()
    };
    let Some(profile) = profile else {
        return;
    };

    let machine_key = node_slot_id.to_ascii_uppercase().replace('-', "_");
    let mut env_pairs = Vec::<(String, String)>::new();
    env_pairs.push((
        "SYNERGY_TESTNET_SSH_USER".to_string(),
        profile.ssh_user.clone(),
    ));
    env_pairs.push((
        "SYNERGY_TESTNET_SSH_PORT".to_string(),
        profile.ssh_port.to_string(),
    ));
    if let Some(value) = profile
        .ssh_key_path
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        env_pairs.push(("SYNERGY_TESTNET_SSH_KEY".to_string(), value.to_string()));
    }
    if let Some(value) = profile
        .remote_root
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        env_pairs.push(("SYNERGY_REMOTE_ROOT".to_string(), value.to_string()));
    }
    // Machine-specific host/dir overrides are only applied when there is an
    // explicit binding for this machine; don't use another machine's overrides.
    if let Some(binding) = binding {
        if let Some(value) = binding
            .host_override
            .as_ref()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        {
            env_pairs.push((format!("{machine_key}_HOST"), value.to_string()));
        }
        if let Some(value) = binding
            .remote_dir_override
            .as_ref()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        {
            env_pairs.push((format!("{machine_key}_REMOTE_DIR"), value.to_string()));
        }
    }

    prefix_commands_with_env(commands, &env_pairs);
}

fn prefix_commands_with_env(commands: &mut NodeControlCommands, env_pairs: &[(String, String)]) {
    if env_pairs.is_empty() {
        return;
    }

    let prefix = env_pairs
        .iter()
        .map(|(key, value)| format!("{key}={}", shell_quote(value)))
        .collect::<Vec<_>>()
        .join(" ");
    let prepend = |command: &str| -> String {
        let trimmed = command.trim();
        if trimmed.is_empty() {
            String::new()
        } else {
            format!("{prefix} {trimmed}")
        }
    };

    if let Some(command) = commands.start.as_mut() {
        *command = prepend(command);
    }
    if let Some(command) = commands.stop.as_mut() {
        *command = prepend(command);
    }
    if let Some(command) = commands.restart.as_mut() {
        *command = prepend(command);
    }
    if let Some(command) = commands.status.as_mut() {
        *command = prepend(command);
    }
    if let Some(command) = commands.setup.as_mut() {
        *command = prepend(command);
    }
    if let Some(command) = commands.export_logs.as_mut() {
        *command = prepend(command);
    }
    if let Some(command) = commands.view_chain_data.as_mut() {
        *command = prepend(command);
    }
    if let Some(command) = commands.export_chain_data.as_mut() {
        *command = prepend(command);
    }
    for command in commands.custom_actions.values_mut() {
        *command = prepend(command);
    }
}

fn select_nodes_for_scope(nodes: &[MonitorNode], scope: &str) -> Vec<String> {
    let normalized = scope.trim().to_ascii_lowercase();
    if normalized.is_empty() || normalized == "all" {
        return nodes
            .iter()
            .map(|node| node.node_slot_id.clone())
            .collect::<Vec<_>>();
    }

    if normalized.contains(',') {
        let mut seen = HashSet::<String>::new();
        let mut selected = Vec::<String>::new();
        for token in normalized
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            for node in nodes.iter().filter(|node| {
                node.node_slot_id.eq_ignore_ascii_case(token)
                    || node.node_alias.eq_ignore_ascii_case(token)
                    || node.physical_machine_id.eq_ignore_ascii_case(token)
            }) {
                let normalized_id = node.node_slot_id.trim().to_ascii_lowercase();
                if seen.insert(normalized_id) {
                    selected.push(node.node_slot_id.clone());
                }
            }
        }
        return selected;
    }

    if let Some(group) = normalized.strip_prefix("role_group:") {
        let target = group.trim();
        return nodes
            .iter()
            .filter(|node| node.role_group.to_ascii_lowercase() == target)
            .map(|node| node.node_slot_id.clone())
            .collect::<Vec<_>>();
    }

    if let Some(role) = normalized.strip_prefix("role:") {
        let target = role.trim();
        return nodes
            .iter()
            .filter(|node| node.role.to_ascii_lowercase().contains(target))
            .map(|node| node.node_slot_id.clone())
            .collect::<Vec<_>>();
    }

    if let Some(physical) = normalized
        .strip_prefix("physical:")
        .or_else(|| normalized.strip_prefix("physical_machine_id:"))
    {
        let target = physical.trim();
        return nodes
            .iter()
            .filter(|node| node.physical_machine_id.eq_ignore_ascii_case(target))
            .map(|node| node.node_slot_id.clone())
            .collect::<Vec<_>>();
    }

    nodes
        .iter()
        .filter(|node| {
            node.node_slot_id.eq_ignore_ascii_case(scope)
                || node.node_alias.eq_ignore_ascii_case(scope)
                || node.physical_machine_id.eq_ignore_ascii_case(scope)
        })
        .map(|node| node.node_slot_id.clone())
        .collect::<Vec<_>>()
}

fn is_bootnode_slot(node_slot_id: &str) -> bool {
    matches!(node_slot_id, "node-01" | "node-02")
}

fn is_bootstrap_consensus_validator(node: &MonitorNode) -> bool {
    node.role_group.eq_ignore_ascii_case("consensus")
        && (node.node_type.eq_ignore_ascii_case("validator")
            || node.role.eq_ignore_ascii_case("validator"))
}

fn bootstrap_consensus_validator_count(nodes: &[MonitorNode]) -> usize {
    nodes
        .iter()
        .filter(|node| is_bootstrap_consensus_validator(node))
        .count()
}

async fn installed_bootstrap_validator_slots(
    nodes: &[MonitorNode],
) -> Result<HashSet<String>, String> {
    let snapshot = get_monitor_agent_snapshot().await?;
    let installed = snapshot
        .agents
        .into_iter()
        .filter(|agent| agent.reachable)
        .flat_map(|agent| agent.node_slot_ids.into_iter())
        .map(|node_slot_id| node_slot_id.trim().to_ascii_lowercase())
        .collect::<HashSet<_>>();

    Ok(nodes
        .iter()
        .filter(|node| is_bootstrap_consensus_validator(node))
        .filter(|node| installed.contains(&node.node_slot_id.to_ascii_lowercase()))
        .map(|node| node.node_slot_id.to_ascii_lowercase())
        .collect())
}

fn bulk_action_phase(action: &str, node: &MonitorNode) -> u8 {
    let is_bootnode = is_bootnode_slot(node.node_slot_id.as_str());
    let is_consensus_validator = node.role_group.eq_ignore_ascii_case("consensus")
        && (node.node_type.eq_ignore_ascii_case("validator")
            || node.role.eq_ignore_ascii_case("validator"));

    match action {
        "stop" => {
            if is_bootnode {
                2
            } else if is_consensus_validator {
                1
            } else {
                0
            }
        }
        "start" | "restart" | "reset_chain" | "setup" | "setup_node" | "install_node"
        | "bootstrap_node" => {
            if is_bootnode {
                0
            } else if is_consensus_validator {
                1
            } else {
                2
            }
        }
        // sync_node: each node syncs independently from peers; no ordering needed.
        "sync_node" => 0,
        _ => 0,
    }
}

fn bulk_action_pause(action: &str, phase: u8) -> Option<Duration> {
    match (action, phase) {
        (
            "start" | "restart" | "reset_chain" | "setup" | "setup_node" | "install_node"
            | "bootstrap_node",
            1,
        ) => {
            // Give bootnodes (phase 0) 30 s to bind their P2P and RPC ports before
            // the consensus validators (phase 1) attempt their pre-start sync.
            // The pre-start sync retry loop will cover any remaining startup time,
            // but a generous initial pause reduces first-attempt failures in logs.
            Some(Duration::from_secs(30))
        }
        (
            "start" | "restart" | "reset_chain" | "setup" | "setup_node" | "install_node"
            | "bootstrap_node",
            2,
        ) => Some(Duration::from_secs(5)),
        _ => None,
    }
}

fn order_nodes_for_bulk_action(
    nodes: &[MonitorNode],
    selected: Vec<String>,
    action: &str,
) -> Vec<String> {
    let selected_set = selected
        .into_iter()
        .map(|node_slot_id| node_slot_id.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    let mut selected_nodes = nodes
        .iter()
        .filter(|node| selected_set.contains(&node.node_slot_id.to_ascii_lowercase()))
        .cloned()
        .collect::<Vec<_>>();

    selected_nodes.sort_by(|left, right| {
        bulk_action_phase(action, left)
            .cmp(&bulk_action_phase(action, right))
            .then(left.physical_machine_id.cmp(&right.physical_machine_id))
            .then(left.node_slot_id.cmp(&right.node_slot_id))
    });

    selected_nodes
        .into_iter()
        .map(|node| node.node_slot_id)
        .collect()
}

fn local_nodectl_action(action: &str) -> Option<&'static str> {
    match action {
        "start" => Some("start"),
        "stop" => Some("stop"),
        "restart" => Some("restart"),
        "status" => Some("status"),
        "sync_node" => Some("sync"),
        "setup" | "setup_node" => Some("setup"),
        "install_node" => Some("install_node"),
        "bootstrap_node" => Some("bootstrap_node"),
        "reset_chain" => Some("reset_chain"),
        "export_logs" => Some("export_logs"),
        "view_chain_data" => Some("view_chain_data"),
        "export_chain_data" => Some("export_chain_data"),
        "logs" | "node_logs" => Some("logs"),
        _ => None,
    }
}

fn try_execute_local_monitor_control(
    node: &MonitorNode,
    action: &str,
    inventory_path: &Path,
    effective_machine_id: &str,
) -> Result<Option<MonitorControlResult>, String> {
    let Some(nodectl_action) = local_nodectl_action(action) else {
        return Ok(None);
    };

    let Ok(identity) = monitor_detect_local_machine_identity() else {
        return Ok(None);
    };
    if !identity.detected {
        return Ok(None);
    }

    let Some(local_machine_id) = identity.physical_machine_id.as_deref() else {
        return Ok(None);
    };
    if !effective_machine_id.eq_ignore_ascii_case(local_machine_id) {
        return Ok(None);
    }

    let installers_root = inventory_path
        .parent()
        .ok_or_else(|| format!("Inventory path has no parent: {}", inventory_path.display()))?
        .join("installers");
    let install_dir = installers_root.join(&node.node_slot_id);

    #[cfg(target_os = "windows")]
    let command = {
        let script_path = install_dir.join("nodectl.ps1");
        format!(
            r#"powershell -NoProfile -ExecutionPolicy Bypass -File "{}" {}"#,
            script_path.display(),
            nodectl_action
        )
    };

    #[cfg(not(target_os = "windows"))]
    let command = {
        let script_path = install_dir.join("nodectl.sh");
        format!(r#"bash "{}" {}"#, script_path.display(), nodectl_action)
    };

    let (exit_code, stdout, stderr) = run_shell_command(&command)?;
    Ok(Some(MonitorControlResult {
        node_slot_id: node.node_slot_id.clone(),
        action: action.to_string(),
        success: exit_code == 0,
        exit_code,
        command: format!("local-nodectl {nodectl_action}"),
        stdout: truncate_text(stdout.trim(), 6000),
        stderr: truncate_text(stderr.trim(), 6000),
        executed_at_utc: Utc::now().to_rfc3339(),
    }))
}

async fn execute_monitor_node_control(
    node_slot_id: &str,
    normalized_action: &str,
    operator: &MonitorOperatorProfile,
    control_mode: &str,
) -> Result<MonitorControlResult, String> {
    let inventory_path = resolve_inventory_path()?;
    let nodes = load_inventory_nodes(&inventory_path)?;

    let node = nodes
        .iter()
        .find(|candidate| {
            candidate.node_slot_id.eq_ignore_ascii_case(node_slot_id)
                || candidate.node_alias.eq_ignore_ascii_case(node_slot_id)
        })
        .cloned()
        .ok_or_else(|| format!("Node not found in inventory: {node_slot_id}"))?;

    let mut host_overrides = load_hosts_overrides(&inventory_path);
    augment_host_overrides_with_runtime_placements(&mut host_overrides).await;
    let commands = resolve_control_commands(
        &host_overrides,
        &node.node_slot_id,
        &node.node_alias,
        &node.physical_machine_id,
        &inventory_path,
    );
    let effective_machine_id = effective_machine_id_for_node(&node, &host_overrides);

    if normalized_action == "sync_node" && is_bootstrap_consensus_validator(&node) {
        return Err(format!(
            "{} is a bootstrap validator. Validator quorum uses install + start/restart; Sync Node is reserved for late-joining non-validator nodes.",
            node.node_slot_id
        ));
    }

    let installed_bootstrap_validators = if matches!(normalized_action, "start" | "restart")
        && is_bootstrap_consensus_validator(&node)
    {
        Some(installed_bootstrap_validator_slots(&nodes).await?)
    } else {
        None
    };

    if let Some(installed_validators) = installed_bootstrap_validators.as_ref() {
        let required_quorum =
            validator_network_cluster_quorum_threshold(bootstrap_consensus_validator_count(&nodes));
        if installed_validators.len() < required_quorum {
            return Err(format!(
                "Validator quorum is not ready for {}: {} of {} bootstrap validators are installed. Install {} validators before start/restart is allowed.",
                node.node_slot_id,
                installed_validators.len(),
                required_quorum,
                required_quorum,
            ));
        }
    }

    let outcome = if normalized_action.starts_with("rpc:") {
        let (method, params) = resolve_rpc_control_call(normalized_action).ok_or_else(|| {
            format!(
                "Unsupported RPC operation '{normalized_action}'. Add a supported rpc:* action or configure a custom MACHINE_XX_ACTION_<name>_CMD."
            )
        })?;

        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .connect_timeout(Duration::from_secs(3))
            .build()
            .unwrap_or_else(|_| Client::new());

        match rpc_call(&client, &node.rpc_url, method, params).await {
            Ok(result) => {
                let stdout =
                    serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string());
                MonitorControlResult {
                    node_slot_id: node.node_slot_id.clone(),
                    action: normalized_action.to_string(),
                    success: true,
                    exit_code: 0,
                    command: format!("RPC {method}"),
                    stdout: truncate_text(stdout.trim(), 6000),
                    stderr: String::new(),
                    executed_at_utc: Utc::now().to_rfc3339(),
                }
            }
            Err(error) => MonitorControlResult {
                node_slot_id: node.node_slot_id.clone(),
                action: normalized_action.to_string(),
                success: false,
                exit_code: 1,
                command: format!("RPC {method}"),
                stdout: String::new(),
                stderr: truncate_text(error.trim(), 6000),
                executed_at_utc: Utc::now().to_rfc3339(),
            },
        }
    } else if normalized_action == "validator_wait_promote_vote_only"
        || normalized_action.starts_with("validator_wait_promote_vote_only_")
    {
        execute_validator_wait_promote_vote_only_control(
            &node,
            &host_overrides,
            &inventory_path,
            normalized_action,
        )?
    } else if normalized_action == "validator_mesh_reconnect"
        || normalized_action == "validator_state_diagnostics"
        || normalized_action == "validator_chain_body_repair"
    {
        execute_validator_recovery_phase_control(
            &node,
            &host_overrides,
            &inventory_path,
            normalized_action,
        )?
    } else if agent_supports_action(normalized_action) {
        match try_execute_monitor_agent_control(&node, normalized_action, &host_overrides).await {
            AgentControlAttempt::Completed(result) => result,
            AgentControlAttempt::Unavailable => {
                if let Some(local_result) = try_execute_local_monitor_control(
                    &node,
                    normalized_action,
                    &inventory_path,
                    &effective_machine_id,
                )? {
                    local_result
                } else {
                    MonitorControlResult {
                        node_slot_id: node.node_slot_id.clone(),
                        action: normalized_action.to_string(),
                        success: false,
                        exit_code: 1,
                        command: "testnet-agent".to_string(),
                        stdout: String::new(),
                        stderr: format!(
                            "The testnet agent is unavailable for {}. Normal '{}' operations require the local control panel on the target machine or a healthy remote testnet-agent; SSH fallback is disabled for this action.",
                            node.node_slot_id, normalized_action
                        ),
                        executed_at_utc: Utc::now().to_rfc3339(),
                    }
                }
            }
        }
    } else {
        let selected_command = resolve_control_action_command(&commands, normalized_action).ok_or_else(
            || {
                format!(
                    "No '{normalized_action}' control command configured for {}. Configure MACHINE_XX_{ACTION}_CMD or MACHINE_XX_ACTION_<name>_CMD in hosts.env.",
                    node.node_slot_id,
                    ACTION = normalized_action.to_ascii_uppercase(),
                )
            },
        )?;

        let (exit_code, stdout, stderr) = run_shell_command(&selected_command)?;
        let success = exit_code == 0;

        MonitorControlResult {
            node_slot_id: node.node_slot_id.clone(),
            action: normalized_action.to_string(),
            success,
            exit_code,
            command: truncate_text(&selected_command, 180),
            stdout: truncate_text(stdout.trim(), 6000),
            stderr: truncate_text(stderr.trim(), 6000),
            executed_at_utc: Utc::now().to_rfc3339(),
        }
    };

    // After a single-node reset_chain, notify the explorer/indexer to reindex from genesis
    // so it doesn't continue showing stale chain data.  Mirrors the same call in the bulk
    // control path.  Non-blocking: a failure here is logged but does not fail the overall
    // reset_chain outcome.
    if normalized_action == "reset_chain" && outcome.success {
        if let Err(warning) = reset_explorer_index().await {
            eprintln!("Explorer reset warning (non-blocking): {warning}");
        }
    }

    append_audit_event(json!({
        "event_type": "control.node.executed",
        "mode": control_mode,
        "operator_id": operator.operator_id,
        "operator_role": operator.role,
        "node_slot_id": outcome.node_slot_id,
        "action": outcome.action,
        "success": outcome.success,
        "exit_code": outcome.exit_code,
        "command": outcome.command,
        "timestamp_utc": outcome.executed_at_utc,
    }))?;
    Ok(outcome)
}

fn execute_validator_wait_promote_vote_only_control(
    node: &MonitorNode,
    host_overrides: &HashMap<String, String>,
    inventory_path: &Path,
    normalized_action: &str,
) -> Result<MonitorControlResult, String> {
    if node.node_type.to_ascii_lowercase() != "validator" {
        return Err(format!(
            "Promote Vote-only is only available for validator nodes; {} is '{}'.",
            node.node_slot_id, node.node_type
        ));
    }

    let rejoin_height = parse_validator_wait_promote_rejoin_height(normalized_action)?;
    let recovery_script = resolve_validator_appliance_recovery_script_path(inventory_path)
        .ok_or_else(|| {
            "validator-appliance-recovery.sh was not found in the active control-panel workspace."
                .to_string()
        })?;
    let workbook = resolve_node_machine_credentials_path();
    if !workbook.is_file() {
        return Err(format!(
            "Node credentials workbook was not found at {}. Set SYNERGY_NODE_MACHINE_CREDENTIALS to the workbook path.",
            workbook.display()
        ));
    }

    let target = resolve_validator_recovery_target(host_overrides, node);
    let public_rpc = resolve_process_or_hosts_env_value("SYNERGY_PUBLIC_RPC_URL")
        .unwrap_or_else(|| "https://testnet-rpc.synergy-network.io".to_string());
    let probation_blocks =
        resolve_process_or_hosts_env_value("SYNERGY_CONTROL_PANEL_VOTE_ONLY_PROBATION_BLOCKS")
            .unwrap_or_else(|| "1000".to_string());
    let poll_secs = resolve_process_or_hosts_env_value("SYNERGY_CONTROL_PANEL_RECOVERY_POLL_SECS")
        .unwrap_or_else(|| "20".to_string());
    let max_wait_secs =
        resolve_process_or_hosts_env_value("SYNERGY_CONTROL_PANEL_RECOVERY_MAX_WAIT_SECS")
            .unwrap_or_else(|| "0".to_string());
    let remote_timeout =
        resolve_process_or_hosts_env_value("SYNERGY_CONTROL_PANEL_RECOVERY_REMOTE_TIMEOUT_SECS")
            .unwrap_or_else(|| "300".to_string());

    let workspace = resolve_monitor_workspace_path()?;
    let report_dir = workspace.join("reports").join("validator-recovery");
    fs::create_dir_all(&report_dir).map_err(|error| {
        format!(
            "Failed to create validator recovery report directory {}: {error}",
            report_dir.display()
        )
    })?;
    let report_path = report_dir.join(format!(
        "{}-wait-promote-{}.md",
        sanitize_filename_fragment(&node.node_slot_id),
        Utc::now().format("%Y%m%dT%H%M%SZ")
    ));

    let command = [
        "bash".to_string(),
        shell_quote(&recovery_script),
        "wait-promote-vote-only-to-active".to_string(),
        "--target".to_string(),
        shell_quote(&target),
        "--rejoin-height".to_string(),
        shell_quote(&rejoin_height.to_string()),
        "--probation-blocks".to_string(),
        shell_quote(&probation_blocks),
        "--public-rpc".to_string(),
        shell_quote(&public_rpc),
        "--poll-secs".to_string(),
        shell_quote(&poll_secs),
        "--max-wait-secs".to_string(),
        shell_quote(&max_wait_secs),
        "--workbook".to_string(),
        shell_quote(&workbook.to_string_lossy()),
        "--timeout".to_string(),
        shell_quote(&remote_timeout),
        "--execute".to_string(),
        "--output".to_string(),
        shell_quote(&report_path.to_string_lossy()),
    ]
    .join(" ");

    let (exit_code, stdout, stderr) = run_shell_command(&command)?;
    let success = exit_code == 0;
    let report_note = format!("report={}", report_path.display());
    let stdout = if stdout.trim().is_empty() {
        report_note
    } else {
        format!("{}\n{}", stdout.trim(), report_note)
    };

    Ok(MonitorControlResult {
        node_slot_id: node.node_slot_id.clone(),
        action: normalized_action.to_string(),
        success,
        exit_code,
        command: truncate_text(&command, 180),
        stdout: truncate_text(stdout.trim(), 6000),
        stderr: truncate_text(stderr.trim(), 6000),
        executed_at_utc: Utc::now().to_rfc3339(),
    })
}

fn execute_validator_recovery_phase_control(
    node: &MonitorNode,
    host_overrides: &HashMap<String, String>,
    inventory_path: &Path,
    normalized_action: &str,
) -> Result<MonitorControlResult, String> {
    if node.node_type.to_ascii_lowercase() != "validator" {
        return Err(format!(
            "Recovery action '{normalized_action}' is only available for validator nodes; {} is '{}'.",
            node.node_slot_id, node.node_type
        ));
    }

    let recovery_script = resolve_validator_appliance_recovery_script_path(inventory_path)
        .ok_or_else(|| {
            "validator-appliance-recovery.sh was not found in the active control-panel workspace."
                .to_string()
        })?;

    let workbook = resolve_node_machine_credentials_path();
    if !workbook.is_file() {
        return Err(format!(
            "Node credentials workbook was not found at {}. Set SYNERGY_NODE_MACHINE_CREDENTIALS to the workbook path.",
            workbook.display()
        ));
    }

    let target = resolve_validator_recovery_target(host_overrides, node);
    let workspace = resolve_monitor_workspace_path()?;
    let report_dir = workspace.join("reports").join("validator-recovery");
    fs::create_dir_all(&report_dir).map_err(|error| {
        format!(
            "Failed to create validator recovery report directory {}: {error}",
            report_dir.display()
        )
    })?;
    let report_path = report_dir.join(format!(
        "{}-{}-{}.md",
        sanitize_filename_fragment(&node.node_slot_id),
        normalized_action,
        Utc::now().format("%Y%m%dT%H%M%SZ")
    ));

    let public_rpc = resolve_process_or_hosts_env_value("SYNERGY_PUBLIC_RPC_URL")
        .unwrap_or_else(|| "https://testnet-rpc.synergy-network.io".to_string());
    let remote_timeout =
        resolve_process_or_hosts_env_value("SYNERGY_CONTROL_PANEL_RECOVERY_REMOTE_TIMEOUT_SECS")
            .unwrap_or_else(|| "300".to_string());
    let phase = match normalized_action {
        "validator_mesh_reconnect" => "mesh-reconnect",
        "validator_state_diagnostics" => "state-diagnostics",
        "validator_chain_body_repair" => "chain-body-repair",
        _ => {
            return Err(format!(
                "Unsupported validator recovery action '{normalized_action}'."
            ));
        }
    };

    let mut command_parts = vec![
        "bash".to_string(),
        shell_quote(&recovery_script),
        phase.to_string(),
        "--target".to_string(),
        shell_quote(&target),
        "--workbook".to_string(),
        shell_quote(&workbook.to_string_lossy()),
        "--timeout".to_string(),
        shell_quote(&remote_timeout),
    ];

    match normalized_action {
        "validator_mesh_reconnect" => {
            let sample_blocks = resolve_process_or_hosts_env_value(
                "SYNERGY_CONTROL_PANEL_MESH_RECONNECT_SAMPLE_BLOCKS",
            )
            .unwrap_or_else(|| "80".to_string());
            let restart_wait_secs = resolve_process_or_hosts_env_value(
                "SYNERGY_CONTROL_PANEL_MESH_RECONNECT_RESTART_WAIT_SECS",
            )
            .unwrap_or_else(|| "20".to_string());
            command_parts.push("--sample-blocks".to_string());
            command_parts.push(shell_quote(&sample_blocks));
            command_parts.push("--restart-wait-secs".to_string());
            command_parts.push(shell_quote(&restart_wait_secs));
            command_parts.push("--public-rpc".to_string());
            command_parts.push(shell_quote(&public_rpc));
            command_parts.push("--execute".to_string());
        }
        "validator_state_diagnostics" => {}
        "validator_chain_body_repair" => {
            let restart_wait_secs = resolve_process_or_hosts_env_value(
                "SYNERGY_CONTROL_PANEL_CHAIN_BODY_REPAIR_RESTART_WAIT_SECS",
            )
            .unwrap_or_else(|| "20".to_string());
            let restart_target = resolve_process_or_hosts_env_value(
                "SYNERGY_CONTROL_PANEL_CHAIN_BODY_REPAIR_RESTART_TARGET",
            )
            .unwrap_or_else(|| "false".to_string());
            let should_restart_target = matches!(
                restart_target.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            );

            command_parts.push("--restart-wait-secs".to_string());
            command_parts.push(shell_quote(&restart_wait_secs));
            if should_restart_target {
                command_parts.push("--restart-target".to_string());
            }
            command_parts.push("--execute".to_string());
        }
        _ => unreachable!(),
    }

    command_parts.push("--output".to_string());
    command_parts.push(shell_quote(&report_path.to_string_lossy()));
    let command = command_parts.join(" ");

    let (exit_code, stdout, stderr) = run_shell_command(&command)?;
    let success = exit_code == 0;
    let report_note = format!("report={}", report_path.display());
    let stdout = if stdout.trim().is_empty() {
        report_note
    } else {
        format!("{}\n{}", stdout.trim(), report_note)
    };

    Ok(MonitorControlResult {
        node_slot_id: node.node_slot_id.clone(),
        action: normalized_action.to_string(),
        success,
        exit_code,
        command: truncate_text(&command, 180),
        stdout: truncate_text(stdout.trim(), 6000),
        stderr: truncate_text(stderr.trim(), 6000),
        executed_at_utc: Utc::now().to_rfc3339(),
    })
}

fn append_audit_event(event: Value) -> Result<(), String> {
    let workspace = resolve_monitor_workspace_path()?;
    let audit_path = workspace.join(MONITOR_AUDIT_LOG_RELATIVE);
    if let Some(parent) = audit_path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "Failed to create audit directory {}: {error}",
                parent.display()
            )
        })?;
    }

    let mut encoded = serde_json::to_string(&event)
        .map_err(|error| format!("Failed to serialize audit event: {error}"))?;
    encoded.push('\n');
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&audit_path)
        .map_err(|error| format!("Failed to open audit log {}: {error}", audit_path.display()))?;
    file.write_all(encoded.as_bytes()).map_err(|error| {
        format!(
            "Failed to write audit event to {}: {error}",
            audit_path.display()
        )
    })?;
    Ok(())
}

fn sanitize_identifier(value: &str) -> String {
    value
        .trim()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches('_')
        .to_string()
}

fn run_shell_command(command: &str) -> Result<(i32, String, String), String> {
    #[cfg(target_os = "windows")]
    let output = ProcessCommand::new("cmd")
        .args(["/C", command])
        .output()
        .map_err(|e| e.to_string())?;

    #[cfg(not(target_os = "windows"))]
    let output = ProcessCommand::new("sh")
        .arg("-lc")
        .arg(command)
        .output()
        .map_err(|e| e.to_string())?;

    let exit_code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    Ok((exit_code, stdout, stderr))
}

fn truncate_text(input: &str, max_chars: usize) -> String {
    if input.chars().count() <= max_chars {
        return input.to_string();
    }

    let mut output = String::new();
    for (index, ch) in input.chars().enumerate() {
        if index >= max_chars.saturating_sub(3) {
            break;
        }
        output.push(ch);
    }
    output.push_str("...");
    output
}
