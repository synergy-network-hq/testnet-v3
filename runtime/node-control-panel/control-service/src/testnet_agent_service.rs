use axum::{
    extract::{ConnectInfo, Path as AxumPath, State},
    http::{
        header::{AUTHORIZATION, WWW_AUTHENTICATE},
        HeaderMap, StatusCode,
    },
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use uuid::Uuid;

pub const TESTNET_AGENT_PORT: u16 = 47_990;
const TESTNET_AGENT_TOKEN_ENV: &str = "SYNERGY_TESTNET_AGENT_TOKEN";
const TESTNET_AGENT_ALLOWED_REMOTES_ENV: &str = "SYNERGY_TESTNET_AGENT_ALLOWED_REMOTES";
const DEFAULT_REMOTE_ROOT_UNIX: &str = "/opt/synergy";
const DEFAULT_REMOTE_ROOT_WINDOWS: &str = "C:\\Synergy\\Testnet";
const DEFAULT_VALIDATOR_VPN_COORDINATOR_URL: &str = "https://vpn-coordinator.synergy-network.io";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestnetAgentHealth {
    pub status: String,
    pub version: String,
    pub workspace_path: String,
    pub local_management_host: Option<String>,
    pub physical_machine_id: Option<String>,
    pub node_slot_ids: Vec<String>,
    pub supported_actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestnetAgentControlRequest {
    pub node_slot_id: String,
    pub action: String,
    #[serde(default)]
    pub target_reason: Option<String>,
    #[serde(default)]
    pub target_url: Option<String>,
    #[serde(default)]
    pub vpn_node_id: Option<String>,
    #[serde(default)]
    pub vpn_ip: Option<String>,
    #[serde(default)]
    pub vpn_public_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestnetAgentControlResponse {
    pub node_slot_id: String,
    pub action: String,
    pub success: bool,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub transport: String,
    pub executed_at_utc: String,
    #[serde(default)]
    pub phase: Option<String>,
    #[serde(default)]
    pub job_id: Option<String>,
    #[serde(default)]
    pub process_alive: Option<bool>,
}

#[derive(Debug, Clone)]
struct AgentState {
    workspace_root: PathBuf,
    jobs: Arc<Mutex<HashMap<String, TestnetAgentControlResponse>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InventoryNode {
    node_slot_id: String,
    host: String,
    management_host: String,
    public_ip: String,
    local_ip: String,
    physical_machine_id: String,
}

#[derive(Debug, Clone)]
struct NodeInstall {
    node_slot_id: String,
    install_dir: PathBuf,
}

pub async fn serve(workspace_root: PathBuf, port: u16) -> Result<(), String> {
    serve_with_host(workspace_root, port, None).await
}

pub async fn serve_with_host(
    workspace_root: PathBuf,
    port: u16,
    host: Option<String>,
) -> Result<(), String> {
    eprintln!(
        "[{}] testnet-agent starting workspace={} port={} host={}",
        Utc::now().to_rfc3339(),
        workspace_root.display(),
        port,
        host.as_deref().unwrap_or("127.0.0.1")
    );
    let bind_addresses = match bind_addresses_for_host(host.as_deref(), port) {
        Ok(addresses) => addresses,
        Err(error) => return Err(error),
    };
    let state = AgentState {
        workspace_root,
        jobs: Arc::new(Mutex::new(HashMap::new())),
    };
    let router = Router::new()
        .route("/health", get(health_handler))
        .route("/v1/control", post(control_handler))
        .route("/v1/control/jobs/{job_id}", get(control_job_handler))
        .with_state(state);

    let mut listeners = Vec::new();
    for bind_addr in bind_addresses {
        match tokio::net::TcpListener::bind(bind_addr).await {
            Ok(listener) => listeners.push((bind_addr, listener)),
            Err(error) if bind_addr.ip().is_loopback() => {
                return Err(format!(
                    "Failed to bind testnet agent on {bind_addr}: {error}"
                ));
            }
            Err(error) => {
                eprintln!("testnet agent optional bind skipped on {bind_addr}: {error}");
            }
        }
    }

    if listeners.is_empty() {
        return Err("Failed to bind testnet agent on loopback".to_string());
    }

    let mut servers = JoinSet::new();
    for (bind_addr, listener) in listeners {
        let service = router
            .clone()
            .into_make_service_with_connect_info::<SocketAddr>();
        servers.spawn(async move {
            axum::serve(listener, service)
                .await
                .map_err(|error| format!("Testnet agent server error on {bind_addr}: {error}"))
        });
    }

    while let Some(result) = servers.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return Err(error),
            Err(error) => return Err(format!("Testnet agent server task panicked: {error}")),
        }
    }

    Ok(())
}

#[allow(dead_code)]
fn bind_addresses(port: u16) -> Vec<SocketAddr> {
    bind_addresses_for_host(None, port)
        .unwrap_or_else(|_| vec![SocketAddr::from(([127, 0, 0, 1], port))])
}

fn bind_addresses_for_host(host: Option<&str>, port: u16) -> Result<Vec<SocketAddr>, String> {
    if let Some(host) = host {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::from((ip, port))]);
        }
        return Err(format!(
            "Invalid --host value '{host}', expected a valid IP address"
        ));
    }

    Ok(vec![SocketAddr::from(([127, 0, 0, 1], port))])
}

fn supported_agent_actions() -> Vec<String> {
    [
        "start",
        "stop",
        "restart",
        "status",
        "setup",
        "setup_node",
        "install_node",
        "bootstrap_node",
        "reset_chain",
        "explorer_reset",
        "node_logs",
        "logs",
        "sync_node",
        "validator_vpn_status",
        "validator_vpn_prepare",
        "validator_vpn_apply_latest",
        "validator_vpn_poll",
    ]
    .iter()
    .map(|entry| entry.to_string())
    .collect()
}

fn should_run_as_job(action: &str) -> bool {
    #[cfg(target_os = "windows")]
    {
        matches!(
            action,
            "start" | "restart" | "setup" | "setup_node" | "install_node" | "bootstrap_node"
        )
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = action;
        false
    }
}

async fn health_handler(
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    State(state): State<AgentState>,
) -> impl IntoResponse {
    if !is_allowed_remote(remote_addr.ip()) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "agent access restricted to loopback or approved management networks" })),
        )
            .into_response();
    }

    match build_health(&state.workspace_root) {
        Ok(payload) => (
            StatusCode::OK,
            Json(serde_json::to_value(payload).unwrap_or_default()),
        )
            .into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error })),
        )
            .into_response(),
    }
}

async fn control_handler(
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    State(state): State<AgentState>,
    headers: HeaderMap,
    Json(input): Json<TestnetAgentControlRequest>,
) -> impl IntoResponse {
    if !is_allowed_remote(remote_addr.ip()) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "agent access restricted to loopback or approved management networks" })),
        )
            .into_response();
    }
    if !is_authorized_control_request(remote_addr, &headers) {
        return (
            StatusCode::UNAUTHORIZED,
            ([(WWW_AUTHENTICATE, "Bearer".to_string())],),
            Json(serde_json::json!({
                "error":
                    "agent token required for non-loopback /v1/control requests. Set SYNERGY_TESTNET_AGENT_TOKEN and send Authorization: Bearer <token>."
            })),
        )
            .into_response();
    }

    let normalized_action = normalize_action(&input.action);
    eprintln!(
        "[{}] testnet-agent control node={} action={} remote={}",
        Utc::now().to_rfc3339(),
        input.node_slot_id.trim(),
        normalized_action,
        remote_addr
    );
    if should_run_as_job(&normalized_action) {
        let job_id = Uuid::new_v4().to_string();
        let queued = TestnetAgentControlResponse {
            node_slot_id: input.node_slot_id.trim().to_string(),
            action: normalized_action.clone(),
            success: false,
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            transport: "testnet-agent".to_string(),
            executed_at_utc: Utc::now().to_rfc3339(),
            phase: Some("queued".to_string()),
            job_id: Some(job_id.clone()),
            process_alive: None,
        };

        {
            let mut jobs = state.jobs.lock().await;
            jobs.insert(job_id.clone(), queued.clone());
        }

        let workspace_root = state.workspace_root.clone();
        let jobs = state.jobs.clone();
        let queued_for_job = queued.clone();
        let job_id_for_task = job_id.clone();
        tokio::spawn(async move {
            {
                let mut map = jobs.lock().await;
                if let Some(entry) = map.get_mut(&job_id_for_task) {
                    entry.phase = Some("running".to_string());
                }
            }

            let job_result =
                tokio::task::spawn_blocking(move || execute_control(&workspace_root, input)).await;
            let final_response = match job_result {
                Ok(Ok(mut outcome)) => {
                    outcome.job_id = Some(job_id_for_task.clone());
                    outcome
                }
                Ok(Err(error)) => TestnetAgentControlResponse {
                    node_slot_id: queued_for_job.node_slot_id.clone(),
                    action: queued_for_job.action.clone(),
                    success: false,
                    exit_code: 1,
                    stdout: String::new(),
                    stderr: error,
                    transport: "testnet-agent".to_string(),
                    executed_at_utc: Utc::now().to_rfc3339(),
                    phase: Some("failed".to_string()),
                    job_id: Some(job_id_for_task.clone()),
                    process_alive: None,
                },
                Err(join_error) => TestnetAgentControlResponse {
                    node_slot_id: queued_for_job.node_slot_id.clone(),
                    action: queued_for_job.action.clone(),
                    success: false,
                    exit_code: 1,
                    stdout: String::new(),
                    stderr: format!("agent task panicked: {join_error}"),
                    transport: "testnet-agent".to_string(),
                    executed_at_utc: Utc::now().to_rfc3339(),
                    phase: Some("failed".to_string()),
                    job_id: Some(job_id_for_task.clone()),
                    process_alive: None,
                },
            };

            let mut map = jobs.lock().await;
            map.insert(job_id_for_task, final_response);
        });

        return (
            StatusCode::ACCEPTED,
            Json(serde_json::to_value(queued).unwrap_or_default()),
        )
            .into_response();
    }

    // `execute_control` can block for several minutes. Offload to a blocking
    // thread pool so the async executor stays responsive.
    let workspace_root = state.workspace_root.clone();
    let result = tokio::task::spawn_blocking(move || execute_control(&workspace_root, input)).await;

    match result {
        Ok(Ok(outcome)) => (
            if outcome.success {
                StatusCode::OK
            } else {
                StatusCode::BAD_REQUEST
            },
            Json(serde_json::to_value(outcome).unwrap_or_default()),
        )
            .into_response(),
        Ok(Err(error)) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": error })),
        )
            .into_response(),
        Err(join_error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("agent task panicked: {join_error}") })),
        )
            .into_response(),
    }
}

async fn control_job_handler(
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    State(state): State<AgentState>,
    AxumPath(job_id): AxumPath<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !is_allowed_remote(remote_addr.ip()) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "agent access restricted to loopback or approved management networks" })),
        )
            .into_response();
    }
    if !is_authorized_control_request(remote_addr, &headers) {
        return (
            StatusCode::UNAUTHORIZED,
            ([(WWW_AUTHENTICATE, "Bearer".to_string())],),
            Json(serde_json::json!({
                "error":
                    "agent token required for non-loopback /v1/control/jobs requests. Set SYNERGY_TESTNET_AGENT_TOKEN and send Authorization: Bearer <token>."
            })),
        )
            .into_response();
    }

    let jobs = state.jobs.lock().await;
    if let Some(result) = jobs.get(job_id.trim()) {
        return (
            StatusCode::OK,
            Json(serde_json::to_value(result).unwrap_or_default()),
        )
            .into_response();
    }

    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({ "error": format!("control job not found: {}", job_id.trim()) })),
    )
        .into_response()
}

fn build_health(workspace_root: &Path) -> Result<TestnetAgentHealth, String> {
    let nodes = load_inventory_nodes(workspace_root)?;
    let local_management_host = detect_local_management_ip(&nodes);
    let installable = installed_node_slots(workspace_root, &nodes);
    let physical_machine_id = local_management_host
        .as_deref()
        .and_then(|ip| {
            nodes
                .iter()
                .find(|node| matches_inventory_address(node, ip))
        })
        .map(|node| node.physical_machine_id.clone());

    Ok(TestnetAgentHealth {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        workspace_path: workspace_root.to_string_lossy().to_string(),
        local_management_host,
        physical_machine_id,
        node_slot_ids: installable,
        supported_actions: supported_agent_actions(),
    })
}

fn execute_control(
    workspace_root: &Path,
    input: TestnetAgentControlRequest,
) -> Result<TestnetAgentControlResponse, String> {
    let node_slot_id = input.node_slot_id.trim().to_string();
    if node_slot_id.is_empty() {
        return Err("node_slot_id is required".to_string());
    }

    let normalized_action = normalize_action(&input.action);
    if normalized_action.is_empty() {
        return Err("action is required".to_string());
    }
    let target_url = input.target_url.clone();
    let vpn_node_id = input.vpn_node_id.clone();
    let vpn_ip = input.vpn_ip.clone();
    let vpn_public_key = input.vpn_public_key.clone();

    let result = match normalized_action.as_str() {
        "explorer_reset" => {
            trigger_explorer_reset(input.target_url.as_deref(), input.target_reason.as_deref())
        }
        "stop" => {
            let install = resolve_node_install(workspace_root, &node_slot_id)?;
            // Ask nodectl to stop first (clean shutdown via PID file if available).
            let nodectl_result = run_nodectl(&install, "stop");
            // Always follow with force-kill to handle the case where the node was
            // started outside nodectl (no PID file), leaving nodectl returning "not
            // running" while the process is still alive. This is the root cause of
            // validator nodes (node-02, node-04, node-06) ignoring stop commands.
            force_kill_node_processes(&install);
            nodectl_result
        }
        "restart" => {
            let install = resolve_node_install(workspace_root, &node_slot_id)?;
            // Same safe-stop sequence, then start fresh.
            let _ = run_nodectl(&install, "stop");
            force_kill_node_processes(&install);
            run_nodectl(&install, "start")
        }
        "start" => {
            let install = resolve_node_install(workspace_root, &node_slot_id)?;
            if is_node_process_running(&install) {
                Ok(CommandOutcome {
                    success: true,
                    exit_code: 0,
                    stdout: format!(
                        "{} already running (live process detected for {}). Refusing duplicate start.",
                        node_slot_id,
                        install.install_dir.display()
                    ),
                    stderr: String::new(),
                })
            } else {
                run_nodectl(&install, &normalized_action)
            }
        }
        "sync_node" => {
            // Catch the node up from peers and let nodectl promote the node into
            // service once sync completes. Intended for late-joining non-validator
            // nodes or nodes that have been offline long enough to fall behind the
            // chain tip.
            //
            // The HTTP timeout for this action is set to 7200 s in monitor.rs so
            // that the caller waits as long as the sync needs.  The sync itself
            // honours PRESTART_SYNC_TIMEOUT_SECS (defaulting to 7200 s inside
            // nodectl.sh sync) which gives a 2-hour window to download blocks.
            let install = resolve_node_install(workspace_root, &node_slot_id)?;
            run_nodectl(&install, "sync")
        }
        "status" => {
            let install = resolve_node_install(workspace_root, &node_slot_id)?;
            // Run nodectl status first (PID-file based), then cross-check with
            // OS-level process detection to catch nodes running without PID files.
            let nodectl_result = run_nodectl(&install, "status");
            let process_alive = is_node_process_running(&install);
            match nodectl_result {
                Ok(mut outcome) => {
                    // Append process-alive status to stdout so the caller gets both signals.
                    let process_status = if process_alive { "true" } else { "false" };
                    outcome.stdout = format!(
                        "{}\nPROCESS_ALIVE: {}",
                        outcome.stdout.trim(),
                        process_status
                    );
                    // If nodectl says "not running" but process is actually alive,
                    // override success to true so the dashboard shows the node as running.
                    if !outcome.success && process_alive {
                        outcome.success = true;
                        outcome.stdout = format!(
                            "{}\nNOTE: nodectl reports not running (no PID file) but process is alive. Node is running without PID tracking.",
                            outcome.stdout
                        );
                    }
                    Ok(outcome)
                }
                Err(error) => {
                    if process_alive {
                        Ok(CommandOutcome {
                            success: true,
                            exit_code: 0,
                            stdout: "PROCESS_ALIVE: true\nNOTE: nodectl failed but process is alive. Node is running without PID tracking.".to_string(),
                            stderr: error,
                        })
                    } else {
                        Err(error)
                    }
                }
            }
        }
        "logs" | "node_logs" => {
            let install = resolve_node_install(workspace_root, &node_slot_id)?;
            run_nodectl(&install, "logs")
        }
        "setup" | "setup_node" | "install_node" | "bootstrap_node" => {
            let install = resolve_node_install(workspace_root, &node_slot_id)?;
            let _ = run_nodectl(&install, "stop");
            force_kill_node_processes(&install);
            sync_workspace_installer(workspace_root, &install)?;
            let nodectl_action = match normalized_action.as_str() {
                "bootstrap_node" => "bootstrap_node",
                "install_node" => "install_node",
                _ => "setup",
            };
            run_nodectl(&install, nodectl_action)
        }
        "reset_chain" => {
            let install = resolve_node_install(workspace_root, &node_slot_id)?;
            reset_chain(workspace_root, &install)
        }
        "validator_vpn_status" => run_validator_vpn_agent(workspace_root, &["status"], None),
        "validator_vpn_prepare" => run_validator_vpn_agent(workspace_root, &["prepare"], None),
        "validator_vpn_apply_latest" | "validator_vpn_poll" => {
            let coordinator_url = target_url
                .or_else(|| std::env::var("VALIDATOR_VPN_COORDINATOR_URL").ok())
                .or_else(|| std::env::var("SYNERGY_VALIDATOR_VPN_COORDINATOR_URL").ok())
                .unwrap_or_else(|| DEFAULT_VALIDATOR_VPN_COORDINATOR_URL.to_string());
            let vpn_node_id = vpn_node_id
                .or_else(|| std::env::var("VALIDATOR_VPN_NODE_ID").ok())
                .ok_or_else(|| "VALIDATOR_VPN_NODE_ID or vpn_node_id is required".to_string())?;
            let vpn_ip = vpn_ip
                .or_else(|| std::env::var("VALIDATOR_VPN_IP").ok())
                .ok_or_else(|| "VALIDATOR_VPN_IP or vpn_ip is required".to_string())?;
            let vpn_public_key = vpn_public_key
                .or_else(|| std::env::var("VALIDATOR_VPN_COORDINATOR_PUBLIC_KEY").ok());
            let action = if normalized_action == "validator_vpn_poll" {
                "poll"
            } else {
                "apply-latest"
            };
            run_validator_vpn_agent(
                workspace_root,
                &[
                    action,
                    "--coordinator-url",
                    coordinator_url.as_str(),
                    "--node-id",
                    vpn_node_id.as_str(),
                    "--vpn-ip",
                    vpn_ip.as_str(),
                ],
                vpn_public_key.as_deref(),
            )
        }
        other => Err(format!("Unsupported testnet agent action: {other}")),
    }?;

    let process_alive = match normalized_action.as_str() {
        "start" | "restart" | "status" | "setup" | "setup_node" | "install_node"
        | "bootstrap_node" => resolve_node_install(workspace_root, &node_slot_id)
            .ok()
            .map(|install| is_node_process_running(&install)),
        _ => None,
    };
    let phase = match normalized_action.as_str() {
        "start" | "restart" | "setup" | "setup_node" | "install_node" | "bootstrap_node" => {
            if result.success && process_alive == Some(true) {
                Some("process_alive".to_string())
            } else if result.success {
                Some("pid_written".to_string())
            } else {
                Some("spawn_failed".to_string())
            }
        }
        "status" => Some("status_complete".to_string()),
        "sync_node" => Some(if result.success {
            "sync_complete".to_string()
        } else {
            "sync_failed".to_string()
        }),
        "reset_chain" => Some(if result.success {
            "reset_complete".to_string()
        } else {
            "reset_failed".to_string()
        }),
        "validator_vpn_status" => Some("validator_vpn_status_complete".to_string()),
        "validator_vpn_prepare" => Some(if result.success {
            "validator_vpn_prepare_complete".to_string()
        } else {
            "validator_vpn_prepare_failed".to_string()
        }),
        "validator_vpn_apply_latest" | "validator_vpn_poll" => Some(if result.success {
            "validator_vpn_apply_complete".to_string()
        } else {
            "validator_vpn_apply_failed".to_string()
        }),
        _ => Some("completed".to_string()),
    };

    Ok(TestnetAgentControlResponse {
        node_slot_id,
        action: normalized_action,
        success: result.success,
        exit_code: result.exit_code,
        stdout: result.stdout,
        stderr: result.stderr,
        transport: "testnet-agent".to_string(),
        executed_at_utc: Utc::now().to_rfc3339(),
        phase,
        job_id: None,
        process_alive,
    })
}

#[derive(Debug)]
struct CommandOutcome {
    success: bool,
    exit_code: i32,
    stdout: String,
    stderr: String,
}

fn normalize_action(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace(' ', "_")
}

fn trigger_explorer_reset(
    endpoint: Option<&str>,
    reason: Option<&str>,
) -> Result<CommandOutcome, String> {
    let endpoint = endpoint
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "target_url is required for explorer_reset".to_string())?;
    let reason = reason
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("chain_reset");
    let parsed =
        Url::parse(endpoint).map_err(|error| format!("Invalid explorer reset URL: {error}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| "Explorer reset URL is missing a hostname".to_string())?
        .to_string();
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| "Explorer reset URL is missing a known port".to_string())?;
    let payload = json!({
        "action": "reindex_from_genesis",
        "reason": reason,
        "timestamp_utc": Utc::now().to_rfc3339(),
    });

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("Failed to build async runtime for explorer reset: {error}"))?;

    let (transport, body) = runtime.block_on(async move {
        let loopback_client = Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .resolve(&host, SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
            .build()
            .map_err(|error| format!("Failed to build loopback HTTP client: {error}"))?;

        match loopback_client.post(endpoint).json(&payload).send().await {
            Ok(response) if response.status().is_success() => {
                let body = response.text().await.unwrap_or_default();
                return Ok((format!("loopback-resolve({host})"), body));
            }
            Ok(response) => {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                eprintln!("Explorer reset loopback attempt returned HTTP {status}: {body}");
            }
            Err(error) => {
                eprintln!("Explorer reset loopback attempt failed: {error}");
            }
        }

        let direct_client = Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|error| format!("Failed to build direct HTTP client: {error}"))?;
        let response = direct_client
            .post(endpoint)
            .json(&payload)
            .send()
            .await
            .map_err(|error| format!("Explorer reset direct request failed: {error}"))?;
        if response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            Ok(("direct".to_string(), body))
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(format!("Explorer reset returned HTTP {status}: {body}"))
        }
    })?;

    Ok(CommandOutcome {
        success: true,
        exit_code: 0,
        stdout: format!("Explorer reset accepted via {transport}\n{body}"),
        stderr: String::new(),
    })
}

fn is_allowed_remote(ip: IpAddr) -> bool {
    if is_loopback_address(ip) {
        return true;
    }
    match ip.to_owned() {
        IpAddr::V4(ip) => is_allowed_remote_v4(ip),
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(is_allowed_remote_v4)
            .unwrap_or(false),
    }
}

fn is_allowed_remote_v4(ip: Ipv4Addr) -> bool {
    let allowed = parse_allowed_remotes(std::env::var(TESTNET_AGENT_ALLOWED_REMOTES_ENV).ok());
    allowed.iter().any(|entry| entry.contains(ip))
}

fn is_authorized_control_request(remote_addr: SocketAddr, headers: &HeaderMap) -> bool {
    if is_loopback_address(remote_addr.ip()) {
        return true;
    }

    let expected = std::env::var(TESTNET_AGENT_TOKEN_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let Some(expected) = expected else {
        return false;
    };

    parse_bearer_token(headers)
        .as_deref()
        .map(str::trim)
        .is_some_and(|token| token == expected)
}

fn parse_bearer_token(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(AUTHORIZATION)?;
    let header = raw.to_str().ok()?.trim();
    if header.len() <= 7 {
        return None;
    }
    if !header[..7].eq_ignore_ascii_case("bearer ") {
        return None;
    }

    let token = header[7..].trim();
    (!token.is_empty()).then(|| token.to_string())
}

#[cfg_attr(not(test), allow(dead_code))]
fn parse_allowed_remotes(value: Option<String>) -> Vec<Ipv4AddressRange> {
    let raw = value.unwrap_or_default();
    raw.split(|ch| matches!(ch, ',' | ' ' | ';' | '\n' | '\t'))
        .filter_map(|entry| parse_allowed_remote_entry(entry))
        .collect()
}

fn parse_allowed_remote_entry(entry: &str) -> Option<Ipv4AddressRange> {
    let entry = entry.trim();
    if entry.is_empty() {
        return None;
    }

    let (addr, prefix) = if let Some((addr, prefix)) = entry.split_once('/') {
        (addr, Some(prefix))
    } else {
        (entry, None)
    };

    let network = addr.parse::<Ipv4Addr>().ok()?;
    let prefix = match prefix {
        Some(prefix) => {
            let prefix = prefix.parse::<u8>().ok()?;
            if prefix > 32 {
                return None;
            }
            prefix
        }
        None => 32,
    };
    Some(Ipv4AddressRange::from_network(network, prefix))
}

fn is_loopback_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => {
            ip.is_loopback() || ip.to_ipv4_mapped().is_some_and(|addr| addr.is_loopback())
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Ipv4AddressRange {
    network: u32,
    prefix: u8,
}

impl Ipv4AddressRange {
    fn from_network(network: Ipv4Addr, prefix: u8) -> Self {
        let mask = Self::prefix_to_mask(prefix);
        Self {
            network: u32::from(network) & mask,
            prefix,
        }
    }

    fn prefix_to_mask(prefix: u8) -> u32 {
        if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        }
    }

    fn contains(&self, ip: Ipv4Addr) -> bool {
        let mask = Self::prefix_to_mask(self.prefix);
        (u32::from(ip) & mask) == self.network
    }
}

fn load_inventory_nodes(workspace_root: &Path) -> Result<Vec<InventoryNode>, String> {
    let inventory_path = workspace_root.join("testnet/runtime/node-inventory.csv");
    let content = fs::read_to_string(&inventory_path).map_err(|error| {
        format!(
            "Failed to read inventory {}: {error}",
            inventory_path.display()
        )
    })?;
    let mut lines = content.lines();
    let header = lines
        .next()
        .ok_or_else(|| format!("Inventory file is empty: {}", inventory_path.display()))?;
    let headers = header
        .split(',')
        .map(|entry| entry.trim().to_string())
        .collect::<Vec<_>>();

    let column = |aliases: &[&str], label: &str| -> Result<usize, String> {
        aliases
            .iter()
            .find_map(|alias| {
                headers
                    .iter()
                    .position(|header| header.eq_ignore_ascii_case(alias))
            })
            .ok_or_else(|| format!("Inventory column '{label}' is missing"))
    };

    let node_slot_idx = column(&["node_slot_id", "machine_id"], "node_slot_id")?;
    let host_idx = column(&["host"], "host")?;
    let management_host_idx = column(&["management_host"], "management_host")?;
    let public_ip_idx = headers
        .iter()
        .position(|header| header.eq_ignore_ascii_case("public_ip"));
    let local_ip_idx = headers
        .iter()
        .position(|header| header.eq_ignore_ascii_case("local_ip"));
    let physical_idx = column(
        &["physical_machine_id", "physical_machine"],
        "physical_machine_id",
    )?;

    let mut nodes = Vec::new();
    for raw_line in lines {
        if raw_line.trim().is_empty() {
            continue;
        }
        let values = raw_line
            .split(',')
            .map(|entry| entry.trim().trim_end_matches('\r').to_string())
            .collect::<Vec<_>>();
        let get = |index: usize| values.get(index).cloned().unwrap_or_default();
        let node_slot_id = get(node_slot_idx);
        if node_slot_id.is_empty() {
            continue;
        }
        nodes.push(InventoryNode {
            node_slot_id,
            host: get(host_idx),
            management_host: get(management_host_idx),
            public_ip: public_ip_idx.map(&get).unwrap_or_default(),
            local_ip: local_ip_idx.map(&get).unwrap_or_default(),
            physical_machine_id: get(physical_idx),
        });
    }

    Ok(nodes)
}

fn installed_node_slots(workspace_root: &Path, inventory: &[InventoryNode]) -> Vec<String> {
    let mut installed = inventory
        .iter()
        .filter_map(|node| {
            resolve_node_install(workspace_root, node.node_slot_id.as_str())
                .ok()
                .filter(|install| install_dir_has_runtime_state(&install.install_dir))
                .map(|install| {
                    (
                        node.node_slot_id.clone(),
                        install_dir_runtime_timestamp(&install.install_dir),
                    )
                })
        })
        .collect::<Vec<_>>();

    installed.sort_by(|left, right| left.1.cmp(&right.1).then(left.0.cmp(&right.0)));
    installed.into_iter().map(|entry| entry.0).collect()
}

fn legacy_workspace_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(home_dir) = dirs::home_dir().or_else(dirs::data_dir) {
        roots.push(
            home_dir
                .join(".synergy-node-monitor")
                .join("monitor-workspace"),
        );
    }
    roots
}

fn default_agent_install_directory(workspace_root: &Path, node_slot_id: &str) -> String {
    if cfg!(target_os = "windows") {
        format!("{DEFAULT_REMOTE_ROOT_WINDOWS}\\{node_slot_id}")
    } else if cfg!(target_os = "linux") {
        format!("{DEFAULT_REMOTE_ROOT_UNIX}/{node_slot_id}")
    } else {
        workspace_root
            .join("testnet/runtime/installers")
            .join(node_slot_id)
            .to_string_lossy()
            .to_string()
    }
}

fn install_candidates(workspace_root: &Path, node_slot_id: &str) -> Result<Vec<PathBuf>, String> {
    let hosts_env = parse_hosts_env(workspace_root.join("testnet/runtime/hosts.env"))?;
    let key_prefix = node_slot_id.to_ascii_uppercase().replace('-', "_");
    let remote_dir_key = format!("{key_prefix}_REMOTE_DIR");
    let remote_dir = hosts_env
        .get(&remote_dir_key)
        .cloned()
        .or_else(|| {
            hosts_env.get("SYNERGY_REMOTE_ROOT").map(|root| {
                PathBuf::from(root)
                    .join(node_slot_id)
                    .to_string_lossy()
                    .to_string()
            })
        })
        .unwrap_or_else(|| default_agent_install_directory(workspace_root, node_slot_id));

    let mut candidates = Vec::new();
    candidates.push(PathBuf::from(remote_dir));
    candidates.push(
        workspace_root
            .join("testnet/runtime/installers")
            .join(node_slot_id),
    );
    for legacy_root in legacy_workspace_roots() {
        candidates.push(
            legacy_root
                .join("testnet/runtime/installers")
                .join(node_slot_id),
        );
    }

    let mut deduped = Vec::new();
    for candidate in candidates {
        if !deduped
            .iter()
            .any(|existing: &PathBuf| existing == &candidate)
        {
            deduped.push(candidate);
        }
    }

    Ok(deduped)
}

fn is_process_running_for_install_dir(install_dir: &Path) -> bool {
    #[cfg(target_os = "windows")]
    {
        let install_path = install_dir.to_string_lossy().replace('\'', "''");
        let script = format!(
            "$target = '{install_path}'; $match = Get-CimInstance Win32_Process | Where-Object {{ $_.CommandLine -and $_.CommandLine.Contains($target) }} | Select-Object -First 1; if ($match) {{ exit 0 }} else {{ exit 1 }}"
        );
        return ProcessCommand::new("powershell")
            .args([
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                &script,
            ])
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
    }

    #[cfg(not(target_os = "windows"))]
    {
        let install_path = install_dir.to_string_lossy().to_string();
        ProcessCommand::new("pgrep")
            .args(["-f", &install_path])
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }
}

fn resolve_node_install(workspace_root: &Path, node_slot_id: &str) -> Result<NodeInstall, String> {
    let candidates = install_candidates(workspace_root, node_slot_id)?;
    let existing_candidates = candidates
        .into_iter()
        .filter(|candidate| candidate.join("node.env").is_file())
        .collect::<Vec<_>>();

    let install_dir = existing_candidates
        .iter()
        .find(|candidate| is_process_running_for_install_dir(candidate))
        .cloned()
        .or_else(|| existing_candidates.first().cloned())
        .ok_or_else(|| {
            format!(
                "No local installer directory found for {node_slot_id}. Expected node.env in workspace installer, legacy workspace, or configured remote root."
            )
        })?;

    Ok(NodeInstall {
        node_slot_id: node_slot_id.to_string(),
        install_dir,
    })
}

fn install_dir_has_runtime_state(install_dir: &Path) -> bool {
    let data_dir = install_dir.join("data");
    let runtime_markers = [
        data_dir.join(".installed_at"),
        data_dir.join("node.pid"),
        data_dir.join("chain.json"),
        data_dir.join("token_state.json"),
        data_dir.join("validator_registry.json"),
        data_dir.join("logs/node.out"),
        data_dir.join("logs/node.err"),
    ];

    runtime_markers.iter().any(|path| path.exists())
        || is_process_running_for_install_dir(install_dir)
}

fn install_dir_runtime_timestamp(install_dir: &Path) -> u64 {
    let data_dir = install_dir.join("data");
    let candidates = [
        data_dir.join(".installed_at"),
        data_dir.join("node.pid"),
        data_dir.join("logs/node.out"),
        data_dir.join("logs/node.err"),
        data_dir.join("chain.json"),
        data_dir.join("validator_registry.json"),
    ];

    candidates
        .iter()
        .filter_map(|path| fs::metadata(path).ok())
        .filter_map(|meta| meta.modified().ok())
        .filter_map(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs())
        .min()
        .unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_secs())
                .unwrap_or(0)
        })
}

fn parse_hosts_env(path: PathBuf) -> Result<HashMap<String, String>, String> {
    if !path.is_file() {
        return Ok(HashMap::new());
    }

    let content = fs::read_to_string(&path)
        .map_err(|error| format!("Failed to read hosts env {}: {error}", path.display()))?;
    let mut output = HashMap::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let normalized = trimmed.strip_prefix("export ").unwrap_or(trimmed).trim();
        let Some((key, value)) = normalized.split_once('=') else {
            continue;
        };
        output.insert(key.trim().to_string(), strip_env_quotes(value.trim()));
    }
    Ok(output)
}

fn strip_env_quotes(value: &str) -> String {
    if value.len() >= 2 {
        let first = value.as_bytes()[0] as char;
        let last = value.as_bytes()[value.len() - 1] as char;
        if (first == '\'' && last == '\'') || (first == '"' && last == '"') {
            return value[1..value.len() - 1].to_string();
        }
    }
    value.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static TEST_ENV_MUTEX: Mutex<()> = Mutex::new(());

    fn with_env_vars<F>(vars: &[(&str, Option<&str>)], test: F)
    where
        F: FnOnce(),
    {
        let _guard = TEST_ENV_MUTEX.lock().unwrap();
        let originals = vars
            .iter()
            .map(|(key, _)| (key.to_string(), std::env::var(key).ok()))
            .collect::<Vec<_>>();

        for (key, value) in vars {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }

        test();

        for (key, original) in originals {
            match original {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }

    #[test]
    fn bind_addresses_default_to_loopback_only() {
        let addresses = bind_addresses_for_host(None, TESTNET_AGENT_PORT)
            .expect("default bind addresses should be resolvable");
        assert_eq!(
            addresses,
            vec![SocketAddr::from(([127, 0, 0, 1], TESTNET_AGENT_PORT))]
        );
    }

    #[test]
    fn bind_addresses_invalid_host_is_rejected() {
        assert!(
            bind_addresses_for_host(Some("not-an-ip"), TESTNET_AGENT_PORT).is_err(),
            "invalid host should fail closed"
        );
    }

    #[test]
    fn private_ip_rejected_without_allowlist() {
        with_env_vars(&[(TESTNET_AGENT_ALLOWED_REMOTES_ENV, None)], || {
            assert!(!is_allowed_remote_v4(Ipv4Addr::new(192, 168, 1, 42)));
            assert!(!is_allowed_remote(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        });
    }

    #[test]
    fn allowlist_can_express_exact_ips_and_cidr() {
        with_env_vars(
            &[(
                TESTNET_AGENT_ALLOWED_REMOTES_ENV,
                Some("203.0.113.9,198.51.100.0/24"),
            )],
            || {
                assert!(is_allowed_remote(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))));
                assert!(is_allowed_remote(IpAddr::V4(Ipv4Addr::new(
                    198, 51, 100, 20
                ))));
                assert!(!is_allowed_remote(IpAddr::V4(Ipv4Addr::new(
                    198, 51, 101, 1
                ))));
            },
        );
    }

    #[test]
    fn control_request_without_token_is_rejected_for_remote_callers() {
        with_env_vars(
            &[
                (TESTNET_AGENT_ALLOWED_REMOTES_ENV, Some("198.18.0.10")),
                (TESTNET_AGENT_TOKEN_ENV, None),
            ],
            || {
                let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 10)), 1234);
                let headers = HeaderMap::new();
                assert!(!is_authorized_control_request(remote, &headers));
            },
        );
    }

    #[test]
    fn control_request_accepts_bearer_token_for_non_loopback() {
        with_env_vars(
            &[
                (TESTNET_AGENT_ALLOWED_REMOTES_ENV, Some("198.18.0.20")),
                (TESTNET_AGENT_TOKEN_ENV, Some("agent-secret")),
            ],
            || {
                let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 20)), 1234);
                let mut headers = HeaderMap::new();
                headers.insert(
                    AUTHORIZATION,
                    "Bearer agent-secret".parse().expect("authorization header"),
                );

                assert!(is_authorized_control_request(remote, &headers));
            },
        );
    }

    #[test]
    fn validator_vpn_agent_env_uses_packaged_workspace_paths() {
        with_env_vars(
            &[
                ("VALIDATOR_VPN_COORDINATOR_URL", None),
                ("SYNERGY_VALIDATOR_VPN_COORDINATOR_URL", None),
            ],
            || {
                let workspace = tempfile::tempdir().expect("workspace tempdir");
                let workspace_path = workspace.path();
                let vpn_dir = workspace_path
                    .join("testnet")
                    .join("runtime")
                    .join("validator-vpn")
                    .join("agent");
                let expected_vpn_dir = vpn_dir.to_string_lossy().to_string();
                let expected_private_key =
                    vpn_dir.join("private.key").to_string_lossy().to_string();
                let expected_snapshot = vpn_dir
                    .join("latest-snapshot.json")
                    .to_string_lossy()
                    .to_string();
                let env = validator_vpn_agent_env(workspace_path)
                    .into_iter()
                    .collect::<HashMap<_, _>>();

                assert_eq!(
                    env.get("VALIDATOR_VPN_DIR").map(String::as_str),
                    Some(expected_vpn_dir.as_str())
                );
                assert_eq!(
                    env.get("VALIDATOR_VPN_PRIVATE_KEY").map(String::as_str),
                    Some(expected_private_key.as_str())
                );
                assert_eq!(
                    env.get("VALIDATOR_VPN_SNAPSHOT_PATH").map(String::as_str),
                    Some(expected_snapshot.as_str())
                );
                assert_eq!(
                    env.get("VALIDATOR_VPN_ALLOW_ADMIN_PROMPT")
                        .map(String::as_str),
                    Some("1")
                );
                assert_eq!(
                    env.get("VALIDATOR_VPN_COORDINATOR_URL").map(String::as_str),
                    Some(DEFAULT_VALIDATOR_VPN_COORDINATOR_URL)
                );
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;

                    let metadata = fs::metadata(workspace_path).expect("workspace metadata");
                    let expected_uid = metadata.uid().to_string();
                    let expected_gid = metadata.gid().to_string();
                    assert_eq!(
                        env.get("VALIDATOR_VPN_RESULT_OWNER_UID")
                            .map(String::as_str),
                        Some(expected_uid.as_str())
                    );
                    assert_eq!(
                        env.get("VALIDATOR_VPN_RESULT_OWNER_GID")
                            .map(String::as_str),
                        Some(expected_gid.as_str())
                    );
                }
            },
        );
    }

    #[test]
    fn packaged_validator_vpn_coordinator_url_prefers_installer_env() {
        with_env_vars(
            &[
                ("VALIDATOR_VPN_COORDINATOR_URL", None),
                (
                    "SYNERGY_VALIDATOR_VPN_COORDINATOR_URL",
                    Some("https://installer-vpn.example"),
                ),
            ],
            || {
                assert_eq!(
                    packaged_validator_vpn_coordinator_url(),
                    "https://installer-vpn.example"
                );
            },
        );
    }

    #[test]
    fn packaged_validator_vpn_public_key_prefers_agent_specific_value() {
        with_env_vars(
            &[
                (
                    "VALIDATOR_VPN_COORDINATOR_PUBLIC_KEY",
                    Some("ed25519:agent"),
                ),
                (
                    "SYNERGY_VALIDATOR_VPN_COORDINATOR_PUBLIC_KEY",
                    Some("ed25519:packaged"),
                ),
            ],
            || {
                assert_eq!(
                    packaged_validator_vpn_coordinator_public_key().as_deref(),
                    Some("ed25519:agent")
                );
            },
        );
    }

    #[test]
    fn packaged_validator_vpn_public_key_falls_back_to_synergy_config() {
        with_env_vars(
            &[
                ("VALIDATOR_VPN_COORDINATOR_PUBLIC_KEY", None),
                (
                    "SYNERGY_VALIDATOR_VPN_COORDINATOR_PUBLIC_KEY",
                    Some("ed25519:packaged"),
                ),
            ],
            || {
                assert_eq!(
                    packaged_validator_vpn_coordinator_public_key().as_deref(),
                    Some("ed25519:packaged")
                );
            },
        );
    }
}

fn sync_workspace_installer(workspace_root: &Path, install: &NodeInstall) -> Result<(), String> {
    let source = workspace_root
        .join("testnet/runtime/installers")
        .join(&install.node_slot_id);
    if !source.is_dir() || source == install.install_dir {
        return Ok(());
    }

    copy_directory_force(&source, &install.install_dir)
}

#[cfg(not(target_os = "windows"))]
fn read_pid_cmdline(pid: &str) -> Option<String> {
    let proc_path = PathBuf::from(format!("/proc/{pid}/cmdline"));
    if proc_path.is_file() {
        let bytes = fs::read(proc_path).ok()?;
        let joined = bytes
            .split(|byte| *byte == 0)
            .filter(|part| !part.is_empty())
            .map(|part| String::from_utf8_lossy(part).to_string())
            .collect::<Vec<_>>()
            .join(" ");
        if !joined.is_empty() {
            return Some(joined);
        }
    }

    let output = ProcessCommand::new("ps")
        .args(["-p", pid, "-o", "command="])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

#[cfg(not(target_os = "windows"))]
fn read_pid_cwd(pid: &str) -> Option<PathBuf> {
    let proc_path = PathBuf::from(format!("/proc/{pid}/cwd"));
    if proc_path.exists() {
        return fs::read_link(proc_path).ok();
    }

    let output = ProcessCommand::new("lsof")
        .args(["-a", "-p", pid, "-d", "cwd", "-Fn"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.strip_prefix('n'))
        .map(PathBuf::from)
}

#[cfg(not(target_os = "windows"))]
fn pid_matches_install(install: &NodeInstall, pid: &str) -> bool {
    let Some(cmdline) = read_pid_cmdline(pid) else {
        return false;
    };
    if !cmdline.contains("synergy-testnet") || cmdline.contains("synergy-testnet-agent") {
        return false;
    }

    let config_path = install
        .install_dir
        .join("config/node.toml")
        .to_string_lossy()
        .to_string();
    if cmdline.contains(&config_path) {
        return true;
    }

    if !cmdline.contains("--config config/node.toml") {
        return false;
    }

    read_pid_cwd(pid)
        .map(|cwd| cwd == install.install_dir)
        .unwrap_or(false)
}

#[cfg(not(target_os = "windows"))]
fn matching_node_pids(install: &NodeInstall) -> Vec<String> {
    let mut matches = Vec::new();
    let pid_file = install.install_dir.join("data/node.pid");
    if let Ok(contents) = fs::read_to_string(&pid_file) {
        let pid = contents.trim();
        if !pid.is_empty() && pid_matches_install(install, pid) {
            matches.push(pid.to_string());
            return matches;
        }
    }

    let Ok(output) = ProcessCommand::new("pgrep")
        .args(["-f", "synergy-testnet"])
        .output()
    else {
        return matches;
    };
    if !output.status.success() {
        return matches;
    }

    for pid in String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|pid| !pid.is_empty())
    {
        if pid_matches_install(install, pid) {
            matches.push(pid.to_string());
        }
    }

    matches
}

/// Checks if a node process is actually running, independent of PID files.
/// Detects both correctly launched processes with absolute config paths and
/// older relative-path launches whose working directory is the install root.
fn is_node_process_running(install: &NodeInstall) -> bool {
    #[cfg(not(target_os = "windows"))]
    {
        !matching_node_pids(install).is_empty()
    }

    #[cfg(target_os = "windows")]
    {
        let install_path = install.install_dir.to_string_lossy().replace('\'', "''");
        let script = format!(
            "$target = '{install_path}'; $p = Get-CimInstance Win32_Process | Where-Object {{ $_.CommandLine -and $_.CommandLine.Contains($target) }}; if ($p) {{ exit 0 }} else {{ exit 1 }}"
        );
        match ProcessCommand::new("powershell")
            .args([
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                &script,
            ])
            .output()
        {
            Ok(output) => output.status.success(),
            Err(_) => false,
        }
    }
}

/// Kill any lingering node processes associated with this install directory.
/// This handles the case where the node is running but has no PID file (e.g.
/// it was started manually, the PID file was deleted, or the file got out of sync).
/// nodectl stop_node silently exits when the PID file is missing, so this is the
/// safety net that ensures the old process is truly gone before we wipe chain data.
fn force_kill_node_processes(install: &NodeInstall) {
    #[cfg(not(target_os = "windows"))]
    {
        let live_pids = matching_node_pids(install);
        for pid in &live_pids {
            let _ = ProcessCommand::new("kill").args(["-TERM", pid]).output();
        }
        std::thread::sleep(std::time::Duration::from_millis(1500));

        for pid in matching_node_pids(install) {
            let _ = ProcessCommand::new("kill").args(["-KILL", &pid]).output();
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    #[cfg(target_os = "windows")]
    {
        let install_path = install.install_dir.to_string_lossy().replace('\'', "''");
        let script = format!(
            "$target = '{install_path}'; Get-CimInstance Win32_Process | Where-Object {{ $_.CommandLine -and $_.CommandLine.Contains($target) }} | ForEach-Object {{ Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }}"
        );
        let _ = ProcessCommand::new("powershell")
            .args([
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                &script,
            ])
            .output();
        std::thread::sleep(std::time::Duration::from_millis(1500));
    }
}

fn reset_chain(workspace_root: &Path, install: &NodeInstall) -> Result<CommandOutcome, String> {
    let _ = run_nodectl(install, "stop");
    // Belt-and-suspenders: kill any orphaned process that nodectl may have missed
    // (e.g. node started outside nodectl so it has no PID file).
    force_kill_node_processes(install);
    sync_workspace_installer(workspace_root, install)?;

    let data_dir = install.install_dir.join("data");
    let node_data_dir = data_dir.join("testnet15").join(&install.node_slot_id);
    let targets = [
        data_dir.join("chain"),
        node_data_dir.join("chain"),
        node_data_dir.join("logs"),
        data_dir.join("chain.json"),
        data_dir.join("token_state.json"),
        data_dir.join("validator_registry.json"),
        data_dir.join("committed_qcs.json"),
        data_dir.join("committed_qcs.json.tmp"),
        data_dir.join("canonical_locks.json"),
        data_dir.join("canonical_locks.json.tmp"),
        data_dir.join("consensus_vote_locks.json"),
        data_dir.join("consensus_vote_locks.json.tmp"),
        data_dir.join("dag_state.json"),
        node_data_dir.join("committed_qcs.json"),
        node_data_dir.join("committed_qcs.json.tmp"),
        node_data_dir.join("canonical_locks.json"),
        node_data_dir.join("canonical_locks.json.tmp"),
        node_data_dir.join("consensus_vote_locks.json"),
        node_data_dir.join("consensus_vote_locks.json.tmp"),
        node_data_dir.join("dag_state.json"),
        data_dir.join("synergy-testnet.pid"),
        data_dir.join(".reset_flag"),
        data_dir.join("node.pid"),
    ];

    for target in targets {
        if target.is_dir() {
            fs::remove_dir_all(&target).map_err(|error| {
                format!(
                    "Failed to remove {} during reset: {error}",
                    target.display()
                )
            })?;
        } else if target.is_file() {
            fs::remove_file(&target).map_err(|error| {
                format!(
                    "Failed to remove {} during reset: {error}",
                    target.display()
                )
            })?;
        }
    }

    fs::create_dir_all(data_dir.join("chain"))
        .map_err(|error| format!("Failed to recreate chain dir: {error}"))?;
    fs::create_dir_all(node_data_dir.join("chain"))
        .map_err(|error| format!("Failed to recreate node chain dir: {error}"))?;
    fs::create_dir_all(node_data_dir.join("logs"))
        .map_err(|error| format!("Failed to recreate node log dir: {error}"))?;
    fs::create_dir_all(data_dir.join("logs"))
        .map_err(|error| format!("Failed to recreate shared log dir: {error}"))?;

    // Verify chain data was actually deleted — fail hard if not.
    let chain_dir = data_dir.join("chain");
    if chain_dir.is_dir() {
        let has_files = fs::read_dir(&chain_dir)
            .map(|mut entries| entries.next().is_some())
            .unwrap_or(false);
        if has_files {
            return Err(format!(
                "Chain directory still contains files after reset for {}",
                install.node_slot_id
            ));
        }
    }
    for check_file in &[
        "chain.json",
        "token_state.json",
        "validator_registry.json",
        "committed_qcs.json",
        "canonical_locks.json",
        "consensus_vote_locks.json",
        "dag_state.json",
    ] {
        if data_dir.join(check_file).exists() {
            return Err(format!(
                "{} still exists after reset for {}",
                check_file, install.node_slot_id
            ));
        }
    }

    // Node is intentionally NOT restarted after reset. User should use
    // "Start All" from the control panel dashboard when all nodes are
    // confirmed reset.
    Ok(CommandOutcome {
        success: true,
        exit_code: 0,
        stdout: format!(
            "Cleared chain state for {}. Node is stopped and ready for manual start.",
            install.node_slot_id
        ),
        stderr: String::new(),
    })
}

#[allow(dead_code)]
fn run_install_script(install: &NodeInstall) -> Result<CommandOutcome, String> {
    #[cfg(target_os = "windows")]
    let output = ProcessCommand::new("powershell")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            install
                .install_dir
                .join("install_and_start.ps1")
                .to_string_lossy()
                .as_ref(),
        ])
        .current_dir(&install.install_dir)
        .output()
        .map_err(|error| format!("Failed to run install script: {error}"))?;

    #[cfg(not(target_os = "windows"))]
    let output = ProcessCommand::new("bash")
        .arg(install.install_dir.join("install_and_start.sh"))
        .current_dir(&install.install_dir)
        .output()
        .map_err(|error| format!("Failed to run install script: {error}"))?;

    Ok(CommandOutcome {
        success: output.status.success(),
        exit_code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

fn run_nodectl(install: &NodeInstall, action: &str) -> Result<CommandOutcome, String> {
    #[cfg(target_os = "windows")]
    let output = ProcessCommand::new("powershell")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            install
                .install_dir
                .join("nodectl.ps1")
                .to_string_lossy()
                .as_ref(),
            action,
        ])
        .current_dir(&install.install_dir)
        .output()
        .map_err(|error| format!("Failed to run nodectl action '{action}': {error}"))?;

    #[cfg(not(target_os = "windows"))]
    let output = ProcessCommand::new("bash")
        .arg(install.install_dir.join("nodectl.sh"))
        .arg(action)
        .current_dir(&install.install_dir)
        .output()
        .map_err(|error| format!("Failed to run nodectl action '{action}': {error}"))?;

    Ok(CommandOutcome {
        success: output.status.success(),
        exit_code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

fn run_validator_vpn_agent(
    workspace_root: &Path,
    args: &[&str],
    public_key: Option<&str>,
) -> Result<CommandOutcome, String> {
    let script = workspace_root
        .join("scripts")
        .join("testnet")
        .join("validator-vpn-agent.sh");
    if !script.is_file() {
        return Err(format!(
            "Validator VPN agent helper not found at {}",
            script.display()
        ));
    }
    let mut command = ProcessCommand::new("bash");
    command.arg(&script).args(args).current_dir(workspace_root);
    command.env("PATH", validator_vpn_tool_path());
    for (key, value) in validator_vpn_agent_env(workspace_root) {
        command.env(key, value);
    }
    if let Some(public_key) = public_key.map(str::trim).filter(|value| !value.is_empty()) {
        command.env("VALIDATOR_VPN_COORDINATOR_PUBLIC_KEY", public_key);
    } else if let Some(public_key) = packaged_validator_vpn_coordinator_public_key() {
        command.env("VALIDATOR_VPN_COORDINATOR_PUBLIC_KEY", public_key);
    }
    if let Some(token) = packaged_validator_vpn_coordinator_token() {
        command.env("VALIDATOR_VPN_COORDINATOR_TOKEN", token);
    }
    let output = command
        .output()
        .map_err(|error| format!("Failed to run validator VPN agent action: {error}"))?;

    Ok(CommandOutcome {
        success: output.status.success(),
        exit_code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

fn validator_vpn_tool_path() -> String {
    let existing = std::env::var("PATH").unwrap_or_default();
    let preferred = "/opt/homebrew/bin:/usr/local/bin:/usr/sbin:/sbin:/usr/bin:/bin";
    if existing.trim().is_empty() {
        preferred.to_string()
    } else {
        format!("{preferred}:{existing}")
    }
}

fn validator_vpn_agent_env(workspace_root: &Path) -> Vec<(&'static str, String)> {
    let vpn_dir = workspace_root
        .join("testnet")
        .join("runtime")
        .join("validator-vpn")
        .join("agent");
    let mut env = vec![
        ("VALIDATOR_VPN_DIR", vpn_dir.to_string_lossy().to_string()),
        (
            "VALIDATOR_VPN_PRIVATE_KEY",
            vpn_dir.join("private.key").to_string_lossy().to_string(),
        ),
        (
            "VALIDATOR_VPN_PUBLIC_KEY",
            vpn_dir.join("public.key").to_string_lossy().to_string(),
        ),
        (
            "VALIDATOR_VPN_STATE_PATH",
            vpn_dir
                .join("agent-state.json")
                .to_string_lossy()
                .to_string(),
        ),
        (
            "VALIDATOR_VPN_SNAPSHOT_PATH",
            vpn_dir
                .join("latest-snapshot.json")
                .to_string_lossy()
                .to_string(),
        ),
        ("VALIDATOR_VPN_ALLOW_ADMIN_PROMPT", "1".to_string()),
        (
            "VALIDATOR_VPN_COORDINATOR_URL",
            packaged_validator_vpn_coordinator_url(),
        ),
    ];
    env.extend(validator_vpn_result_owner_env(&vpn_dir, workspace_root));
    env
}

#[cfg(unix)]
fn validator_vpn_result_owner_env(path: &Path, fallback: &Path) -> Vec<(&'static str, String)> {
    use std::os::unix::fs::MetadataExt;

    fs::metadata(path)
        .or_else(|_| fs::metadata(fallback))
        .map(|metadata| {
            vec![
                ("VALIDATOR_VPN_RESULT_OWNER_UID", metadata.uid().to_string()),
                ("VALIDATOR_VPN_RESULT_OWNER_GID", metadata.gid().to_string()),
            ]
        })
        .unwrap_or_default()
}

#[cfg(not(unix))]
fn validator_vpn_result_owner_env(_path: &Path, _fallback: &Path) -> Vec<(&'static str, String)> {
    Vec::new()
}

fn packaged_validator_vpn_coordinator_url() -> String {
    std::env::var("VALIDATOR_VPN_COORDINATOR_URL")
        .or_else(|_| std::env::var("SYNERGY_VALIDATOR_VPN_COORDINATOR_URL"))
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_VALIDATOR_VPN_COORDINATOR_URL.to_string())
}

fn packaged_validator_vpn_coordinator_public_key() -> Option<String> {
    std::env::var("VALIDATOR_VPN_COORDINATOR_PUBLIC_KEY")
        .or_else(|_| std::env::var("SYNERGY_VALIDATOR_VPN_COORDINATOR_PUBLIC_KEY"))
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn packaged_validator_vpn_coordinator_token() -> Option<String> {
    std::env::var("VALIDATOR_VPN_COORDINATOR_TOKEN")
        .or_else(|_| std::env::var("SYNERGY_VALIDATOR_VPN_COORDINATOR_TOKEN"))
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn detect_local_management_ip(nodes: &[InventoryNode]) -> Option<String> {
    for key in ["SYNERGY_MACHINE_ADDRESS", "SYNERGY_MACHINE_MANAGEMENT_HOST"] {
        if let Ok(value) = std::env::var(key) {
            let trimmed = value.trim();
            if trimmed.parse::<Ipv4Addr>().is_ok() {
                return Some(trimmed.to_string());
            }
        }
    }

    let candidates = gather_local_ips();
    candidates
        .iter()
        .find(|ip| nodes.iter().any(|node| matches_inventory_address(node, ip)))
        .cloned()
        .or_else(|| {
            candidates.into_iter().find(|ip| {
                ip.parse::<Ipv4Addr>()
                    .ok()
                    .map(is_allowed_remote_v4)
                    .unwrap_or(false)
            })
        })
}

fn gather_local_ips() -> Vec<String> {
    #[cfg(target_os = "windows")]
    let command_output = ProcessCommand::new("ipconfig").output().ok();

    #[cfg(not(target_os = "windows"))]
    let command_output = ProcessCommand::new("sh")
        .arg("-lc")
        .arg("ip -o -4 addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 || ifconfig 2>/dev/null | awk '/inet /{print $2}'")
        .output()
        .ok();

    let raw = command_output
        .as_ref()
        .map(|output| String::from_utf8_lossy(&output.stdout).to_string())
        .unwrap_or_default();

    raw.lines()
        .flat_map(|line| line.split_whitespace())
        .map(|entry| {
            entry
                .trim()
                .trim_matches(|ch: char| ch == ':' || ch == '(' || ch == ')')
        })
        .filter(|entry| entry.parse::<Ipv4Addr>().is_ok())
        .map(|entry| entry.to_string())
        .collect()
}

fn matches_inventory_address(node: &InventoryNode, value: &str) -> bool {
    let target = value.trim();
    !target.is_empty()
        && [
            node.management_host.as_str(),
            node.host.as_str(),
            node.public_ip.as_str(),
            node.local_ip.as_str(),
        ]
        .into_iter()
        .any(|candidate| !candidate.trim().is_empty() && candidate.eq_ignore_ascii_case(target))
}

fn copy_directory_force(source: &Path, destination: &Path) -> Result<(), String> {
    if !source.is_dir() {
        return Err(format!("Directory missing: {}", source.display()));
    }

    fs::create_dir_all(destination).map_err(|error| {
        format!(
            "Failed to create destination directory {}: {error}",
            destination.display()
        )
    })?;

    for entry in fs::read_dir(source)
        .map_err(|error| format!("Failed to read {}: {error}", source.display()))?
    {
        let entry = entry.map_err(|error| error.to_string())?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if source_path.is_dir() {
            copy_directory_force(&source_path, &destination_path)?;
        } else {
            if let Some(parent) = destination_path.parent() {
                fs::create_dir_all(parent).map_err(|error| {
                    format!(
                        "Failed to create destination parent {}: {error}",
                        parent.display()
                    )
                })?;
            }
            fs::copy(&source_path, &destination_path).map_err(|error| {
                format!(
                    "Failed to copy {} to {}: {error}",
                    source_path.display(),
                    destination_path.display()
                )
            })?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if destination_path
                    .extension()
                    .and_then(|entry| entry.to_str())
                    .is_none()
                    || matches!(
                        destination_path
                            .extension()
                            .and_then(|entry| entry.to_str()),
                        Some("sh")
                    )
                {
                    let _ =
                        fs::set_permissions(&destination_path, fs::Permissions::from_mode(0o755));
                }
            }
        }
    }

    Ok(())
}
