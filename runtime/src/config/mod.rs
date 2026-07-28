use serde::{Deserialize, Serialize};
use serde_json;
use std::env;
use std::error::Error;
use std::fs;
use std::path::Path;
use toml;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct NodeConfig {
    pub network: NetworkConfig,
    pub blockchain: BlockchainConfig,
    pub consensus: ConsensusConfig,
    pub logging: LoggingConfig,
    pub rpc: RPCConfig,
    pub p2p: P2PConfig,
    pub storage: StorageConfig,
    #[serde(default)]
    pub node: NodeSettings,
    #[serde(default)]
    pub identity: IdentityConfig,
    #[serde(default)]
    pub role: RoleConfig,
    #[serde(default)]
    pub validator: ValidatorConfig,
    #[serde(default)]
    pub telemetry: TelemetryConfig,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct NetworkConfig {
    pub id: u64,
    #[serde(default = "default_network_id")]
    pub network_id: String,
    pub name: String,
    pub p2p_port: u16,
    pub rpc_port: u16,
    pub ws_port: u16,
    pub max_peers: u32,
    #[serde(default)]
    pub bootnodes: Vec<String>,
    #[serde(default)]
    pub seed_servers: Vec<String>,
    #[serde(default)]
    pub bootstrap_dns_records: Vec<String>,
    #[serde(default)]
    pub persistent_peers: Vec<String>,
    #[serde(default)]
    pub additional_dial_targets: Vec<String>,
    #[serde(default)]
    pub validator_vpn_transports: Vec<ValidatorVpnTransportConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct ValidatorVpnTransportConfig {
    pub validator_address: String,
    pub dial_address: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BlockchainConfig {
    pub block_time: u64,
    pub max_gas_limit: String,
    pub chain_id: u64,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ConsensusConfig {
    pub algorithm: String,
    pub block_time_secs: u64,
    pub epoch_length: u64,
    #[serde(default = "default_emergency_stable_committee_mode")]
    pub emergency_stable_committee_mode: bool,
    #[serde(default = "default_freeze_validator_set")]
    pub freeze_validator_set: bool,
    #[serde(default = "default_freeze_score_weighted_proposer_order")]
    pub freeze_score_weighted_proposer_order: bool,
    #[serde(default = "default_vote_only_rejoin_enabled")]
    pub vote_only_rejoin_enabled: bool,
    #[serde(default = "default_vote_only_probation_blocks")]
    pub vote_only_probation_blocks: u64,
    #[serde(default = "default_min_validators")]
    pub min_validators: usize,
    pub validator_cluster_size: usize,
    #[serde(default = "default_validator_vote_threshold")]
    pub validator_vote_threshold: usize,
    #[serde(default = "default_max_validators")]
    pub max_validators: usize,
    #[serde(default = "default_status_ready_gate_enabled")]
    pub status_ready_gate_enabled: bool,
    #[serde(default)]
    pub status_ready_min_validators: usize,
    #[serde(default = "default_status_ready_genesis_grace_secs")]
    pub status_ready_genesis_grace_secs: u64,
    #[serde(default = "default_allow_genesis_status_bypass")]
    pub allow_genesis_status_bypass: bool,
    #[serde(default = "default_mesh_settle_secs")]
    pub mesh_settle_secs: u64,
    #[serde(default)]
    pub leader_timeout_secs: u64,
    #[serde(default = "default_vote_timeout_secs")]
    pub vote_timeout_secs: u64,
    #[serde(default = "default_block_timeout_secs")]
    pub block_timeout_secs: u64,
    #[serde(default = "default_penalization_enabled")]
    pub penalization_enabled: bool,
    pub synergy_score_decay_rate: f64,
    pub vrf_enabled: bool,
    pub vrf_seed_epoch_interval: u64,
    pub max_synergy_points_per_epoch: u64,
    pub max_tasks_per_validator: u32,
    pub reward_weighting: RewardWeighting,
}

fn default_min_validators() -> usize {
    4
}

fn default_emergency_stable_committee_mode() -> bool {
    false
}

fn default_freeze_validator_set() -> bool {
    false
}

fn default_freeze_score_weighted_proposer_order() -> bool {
    false
}

fn default_vote_only_rejoin_enabled() -> bool {
    true
}

fn default_vote_only_probation_blocks() -> u64 {
    1_000
}

fn default_validator_vote_threshold() -> usize {
    0
}

fn default_max_validators() -> usize {
    0
}

fn default_status_ready_gate_enabled() -> bool {
    true
}

fn default_status_ready_genesis_grace_secs() -> u64 {
    15
}

fn default_allow_genesis_status_bypass() -> bool {
    false
}

fn default_mesh_settle_secs() -> u64 {
    1
}

fn default_vote_timeout_secs() -> u64 {
    2
}

fn default_block_timeout_secs() -> u64 {
    6
}

fn default_penalization_enabled() -> bool {
    true
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RewardWeighting {
    pub task_accuracy: f64,
    pub uptime: f64,
    pub collaboration: f64,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LoggingConfig {
    pub log_level: String,
    pub log_file: String,
    pub enable_console: bool,
    pub max_file_size: u64,
    pub max_files: u32,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RPCConfig {
    #[serde(default)]
    pub bind_address: String,
    pub enable_http: bool,
    pub http_port: u16,
    pub enable_ws: bool,
    pub ws_port: u16,
    pub enable_grpc: bool,
    pub grpc_port: u16,
    pub cors_enabled: bool,
    pub cors_origins: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct P2PConfig {
    pub listen_address: String,
    pub public_address: String,
    #[serde(default)]
    pub discovery_listen_address: String,
    #[serde(default)]
    pub discovery_public_address: String,
    pub node_name: String,
    pub enable_discovery: bool,
    #[serde(default = "default_enable_peer_exchange")]
    pub enable_peer_exchange: bool,
    #[serde(default = "default_reject_private_advertise_addrs")]
    pub reject_private_advertise_addrs: bool,
    pub discovery_port: u16,
    pub heartbeat_interval: u64,
    #[serde(default = "default_bootstrap_refresh_secs")]
    pub bootstrap_refresh_secs: u64,
}

fn default_bootstrap_refresh_secs() -> u64 {
    10
}

fn default_enable_peer_exchange() -> bool {
    false
}

fn default_reject_private_advertise_addrs() -> bool {
    true
}

fn default_network_id() -> String {
    "synergy-testnet-v3".to_string()
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct StorageConfig {
    pub database: String,
    pub path: String,
    pub enable_pruning: bool,
    pub pruning_interval: u64,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct NodeSettings {
    #[serde(default)]
    pub bootstrap_only: bool,
    #[serde(default)]
    pub auto_register_validator: bool,
    #[serde(default)]
    pub validator_address: String,
    #[serde(default)]
    pub strict_validator_allowlist: bool,
    #[serde(default)]
    pub allowed_validator_addresses: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct ValidatorConfig {
    #[serde(default)]
    pub participation: String,
    #[serde(default)]
    pub verify_quorum_certificates: bool,
    #[serde(default)]
    pub state_sync_before_join: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct IdentityConfig {
    #[serde(default)]
    pub node_id: String,
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub role_display: String,
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub label: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct RoleConfig {
    #[serde(default)]
    pub compiled_profile: String,
    #[serde(default)]
    pub services: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TelemetryConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_metrics_bind")]
    pub metrics_bind: String,
    #[serde(default)]
    pub structured_logs: bool,
    #[serde(default = "default_telemetry_log_level")]
    pub log_level: String,
}

fn default_metrics_bind() -> String {
    "127.0.0.1:6030".to_string()
}

fn default_telemetry_log_level() -> String {
    "info".to_string()
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            metrics_bind: default_metrics_bind(),
            structured_logs: false,
            log_level: default_telemetry_log_level(),
        }
    }
}

impl Default for NodeConfig {
    fn default() -> Self {
        NodeConfig {
            network: NetworkConfig {
                id: 1266,
                network_id: default_network_id(),
                name: "Synergy Testnet".to_string(),
                p2p_port: 5622,
                rpc_port: 5640,
                ws_port: 5660,
                max_peers: 50,
                bootnodes: vec![],
                seed_servers: vec![],
                bootstrap_dns_records: vec![],
                persistent_peers: vec![],
                additional_dial_targets: vec![],
                validator_vpn_transports: vec![],
            },
            blockchain: BlockchainConfig {
                block_time: 2,
                max_gas_limit: "0x2fefd8".to_string(),
                chain_id: 1266,
            },
            consensus: ConsensusConfig {
                algorithm: "Proof of Synergy".to_string(),
                block_time_secs: 2,
                epoch_length: 1000,
                emergency_stable_committee_mode: default_emergency_stable_committee_mode(),
                freeze_validator_set: default_freeze_validator_set(),
                freeze_score_weighted_proposer_order: default_freeze_score_weighted_proposer_order(
                ),
                vote_only_rejoin_enabled: default_vote_only_rejoin_enabled(),
                vote_only_probation_blocks: default_vote_only_probation_blocks(),
                min_validators: default_min_validators(),
                validator_cluster_size: 6,
                validator_vote_threshold: default_validator_vote_threshold(),
                max_validators: default_max_validators(),
                status_ready_gate_enabled: default_status_ready_gate_enabled(),
                status_ready_min_validators: 0,
                status_ready_genesis_grace_secs: default_status_ready_genesis_grace_secs(),
                allow_genesis_status_bypass: default_allow_genesis_status_bypass(),
                mesh_settle_secs: default_mesh_settle_secs(),
                leader_timeout_secs: 0,
                vote_timeout_secs: default_vote_timeout_secs(),
                block_timeout_secs: default_block_timeout_secs(),
                penalization_enabled: default_penalization_enabled(),
                synergy_score_decay_rate: 0.05,
                vrf_enabled: true,
                vrf_seed_epoch_interval: 1000,
                max_synergy_points_per_epoch: 100,
                max_tasks_per_validator: 10,
                reward_weighting: RewardWeighting {
                    task_accuracy: 0.5,
                    uptime: 0.3,
                    collaboration: 0.2,
                },
            },
            logging: LoggingConfig {
                log_level: "info".to_string(),
                log_file: "data/logs/synergy-node.log".to_string(),
                enable_console: true,
                max_file_size: 10485760, // 10MB
                max_files: 5,
            },
            rpc: RPCConfig {
                bind_address: "127.0.0.1:5640".to_string(),
                enable_http: true,
                http_port: 5640,
                enable_ws: true,
                ws_port: 5660,
                enable_grpc: true,
                grpc_port: 5640,
                cors_enabled: false,
                cors_origins: vec![],
            },
            p2p: P2PConfig {
                listen_address: "127.0.0.1:5622".to_string(),
                public_address: "127.0.0.1:5622".to_string(),
                discovery_listen_address: "127.0.0.1:5680".to_string(),
                discovery_public_address: "127.0.0.1:5680".to_string(),
                node_name: "synergy-node-01".to_string(),
                enable_discovery: false,
                enable_peer_exchange: default_enable_peer_exchange(),
                reject_private_advertise_addrs: default_reject_private_advertise_addrs(),
                discovery_port: 5680,
                heartbeat_interval: 10,
                bootstrap_refresh_secs: default_bootstrap_refresh_secs(),
            },
            storage: StorageConfig {
                database: "rocksdb".to_string(),
                path: "data/chain".to_string(),
                enable_pruning: true,
                pruning_interval: 86400, // 24 hours
            },
            node: NodeSettings::default(),
            identity: IdentityConfig::default(),
            role: RoleConfig::default(),
            validator: ValidatorConfig::default(),
            telemetry: TelemetryConfig::default(),
        }
    }
}

/// Loads the configuration from multiple sources with priority:
/// 1. Specified path
/// 2. Template file (if node type specified)
/// 3. Environment variable SYNERGY_CONFIG_PATH
/// 4. Default config/node.toml
/// 5. Default values
pub fn load_node_config(path: Option<&str>) -> Result<NodeConfig, Box<dyn Error>> {
    let mut config = NodeConfig::default();

    // Load from TOML file if provided
    if let Some(config_path) = path {
        if Path::new(config_path).exists() {
            let content = fs::read_to_string(config_path)?;
            let file_config = parse_node_config_content(&content, Some(Path::new(config_path)))?;
            config = merge_configs(config, file_config);
        }
    } else if let Ok(config_path) = env::var("SYNERGY_CONFIG_PATH") {
        if Path::new(&config_path).exists() {
            let content = fs::read_to_string(&config_path)?;
            let file_config = parse_node_config_content(&content, Some(Path::new(&config_path)))?;
            config = merge_configs(config, file_config);
        }
    } else {
        // Try default config path
        let default_path = "config/node.toml";
        if Path::new(default_path).exists() {
            let content = fs::read_to_string(default_path)?;
            let file_config = parse_node_config_content(&content, Some(Path::new(default_path)))?;
            config = merge_configs(config, file_config);
        }
    }

    // Override with environment variables
    config = apply_env_overrides(config)?;
    enforce_consensus_config_invariants(&config)?;

    Ok(config)
}

pub fn resolve_runtime_validator_address() -> Option<String> {
    ["SYNERGY_VALIDATOR_ADDRESS", "NODE_ADDRESS"]
        .iter()
        .find_map(|key| {
            env::var(key)
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        })
        .or_else(|| {
            load_node_config(None).ok().and_then(|config| {
                let configured = config.node.validator_address.trim();
                if configured.is_empty() {
                    None
                } else {
                    Some(configured.to_string())
                }
            })
        })
}

/// Loads a node configuration from a template file by node type
pub fn load_node_config_from_template(node_type: &str) -> Result<NodeConfig, Box<dyn Error>> {
    let template_path = format!("templates/{}.toml", node_type);

    if !Path::new(&template_path).exists() {
        return Err(format!("Template not found: {}", template_path).into());
    }

    let mut config = NodeConfig::default();
    let content = fs::read_to_string(&template_path)?;
    let file_config = parse_node_config_content(&content, Some(Path::new(&template_path)))?;
    config = merge_configs(config, file_config);

    // Override with environment variables
    config = apply_env_overrides(config)?;
    enforce_consensus_config_invariants(&config)?;

    Ok(config)
}

fn enforce_consensus_config_invariants(config: &NodeConfig) -> Result<(), Box<dyn Error>> {
    if config.blockchain.chain_id != 1266 || config.network.id != 1266 {
        return Err(format!(
            "Synergy Testnet v3 requires chain_id/network id 1266, found blockchain.chain_id={} network.id={}",
            config.blockchain.chain_id, config.network.id
        )
        .into());
    }
    if config.network.network_id != "synergy-testnet-v3" {
        return Err(format!(
            "Synergy Testnet v3 requires network_id synergy-testnet-v3, found {}",
            config.network.network_id
        )
        .into());
    }
    if config.consensus.allow_genesis_status_bypass {
        return Err("genesis status bypass is disabled for PQC Testnet consensus".into());
    }
    Ok(())
}

/// Lists all available node templates
pub fn list_available_templates() -> Result<Vec<String>, Box<dyn Error>> {
    let templates_dir = "templates";
    let mut templates = Vec::new();

    if Path::new(templates_dir).exists() {
        for entry in fs::read_dir(templates_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("toml") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    templates.push(stem.to_string());
                }
            }
        }
    }

    templates.sort();
    Ok(templates)
}

/// Merges two configurations, with the second taking precedence
fn merge_configs(mut base: NodeConfig, override_config: NodeConfig) -> NodeConfig {
    base.network = override_config.network;
    base.blockchain = override_config.blockchain;
    base.consensus = override_config.consensus;
    base.logging = override_config.logging;
    base.rpc = override_config.rpc;
    base.p2p = override_config.p2p;
    base.storage = override_config.storage;
    base.node = override_config.node;
    base.identity = override_config.identity;
    base.role = override_config.role;
    base.validator = override_config.validator;
    base.telemetry = override_config.telemetry;
    base
}

/// Applies environment variable overrides
fn apply_env_overrides(mut config: NodeConfig) -> Result<NodeConfig, Box<dyn Error>> {
    // Network overrides
    if let Ok(val) = env::var("SYNERGY_NETWORK_ID") {
        let trimmed = val.trim();
        if let Ok(network_id) = trimmed.parse() {
            config.network.id = network_id;
        } else if !trimmed.is_empty() {
            config.network.name = trimmed.to_string();
        }
    }
    if let Ok(val) = env::var("SYNERGY_NETWORK_NAME") {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            config.network.name = trimmed.to_string();
        }
    }
    if let Ok(val) = env::var("SYNERGY_CHAIN_ID") {
        config.blockchain.chain_id = val.parse()?;
    }
    if let Some(val) = first_env_value(&["SYNERGY_P2P_PORT", "P2P_PORT"]) {
        config.network.p2p_port = val.parse()?;
        config.p2p.listen_address = replace_port_in_address(
            &config.p2p.listen_address,
            config.network.p2p_port,
            "0.0.0.0",
        );
    }
    if let Some(val) = first_env_value(&["SYNERGY_RPC_PORT", "RPC_PORT"]) {
        let rpc_port = val.parse()?;
        config.network.rpc_port = rpc_port;
        config.rpc.http_port = rpc_port;
        config.rpc.bind_address = replace_port_in_address(
            &config.rpc.bind_address,
            rpc_port,
            extract_host_from_address(&config.rpc.bind_address).unwrap_or("0.0.0.0"),
        );
    }
    if let Ok(val) = env::var("SYNERGY_RPC_BIND_ADDRESS") {
        config.rpc.bind_address = val;
    }
    if let Some(val) = first_env_value(&["SYNERGY_WS_PORT", "WS_PORT"]) {
        let ws_port = val.parse()?;
        config.network.ws_port = ws_port;
        config.rpc.ws_port = ws_port;
    }
    if let Some(val) = first_env_value(&["SYNERGY_GRPC_PORT", "GRPC_PORT"]) {
        config.rpc.grpc_port = val.parse()?;
    }
    if let Some(val) = first_env_value(&["SYNERGY_P2P_LISTEN_ADDRESS", "P2P_LISTEN_ADDRESS"]) {
        config.p2p.listen_address = val.clone();
        if let Some(port) = parse_port_from_address(&val) {
            config.network.p2p_port = port;
        }
    }
    if let Some(val) = first_env_value(&[
        "SYNERGY_P2P_EXTERNAL_ADDRESS",
        "SYNERGY_P2P_PUBLIC_ADDRESS",
        "P2P_EXTERNAL_ADDRESS",
        "P2P_PUBLIC_ADDRESS",
    ]) {
        config.p2p.public_address = val;
    }
    if let Some(val) = first_env_value(&[
        "SYNERGY_P2P_ENABLE_PEER_EXCHANGE",
        "P2P_ENABLE_PEER_EXCHANGE",
    ]) {
        if let Some(enabled) = parse_env_bool(&val) {
            config.p2p.enable_peer_exchange = enabled;
        }
    }
    if let Some(val) = first_env_value(&[
        "SYNERGY_P2P_REJECT_PRIVATE_ADVERTISE_ADDRS",
        "P2P_REJECT_PRIVATE_ADVERTISE_ADDRS",
    ]) {
        if let Some(enabled) = parse_env_bool(&val) {
            config.p2p.reject_private_advertise_addrs = enabled;
        }
    }
    if let Some(val) = first_env_value(&["SYNERGY_DISCOVERY_PORT", "DISCOVERY_PORT"]) {
        config.p2p.discovery_port = val.parse()?;
        config.p2p.discovery_listen_address = replace_port_in_address(
            &config.p2p.discovery_listen_address,
            config.p2p.discovery_port,
            "0.0.0.0",
        );
        config.p2p.discovery_public_address = replace_port_in_address(
            &config.p2p.discovery_public_address,
            config.p2p.discovery_port,
            extract_host_from_address(&config.p2p.public_address).unwrap_or("127.0.0.1"),
        );
    }
    if let Some(val) = first_env_value(&[
        "SYNERGY_DISCOVERY_LISTEN_ADDRESS",
        "DISCOVERY_LISTEN_ADDRESS",
    ]) {
        config.p2p.discovery_listen_address = val.clone();
        if let Some(port) = parse_port_from_address(&val) {
            config.p2p.discovery_port = port;
        }
    }
    if let Some(val) = first_env_value(&[
        "SYNERGY_DISCOVERY_EXTERNAL_ADDRESS",
        "SYNERGY_DISCOVERY_PUBLIC_ADDRESS",
        "DISCOVERY_EXTERNAL_ADDRESS",
        "DISCOVERY_PUBLIC_ADDRESS",
    ]) {
        config.p2p.discovery_public_address = val;
    }
    if let Ok(val) = env::var("SYNERGY_BOOTNODES") {
        config.network.bootnodes = val.split(',').map(|s| s.trim().to_string()).collect();
    }
    if let Ok(val) = env::var("SYNERGY_SEED_SERVERS") {
        config.network.seed_servers = val
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .collect();
    }
    if let Ok(val) = env::var("SYNERGY_BOOTSTRAP_DNS_RECORDS") {
        config.network.bootstrap_dns_records = val
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .collect();
    }
    if let Ok(val) = env::var("SYNERGY_PERSISTENT_PEERS") {
        config.network.persistent_peers = val
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .collect();
    }
    if let Ok(val) = env::var("SYNERGY_ADDITIONAL_DIAL_TARGETS") {
        config.network.additional_dial_targets = val
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .collect();
    }

    if let Ok(val) = env::var("SYNERGY_CONSENSUS_MIN_VALIDATORS") {
        config.consensus.min_validators = val.parse::<usize>()?.max(1);
    }
    if let Ok(val) = env::var("SYNERGY_CONSENSUS_STATUS_READY_MIN_VALIDATORS") {
        config.consensus.status_ready_min_validators = val.parse::<usize>()?;
    }
    if let Ok(val) = env::var("SYNERGY_CONSENSUS_STATUS_READY_GENESIS_GRACE_SECS") {
        config.consensus.status_ready_genesis_grace_secs = val.parse::<u64>()?;
    }
    if let Ok(val) = env::var("SYNERGY_CONSENSUS_MESH_SETTLE_SECS") {
        config.consensus.mesh_settle_secs = val.parse::<u64>()?;
    }
    if let Ok(val) = env::var("SYNERGY_CONSENSUS_LEADER_TIMEOUT_SECS") {
        config.consensus.leader_timeout_secs = val.parse::<u64>()?;
    }
    if let Ok(val) = env::var("SYNERGY_CONSENSUS_VOTE_TIMEOUT_SECS") {
        config.consensus.vote_timeout_secs = val.parse::<u64>()?.max(1);
    }
    if let Ok(val) = env::var("SYNERGY_CONSENSUS_BLOCK_TIMEOUT_SECS") {
        config.consensus.block_timeout_secs = val.parse::<u64>()?.max(1);
    }
    if let Ok(val) = env::var("SYNERGY_CONSENSUS_PENALIZATION_ENABLED") {
        if let Some(enabled) = parse_env_bool(&val) {
            config.consensus.penalization_enabled = enabled;
        }
    }
    if let Ok(val) = env::var("SYNERGY_CONSENSUS_STATUS_READY_GATE_ENABLED") {
        if let Some(enabled) = parse_env_bool(&val) {
            config.consensus.status_ready_gate_enabled = enabled;
        }
    }
    if let Ok(val) = env::var("SYNERGY_P2P_BOOTSTRAP_REFRESH_SECS") {
        config.p2p.bootstrap_refresh_secs = val.parse::<u64>()?.max(1);
    }
    // Logging overrides
    if let Ok(val) = env::var("SYNERGY_LOG_LEVEL") {
        config.logging.log_level = val;
    }
    if let Ok(val) = env::var("SYNERGY_LOG_FILE") {
        config.logging.log_file = val;
    }
    if let Ok(val) = env::var("SYNERGY_ENABLE_METRICS") {
        if let Some(enabled) = parse_env_bool(&val) {
            config.telemetry.enabled = enabled;
        }
    }
    if let Ok(val) = env::var("SYNERGY_METRICS_BIND") {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            config.telemetry.enabled = true;
            config.telemetry.metrics_bind = trimmed.to_string();
        }
    }

    // Storage overrides
    if let Ok(val) = env::var("SYNERGY_DATA_PATH") {
        config.storage.path = val;
    }

    if let Ok(val) = env::var("SYNERGY_AUTO_REGISTER_VALIDATOR") {
        let normalized = val.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "1" | "true" | "yes" | "on" => config.node.auto_register_validator = true,
            "0" | "false" | "no" | "off" => config.node.auto_register_validator = false,
            _ => {}
        }
    }

    if let Ok(val) = env::var("SYNERGY_VALIDATOR_STATE_SYNC_BEFORE_JOIN") {
        let normalized = val.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "1" | "true" | "yes" | "on" => config.validator.state_sync_before_join = true,
            "0" | "false" | "no" | "off" => config.validator.state_sync_before_join = false,
            _ => {}
        }
    }

    if let Ok(val) = env::var("SYNERGY_BOOTSTRAP_ONLY") {
        let normalized = val.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "1" | "true" | "yes" | "on" => config.node.bootstrap_only = true,
            "0" | "false" | "no" | "off" => config.node.bootstrap_only = false,
            _ => {}
        }
    }

    if let Ok(val) = env::var("SYNERGY_VALIDATOR_ADDRESS") {
        config.node.validator_address = val.trim().to_string();
    }

    if let Ok(val) = env::var("SYNERGY_STRICT_VALIDATOR_ALLOWLIST") {
        let normalized = val.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "1" | "true" | "yes" | "on" => config.node.strict_validator_allowlist = true,
            "0" | "false" | "no" | "off" => config.node.strict_validator_allowlist = false,
            _ => {}
        }
    }

    if let Ok(val) = env::var("SYNERGY_ALLOWED_VALIDATOR_ADDRESSES") {
        config.node.allowed_validator_addresses = val
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
    }
    if config.node.validator_address.trim().is_empty() {
        if let Ok(val) = env::var("NODE_ADDRESS") {
            config.node.validator_address = val.trim().to_string();
        }
    }

    Ok(config)
}

/// Loads genesis configuration from genesis.json
pub fn load_genesis_config() -> Result<serde_json::Value, Box<dyn Error>> {
    let genesis_path = "config/genesis.json";
    if !Path::new(genesis_path).exists() {
        return Err(format!("Genesis file not found: {}", genesis_path).into());
    }

    let content = fs::read_to_string(genesis_path)?;
    let genesis: serde_json::Value = serde_json::from_str(&content)?;
    Ok(genesis)
}

/// Saves current configuration to a file
pub fn save_config(config: &NodeConfig, path: &str) -> Result<(), Box<dyn Error>> {
    let content = toml::to_string_pretty(config)?;
    fs::write(path, content)?;
    Ok(())
}

fn parse_node_config_content(
    content: &str,
    source_path: Option<&Path>,
) -> Result<NodeConfig, Box<dyn Error>> {
    let raw: toml::Value = toml::from_str(content)?;
    let mut config = toml::from_str::<NodeConfig>(content).unwrap_or_default();

    apply_compatibility_overrides(&mut config, &raw);

    if let Some(source_path) = source_path {
        merge_companion_peers_file(source_path, &mut config)?;
    }

    Ok(config)
}

fn apply_compatibility_overrides(config: &mut NodeConfig, raw: &toml::Value) {
    if let Some(chain_name) = get_string(raw, &["network", "chain_name"]) {
        config.network.name = chain_name;
    }

    if let Some(chain_id) = get_u64(raw, &["network", "chain_id"]) {
        config.network.id = chain_id;
        config.blockchain.chain_id = chain_id;
    }

    if let Some(network_id) = get_string(raw, &["network", "network_id"]) {
        config.network.network_id = network_id;
    }

    if let Some(max_peers) = get_u64(raw, &["network", "max_peers"]) {
        config.network.max_peers = max_peers as u32;
    }

    if let Some(p2p_listen) = get_string(raw, &["network", "p2p_listen"]) {
        config.p2p.listen_address = p2p_listen.clone();
        if let Some(port) = parse_port_from_address(&p2p_listen) {
            config.network.p2p_port = port;
        }
    }

    if let Some(port) =
        get_u64(raw, &["network", "p2p_port"]).and_then(|value| u16::try_from(value).ok())
    {
        config.network.p2p_port = port;
    }

    if let Some(port) =
        get_u64(raw, &["network", "rpc_port"]).and_then(|value| u16::try_from(value).ok())
    {
        config.network.rpc_port = port;
        config.rpc.http_port = port;
    }

    if let Some(port) =
        get_u64(raw, &["network", "ws_port"]).and_then(|value| u16::try_from(value).ok())
    {
        config.network.ws_port = port;
        config.rpc.ws_port = port;
    }

    if let Some(port) =
        get_u64(raw, &["rpc", "http_port"]).and_then(|value| u16::try_from(value).ok())
    {
        config.network.rpc_port = port;
        config.rpc.http_port = port;
    }

    if let Some(port) =
        get_u64(raw, &["rpc", "ws_port"]).and_then(|value| u16::try_from(value).ok())
    {
        config.network.ws_port = port;
        config.rpc.ws_port = port;
    }

    if let Some(bind_address) = get_string(raw, &["rpc", "bind_address"]) {
        config.rpc.bind_address = bind_address;
    }

    if let Some(enable_http) = get_bool(raw, &["rpc", "enable_http"]) {
        config.rpc.enable_http = enable_http;
    }

    if let Some(enable_ws) = get_bool(raw, &["rpc", "enable_ws"]) {
        config.rpc.enable_ws = enable_ws;
    }

    if let Some(enable_grpc) = get_bool(raw, &["rpc", "enable_grpc"]) {
        config.rpc.enable_grpc = enable_grpc;
    }

    if let Some(listen_address) = get_string(raw, &["p2p", "listen_address"]) {
        config.p2p.listen_address = listen_address.clone();
        if let Some(port) = parse_port_from_address(&listen_address) {
            config.network.p2p_port = port;
        }
    }

    let explicit_public_address = get_string(raw, &["p2p", "public_address"])
        .or_else(|| get_string(raw, &["p2p", "external_address"]))
        .or_else(|| get_string(raw, &["p2p", "external_addr"]))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    if let Some(public_address) = explicit_public_address {
        config.p2p.public_address = public_address;
    } else if let Some(public_host) = get_string(raw, &["network", "public_host"]) {
        let p2p_port = config.network.p2p_port;
        config.p2p.public_address = format!("{public_host}:{p2p_port}");
    }

    if let Some(node_name) = get_string(raw, &["p2p", "node_name"]) {
        config.p2p.node_name = node_name;
    } else if let Some(label) = get_string(raw, &["identity", "label"]) {
        config.p2p.node_name = label;
    } else if let Some(node_id) = get_string(raw, &["identity", "node_id"]) {
        config.p2p.node_name = node_id;
    }

    if let Some(enable_discovery) = get_bool(raw, &["p2p", "enable_discovery"]) {
        config.p2p.enable_discovery = enable_discovery;
        if get_bool(raw, &["p2p", "enable_peer_exchange"]).is_none() {
            config.p2p.enable_peer_exchange = enable_discovery;
        }
    }

    if let Some(enable_peer_exchange) = get_bool(raw, &["p2p", "enable_peer_exchange"]) {
        config.p2p.enable_peer_exchange = enable_peer_exchange;
    }

    if let Some(reject_private_advertise_addrs) =
        get_bool(raw, &["p2p", "reject_private_advertise_addrs"])
    {
        config.p2p.reject_private_advertise_addrs = reject_private_advertise_addrs;
    }

    if let Some(discovery_port) =
        get_u64(raw, &["p2p", "discovery_port"]).and_then(|value| u16::try_from(value).ok())
    {
        config.p2p.discovery_port = discovery_port;
    }

    let explicit_discovery_listen_address = get_string(raw, &["p2p", "discovery_listen_address"])
        .or_else(|| get_string(raw, &["p2p", "discovery_listen_addr"]))
        .or_else(|| get_string(raw, &["discovery", "listen_address"]))
        .or_else(|| get_string(raw, &["discovery", "listen_addr"]));
    if let Some(discovery_listen_address) = explicit_discovery_listen_address {
        config.p2p.discovery_listen_address = discovery_listen_address.clone();
        if let Some(port) = parse_port_from_address(&discovery_listen_address) {
            config.p2p.discovery_port = port;
        }
    } else {
        config.p2p.discovery_listen_address = format!("0.0.0.0:{}", config.p2p.discovery_port);
    }

    let explicit_discovery_public_address = get_string(raw, &["p2p", "discovery_public_address"])
        .or_else(|| get_string(raw, &["p2p", "discovery_external_address"]))
        .or_else(|| get_string(raw, &["p2p", "discovery_external_addr"]))
        .or_else(|| get_string(raw, &["discovery", "public_address"]))
        .or_else(|| get_string(raw, &["discovery", "external_address"]))
        .or_else(|| get_string(raw, &["discovery", "external_addr"]));
    if let Some(discovery_public_address) = explicit_discovery_public_address {
        config.p2p.discovery_public_address = discovery_public_address;
    } else {
        let discovery_public_host =
            get_string(raw, &["network", "public_host"]).unwrap_or_else(|| {
                extract_host_from_address(&config.p2p.public_address)
                    .unwrap_or("127.0.0.1")
                    .to_string()
            });
        config.p2p.discovery_public_address =
            format!("{discovery_public_host}:{}", config.p2p.discovery_port);
    }

    if let Some(heartbeat_interval) = get_u64(raw, &["p2p", "heartbeat_interval"]) {
        config.p2p.heartbeat_interval = heartbeat_interval;
    }

    if let Some(path) = get_string(raw, &["storage", "path"]) {
        config.storage.path = path;
    }

    let telemetry_enabled_override = get_bool(raw, &["telemetry", "enabled"])
        .or_else(|| get_bool(raw, &["node", "enable_metrics"]));
    if let Some(enabled) = telemetry_enabled_override {
        config.telemetry.enabled = enabled;
    }

    let mut telemetry_bind_configured = false;
    if let Some(metrics_bind) = get_string(raw, &["telemetry", "metrics_bind"]) {
        config.telemetry.metrics_bind = metrics_bind;
        telemetry_bind_configured = true;
    } else if let Some(metrics_port) = get_u64(raw, &["telemetry", "metrics_port"])
        .or_else(|| get_u64(raw, &["node", "metrics_port"]))
        .or_else(|| get_u64(raw, &["network", "metrics_port"]))
        .and_then(|value| u16::try_from(value).ok())
    {
        let default_host =
            extract_host_from_address(&config.telemetry.metrics_bind).unwrap_or("127.0.0.1");
        config.telemetry.metrics_bind =
            replace_port_in_address(&config.telemetry.metrics_bind, metrics_port, default_host);
        telemetry_bind_configured = true;
    }
    if telemetry_bind_configured && telemetry_enabled_override.is_none() {
        config.telemetry.enabled = true;
    }

    if let Some(structured_logs) = get_bool(raw, &["telemetry", "structured_logs"]) {
        config.telemetry.structured_logs = structured_logs;
    }

    if let Some(log_level) = get_string(raw, &["telemetry", "log_level"]) {
        config.telemetry.log_level = log_level;
    }

    if let Some(database) = get_string(raw, &["storage", "engine"]) {
        config.storage.database = database;
    } else if let Some(database) = get_string(raw, &["storage", "database"]) {
        config.storage.database = database;
    }

    if let Some(log_level) = get_string(raw, &["logging", "log_level"]) {
        config.logging.log_level = log_level;
    } else if let Some(log_level) = get_string(raw, &["telemetry", "log_level"]) {
        config.logging.log_level = log_level;
    }

    if let Some(log_file) = get_string(raw, &["logging", "log_file"]) {
        config.logging.log_file = log_file;
    }

    if let Some(bootnodes) = get_string_array(raw, &["network", "bootnodes"]) {
        merge_unique_strings(&mut config.network.bootnodes, bootnodes);
    }

    if let Some(seed_servers) = get_string_array(raw, &["network", "seed_servers"]) {
        merge_unique_strings(&mut config.network.seed_servers, seed_servers);
    }

    if let Some(dns_records) = get_string_array(raw, &["network", "bootstrap_dns_records"]) {
        merge_unique_strings(&mut config.network.bootstrap_dns_records, dns_records);
    }

    if let Some(persistent_peers) = get_string_array(raw, &["network", "persistent_peers"]) {
        merge_unique_strings(&mut config.network.persistent_peers, persistent_peers);
    }

    if let Some(additional_targets) = get_string_array(raw, &["network", "additional_dial_targets"])
    {
        merge_unique_strings(
            &mut config.network.additional_dial_targets,
            additional_targets,
        );
    }

    if let Some(bootstrap_only) = get_bool(raw, &["node", "bootstrap_only"]) {
        config.node.bootstrap_only = bootstrap_only;
    }

    if let Some(auto_register_validator) = get_bool(raw, &["node", "auto_register_validator"]) {
        config.node.auto_register_validator = auto_register_validator;
    }

    if let Some(validator_address) = get_string(raw, &["node", "validator_address"]) {
        config.node.validator_address = validator_address;
    } else if let Some(address) = get_string(raw, &["identity", "address"]) {
        config.node.validator_address = address.clone();
        config.identity.address = address;
    }

    if let Some(strict_validator_allowlist) = get_bool(raw, &["node", "strict_validator_allowlist"])
    {
        config.node.strict_validator_allowlist = strict_validator_allowlist;
    }

    if let Some(allowed_validator_addresses) =
        get_string_array(raw, &["node", "allowed_validator_addresses"])
    {
        config.node.allowed_validator_addresses = allowed_validator_addresses;
    }

    if let Some(node_id) = get_string(raw, &["identity", "node_id"]) {
        config.identity.node_id = node_id;
    }

    if let Some(role) = get_string(raw, &["identity", "role"]) {
        config.identity.role = role;
    }

    if let Some(role_display) = get_string(raw, &["identity", "role_display"]) {
        config.identity.role_display = role_display;
    }

    if let Some(label) = get_string(raw, &["identity", "label"]) {
        config.identity.label = label;
    }

    if let Some(compiled_profile) = get_string(raw, &["role", "compiled_profile"]) {
        config.role.compiled_profile = compiled_profile;
    }

    if let Some(services) = get_string_array(raw, &["role", "services"]) {
        config.role.services = services;
    }

    if let Some(participation) = get_string(raw, &["validator", "participation"]) {
        config.validator.participation = participation;
    }

    if let Some(verify_quorum_certificates) =
        get_bool(raw, &["validator", "verify_quorum_certificates"])
    {
        config.validator.verify_quorum_certificates = verify_quorum_certificates;
    }

    if let Some(state_sync_before_join) = get_bool(raw, &["validator", "state_sync_before_join"]) {
        config.validator.state_sync_before_join = state_sync_before_join;
    }
}

fn merge_companion_peers_file(
    source_path: &Path,
    config: &mut NodeConfig,
) -> Result<(), Box<dyn Error>> {
    let Some(parent) = source_path.parent() else {
        return Ok(());
    };

    let peers_path = parent.join("peers.toml");
    if !peers_path.exists() || peers_path == source_path {
        return Ok(());
    }

    let content = fs::read_to_string(&peers_path)?;
    let raw: toml::Value = toml::from_str(&content)?;

    if let Some(bootnodes) = get_string_array(&raw, &["global", "bootnodes"]) {
        merge_unique_strings(&mut config.network.bootnodes, bootnodes);
    }

    if let Some(seed_servers) = get_string_array(&raw, &["global", "seed_servers"]) {
        merge_unique_strings(&mut config.network.seed_servers, seed_servers);
    }

    if let Some(dns_records) = get_string_array(&raw, &["global", "bootstrap_dns_records"]) {
        merge_unique_strings(&mut config.network.bootstrap_dns_records, dns_records);
    }

    if let Some(persistent_peers) = get_string_array(&raw, &["global", "persistent_peers"]) {
        merge_unique_strings(&mut config.network.persistent_peers, persistent_peers);
    }

    if let Some(additional_targets) = get_string_array(&raw, &["global", "additional_dial_targets"])
    {
        merge_unique_strings(
            &mut config.network.additional_dial_targets,
            additional_targets,
        );
    }

    Ok(())
}

fn merge_unique_strings(destination: &mut Vec<String>, values: Vec<String>) {
    for value in values {
        if !destination.iter().any(|existing| existing == &value) {
            destination.push(value);
        }
    }
}

fn get_table<'a>(value: &'a toml::Value, path: &[&str]) -> Option<&'a toml::Value> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    Some(current)
}

fn get_string(value: &toml::Value, path: &[&str]) -> Option<String> {
    get_table(value, path)?
        .as_str()
        .map(|entry| entry.trim().to_string())
}

fn get_bool(value: &toml::Value, path: &[&str]) -> Option<bool> {
    get_table(value, path)?.as_bool()
}

fn get_u64(value: &toml::Value, path: &[&str]) -> Option<u64> {
    get_table(value, path)?
        .as_integer()
        .and_then(|entry| u64::try_from(entry).ok())
}

fn get_string_array(value: &toml::Value, path: &[&str]) -> Option<Vec<String>> {
    let array = get_table(value, path)?.as_array()?;
    Some(
        array
            .iter()
            .filter_map(|entry| entry.as_str())
            .map(|entry| entry.trim())
            .filter(|entry| !entry.is_empty())
            .map(ToString::to_string)
            .collect(),
    )
}

fn first_env_value(keys: &[&str]) -> Option<String> {
    keys.iter()
        .filter_map(|key| env::var(key).ok())
        .map(|value| value.trim().to_string())
        .find(|value| !value.is_empty())
}

fn parse_env_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn extract_host_from_address(value: &str) -> Option<&str> {
    value
        .trim()
        .rsplit_once(':')
        .map(|(host, _)| host.trim())
        .filter(|host| !host.is_empty())
}

fn replace_port_in_address(value: &str, port: u16, default_host: &str) -> String {
    let host = extract_host_from_address(value)
        .unwrap_or(default_host)
        .trim();
    format!("{host}:{port}")
}

fn parse_port_from_address(value: &str) -> Option<u16> {
    value
        .trim()
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = env::var(key).ok();
            unsafe {
                env::set_var(key, value);
            }
            Self { key, previous }
        }

        fn clear(key: &'static str) -> Self {
            let previous = env::var(key).ok();
            unsafe {
                env::remove_var(key);
            }
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(previous) = &self.previous {
                unsafe {
                    env::set_var(self.key, previous);
                }
            } else {
                unsafe {
                    env::remove_var(self.key);
                }
            }
        }
    }

    #[test]
    fn parses_testnet_control_panel_workspace_config() {
        let content = r#"
[identity]
node_id = "node-01"
role = "validator"
address = "synv1test"
label = "Validator Node 01"

[network]
chain_name = "synergy-testnet"
chain_id = 1266
p2p_listen = "0.0.0.0:5622"
bootnodes = ["bootnode1.synergy-network.io:5620"]
seed_servers = ["http://seed1.synergy-network.io:5621"]
bootstrap_dns_records = ["_dnsaddr.bootstrap.synergy-network.io"]
persistent_peers = ["genesisval2.synergy-network.io:5622"]
additional_dial_targets = ["24.181.87.76:5622"]
max_peers = 128

[role]
compiled_profile = "validator_node"

[storage]
path = "/tmp/synergy-testnet"

[telemetry]
log_level = "debug"
"#;

        let config = parse_node_config_content(content, None).expect("config should parse");

        assert_eq!(config.identity.role, "validator");
        assert_eq!(config.role.compiled_profile, "validator_node");
        assert_eq!(config.network.name, "synergy-testnet");
        assert_eq!(config.network.id, 1266);
        assert_eq!(config.blockchain.chain_id, 1266);
        assert_eq!(config.network.p2p_port, 5622);
        assert_eq!(config.p2p.listen_address, "0.0.0.0:5622");
        assert_eq!(
            config.network.bootnodes,
            vec!["bootnode1.synergy-network.io:5620".to_string()]
        );
        assert_eq!(
            config.network.seed_servers,
            vec!["http://seed1.synergy-network.io:5621".to_string()]
        );
        assert_eq!(
            config.network.bootstrap_dns_records,
            vec!["_dnsaddr.bootstrap.synergy-network.io".to_string()]
        );
        assert_eq!(
            config.network.persistent_peers,
            vec!["genesisval2.synergy-network.io:5622".to_string()]
        );
        assert_eq!(
            config.network.additional_dial_targets,
            vec!["24.181.87.76:5622".to_string()]
        );
        assert_eq!(config.logging.log_level, "debug");
        assert!(!config.telemetry.enabled);
    }

    #[test]
    fn parses_metrics_bind_from_telemetry_section() {
        let content = r#"
[telemetry]
metrics_bind = "0.0.0.0:6030"
structured_logs = true
"#;

        let config = parse_node_config_content(content, None).expect("config should parse");

        assert!(config.telemetry.enabled);
        assert_eq!(config.telemetry.metrics_bind, "0.0.0.0:6030");
        assert!(config.telemetry.structured_logs);
    }

    #[test]
    fn maps_legacy_metrics_port_into_metrics_bind() {
        let content = r#"
[node]
enable_metrics = true
metrics_port = 6060
"#;

        let config = parse_node_config_content(content, None).expect("config should parse");

        assert!(config.telemetry.enabled);
        assert_eq!(config.telemetry.metrics_bind, "127.0.0.1:6060");
    }

    #[test]
    fn load_node_config_preserves_telemetry_when_merging_file_config() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_dir =
            crate::utils::test_temp_root(format!("synergy-telemetry-merge-test-{unique}"));
        fs::create_dir_all(&temp_dir).expect("temp dir should be created");

        let node_path = temp_dir.join("node.toml");
        fs::write(
            &node_path,
            r#"
[telemetry]
metrics_bind = "0.0.0.0:6030"
"#,
        )
        .expect("config should write");

        let config = load_node_config(Some(node_path.to_str().expect("path should be valid")))
            .expect("config should load");

        assert!(config.telemetry.enabled);
        assert_eq!(config.telemetry.metrics_bind, "0.0.0.0:6030");
    }

    #[test]
    fn merges_companion_peers_file_bootstrap_inputs() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_dir = crate::utils::test_temp_root(format!("synergy-config-test-{unique}"));
        fs::create_dir_all(&temp_dir).expect("temp dir should be created");

        let node_path = temp_dir.join("node.toml");
        let peers_path = temp_dir.join("peers.toml");

        fs::write(
            &node_path,
            r#"
[network]
id = 1266
name = "synergy-testnet"
p2p_port = 5622
rpc_port = 5640
ws_port = 5660
bootnodes = ["bootnode1.synergy-network.io:5620"]

[blockchain]
block_time = 5
max_gas_limit = "0x2fefd8"
chain_id = 1266

[consensus]
algorithm = "Proof of Synergy"
block_time_secs = 5
epoch_length = 1000
validator_cluster_size = 6
validator_vote_threshold = 0
max_validators = 0
synergy_score_decay_rate = 0.05
vrf_enabled = true
vrf_seed_epoch_interval = 1000
max_synergy_points_per_epoch = 100
max_tasks_per_validator = 10

[consensus.reward_weighting]
task_accuracy = 0.5
uptime = 0.3
collaboration = 0.2

[logging]
log_level = "info"
log_file = "data/logs/validator.log"
enable_console = true
max_file_size = 10485760
max_files = 5

[rpc]
enable_http = true
http_port = 5640
enable_ws = true
ws_port = 5660
enable_grpc = true
grpc_port = 5640
cors_enabled = false
cors_origins = []

[p2p]
listen_address = "0.0.0.0:5622"
public_address = "127.0.0.1:5622"
node_name = "node-01"
enable_discovery = true
discovery_port = 5680
heartbeat_interval = 10

[storage]
database = "rocksdb"
path = "data/chain"
enable_pruning = false
pruning_interval = 86400
"#,
        )
        .expect("node.toml should be written");

        fs::write(
            &peers_path,
            r#"
[global]
bootnodes = ["bootnode2.synergy-network.io:5620"]
seed_servers = ["http://seed2.synergy-network.io:5621"]
bootstrap_dns_records = ["_dnsaddr.bootstrap.synergy-network.io"]
persistent_peers = ["genesisval2.synergy-network.io:5622"]
additional_dial_targets = ["62.146.182.208:39638"]
"#,
        )
        .expect("peers.toml should be written");

        let content = fs::read_to_string(&node_path).expect("node.toml should be readable");
        let config =
            parse_node_config_content(&content, Some(&node_path)).expect("config should parse");

        assert_eq!(config.network.bootnodes.len(), 2);
        assert!(config
            .network
            .bootnodes
            .contains(&"bootnode1.synergy-network.io:5620".to_string()));
        assert!(config
            .network
            .bootnodes
            .contains(&"bootnode2.synergy-network.io:5620".to_string()));
        assert_eq!(
            config.network.seed_servers,
            vec!["http://seed2.synergy-network.io:5621".to_string()]
        );
        assert_eq!(
            config.network.bootstrap_dns_records,
            vec!["_dnsaddr.bootstrap.synergy-network.io".to_string()]
        );
        assert_eq!(
            config.network.persistent_peers,
            vec!["genesisval2.synergy-network.io:5622".to_string()]
        );
        assert_eq!(
            config.network.additional_dial_targets,
            vec!["62.146.182.208:39638".to_string()]
        );

        fs::remove_file(&node_path).ok();
        fs::remove_file(&peers_path).ok();
        fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn preserves_explicit_p2p_public_address_for_initial_validator_configs() {
        let content = r#"
[identity]
node_id = "synv11e3ephsarcw6mey0fx5xtnygg2ewegnum4re"
role = "validator"
address = "synv11e3ephsarcw6mey0fx5xtnygg2ewegnum4re"
label = "Validator 3 Node"

[network]
chain_name = "synergy-testnet"
chain_id = 1266
p2p_port = 5622
public_host = "genesisval3.synergy-network.io"

[p2p]
listen_address = "0.0.0.0:5622"
public_address = "genesisval3.synergy-network.io:5622"
"#;

        let config = parse_node_config_content(content, None).expect("config should parse");

        assert_eq!(config.network.p2p_port, 5622);
        assert_eq!(
            config.p2p.public_address,
            "genesisval3.synergy-network.io:5622".to_string()
        );
    }

    #[test]
    fn synthesizes_public_address_from_public_host_when_explicit_value_missing() {
        let content = r#"
[network]
chain_name = "synergy-testnet"
chain_id = 1266
p2p_port = 5622
public_host = "genesisval1.synergy-network.io"

[p2p]
listen_address = "0.0.0.0:5622"
"#;

        let config = parse_node_config_content(content, None).expect("config should parse");

        assert_eq!(
            config.p2p.public_address,
            "genesisval1.synergy-network.io:5622".to_string()
        );
        assert_eq!(
            config.p2p.discovery_public_address,
            "genesisval1.synergy-network.io:5680".to_string()
        );
    }

    #[test]
    fn parses_explicit_discovery_addresses_from_compatibility_blocks() {
        let content = r#"
[network]
chain_name = "synergy-testnet"
chain_id = 1266
p2p_port = 5622
public_host = "genesisval1.synergy-network.io"

[p2p]
listen_address = "0.0.0.0:5622"
external_addr = "genesisval1.synergy-network.io:5622"
enable_discovery = true
discovery_port = 5680

[discovery]
listen_addr = "0.0.0.0:5680"
external_addr = "genesisval1.synergy-network.io:5680"
"#;

        let config = parse_node_config_content(content, None).expect("config should parse");

        assert_eq!(config.p2p.listen_address, "0.0.0.0:5622");
        assert_eq!(
            config.p2p.public_address,
            "genesisval1.synergy-network.io:5622"
        );
        assert_eq!(config.p2p.discovery_listen_address, "0.0.0.0:5680");
        assert_eq!(
            config.p2p.discovery_public_address,
            "genesisval1.synergy-network.io:5680"
        );
    }

    #[test]
    fn parses_peer_exchange_runtime_controls() {
        let content = r#"
[p2p]
enable_discovery = true
enable_peer_exchange = false
reject_private_advertise_addrs = false
"#;

        let config = parse_node_config_content(content, None).expect("config should parse");

        assert!(!config.p2p.enable_peer_exchange);
        assert!(!config.p2p.reject_private_advertise_addrs);
    }

    #[test]
    fn legacy_discovery_configs_enable_peer_exchange_compatibly() {
        let content = r#"
[p2p]
enable_discovery = true
"#;

        let config = parse_node_config_content(content, None).expect("config should parse");

        assert!(config.p2p.enable_peer_exchange);
        assert!(config.p2p.reject_private_advertise_addrs);
    }

    #[test]
    fn parses_validator_state_sync_before_join() {
        let content = r#"
[validator]
participation = "active"
verify_quorum_certificates = true
state_sync_before_join = true
"#;

        let config = parse_node_config_content(content, None).expect("config should parse");

        assert_eq!(config.validator.participation, "active");
        assert!(config.validator.verify_quorum_certificates);
        assert!(config.validator.state_sync_before_join);
    }

    #[test]
    fn apply_env_overrides_sets_explicit_runtime_network_addresses() {
        let _lock = ENV_MUTEX.lock().expect("env mutex should lock");
        let _p2p_listen = EnvVarGuard::set("SYNERGY_P2P_LISTEN_ADDRESS", "0.0.0.0:5622");
        let _p2p_external = EnvVarGuard::set(
            "SYNERGY_P2P_EXTERNAL_ADDRESS",
            "genesisval1.synergy-network.io:5622",
        );
        let _discovery_listen =
            EnvVarGuard::set("SYNERGY_DISCOVERY_LISTEN_ADDRESS", "0.0.0.0:5680");
        let _discovery_external = EnvVarGuard::set(
            "SYNERGY_DISCOVERY_EXTERNAL_ADDRESS",
            "genesisval1.synergy-network.io:5680",
        );

        let config = apply_env_overrides(NodeConfig::default()).expect("env overrides should load");

        assert_eq!(config.p2p.listen_address, "0.0.0.0:5622");
        assert_eq!(
            config.p2p.public_address,
            "genesisval1.synergy-network.io:5622"
        );
        assert_eq!(config.p2p.discovery_listen_address, "0.0.0.0:5680");
        assert_eq!(
            config.p2p.discovery_public_address,
            "genesisval1.synergy-network.io:5680"
        );
    }

    #[test]
    fn apply_env_overrides_accepts_mesh_stability_controls() {
        let _lock = ENV_MUTEX.lock().expect("env mutex should lock");
        let _persistent_peers = EnvVarGuard::set(
            "SYNERGY_PERSISTENT_PEERS",
            "genesisval2.synergy-network.io:5622,62.146.182.208:5622",
        );
        let _status_gate = EnvVarGuard::set("SYNERGY_CONSENSUS_STATUS_READY_GATE_ENABLED", "false");
        let _status_min = EnvVarGuard::set("SYNERGY_CONSENSUS_STATUS_READY_MIN_VALIDATORS", "3");
        let _status_grace =
            EnvVarGuard::set("SYNERGY_CONSENSUS_STATUS_READY_GENESIS_GRACE_SECS", "25");
        let _leader_timeout = EnvVarGuard::set("SYNERGY_CONSENSUS_LEADER_TIMEOUT_SECS", "21");
        let _vote_timeout = EnvVarGuard::set("SYNERGY_CONSENSUS_VOTE_TIMEOUT_SECS", "11");
        let _block_timeout = EnvVarGuard::set("SYNERGY_CONSENSUS_BLOCK_TIMEOUT_SECS", "9");
        let _penalization = EnvVarGuard::set("SYNERGY_CONSENSUS_PENALIZATION_ENABLED", "false");
        let _bootstrap_refresh = EnvVarGuard::set("SYNERGY_P2P_BOOTSTRAP_REFRESH_SECS", "61");

        let config = apply_env_overrides(NodeConfig::default()).expect("env overrides should load");

        assert_eq!(
            config.network.persistent_peers,
            vec![
                "genesisval2.synergy-network.io:5622".to_string(),
                "62.146.182.208:5622".to_string()
            ]
        );
        assert!(!config.consensus.status_ready_gate_enabled);
        assert_eq!(config.consensus.status_ready_min_validators, 3);
        assert_eq!(config.consensus.status_ready_genesis_grace_secs, 25);
        assert_eq!(config.consensus.leader_timeout_secs, 21);
        assert_eq!(config.consensus.vote_timeout_secs, 11);
        assert_eq!(config.consensus.block_timeout_secs, 9);
        assert!(!config.consensus.penalization_enabled);
        assert_eq!(config.p2p.bootstrap_refresh_secs, 61);
    }

    #[test]
    fn dynamic_committee_templates_keep_safety_floor_without_freezing_growth() {
        let templates_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../templates");
        let entries = fs::read_dir(&templates_dir).expect("templates directory should be readable");
        let mut checked = 0usize;

        for entry in entries {
            let path = entry.expect("template entry should be readable").path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("toml") {
                continue;
            }
            let content = fs::read_to_string(&path).expect("template should be readable");
            let value = content
                .parse::<toml::Value>()
                .expect("template should be valid TOML");
            let consensus = value
                .get("consensus")
                .and_then(toml::Value::as_table)
                .expect("template should define consensus section");
            let cluster_size = consensus
                .get("validator_cluster_size")
                .and_then(toml::Value::as_integer)
                .expect("template should define validator_cluster_size");

            if cluster_size == 6 {
                let min_validators = consensus
                    .get("min_validators")
                    .and_then(toml::Value::as_integer)
                    .expect("stable committee template should define min_validators");
                let ready_min = consensus
                    .get("status_ready_min_validators")
                    .and_then(toml::Value::as_integer)
                    .expect("stable committee template should define status_ready_min_validators");
                let max_validators = consensus
                    .get("max_validators")
                    .and_then(toml::Value::as_integer)
                    .expect("stable committee template should define max_validators");
                assert!(
                    min_validators >= 4,
                    "{} regressed min_validators below 4",
                    path.display()
                );
                assert!(
                    ready_min >= 4,
                    "{} regressed status_ready_min_validators below 4",
                    path.display()
                );
                assert_eq!(
                    max_validators,
                    0,
                    "{} must keep max_validators dynamic instead of capping the network at 6",
                    path.display()
                );
                for flag in [
                    "emergency_stable_committee_mode",
                    "freeze_validator_set",
                    "freeze_score_weighted_proposer_order",
                ] {
                    assert_eq!(
                        consensus.get(flag).and_then(toml::Value::as_bool),
                        Some(false),
                        "{} must leave {flag} disabled for automatic validator growth",
                        path.display()
                    );
                }
                checked += 1;
            }
        }

        assert!(
            checked > 0,
            "expected at least one dynamic committee template"
        );
    }

    #[test]
    fn resolve_runtime_validator_address_prefers_env() {
        let _lock = ENV_MUTEX.lock().expect("env mutex should lock");
        let _validator = EnvVarGuard::set(
            "SYNERGY_VALIDATOR_ADDRESS",
            "synv11s4wc6l4kg4jr0k5meg42cyzxa03cf863srt",
        );
        let _node_address = EnvVarGuard::clear("NODE_ADDRESS");
        let _config_path = EnvVarGuard::clear("SYNERGY_CONFIG_PATH");

        assert_eq!(
            resolve_runtime_validator_address().as_deref(),
            Some("synv11s4wc6l4kg4jr0k5meg42cyzxa03cf863srt")
        );
    }

    #[test]
    fn resolve_runtime_validator_address_falls_back_to_config() {
        let _lock = ENV_MUTEX.lock().expect("env mutex should lock");
        let _validator = EnvVarGuard::clear("SYNERGY_VALIDATOR_ADDRESS");
        let _node_address = EnvVarGuard::clear("NODE_ADDRESS");

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_dir = crate::utils::test_temp_root(format!("synergy-config-identity-{unique}"));
        fs::create_dir_all(&temp_dir).expect("temp dir should be created");
        let config_path = temp_dir.join("node.toml");
        fs::write(
            &config_path,
            r#"
[network]
id = 1266
name = "synergy-testnet"
p2p_port = 5622
rpc_port = 5640
ws_port = 5660
max_peers = 32

[blockchain]
block_time = 5
max_gas_limit = "0x2fefd8"
chain_id = 1266

[consensus]
algorithm = "Proof of Synergy"
block_time_secs = 5
epoch_length = 1000
validator_cluster_size = 6
validator_vote_threshold = 0
max_validators = 0
synergy_score_decay_rate = 0.05
vrf_enabled = true
vrf_seed_epoch_interval = 1000
max_synergy_points_per_epoch = 100
max_tasks_per_validator = 10

[consensus.reward_weighting]
task_accuracy = 0.5
uptime = 0.3
collaboration = 0.2

[logging]
log_level = "info"
log_file = "data/logs/validator.log"
enable_console = true
max_file_size = 10485760
max_files = 5

[rpc]
bind_address = "127.0.0.1:5640"
enable_http = true
http_port = 5640
enable_ws = true
ws_port = 5660
enable_grpc = true
grpc_port = 5640
cors_enabled = false
cors_origins = []

[p2p]
listen_address = "0.0.0.0:5622"
public_address = "62.146.182.207:5622"
node_name = "testnet-test"
enable_discovery = true
discovery_port = 5680
heartbeat_interval = 10

[storage]
database = "rocksdb"
path = "data/chain"
enable_pruning = false
pruning_interval = 86400

[node]
validator_address = "synv11mka64uz049aekwhdvfrq6dvh75d0k7kmdp5"
"#,
        )
        .expect("config should write");
        let _config_path = EnvVarGuard::set(
            "SYNERGY_CONFIG_PATH",
            config_path.to_str().expect("config path should be utf-8"),
        );

        assert_eq!(
            resolve_runtime_validator_address().as_deref(),
            Some("synv11mka64uz049aekwhdvfrq6dvh75d0k7kmdp5")
        );

        fs::remove_file(&config_path).ok();
        fs::remove_dir_all(&temp_dir).ok();
    }
}
