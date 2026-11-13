//! Runtime-owned implementation of the shared node administration contract.
//!
//! This module is the single decision point used by the terminal client today
//! and by the local Admin API transport/Node Control Panel as it is connected.
//! It is intentionally observational at this stage: lifecycle-changing
//! operations remain in the runtime until they have explicit authorization,
//! idempotency, and recovery semantics.

use std::fs;
use std::net::SocketAddr;
use std::path::Path;

use serde::Serialize;
use serde_json::{json, Value};
use synergy_admin_api::{AdminError, AdminRequest, AdminResponse, AdminService};
use synergy_node_core::{
    DiagnosticCheck, ManagementOperation, NodeLifecycleState, ReadinessReport,
};

use crate::config::{self, NodeConfig, ResolvedConsensusMode};
use crate::role_profiles::{self, NodeRole, RoleProfile};

const FORBIDDEN_AUTHORITY_FIELDS: &[&str] = &[
    "stake_weight",
    "bonded_weight",
    "voting_weight",
    "voting_power",
    "validator_power",
    "quorum_weight",
];

#[derive(Debug, Clone)]
pub struct NodeManagementCore {
    config_path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NodeStatus {
    pub lifecycle: NodeLifecycleState,
    pub chain_id: u64,
    pub network_id: String,
    pub node_id: Option<String>,
    pub role: Option<RoleStatus>,
    pub consensus_mode: String,
    pub p2p_listen_address: String,
    pub storage_path: String,
    pub readiness: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RoleStatus {
    pub role_id: String,
    pub display_name: String,
    pub compiled_profile: String,
    pub authority_plane: String,
    pub service_surface: Vec<String>,
    pub required_ports: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HealthReport {
    pub healthy: bool,
    pub checks: Vec<DiagnosticCheck>,
}

impl NodeManagementCore {
    pub fn new(config_path: Option<String>) -> Self {
        Self { config_path }
    }

    pub fn status(&self) -> Result<NodeStatus, AdminError> {
        let config = self.load_config()?;
        let checks = self.diagnostic_checks_for(&config)?;
        let role = resolve_role(&config)?;
        let lifecycle = lifecycle_for(&config, role, &checks);
        let readiness = !checks.iter().any(|check| check.state.is_blocking())
            && matches!(
                lifecycle,
                NodeLifecycleState::Ready | NodeLifecycleState::Active
            );

        Ok(NodeStatus {
            lifecycle,
            chain_id: config.blockchain.chain_id,
            network_id: config.network.network_id,
            node_id: non_empty(&config.identity.node_id).map(str::to_owned),
            role: role.map(role_status),
            consensus_mode: config.consensus.mode,
            p2p_listen_address: config.p2p.listen_address,
            storage_path: config.storage.path,
            readiness,
        })
    }

    pub fn health(&self) -> Result<HealthReport, AdminError> {
        let config = self.load_config()?;
        let checks = self.diagnostic_checks_for(&config)?;
        Ok(HealthReport {
            healthy: !checks.iter().any(|check| check.state.is_blocking()),
            checks,
        })
    }

    pub fn readiness(&self) -> Result<ReadinessReport, AdminError> {
        let status = self.status()?;
        let config = self.load_config()?;
        let checks = self.diagnostic_checks_for(&config)?;
        let blocking_checks = checks
            .iter()
            .filter(|check| check.state.is_blocking())
            .map(|check| check.id.clone())
            .collect();
        Ok(ReadinessReport {
            ready: status.readiness,
            lifecycle: status.lifecycle,
            blocking_checks,
            checks,
        })
    }

    pub fn diagnostic_checks(&self) -> Result<Vec<DiagnosticCheck>, AdminError> {
        let config = self.load_config()?;
        self.diagnostic_checks_for(&config)
    }

    pub fn role_status(&self) -> Result<Option<RoleStatus>, AdminError> {
        let config = self.load_config()?;
        Ok(resolve_role(&config)?.map(role_status))
    }

    fn load_config(&self) -> Result<NodeConfig, AdminError> {
        if let Some(path) = self.config_path.as_deref() {
            if !Path::new(path).is_file() {
                return Err(AdminError::invalid_request(format!(
                    "configuration file does not exist: {path}"
                )));
            }
            let text = fs::read_to_string(path).map_err(|error| {
                AdminError::unavailable(format!("read configuration {path}: {error}"))
            })?;
            reject_legacy_authority_fields(&text).map_err(AdminError::invalid_request)?;
        }

        config::load_node_config(self.config_path.as_deref()).map_err(|error| {
            AdminError::invalid_request(format!("load node configuration: {error}"))
        })
    }

    fn diagnostic_checks_for(
        &self,
        config: &NodeConfig,
    ) -> Result<Vec<DiagnosticCheck>, AdminError> {
        let mut checks = Vec::new();
        checks.push(DiagnosticCheck::passed(
            "network.binding",
            "configuration",
            format!(
                "chain {} and network {} passed canonical configuration validation",
                config.blockchain.chain_id, config.network.network_id
            ),
        ));

        match config.consensus.resolve_mode(config.blockchain.chain_id, &config.network.network_id) {
            Ok(ResolvedConsensusMode::PosySimplifiedV3) => checks.push(DiagnosticCheck::passed(
                "consensus.posy_authority",
                "consensus",
                "PoSy simplified v3 is selected; validator authority is Genesis-bound",
            )),
            Ok(ResolvedConsensusMode::CoordinatedRoundRobinV1(_)) => checks.push(DiagnosticCheck::failed(
                "consensus.posy_authority",
                "consensus",
                "coordinated round-robin is not authorized for this fresh Chain 1266 node",
                "set consensus.mode to posy_simplified_v3 and use the canonical release binding",
            )),
            Err(error) => checks.push(DiagnosticCheck::failed(
                "consensus.posy_authority",
                "consensus",
                format!("consensus configuration is invalid: {error}"),
                "restore the canonical PoSy configuration; do not configure local voting weights",
            )),
        }

        match resolve_role(config) {
            Ok(Some(role)) => checks.push(DiagnosticCheck::passed(
                "role.profile",
                "node",
                format!(
                    "role {} resolves to {}",
                    role.role_id, role.compiled_profile
                ),
            )),
            Ok(None) => checks.push(DiagnosticCheck::failed(
                "role.profile",
                "node",
                "node role has not been configured",
                "initialize a node identity and select a supported role before starting services",
            )),
            Err(error) => checks.push(DiagnosticCheck::failed(
                "role.profile",
                "node",
                error.message,
                "make identity.role and role.compiled_profile refer to the same supported role",
            )),
        }

        if non_empty(&config.identity.node_id).is_some() {
            checks.push(DiagnosticCheck::passed(
                "identity.node_id",
                "identity",
                "node identity is configured",
            ));
        } else {
            checks.push(DiagnosticCheck::failed(
                "identity.node_id",
                "identity",
                "node identity is missing",
                "initialize or import a cryptographic node identity before joining the network",
            ));
        }

        if config.p2p.listen_address.parse::<SocketAddr>().is_ok() {
            checks.push(DiagnosticCheck::passed(
                "p2p.listen_address",
                "p2p",
                format!("P2P listen address {} is valid", config.p2p.listen_address),
            ));
        } else {
            checks.push(DiagnosticCheck::failed(
                "p2p.listen_address",
                "p2p",
                format!(
                    "P2P listen address {} is invalid",
                    config.p2p.listen_address
                ),
                "configure p2p.listen_address as a concrete host:port socket address",
            ));
        }

        if config.rpc.bind_address.parse::<SocketAddr>().is_ok() {
            checks.push(DiagnosticCheck::passed(
                "rpc.bind_address",
                "rpc",
                format!("RPC bind address {} is valid", config.rpc.bind_address),
            ));
        } else {
            checks.push(DiagnosticCheck::failed(
                "rpc.bind_address",
                "rpc",
                format!("RPC bind address {} is invalid", config.rpc.bind_address),
                "configure rpc.bind_address as a concrete host:port socket address",
            ));
        }

        let storage = Path::new(&config.storage.path);
        if storage.exists() {
            checks.push(DiagnosticCheck::passed(
                "storage.path",
                "storage",
                format!("storage path {} is accessible", storage.display()),
            ));
        } else if storage.parent().map(Path::exists).unwrap_or(false) {
            checks.push(DiagnosticCheck::warning(
                "storage.path",
                "storage",
                format!("storage path {} does not exist yet", storage.display()),
                "the runtime will create storage only during an authorized start operation",
            ));
        } else {
            checks.push(DiagnosticCheck::failed(
                "storage.path",
                "storage",
                format!("storage parent for {} is unavailable", storage.display()),
                "create or mount the configured storage parent before starting the node",
            ));
        }

        let validator_without_custody = matches!(
            resolve_role(config),
            Ok(Some(role)) if role.role == NodeRole::Validator
        ) && non_empty(&config.identity.encrypted_custody_path)
            .is_none();
        if validator_without_custody {
            checks.push(DiagnosticCheck::failed(
                "validator.custody",
                "identity",
                "validator role has no encrypted Aegis custody path",
                "initialize or import encrypted validator custody through the shared onboarding flow",
            ));
        }

        Ok(checks)
    }
}

/// Starts the local-only Unix-domain Admin API for a running node. The socket
/// is intentionally separate from public RPC and P2P listeners.
#[cfg(unix)]
pub fn start_local_admin_api(
    config_path: Option<String>,
    socket_path: impl AsRef<Path>,
) -> Result<synergy_admin_api::local::LocalAdminServer, AdminError> {
    synergy_admin_api::local::LocalAdminServer::start(
        socket_path,
        std::sync::Arc::new(NodeManagementCore::new(config_path)),
    )
}

impl AdminService for NodeManagementCore {
    fn handle(&self, request: AdminRequest) -> AdminResponse {
        let request_id = request.request_id.clone();
        if let Err(error) = request.validate() {
            return AdminResponse::failure(request_id, error);
        }
        let result = match request.operation {
            ManagementOperation::NodeStatus => self.status().and_then(to_json),
            ManagementOperation::Health => self.health().and_then(to_json),
            ManagementOperation::Readiness => self.readiness().and_then(to_json),
            ManagementOperation::Diagnostics => self.diagnostic_checks().and_then(|checks| {
                to_json(HealthReport {
                    healthy: !checks.iter().any(|check| check.state.is_blocking()),
                    checks,
                })
            }),
            ManagementOperation::ConfigurationValidation => self.health().and_then(|health| {
                to_json(json!({
                    "valid": health.healthy,
                    "checks": health.checks,
                }))
            }),
            ManagementOperation::RoleInspection => self.role_status().and_then(to_json),
            ManagementOperation::CapabilityDiscovery => to_json(json!({
                "operations": ManagementOperation::ALL,
                "mutating_operations": [],
                "transport": "runtime_dispatcher",
            })),
        };
        match result {
            Ok(value) => AdminResponse::success(request_id, value),
            Err(error) => AdminResponse::failure(request_id, error),
        }
    }
}

fn to_json<T: Serialize>(value: T) -> Result<Value, AdminError> {
    serde_json::to_value(value)
        .map_err(|error| AdminError::unavailable(format!("serialize management response: {error}")))
}

fn resolve_role(config: &NodeConfig) -> Result<Option<&'static RoleProfile>, AdminError> {
    role_profiles::resolve_configured_role(&config.identity.role, &config.role.compiled_profile)
        .map_err(AdminError::invalid_request)
}

fn role_status(role: &RoleProfile) -> RoleStatus {
    RoleStatus {
        role_id: role.role_id.to_string(),
        display_name: role.display_name.to_string(),
        compiled_profile: role.compiled_profile.to_string(),
        authority_plane: format!("{:?}", role.authority_plane).to_lowercase(),
        service_surface: role
            .service_surface
            .iter()
            .map(|item| (*item).to_string())
            .collect(),
        required_ports: role
            .required_ports
            .iter()
            .map(|item| (*item).to_string())
            .collect(),
    }
}

fn lifecycle_for(
    config: &NodeConfig,
    role: Option<&RoleProfile>,
    checks: &[DiagnosticCheck],
) -> NodeLifecycleState {
    if role.is_none() || non_empty(&config.identity.node_id).is_none() {
        return NodeLifecycleState::Uninitialized;
    }
    if checks.iter().any(|check| check.state.is_blocking()) {
        return NodeLifecycleState::Degraded;
    }
    NodeLifecycleState::Ready
}

fn non_empty(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}

fn reject_legacy_authority_fields(config_text: &str) -> Result<(), String> {
    for (line_number, raw_line) in config_text.lines().enumerate() {
        let key = raw_line.split('#').next().unwrap_or_default().trim();
        let Some((field, _)) = key.split_once('=') else {
            continue;
        };
        let field = field.trim().trim_matches('"');
        if FORBIDDEN_AUTHORITY_FIELDS.contains(&field) {
            return Err(format!(
                "configuration line {} uses forbidden PoS-derived authority field '{field}'",
                line_number + 1
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_pos_derived_authority_keys_without_renaming_them() {
        let error = reject_legacy_authority_fields("[consensus]\nvoting_weight = 1")
            .expect_err("weight-based authority must be rejected");
        assert!(error.contains("voting_weight"));
    }

    #[test]
    fn allows_synergy_score_reward_configuration() {
        reject_legacy_authority_fields("[consensus]\nsynergy_score_decay_rate = 0.1")
            .expect("reward configuration is not finality authority");
    }

    #[test]
    fn unknown_role_is_reported_as_a_configuration_error() {
        let mut config = NodeConfig::default();
        config.identity.role = "not-a-role".to_string();
        let error = resolve_role(&config).expect_err("unknown role must not resolve");
        assert_eq!(error.code, "invalid_request");
    }
}
