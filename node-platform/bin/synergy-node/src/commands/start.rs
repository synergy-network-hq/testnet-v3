use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

use synergy_config::{load, ConfigLoadError, ConsensusMode, NodeConfiguration, VpnMode};
use synergy_node_core::{
    LifecycleController, LifecycleTransitionError, ManagedService, NodeLifecycleState,
    RuntimeSnapshot, RuntimeView, ServiceHealth, ServiceId, ServiceObservation, ServiceReadiness,
    ServiceSpec, ServiceState, StartupPlan, Supervisor, SupervisorError,
};
use synergy_protocol_types::NodeRole;
use synergy_roles::{
    AuthorityPlane, Capability, RolePorts, RoleProfile, ServiceBinding as RoleServiceBinding,
    ServiceId as RoleServiceId,
};
use synergy_ws::server::WsServer;

use crate::services::{
    admin, authority, etdag, execution, health, identity, ingress, network, posy, preparation,
    protected_admission, rpc, sentry, storage, sync, telemetry, vpn, websocket,
};

pub type ServiceRegistration = (ServiceSpec, Box<dyn ManagedService>);

/// A node whose configuration, lifecycle, and concrete service graph have
/// passed startup. The caller must retain this value for the process lifetime.
pub struct StartedNode {
    configuration: NodeConfiguration,
    verified_genesis_hash: String,
    startup_plan: StartupPlan,
    lifecycle: LifecycleController,
    supervisor: Supervisor,
    runtime_view: RuntimeView,
    authority_transition: authority::AuthorityTransitionSignal,
    has_external_services: bool,
    authorized_production_consensus: bool,
    preparation: preparation::Pool,
    #[cfg(feature = "qualification-timing")]
    qualification_timing: Option<crate::services::qualification_timing::QualificationTiming>,
}

impl StartedNode {
    pub fn run(mut self) -> Result<(), StartError> {
        let running = Arc::new(AtomicBool::new(true));
        let signal_state = Arc::clone(&running);
        if let Err(error) = ctrlc::set_handler(move || signal_state.store(false, Ordering::Release))
        {
            self.fail_and_shutdown();
            return Err(StartError::SignalHandler(error.to_string()));
        }
        if let Err(error) = self.refresh_runtime_view() {
            self.fail_and_shutdown();
            return Err(error);
        }
        while running.load(Ordering::Acquire) {
            if let Err(reason) = self.preparation.handle().health() {
                self.fail_and_shutdown();
                return Err(StartError::AuthorityTransition(reason));
            }
            let poll = self.supervisor.poll_all();
            if matches!(poll, Err(SupervisorError::Cancelled)) {
                break;
            }
            let tick = poll
                .map_err(StartError::Supervisor)
                .and_then(|_| self.advance_readiness())
                .and_then(|_| self.refresh_runtime_view());
            if let Err(error) = tick {
                self.fail_and_shutdown();
                return Err(error);
            }
            let pending_epoch = self
                .authority_transition
                .take()
                .map_err(StartError::AuthorityTransition)?;
            if let Some(next_epoch) = pending_epoch {
                if let Err(error) = self.reload_authority_graph(next_epoch) {
                    self.fail_and_shutdown();
                    return Err(error);
                }
            }
            thread::sleep(Duration::from_millis(50));
        }
        self.lifecycle
            .transition(NodeLifecycleState::Stopping)
            .map_err(StartError::Lifecycle)?;
        let report = self.supervisor.shutdown();
        if !report.clean() {
            let _ = self.lifecycle.transition(NodeLifecycleState::Failed);
            self.refresh_runtime_view()?;
            return Err(StartError::ShutdownFailures(report.failed));
        }
        self.preparation
            .shutdown()
            .map_err(StartError::AuthorityTransition)?;
        self.lifecycle
            .transition(NodeLifecycleState::Stopped)
            .map_err(StartError::Lifecycle)?;
        self.refresh_runtime_view()?;
        Ok(())
    }

    fn reload_authority_graph(&mut self, expected_epoch: u64) -> Result<(), StartError> {
        if self.has_external_services {
            return Err(StartError::AuthorityTransition(
                "cannot reconstruct externally supplied runtime services at an epoch boundary"
                    .into(),
            ));
        }
        let loaded = authority::load(&self.configuration)
            .map_err(StartError::AuthorityTransition)?
            .ok_or_else(|| {
                StartError::AuthorityTransition(
                    "persisted successor authority binding is unavailable".into(),
                )
            })?;
        if loaded.epoch.epoch != expected_epoch {
            return Err(StartError::AuthorityTransition(format!(
                "persisted authority epoch {} differs from staged epoch {expected_epoch}",
                loaded.epoch.epoch
            )));
        }
        let report = self.supervisor.shutdown();
        if !report.clean() {
            return Err(StartError::ShutdownFailures(report.failed));
        }
        self.preparation
            .shutdown()
            .map_err(StartError::AuthorityTransition)?;
        self.preparation = preparation::Pool::new().map_err(StartError::AuthorityTransition)?;
        let mut registrations = Vec::new();
        self.authorized_production_consensus = false;
        let authorized_production_consensus = register_builtin_services(
            &self.configuration,
            &self.verified_genesis_hash,
            &self.runtime_view,
            &mut registrations,
            self.authority_transition.clone(),
            self.preparation.handle(),
        )?;
        require_complete_service_set(&self.startup_plan, &registrations)?;
        let mut supervisor = Supervisor::new(registrations).map_err(StartError::Supervisor)?;
        #[cfg(feature = "qualification-timing")]
        if self.qualification_timing.is_some() {
            supervisor.enable_poll_timing(true);
        }
        supervisor.start_all().map_err(StartError::Supervisor)?;
        self.supervisor = supervisor;
        self.authorized_production_consensus = authorized_production_consensus;
        self.refresh_runtime_view()
    }

    fn fail_and_shutdown(&mut self) {
        let _ = self.lifecycle.transition(NodeLifecycleState::Failed);
        let _ = self.supervisor.shutdown();
        let _ = self.preparation.shutdown();
        let _ = self.refresh_runtime_view();
    }

    fn advance_readiness(&mut self) -> Result<(), StartError> {
        advance_lifecycle_readiness(
            &mut self.lifecycle,
            self.startup_plan.shadow_before_active,
            self.authorized_production_consensus,
            &self.supervisor.observations(),
        )
        .map_err(StartError::Lifecycle)
    }

    fn refresh_runtime_view(&self) -> Result<(), StartError> {
        let snapshot = RuntimeSnapshot {
            node_name: self.configuration.node_name.clone(),
            role: format!("{:?}", self.configuration.role).to_ascii_lowercase(),
            chain_id: self.configuration.chain_id,
            lifecycle: self.lifecycle.state(),
            services: self.supervisor.observations(),
        };
        *self
            .runtime_view
            .write()
            .map_err(|_| StartError::RuntimeViewPoisoned)? = snapshot;
        Ok(())
    }
}

fn advance_lifecycle_readiness(
    lifecycle: &mut LifecycleController,
    shadow_before_active: bool,
    authorized_production_consensus: bool,
    services: &[ServiceObservation],
) -> Result<(), LifecycleTransitionError> {
    let all_ready = !services.is_empty()
        && services.iter().all(|service| {
            service.state == ServiceState::Running
                && service.health == ServiceHealth::Healthy
                && service.readiness == ServiceReadiness::Ready
        });
    match (lifecycle.state(), all_ready) {
        (NodeLifecycleState::Starting, true) if shadow_before_active => {
            lifecycle.transition(NodeLifecycleState::Shadowing)?;
        }
        (NodeLifecycleState::Starting, true) => {
            lifecycle.transition(NodeLifecycleState::Ready)?;
            lifecycle.transition(NodeLifecycleState::Active)?;
        }
        (NodeLifecycleState::Shadowing, true) if authorized_production_consensus => {
            lifecycle.transition(NodeLifecycleState::Ready)?;
            lifecycle.transition(NodeLifecycleState::Active)?;
        }
        _ => {}
    }
    Ok(())
}

/// CLI entry point for the complete configured supervised service graph.
pub fn run(config_path: &Path) -> Result<(), StartError> {
    let configuration = load(config_path).map_err(StartError::Configuration)?;
    // Fail before custody unlock, lifecycle transition, or listener creation.
    let capacity_authority =
        authority::load(&configuration).map_err(StartError::AuthorityTransition)?;
    validate_processing_memory(&configuration, capacity_authority.as_deref())
        .map_err(StartError::AuthorityTransition)?;
    drop(capacity_authority);
    start_with_services(config_path, Vec::new())?.run()
}

/// Read-only configuration/public-authority checks. Never registers or starts
/// services, opens storage, reads private custody, or binds a listener.
pub fn preflight(config_path: &Path) -> Result<serde_json::Value, String> {
    let metadata = std::fs::symlink_metadata(config_path)
        .map_err(|error| format!("inspect preflight configuration: {error}"))?;
    if !config_path.is_absolute()
        || !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > 1024 * 1024
    {
        return Err("preflight requires a bounded regular absolute configuration".into());
    }
    let configuration = load(config_path).map_err(|error| error.to_string())?;
    if configuration.apqe_transport.is_some() {
        crate::services::apqe_transport::preflight(&configuration)?;
    } else {
        configuration
            .require_native_post_quantum_transport()
            .map_err(|error| error.to_string())?;
    }
    let genesis_hash = super::selected_network::verify(&configuration)?;
    let verified_authority = authority::load(&configuration)?;
    validate_processing_memory(&configuration, verified_authority.as_deref())?;
    let plan = build_startup_plan(&configuration).map_err(|error| error.to_string())?;
    let public_identity =
        identity::load_public_identity(&configuration.public_identity_path, configuration.role)?;
    let consensus_key_id = preflight_voting_binding(
        configuration.role,
        configuration.consensus.mode,
        verified_authority.as_deref(),
        public_identity.node_address.as_str(),
    )?;
    Ok(serde_json::json!({
        "configuration_verified": true,
        "engineering_transport_profile": configuration.apqe_transport.as_ref().map(|v| &v.profile),
        "production_approved": false,
        "signed_genesis_verified": true,
        "genesis_hash": genesis_hash,
        "signed_authority_verified": verified_authority.is_some(),
        "startup_plan_verified": true,
        "network_id": configuration.network_id,
        "chain_id": configuration.chain_id,
        "role": configuration.role,
        "consensus_mode": configuration.consensus.mode,
        "public_identity_verified": true,
        "node_address": public_identity.node_address.as_str(),
        "validator_membership_verified": consensus_key_id.is_some(),
        "consensus_key_id": consensus_key_id,
        "active_validator_count": verified_authority.as_ref().map(|a| a.registry.active_count()),
        "required_services": plan.required_services,
        "private_keys_verified": false,
        "vpn_service_verified": false,
        "read_only": true
    }))
}

fn validate_processing_memory(
    configuration: &NodeConfiguration,
    authority: Option<&authority::VerifiedAuthority>,
) -> Result<(), String> {
    if configuration.etdag.enabled
        && authority.is_some_and(authority::VerifiedAuthority::processing_profile_enabled)
    {
        crate::services::processing_store::validate_processing_world_capacity(
            configuration.storage.world_memory_budget_bytes,
        )?;
    }
    Ok(())
}

fn preflight_voting_binding(
    role: synergy_protocol_types::NodeRole,
    mode: ConsensusMode,
    authority: Option<&authority::VerifiedAuthority>,
    node_address: &str,
) -> Result<Option<String>, String> {
    if mode != ConsensusMode::ValidateAndVote {
        return Ok(None);
    }
    if role != synergy_protocol_types::NodeRole::Validator {
        return Err("voting preflight requires the validator role".into());
    }
    let authority = authority.ok_or("voting preflight requires signed frozen authority")?;
    let (key_id, _) = authority.consensus_binding(node_address)?;
    Ok(Some(key_id.to_owned()))
}

/// Starts a fully supplied concrete runtime through the canonical lifecycle
/// and dependency-aware supervisor. No service is synthesized or marked
/// healthy by this boundary.
pub fn start_with_services(
    config_path: &Path,
    mut registrations: Vec<ServiceRegistration>,
) -> Result<StartedNode, StartError> {
    let configuration = load(config_path).map_err(StartError::Configuration)?;
    if configuration.apqe_transport.is_some() {
        crate::services::apqe_transport::verify_runtime(&configuration)
            .map_err(StartError::AuthorityTransition)?;
    } else {
        #[cfg(not(test))]
        configuration
            .require_native_post_quantum_transport()
            .map_err(|error| StartError::AuthorityTransition(error.to_string()))?;
    }
    let verified_genesis_hash =
        super::selected_network::verify(&configuration).map_err(StartError::AuthorityTransition)?;
    #[cfg(feature = "qualification-timing")]
    let qualification_timing =
        crate::services::qualification_timing::from_environment(&configuration, config_path)
            .map_err(StartError::AuthorityTransition)?;
    let has_external_services = !registrations.is_empty();
    let authority_transition = authority::AuthorityTransitionSignal::default();
    let preparation = preparation::Pool::new().map_err(StartError::AuthorityTransition)?;
    let mut lifecycle = LifecycleController::new();
    lifecycle
        .transition(NodeLifecycleState::Configured)
        .map_err(StartError::Lifecycle)?;
    let runtime_view = Arc::new(RwLock::new(RuntimeSnapshot {
        node_name: configuration.node_name.clone(),
        role: format!("{:?}", configuration.role).to_ascii_lowercase(),
        chain_id: configuration.chain_id,
        lifecycle: lifecycle.state(),
        services: Vec::new(),
    }));
    let authorized_production_consensus = register_builtin_services(
        &configuration,
        &verified_genesis_hash,
        &runtime_view,
        &mut registrations,
        authority_transition.clone(),
        preparation.handle(),
    )?;
    let startup_plan = build_startup_plan(&configuration)?;
    require_complete_service_set(&startup_plan, &registrations)?;

    let mut supervisor = Supervisor::new(registrations).map_err(StartError::Supervisor)?;
    #[cfg(feature = "qualification-timing")]
    if qualification_timing.is_some() {
        supervisor.enable_poll_timing(true);
    }
    lifecycle
        .transition(NodeLifecycleState::Starting)
        .map_err(StartError::Lifecycle)?;
    if let Err(error) = supervisor.start_all() {
        let _ = lifecycle.transition(NodeLifecycleState::Failed);
        return Err(StartError::Supervisor(error));
    }

    let startup_snapshot = RuntimeSnapshot {
        node_name: configuration.node_name.clone(),
        role: format!("{:?}", configuration.role).to_ascii_lowercase(),
        chain_id: configuration.chain_id,
        lifecycle: lifecycle.state(),
        services: supervisor.observations(),
    };
    match runtime_view.write() {
        Ok(mut view) => *view = startup_snapshot,
        Err(_) => {
            let _ = lifecycle.transition(NodeLifecycleState::Failed);
            let _ = supervisor.shutdown();
            return Err(StartError::RuntimeViewPoisoned);
        }
    }

    Ok(StartedNode {
        configuration,
        verified_genesis_hash,
        startup_plan,
        lifecycle,
        supervisor,
        runtime_view,
        authority_transition,
        has_external_services,
        authorized_production_consensus: authorized_production_consensus && !has_external_services,
        preparation,
        #[cfg(feature = "qualification-timing")]
        qualification_timing,
    })
}

fn register_builtin_services(
    configuration: &NodeConfiguration,
    verified_genesis_hash: &str,
    runtime_view: &RuntimeView,
    registrations: &mut Vec<ServiceRegistration>,
    authority_transition: authority::AuthorityTransitionSignal,
    preparation: preparation::Handle,
) -> Result<bool, StartError> {
    let mut authorized_production_consensus = false;
    let authenticated_ingress = ingress::AuthenticatedIngress::with_world_budget(
        synergy_state::world_resources::WorldResourceBudget::new(
            configuration.storage.world_memory_budget_bytes,
        ),
    );
    let wallet_admission = configuration
        .etdag
        .enabled
        .then(protected_admission::AdmissionHandle::default);
    let verified_authority =
        authority::load(configuration).map_err(|reason| StartError::ServiceRegistration {
            service: "authority",
            reason,
        })?;
    push_builtin(
        registrations,
        "identity",
        identity::registration(&configuration.public_identity_path, configuration.role).map_err(
            |error| StartError::ServiceRegistration {
                service: "identity",
                reason: error.to_string(),
            },
        )?,
    )?;
    let storage_registration = storage::registration(&configuration.storage).map_err(|error| {
        StartError::ServiceRegistration {
            service: "storage",
            reason: error.to_string(),
        }
    })?;
    push_builtin(registrations, "storage", storage_registration)?;
    push_builtin(
        registrations,
        "network",
        network::registration(configuration, authenticated_ingress.clone()).map_err(|reason| {
            StartError::ServiceRegistration {
                service: "network",
                reason,
            }
        })?,
    )?;
    if configuration.etdag.enabled {
        let authority =
            verified_authority
                .clone()
                .ok_or_else(|| StartError::ServiceRegistration {
                    service: "etdag",
                    reason: "ETDAG requires a verified frozen authority binding".into(),
                })?;
        push_builtin(
            registrations,
            "etdag",
            etdag::registration_with_preparation(
                configuration,
                Arc::clone(&authority),
                authenticated_ingress.clone(),
                wallet_admission.clone(),
                Some(preparation.clone()),
            )
            .map_err(|reason| StartError::ServiceRegistration {
                service: "etdag",
                reason,
            })?,
        )?;
        push_builtin(
            registrations,
            "execution",
            execution::registration(configuration, authority, authenticated_ingress.clone())
                .map_err(|reason| StartError::ServiceRegistration {
                    service: "execution",
                    reason,
                })?,
        )?;
    }
    if configuration.vpn.mode != VpnMode::Disabled {
        push_builtin(
            registrations,
            "vpn",
            vpn::registration(
                configuration,
                verified_authority.clone(),
                authenticated_ingress.clone(),
            )
            .map_err(|reason| StartError::ServiceRegistration {
                service: "vpn",
                reason,
            })?,
        )?;
    }
    push_builtin(
        registrations,
        "sync",
        sync::registration_with_preparation(
            configuration,
            verified_authority.clone(),
            authority_transition,
            authenticated_ingress.clone(),
            Some(preparation.clone()),
        )
        .map_err(|reason| StartError::ServiceRegistration {
            service: "sync",
            reason,
        })?,
    )?;
    push_builtin(
        registrations,
        "admin-api",
        admin::registration(
            configuration,
            Arc::clone(runtime_view),
            verified_authority.clone(),
            authenticated_ingress.clone(),
        )
        .map_err(|reason| StartError::ServiceRegistration {
            service: "admin-api",
            reason,
        })?,
    )?;
    if configuration.consensus.mode != ConsensusMode::Disabled {
        push_builtin(
            registrations,
            "posy",
            posy::registration_with_preparation(
                configuration,
                verified_authority
                    .clone()
                    .ok_or_else(|| StartError::ServiceRegistration {
                        service: "posy",
                        reason: "PoSy requires a verified frozen authority binding".into(),
                    })?,
                authenticated_ingress.clone(),
                Some(preparation.clone()),
            )
            .map_err(|reason| StartError::ServiceRegistration {
                service: "posy",
                reason,
            })?,
        )?;
        // Canonical PoSy registration has verified active signed membership and
        // consensus-key possession. Role placement alone cannot set this marker.
        authorized_production_consensus =
            configuration.consensus.mode == ConsensusMode::ValidateAndVote;
    }
    if configuration.rpc.enabled {
        let query_store: Arc<dyn synergy_rpc::provider::CanonicalReadProvider> = Arc::new(
            rpc::CanonicalQueryStore::load_with_world_budget(
                configuration.storage.data_directory.clone(),
                Arc::clone(authenticated_ingress.world_budget()),
            )
            .map_err(|reason| StartError::ServiceRegistration {
                service: "rpc",
                reason,
            })?,
        );
        let websocket_hub = Arc::new(
            WsServer::new(
                configuration.rpc.max_concurrent_requests,
                64,
                configuration.rpc.max_request_bytes,
            )
            .map_err(|error| StartError::ServiceRegistration {
                service: "websocket",
                reason: format!("construct bounded WebSocket hub: {error:?}"),
            })?,
        );
        push_builtin(
            registrations,
            "rpc",
            rpc::registration_with_preparation(
                &configuration.rpc,
                Arc::clone(runtime_view),
                Arc::clone(&query_store),
                Arc::clone(&websocket_hub),
                wallet_admission.clone(),
                Some(preparation.clone()),
                verified_authority
                    .as_ref()
                    .map(|authority| rpc::VerifiedRpcNetwork {
                        network_id: authority.epoch.network_id.clone(),
                        epoch: authority.epoch.epoch,
                        genesis_hash: verified_genesis_hash.to_owned(),
                    }),
            )
            .map_err(|reason| StartError::ServiceRegistration {
                service: "rpc",
                reason,
            })?,
        )?;
        push_builtin(
            registrations,
            "websocket",
            websocket::registration(
                &configuration.rpc,
                Arc::clone(runtime_view),
                websocket_hub,
                query_store,
            )
            .map_err(|reason| StartError::ServiceRegistration {
                service: "websocket",
                reason,
            })?,
        )?;
    }
    if configuration.role == NodeRole::Sentry {
        push_builtin(
            registrations,
            "sentry",
            sentry::registration(&configuration.p2p).map_err(|reason| {
                StartError::ServiceRegistration {
                    service: "sentry",
                    reason,
                }
            })?,
        )?;
    }
    push_builtin(
        registrations,
        "telemetry",
        telemetry::registration(&configuration.telemetry).map_err(|reason| {
            StartError::ServiceRegistration {
                service: "telemetry",
                reason,
            }
        })?,
    )?;
    push_builtin(
        registrations,
        "health",
        health::registration(Arc::clone(runtime_view)).map_err(|reason| {
            StartError::ServiceRegistration {
                service: "health",
                reason,
            }
        })?,
    )?;
    Ok(authorized_production_consensus)
}

fn push_builtin(
    registrations: &mut Vec<ServiceRegistration>,
    name: &'static str,
    registration: ServiceRegistration,
) -> Result<(), StartError> {
    if registrations
        .iter()
        .any(|(specification, _)| specification.id == registration.0.id)
    {
        return Err(StartError::DuplicateBuiltinService(name));
    }
    registrations.push(registration);
    Ok(())
}

fn build_startup_plan(configuration: &NodeConfiguration) -> Result<StartupPlan, StartError> {
    let plan = StartupPlan {
        role: format!("{:?}", configuration.role).to_ascii_lowercase(),
        required_services: required_service_ids(configuration)?,
        shadow_before_active: configuration.role_hosts_consensus_signer(),
    };
    plan.validate().map_err(StartError::InvalidStartupPlan)?;
    Ok(plan)
}

fn required_service_ids(configuration: &NodeConfiguration) -> Result<Vec<ServiceId>, StartError> {
    let mut names = vec![
        "identity",
        "storage",
        "telemetry",
        "network",
        "sync",
        "admin-api",
        "health",
    ];
    if configuration.vpn.mode != VpnMode::Disabled {
        names.push("vpn");
    }
    if configuration.etdag.enabled {
        names.extend(["etdag", "execution"]);
    }
    if configuration.consensus.mode != ConsensusMode::Disabled {
        names.push("posy");
    }
    if configuration.rpc.enabled {
        names.extend(["rpc", "websocket"]);
    }
    if configuration.role == NodeRole::Sentry {
        names.push("sentry");
    }
    validate_role_service_declaration(configuration, &names)?;
    names
        .into_iter()
        .map(|name| ServiceId::new(name).map_err(StartError::InvalidServiceId))
        .collect()
}

fn validate_role_service_declaration(
    configuration: &NodeConfiguration,
    names: &[&str],
) -> Result<(), StartError> {
    let capabilities = names
        .iter()
        .flat_map(|name| service_capabilities(name, configuration))
        .collect::<BTreeSet<_>>();
    let profile = RoleProfile {
        role: configuration.role,
        plane: if configuration.role_hosts_consensus_signer() {
            AuthorityPlane::ConsensusCandidate
        } else {
            AuthorityPlane::Operator
        },
        capabilities,
        ports: RolePorts {
            p2p: None,
            rpc: None,
            admin: None,
            metrics: None,
        },
    };
    profile
        .validate()
        .map_err(|error| StartError::InvalidStartupPlan(error.to_string()))?;
    let services = names
        .iter()
        .map(|name| RoleServiceBinding {
            service_id: RoleServiceId((*name).to_string()),
            required_capability: service_capabilities(name, configuration)[0],
            dependencies: BTreeSet::new(),
        })
        .collect::<Vec<_>>();
    synergy_roles::validate_service_graph(&profile, &services)
        .map_err(|error| StartError::InvalidStartupPlan(error.to_string()))
}

pub(crate) fn service_capabilities(
    name: &str,
    configuration: &NodeConfiguration,
) -> Vec<Capability> {
    match name {
        "identity" => vec![Capability::Identity],
        "storage" => vec![Capability::DurableStorage],
        "telemetry" => vec![Capability::Telemetry],
        "health" => vec![Capability::Health],
        "network" => vec![Capability::NetworkTransport, Capability::PeerDiscovery],
        "sync" => vec![Capability::Sync],
        "admin-api" => vec![Capability::AdminApi],
        "vpn" => vec![Capability::NetworkTransport],
        "etdag" => vec![Capability::ExecuteTransactions],
        "execution" => vec![Capability::ExecuteTransactions],
        "posy" if configuration.consensus.mode == ConsensusMode::ValidateAndVote => vec![
            Capability::ObserveConsensus,
            Capability::ProposeBlocks,
            Capability::VoteConsensus,
        ],
        "posy" => vec![Capability::ObserveConsensus],
        "rpc" => vec![Capability::PublicRpc],
        "websocket" => vec![Capability::PublicRpc],
        "sentry" => vec![Capability::NetworkTransport],
        _ => vec![Capability::Health],
    }
}

fn require_complete_service_set(
    plan: &StartupPlan,
    registrations: &[ServiceRegistration],
) -> Result<(), StartError> {
    let registered = registrations
        .iter()
        .map(|(spec, _)| spec.id.clone())
        .collect::<BTreeSet<_>>();
    let missing = plan
        .required_services
        .iter()
        .filter(|service| !registered.contains(*service))
        .map(|service| service.as_str().to_string())
        .collect::<Vec<_>>();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(StartError::MissingServices(missing))
    }
}

#[derive(Debug)]
pub enum StartError {
    Configuration(ConfigLoadError),
    InvalidServiceId(String),
    InvalidStartupPlan(String),
    ServiceRegistration {
        service: &'static str,
        reason: String,
    },
    DuplicateBuiltinService(&'static str),
    MissingServices(Vec<String>),
    Lifecycle(LifecycleTransitionError),
    Supervisor(SupervisorError),
    RuntimeViewPoisoned,
    SignalHandler(String),
    AuthorityTransition(String),
    ShutdownFailures(Vec<(ServiceId, String)>),
}

impl fmt::Display for StartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(error) => write!(formatter, "{error}"),
            Self::InvalidServiceId(error) => write!(formatter, "invalid runtime service: {error}"),
            Self::InvalidStartupPlan(error) => write!(formatter, "invalid startup plan: {error}"),
            Self::ServiceRegistration { service, reason } => {
                write!(formatter, "register runtime service {service}: {reason}")
            }
            Self::DuplicateBuiltinService(service) => {
                write!(
                    formatter,
                    "runtime service {service} is registered more than once"
                )
            }
            Self::MissingServices(services) => write!(
                formatter,
                "runtime service adapters are not registered: {}",
                services.join(", ")
            ),
            Self::Lifecycle(error) => write!(formatter, "node lifecycle failed: {error}"),
            Self::Supervisor(error) => write!(formatter, "node supervisor failed: {error}"),
            Self::RuntimeViewPoisoned => {
                formatter.write_str("runtime observation state is unavailable")
            }
            Self::SignalHandler(error) => {
                write!(formatter, "install shutdown signal handler: {error}")
            }
            Self::AuthorityTransition(error) => {
                write!(formatter, "apply finalized authority transition: {error}")
            }
            Self::ShutdownFailures(failures) => write!(
                formatter,
                "{} service(s) failed shutdown: {failures:?}",
                failures.len()
            ),
        }
    }
}

impl std::error::Error for StartError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Configuration(error) => Some(error),
            Self::Lifecycle(error) => Some(error),
            Self::Supervisor(error) => Some(error),
            Self::InvalidServiceId(_)
            | Self::InvalidStartupPlan(_)
            | Self::ServiceRegistration { .. }
            | Self::DuplicateBuiltinService(_)
            | Self::MissingServices(_)
            | Self::RuntimeViewPoisoned
            | Self::SignalHandler(_)
            | Self::AuthorityTransition(_)
            | Self::ShutdownFailures(_) => None,
        }
    }
}

#[cfg(feature = "qualification-timing")]
impl Drop for StartedNode {
    fn drop(&mut self) {
        crate::services::qualification_timing::clear_process_handle();
        if let Some(collector) = self.qualification_timing.take() {
            let report = collector.finish();
            eprintln!(
                "qualification timing report: written={} dropped={} failures={} complete={}",
                report.written,
                report.dropped,
                report.failures,
                report.complete()
            );
        }
    }
}

#[cfg(test)]
mod readiness_tests {
    use super::*;

    #[test]
    fn voting_preflight_requires_exact_active_membership_without_private_custody() {
        use synergy_posy::{ValidatorRecord, ValidatorStatus, POSY_MIN_VALIDATOR_COUNT};
        let mut entries = (0..POSY_MIN_VALIDATOR_COUNT)
            .map(|i| {
                (
                    ValidatorRecord {
                        validator_id: format!("validator-{i}"),
                        consensus_key_id: format!("consensus-{i}"),
                        frozen_voting_weight: 1,
                        status: ValidatorStatus::Active,
                    },
                    vec![1],
                )
            })
            .collect::<Vec<_>>();
        entries.push((
            ValidatorRecord {
                validator_id: "shadow".into(),
                consensus_key_id: "shadow-key".into(),
                frozen_voting_weight: 1,
                status: ValidatorStatus::Shadow,
            },
            vec![1],
        ));
        let authority = authority::qualification_authority(entries);
        let role = synergy_protocol_types::NodeRole::Validator;
        let check = |mode, authority, id| preflight_voting_binding(role, mode, authority, id);
        assert_eq!(
            check(
                ConsensusMode::ValidateAndVote,
                Some(authority.as_ref()),
                "validator-0"
            )
            .unwrap()
            .as_deref(),
            Some("consensus-0")
        );
        for id in ["unregistered", "shadow"] {
            assert!(check(ConsensusMode::ValidateAndVote, Some(authority.as_ref()), id).is_err());
        }
        assert!(check(ConsensusMode::ValidateAndVote, None, "validator-0").is_err());
        assert!(check(ConsensusMode::Observe, None, "unregistered")
            .unwrap()
            .is_none());
        assert!(preflight_voting_binding(
            synergy_protocol_types::NodeRole::ObserverLight,
            ConsensusMode::ValidateAndVote,
            Some(authority.as_ref()),
            "validator-0"
        )
        .is_err());
    }

    fn starting() -> LifecycleController {
        let mut lifecycle = LifecycleController::new();
        lifecycle
            .transition(NodeLifecycleState::Configured)
            .unwrap();
        lifecycle.transition(NodeLifecycleState::Starting).unwrap();
        lifecycle
    }

    fn ready_service() -> ServiceObservation {
        ServiceObservation {
            id: ServiceId::new("posy").unwrap(),
            state: ServiceState::Running,
            health: ServiceHealth::Healthy,
            readiness: ServiceReadiness::Ready,
        }
    }

    #[test]
    fn authorized_production_validator_leaves_shadow_only_after_complete_readiness() {
        let mut lifecycle = starting();
        let ready = ready_service();
        advance_lifecycle_readiness(&mut lifecycle, true, true, std::slice::from_ref(&ready))
            .unwrap();
        assert_eq!(lifecycle.state(), NodeLifecycleState::Shadowing);
        let mut pending = ready.clone();
        pending.readiness = ServiceReadiness::Pending {
            reason: "verified catch-up pending".into(),
        };
        advance_lifecycle_readiness(&mut lifecycle, true, true, &[pending]).unwrap();
        assert_eq!(lifecycle.state(), NodeLifecycleState::Shadowing);
        advance_lifecycle_readiness(&mut lifecycle, true, true, &[ready]).unwrap();
        assert_eq!(lifecycle.state(), NodeLifecycleState::Active);
    }

    #[test]
    fn unauthorized_or_external_shadow_and_unhealthy_graph_cannot_activate() {
        let ready = ready_service();
        let mut lifecycle = starting();
        advance_lifecycle_readiness(&mut lifecycle, true, false, std::slice::from_ref(&ready))
            .unwrap();
        advance_lifecycle_readiness(&mut lifecycle, true, false, std::slice::from_ref(&ready))
            .unwrap();
        assert_eq!(lifecycle.state(), NodeLifecycleState::Shadowing);
        let mut unhealthy = ready.clone();
        unhealthy.health = ServiceHealth::Unhealthy {
            reason: "authority verification failed".into(),
        };
        let mut stopped = ready.clone();
        stopped.state = ServiceState::Stopped;
        for services in [vec![], vec![unhealthy], vec![stopped]] {
            advance_lifecycle_readiness(&mut lifecycle, true, true, &services).unwrap();
            assert_eq!(lifecycle.state(), NodeLifecycleState::Shadowing);
        }
        lifecycle.transition(NodeLifecycleState::Failed).unwrap();
        advance_lifecycle_readiness(&mut lifecycle, true, true, &[ready]).unwrap();
        assert_eq!(lifecycle.state(), NodeLifecycleState::Failed);
    }
}
