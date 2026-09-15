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
    RuntimeSnapshot, RuntimeView, ServiceId, ServiceReadiness, ServiceSpec, StartupPlan,
    Supervisor, SupervisorError,
};
use synergy_protocol_types::NodeRole;
use synergy_roles::{
    AuthorityPlane, Capability, RolePorts, RoleProfile, ServiceBinding as RoleServiceBinding,
    ServiceId as RoleServiceId,
};
use synergy_ws::server::WsServer;

use crate::services::{
    admin, authority, etdag, execution, health, identity, ingress, network, posy, rpc, sentry,
    storage, sync, telemetry, vpn, websocket,
};

pub type ServiceRegistration = (ServiceSpec, Box<dyn ManagedService>);

/// A node whose configuration, lifecycle, and concrete service graph have
/// passed startup. The caller must retain this value for the process lifetime.
pub struct StartedNode {
    configuration: NodeConfiguration,
    startup_plan: StartupPlan,
    lifecycle: LifecycleController,
    supervisor: Supervisor,
    runtime_view: RuntimeView,
    authority_transition: authority::AuthorityTransitionSignal,
    has_external_services: bool,
}

impl StartedNode {
    pub fn configuration(&self) -> &NodeConfiguration {
        &self.configuration
    }

    pub fn startup_plan(&self) -> &StartupPlan {
        &self.startup_plan
    }

    pub fn lifecycle(&self) -> NodeLifecycleState {
        self.lifecycle.state()
    }

    pub fn supervisor(&self) -> &Supervisor {
        &self.supervisor
    }

    pub fn supervisor_mut(&mut self) -> &mut Supervisor {
        &mut self.supervisor
    }

    pub fn runtime_view(&self) -> RuntimeView {
        Arc::clone(&self.runtime_view)
    }

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
            let tick = self
                .supervisor
                .poll_all()
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
        let mut registrations = Vec::new();
        register_builtin_services(
            &self.configuration,
            &self.runtime_view,
            &mut registrations,
            self.authority_transition.clone(),
        )?;
        require_complete_service_set(&self.startup_plan, &registrations)?;
        let mut supervisor = Supervisor::new(registrations).map_err(StartError::Supervisor)?;
        supervisor.start_all().map_err(StartError::Supervisor)?;
        self.supervisor = supervisor;
        self.refresh_runtime_view()
    }

    fn fail_and_shutdown(&mut self) {
        let _ = self.lifecycle.transition(NodeLifecycleState::Failed);
        let _ = self.supervisor.shutdown();
        let _ = self.refresh_runtime_view();
    }

    fn advance_readiness(&mut self) -> Result<(), StartError> {
        let all_ready = self
            .supervisor
            .observations()
            .iter()
            .all(|service| service.readiness == ServiceReadiness::Ready);
        match (self.lifecycle.state(), all_ready) {
            (NodeLifecycleState::Starting, true) if self.startup_plan.shadow_before_active => {
                self.lifecycle
                    .transition(NodeLifecycleState::Shadowing)
                    .map_err(StartError::Lifecycle)?;
            }
            (NodeLifecycleState::Starting, true) => {
                self.lifecycle
                    .transition(NodeLifecycleState::Ready)
                    .map_err(StartError::Lifecycle)?;
                self.lifecycle
                    .transition(NodeLifecycleState::Active)
                    .map_err(StartError::Lifecycle)?;
            }
            _ => {}
        }
        Ok(())
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

/// CLI entry point for the complete configured supervised service graph.
pub fn run(config_path: &Path) -> Result<(), StartError> {
    start_with_services(config_path, Vec::new())?.run()
}

/// Starts a fully supplied concrete runtime through the canonical lifecycle
/// and dependency-aware supervisor. No service is synthesized or marked
/// healthy by this boundary.
pub fn start_with_services(
    config_path: &Path,
    mut registrations: Vec<ServiceRegistration>,
) -> Result<StartedNode, StartError> {
    let configuration = load(config_path).map_err(StartError::Configuration)?;
    let has_external_services = !registrations.is_empty();
    let authority_transition = authority::AuthorityTransitionSignal::default();
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
    register_builtin_services(
        &configuration,
        &runtime_view,
        &mut registrations,
        authority_transition.clone(),
    )?;
    let startup_plan = build_startup_plan(&configuration)?;
    require_complete_service_set(&startup_plan, &registrations)?;

    let mut supervisor = Supervisor::new(registrations).map_err(StartError::Supervisor)?;
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
        startup_plan,
        lifecycle,
        supervisor,
        runtime_view,
        authority_transition,
        has_external_services,
    })
}

fn register_builtin_services(
    configuration: &NodeConfiguration,
    runtime_view: &RuntimeView,
    registrations: &mut Vec<ServiceRegistration>,
    authority_transition: authority::AuthorityTransitionSignal,
) -> Result<(), StartError> {
    let authenticated_ingress = ingress::AuthenticatedIngress::default();
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
            etdag::registration(
                configuration,
                Arc::clone(&authority),
                authenticated_ingress.clone(),
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
        sync::registration(
            configuration,
            verified_authority.clone(),
            authority_transition,
            authenticated_ingress.clone(),
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
            posy::registration(
                configuration,
                verified_authority
                    .clone()
                    .ok_or_else(|| StartError::ServiceRegistration {
                        service: "posy",
                        reason: "PoSy requires a verified frozen authority binding".into(),
                    })?,
                authenticated_ingress.clone(),
            )
            .map_err(|reason| StartError::ServiceRegistration {
                service: "posy",
                reason,
            })?,
        )?;
    }
    if configuration.rpc.enabled {
        let query_store: Arc<dyn synergy_rpc::provider::CanonicalReadProvider> = Arc::new(
            rpc::CanonicalQueryStore::load(configuration.storage.data_directory.clone()).map_err(
                |reason| StartError::ServiceRegistration {
                    service: "rpc",
                    reason,
                },
            )?,
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
            rpc::registration(
                &configuration.rpc,
                Arc::clone(runtime_view),
                Arc::clone(&query_store),
                Arc::clone(&websocket_hub),
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
    )
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
