use std::collections::BTreeMap;

use crate::{ServiceObservation, ServiceReadiness, SupervisorError};

use super::{
    CancellationToken, Criticality, DependencyGraph, ManagedService, ServiceHealth, ServiceId,
    ServiceSpec, ServiceState, ShutdownReport,
};

/// Owns startup, bounded restart, health, and reverse-order shutdown for node services.
pub struct Supervisor {
    graph: DependencyGraph,
    services: BTreeMap<ServiceId, Box<dyn ManagedService>>,
    states: BTreeMap<ServiceId, ServiceState>,
    restart_attempts: BTreeMap<ServiceId, u16>,
    cancellation: CancellationToken,
}

impl Supervisor {
    pub fn new(
        registrations: impl IntoIterator<Item = (ServiceSpec, Box<dyn ManagedService>)>,
    ) -> Result<Self, SupervisorError> {
        let mut specs = Vec::new();
        let mut services = BTreeMap::new();
        for (spec, service) in registrations {
            let id = spec.id.clone();
            if services.insert(id.clone(), service).is_some() {
                return Err(SupervisorError::DuplicateService(id));
            }
            specs.push(spec);
        }
        let graph = DependencyGraph::build(specs)?;
        let states = graph
            .startup_order()
            .iter()
            .cloned()
            .map(|id| (id, ServiceState::Registered))
            .collect();
        Ok(Self {
            graph,
            services,
            states,
            restart_attempts: BTreeMap::new(),
            cancellation: CancellationToken::default(),
        })
    }

    pub fn start_all(&mut self) -> Result<(), SupervisorError> {
        if self.cancellation.is_cancelled() {
            return Err(SupervisorError::Cancelled);
        }
        if self
            .states
            .values()
            .any(|state| *state != ServiceState::Registered)
        {
            let service = self
                .graph
                .startup_order()
                .first()
                .cloned()
                .ok_or(SupervisorError::Cancelled)?;
            return Err(SupervisorError::InvalidState {
                service,
                operation: "start all",
            });
        }
        let order = self.graph.startup_order().to_vec();
        for id in order {
            if let Err(cause) = self.start_one(&id) {
                let report = self.shutdown();
                if report.clean() {
                    return Err(cause);
                }
                return Err(SupervisorError::StartupCleanup {
                    cause: Box::new(cause),
                    failures: report.failed,
                });
            }
        }
        Ok(())
    }

    pub fn restart_failed(&mut self, id: &ServiceId) -> Result<(), SupervisorError> {
        if self.cancellation.is_cancelled() {
            return Err(SupervisorError::Cancelled);
        }
        if self.service_state(id) != Some(ServiceState::Failed) {
            return Err(SupervisorError::InvalidState {
                service: id.clone(),
                operation: "restart",
            });
        }
        // A running dependent must first be drained by the runtime owner.
        for candidate in self.graph.startup_order() {
            if self
                .graph
                .spec(candidate)
                .is_some_and(|spec| spec.dependencies.contains(id))
                && self.service_state(candidate) == Some(ServiceState::Running)
            {
                return Err(SupervisorError::InvalidState {
                    service: candidate.clone(),
                    operation: "restart dependency of",
                });
            }
        }
        let spec = self
            .graph
            .spec(id)
            .ok_or_else(|| SupervisorError::ServiceUnavailable(id.clone()))?;
        let attempts = self.restart_attempts.get(id).copied().unwrap_or(0);
        if !spec.restart_policy.permits(attempts, true) {
            self.states.insert(id.clone(), ServiceState::Failed);
            return Err(SupervisorError::RestartExhausted(id.clone()));
        }
        self.restart_attempts
            .insert(id.clone(), attempts.saturating_add(1));
        self.services
            .get_mut(id)
            .ok_or_else(|| SupervisorError::ServiceUnavailable(id.clone()))?
            .stop()
            .map_err(|message| SupervisorError::StopFailed {
                service: id.clone(),
                message,
            })?;
        self.states.insert(id.clone(), ServiceState::Restarting);
        self.start_one(id)
    }

    pub fn service_state(&self, id: &ServiceId) -> Option<ServiceState> {
        self.states.get(id).copied()
    }

    pub fn service_health(&self, id: &ServiceId) -> Result<ServiceHealth, SupervisorError> {
        self.services
            .get(id)
            .map(|service| service.health())
            .ok_or_else(|| SupervisorError::ServiceUnavailable(id.clone()))
    }

    pub fn requires_fail_closed(&self, id: &ServiceId) -> Result<bool, SupervisorError> {
        let spec = self
            .graph
            .spec(id)
            .ok_or_else(|| SupervisorError::ServiceUnavailable(id.clone()))?;
        Ok(spec.criticality == Criticality::Critical
            && matches!(self.service_health(id)?, ServiceHealth::Unhealthy { .. }))
    }

    pub fn health(&self, id: &ServiceId) -> Result<ServiceHealth, SupervisorError> {
        self.service_health(id)
    }

    /// Advances running subsystem event loops in dependency order.
    pub fn poll_all(&mut self) -> Result<(), SupervisorError> {
        if self.cancellation.is_cancelled() {
            return Err(SupervisorError::Cancelled);
        }
        for id in self.graph.startup_order() {
            if self.states.get(id) != Some(&ServiceState::Running) {
                continue;
            }
            let service = self
                .services
                .get_mut(id)
                .ok_or_else(|| SupervisorError::ServiceUnavailable(id.clone()))?;
            if let Err(message) = service.poll() {
                self.states.insert(id.clone(), ServiceState::Failed);
                return Err(SupervisorError::PollFailed {
                    service: id.clone(),
                    message,
                });
            }
        }
        Ok(())
    }

    pub fn observations(&self) -> Vec<ServiceObservation> {
        self.graph
            .startup_order()
            .iter()
            .map(|id| {
                let state = self.states.get(id).copied().unwrap_or(ServiceState::Failed);
                match self.services.get(id) {
                    Some(service) if state == ServiceState::Running => ServiceObservation {
                        id: id.clone(),
                        state,
                        health: service.health(),
                        readiness: service.readiness(),
                    },
                    _ => ServiceObservation {
                        id: id.clone(),
                        state,
                        health: ServiceHealth::Unhealthy {
                            reason: "service is not running".into(),
                        },
                        readiness: ServiceReadiness::Blocked {
                            reason: "service is not running".into(),
                        },
                    },
                }
            })
            .collect()
    }

    pub fn must_fail_closed(&self, id: &ServiceId) -> bool {
        self.graph
            .spec(id)
            .is_some_and(|spec| spec.criticality == Criticality::Critical)
    }

    pub fn shutdown(&mut self) -> ShutdownReport {
        self.cancellation.cancel();
        let order: Vec<_> = self.graph.shutdown_order().cloned().collect();
        let mut report = ShutdownReport {
            stopped: Vec::new(),
            failed: Vec::new(),
        };
        for id in order {
            if !matches!(
                self.states.get(&id),
                Some(
                    ServiceState::Running
                        | ServiceState::Failed
                        | ServiceState::Starting
                        | ServiceState::Restarting
                )
            ) {
                continue;
            }
            self.states.insert(id.clone(), ServiceState::Stopping);
            match self.services.get_mut(&id) {
                Some(service) => match service.stop() {
                    Ok(()) => {
                        self.states.insert(id.clone(), ServiceState::Stopped);
                        report.stopped.push(id);
                    }
                    Err(message) => {
                        self.states.insert(id.clone(), ServiceState::Failed);
                        report.failed.push((id, message));
                    }
                },
                None => report.failed.push((
                    id,
                    "registered service implementation is unavailable".into(),
                )),
            }
        }
        report
    }

    fn start_one(&mut self, id: &ServiceId) -> Result<(), SupervisorError> {
        if self.cancellation.is_cancelled() {
            return Err(SupervisorError::Cancelled);
        }
        let spec = self
            .graph
            .spec(id)
            .ok_or_else(|| SupervisorError::ServiceUnavailable(id.clone()))?;
        for dependency in &spec.dependencies {
            if !matches!(self.states.get(dependency), Some(ServiceState::Running)) {
                return Err(SupervisorError::DependencyNotRunning {
                    service: id.clone(),
                    dependency: dependency.clone(),
                });
            }
        }
        self.states.insert(id.clone(), ServiceState::Starting);
        let service = self
            .services
            .get_mut(id)
            .ok_or_else(|| SupervisorError::ServiceUnavailable(id.clone()))?;
        if let Err(message) = service.start(&self.cancellation) {
            self.states.insert(id.clone(), ServiceState::Failed);
            return Err(SupervisorError::StartFailed {
                service: id.clone(),
                message,
            });
        }
        self.states.insert(id.clone(), ServiceState::Running);
        Ok(())
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}
