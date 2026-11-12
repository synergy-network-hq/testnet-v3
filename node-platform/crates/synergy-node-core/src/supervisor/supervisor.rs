use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

use crate::{ServiceObservation, ServiceReadiness, SupervisorError};

use super::{
    CancellationToken, Criticality, DependencyGraph, ManagedService, ServiceHealth, ServiceId,
    ServiceSpec, ServiceState, ShutdownReport,
};

/// Fixed-capacity measurements; labels are registered service IDs only.
#[derive(Debug, Clone)]
pub struct PollTimingSample {
    pub elapsed: Duration,
    pub service_elapsed: Duration,
    pub failed_service: Option<ServiceId>,
}

#[derive(Debug, Clone, Default)]
pub struct ServicePollTiming {
    pub calls: u64,
    pub failures: u64,
    pub total: Duration,
    pub maximum: Duration,
}

#[derive(Debug, Clone, Default)]
pub struct PollTimings {
    pub services: BTreeMap<ServiceId, ServicePollTiming>,
    pub recent: VecDeque<PollTimingSample>,
    pub passes: u64,
    pub failed_passes: u64,
    /// Measured pass time outside service.poll, including instrumentation.
    pub overhead: Duration,
}

impl PollTimings {
    fn service(&mut self, id: &ServiceId, elapsed: Duration, failed: bool) {
        if !self.services.contains_key(id) && self.services.len() >= 64 {
            return;
        }
        let value = self.services.entry(id.clone()).or_default();
        value.calls = value.calls.saturating_add(1);
        value.failures = value.failures.saturating_add(u64::from(failed));
        value.total = value.total.saturating_add(elapsed);
        value.maximum = value.maximum.max(elapsed);
    }

    fn pass(&mut self, sample: PollTimingSample) {
        self.passes = self.passes.saturating_add(1);
        self.failed_passes = self
            .failed_passes
            .saturating_add(u64::from(sample.failed_service.is_some()));
        self.overhead = self
            .overhead
            .saturating_add(sample.elapsed.saturating_sub(sample.service_elapsed));
        if self.recent.len() == 128 {
            self.recent.pop_front();
        }
        self.recent.push_back(sample);
    }
}

/// Owns startup, bounded restart, health, and reverse-order shutdown for node services.
pub struct Supervisor {
    graph: DependencyGraph,
    services: BTreeMap<ServiceId, Box<dyn ManagedService>>,
    states: BTreeMap<ServiceId, ServiceState>,
    restart_attempts: BTreeMap<ServiceId, u16>,
    cancellation: CancellationToken,
    poll_timings: Option<PollTimings>,
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
            poll_timings: None,
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
    /// Explicit opt-in; disabling discards measurements and reads no clock.
    pub fn enable_poll_timing(&mut self, enabled: bool) {
        self.poll_timings = enabled.then(PollTimings::default);
    }

    pub fn poll_timings(&self) -> Option<&PollTimings> {
        self.poll_timings.as_ref()
    }

    pub fn poll_all(&mut self) -> Result<(), SupervisorError> {
        if self.cancellation.is_cancelled() {
            return Err(SupervisorError::Cancelled);
        }
        let started = self.poll_timings.as_ref().map(|_| Instant::now());
        let mut service_elapsed = Duration::ZERO;
        let mut failed_service = None;
        let result = (|| {
            for id in self.graph.startup_order() {
                if self.states.get(id) != Some(&ServiceState::Running) {
                    continue;
                }
                let service = self
                    .services
                    .get_mut(id)
                    .ok_or_else(|| SupervisorError::ServiceUnavailable(id.clone()))?;
                let service_started = started.map(|_| Instant::now());
                let result = service.poll();
                if let Some(service_started) = service_started {
                    let elapsed = service_started.elapsed();
                    service_elapsed = service_elapsed.saturating_add(elapsed);
                    self.poll_timings
                        .as_mut()
                        .unwrap()
                        .service(id, elapsed, result.is_err());
                }
                if let Err(message) = result {
                    failed_service = Some(id.clone());
                    self.states.insert(id.clone(), ServiceState::Failed);
                    return Err(SupervisorError::PollFailed {
                        service: id.clone(),
                        message,
                    });
                }
            }
            Ok(())
        })();
        if let Some(started) = started {
            self.poll_timings.as_mut().unwrap().pass(PollTimingSample {
                elapsed: started.elapsed(),
                service_elapsed,
                failed_service,
            });
        }
        result
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

#[cfg(test)]
mod poll_timing_tests {
    use super::*;

    #[test]
    fn timing_storage_is_bounded_and_accounts_errors_and_overhead() {
        let mut timing = PollTimings::default();
        for i in 0..200 {
            let id = ServiceId::new(format!("service-{i}")).unwrap();
            timing.service(&id, Duration::from_millis(3), i % 2 == 0);
            timing.pass(PollTimingSample {
                elapsed: Duration::from_millis(5),
                service_elapsed: Duration::from_millis(3),
                failed_service: (i % 2 == 0).then_some(id),
            });
        }
        assert_eq!(timing.services.len(), 64);
        assert_eq!(timing.recent.len(), 128);
        assert_eq!(timing.passes, 200);
        assert_eq!(timing.failed_passes, 100);
        assert_eq!(timing.overhead, Duration::from_millis(400));
    }

    struct FailingPoll;
    impl ManagedService for FailingPoll {
        fn start(&mut self, _: &CancellationToken) -> Result<(), String> {
            Ok(())
        }
        fn stop(&mut self) -> Result<(), String> {
            Ok(())
        }
        fn health(&self) -> ServiceHealth {
            ServiceHealth::Healthy
        }
        fn poll(&mut self) -> Result<(), String> {
            Err("test failure".into())
        }
    }

    #[test]
    fn timing_opt_in_preserves_fail_closed_poll_behavior() {
        let id = ServiceId::new("test-owner").unwrap();
        let spec = ServiceSpec {
            id: id.clone(),
            dependencies: vec![],
            criticality: Criticality::Critical,
            restart_policy: super::super::RestartPolicy::Never,
        };
        let mut supervisor = Supervisor::new(vec![(
            spec,
            Box::new(FailingPoll) as Box<dyn ManagedService>,
        )])
        .unwrap();
        assert!(supervisor.poll_timings().is_none());
        supervisor.start_all().unwrap();
        supervisor.enable_poll_timing(true);
        assert!(matches!(
            supervisor.poll_all(),
            Err(SupervisorError::PollFailed { .. })
        ));
        let timing = supervisor.poll_timings().unwrap();
        assert_eq!(timing.services[&id].calls, 1);
        assert_eq!(timing.services[&id].failures, 1);
        assert_eq!(timing.failed_passes, 1);
        assert_eq!(supervisor.service_state(&id), Some(ServiceState::Failed));
        supervisor.enable_poll_timing(false);
        assert!(supervisor.poll_timings().is_none());
    }
}
