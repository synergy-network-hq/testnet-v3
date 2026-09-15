use synergy_health::{HealthCheck, HealthReport, HealthSeverity};
use synergy_node_core::{
    CancellationToken, Criticality, ManagedService, RestartPolicy, RuntimeView, ServiceHealth,
    ServiceId, ServiceReadiness, ServiceSpec, ServiceState,
};

pub fn registration(
    runtime: RuntimeView,
) -> Result<(ServiceSpec, Box<dyn ManagedService>), String> {
    Ok((
        ServiceSpec {
            id: ServiceId::new("health")?,
            dependencies: vec![ServiceId::new("identity")?, ServiceId::new("storage")?],
            criticality: Criticality::Required,
            restart_policy: RestartPolicy::OnFailure { max_attempts: 3 },
        },
        Box::new(HealthService {
            runtime,
            report: None,
            running: false,
        }),
    ))
}

struct HealthService {
    runtime: RuntimeView,
    report: Option<HealthReport>,
    running: bool,
}

impl HealthService {
    fn collect(&self) -> Result<HealthReport, String> {
        let snapshot = self
            .runtime
            .read()
            .map_err(|_| "runtime observation lock is poisoned".to_string())?;
        let checks = snapshot
            .services
            .iter()
            .filter(|service| service.id.as_str() != "health")
            .map(|service| {
                let (severity, detail) = if service.state != ServiceState::Running {
                    (
                        HealthSeverity::Critical,
                        format!("service state is {:?}", service.state),
                    )
                } else {
                    match &service.health {
                        ServiceHealth::Healthy => {
                            (HealthSeverity::Info, "service is healthy".into())
                        }
                        ServiceHealth::Degraded { reason } => {
                            (HealthSeverity::Warning, reason.clone())
                        }
                        ServiceHealth::Unhealthy { reason } => {
                            (HealthSeverity::Critical, reason.clone())
                        }
                    }
                };
                HealthCheck::new(service.id.as_str(), severity, detail).map_err(str::to_string)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(HealthReport::new(checks))
    }
}

impl ManagedService for HealthService {
    fn start(&mut self, cancellation: &CancellationToken) -> Result<(), String> {
        if cancellation.is_cancelled() {
            return Err("health service start was cancelled".into());
        }
        self.report = Some(self.collect()?);
        self.running = true;
        Ok(())
    }

    fn poll(&mut self) -> Result<(), String> {
        self.report = Some(self.collect()?);
        Ok(())
    }

    fn stop(&mut self) -> Result<(), String> {
        self.running = false;
        self.report = None;
        Ok(())
    }

    fn health(&self) -> ServiceHealth {
        if !self.running {
            return ServiceHealth::Unhealthy {
                reason: "health service is stopped".into(),
            };
        }
        match self.runtime.read() {
            Ok(_) => ServiceHealth::Healthy,
            Err(_) => ServiceHealth::Unhealthy {
                reason: "runtime observation lock is poisoned".into(),
            },
        }
    }

    fn readiness(&self) -> ServiceReadiness {
        if self.running && self.report.is_some() {
            ServiceReadiness::Ready
        } else {
            ServiceReadiness::Pending {
                reason: "health report is not available".into(),
            }
        }
    }
}
