use synergy_config::TelemetryConfiguration;
use synergy_node_core::{
    CancellationToken, Criticality, ManagedService, RestartPolicy, ServiceHealth, ServiceId,
    ServiceReadiness, ServiceSpec,
};
use synergy_telemetry::TelemetryRegistry;

const MAX_RUNTIME_METRIC_SERIES: usize = 512;

pub fn registration(
    configuration: &TelemetryConfiguration,
) -> Result<(ServiceSpec, Box<dyn ManagedService>), String> {
    Ok((
        ServiceSpec {
            id: ServiceId::new("telemetry")?,
            dependencies: vec![ServiceId::new("identity")?],
            criticality: Criticality::Required,
            restart_policy: RestartPolicy::OnFailure { max_attempts: 3 },
        },
        Box::new(TelemetryService {
            configuration: configuration.clone(),
            registry: None,
            state: None,
        }),
    ))
}

struct TelemetryService {
    configuration: TelemetryConfiguration,
    registry: Option<TelemetryRegistry>,
    state: Option<String>,
}

impl ManagedService for TelemetryService {
    fn start(&mut self, cancellation: &CancellationToken) -> Result<(), String> {
        if cancellation.is_cancelled() {
            return Err("telemetry start was cancelled".into());
        }
        if self.configuration.metrics_listen_address.is_some() {
            return Err(
                "configured telemetry listener requires the canonical exporter service".into(),
            );
        }
        let mut registry = TelemetryRegistry::new(MAX_RUNTIME_METRIC_SERIES);
        registry
            .increment("runtime_start_total")
            .map_err(|error| format!("initialize telemetry registry: {error:?}"))?;
        self.registry = Some(registry);
        self.state = None;
        Ok(())
    }

    fn poll(&mut self) -> Result<(), String> {
        self.registry
            .as_mut()
            .ok_or_else(|| "telemetry registry is unavailable".to_string())?
            .increment("runtime_poll_total")
            .map_err(|error| format!("update telemetry registry: {error:?}"))
    }

    fn stop(&mut self) -> Result<(), String> {
        self.registry = None;
        Ok(())
    }

    fn health(&self) -> ServiceHealth {
        match (&self.registry, &self.state) {
            (Some(_), _) => ServiceHealth::Healthy,
            (None, Some(reason)) => ServiceHealth::Unhealthy {
                reason: reason.clone(),
            },
            (None, None) => ServiceHealth::Unhealthy {
                reason: "telemetry registry is stopped".into(),
            },
        }
    }

    fn readiness(&self) -> ServiceReadiness {
        match self.health() {
            ServiceHealth::Healthy => ServiceReadiness::Ready,
            ServiceHealth::Degraded { reason } => ServiceReadiness::Pending { reason },
            ServiceHealth::Unhealthy { reason } => ServiceReadiness::Blocked { reason },
        }
    }
}
