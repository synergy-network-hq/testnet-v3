use synergy_config::P2pConfiguration;
use synergy_network::sentry::SentryForwarder;
use synergy_node_core::{
    CancellationToken, Criticality, ManagedService, RestartPolicy, ServiceHealth, ServiceId,
    ServiceReadiness, ServiceSpec,
};

/// Owns only the bounded forwarding perimeter for a Sentry role. It does not
/// accept a raw transport stream or acquire any consensus capability.
pub fn registration(
    configuration: &P2pConfiguration,
) -> Result<(ServiceSpec, Box<dyn ManagedService>), String> {
    if configuration.max_authenticated_peers == 0 || configuration.max_pending_handshakes == 0 {
        return Err("Sentry forwarding requires nonzero peer capacities".into());
    }
    Ok((
        ServiceSpec {
            id: ServiceId::new("sentry")?,
            dependencies: vec![ServiceId::new("network")?, ServiceId::new("identity")?],
            criticality: Criticality::Required,
            restart_policy: RestartPolicy::OnFailure { max_attempts: 3 },
        },
        Box::new(SentryService {
            forwarder: Some(SentryForwarder::new(
                configuration.max_authenticated_peers,
                configuration.max_pending_handshakes,
            )),
        }),
    ))
}

struct SentryService {
    forwarder: Option<SentryForwarder>,
}

impl ManagedService for SentryService {
    fn start(&mut self, cancellation: &CancellationToken) -> Result<(), String> {
        if cancellation.is_cancelled() {
            return Err("Sentry service start was cancelled".into());
        }
        if self.forwarder.is_none() {
            return Err("Sentry forwarding perimeter is unavailable".into());
        }
        Ok(())
    }

    fn stop(&mut self) -> Result<(), String> {
        self.forwarder = None;
        Ok(())
    }

    fn health(&self) -> ServiceHealth {
        if self.forwarder.is_some() {
            ServiceHealth::Degraded {
                reason: "Sentry perimeter awaits authenticated network session ownership".into(),
            }
        } else {
            ServiceHealth::Unhealthy {
                reason: "Sentry forwarding perimeter is stopped".into(),
            }
        }
    }

    fn readiness(&self) -> ServiceReadiness {
        ServiceReadiness::Blocked {
            reason: "Sentry accepts only authenticated ingress, which has no runtime owner yet"
                .into(),
        }
    }
}
