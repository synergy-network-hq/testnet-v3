use std::fmt;

use serde::{Deserialize, Serialize};

/// Stable identifier for one supervised runtime service.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ServiceId(String);

impl ServiceId {
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        if value.is_empty()
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err("service id must use lowercase ASCII letters, digits, or hyphens".into());
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ServiceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Whether a service failure requires the complete node to fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Criticality {
    Critical,
    Required,
    Optional,
}

/// Observable health reported by a running service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceHealth {
    Healthy,
    Degraded { reason: String },
    Unhealthy { reason: String },
}

/// Runtime state owned by the supervisor, not by the service implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceState {
    Registered,
    Starting,
    Running,
    Restarting,
    Stopping,
    Stopped,
    Failed,
}

/// Static service declaration used to build the startup and shutdown graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceSpec {
    pub id: ServiceId,
    pub dependencies: Vec<ServiceId>,
    pub criticality: Criticality,
    pub restart_policy: super::RestartPolicy,
}

/// Heterogeneous service boundary owned by the universal node runtime.
pub trait ManagedService: Send {
    fn start(&mut self, cancellation: &super::CancellationToken) -> Result<(), String>;
    fn stop(&mut self) -> Result<(), String>;
    fn health(&self) -> ServiceHealth;

    /// Advances a service whose subsystem uses a caller-owned event loop.
    /// Thread-owned services need no work on the supervisor thread.
    fn poll(&mut self) -> Result<(), String> {
        Ok(())
    }

    /// Readiness must be supplied explicitly; a live worker is insufficient.
    fn readiness(&self) -> ServiceReadiness {
        ServiceReadiness::Pending {
            reason: "subsystem readiness evidence has not been supplied".into(),
        }
    }
}

/// Evidence reported by the subsystem for serving its assigned responsibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum ServiceReadiness {
    Ready,
    Pending { reason: String },
    Blocked { reason: String },
}
