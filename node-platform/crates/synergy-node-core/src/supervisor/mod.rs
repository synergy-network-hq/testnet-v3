//! Dependency-aware ownership and lifecycle control for node services.

mod cancellation;
mod dependency_graph;
mod restart_policy;
mod service;
mod shutdown;
mod supervisor;

pub use cancellation::CancellationToken;
pub use dependency_graph::DependencyGraph;
pub use restart_policy::RestartPolicy;
pub use service::{
    Criticality, ManagedService, ServiceHealth, ServiceId, ServiceReadiness, ServiceSpec,
    ServiceState,
};
pub use shutdown::ShutdownReport;
pub use supervisor::Supervisor;
