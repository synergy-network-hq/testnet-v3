//! Stable, authority-neutral types shared by node management clients.
//!
//! This crate deliberately contains no consensus voting, validator weighting,
//! or transport authority. PoSy authority remains Genesis-bound and runtime
//! owned; management only observes and asks the runtime to perform safe work.

pub mod lifecycle;
pub mod readiness;
pub mod runtime;
pub mod supervisor;

mod context;
mod error;
mod node;

pub use context::MANAGEMENT_SCHEMA_VERSION;
pub use error::SupervisorError;
pub use lifecycle::{
    BootstrapReadiness, DegradedCondition, DegradedReason, DrainPlan, LifecycleController,
    LifecycleTransitionError, NodeLifecycleState, PreflightReport, ReadyEvidence, ShutdownOutcome,
    StartupPlan, SynchronizationEvidence,
};
pub use node::ManagementOperation;
pub use readiness::{
    CheckSeverity, CheckState, ConsensusReadiness, DiagnosticCheck, EtdagReadiness,
    NetworkReadiness, ReadinessReport, StorageReadiness, SyncReadiness, VpnReadiness,
};
pub use runtime::{RuntimeSnapshot, RuntimeView, ServiceObservation};
pub use supervisor::{
    CancellationToken, Criticality, DependencyGraph, ManagedService, RestartPolicy, ServiceHealth,
    ServiceId, ServiceReadiness, ServiceSpec, ServiceState, ShutdownReport, Supervisor,
};
