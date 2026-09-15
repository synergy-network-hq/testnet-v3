mod bootstrap;
mod degraded;
mod draining;
mod preflight;
mod ready;
mod shutdown;
mod startup;
mod state;
mod synchronized;

pub use bootstrap::BootstrapReadiness;
pub use degraded::{DegradedCondition, DegradedReason};
pub use draining::DrainPlan;
pub use preflight::PreflightReport;
pub use ready::ReadyEvidence;
pub use shutdown::ShutdownOutcome;
pub use startup::StartupPlan;
pub use state::{LifecycleController, LifecycleTransitionError, NodeLifecycleState};
pub use synchronized::SynchronizationEvidence;
