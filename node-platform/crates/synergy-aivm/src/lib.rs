//! Deterministic bounded AIVM execution boundary. It cannot create consensus or finality evidence.
pub mod metrics;
mod quantum;
pub mod resources;
pub mod runtime;
pub mod sandbox;
mod synq_vm;
pub mod validation;
pub use resources::{ResourceBudget, ResourceUsage};
pub use runtime::{AivmEngine, AivmRequest, AivmResult};
pub use sandbox::{SandboxPolicy, SandboxViolation};
pub use synq_vm::CanonicalAivmSynqVm;
