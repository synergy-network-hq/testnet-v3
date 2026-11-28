//! Deterministic bounded AIVM execution boundary. It cannot create consensus or finality evidence.
pub mod metrics;
pub mod ethereum;
pub mod ethereum_admission;
pub mod ethereum_execution;
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

pub mod ethereum_projection;

pub mod r1_addresses;

pub mod r1_evm;
