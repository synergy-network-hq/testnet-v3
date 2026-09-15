//! SynQ deterministic smart-execution boundary.
//!
//! SynQ executes only within a deterministic block context. It cannot select a
//! proposer, grant validator authority, compute PoSy quorum, or determine finality.

mod bytecode;
mod determinism;
mod executor;
mod gas;
mod host;
mod storage;
mod tracing;
mod verifier;
mod vm;

pub use bytecode::SynqArtifact;
pub use determinism::DeterministicContext;
pub use executor::{SynqExecutionReceipt, SynqExecutor};
pub use gas::GasMeter;
pub use host::SynqHost;
pub use storage::{load_verified_artifact, store_verified_artifact, SynqStorage};
pub use tracing::{NoopSynqTrace, SynqTraceEvent, SynqTraceSink};
pub use verifier::SynqArtifactVerifier;
pub use vm::SynqVm;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SynqError {
    EmptyArtifact,
    ArtifactHashMismatch,
    InvalidGasLimit,
    GasOverflow,
    OutOfGas,
    InvalidContext,
    Transaction(String),
    Host(String),
    Vm(String),
}

impl std::fmt::Display for SynqError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for SynqError {}
