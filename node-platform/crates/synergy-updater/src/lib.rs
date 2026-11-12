//! Signed, bounded software-update orchestration.
//!
//! Installing software never activates a protocol version. Protocol activation
//! remains a separately governed chain decision enforced by [`ActivationGate`].

mod activation;
mod audit;
mod channel;
mod compatibility;
mod coordinator;
mod discovery;
mod drain;
mod health;
mod install;
mod metadata;
mod policy;
mod preflight;
mod rollback;
mod staging;
mod verification;

pub use activation::{ActivationDecision, ActivationGate};
pub use audit::{AuditEvent, AuditOutcome, AuditSink, UpdatePhase};
pub use channel::ReleaseChannel;
pub use compatibility::{CompatibilityGate, RuntimeVersions};
pub use coordinator::{
    ArtifactSource, UpdateCoordinator, UpdateError, UpdateOutcome, UpdateRequest, UpdateRuntime,
};
pub use discovery::{discover_release, ReleaseCatalog, ReleaseDiscovery};
pub use drain::{DrainCoordinator, DrainReceipt};
pub use health::{HealthGate, HealthObservation};
pub use install::{InstallCoordinator, InstallReceipt};
pub use metadata::{ArtifactMetadata, ReleaseMetadata, SignedReleaseMetadata};
pub use policy::{AutomaticUpdatePolicy, UpdateMode};
pub use preflight::{PreflightGate, PreflightObservation};
pub use rollback::{RollbackCoordinator, RollbackReceipt};
pub use staging::{stage_artifact, StagedArtifact, StagingError};
pub use verification::{verify_release, VerificationError, VerifiedRelease};

pub const MAXIMUM_CATALOG_RELEASES: usize = 256;
pub const MAXIMUM_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024 * 1024;
