//! Node-facing Aegis signing, verification, custody, and audit boundary.
//!
//! Private key material never crosses this crate's provider traits. Concrete
//! post-quantum implementations must be supplied by an approved provider and
//! are never silently substituted by a classical or test algorithm.

mod attestation;
mod audit;
mod binding;
mod digest;
mod entropy;
mod kem;
mod key_lifecycle;
mod kms_bridge;
mod policy;
mod pqsynq;
mod pqvm;
mod signer;
mod verifier;

pub use attestation::{ProviderAttestation, ProviderAttestationError};
pub use audit::{AuditEvent, AuditOperation, AuditOutcome, AuditSink};
pub use binding::{BindingError, GovernedKeyBindings, GovernedNodeKeyBinding};
pub use digest::{AegisDigest, AegisHashEngine, AegisSha3_256, DigestError};
pub use entropy::{AegisEntropy, EntropyError, OperatingSystemEntropy};
pub use kem::{AegisKem, KemEncapsulation, KemError, PqvmMlKem768};
pub use key_lifecycle::{KeyId, KeyIdError, KeyPurpose, KeyRecord, KeyState, KeyTransitionError};
pub use kms_bridge::{KmsBridge, KmsError, ProviderHealth};
pub use policy::{AegisPolicy, PolicyError, SignatureAlgorithm};
pub use pqsynq::{
    PqSynqError, PqSynqExecutionAuthorization, PqSynqVerifier, VerifiedPqSynqExecution,
    VerifiedPqSynqOperation,
};
pub use pqvm::{PqvmSigner, PqvmVerifier};
pub use signer::{AegisSigner, Signature, SigningContext, SigningError};
pub use verifier::{AegisVerifier, VerificationError};
