//! Canonical client-side ETDAG protected-ingress construction.
//!
//! This crate prepares only H+5-bound encrypted envelopes and submits them to
//! a node ingress boundary. It cannot reveal plaintext, determine PoSy
//! finality, or grant authority from an ingress key registry.

pub mod encrypt;
pub mod envelope;
pub mod ingress_keys;
pub mod padding;
pub mod receipt;
pub mod request;
pub mod submit;
pub mod target_context;

pub use encrypt::{encrypt_for_target, ClientEncryptionError, ClientEncryptor, EncryptedPayload};
pub use envelope::{ClientEnvelope, EnvelopeBuildError};
pub use ingress_keys::{ActiveIngressKeys, ClusterMembershipVerifier, IngressKeyError};
pub use padding::{pad_plaintext, PaddingError};
pub use receipt::ClientSubmissionReceipt;
pub use request::{AdmissionRequestBuildError, AdmissionRequestSigner, ClientAdmissionRequest};
pub use submit::{ProtectedIngressSubmitter, SubmissionError};
pub use target_context::{TargetContextError, VerifiedTargetContext};

pub mod protected;
pub use protected::ProtectedClientEncryptor;
