//! Canonical ETDAG v3 protected transaction subsystem.
//!
//! ETDAG binds encrypted ingress to finalized context, certifies availability,
//! produces deterministic protected order, authorizes reveal, and prepares
//! execution input. It neither determines PoSy finality nor grants validator
//! authority from transport, VPN, or role configuration.

pub mod admission;
pub mod availability;
pub mod certificates;
pub mod crypto;
pub mod dag;
pub mod digest;
pub mod domains;
pub mod errors;
pub mod execution;
pub mod governance;
pub mod ingress;
pub mod metrics;
pub mod network;
pub mod ordering;
pub mod parameters;
pub mod persistence;
pub mod profile;
pub mod recovery;
pub mod reveal;

pub use admission::{EtdagAdmission, TargetAdmissionContext, TargetAdmissionContextV3};
pub use availability::{certificate_quorum, AvailabilityCertificate, AvailabilityVote};
pub use crypto::{
    AeadCiphertext, AeadProvider, EncryptedTransactionEnvelope, EnvelopeNonce, IngressKemKeyRecord,
    IngressKemKeyRegistry, IngressKemPublicKey, KemProvider, ShareCapsule,
};
pub use dag::{
    deterministic_topological_order, insert_vertex, validate_graph, EtdagGraph, TransactionVertex,
};
pub use digest::EtdagDigest;
pub use errors::EtdagError;
pub use execution::DeterministicProtectedExecutionInput;
pub use ingress::{ProtectedEnvelope, ProtectedIngressReceipt, ProtectedIngressService};
pub use metrics::{EtdagMetrics, EtdagMetricsSnapshot};
pub use network::{
    AuthenticatedEtdagMessage, CertifiedExecutionHandoff, EtdagNetworkHandler, EtdagNetworkMessage,
    MissingArtifactRequest, RecoveredShardCustody, ShardCustodyMessage,
};
pub use ordering::{
    canonical_content_blind_order, derive_order_seed, protected_order_root, CertifiedEnvelopeRef,
    DeterministicProtectedBatch, ProtectedCutProof, ProtectedOrderingProof,
};
pub use parameters::{
    EtdagParameters, CIPHERTEXT_SIZE_CLASSES, MAX_OUTSTANDING_NONCE_SLOTS, MIN_TARGET_HEIGHT_OFFSET,
};
pub use persistence::PersistentEtdagAdmission;
pub use profile::ETDAG_PROFILE_ID;
pub use reveal::{DecryptShareCollection, DecryptShareMessage, ProtectedRevealAuthorization};
