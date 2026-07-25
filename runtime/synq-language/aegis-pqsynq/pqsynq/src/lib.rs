//! # PQSynQ - Post-Quantum Cryptography for SynQ
//!
//! This crate provides a unified interface for Post-Quantum Cryptography (PQC) algorithms
//! specifically designed for use within the SynQ quantum computing framework.
//!
//! ## Supported Algorithms
//!
//! ### Key Encapsulation Mechanisms (KEM)
//! - **ML-KEM** (Module-Lattice-based Key Encapsulation Mechanism) - NIST Standard
//! - **HQC-KEM** (Hamming Quasi-Cyclic Key Encapsulation Mechanism) - Optional
//!
//! ### Digital Signature Schemes
//! - **ML-DSA** (Module-Lattice-based Digital Signature Algorithm) - NIST Standard
//! - **FN-DSA** (FN-DSA Digital Signature Algorithm) - NIST Standard
//!
//! ## Usage
//!
//! ```rust
//! use pqsynq::{DigitalSignature, Kem, KeyEncapsulation, Sign, PqcError};
//!
//! # fn main() -> Result<(), PqcError> {
//! // KEM operations
//! let kem = Kem::mlkem768();
//! let (pk, sk) = kem.keygen()?;
//! let (ct, ss) = kem.encapsulate(&pk)?;
//! let recovered_ss = kem.decapsulate(&ct, &sk)?;
//!
//! // Signature operations
//! let signer = Sign::mldsa65();
//! let (pk, sk) = signer.keygen()?;
//! let message: &[u8] = b"hello";
//! let sig = signer.sign(message, &sk)?;
//! let valid = signer.verify(message, &sig, &pk)?;
//! # Ok(()) }
//! ```

#![no_std]
#![allow(clippy::len_without_is_empty)]

// For no-std vectors
extern crate alloc;

// For tests
#[cfg(feature = "std")]
extern crate std;

pub mod address;
pub mod algorithms;
pub mod domain;
pub mod error;
pub mod kem;
pub mod keys;
pub mod payload;
pub mod policy;
pub mod serialization;
pub mod sign;
pub mod signature;
pub mod test_vectors;
pub mod traits;
pub mod utils;
pub mod verifier;

// Re-export main types
pub use address::{derive_synq_address, SynQAddress};
pub use algorithms::{AlgorithmId, SecurityLevel, SignaturePurpose};
pub use domain::{ChainId, DomainTag, NetworkId};
pub use error::{AegisSynQError, PqcError};
pub use kem::{Kem, KemAlgorithm};
pub use keys::{SynQPrivateKeyRef, SynQPublicKey, SynQSignature};
pub use payload::{
    ContractCallEnvelope, ContractDeployEnvelope, Hash32, SynQSigningPayload,
    SynQTransactionEnvelope, VerificationContext, VerifiedContractCall, VerifiedContractDeploy,
    VerifiedSynQTransaction,
};
pub use policy::SynQSecurityPolicy;
pub use serialization::{
    canonicalize_signing_payload, hash_contract_call_body, hash_contract_deploy_body,
    hash_signing_payload,
};
pub use sign::{Sign, SignAlgorithm};
pub use traits::{DigitalSignature, KeyEncapsulation};
pub use utils::SecretBytes;
pub use verifier::AegisSynQVerifier;

// Re-export specific algorithms for direct access
#[cfg(feature = "hqckem")]
pub use kem::{Hqckem128, Hqckem192, Hqckem256};
#[cfg(feature = "mlkem")]
pub use kem::{Mlkem1024, Mlkem512, Mlkem768};

#[cfg(feature = "fndsa")]
pub use sign::{Fndsa1024, Fndsa512};
#[cfg(feature = "mldsa")]
pub use sign::{Mldsa44, Mldsa65, Mldsa87};

/// Result type for PQC operations
pub type Result<T> = core::result::Result<T, PqcError>;

/// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Get the version string
pub fn version() -> &'static str {
    VERSION
}
