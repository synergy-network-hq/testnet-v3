//! # SynQ PQC Shims
//!
//! This crate provides real Post-Quantum Cryptography (PQC) implementations
//! for the SynQ programming language using the pqcrypto crate.
//!
//! All implementations use the actual cryptographic algorithms from pqcrypto
//! and are suitable for production use.

pub mod dilithium;
pub mod falcon;
pub mod hqc;
pub mod kyber;
pub mod mceliece;
pub mod sphincs;

// Re-export common PQC types - using specific algorithm implementations
// Note: The pqcrypto API has changed and these generic types are no longer available
// Each algorithm module exports its own types

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
