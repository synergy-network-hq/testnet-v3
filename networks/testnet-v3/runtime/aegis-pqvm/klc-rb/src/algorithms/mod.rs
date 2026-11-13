//! Algorithm implementations for key lifecycle and randomness beacon functionality

pub mod dilithium;
pub mod kyber;

// Re-export as mlkem/mldsa for API consistency (dilithium=ML-DSA, kyber=ML-KEM)
pub mod mldsa {
    pub use super::dilithium::*;
}
pub mod mlkem {
    pub use super::kyber::*;
}
pub use mldsa::*;
pub use mlkem::*;
