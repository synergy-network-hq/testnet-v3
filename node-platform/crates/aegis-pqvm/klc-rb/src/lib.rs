//! Aegis KLC-RB - Self-contained randomness beacon and key lifecycle manager
//!
//! This crate provides quantum randomness beacon and key lifecycle management
//! functionality with all required algorithm implementations.

pub mod algorithms;
pub mod hash;
pub mod utils;

// Re-export algorithm modules
pub use algorithms::mldsa;
pub use algorithms::mlkem;

// Main modules
pub mod key_lifecycle_manager;
pub mod quantum_randomness_beacon;

#[cfg(feature = "wasm")]
mod key_lifecycle_manager_wasm;

// Re-export public APIs
pub use key_lifecycle_manager::*;
pub use quantum_randomness_beacon::*;
