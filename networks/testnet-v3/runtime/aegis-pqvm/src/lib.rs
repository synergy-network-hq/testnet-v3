#![deny(rust_2018_idioms)]
#![allow(dead_code)]

extern crate alloc;

pub mod integrations;
pub mod key_lifecycle;
pub mod pqc;
pub mod quantum_randomness_beacon;
pub mod security;
pub mod traits;
pub mod utils;

#[cfg(feature = "mlkem")]
pub use pqc::kem::mlkem;
#[cfg(feature = "fndsa")]
pub use pqc::signatures::fndsa;
#[cfg(feature = "mldsa")]
pub use pqc::signatures::mldsa;
