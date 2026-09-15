#![deny(rust_2018_idioms)]
#![allow(dead_code)]

extern crate alloc;

pub mod integrations;
pub mod key_lifecycle;
pub mod licensing;
pub mod licensing_secret;
pub mod pqc;
pub mod quantum_randomness_beacon;
pub mod security;
pub mod traits;
pub mod utils;

pub use pqc::kem::mlkem;
pub use pqc::signatures::{fndsa, mldsa};
