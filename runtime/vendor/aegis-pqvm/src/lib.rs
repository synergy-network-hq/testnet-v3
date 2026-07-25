#![deny(rust_2018_idioms)]
#![allow(dead_code)]

extern crate alloc;

pub mod integrations;
pub mod pqc;
pub mod security;
pub mod traits;
pub mod utils;

#[cfg(feature = "mlkem")]
pub use pqc::kem::mlkem;
#[cfg(feature = "fndsa")]
pub use pqc::signatures::fndsa;
