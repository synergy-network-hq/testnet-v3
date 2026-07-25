// Include Node.js initialization for WASM builds
#[cfg(feature = "wasm-nodejs")]
pub mod nodejs_init;

#[cfg(feature = "cmce")]
pub mod cmce;
#[cfg(feature = "fndsa")]
pub mod fndsa;
#[cfg(feature = "hqc")]
pub mod hqckem;
#[cfg(feature = "mldsa")]
pub mod mldsa;
#[cfg(feature = "mlkem")]
pub mod mlkem;
#[cfg(feature = "slhdsa")]
pub mod slhdsa;

// NIST Reference WASM implementations
#[cfg(feature = "nist-wasm")]
pub mod nist_wasm_mldsa;
#[cfg(feature = "nist-wasm")]
pub mod nist_wasm_mlkem;
#[cfg(feature = "nist-wasm")]
pub mod wasm_loader;

/// Trait definitions for unified algorithm interfaces.
pub mod traits;

pub mod hash;
pub mod performance;
pub mod utils;

// Security modules
pub mod secure_key_management;
pub mod security_monitoring;

// The `js_bindings` module exposes a JavaScript‑friendly API on top of the
// low‑level functions.  It is compiled unconditionally when building the
// WebAssembly target so that its exports are available via `wasm-pack`.
pub mod js_bindings;

// The Python bindings are conditionally compiled when the
// `python-bindings` feature is enabled.  See `Cargo.toml` for more
// details.  The module contains PyO3 wrappers that expose the
// algorithms to Python as a native extension.
// #[cfg(feature = "python-bindings")]
// pub mod python_bindings;

#[cfg(feature = "cmce")]
pub use cmce::*;
#[cfg(feature = "fndsa")]
pub use fndsa::*;
#[cfg(feature = "hqc")]
pub use hqckem::*;
#[cfg(feature = "mldsa")]
pub use mldsa::*;
#[cfg(feature = "mlkem")]
pub use mlkem::*;
#[cfg(feature = "slhdsa")]
pub use slhdsa::*;

// Re-export NIST Reference WASM implementations
#[cfg(feature = "nist-wasm")]
pub use nist_wasm_mldsa::*;
#[cfg(feature = "nist-wasm")]
pub use nist_wasm_mlkem::*;
#[cfg(feature = "nist-wasm")]
pub use wasm_loader::*;
