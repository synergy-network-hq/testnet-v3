//! Epoch-gated PoSy v3 simplified consensus primitives.
//!
//! This module is intentionally separate from the disabled inherited engine
//! and the historical `posy/2.2` typed coordinator. It cannot become active
//! without a canonical v3 parameter manifest and epoch-transition binding.

mod activation;
mod certificates;
mod core_material;
mod driver;
mod finality;
mod material;
mod material_sync;
mod metrics;
mod protected_material;
mod reliable_delivery;
mod schedule;
mod state;
mod state_sync;
mod target_admission_producer;
mod transition;

pub use activation::*;
pub use certificates::*;
pub use core_material::*;
pub use driver::*;
pub use finality::*;
pub use material::*;
pub use material_sync::*;
pub use metrics::*;
pub use protected_material::*;
pub use reliable_delivery::*;
pub use schedule::*;
pub use state::*;
pub use state_sync::*;
pub use target_admission_producer::*;
pub use transition::*;

#[cfg(test)]
pub(crate) use transition::tests::{
    proof as test_simplified_transition_proof,
    DeterministicAuthorityVerifier as TestSimplifiedTransitionAuthorityVerifier,
    DeterministicVerifier as TestSimplifiedConsensusVerifier,
};

#[cfg(test)]
mod tests;
