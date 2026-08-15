//! Epoch-gated PoSy v3 simplified consensus primitives.
//!
//! This module is intentionally separate from the disabled inherited engine
//! and the historical `posy/2.2` typed coordinator. It cannot become active
//! without a canonical v3 parameter manifest and epoch-transition binding.

mod activation;
mod certificates;
mod driver;
mod metrics;
mod reliable_delivery;
mod schedule;
mod state;
mod state_sync;

pub use activation::*;
pub use certificates::*;
pub use driver::*;
pub use metrics::*;
pub use reliable_delivery::*;
pub use schedule::*;
pub use state::*;
pub use state_sync::*;

#[cfg(test)]
mod tests;
