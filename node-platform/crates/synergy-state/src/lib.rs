//! Deterministic account-state transitions and finalized state-commit ownership.
//!
//! PoSy proves finality before persistence is called. State code can validate
//! continuity and durability, but cannot manufacture a QC or finality.

mod account;
mod diff;
mod overlay;
mod proof;
mod pruning;
mod root;
mod state;
mod transition;

pub use account::AccountState;
pub use diff::{AccountChange, ProtocolChange, StateDiff};
pub use overlay::StateOverlay;
pub use proof::{verify_finalized_state_proof, StateProof, StateProofVerifier};
pub use pruning::RetentionPolicy;
pub use root::state_root;
pub use state::{FinalizedState, WorldState};
pub use transition::{FinalizedStateStore, StateError};
