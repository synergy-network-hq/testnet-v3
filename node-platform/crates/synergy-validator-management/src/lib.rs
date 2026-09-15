//! Operational validator onboarding and future-epoch lifecycle preparation.
//!
//! This crate never mutates the active frozen PoSy registry. Only validated
//! PoSy membership authority and epoch transition logic can make changes active.

mod activation;
mod expulsion;
mod health;
mod jailing;
mod lifecycle;
mod migration;
mod onboarding;
mod persistence;
mod registry;
mod removal;
mod shadow;
mod slashing;

pub use activation::ActivationRequest;
pub use expulsion::schedule_expulsion;
pub use health::ValidatorHealthObservation;
pub use jailing::schedule_jailing;
pub use lifecycle::{ActiveMembershipWitness, ValidatorLifecycle, ValidatorLifecycleState};
pub use migration::prepare_next_epoch_records;
pub use onboarding::ValidatorApplication;
pub use persistence::ValidatorManagementStore;
pub use registry::{
    ManagedValidatorRecord, PersistentValidatorManagement, ValidatorManagementCommand,
    ValidatorManagementReceipt, ValidatorManagementResult,
};
pub use removal::schedule_removal;
pub use shadow::stage_shadow_registration;
pub use slashing::schedule_slashing;
