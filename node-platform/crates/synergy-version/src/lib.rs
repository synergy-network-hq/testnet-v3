//! Independent version domains and governed compatibility decisions.
//!
//! A matching software release is never treated as proof of protocol,
//! configuration, database, or authority compatibility.

mod activation;
mod compatibility;
mod config;
mod database;
mod protocol;
mod release;

pub use activation::{Activation, ActivationError, ActivationPoint};
pub use compatibility::{Compatibility, CompatibilityMatrix, CompatibilityRequirement};
pub use config::ConfigSchemaVersion;
pub use database::DatabaseSchemaVersion;
pub use protocol::{ProtocolComponent, ProtocolVersion};
pub use release::{ReleaseVersion, ReleaseVersionError};
