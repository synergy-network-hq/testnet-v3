//! Universal Meta-Address parsing, authorized mapping, and resolution.

pub mod adapters;
mod address;
mod coordinator;
mod mapping;
mod registry;
mod verifier;

pub use address::UmaAddress;
pub use coordinator::UmaCoordinator;
pub use mapping::{AddressMapping, AddressNamespace};
pub use registry::UmaRegistry;
pub use verifier::{verify_mapping, MappingAuthorizationVerifier};
