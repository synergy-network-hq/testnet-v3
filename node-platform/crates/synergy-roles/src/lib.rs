//! Protocol-neutral node-role and service-capability declarations.
//!
//! Role configuration selects services only. PoSy membership, frozen voting
//! weight, governed key bindings, and verified certificates remain the sole
//! sources of consensus authority.

mod authority_plane;
mod capability;
mod ports;
mod profile;
mod registry;
mod role;
mod service_graph;
mod validation;

pub use authority_plane::{validate_authority_plane, AuthorityPlane};
pub use capability::Capability;
pub use ports::RolePorts;
pub use profile::RoleProfile;
pub use registry::RoleRegistry;
pub use role::{role_id, NodeRole};
pub use service_graph::{validate_service_graph, ServiceBinding, ServiceId};
pub use validation::validate_profile_set;

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoleError {
    Invalid(String),
    DuplicateRole(String),
    UnknownRole(String),
}

impl fmt::Display for RoleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => formatter.write_str(message),
            Self::DuplicateRole(role) => write!(formatter, "duplicate role: {role}"),
            Self::UnknownRole(role) => write!(formatter, "unknown role: {role}"),
        }
    }
}

impl std::error::Error for RoleError {}
