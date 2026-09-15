use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagementOperation {
    NodeStatus,
    Health,
    Readiness,
    Diagnostics,
    ConfigurationValidation,
    RoleInspection,
    CapabilityDiscovery,
}

impl ManagementOperation {
    pub const ALL: [Self; 7] = [
        Self::NodeStatus,
        Self::Health,
        Self::Readiness,
        Self::Diagnostics,
        Self::ConfigurationValidation,
        Self::RoleInspection,
        Self::CapabilityDiscovery,
    ];

    pub fn is_read_only(self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn management_surface_is_read_only_until_a_mutating_operation_is_implemented() {
        assert!(ManagementOperation::ALL
            .into_iter()
            .all(ManagementOperation::is_read_only));
    }
}
