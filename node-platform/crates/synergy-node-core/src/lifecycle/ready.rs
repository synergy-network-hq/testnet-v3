use serde::{Deserialize, Serialize};

use crate::supervisor::ServiceId;

/// Evidence that all role-required services and safety gates permit readiness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadyEvidence {
    pub preflight_passed: bool,
    pub bootstrap_complete: bool,
    pub synchronization_complete: bool,
    pub healthy_required_services: Vec<ServiceId>,
    pub expected_required_services: Vec<ServiceId>,
}

impl ReadyEvidence {
    pub fn ready(&self) -> bool {
        if !(self.preflight_passed && self.bootstrap_complete && self.synchronization_complete) {
            return false;
        }
        self.expected_required_services
            .iter()
            .all(|service| self.healthy_required_services.contains(service))
    }
}
