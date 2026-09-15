use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::supervisor::ServiceId;

/// Immutable startup intent consumed by the dependency-aware supervisor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartupPlan {
    pub role: String,
    pub required_services: Vec<ServiceId>,
    pub shadow_before_active: bool,
}

impl StartupPlan {
    pub fn validate(&self) -> Result<(), String> {
        if self.role.trim().is_empty() {
            return Err("startup role must not be empty".into());
        }
        if self.required_services.is_empty() {
            return Err("startup plan must require at least one service".into());
        }
        let unique: BTreeSet<_> = self.required_services.iter().collect();
        if unique.len() != self.required_services.len() {
            return Err("startup plan contains duplicate services".into());
        }
        Ok(())
    }
}
