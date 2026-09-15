//! Read-only runtime observations shared by administration and public APIs.

use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

use crate::{NodeLifecycleState, ServiceHealth, ServiceId, ServiceReadiness, ServiceState};

/// Snapshot publication never transfers subsystem ownership or signing authority.
pub type RuntimeView = Arc<RwLock<RuntimeSnapshot>>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceObservation {
    pub id: ServiceId,
    pub state: ServiceState,
    pub health: ServiceHealth,
    pub readiness: ServiceReadiness,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeSnapshot {
    pub node_name: String,
    pub role: String,
    pub chain_id: u64,
    pub lifecycle: NodeLifecycleState,
    pub services: Vec<ServiceObservation>,
}

impl RuntimeSnapshot {
    pub fn service(&self, id: &str) -> Option<&ServiceObservation> {
        self.services
            .iter()
            .find(|service| service.id.as_str() == id)
    }

    /// Includes an explicit lifecycle gate and refuses vacuous readiness.
    pub fn ready(&self) -> bool {
        matches!(
            self.lifecycle,
            NodeLifecycleState::Ready | NodeLifecycleState::Active
        ) && !self.services.is_empty()
            && self.services.iter().all(|service| {
                service.state == ServiceState::Running
                    && service.health == ServiceHealth::Healthy
                    && service.readiness == ServiceReadiness::Ready
            })
    }
}
