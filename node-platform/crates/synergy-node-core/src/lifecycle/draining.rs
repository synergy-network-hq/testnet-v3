use serde::{Deserialize, Serialize};

use crate::supervisor::ServiceId;

/// Graceful drain request consumed before reverse dependency shutdown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrainPlan {
    pub stop_accepting_work: Vec<ServiceId>,
    pub grace_period_millis: u64,
}

impl DrainPlan {
    pub fn bounded(self, maximum_grace_millis: u64) -> Self {
        Self {
            grace_period_millis: self.grace_period_millis.min(maximum_grace_millis),
            ..self
        }
    }
}
