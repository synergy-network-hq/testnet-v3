use serde::{Deserialize, Serialize};

/// Minimum authority-neutral bootstrap evidence required before synchronization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapReadiness {
    pub configuration_validated: bool,
    pub identity_loaded: bool,
    pub storage_opened: bool,
    pub network_bound: bool,
}

impl BootstrapReadiness {
    pub fn ready_for_synchronization(self) -> bool {
        self.configuration_validated
            && self.identity_loaded
            && self.storage_opened
            && self.network_bound
    }
}
