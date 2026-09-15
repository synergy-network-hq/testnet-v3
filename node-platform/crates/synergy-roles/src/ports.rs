use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::RoleError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolePorts {
    pub p2p: Option<u16>,
    pub rpc: Option<u16>,
    pub admin: Option<u16>,
    pub metrics: Option<u16>,
}

impl RolePorts {
    pub fn validate(&self) -> Result<(), RoleError> {
        let mut seen = BTreeSet::new();
        for port in [self.p2p, self.rpc, self.admin, self.metrics]
            .into_iter()
            .flatten()
        {
            if port == 0 || !seen.insert(port) {
                return Err(RoleError::Invalid(
                    "role ports must be non-zero and unique".into(),
                ));
            }
        }
        Ok(())
    }
}
