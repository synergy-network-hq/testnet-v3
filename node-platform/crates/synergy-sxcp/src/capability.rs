use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::ExternalChain;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SxcpCapability {
    pub chains: BTreeSet<ExternalChain>,
    pub maximum_proof_bytes: usize,
    pub maximum_inflight_relays: usize,
}

impl SxcpCapability {
    pub fn validate(&self) -> Result<(), String> {
        if self.chains.is_empty()
            || self.maximum_proof_bytes == 0
            || self.maximum_proof_bytes > 16 * 1024 * 1024
            || self.maximum_inflight_relays == 0
        {
            return Err("invalid SXCP capability".into());
        }
        Ok(())
    }
}
