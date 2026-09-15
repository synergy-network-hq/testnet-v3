//! Chain identity primitives. These bind data to a network, not to authority.

use serde::{Deserialize, Serialize};

use crate::ProtocolHash;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ChainId(u64);

impl ChainId {
    pub fn new(value: u64) -> Result<Self, ChainIdError> {
        if value == 0 {
            return Err(ChainIdError::Zero);
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainContext {
    pub chain_id: ChainId,
    pub genesis_hash: ProtocolHash,
}

impl ChainContext {
    pub const fn new(chain_id: ChainId, genesis_hash: ProtocolHash) -> Self {
        Self {
            chain_id,
            genesis_hash,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainIdError {
    Zero,
}

impl std::fmt::Display for ChainIdError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("chain id must be nonzero")
    }
}

impl std::error::Error for ChainIdError {}
