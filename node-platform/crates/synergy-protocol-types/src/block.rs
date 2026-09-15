//! Canonical cross-component block reference.

use serde::{Deserialize, Serialize};

use crate::{Height, ProtocolHash};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockReference {
    pub height: Height,
    pub block_hash: ProtocolHash,
    pub parent_hash: ProtocolHash,
}

impl BlockReference {
    pub fn new(
        height: Height,
        block_hash: ProtocolHash,
        parent_hash: ProtocolHash,
    ) -> Result<Self, BlockReferenceError> {
        if block_hash.is_zero() {
            return Err(BlockReferenceError::ZeroBlockHash);
        }
        if height != Height::GENESIS && parent_hash.is_zero() {
            return Err(BlockReferenceError::MissingParentHash);
        }
        if block_hash == parent_hash {
            return Err(BlockReferenceError::SelfParent);
        }
        Ok(Self {
            height,
            block_hash,
            parent_hash,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockReferenceError {
    ZeroBlockHash,
    MissingParentHash,
    SelfParent,
}

impl std::fmt::Display for BlockReferenceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroBlockHash => formatter.write_str("block hash must be nonzero"),
            Self::MissingParentHash => {
                formatter.write_str("non-genesis block requires a parent hash")
            }
            Self::SelfParent => formatter.write_str("block cannot name itself as parent"),
        }
    }
}

impl std::error::Error for BlockReferenceError {}
