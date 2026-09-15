use serde::{Deserialize, Serialize};

use crate::{Block, BlockError};

pub const BLOCK_FORMAT: &str = "synergy-block-v1";
pub const DEFAULT_MAX_BLOCK_BYTES: usize = 16 * 1024 * 1024;

/// The canonical encoding boundary is intentionally explicit. Network framing,
/// persistence codecs, and signature verification own their respective formats.
pub trait BlockCodec {
    type Error: std::fmt::Display;

    fn encode(&self, block: &Block) -> Result<Vec<u8>, Self::Error>;
    fn decode(&self, bytes: &[u8]) -> Result<Block, Self::Error>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanonicalBlockCodec {
    max_block_bytes: usize,
}

impl Default for CanonicalBlockCodec {
    fn default() -> Self {
        Self {
            max_block_bytes: DEFAULT_MAX_BLOCK_BYTES,
        }
    }
}

impl CanonicalBlockCodec {
    pub fn new(max_block_bytes: usize) -> Result<Self, BlockError> {
        (max_block_bytes > 0)
            .then_some(Self { max_block_bytes })
            .ok_or(BlockError::InvalidCodecLimit)
    }
}

#[derive(Serialize)]
struct BlockEnvelopeRef<'a> {
    format: &'static str,
    block: &'a Block,
}

#[derive(Deserialize)]
struct BlockEnvelope {
    format: String,
    block: Block,
}

impl BlockCodec for CanonicalBlockCodec {
    type Error = BlockError;

    fn encode(&self, block: &Block) -> Result<Vec<u8>, Self::Error> {
        block.validate_structure()?;
        let bytes = serde_json::to_vec(&BlockEnvelopeRef {
            format: BLOCK_FORMAT,
            block,
        })
        .map_err(|error| BlockError::Encoding(error.to_string()))?;
        if bytes.len() > self.max_block_bytes {
            return Err(BlockError::BlockTooLarge {
                actual: bytes.len(),
                maximum: self.max_block_bytes,
            });
        }
        Ok(bytes)
    }

    fn decode(&self, bytes: &[u8]) -> Result<Block, Self::Error> {
        if bytes.is_empty() || bytes.len() > self.max_block_bytes {
            return Err(BlockError::BlockTooLarge {
                actual: bytes.len(),
                maximum: self.max_block_bytes,
            });
        }
        let envelope: BlockEnvelope = serde_json::from_slice(bytes)
            .map_err(|error| BlockError::Encoding(error.to_string()))?;
        if envelope.format != BLOCK_FORMAT {
            return Err(BlockError::UnsupportedFormat);
        }
        envelope.block.validate_structure()?;
        Ok(envelope.block)
    }
}

pub fn validate_decoded(block: &Block) -> Result<(), BlockError> {
    block.validate_structure()
}
