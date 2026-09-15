use crate::block::{BlockResponse, SyncBlock};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockImportError {
    InvalidRequest,
    EmptyResponse,
    RequestAnchorMismatch,
    ResponseOutOfRange { through_height: u64, received: u64 },
    HeightGap { expected: u64, received: u64 },
    ParentMismatch,
    EmptyCommitment,
    InvalidFinalityEvidence,
}

/// Imports only already-verified block material. PoSy validation and finality
/// evidence verification are supplied by the caller; this type checks only
/// continuity and prevents a sync source from inventing a chain branch.
#[derive(Debug, Clone)]
pub struct VerifiedBlockImporter {
    expected_next_height: u64,
    expected_parent_id: String,
}

impl VerifiedBlockImporter {
    pub fn new(expected_next_height: u64, expected_parent_id: impl Into<String>) -> Self {
        Self {
            expected_next_height,
            expected_parent_id: expected_parent_id.into(),
        }
    }

    pub fn validate_response(
        &mut self,
        response: &BlockResponse,
    ) -> Result<Vec<SyncBlock>, BlockImportError> {
        if !response.request.validate() {
            return Err(BlockImportError::InvalidRequest);
        }
        if response.request.from_height != self.expected_next_height
            || response.request.expected_parent_id != self.expected_parent_id
        {
            return Err(BlockImportError::RequestAnchorMismatch);
        }
        if response.blocks.is_empty() {
            return Err(BlockImportError::EmptyResponse);
        }
        let mut next_height = self.expected_next_height;
        let mut parent = self.expected_parent_id.clone();
        for block in &response.blocks {
            if block.height > response.request.through_height {
                return Err(BlockImportError::ResponseOutOfRange {
                    through_height: response.request.through_height,
                    received: block.height,
                });
            }
            if block.height != next_height {
                return Err(BlockImportError::HeightGap {
                    expected: next_height,
                    received: block.height,
                });
            }
            if block.parent_id != parent {
                return Err(BlockImportError::ParentMismatch);
            }
            if block.block_id.trim().is_empty() || block.finality_evidence_id.trim().is_empty() {
                return Err(BlockImportError::EmptyCommitment);
            }
            next_height = next_height.saturating_add(1);
            parent = block.block_id.clone();
        }
        self.expected_next_height = next_height;
        self.expected_parent_id = parent;
        Ok(response.blocks.clone())
    }

    pub const fn may_determine_finality(&self) -> bool {
        false
    }
}
