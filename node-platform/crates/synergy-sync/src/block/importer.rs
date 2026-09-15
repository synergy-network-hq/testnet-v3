use super::{BlockImportError, BlockResponse, SyncBlock, VerifiedBlockImporter};

/// Adapter implemented by PoSy to verify a block's finality evidence.
pub trait PosyBlockFinalityVerifier {
    type Error;

    /// Verifies that the evidence finalizes exactly this height and block ID.
    fn verify_finalized_block(&self, block: &SyncBlock) -> Result<(), Self::Error>;
}

/// Durable store for a fully continuity-checked block batch.
pub trait VerifiedBlockStore {
    type Error;

    /// Atomically imports the ordered batch or leaves the store unchanged.
    fn import_verified_blocks(&mut self, blocks: &[SyncBlock]) -> Result<(), Self::Error>;
}

/// Receipt used to advance scheduling only after durable import succeeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockImportReceipt {
    pub from_height: u64,
    pub through_height: u64,
    pub imported_blocks: usize,
    pub last_block_id: String,
}

/// Typed failure from validation or durable storage.
#[derive(Debug)]
pub enum BlockCommitError<F, S> {
    Validation(BlockImportError),
    Finality { height: u64, source: F },
    Store(S),
}

/// Coordinates continuity validation and atomic storage without taking finality authority.
#[derive(Debug, Clone)]
pub struct BlockImportCoordinator {
    verifier: VerifiedBlockImporter,
}

impl BlockImportCoordinator {
    /// Creates an importer anchored to the caller's locally finalized block.
    pub fn new(expected_next_height: u64, expected_parent_id: impl Into<String>) -> Self {
        Self {
            verifier: VerifiedBlockImporter::new(expected_next_height, expected_parent_id),
        }
    }

    /// Validates and atomically imports one response.
    ///
    /// The internal continuity anchor advances only after storage succeeds.
    ///
    /// # Errors
    /// Returns a validation failure or the store's typed import error.
    pub fn import<V: PosyBlockFinalityVerifier, S: VerifiedBlockStore>(
        &mut self,
        response: &BlockResponse,
        finality: &V,
        store: &mut S,
    ) -> Result<BlockImportReceipt, BlockCommitError<V::Error, S::Error>> {
        let mut proposed = self.verifier.clone();
        let blocks = proposed
            .validate_response(response)
            .map_err(BlockCommitError::Validation)?;
        for block in &blocks {
            finality.verify_finalized_block(block).map_err(|source| {
                BlockCommitError::Finality {
                    height: block.height,
                    source,
                }
            })?;
        }
        store
            .import_verified_blocks(&blocks)
            .map_err(BlockCommitError::Store)?;
        let Some(last) = blocks.last() else {
            return Err(BlockCommitError::Validation(
                BlockImportError::EmptyResponse,
            ));
        };
        let receipt = BlockImportReceipt {
            from_height: response.request.from_height,
            through_height: last.height,
            imported_blocks: blocks.len(),
            last_block_id: last.block_id.clone(),
        };
        self.verifier = proposed;
        Ok(receipt)
    }

    /// Sync imports caller-verified finality; it never creates it.
    pub const fn may_determine_finality(&self) -> bool {
        false
    }
}
