use crate::{StateChunk, VerifiedSnapshot};

/// Storage boundary for the new canonical snapshot format.
pub trait CanonicalStateStore {
    type Error;

    /// Computes the canonical state root without mutating durable state.
    fn verify_state_root(&self, chunks: &[StateChunk]) -> Result<String, Self::Error>;

    /// Atomically replaces state with an already verified snapshot package.
    fn commit_verified_snapshot(&mut self, snapshot: &VerifiedSnapshot) -> Result<(), Self::Error>;
}

/// Receipt proving that a verified snapshot reached the store boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateImportReceipt {
    pub finalized_height: u64,
    pub finalized_block_id: String,
    pub state_root: String,
    pub imported_chunks: u64,
}

/// Failure before or during canonical state import.
#[derive(Debug)]
pub enum StateImportError<E> {
    StateRoot(E),
    StateRootMismatch { expected: String, computed: String },
    Commit(E),
}

/// Imports only a complete [`VerifiedSnapshot`] and never performs legacy conversion.
#[derive(Debug, Clone, Copy, Default)]
pub struct VerifiedStateImporter;

impl VerifiedStateImporter {
    /// Recomputes the application state root before committing the snapshot.
    ///
    /// # Errors
    /// Returns a typed store failure or a state-root mismatch before mutation.
    pub fn import<S: CanonicalStateStore>(
        &self,
        snapshot: &VerifiedSnapshot,
        store: &mut S,
    ) -> Result<StateImportReceipt, StateImportError<S::Error>> {
        let computed = store
            .verify_state_root(snapshot.chunks())
            .map_err(StateImportError::StateRoot)?;
        if computed != snapshot.checkpoint().state_root {
            return Err(StateImportError::StateRootMismatch {
                expected: snapshot.checkpoint().state_root.clone(),
                computed,
            });
        }
        store
            .commit_verified_snapshot(snapshot)
            .map_err(StateImportError::Commit)?;
        Ok(StateImportReceipt {
            finalized_height: snapshot.checkpoint().finalized_height,
            finalized_block_id: snapshot.checkpoint().finalized_block_id.clone(),
            state_root: snapshot.checkpoint().state_root.clone(),
            imported_chunks: snapshot.checkpoint().chunk_count,
        })
    }

    /// State import consumes verified finality and never grants authority.
    pub const fn may_determine_finality(&self) -> bool {
        false
    }
}
