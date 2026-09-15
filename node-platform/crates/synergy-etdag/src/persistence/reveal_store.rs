use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::{
    reveal::VerifiedDecryptShare, DecryptShareMessage, EtdagDigest, EtdagError,
    ProtectedRevealAuthorization,
};

use super::recovery::RecoveredRevealState;

const REVEAL_STATE_PATH: &str = "reveal/state-v1.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DurableRevealState {
    pub(crate) format_version: u32,
    pub(crate) context_root: EtdagDigest,
    pub(crate) target_height: u64,
    pub(crate) protected_batch_root: EtdagDigest,
    pub(crate) envelope_id: EtdagDigest,
    pub(crate) authorization: Option<ProtectedRevealAuthorization>,
    pub(crate) signed_shares: Vec<DecryptShareMessage>,
}

/// Atomic store for finality authorization and signed reveal shares.
///
/// Plaintext and decrypted execution input are deliberately never persisted.
#[derive(Debug)]
pub struct PersistentRevealStore {
    store: synergy_storage::AtomicStore,
    state: DurableRevealState,
}

impl PersistentRevealStore {
    /// Opens one context-, height-, batch-, and envelope-bound reveal slot.
    pub fn open(
        root: impl AsRef<Path>,
        context_root: EtdagDigest,
        target_height: u64,
        protected_batch_root: EtdagDigest,
        envelope_id: EtdagDigest,
        max_record_bytes: usize,
    ) -> Result<Self, EtdagError> {
        context_root.validate()?;
        protected_batch_root.validate()?;
        envelope_id.validate()?;
        if target_height == 0 || max_record_bytes == 0 {
            return Err(EtdagError::InvalidCapacity);
        }
        let store = synergy_storage::AtomicStore::new(root.as_ref(), max_record_bytes)
            .map_err(storage_error)?;
        let state = if store.exists(REVEAL_STATE_PATH).map_err(storage_error)? {
            let bytes = store
                .read_bounded(REVEAL_STATE_PATH)
                .map_err(storage_error)?;
            let durable = serde_json::from_slice::<DurableRevealState>(&bytes)
                .map_err(|error| EtdagError::Corrupt(error.to_string()))?;
            RecoveredRevealState::from_durable(
                &durable,
                &context_root,
                target_height,
                &protected_batch_root,
                &envelope_id,
            )?;
            durable
        } else {
            DurableRevealState {
                format_version: 1,
                context_root,
                target_height,
                protected_batch_root,
                envelope_id,
                authorization: None,
                signed_shares: Vec::new(),
            }
        };
        Ok(Self { store, state })
    }

    /// Persists the finality-bound reveal authorization idempotently.
    pub fn authorize(
        &mut self,
        authorization: ProtectedRevealAuthorization,
    ) -> Result<(), EtdagError> {
        authorization.validate()?;
        if authorization.context_root != self.state.context_root
            || authorization.target_height != self.state.target_height
            || authorization.protected_batch_root != self.state.protected_batch_root
        {
            return Err(EtdagError::UnauthorizedReveal);
        }
        if self.state.authorization.as_ref() == Some(&authorization) {
            return Ok(());
        }
        if self.state.authorization.is_some() {
            return Err(EtdagError::ConflictingArtifact(
                "reveal authorization".into(),
            ));
        }
        let mut next = self.state.clone();
        next.authorization = Some(authorization);
        self.persist(&next)?;
        self.state = next;
        Ok(())
    }

    /// Persists only a share that already crossed cryptographic verification.
    pub fn record_verified_share(
        &mut self,
        share: &VerifiedDecryptShare,
    ) -> Result<(), EtdagError> {
        if self.state.authorization.as_ref() != Some(share.authorization())
            || &self.state.envelope_id != share.envelope_id()
        {
            return Err(EtdagError::UnauthorizedReveal);
        }
        if let Some(existing) = self
            .state
            .signed_shares
            .iter()
            .find(|existing| existing.validator_id == share.validator_id())
        {
            return if existing == share.message() {
                Ok(())
            } else {
                Err(EtdagError::ConflictingArtifact(
                    "validator reveal share".into(),
                ))
            };
        }
        let mut next = self.state.clone();
        next.signed_shares.push(share.message().clone());
        next.signed_shares
            .sort_by(|left, right| left.validator_id.cmp(&right.validator_id));
        self.persist(&next)?;
        self.state = next;
        Ok(())
    }

    /// Returns restart data whose signatures must be verified again by callers.
    pub fn recovered_state(&self) -> Result<RecoveredRevealState, EtdagError> {
        RecoveredRevealState::from_durable(
            &self.state,
            &self.state.context_root,
            self.state.target_height,
            &self.state.protected_batch_root,
            &self.state.envelope_id,
        )
    }

    fn persist(&self, state: &DurableRevealState) -> Result<(), EtdagError> {
        let bytes =
            serde_json::to_vec(state).map_err(|error| EtdagError::Corrupt(error.to_string()))?;
        self.store
            .write_atomic(REVEAL_STATE_PATH, &bytes)
            .map_err(storage_error)
    }
}

fn storage_error(error: synergy_storage::StorageError) -> EtdagError {
    EtdagError::Storage(error.to_string())
}
