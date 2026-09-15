use std::collections::BTreeSet;

use crate::{DecryptShareMessage, EtdagDigest, EtdagError, ProtectedRevealAuthorization};

use super::reveal_store::DurableRevealState;

/// Restart data that remains untrusted until every signed share is verified
/// again against the current governed key registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredRevealState {
    authorization: Option<ProtectedRevealAuthorization>,
    signed_shares: Vec<DecryptShareMessage>,
}

impl RecoveredRevealState {
    pub(crate) fn from_durable(
        durable: &DurableRevealState,
        expected_context_root: &EtdagDigest,
        expected_target_height: u64,
        expected_batch_root: &EtdagDigest,
        expected_envelope_id: &EtdagDigest,
    ) -> Result<Self, EtdagError> {
        durable.context_root.validate()?;
        durable.protected_batch_root.validate()?;
        durable.envelope_id.validate()?;
        if durable.format_version != 1
            || &durable.context_root != expected_context_root
            || durable.target_height != expected_target_height
            || &durable.protected_batch_root != expected_batch_root
            || &durable.envelope_id != expected_envelope_id
        {
            return Err(EtdagError::ContextMismatch);
        }

        if let Some(authorization) = &durable.authorization {
            authorization.validate()?;
            if authorization.context_root != durable.context_root
                || authorization.target_height != durable.target_height
                || authorization.protected_batch_root != durable.protected_batch_root
            {
                return Err(EtdagError::UnauthorizedReveal);
            }
        } else if !durable.signed_shares.is_empty() {
            return Err(EtdagError::Corrupt(
                "reveal shares persisted without authorization".into(),
            ));
        }

        let mut validators = BTreeSet::new();
        for share in &durable.signed_shares {
            share.validate()?;
            if Some(&share.authorization) != durable.authorization.as_ref()
                || share.envelope_id != durable.envelope_id
                || !validators.insert(&share.validator_id)
            {
                return Err(EtdagError::Corrupt(
                    "invalid durable reveal share set".into(),
                ));
            }
        }

        Ok(Self {
            authorization: durable.authorization.clone(),
            signed_shares: durable.signed_shares.clone(),
        })
    }

    /// Returns the finality-bound authorization recovered for this slot.
    pub fn authorization(&self) -> Option<&ProtectedRevealAuthorization> {
        self.authorization.as_ref()
    }

    /// Returns signed messages that callers must cryptographically reverify.
    pub fn signed_shares(&self) -> &[DecryptShareMessage] {
        &self.signed_shares
    }
}
