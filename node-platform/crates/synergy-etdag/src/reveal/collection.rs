use std::collections::BTreeMap;

use crate::{DecryptShareMessage, EtdagError};

#[derive(Debug, Default)]
pub struct DecryptShareCollection {
    shares: BTreeMap<String, DecryptShareMessage>,
}

impl DecryptShareCollection {
    pub fn insert(&mut self, share: DecryptShareMessage) -> Result<(), EtdagError> {
        share.validate()?;
        if self.shares.contains_key(&share.validator_id) {
            return Err(EtdagError::DuplicateShare(share.validator_id));
        }
        if self
            .shares
            .values()
            .any(|previous| previous.share_index == share.share_index)
        {
            return Err(EtdagError::UnauthorizedReveal);
        }
        self.shares.insert(share.validator_id.clone(), share);
        Ok(())
    }

    pub fn threshold_reached(&self, threshold: usize) -> bool {
        self.shares.len() >= threshold
    }

    pub fn shares(&self) -> impl Iterator<Item = &DecryptShareMessage> {
        self.shares.values()
    }
}
