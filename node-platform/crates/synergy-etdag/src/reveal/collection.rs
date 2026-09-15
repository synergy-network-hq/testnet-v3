use std::collections::BTreeMap;

use crate::{DecryptShareMessage, EtdagError};

#[derive(Debug, Default)]
pub struct DecryptShareCollection {
    shares: BTreeMap<String, DecryptShareMessage>,
}

impl DecryptShareCollection {
    pub fn insert(&mut self, share: DecryptShareMessage) -> Result<(), EtdagError> {
        share.validate()?;
        if self
            .shares
            .insert(share.validator_id.clone(), share)
            .is_some()
        {
            return Err(EtdagError::DuplicateShare("validator".into()));
        }
        Ok(())
    }

    pub fn threshold_reached(&self, threshold: usize) -> bool {
        self.shares.len() >= threshold
    }

    pub fn shares(&self) -> impl Iterator<Item = &DecryptShareMessage> {
        self.shares.values()
    }
}
