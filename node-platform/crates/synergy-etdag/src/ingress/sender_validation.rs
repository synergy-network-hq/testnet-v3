use std::collections::{BTreeMap, BTreeSet};

use crate::EtdagError;

#[derive(Debug, Clone)]
pub struct SenderPolicy {
    keys: BTreeMap<String, BTreeSet<String>>,
}

impl SenderPolicy {
    pub fn new(keys: BTreeMap<String, BTreeSet<String>>) -> Result<Self, EtdagError> {
        if keys.is_empty()
            || keys.iter().any(|(sender, key_ids)| {
                sender.trim().is_empty()
                    || key_ids.is_empty()
                    || key_ids.iter().any(|key| key.trim().is_empty())
            })
        {
            return Err(EtdagError::Governance(
                "invalid ingress sender policy".into(),
            ));
        }
        Ok(Self { keys })
    }

    pub fn validate(&self, sender: &str, key_id: &str) -> Result<(), EtdagError> {
        if self
            .keys
            .get(sender)
            .is_some_and(|keys| keys.contains(key_id))
        {
            Ok(())
        } else {
            Err(EtdagError::UnauthorizedValidator(sender.into()))
        }
    }
}
