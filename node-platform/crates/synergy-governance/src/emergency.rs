use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{bounded, Constitution};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmergencyAuthorization {
    pub action_kind: String,
    pub payload_root: String,
    pub approving_authorities: BTreeSet<String>,
    pub expires_at_height: u64,
    pub authorization_root: String,
}

impl EmergencyAuthorization {
    pub fn validate(&self, constitution: &Constitution, current_height: u64) -> Result<(), String> {
        let rule = constitution.rule(&self.action_kind)?;
        let eligible = self
            .approving_authorities
            .iter()
            .filter(|authority| rule.eligible_authorities.contains(*authority))
            .count();
        if !rule.emergency_permitted
            || !bounded(&self.payload_root, 256)
            || !bounded(&self.authorization_root, 256)
            || self.expires_at_height <= current_height
            || eligible < rule.approval_threshold
        {
            return Err("invalid or unauthorized emergency governance action".into());
        }
        Ok(())
    }
}
