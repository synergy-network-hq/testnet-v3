use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::bounded;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceRule {
    pub action_kind: String,
    pub eligible_authorities: BTreeSet<String>,
    pub approval_threshold: usize,
    pub minimum_delay_blocks: u64,
    pub emergency_permitted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Constitution {
    pub version: u64,
    pub constitution_root: String,
    pub rules: BTreeMap<String, GovernanceRule>,
}

impl Constitution {
    pub fn canonical_root(&self) -> Result<String, String> {
        crate::canonical_root(
            b"SYNERGY_GOVERNANCE_CONSTITUTION_V1",
            &(self.version, &self.rules),
        )
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.version == 0
            || !bounded(&self.constitution_root, 256)
            || self.rules.is_empty()
            || self.constitution_root != self.canonical_root()?
        {
            return Err("invalid governance constitution".into());
        }
        for (kind, rule) in &self.rules {
            if kind != &rule.action_kind
                || !bounded(kind, 128)
                || rule.eligible_authorities.is_empty()
                || rule.approval_threshold == 0
                || rule.approval_threshold > rule.eligible_authorities.len()
                || rule
                    .eligible_authorities
                    .iter()
                    .any(|authority| !bounded(authority, 256))
            {
                return Err("invalid governance rule".into());
            }
        }
        Ok(())
    }

    pub fn rule(&self, action_kind: &str) -> Result<&GovernanceRule, String> {
        self.validate()?;
        self.rules
            .get(action_kind)
            .ok_or_else(|| "governance action is not constitutional".into())
    }
}
