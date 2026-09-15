//! Governed cryptographic identity bindings; these authenticate nodes only.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use synergy_protocol_types::NodeAddress;

use crate::{KeyId, SignatureAlgorithm};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernedNodeKeyBinding {
    #[serde(alias = "node_id")]
    pub node_address: NodeAddress,
    pub key_id: KeyId,
    pub algorithm: SignatureAlgorithm,
    pub public_key: Vec<u8>,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

impl GovernedNodeKeyBinding {
    pub fn validate(&self) -> Result<(), BindingError> {
        if self.public_key.is_empty() || KeyId::new(self.key_id.as_str().to_string()).is_err() {
            return Err(BindingError::InvalidBinding);
        }
        Ok(())
    }
}

/// Immutable node-address to public-verification-material mapping. It carries
/// no validator membership, quorum, role, VPN, or routing authority.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernedKeyBindings {
    bindings: BTreeMap<NodeAddress, GovernedNodeKeyBinding>,
}

impl GovernedKeyBindings {
    pub fn new(entries: Vec<GovernedNodeKeyBinding>) -> Result<Self, BindingError> {
        let mut bindings = BTreeMap::new();
        for entry in entries {
            entry.validate()?;
            if bindings.insert(entry.node_address.clone(), entry).is_some() {
                return Err(BindingError::DuplicateNode);
            }
        }
        Ok(Self { bindings })
    }

    pub fn validate(&self) -> Result<(), BindingError> {
        for (node_address, binding) in &self.bindings {
            binding.validate()?;
            if node_address != &binding.node_address {
                return Err(BindingError::InvalidBinding);
            }
        }
        Ok(())
    }

    pub fn get(&self, node_address: &str) -> Option<&GovernedNodeKeyBinding> {
        self.bindings.get(node_address)
    }

    pub fn entries(&self) -> impl Iterator<Item = &GovernedNodeKeyBinding> {
        self.bindings.values()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingError {
    InvalidBinding,
    DuplicateNode,
}

impl std::fmt::Display for BindingError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for BindingError {}
