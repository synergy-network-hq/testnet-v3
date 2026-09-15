use serde::{Deserialize, Serialize};

use crate::NodeAddress;

/// Public cryptographic material bound to one canonical node address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicNodeIdentity {
    #[serde(alias = "node_id")]
    pub node_address: NodeAddress,
    pub public_key_fingerprint: String,
    #[serde(default, rename = "validator_address", skip_serializing)]
    legacy_validator_address: Option<String>,
}

impl PublicNodeIdentity {
    /// Creates a public identity without any parallel validator identity.
    pub fn new(node_address: NodeAddress, public_key_fingerprint: String) -> Self {
        Self {
            node_address,
            public_key_fingerprint,
            legacy_validator_address: None,
        }
    }

    pub(crate) fn legacy_validator_address(&self) -> Option<&str> {
        self.legacy_validator_address.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    EmptyNodeAddress,
    InvalidNodeAddress,
    InvalidPossessionProof,
    ConflictingIdentity,
    DuplicateKeyBinding,
    InvalidRotation,
    InvalidFingerprint,
    InvalidValidatorAddress,
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "invalid public node identity: {self:?}")
    }
}

impl std::error::Error for IdentityError {}
