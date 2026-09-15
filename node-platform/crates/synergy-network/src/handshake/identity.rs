//! Canonical transport binding for a Synergy node address and advertised capabilities.

use std::collections::BTreeSet;

use synergy_protocol_types::{NodeAddress, NodeRole};

const MAX_CAPABILITIES: usize = 32;
const MAX_CAPABILITY_BYTES: usize = 64;

/// Invalid transport identity input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityError {
    InvalidNodeAddress,
    TooManyCapabilities,
    InvalidCapability,
    DuplicateCapability,
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "invalid P2P transport binding: {self:?}")
    }
}

impl std::error::Error for IdentityError {}

/// Authenticated transport metadata bound to the canonical node address.
/// Role and capabilities grant no authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportIdentity {
    node_address: NodeAddress,
    role: NodeRole,
    capabilities: Vec<String>,
}

impl TransportIdentity {
    /// Validates and canonicalizes a node address and advertised capabilities.
    ///
    /// # Errors
    /// Returns [`IdentityError`] for a malformed address or capability set.
    pub fn new(
        node_address: &str,
        role: NodeRole,
        capabilities: &[String],
    ) -> Result<Self, IdentityError> {
        let node_address =
            NodeAddress::parse(node_address).map_err(|_| IdentityError::InvalidNodeAddress)?;
        if capabilities.len() > MAX_CAPABILITIES {
            return Err(IdentityError::TooManyCapabilities);
        }
        let mut canonical = BTreeSet::new();
        for capability in capabilities {
            let capability = capability.trim();
            if capability.is_empty()
                || capability.len() > MAX_CAPABILITY_BYTES
                || !capability.bytes().all(valid_capability_byte)
            {
                return Err(IdentityError::InvalidCapability);
            }
            if !canonical.insert(capability.to_string()) {
                return Err(IdentityError::DuplicateCapability);
            }
        }
        Ok(Self {
            node_address,
            role,
            capabilities: canonical.into_iter().collect(),
        })
    }

    /// Canonical node address authenticated by this transport session.
    pub fn node_address(&self) -> &NodeAddress {
        &self.node_address
    }

    /// Advertised runtime role; this value does not prove PoSy membership.
    pub const fn role(&self) -> NodeRole {
        self.role
    }

    /// Canonical sorted protocol capabilities.
    pub fn capabilities(&self) -> &[String] {
        &self.capabilities
    }

    /// Transport metadata never determines PoSy finality.
    pub const fn may_determine_finality(&self) -> bool {
        false
    }
}

fn valid_capability_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/')
}
