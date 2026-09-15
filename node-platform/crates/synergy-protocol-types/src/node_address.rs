//! Canonical Synergy node-address identity.
//!
//! A [`NodeAddress`] is the only protocol identity for a Synergy node. Human-
//! readable `<name>.node` NodeIDs resolve to this address and are never used
//! directly for authorization.

use std::borrow::Borrow;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

const PREFIX: &str = "synv";
const CANONICAL_LENGTH: usize = 41;

/// The architectural class encoded immediately after the `synv` prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum NodeClass {
    ConsensusAndChainIntegrity = 1,
    Interoperability = 2,
    ExecutionDataAndCryptography = 3,
    AiAndIntelligence = 4,
    ServiceAndAccess = 5,
}

impl NodeClass {
    /// Returns the digit encoded in a canonical node address.
    pub const fn digit(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for NodeClass {
    type Error = NodeAddressError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::ConsensusAndChainIntegrity),
            2 => Ok(Self::Interoperability),
            3 => Ok(Self::ExecutionDataAndCryptography),
            4 => Ok(Self::AiAndIntelligence),
            5 => Ok(Self::ServiceAndAccess),
            _ => Err(NodeAddressError::InvalidClass),
        }
    }
}

/// The single canonical `synv<class>...` protocol identity of a node.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeAddress {
    value: String,
    class: NodeClass,
}

impl NodeAddress {
    /// Parses and validates a canonical Synergy node address.
    ///
    /// # Errors
    /// Returns [`NodeAddressError`] when the prefix, class, length, or address
    /// alphabet is invalid.
    pub fn parse(value: impl Into<String>) -> Result<Self, NodeAddressError> {
        let value = value.into();
        if value.len() != CANONICAL_LENGTH {
            return Err(NodeAddressError::InvalidLength);
        }
        let bytes = value.as_bytes();
        if !bytes.starts_with(PREFIX.as_bytes()) {
            return Err(NodeAddressError::InvalidPrefix);
        }
        let class = NodeClass::try_from(bytes[4].saturating_sub(b'0'))?;
        if !bytes[5..]
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        {
            return Err(NodeAddressError::InvalidCharacter);
        }
        let decoded = synergy_address::decode_address(&value)
            .map_err(|_| NodeAddressError::InvalidEncoding)?;
        if decoded.hrp != format!("{PREFIX}{}", class.digit())
            || synergy_address::address_kind(&value) != synergy_address::AddressKind::Validator
        {
            return Err(NodeAddressError::InvalidEncoding);
        }
        Ok(Self { value, class })
    }

    /// Returns the exact canonical address string.
    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// Returns the node class encoded by this validated address.
    pub fn class(&self) -> NodeClass {
        self.class
    }
}

impl fmt::Display for NodeAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl AsRef<str> for NodeAddress {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for NodeAddress {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl FromStr for NodeAddress {
    type Err = NodeAddressError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl TryFrom<String> for NodeAddress {
    type Error = NodeAddressError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl TryFrom<&str> for NodeAddress {
    type Error = NodeAddressError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl Serialize for NodeAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for NodeAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

/// Canonical node-address validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeAddressError {
    InvalidLength,
    InvalidPrefix,
    InvalidClass,
    InvalidCharacter,
    InvalidEncoding,
}

impl fmt::Display for NodeAddressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidLength => "node address length is outside the canonical range",
            Self::InvalidPrefix => "node address must begin with synv",
            Self::InvalidClass => "node address class must be one of 1 through 5",
            Self::InvalidCharacter => {
                "node address remainder must contain only lowercase ASCII letters and digits"
            }
            Self::InvalidEncoding => {
                "node address must be a canonical SNTS-01 Bech32m validator address"
            }
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for NodeAddressError {}

#[cfg(test)]
mod tests {
    use super::{NodeAddress, NodeClass};

    #[test]
    fn parses_each_canonical_node_class() {
        for (value, expected) in [
            (
                "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn",
                NodeClass::ConsensusAndChainIntegrity,
            ),
            (
                "synv21lrh6jcxaejkj4zv994j7qwn2rk6u3zat22n",
                NodeClass::Interoperability,
            ),
            (
                "synv31lrh6jcxaejkj4zv994j7qwn2rk6u3shpu9n",
                NodeClass::ExecutionDataAndCryptography,
            ),
            (
                "synv41lrh6jcxaejkj4zv994j7qwn2rk6u34g79pn",
                NodeClass::AiAndIntelligence,
            ),
            (
                "synv51lrh6jcxaejkj4zv994j7qwn2rk6u38z5nwn",
                NodeClass::ServiceAndAccess,
            ),
        ] {
            assert_eq!(NodeAddress::parse(value).unwrap().class(), expected);
        }
    }

    #[test]
    fn refuses_legacy_or_out_of_range_identity_prefixes() {
        for value in [
            "syn1validator0001",
            "synv0validator0001",
            "synv6validator0001",
            "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emq",
        ] {
            assert!(NodeAddress::parse(value).is_err(), "accepted {value}");
        }
    }
}
