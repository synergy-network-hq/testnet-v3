//! Canonical Synergy node-address identity.
//!
//! A [`NodeAddress`] is the only protocol identity for a Synergy node. Human-
//! readable `<name>.node` NodeIDs resolve to this address and are never used
//! directly for authorization. Presentation parsing authenticates no network,
//! birth policy, possession, current role, release or PoSy authority.

use std::borrow::Borrow;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use synergy_address::r1_public::NativeIdentityPresentation;

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
    /// Parses exact full-width R1 syntax for the independently selected node class.
    /// This verifies presentation only, not birth derivation, network incarnation,
    /// possession, current role authority, or profile activation.
    pub fn parse_current(
        value: impl Into<String>,
        expected_class: NodeClass,
    ) -> Result<Self, NodeAddressError> {
        let parsed = Self::parse_current_presentation(value.into())?;
        if parsed.class != expected_class {
            return Err(NodeAddressError::InvalidClass);
        }
        Ok(parsed)
    }

    fn parse_current_presentation(value: String) -> Result<Self, NodeAddressError> {
        let parsed = NativeIdentityPresentation::parse(&value)
            .map_err(|_| NodeAddressError::InvalidCurrentEncoding)?;
        let class = match parsed.namespace() {
            "synv1" => NodeClass::ConsensusAndChainIntegrity,
            "synv2" => NodeClass::Interoperability,
            "synv3" => NodeClass::ExecutionDataAndCryptography,
            "synv4" => NodeClass::AiAndIntelligence,
            "synv5" => NodeClass::ServiceAndAccess,
            _ => return Err(NodeAddressError::InvalidPrefix),
        };
        Ok(Self { value, class })
    }

    /// Recognizes either exact supported presentation without converting it.
    /// The profile and namespace are syntax only; current callers independently
    /// authenticate the network and bind the selected role/class through policy.
    pub fn parse(value: impl Into<String>) -> Result<Self, NodeAddressError> {
        let value = value.into();
        if value.contains('.') {
            Self::parse_current_presentation(value)
        } else {
            Self::parse_historical(value)
        }
    }

    /// Parses the historical SNTS-01 node presentation for historical consumers.
    ///
    /// # Errors
    /// Returns [`NodeAddressError`] when the prefix, class, length, or address
    /// alphabet is invalid.
    pub fn parse_historical(value: impl Into<String>) -> Result<Self, NodeAddressError> {
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
    InvalidCurrentEncoding,
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
            Self::InvalidCurrentEncoding => {
                "node address must use the exact full-width R1 presentation"
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
    use super::{NodeAddress, NodeAddressError, NodeClass};

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

    #[test]
    fn current_profile_preserves_all_five_classes_and_complete_text() {
        for digit in 1..=5 {
            let class = NodeClass::try_from(digit).unwrap();
            let text = format!("synv{digit}.2.{}", "A".repeat(64));
            let parsed = NodeAddress::parse_current(&text, class).unwrap();
            assert_eq!(parsed.class(), class);
            assert_eq!(parsed.as_str(), text);
            assert_eq!(parsed.as_str().len(), 72);
            assert!(NodeAddress::parse_historical(text).is_err());
        }
    }

    #[test]
    fn current_profile_payload_case_is_preserved_and_significant() {
        let upper = format!("synv1.2.{}", "A".repeat(64));
        let lower = format!("synv1.2.{}", "a".repeat(64));
        let class = NodeClass::ConsensusAndChainIntegrity;
        let a = NodeAddress::parse_current(&upper, class).unwrap();
        let b = NodeAddress::parse_current(&lower, class).unwrap();
        assert_ne!(a, b);
        assert_eq!(a.as_str(), upper);
        assert_eq!(b.as_str(), lower);
    }

    #[test]
    fn current_profile_requires_selected_class_and_node_family() {
        let sentry = format!("synv1.2.{}", "A".repeat(64));
        assert_eq!(
            NodeAddress::parse_current(sentry, NodeClass::ServiceAndAccess),
            Err(NodeAddressError::InvalidClass)
        );
        let wallet = format!("synw.2.{}", "A".repeat(64));
        assert_eq!(
            NodeAddress::parse_current(wallet, NodeClass::ServiceAndAccess),
            Err(NodeAddressError::InvalidPrefix)
        );
    }

    #[test]
    fn current_profile_rejects_historical_and_noncanonical_presentations() {
        let class = NodeClass::ConsensusAndChainIntegrity;
        let text = format!("synv1.2.{}", "A".repeat(64));
        for value in [
            "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn".to_owned(),
            text.replace("synv1", "SYNV1"),
            text.replace("synv1", "synv6"),
            text.replace(".2.", ".3."),
            format!("{text}="),
            format!(" {text}"),
            format!("{text}\n"),
            text[..71].to_owned(),
        ] {
            assert!(NodeAddress::parse_current(value, class).is_err());
        }
        assert!(NodeAddress::parse("synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn").is_ok());
    }
}
