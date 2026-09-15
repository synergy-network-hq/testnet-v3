use std::{borrow::Borrow, fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::normalize_node_id;

/// A canonical, normalized human-readable Synergy node alias.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(String);

impl NodeId {
    /// Normalizes and validates a name ending in .node.
    ///
    /// # Errors
    /// Returns NodeIdError when the suffix, label length, or label alphabet is
    /// invalid.
    pub fn parse(value: &str) -> Result<Self, NodeIdError> {
        normalize_node_id(value).map(Self)
    }

    /// Returns the canonical lowercase alias.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl AsRef<str> for NodeId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for NodeId {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl FromStr for NodeId {
    type Err = NodeIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl TryFrom<&str> for NodeId {
    type Error = NodeIdError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl Serialize for NodeId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for NodeId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

/// Canonical NodeID validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeIdError {
    Empty,
    InvalidSuffix,
    InvalidLabelLength,
    InvalidCharacter,
    InvalidHyphen,
}

impl fmt::Display for NodeIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Empty => "NodeID is empty",
            Self::InvalidSuffix => "NodeID must end in .node",
            Self::InvalidLabelLength => "NodeID label must contain 3 through 63 characters",
            Self::InvalidCharacter => {
                "NodeID label may contain only ASCII letters, digits, and hyphens"
            }
            Self::InvalidHyphen => "NodeID label cannot begin or end with a hyphen",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for NodeIdError {}
