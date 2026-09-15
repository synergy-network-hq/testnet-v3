//! Operational cluster identity; never a validator-set or quorum boundary.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ClusterId(String);

impl ClusterId {
    pub const MAX_LENGTH: usize = 64;

    pub fn new(value: impl Into<String>) -> Result<Self, ClusterIdError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ClusterIdError::Empty);
        }
        if value.len() > Self::MAX_LENGTH {
            return Err(ClusterIdError::TooLong);
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(ClusterIdError::InvalidCharacter);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub const fn may_determine_authority(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterIdError {
    Empty,
    TooLong,
    InvalidCharacter,
}

impl std::fmt::Display for ClusterIdError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => formatter.write_str("cluster id must not be empty"),
            Self::TooLong => formatter.write_str("cluster id is too long"),
            Self::InvalidCharacter => {
                formatter.write_str("cluster id must use lowercase ASCII, digits, and hyphens")
            }
        }
    }
}

impl std::error::Error for ClusterIdError {}
