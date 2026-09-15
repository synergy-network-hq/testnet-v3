//! Validator identity only. Active authority is resolved exclusively by PoSy.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ValidatorId(String);

impl ValidatorId {
    pub const MAX_LENGTH: usize = 128;

    pub fn new(value: impl Into<String>) -> Result<Self, ValidatorIdError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ValidatorIdError::Empty);
        }
        if value.len() > Self::MAX_LENGTH {
            return Err(ValidatorIdError::TooLong {
                actual: value.len(),
                maximum: Self::MAX_LENGTH,
            });
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(ValidatorIdError::InvalidCharacter);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatorIdError {
    Empty,
    TooLong { actual: usize, maximum: usize },
    InvalidCharacter,
}

impl std::fmt::Display for ValidatorIdError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => formatter.write_str("validator id must not be empty"),
            Self::TooLong { actual, maximum } => {
                write!(formatter, "validator id length {actual} exceeds {maximum}")
            }
            Self::InvalidCharacter => {
                formatter.write_str("validator id contains an invalid character")
            }
        }
    }
}

impl std::error::Error for ValidatorIdError {}
