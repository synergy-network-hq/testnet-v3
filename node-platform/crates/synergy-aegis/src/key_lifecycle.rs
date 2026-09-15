//! Key identity and fail-closed lifecycle transitions without private material.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyId(String);

impl KeyId {
    pub const MAX_LENGTH: usize = 128;

    pub fn new(value: impl Into<String>) -> Result<Self, KeyIdError> {
        let value = value.into();
        if value.is_empty() {
            return Err(KeyIdError::Empty);
        }
        if value.len() > Self::MAX_LENGTH {
            return Err(KeyIdError::TooLong);
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'/'))
        {
            return Err(KeyIdError::InvalidCharacter);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyPurpose {
    NodeIdentity,
    P2pIdentity,
    PosyConsensus,
    EtdagDecryption,
    Manifest,
    Snapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyState {
    Generated,
    Active,
    Retiring,
    Retired,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRecord {
    pub id: KeyId,
    pub purpose: KeyPurpose,
    pub state: KeyState,
    pub public_key: Vec<u8>,
}

impl KeyRecord {
    pub fn transition(&mut self, next: KeyState) -> Result<(), KeyTransitionError> {
        let permitted = matches!(
            (self.state, next),
            (KeyState::Generated, KeyState::Active)
                | (KeyState::Generated, KeyState::Revoked)
                | (KeyState::Active, KeyState::Retiring)
                | (KeyState::Active, KeyState::Revoked)
                | (KeyState::Retiring, KeyState::Retired)
                | (KeyState::Retiring, KeyState::Revoked)
        );
        if !permitted {
            return Err(KeyTransitionError {
                current: self.state,
                requested: next,
            });
        }
        self.state = next;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyIdError {
    Empty,
    TooLong,
    InvalidCharacter,
}

impl std::fmt::Display for KeyIdError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "invalid Aegis key id: {self:?}")
    }
}

impl std::error::Error for KeyIdError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyTransitionError {
    pub current: KeyState,
    pub requested: KeyState,
}

impl std::fmt::Display for KeyTransitionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "key transition {:?} -> {:?} is not permitted",
            self.current, self.requested
        )
    }
}

impl std::error::Error for KeyTransitionError {}
