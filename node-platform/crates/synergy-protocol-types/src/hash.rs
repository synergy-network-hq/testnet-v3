//! Fixed-width hash values used as opaque protocol commitments.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProtocolHash([u8; Self::LENGTH]);

impl ProtocolHash {
    pub const LENGTH: usize = 32;
    pub const ZERO: Self = Self([0; Self::LENGTH]);

    pub const fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; Self::LENGTH] {
        self.0
    }

    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }
}

impl From<[u8; ProtocolHash::LENGTH]> for ProtocolHash {
    fn from(bytes: [u8; ProtocolHash::LENGTH]) -> Self {
        Self::new(bytes)
    }
}
