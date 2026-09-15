//! Bounded version descriptor for protocol serialization layers.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WireVersion(u16);

impl WireVersion {
    pub const V1: Self = Self(1);

    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameDescriptor {
    pub version: WireVersion,
    pub payload_length: u32,
}

impl FrameDescriptor {
    pub fn new(
        version: WireVersion,
        payload_length: usize,
        maximum_payload_length: usize,
    ) -> Result<Self, FrameDescriptorError> {
        if version.get() == 0 {
            return Err(FrameDescriptorError::UnsupportedVersion(0));
        }
        if payload_length > maximum_payload_length {
            return Err(FrameDescriptorError::PayloadTooLarge {
                actual: payload_length,
                maximum: maximum_payload_length,
            });
        }
        let payload_length = u32::try_from(payload_length)
            .map_err(|_| FrameDescriptorError::PayloadLengthOverflow)?;
        Ok(Self {
            version,
            payload_length,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameDescriptorError {
    UnsupportedVersion(u16),
    PayloadTooLarge { actual: usize, maximum: usize },
    PayloadLengthOverflow,
}

impl std::fmt::Display for FrameDescriptorError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported wire version {version}")
            }
            Self::PayloadTooLarge { actual, maximum } => {
                write!(formatter, "payload length {actual} exceeds {maximum}")
            }
            Self::PayloadLengthOverflow => {
                formatter.write_str("payload length cannot fit in the wire descriptor")
            }
        }
    }
}

impl std::error::Error for FrameDescriptorError {}
