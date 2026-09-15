//! Bounded allocation policy for authenticated P2P frames.

use super::DEFAULT_MAX_FRAME_BYTES;

/// Default maximum bytes accepted for a frame authenticator.
pub const DEFAULT_MAX_AUTHENTICATOR_BYTES: usize = 16_384;

/// Invalid frame-limit configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameLimitError {
    InvalidPayloadLimit,
    InvalidAuthenticatorLimit,
}

impl std::fmt::Display for FrameLimitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPayloadLimit => formatter
                .write_str("frame payload limit must be nonzero and fit in the wire length field"),
            Self::InvalidAuthenticatorLimit => formatter.write_str(
                "frame authenticator limit must be nonzero and fit in the wire length field",
            ),
        }
    }
}

impl std::error::Error for FrameLimitError {}

/// Allocation limits applied before payload or authenticator data is copied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameLimits {
    max_payload_bytes: usize,
    max_authenticator_bytes: usize,
}

impl FrameLimits {
    /// Creates a validated set of framing limits.
    ///
    /// # Errors
    /// Returns [`FrameLimitError`] for zero or unrepresentable limits.
    pub fn new(
        max_payload_bytes: usize,
        max_authenticator_bytes: usize,
    ) -> Result<Self, FrameLimitError> {
        if max_payload_bytes == 0 || max_payload_bytes > u32::MAX as usize {
            return Err(FrameLimitError::InvalidPayloadLimit);
        }
        if max_authenticator_bytes == 0 || max_authenticator_bytes > u16::MAX as usize {
            return Err(FrameLimitError::InvalidAuthenticatorLimit);
        }
        Ok(Self {
            max_payload_bytes,
            max_authenticator_bytes,
        })
    }

    /// Maximum accepted opaque payload bytes.
    pub const fn max_payload_bytes(self) -> usize {
        self.max_payload_bytes
    }

    /// Maximum accepted authenticator bytes.
    pub const fn max_authenticator_bytes(self) -> usize {
        self.max_authenticator_bytes
    }
}

impl Default for FrameLimits {
    fn default() -> Self {
        Self {
            max_payload_bytes: DEFAULT_MAX_FRAME_BYTES,
            max_authenticator_bytes: DEFAULT_MAX_AUTHENTICATOR_BYTES,
        }
    }
}
