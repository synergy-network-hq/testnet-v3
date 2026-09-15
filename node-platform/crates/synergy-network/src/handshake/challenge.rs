//! Short-lived challenges used to prevent handshake replay.

/// Maximum accepted challenge lifetime in seconds.
pub const MAX_CHALLENGE_LIFETIME_SECS: u64 = 120;

/// Invalid or stale handshake challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeError {
    ZeroNonce,
    InvalidLifetime,
    NotYetValid,
    Expired,
}

impl std::fmt::Display for ChallengeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "invalid P2P handshake challenge: {self:?}")
    }
}

impl std::error::Error for ChallengeError {}

/// A caller-generated nonce with a narrow validity window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeChallenge {
    nonce: [u8; 32],
    issued_at: u64,
    expires_at: u64,
}

impl HandshakeChallenge {
    /// Creates a challenge from cryptographically secure caller-provided bytes.
    ///
    /// # Errors
    /// Returns [`ChallengeError`] for an all-zero nonce or invalid lifetime.
    pub fn new(
        nonce: [u8; 32],
        issued_at: u64,
        lifetime_secs: u64,
    ) -> Result<Self, ChallengeError> {
        if nonce.iter().all(|byte| *byte == 0) {
            return Err(ChallengeError::ZeroNonce);
        }
        if lifetime_secs == 0 || lifetime_secs > MAX_CHALLENGE_LIFETIME_SECS {
            return Err(ChallengeError::InvalidLifetime);
        }
        let expires_at = issued_at
            .checked_add(lifetime_secs)
            .ok_or(ChallengeError::InvalidLifetime)?;
        Ok(Self {
            nonce,
            issued_at,
            expires_at,
        })
    }

    /// Returns the challenge nonce included in the signed transcript.
    pub const fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }

    pub const fn issued_at(&self) -> u64 {
        self.issued_at
    }

    pub const fn lifetime_secs(&self) -> u64 {
        self.expires_at - self.issued_at
    }

    /// Verifies that this challenge is valid at `now`.
    ///
    /// # Errors
    /// Returns [`ChallengeError`] if `now` precedes issuance or exceeds expiry.
    pub fn validate_at(&self, now: u64) -> Result<(), ChallengeError> {
        if now < self.issued_at {
            return Err(ChallengeError::NotYetValid);
        }
        if now > self.expires_at {
            return Err(ChallengeError::Expired);
        }
        Ok(())
    }
}
