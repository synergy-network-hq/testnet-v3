use crate::{DecryptShareMessage, EtdagDigest};

use super::authorization::ProtectedRevealAuthorization;

/// A decrypt share whose validator membership, context binding, and signature
/// were checked by [`crate::reveal::verify_decrypt_share`].
///
/// Construction is crate-private so callers cannot promote an untrusted
/// network message into a verified share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDecryptShare {
    message: DecryptShareMessage,
}

impl VerifiedDecryptShare {
    pub(crate) fn new(message: DecryptShareMessage) -> Self {
        Self { message }
    }

    /// Returns the finality-bound authorization carried by this share.
    pub fn authorization(&self) -> &ProtectedRevealAuthorization {
        &self.message.authorization
    }

    /// Returns the protected envelope this share can help decrypt.
    pub fn envelope_id(&self) -> &EtdagDigest {
        &self.message.envelope_id
    }

    /// Returns the governed validator identity that produced the share.
    pub fn validator_id(&self) -> &str {
        &self.message.validator_id
    }

    /// Returns the governed consensus key identity used to sign the share.
    pub fn key_id(&self) -> &str {
        &self.message.key_id
    }

    /// Returns the opaque threshold-decryption share bytes.
    pub fn encrypted_share(&self) -> &[u8] {
        &self.message.encrypted_share
    }

    pub(crate) fn message(&self) -> &DecryptShareMessage {
        &self.message
    }
}
