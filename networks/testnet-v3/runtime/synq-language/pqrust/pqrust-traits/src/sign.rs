use crate::Result;

pub trait PublicKey {
    fn as_bytes(&self) -> &[u8];
    fn from_bytes(bytes: &[u8]) -> Result<Self>
    where
        Self: Sized;
}

pub trait SecretKey {
    fn as_bytes(&self) -> &[u8];
    fn from_bytes(bytes: &[u8]) -> Result<Self>
    where
        Self: Sized;
}

pub trait SignedMessage {
    fn as_bytes(&self) -> &[u8];
    fn from_bytes(bytes: &[u8]) -> Result<Self>
    where
        Self: Sized;
}

pub trait DetachedSignature {
    fn as_bytes(&self) -> &[u8];
    fn from_bytes(bytes: &[u8]) -> Result<Self>
    where
        Self: Sized;
}

#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum VerificationError {
    InvalidSignature,
    UnknownVerificationError,
}

impl core::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::result::Result<(), core::fmt::Error> {
        match self {
            VerificationError::InvalidSignature => write!(f, "error: verification failed"),
            VerificationError::UnknownVerificationError => write!(f, "unknown error"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for VerificationError {}
