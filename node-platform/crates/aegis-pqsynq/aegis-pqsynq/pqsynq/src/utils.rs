//! Utility functions for PQSynQ

use crate::error::PqcError;
use alloc::string::String;
#[cfg(feature = "std")]
use alloc::vec;
use alloc::vec::Vec;
use zeroize::Zeroize;

/// Convert bytes to hex string
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Convert hex string to bytes
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, PqcError> {
    hex::decode(hex).map_err(|_| PqcError::InvalidKeySize)
}

/// Check if a buffer has the correct size
pub fn check_buffer_size(buffer: &[u8], expected_size: usize) -> Result<(), PqcError> {
    if buffer.len() != expected_size {
        return Err(PqcError::InvalidKeySize);
    }
    Ok(())
}

/// Check if a buffer is large enough
pub fn check_buffer_min_size(buffer: &[u8], min_size: usize) -> Result<(), PqcError> {
    if buffer.len() < min_size {
        return Err(PqcError::BufferTooSmall);
    }
    Ok(())
}

/// Generate random bytes using cryptographically secure random number generator
#[cfg(feature = "std")]
pub fn random_bytes(size: usize) -> Result<Vec<u8>, PqcError> {
    use getrandom::getrandom;

    let mut bytes = vec![0u8; size];
    getrandom(&mut bytes).map_err(|_| PqcError::InternalError)?;
    Ok(bytes)
}

#[cfg(not(feature = "std"))]
pub fn random_bytes(_size: usize) -> Result<Vec<u8>, PqcError> {
    Err(PqcError::InternalError)
}

/// Compare two byte slices in constant time
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Copy bytes with bounds checking
pub fn safe_copy(dst: &mut [u8], src: &[u8]) -> Result<(), PqcError> {
    if src.len() > dst.len() {
        return Err(PqcError::BufferTooSmall);
    }
    dst[..src.len()].copy_from_slice(src);
    Ok(())
}

/// Zeroize sensitive bytes in place.
pub fn zeroize_bytes(bytes: &mut [u8]) {
    bytes.zeroize();
}

/// Owned secret bytes that automatically zeroize on drop.
pub struct SecretBytes {
    inner: Vec<u8>,
}

impl SecretBytes {
    /// Create zeroizing secret bytes from an owned buffer.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { inner: bytes }
    }

    /// View secret bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    /// Mutable view for in-place cryptographic operations.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.inner
    }

    /// Byte length of the secret buffer.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the secret buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Move bytes out, leaving an empty zeroizing wrapper.
    pub fn into_vec(mut self) -> Vec<u8> {
        let mut out = Vec::new();
        core::mem::swap(&mut self.inner, &mut out);
        out
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(value: Vec<u8>) -> Self {
        Self::new(value)
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}
