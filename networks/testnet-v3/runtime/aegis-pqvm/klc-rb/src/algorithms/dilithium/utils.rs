//! Utility functions for mldsa operations.

use pqrust_mldsa::mldsa87::{public_key_bytes, secret_key_bytes, signature_bytes};
use alloc::string::String;
use alloc::string::ToString;
use alloc::format;


/// Returns the expected public key length for mldsa.
pub fn public_key_length() -> usize {
    public_key_bytes()
}

/// Returns the expected secret key length for mldsa.
pub fn secret_key_length() -> usize {
    secret_key_bytes()
}

/// Returns the expected signature length for mldsa.
pub fn signature_length() -> usize {
    // Note: mldsa signatures have variable length, this returns the maximum
    // In practice, you might need to handle variable-length signatures differently
    signature_bytes()
}

/// Validates that a public key has the correct length.
pub fn validate_public_key_length(key: &[u8]) -> Result<(), String> {
    let expected_len = public_key_length();
    if key.len() != expected_len {
        Err(format!("Invalid public key length. Expected {}, got {}", expected_len, key.len()))
    } else {
        Ok(())
    }
}

/// Validates that a secret key has the correct length.
pub fn validate_secret_key_length(key: &[u8]) -> Result<(), String> {
    let expected_len = secret_key_length();
    if key.len() != expected_len {
        Err(format!("Invalid secret key length. Expected {}, got {}", expected_len, key.len()))
    } else {
        Ok(())
    }
}

/// Validates that a signature has the correct length.
/// Note: mldsa signatures can have variable length, so this validates
/// against the maximum expected length.
pub fn validate_signature_length(signature: &[u8]) -> Result<(), String> {
    let max_len = signature_length();
    if signature.is_empty() {
        Err("Signature cannot be empty".to_string())
    } else if signature.len() > max_len {
        Err(format!("Invalid signature length. Maximum {}, got {}", max_len, signature.len()))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_length_constants() {
        assert!(public_key_length() > 0);
        assert!(secret_key_length() > 0);
        assert!(signature_length() > 0);
    }

    #[test]
    fn test_validation_functions() {
        let valid_pk = vec![0u8; public_key_length()];
        let invalid_pk = vec![0u8; public_key_length() + 1];

        assert!(validate_public_key_length(&valid_pk).is_ok());
        assert!(validate_public_key_length(&invalid_pk).is_err());

        let valid_sk = vec![0u8; secret_key_length()];
        let invalid_sk = vec![0u8; secret_key_length() - 1];

        assert!(validate_secret_key_length(&valid_sk).is_ok());
        assert!(validate_secret_key_length(&invalid_sk).is_err());

        let valid_sig = vec![0u8; signature_length()];
        let empty_sig = vec![];
        let oversized_sig = vec![0u8; signature_length() + 100];

        assert!(validate_signature_length(&valid_sig).is_ok());
        assert!(validate_signature_length(&empty_sig).is_err());
        assert!(validate_signature_length(&oversized_sig).is_err());
    }
}
