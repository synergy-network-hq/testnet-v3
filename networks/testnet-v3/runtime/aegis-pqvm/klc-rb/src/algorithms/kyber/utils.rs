//! Utility functions for mlkem operations.

use alloc::format;
use pqrust_mlkem::mlkem768::{public_key_bytes, secret_key_bytes, ciphertext_bytes, shared_secret_bytes};
use alloc::string::String;

/// Returns the expected public key length for mlkem.
pub fn public_key_length() -> usize {
    public_key_bytes()
}

/// Returns the expected secret key length for mlkem.
pub fn secret_key_length() -> usize {
    secret_key_bytes()
}

/// Returns the expected ciphertext length for mlkem.
pub fn ciphertext_length() -> usize {
    ciphertext_bytes()
}

/// Returns the expected shared secret length for mlkem.
pub fn shared_secret_length() -> usize {
    shared_secret_bytes()
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

/// Validates that a ciphertext has the correct length.
pub fn validate_ciphertext_length(ciphertext: &[u8]) -> Result<(), String> {
    let expected_len = ciphertext_length();
    if ciphertext.len() != expected_len {
        Err(format!("Invalid ciphertext length. Expected {}, got {}", expected_len, ciphertext.len()))
    } else {
        Ok(())
    }
}

/// Validates that a shared secret has the correct length.
pub fn validate_shared_secret_length(shared_secret: &[u8]) -> Result<(), String> {
    let expected_len = shared_secret_length();
    if shared_secret.len() != expected_len {
        Err(format!("Invalid shared secret length. Expected {}, got {}", expected_len, shared_secret.len()))
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
        assert!(ciphertext_length() > 0);
        assert!(shared_secret_length() > 0);
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

        let valid_ct = vec![0u8; ciphertext_length()];
        let invalid_ct = vec![0u8; ciphertext_length() + 10];

        assert!(validate_ciphertext_length(&valid_ct).is_ok());
        assert!(validate_ciphertext_length(&invalid_ct).is_err());

        let valid_ss = vec![0u8; shared_secret_length()];
        let invalid_ss = vec![0u8; shared_secret_length() - 5];

        assert!(validate_shared_secret_length(&valid_ss).is_ok());
        assert!(validate_shared_secret_length(&invalid_ss).is_err());
    }
}
