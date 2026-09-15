//! Utility functions for HQC operations.

use alloc::format;
use alloc::string::String;

// HQC-128 length functions
/// Returns the expected public key length for HQC-128.
pub fn hqc128_public_key_length() -> usize {
    use pqrust_hqckem::hqckem128::public_key_bytes;
    public_key_bytes()
}

/// Returns the expected secret key length for HQC-128.
pub fn hqc128_secret_key_length() -> usize {
    use pqrust_hqckem::hqckem128::secret_key_bytes;
    secret_key_bytes()
}

/// Returns the expected ciphertext length for HQC-128.
pub fn hqc128_ciphertext_length() -> usize {
    use pqrust_hqckem::hqckem128::ciphertext_bytes;
    ciphertext_bytes()
}

/// Returns the expected shared secret length for HQC-128.
pub fn hqc128_shared_secret_length() -> usize {
    use pqrust_hqckem::hqckem128::shared_secret_bytes;
    shared_secret_bytes()
}

// HQC-192 length functions
/// Returns the expected public key length for HQC-192.
pub fn hqc192_public_key_length() -> usize {
    use pqrust_hqckem::hqckem192::public_key_bytes;
    public_key_bytes()
}

/// Returns the expected secret key length for HQC-192.
pub fn hqc192_secret_key_length() -> usize {
    use pqrust_hqckem::hqckem192::secret_key_bytes;
    secret_key_bytes()
}

/// Returns the expected ciphertext length for HQC-192.
pub fn hqc192_ciphertext_length() -> usize {
    use pqrust_hqckem::hqckem192::ciphertext_bytes;
    ciphertext_bytes()
}

/// Returns the expected shared secret length for HQC-192.
pub fn hqc192_shared_secret_length() -> usize {
    use pqrust_hqckem::hqckem192::shared_secret_bytes;
    shared_secret_bytes()
}

// HQC-256 length functions
/// Returns the expected public key length for HQC-256.
pub fn hqc256_public_key_length() -> usize {
    use pqrust_hqckem::hqckem256::public_key_bytes;
    public_key_bytes()
}

/// Returns the expected secret key length for HQC-256.
pub fn hqc256_secret_key_length() -> usize {
    use pqrust_hqckem::hqckem256::secret_key_bytes;
    secret_key_bytes()
}

/// Returns the expected ciphertext length for HQC-256.
pub fn hqc256_ciphertext_length() -> usize {
    use pqrust_hqckem::hqckem256::ciphertext_bytes;
    ciphertext_bytes()
}

/// Returns the expected shared secret length for HQC-256.
pub fn hqc256_shared_secret_length() -> usize {
    use pqrust_hqckem::hqckem256::shared_secret_bytes;
    shared_secret_bytes()
}

// HQC-128 validation functions
/// Validates that an HQC-128 public key has the correct length.
pub fn validate_hqc128_public_key_length(key: &[u8]) -> Result<(), String> {
    let expected_len = hqc128_public_key_length();
    if key.len() != expected_len {
        Err(format!("Invalid HQC-128 public key length. Expected {}, got {}", expected_len, key.len()))
    } else {
        Ok(())
    }
}

/// Validates that an HQC-128 secret key has the correct length.
pub fn validate_hqc128_secret_key_length(key: &[u8]) -> Result<(), String> {
    let expected_len = hqc128_secret_key_length();
    if key.len() != expected_len {
        Err(format!("Invalid HQC-128 secret key length. Expected {}, got {}", expected_len, key.len()))
    } else {
        Ok(())
    }
}

/// Validates that an HQC-128 ciphertext has the correct length.
pub fn validate_hqc128_ciphertext_length(ciphertext: &[u8]) -> Result<(), String> {
    let expected_len = hqc128_ciphertext_length();
    if ciphertext.len() != expected_len {
        Err(format!("Invalid HQC-128 ciphertext length. Expected {}, got {}", expected_len, ciphertext.len()))
    } else {
        Ok(())
    }
}

// HQC-192 validation functions
/// Validates that an HQC-192 public key has the correct length.
pub fn validate_hqc192_public_key_length(key: &[u8]) -> Result<(), String> {
    let expected_len = hqc192_public_key_length();
    if key.len() != expected_len {
        Err(format!("Invalid HQC-192 public key length. Expected {}, got {}", expected_len, key.len()))
    } else {
        Ok(())
    }
}

/// Validates that an HQC-192 secret key has the correct length.
pub fn validate_hqc192_secret_key_length(key: &[u8]) -> Result<(), String> {
    let expected_len = hqc192_secret_key_length();
    if key.len() != expected_len {
        Err(format!("Invalid HQC-192 secret key length. Expected {}, got {}", expected_len, key.len()))
    } else {
        Ok(())
    }
}

/// Validates that an HQC-192 ciphertext has the correct length.
pub fn validate_hqc192_ciphertext_length(ciphertext: &[u8]) -> Result<(), String> {
    let expected_len = hqc192_ciphertext_length();
    if ciphertext.len() != expected_len {
        Err(format!("Invalid HQC-192 ciphertext length. Expected {}, got {}", expected_len, ciphertext.len()))
    } else {
        Ok(())
    }
}

// HQC-256 validation functions
/// Validates that an HQC-256 public key has the correct length.
pub fn validate_hqc256_public_key_length(key: &[u8]) -> Result<(), String> {
    let expected_len = hqc256_public_key_length();
    if key.len() != expected_len {
        Err(format!("Invalid HQC-256 public key length. Expected {}, got {}", expected_len, key.len()))
    } else {
        Ok(())
    }
}

/// Validates that an HQC-256 secret key has the correct length.
pub fn validate_hqc256_secret_key_length(key: &[u8]) -> Result<(), String> {
    let expected_len = hqc256_secret_key_length();
    if key.len() != expected_len {
        Err(format!("Invalid HQC-256 secret key length. Expected {}, got {}", expected_len, key.len()))
    } else {
        Ok(())
    }
}

/// Validates that an HQC-256 ciphertext has the correct length.
pub fn validate_hqc256_ciphertext_length(ciphertext: &[u8]) -> Result<(), String> {
    let expected_len = hqc256_ciphertext_length();
    if ciphertext.len() != expected_len {
        Err(format!("Invalid HQC-256 ciphertext length. Expected {}, got {}", expected_len, ciphertext.len()))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hqc_length_constants() {
        // Test that all lengths are positive
        assert!(hqc128_public_key_length() > 0);
        assert!(hqc128_secret_key_length() > 0);
        assert!(hqc128_ciphertext_length() > 0);
        assert!(hqc128_shared_secret_length() > 0);

        assert!(hqc192_public_key_length() > 0);
        assert!(hqc192_secret_key_length() > 0);
        assert!(hqc192_ciphertext_length() > 0);
        assert!(hqc192_shared_secret_length() > 0);

        assert!(hqc256_public_key_length() > 0);
        assert!(hqc256_secret_key_length() > 0);
        assert!(hqc256_ciphertext_length() > 0);
        assert!(hqc256_shared_secret_length() > 0);
    }

    #[test]
    fn test_hqc128_validation_functions() {
        let valid_pk = vec![0u8; hqc128_public_key_length()];
        let invalid_pk = vec![0u8; hqc128_public_key_length() + 1];

        assert!(validate_hqc128_public_key_length(&valid_pk).is_ok());
        assert!(validate_hqc128_public_key_length(&invalid_pk).is_err());

        let valid_sk = vec![0u8; hqc128_secret_key_length()];
        let invalid_sk = vec![0u8; hqc128_secret_key_length() - 1];

        assert!(validate_hqc128_secret_key_length(&valid_sk).is_ok());
        assert!(validate_hqc128_secret_key_length(&invalid_sk).is_err());

        let valid_ct = vec![0u8; hqc128_ciphertext_length()];
        let invalid_ct = vec![0u8; hqc128_ciphertext_length() + 10];

        assert!(validate_hqc128_ciphertext_length(&valid_ct).is_ok());
        assert!(validate_hqc128_ciphertext_length(&invalid_ct).is_err());
    }

    #[test]
    fn test_hqc192_validation_functions() {
        let valid_pk = vec![0u8; hqc192_public_key_length()];
        let invalid_pk = vec![0u8; hqc192_public_key_length() + 1];

        assert!(validate_hqc192_public_key_length(&valid_pk).is_ok());
        assert!(validate_hqc192_public_key_length(&invalid_pk).is_err());

        let valid_sk = vec![0u8; hqc192_secret_key_length()];
        let invalid_sk = vec![0u8; hqc192_secret_key_length() - 1];

        assert!(validate_hqc192_secret_key_length(&valid_sk).is_ok());
        assert!(validate_hqc192_secret_key_length(&invalid_sk).is_err());

        let valid_ct = vec![0u8; hqc192_ciphertext_length()];
        let invalid_ct = vec![0u8; hqc192_ciphertext_length() + 10];

        assert!(validate_hqc192_ciphertext_length(&valid_ct).is_ok());
        assert!(validate_hqc192_ciphertext_length(&invalid_ct).is_err());
    }

    #[test]
    fn test_hqc256_validation_functions() {
        let valid_pk = vec![0u8; hqc256_public_key_length()];
        let invalid_pk = vec![0u8; hqc256_public_key_length() + 1];

        assert!(validate_hqc256_public_key_length(&valid_pk).is_ok());
        assert!(validate_hqc256_public_key_length(&invalid_pk).is_err());

        let valid_sk = vec![0u8; hqc256_secret_key_length()];
        let invalid_sk = vec![0u8; hqc256_secret_key_length() - 1];

        assert!(validate_hqc256_secret_key_length(&valid_sk).is_ok());
        assert!(validate_hqc256_secret_key_length(&invalid_sk).is_err());

        let valid_ct = vec![0u8; hqc256_ciphertext_length()];
        let invalid_ct = vec![0u8; hqc256_ciphertext_length() + 10];

        assert!(validate_hqc256_ciphertext_length(&valid_ct).is_ok());
        assert!(validate_hqc256_ciphertext_length(&invalid_ct).is_err());
    }
}
