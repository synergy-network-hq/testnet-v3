//! Utility functions for Classic McEliece operations.

use pqrust_cmce::mceliece348864;
use pqrust_cmce::mceliece460896;
use pqrust_cmce::mceliece6688128;
use alloc::string::String;
use alloc::format;


// Classic McEliece 128-bit security level constants
/// Public key length for Classic McEliece with 128-bit security level.
pub const CLASSIC_MCELIECE_128_PUBLIC_KEY_LEN: usize = mceliece348864::public_key_bytes();
/// Secret key length for Classic McEliece with 128-bit security level.
pub const CLASSIC_MCELIECE_128_SECRET_KEY_LEN: usize = mceliece348864::secret_key_bytes();
/// Ciphertext length for Classic McEliece with 128-bit security level.
pub const CLASSIC_MCELIECE_128_CIPHERTEXT_LEN: usize = mceliece348864::ciphertext_bytes();
/// Shared secret length for Classic McEliece with 128-bit security level.
pub const CLASSIC_MCELIECE_128_SHARED_SECRET_LEN: usize = mceliece348864::shared_secret_bytes();

// Classic McEliece 192-bit security level constants
/// Public key length for Classic McEliece with 192-bit security level.
pub const CLASSIC_MCELIECE_192_PUBLIC_KEY_LEN: usize = mceliece460896::public_key_bytes();
/// Secret key length for Classic McEliece with 192-bit security level.
pub const CLASSIC_MCELIECE_192_SECRET_KEY_LEN: usize = mceliece460896::secret_key_bytes();
/// Ciphertext length for Classic McEliece with 192-bit security level.
pub const CLASSIC_MCELIECE_192_CIPHERTEXT_LEN: usize = mceliece460896::ciphertext_bytes();
/// Shared secret length for Classic McEliece with 192-bit security level.
pub const CLASSIC_MCELIECE_192_SHARED_SECRET_LEN: usize = mceliece460896::shared_secret_bytes();

// Classic McEliece 256-bit security level constants
/// Public key length for Classic McEliece with 256-bit security level.
pub const CLASSIC_MCELIECE_256_PUBLIC_KEY_LEN: usize = mceliece6688128::public_key_bytes();
/// Secret key length for Classic McEliece with 256-bit security level.
pub const CLASSIC_MCELIECE_256_SECRET_KEY_LEN: usize = mceliece6688128::secret_key_bytes();
/// Ciphertext length for Classic McEliece with 256-bit security level.
pub const CLASSIC_MCELIECE_256_CIPHERTEXT_LEN: usize = mceliece6688128::ciphertext_bytes();
/// Shared secret length for Classic McEliece with 256-bit security level.
pub const CLASSIC_MCELIECE_256_SHARED_SECRET_LEN: usize = mceliece6688128::shared_secret_bytes();

// Length getter functions for 128-bit security
/// Returns the public key length for Classic McEliece with 128-bit security level.
pub fn public_key_length_128() -> usize {
    CLASSIC_MCELIECE_128_PUBLIC_KEY_LEN
}

/// Returns the secret key length for Classic McEliece with 128-bit security level.
pub fn secret_key_length_128() -> usize {
    CLASSIC_MCELIECE_128_SECRET_KEY_LEN
}

/// Returns the ciphertext length for Classic McEliece with 128-bit security level.
pub fn ciphertext_length_128() -> usize {
    CLASSIC_MCELIECE_128_CIPHERTEXT_LEN
}

/// Returns the shared secret length for Classic McEliece with 128-bit security level.
pub fn shared_secret_length_128() -> usize {
    CLASSIC_MCELIECE_128_SHARED_SECRET_LEN
}

// Length getter functions for 192-bit security
/// Returns the public key length for Classic McEliece with 192-bit security level.
pub fn public_key_length_192() -> usize {
    CLASSIC_MCELIECE_192_PUBLIC_KEY_LEN
}

/// Returns the secret key length for Classic McEliece with 192-bit security level.
pub fn secret_key_length_192() -> usize {
    CLASSIC_MCELIECE_192_SECRET_KEY_LEN
}

/// Returns the ciphertext length for Classic McEliece with 192-bit security level.
pub fn ciphertext_length_192() -> usize {
    CLASSIC_MCELIECE_192_CIPHERTEXT_LEN
}

/// Returns the shared secret length for Classic McEliece with 192-bit security level.
pub fn shared_secret_length_192() -> usize {
    CLASSIC_MCELIECE_192_SHARED_SECRET_LEN
}

// Length getter functions for 256-bit security
/// Returns the public key length for Classic McEliece with 256-bit security level.
pub fn public_key_length_256() -> usize {
    CLASSIC_MCELIECE_256_PUBLIC_KEY_LEN
}

/// Returns the secret key length for Classic McEliece with 256-bit security level.
pub fn secret_key_length_256() -> usize {
    CLASSIC_MCELIECE_256_SECRET_KEY_LEN
}

/// Returns the ciphertext length for Classic McEliece with 256-bit security level.
pub fn ciphertext_length_256() -> usize {
    CLASSIC_MCELIECE_256_CIPHERTEXT_LEN
}

/// Returns the shared secret length for Classic McEliece with 256-bit security level.
pub fn shared_secret_length_256() -> usize {
    CLASSIC_MCELIECE_256_SHARED_SECRET_LEN
}

// Validation functions for 128-bit security
/// Validates that a public key has the correct length for Classic McEliece with 128-bit security level.
pub fn validate_public_key_length_128(key: &[u8]) -> Result<(), String> {
    if key.len() != CLASSIC_MCELIECE_128_PUBLIC_KEY_LEN {
        Err(format!("Invalid public key length for 128-bit security. Expected {}, got {}",
                   CLASSIC_MCELIECE_128_PUBLIC_KEY_LEN, key.len()))
    } else {
        Ok(())
    }
}

/// Validates that a secret key has the correct length for Classic McEliece with 128-bit security level.
pub fn validate_secret_key_length_128(key: &[u8]) -> Result<(), String> {
    if key.len() != CLASSIC_MCELIECE_128_SECRET_KEY_LEN {
        Err(format!("Invalid secret key length for 128-bit security. Expected {}, got {}",
                   CLASSIC_MCELIECE_128_SECRET_KEY_LEN, key.len()))
    } else {
        Ok(())
    }
}

/// Validates that a ciphertext has the correct length for Classic McEliece with 128-bit security level.
pub fn validate_ciphertext_length_128(ciphertext: &[u8]) -> Result<(), String> {
    if ciphertext.len() != CLASSIC_MCELIECE_128_CIPHERTEXT_LEN {
        Err(format!("Invalid ciphertext length for 128-bit security. Expected {}, got {}",
                   CLASSIC_MCELIECE_128_CIPHERTEXT_LEN, ciphertext.len()))
    } else {
        Ok(())
    }
}

/// Validates that a shared secret has the correct length for Classic McEliece with 128-bit security level.
pub fn validate_shared_secret_length_128(shared_secret: &[u8]) -> Result<(), String> {
    if shared_secret.len() != CLASSIC_MCELIECE_128_SHARED_SECRET_LEN {
        Err(format!("Invalid shared secret length for 128-bit security. Expected {}, got {}",
                   CLASSIC_MCELIECE_128_SHARED_SECRET_LEN, shared_secret.len()))
    } else {
        Ok(())
    }
}

// Validation functions for 192-bit security
/// Validates that a public key has the correct length for Classic McEliece with 192-bit security level.
pub fn validate_public_key_length_192(key: &[u8]) -> Result<(), String> {
    if key.len() != CLASSIC_MCELIECE_192_PUBLIC_KEY_LEN {
        Err(format!("Invalid public key length for 192-bit security. Expected {}, got {}",
                   CLASSIC_MCELIECE_192_PUBLIC_KEY_LEN, key.len()))
    } else {
        Ok(())
    }
}

/// Validates that a secret key has the correct length for Classic McEliece with 192-bit security level.
pub fn validate_secret_key_length_192(key: &[u8]) -> Result<(), String> {
    if key.len() != CLASSIC_MCELIECE_192_SECRET_KEY_LEN {
        Err(format!("Invalid secret key length for 192-bit security. Expected {}, got {}",
                   CLASSIC_MCELIECE_192_SECRET_KEY_LEN, key.len()))
    } else {
        Ok(())
    }
}

/// Validates that a ciphertext has the correct length for Classic McEliece with 192-bit security level.
pub fn validate_ciphertext_length_192(ciphertext: &[u8]) -> Result<(), String> {
    if ciphertext.len() != CLASSIC_MCELIECE_192_CIPHERTEXT_LEN {
        Err(format!("Invalid ciphertext length for 192-bit security. Expected {}, got {}",
                   CLASSIC_MCELIECE_192_CIPHERTEXT_LEN, ciphertext.len()))
    } else {
        Ok(())
    }
}

/// Validates that a shared secret has the correct length for Classic McEliece with 192-bit security level.
pub fn validate_shared_secret_length_192(shared_secret: &[u8]) -> Result<(), String> {
    if shared_secret.len() != CLASSIC_MCELIECE_192_SHARED_SECRET_LEN {
        Err(format!("Invalid shared secret length for 192-bit security. Expected {}, got {}",
                   CLASSIC_MCELIECE_192_SHARED_SECRET_LEN, shared_secret.len()))
    } else {
        Ok(())
    }
}

// Validation functions for 256-bit security
/// Validates that a public key has the correct length for Classic McEliece with 256-bit security level.
pub fn validate_public_key_length_256(key: &[u8]) -> Result<(), String> {
    if key.len() != CLASSIC_MCELIECE_256_PUBLIC_KEY_LEN {
        Err(format!("Invalid public key length for 256-bit security. Expected {}, got {}",
                   CLASSIC_MCELIECE_256_PUBLIC_KEY_LEN, key.len()))
    } else {
        Ok(())
    }
}

/// Validates that a secret key has the correct length for Classic McEliece with 256-bit security level.
pub fn validate_secret_key_length_256(key: &[u8]) -> Result<(), String> {
    if key.len() != CLASSIC_MCELIECE_256_SECRET_KEY_LEN {
        Err(format!("Invalid secret key length for 256-bit security. Expected {}, got {}",
                   CLASSIC_MCELIECE_256_SECRET_KEY_LEN, key.len()))
    } else {
        Ok(())
    }
}

/// Validates that a ciphertext has the correct length for Classic McEliece with 256-bit security level.
pub fn validate_ciphertext_length_256(ciphertext: &[u8]) -> Result<(), String> {
    if ciphertext.len() != CLASSIC_MCELIECE_256_CIPHERTEXT_LEN {
        Err(format!("Invalid ciphertext length for 256-bit security. Expected {}, got {}",
                   CLASSIC_MCELIECE_256_CIPHERTEXT_LEN, ciphertext.len()))
    } else {
        Ok(())
    }
}

/// Validates that a shared secret has the correct length for Classic McEliece with 256-bit security level.
pub fn validate_shared_secret_length_256(shared_secret: &[u8]) -> Result<(), String> {
    if shared_secret.len() != CLASSIC_MCELIECE_256_SHARED_SECRET_LEN {
        Err(format!("Invalid shared secret length for 256-bit security. Expected {}, got {}",
                   CLASSIC_MCELIECE_256_SHARED_SECRET_LEN, shared_secret.len()))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_length_constants_128() {
        assert_eq!(public_key_length_128(), CLASSIC_MCELIECE_128_PUBLIC_KEY_LEN);
        assert_eq!(secret_key_length_128(), CLASSIC_MCELIECE_128_SECRET_KEY_LEN);
        assert_eq!(ciphertext_length_128(), CLASSIC_MCELIECE_128_CIPHERTEXT_LEN);
        assert_eq!(shared_secret_length_128(), CLASSIC_MCELIECE_128_SHARED_SECRET_LEN);
    }

    #[test]
    fn test_length_constants_192() {
        assert_eq!(public_key_length_192(), CLASSIC_MCELIECE_192_PUBLIC_KEY_LEN);
        assert_eq!(secret_key_length_192(), CLASSIC_MCELIECE_192_SECRET_KEY_LEN);
        assert_eq!(ciphertext_length_192(), CLASSIC_MCELIECE_192_CIPHERTEXT_LEN);
        assert_eq!(shared_secret_length_192(), CLASSIC_MCELIECE_192_SHARED_SECRET_LEN);
    }

    #[test]
    fn test_length_constants_256() {
        assert_eq!(public_key_length_256(), CLASSIC_MCELIECE_256_PUBLIC_KEY_LEN);
        assert_eq!(secret_key_length_256(), CLASSIC_MCELIECE_256_SECRET_KEY_LEN);
        assert_eq!(ciphertext_length_256(), CLASSIC_MCELIECE_256_CIPHERTEXT_LEN);
        assert_eq!(shared_secret_length_256(), CLASSIC_MCELIECE_256_SHARED_SECRET_LEN);
    }

    #[test]
    fn test_validation_functions_128() {
        let valid_pk = vec![0u8; CLASSIC_MCELIECE_128_PUBLIC_KEY_LEN];
        let invalid_pk = vec![0u8; CLASSIC_MCELIECE_128_PUBLIC_KEY_LEN + 1];

        assert!(validate_public_key_length_128(&valid_pk).is_ok());
        assert!(validate_public_key_length_128(&invalid_pk).is_err());

        let valid_sk = vec![0u8; CLASSIC_MCELIECE_128_SECRET_KEY_LEN];
        let invalid_sk = vec![0u8; CLASSIC_MCELIECE_128_SECRET_KEY_LEN - 1];

        assert!(validate_secret_key_length_128(&valid_sk).is_ok());
        assert!(validate_secret_key_length_128(&invalid_sk).is_err());

        let valid_ct = vec![0u8; CLASSIC_MCELIECE_128_CIPHERTEXT_LEN];
        let invalid_ct = vec![0u8; CLASSIC_MCELIECE_128_CIPHERTEXT_LEN + 10];

        assert!(validate_ciphertext_length_128(&valid_ct).is_ok());
        assert!(validate_ciphertext_length_128(&invalid_ct).is_err());

        let valid_ss = vec![0u8; CLASSIC_MCELIECE_128_SHARED_SECRET_LEN];
        let invalid_ss = vec![0u8; CLASSIC_MCELIECE_128_SHARED_SECRET_LEN - 5];

        assert!(validate_shared_secret_length_128(&valid_ss).is_ok());
        assert!(validate_shared_secret_length_128(&invalid_ss).is_err());
    }

    #[test]
    fn test_validation_functions_192() {
        let valid_pk = vec![0u8; CLASSIC_MCELIECE_192_PUBLIC_KEY_LEN];
        let invalid_pk = vec![0u8; 100]; // Wrong size

        assert!(validate_public_key_length_192(&valid_pk).is_ok());
        assert!(validate_public_key_length_192(&invalid_pk).is_err());

        let valid_sk = vec![0u8; CLASSIC_MCELIECE_192_SECRET_KEY_LEN];
        let invalid_sk = vec![0u8; 200]; // Wrong size

        assert!(validate_secret_key_length_192(&valid_sk).is_ok());
        assert!(validate_secret_key_length_192(&invalid_sk).is_err());
    }

    #[test]
    fn test_validation_functions_256() {
        let valid_pk = vec![0u8; CLASSIC_MCELIECE_256_PUBLIC_KEY_LEN];
        let invalid_pk = vec![0u8; 500]; // Wrong size

        assert!(validate_public_key_length_256(&valid_pk).is_ok());
        assert!(validate_public_key_length_256(&invalid_pk).is_err());

        let valid_sk = vec![0u8; CLASSIC_MCELIECE_256_SECRET_KEY_LEN];
        let invalid_sk = vec![0u8; 1000]; // Wrong size

        assert!(validate_secret_key_length_256(&valid_sk).is_ok());
        assert!(validate_secret_key_length_256(&invalid_sk).is_err());
    }
}
