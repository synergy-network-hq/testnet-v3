//! Basic tests for PQSynQ

use pqsynq::{DigitalSignature, Kem, KeyEncapsulation, PqcError, Sign};

#[test]
fn test_mlkem768_basic() -> Result<(), PqcError> {
    let kem = Kem::mlkem768();

    // Test key generation
    let (pk, sk) = kem.keygen()?;
    assert_eq!(pk.len(), kem.public_key_size());
    assert_eq!(sk.len(), kem.secret_key_size());

    // Test encapsulation
    let (ct, ss1) = kem.encapsulate(&pk)?;
    assert_eq!(ct.len(), kem.ciphertext_size());
    assert_eq!(ss1.len(), kem.shared_secret_size());

    // Test decapsulation
    let ss2 = kem.decapsulate(&ct, &sk)?;
    assert_eq!(ss1, ss2);

    Ok(())
}

#[test]
fn test_mldsa65_basic() -> Result<(), PqcError> {
    let signer = Sign::mldsa65();
    let message = b"Hello, PQSynQ!";

    // Test key generation
    let (pk, sk) = signer.keygen()?;
    assert_eq!(pk.len(), signer.public_key_size());
    assert_eq!(sk.len(), signer.secret_key_size());

    // Test signing
    let signature = signer.sign(message, &sk)?;
    assert!(!signature.is_empty());
    assert!(signature.len() <= signer.signature_size());

    // Test verification
    let is_valid = signer.verify(message, &signature, &pk)?;
    assert!(is_valid);

    Ok(())
}

#[test]
fn test_fndsa512_basic() -> Result<(), PqcError> {
    let signer = Sign::fndsa512();
    let message = b"FN-DSA signature test";

    // Test key generation
    let (pk, sk) = signer.keygen()?;
    assert_eq!(pk.len(), signer.public_key_size());
    assert_eq!(sk.len(), signer.secret_key_size());

    // Test signing
    let signature = signer.sign(message, &sk)?;
    assert!(!signature.is_empty());
    assert!(signature.len() <= signer.signature_size());

    // Test verification
    let is_valid = signer.verify(message, &signature, &pk)?;
    assert!(is_valid);

    Ok(())
}
