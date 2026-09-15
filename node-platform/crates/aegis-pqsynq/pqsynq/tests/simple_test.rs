//! Simple test to verify PQSynQ functionality

use pqsynq::{DigitalSignature, Kem, KeyEncapsulation, PqcError, Sign};

#[test]
fn test_mlkem768_workflow() -> Result<(), PqcError> {
    println!("Testing ML-KEM-768 workflow...");

    let kem = Kem::mlkem768();
    println!("Created ML-KEM-768 instance");

    // Test key generation
    println!("Generating key pair...");
    let (pk, sk) = kem.keygen()?;
    println!("Generated public key: {} bytes", pk.len());
    println!("Generated secret key: {} bytes", sk.len());

    // Test encapsulation
    println!("Encapsulating shared secret...");
    let (ct, ss1) = kem.encapsulate(&pk)?;
    println!("Generated ciphertext: {} bytes", ct.len());
    println!("Generated shared secret: {} bytes", ss1.len());

    // Test decapsulation
    println!("Decapsulating shared secret...");
    let ss2 = kem.decapsulate(&ct, &sk)?;
    println!("Decapsulated shared secret: {} bytes", ss2.len());

    // Verify shared secrets match
    assert_eq!(ss1, ss2);
    println!("✓ ML-KEM-768 workflow completed successfully");

    Ok(())
}

#[test]
fn test_mldsa65_workflow() -> Result<(), PqcError> {
    println!("Testing ML-DSA-65 workflow...");

    let signer = Sign::mldsa65();
    let message = b"Hello, PQSynQ!";
    println!(
        "Created ML-DSA-65 instance with message: {} bytes",
        message.len()
    );

    // Test key generation
    println!("Generating key pair...");
    let (pk, sk) = signer.keygen()?;
    println!("Generated public key: {} bytes", pk.len());
    println!("Generated secret key: {} bytes", sk.len());

    // Test signing
    println!("Signing message...");
    let signature = signer.sign(message, &sk)?;
    println!("Generated signature: {} bytes", signature.len());

    // Test verification
    println!("Verifying signature...");
    let is_valid = signer.verify(message, &signature, &pk)?;
    assert!(is_valid);
    println!("✓ ML-DSA-65 workflow completed successfully");

    Ok(())
}
