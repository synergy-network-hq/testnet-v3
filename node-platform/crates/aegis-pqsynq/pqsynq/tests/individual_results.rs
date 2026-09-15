#![cfg(feature = "full")]

//! Per-algorithm smoke tests with printed timing and size metrics.

use pqsynq::{DigitalSignature, Kem, KeyEncapsulation, PqcError, Sign};

fn run_kem_case(name: &str, kem: Kem) -> Result<(), PqcError> {
    println!("=== {name} ===");
    println!(
        "pk={} sk={} ct={} ss={}",
        kem.public_key_size(),
        kem.secret_key_size(),
        kem.ciphertext_size(),
        kem.shared_secret_size()
    );

    let start = std::time::Instant::now();
    let (pk, sk) = kem.keygen()?;
    let keygen = start.elapsed();

    let start = std::time::Instant::now();
    let (ct, ss1) = kem.encapsulate(&pk)?;
    let encaps = start.elapsed();

    let start = std::time::Instant::now();
    let ss2 = kem.decapsulate(&ct, &sk)?;
    let decaps = start.elapsed();

    assert_eq!(ss1, ss2, "{name} shared secret mismatch");
    println!(
        "keygen={}us encaps={}us decaps={}us",
        keygen.as_micros(),
        encaps.as_micros(),
        decaps.as_micros()
    );
    Ok(())
}

fn run_sign_case(name: &str, signer: Sign) -> Result<(), PqcError> {
    let msg = b"synq-individual-results";
    println!("=== {name} ===");
    println!(
        "pk={} sk={} sig(max)={}",
        signer.public_key_size(),
        signer.secret_key_size(),
        signer.signature_size()
    );

    let start = std::time::Instant::now();
    let (pk, sk) = signer.keygen()?;
    let keygen = start.elapsed();

    let start = std::time::Instant::now();
    let sig = signer.sign(msg, &sk)?;
    let sign = start.elapsed();

    let start = std::time::Instant::now();
    let valid = signer.verify(msg, &sig, &pk)?;
    let verify = start.elapsed();

    assert!(valid, "{name} verification failed");
    println!(
        "sig(actual)={} keygen={}us sign={}us verify={}us",
        sig.len(),
        keygen.as_micros(),
        sign.as_micros(),
        verify.as_micros()
    );
    Ok(())
}

#[test]
fn test_mlkem512_individual() -> Result<(), PqcError> {
    run_kem_case("ML-KEM-512", Kem::mlkem512())
}

#[test]
fn test_mlkem768_individual() -> Result<(), PqcError> {
    run_kem_case("ML-KEM-768", Kem::mlkem768())
}

#[test]
fn test_mlkem1024_individual() -> Result<(), PqcError> {
    run_kem_case("ML-KEM-1024", Kem::mlkem1024())
}

#[cfg(feature = "hqckem")]
#[test]
fn test_hqckem128_individual() -> Result<(), PqcError> {
    run_kem_case("HQC-KEM-128", Kem::hqckem128())
}

#[cfg(feature = "hqckem")]
#[test]
fn test_hqckem192_individual() -> Result<(), PqcError> {
    run_kem_case("HQC-KEM-192", Kem::hqckem192())
}

#[cfg(feature = "hqckem")]
#[test]
fn test_hqckem256_individual() -> Result<(), PqcError> {
    run_kem_case("HQC-KEM-256", Kem::hqckem256())
}

#[test]
fn test_mldsa44_individual() -> Result<(), PqcError> {
    run_sign_case("ML-DSA-44", Sign::mldsa44())
}

#[test]
fn test_mldsa65_individual() -> Result<(), PqcError> {
    run_sign_case("ML-DSA-65", Sign::mldsa65())
}

#[test]
fn test_mldsa87_individual() -> Result<(), PqcError> {
    run_sign_case("ML-DSA-87", Sign::mldsa87())
}

#[test]
fn test_fndsa512_individual() -> Result<(), PqcError> {
    run_sign_case("FN-DSA-512", Sign::fndsa512())
}

#[test]
fn test_fndsa1024_individual() -> Result<(), PqcError> {
    run_sign_case("FN-DSA-1024", Sign::fndsa1024())
}
