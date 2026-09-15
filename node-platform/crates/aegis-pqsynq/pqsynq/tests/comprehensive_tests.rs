#![cfg(feature = "full")]

//! Comprehensive tests for currently supported `aegis-pqsynq` algorithms.

use pqsynq::{DigitalSignature, Kem, KeyEncapsulation, PqcError, Sign};

#[test]
fn test_all_supported_kem_algorithms_basic() {
    let mut kem_algorithms = vec![
        ("ML-KEM-512", Kem::mlkem512()),
        ("ML-KEM-768", Kem::mlkem768()),
        ("ML-KEM-1024", Kem::mlkem1024()),
    ];
    #[cfg(feature = "hqckem")]
    {
        kem_algorithms.extend([
            ("HQC-KEM-128", Kem::hqckem128()),
            ("HQC-KEM-192", Kem::hqckem192()),
            ("HQC-KEM-256", Kem::hqckem256()),
        ]);
    }

    for (name, kem) in kem_algorithms {
        let (pk, sk) = kem
            .keygen()
            .unwrap_or_else(|_| panic!("{name} keygen failed"));
        assert_eq!(
            pk.len(),
            kem.public_key_size(),
            "{name} public key size mismatch"
        );
        assert_eq!(
            sk.len(),
            kem.secret_key_size(),
            "{name} secret key size mismatch"
        );

        let (ct, ss1) = kem
            .encapsulate(&pk)
            .unwrap_or_else(|_| panic!("{name} encapsulation failed"));
        assert_eq!(
            ct.len(),
            kem.ciphertext_size(),
            "{name} ciphertext size mismatch"
        );
        assert_eq!(
            ss1.len(),
            kem.shared_secret_size(),
            "{name} shared secret size mismatch"
        );

        let ss2 = kem
            .decapsulate(&ct, &sk)
            .unwrap_or_else(|_| panic!("{name} decapsulation failed"));
        assert_eq!(ss1, ss2, "{name} shared secrets don't match");
    }
}

#[test]
fn test_all_supported_sign_algorithms_basic() {
    let sign_algorithms = [
        ("ML-DSA-44", Sign::mldsa44()),
        ("ML-DSA-65", Sign::mldsa65()),
        ("ML-DSA-87", Sign::mldsa87()),
        ("FN-DSA-512", Sign::fndsa512()),
        ("FN-DSA-1024", Sign::fndsa1024()),
    ];

    let long_zero = vec![0u8; 2048];
    let test_messages: [&[u8]; 4] = [
        b"Short message",
        b"Medium length test message for signature verification",
        &long_zero,
        b"",
    ];

    for (name, signer) in sign_algorithms {
        for message in test_messages {
            let (pk, sk) = signer
                .keygen()
                .unwrap_or_else(|_| panic!("{name} keygen failed"));

            let sig = signer
                .sign(message, &sk)
                .unwrap_or_else(|_| panic!("{name} signing failed"));
            assert!(
                !sig.is_empty(),
                "{name} produced an empty signature unexpectedly"
            );

            let valid = signer
                .verify(message, &sig, &pk)
                .unwrap_or_else(|_| panic!("{name} verification failed"));
            assert!(valid, "{name} signature verification failed");
        }
    }
}

#[test]
fn test_detached_signature_helpers() {
    let signers = [
        ("ML-DSA-44", Sign::mldsa44()),
        ("ML-DSA-65", Sign::mldsa65()),
        ("ML-DSA-87", Sign::mldsa87()),
        ("FN-DSA-512", Sign::fndsa512()),
        ("FN-DSA-1024", Sign::fndsa1024()),
    ];

    let message = b"detached message";

    for (name, signer) in signers {
        let (pk, sk) = signer.keygen().expect("keygen should succeed");
        let sig = signer
            .detached_sign(message, &sk)
            .unwrap_or_else(|_| panic!("{name} detached_sign failed"));

        let valid = signer
            .verify_detached(message, &sig, &pk)
            .unwrap_or_else(|_| panic!("{name} verify_detached failed"));
        assert!(valid, "{name} detached signature failed verification");
    }
}

#[test]
fn test_contextual_signature_helpers_for_mldsa() {
    let signers = [Sign::mldsa44(), Sign::mldsa65(), Sign::mldsa87()];
    let message = b"context-bound payload";
    let context = b"synq-contract-v1";

    for signer in signers {
        let (pk, sk) = signer.keygen().expect("ML-DSA keygen should succeed");

        let sig = signer
            .sign_ctx(message, &sk, context)
            .expect("ML-DSA sign_ctx should succeed");
        let valid = signer
            .verify_ctx(message, &sig, &pk, context)
            .expect("ML-DSA verify_ctx should succeed");
        assert!(valid);

        let wrong_context_valid = signer
            .verify_ctx(message, &sig, &pk, b"synq-contract-v2")
            .expect("ML-DSA verify_ctx should return bool for wrong context");
        assert!(!wrong_context_valid);
    }
}

#[test]
fn test_contextual_signature_helpers_for_fndsa() {
    let signers = [Sign::fndsa512(), Sign::fndsa1024()];
    let message = b"context-bound payload";
    let context = b"synq-contract-v1";

    for signer in signers {
        let (pk, sk) = signer.keygen().expect("FN-DSA keygen should succeed");

        let sig = signer
            .sign_ctx(message, &sk, context)
            .expect("FN-DSA sign_ctx should succeed");
        let valid = signer
            .verify_ctx(message, &sig, &pk, context)
            .expect("FN-DSA verify_ctx should succeed");
        assert!(valid);

        let wrong_context_valid = signer
            .verify_ctx(message, &sig, &pk, b"synq-contract-v2")
            .expect("FN-DSA verify_ctx should return bool for wrong context");
        assert!(!wrong_context_valid);
    }
}

#[test]
fn test_error_handling_invalid_sizes() {
    let kem = Kem::mlkem768();
    let signer = Sign::mldsa65();

    let invalid_pk = vec![0u8; 10];
    let result = kem.encapsulate(&invalid_pk);
    assert!(matches!(result, Err(PqcError::InvalidKeySize)));

    let (pk, _) = kem.keygen().expect("keygen should succeed");
    let invalid_sk = vec![0u8; 10];
    let (ct, _) = kem.encapsulate(&pk).expect("encaps should succeed");
    let result = kem.decapsulate(&ct, &invalid_sk);
    assert!(matches!(result, Err(PqcError::InvalidKeySize)));

    let invalid_sk = vec![0u8; 10];
    let message = b"test message";
    let result = signer.sign(message, &invalid_sk);
    assert!(matches!(result, Err(PqcError::InvalidKeySize)));
}

#[cfg(feature = "hqckem")]
#[test]
fn test_hqckem_decapsulation_rejects_mismatched_or_tampered_inputs() {
    let kem_algorithms = [
        ("HQC-KEM-128", Kem::hqckem128()),
        ("HQC-KEM-192", Kem::hqckem192()),
        ("HQC-KEM-256", Kem::hqckem256()),
    ];

    for (name, kem) in kem_algorithms {
        let (pk, _sk_valid) = kem
            .keygen()
            .unwrap_or_else(|_| panic!("{name} keygen failed for valid pair"));
        let (_pk_other, sk_other) = kem
            .keygen()
            .unwrap_or_else(|_| panic!("{name} keygen failed for mismatched pair"));
        let (ct, _ss) = kem
            .encapsulate(&pk)
            .unwrap_or_else(|_| panic!("{name} encapsulation failed"));

        let mismatched_result = kem.decapsulate(&ct, &sk_other);
        assert!(
            mismatched_result.is_err(),
            "{name} should return an error for mismatched secret key"
        );

        let mut tampered_ct = ct.clone();
        tampered_ct[0] ^= 0x01;
        let tampered_result = kem.decapsulate(&tampered_ct, &sk_other);
        assert!(
            tampered_result.is_err(),
            "{name} should return an error for tampered ciphertext"
        );
    }
}

#[test]
fn test_stress_rounds() {
    let kem = Kem::mlkem768();
    let signer = Sign::mldsa65();

    for _ in 0..50 {
        let (pk, sk) = kem.keygen().expect("keygen should succeed");
        let (ct, ss1) = kem.encapsulate(&pk).expect("encaps should succeed");
        let ss2 = kem.decapsulate(&ct, &sk).expect("decaps should succeed");
        assert_eq!(ss1, ss2);

        let (pk, sk) = signer.keygen().expect("keygen should succeed");
        let msg = b"stress test message";
        let sig = signer.sign(msg, &sk).expect("sign should succeed");
        let valid = signer
            .verify(msg, &sig, &pk)
            .expect("verify should succeed");
        assert!(valid);
    }
}
