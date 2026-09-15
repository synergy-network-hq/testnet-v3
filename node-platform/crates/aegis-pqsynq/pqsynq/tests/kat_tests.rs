#![cfg(feature = "full")]

//! KAT-style correctness tests for currently supported algorithms.
//!
//! These are deterministic fixture-style API checks (known messages, expected
//! verification outcomes, and strict size invariants) rather than official NIST
//! vector replay for every algorithm.

use pqsynq::{DigitalSignature, Kem, KeyEncapsulation, Sign};

#[test]
fn test_mlkem_size_and_roundtrip_matrix() {
    let kem_variants = [Kem::mlkem512(), Kem::mlkem768(), Kem::mlkem1024()];

    for kem in kem_variants {
        for _ in 0..16 {
            let (pk, sk) = kem.keygen().expect("ML-KEM keygen failed");
            assert_eq!(pk.len(), kem.public_key_size());
            assert_eq!(sk.len(), kem.secret_key_size());

            let (ct, ss1) = kem.encapsulate(&pk).expect("ML-KEM encaps failed");
            assert_eq!(ct.len(), kem.ciphertext_size());
            assert_eq!(ss1.len(), kem.shared_secret_size());

            let ss2 = kem.decapsulate(&ct, &sk).expect("ML-KEM decaps failed");
            assert_eq!(ss1, ss2);
        }
    }
}

#[cfg(feature = "hqckem")]
#[test]
fn test_hqckem_size_and_roundtrip_matrix() {
    let kem_variants = [Kem::hqckem128(), Kem::hqckem192(), Kem::hqckem256()];

    for kem in kem_variants {
        for _ in 0..16 {
            let (pk, sk) = kem.keygen().expect("HQC-KEM keygen failed");
            assert_eq!(pk.len(), kem.public_key_size());
            assert_eq!(sk.len(), kem.secret_key_size());

            let (ct, ss1) = kem.encapsulate(&pk).expect("HQC-KEM encaps failed");
            assert_eq!(ct.len(), kem.ciphertext_size());
            assert_eq!(ss1.len(), kem.shared_secret_size());

            let ss2 = kem.decapsulate(&ct, &sk).expect("HQC-KEM decaps failed");
            assert_eq!(ss1, ss2);
        }
    }
}

#[test]
fn test_mldsa_known_message_matrix() {
    let signers = [Sign::mldsa44(), Sign::mldsa65(), Sign::mldsa87()];
    let messages: [&[u8]; 5] = [
        b"",
        b"a",
        b"SynQ",
        b"quantum-safe-contract-call",
        b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    ];

    for signer in signers {
        let (pk, sk) = signer.keygen().expect("ML-DSA keygen failed");

        for msg in messages {
            let sig = signer.sign(msg, &sk).expect("ML-DSA sign failed");
            let valid = signer.verify(msg, &sig, &pk).expect("ML-DSA verify failed");
            assert!(valid);

            let tampered = if msg.is_empty() {
                b"x".as_slice()
            } else {
                b"tampered".as_slice()
            };
            let invalid = signer
                .verify(tampered, &sig, &pk)
                .expect("ML-DSA verify should return bool");
            assert!(!invalid);
        }
    }
}

#[test]
fn test_mldsa_contextual_matrix() {
    let signers = [Sign::mldsa44(), Sign::mldsa65(), Sign::mldsa87()];
    let contexts: [&[u8]; 3] = [b"synq-v1", b"deployment-alpha", b""];
    let message = b"state transition payload";

    for signer in signers {
        let (pk, sk) = signer.keygen().expect("ML-DSA keygen failed");

        for ctx in contexts {
            let sig = signer
                .sign_ctx(message, &sk, ctx)
                .expect("ML-DSA contextual signing failed");

            let valid = signer
                .verify_ctx(message, &sig, &pk, ctx)
                .expect("ML-DSA contextual verify failed");
            assert!(valid);

            let wrong_ctx = b"wrong-context";
            let invalid = signer
                .verify_ctx(message, &sig, &pk, wrong_ctx)
                .expect("ML-DSA contextual verify should return bool");
            assert!(!invalid);
        }
    }
}

#[test]
fn test_fndsa_known_message_matrix() {
    let signers = [Sign::fndsa512(), Sign::fndsa1024()];
    let messages: [&[u8]; 4] = [
        b"FN-DSA case 1",
        b"FN-DSA case 2",
        b"",
        b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ];

    for signer in signers {
        let (pk, sk) = signer.keygen().expect("FN-DSA keygen failed");

        for msg in messages {
            let sig = signer.sign(msg, &sk).expect("FN-DSA sign failed");
            let valid = signer.verify(msg, &sig, &pk).expect("FN-DSA verify failed");
            assert!(valid);
        }
    }
}
