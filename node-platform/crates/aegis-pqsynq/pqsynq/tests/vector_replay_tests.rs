#![cfg(feature = "full")]

use pqsynq::{DigitalSignature, Kem, KeyEncapsulation, Sign};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct FixtureSet {
    kem_vectors: Vec<KemVector>,
    sign_vectors: Vec<SignVector>,
}

#[derive(Debug, Deserialize)]
struct KemVector {
    algorithm: String,
    public_key_hex: String,
    secret_key_hex: String,
    ciphertext_hex: String,
    shared_secret_hex: String,
}

#[derive(Debug, Deserialize)]
struct SignVector {
    algorithm: String,
    message_hex: String,
    public_key_hex: String,
    secret_key_hex: String,
    signature_hex: String,
    context_hex: Option<String>,
}

fn fixture() -> FixtureSet {
    serde_json::from_str(include_str!("vectors/pinned_vectors.json"))
        .expect("pinned_vectors.json must be valid fixture JSON")
}

fn decode_hex(label: &str, value: &str) -> Vec<u8> {
    hex::decode(value).unwrap_or_else(|_| panic!("failed to decode hex field: {label}"))
}

fn kem_for(algorithm: &str) -> Kem {
    match algorithm {
        "mlkem512" => Kem::mlkem512(),
        "mlkem768" => Kem::mlkem768(),
        "mlkem1024" => Kem::mlkem1024(),
        "hqckem128" => Kem::hqckem128(),
        "hqckem192" => Kem::hqckem192(),
        "hqckem256" => Kem::hqckem256(),
        other => panic!("unsupported KEM fixture algorithm: {other}"),
    }
}

fn sign_for(algorithm: &str) -> Sign {
    match algorithm {
        "mldsa44" => Sign::mldsa44(),
        "mldsa65" => Sign::mldsa65(),
        "mldsa87" => Sign::mldsa87(),
        "fndsa512" => Sign::fndsa512(),
        "fndsa1024" => Sign::fndsa1024(),
        other => panic!("unsupported signature fixture algorithm: {other}"),
    }
}

#[test]
fn test_pinned_kem_vectors_replay() {
    let fixture = fixture();
    assert!(
        !fixture.kem_vectors.is_empty(),
        "fixture KEM vectors must exist"
    );

    for vector in fixture.kem_vectors {
        let kem = kem_for(&vector.algorithm);

        let pk = decode_hex("public_key_hex", &vector.public_key_hex);
        let sk = decode_hex("secret_key_hex", &vector.secret_key_hex);
        let ct = decode_hex("ciphertext_hex", &vector.ciphertext_hex);
        let expected_ss = decode_hex("shared_secret_hex", &vector.shared_secret_hex);

        assert_eq!(
            pk.len(),
            kem.public_key_size(),
            "{} pk length mismatch",
            vector.algorithm
        );
        assert_eq!(
            sk.len(),
            kem.secret_key_size(),
            "{} sk length mismatch",
            vector.algorithm
        );
        assert_eq!(
            ct.len(),
            kem.ciphertext_size(),
            "{} ct length mismatch",
            vector.algorithm
        );
        assert_eq!(
            expected_ss.len(),
            kem.shared_secret_size(),
            "{} shared secret length mismatch",
            vector.algorithm
        );

        let replay_ss = kem
            .decapsulate(&ct, &sk)
            .unwrap_or_else(|_| panic!("{} fixture decapsulation failed", vector.algorithm));
        assert_eq!(
            replay_ss, expected_ss,
            "{} fixture shared secret mismatch",
            vector.algorithm
        );

        let (fresh_ct, fresh_ss_1) = kem
            .encapsulate(&pk)
            .unwrap_or_else(|_| panic!("{} fresh encapsulation failed", vector.algorithm));
        let fresh_ss_2 = kem
            .decapsulate(&fresh_ct, &sk)
            .unwrap_or_else(|_| panic!("{} fresh decapsulation failed", vector.algorithm));
        assert_eq!(
            fresh_ss_1, fresh_ss_2,
            "{} fresh encaps/decaps mismatch",
            vector.algorithm
        );
    }
}

#[test]
fn test_pinned_signature_vectors_replay() {
    let fixture = fixture();
    assert!(
        !fixture.sign_vectors.is_empty(),
        "fixture signature vectors must exist"
    );

    for vector in fixture.sign_vectors {
        let signer = sign_for(&vector.algorithm);

        let message = decode_hex("message_hex", &vector.message_hex);
        let pk = decode_hex("public_key_hex", &vector.public_key_hex);
        let sk = decode_hex("secret_key_hex", &vector.secret_key_hex);
        let signature = decode_hex("signature_hex", &vector.signature_hex);

        assert_eq!(
            pk.len(),
            signer.public_key_size(),
            "{} pk length mismatch",
            vector.algorithm
        );
        assert_eq!(
            sk.len(),
            signer.secret_key_size(),
            "{} sk length mismatch",
            vector.algorithm
        );

        match vector.context_hex {
            Some(ctx_hex) => {
                let ctx = decode_hex("context_hex", &ctx_hex);
                let valid = signer
                    .verify_ctx(&message, &signature, &pk, &ctx)
                    .unwrap_or_else(|_| panic!("{} verify_ctx failed", vector.algorithm));
                assert!(
                    valid,
                    "{} context-bound signature should verify",
                    vector.algorithm
                );

                let mut wrong_ctx = ctx.clone();
                if wrong_ctx.is_empty() {
                    wrong_ctx.push(1);
                } else {
                    wrong_ctx[0] ^= 0x01;
                }
                let wrong_valid = signer
                    .verify_ctx(&message, &signature, &pk, &wrong_ctx)
                    .unwrap_or_else(|_| panic!("{} wrong-context verify failed", vector.algorithm));
                assert!(
                    !wrong_valid,
                    "{} wrong context should fail",
                    vector.algorithm
                );
            }
            None => {
                let valid = signer
                    .verify(&message, &signature, &pk)
                    .unwrap_or_else(|_| panic!("{} verify failed", vector.algorithm));
                assert!(valid, "{} signature should verify", vector.algorithm);
            }
        }

        let mut tampered = message.clone();
        if tampered.is_empty() {
            tampered.push(0x01);
        } else {
            tampered[0] ^= 0x01;
        }

        let tampered_valid = signer
            .verify(&tampered, &signature, &pk)
            .unwrap_or_else(|_| panic!("{} tampered verify failed", vector.algorithm));
        assert!(
            !tampered_valid,
            "{} tampered message should not verify",
            vector.algorithm
        );
    }
}
