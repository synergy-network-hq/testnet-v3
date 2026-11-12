use aegis_crypto_core::{
    fndsa::{
        fndsa1024_keygen, fndsa1024_sign, fndsa1024_verify, fndsa512_keygen, fndsa512_sign,
        fndsa512_verify,
    },
    mldsa::{
        mldsa44_keygen, mldsa44_sign, mldsa44_verify, mldsa65_keygen, mldsa65_sign, mldsa65_verify,
        mldsa87_keygen, mldsa87_sign, mldsa87_verify,
    },
    mlkem::{
        mlkem1024_decapsulate, mlkem1024_encapsulate, mlkem1024_keygen, mlkem512_decapsulate,
        mlkem512_encapsulate, mlkem512_keygen, mlkem768_decapsulate, mlkem768_encapsulate,
        mlkem768_keygen,
    },
};

#[test]
fn fips_203_mlkem_roundtrips_all_parameter_sets() {
    let keypair = mlkem512_keygen();
    let encapsulated =
        mlkem512_encapsulate(&keypair.public_key()).expect("ML-KEM-512 encapsulation failed");
    let decapsulated = mlkem512_decapsulate(&keypair.secret_key(), &encapsulated.ciphertext())
        .expect("ML-KEM-512 decapsulation failed");
    assert_eq!(encapsulated.shared_secret(), decapsulated);

    let keypair = mlkem768_keygen();
    let encapsulated =
        mlkem768_encapsulate(&keypair.public_key()).expect("ML-KEM-768 encapsulation failed");
    let decapsulated = mlkem768_decapsulate(&keypair.secret_key(), &encapsulated.ciphertext())
        .expect("ML-KEM-768 decapsulation failed");
    assert_eq!(encapsulated.shared_secret(), decapsulated);

    let keypair = mlkem1024_keygen();
    let encapsulated =
        mlkem1024_encapsulate(&keypair.public_key()).expect("ML-KEM-1024 encapsulation failed");
    let decapsulated = mlkem1024_decapsulate(&keypair.secret_key(), &encapsulated.ciphertext())
        .expect("ML-KEM-1024 decapsulation failed");
    assert_eq!(encapsulated.shared_secret(), decapsulated);
}

#[test]
fn fips_204_mldsa_roundtrips_all_parameter_sets() {
    let message = b"Aegis FIPS 204 ML-DSA integration test message";

    let keypair = mldsa44_keygen();
    let signature = mldsa44_sign(&keypair.secret_key(), message).expect("ML-DSA-44 signing failed");
    assert!(mldsa44_verify(&keypair.public_key(), message, &signature));
    assert!(!mldsa44_verify(
        &keypair.public_key(),
        b"wrong message",
        &signature
    ));

    let keypair = mldsa65_keygen();
    let signature = mldsa65_sign(&keypair.secret_key(), message).expect("ML-DSA-65 signing failed");
    assert!(mldsa65_verify(&keypair.public_key(), message, &signature));
    assert!(!mldsa65_verify(
        &keypair.public_key(),
        b"wrong message",
        &signature
    ));

    let keypair = mldsa87_keygen();
    let signature = mldsa87_sign(&keypair.secret_key(), message).expect("ML-DSA-87 signing failed");
    assert!(mldsa87_verify(&keypair.public_key(), message, &signature));
    assert!(!mldsa87_verify(
        &keypair.public_key(),
        b"wrong message",
        &signature
    ));
}

#[test]
fn fips_206_fndsa_roundtrips_all_parameter_sets() {
    let message = b"Aegis FIPS 206 FN-DSA integration test message";

    let keypair = fndsa512_keygen();
    let signature =
        fndsa512_sign(&keypair.secret_key(), message).expect("FN-DSA-512 signing failed");
    assert!(fndsa512_verify(&keypair.public_key(), message, &signature));
    assert!(!fndsa512_verify(
        &keypair.public_key(),
        b"wrong message",
        &signature
    ));

    let keypair = fndsa1024_keygen();
    let signature =
        fndsa1024_sign(&keypair.secret_key(), message).expect("FN-DSA-1024 signing failed");
    assert!(fndsa1024_verify(&keypair.public_key(), message, &signature));
    assert!(!fndsa1024_verify(
        &keypair.public_key(),
        b"wrong message",
        &signature
    ));
}
