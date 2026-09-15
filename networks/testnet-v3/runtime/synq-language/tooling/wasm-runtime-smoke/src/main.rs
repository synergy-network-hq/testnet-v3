fn main() {
    #[cfg(not(feature = "pqc-aegis"))]
    {
        println!(
            "WASM runtime smoke SKIP: restore aegis-pqsynq/pqsynq and rebuild with feature `pqc-aegis`"
        );
    }

    #[cfg(feature = "pqc-aegis")]
    run_pqc_smoke();
}

#[cfg(feature = "pqc-aegis")]
fn run_pqc_smoke() {
    use pqsynq::{DigitalSignature, Kem, KeyEncapsulation, Sign};

    let message = b"synq-wasm-runtime-smoke";

    let mldsa = Sign::mldsa65();
    let (mldsa_pk, mldsa_sk) = mldsa.keygen().expect("ML-DSA keygen should succeed");
    let mldsa_sig = mldsa
        .detached_sign(message, &mldsa_sk)
        .expect("ML-DSA detached sign should succeed");
    let mldsa_valid = mldsa
        .verify_detached(message, &mldsa_sig, &mldsa_pk)
        .expect("ML-DSA detached verify should succeed");
    assert!(mldsa_valid, "ML-DSA detached signature must validate");

    let fndsa = Sign::fndsa512();
    let (fndsa_pk, fndsa_sk) = fndsa.keygen().expect("FN-DSA keygen should succeed");
    let fndsa_sig = fndsa
        .detached_sign(message, &fndsa_sk)
        .expect("FN-DSA detached sign should succeed");
    let fndsa_valid = fndsa
        .verify_detached(message, &fndsa_sig, &fndsa_pk)
        .expect("FN-DSA detached verify should succeed");
    assert!(fndsa_valid, "FN-DSA detached signature must validate");

    let mlkem = Kem::mlkem768();
    let (mlkem_pk, mlkem_sk) = mlkem.keygen().expect("ML-KEM keygen should succeed");
    let (mlkem_ct, mlkem_ss) = mlkem
        .encapsulate(&mlkem_pk)
        .expect("ML-KEM encapsulate should succeed");
    let mlkem_recovered_ss = mlkem
        .decapsulate(&mlkem_ct, &mlkem_sk)
        .expect("ML-KEM decapsulate should succeed");
    assert_eq!(
        mlkem_ss, mlkem_recovered_ss,
        "ML-KEM shared secret mismatch"
    );

    let hqckem = Kem::hqckem128();
    let (hq_pk, hq_sk) = hqckem.keygen().expect("HQC-KEM keygen should succeed");
    let (hq_ct, hq_ss) = hqckem
        .encapsulate(&hq_pk)
        .expect("HQC-KEM encapsulate should succeed");
    let hq_recovered_ss = hqckem
        .decapsulate(&hq_ct, &hq_sk)
        .expect("HQC-KEM decapsulate should succeed");
    assert_eq!(hq_ss, hq_recovered_ss, "HQC shared secret mismatch");

    println!("WASM runtime smoke PASS");
}
