use aegis_crypto_core::{
    fndsa::{fndsa512_keygen, fndsa512_sign, fndsa512_verify},
    mldsa::{mldsa65_keygen, mldsa65_sign, mldsa65_verify},
    mlkem::{mlkem512_decapsulate, mlkem512_encapsulate, mlkem512_keygen},
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_mlkem_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("FIPS 203 ML-KEM Operations");

    group.bench_function("mlkem512_keygen", |b| {
        b.iter(|| black_box(mlkem512_keygen()))
    });

    group.bench_function("mlkem512_encapsulate", |b| {
        let keypair = mlkem512_keygen();
        let public_key = keypair.public_key();
        b.iter(|| {
            black_box(
                mlkem512_encapsulate(&public_key).expect("ML-KEM-512 encapsulation should succeed"),
            )
        })
    });

    group.bench_function("mlkem512_decapsulate", |b| {
        let keypair = mlkem512_keygen();
        let public_key = keypair.public_key();
        let secret_key = keypair.secret_key();
        let encapsulated =
            mlkem512_encapsulate(&public_key).expect("ML-KEM-512 encapsulation should succeed");
        let ciphertext = encapsulated.ciphertext();

        b.iter(|| {
            black_box(
                mlkem512_decapsulate(&secret_key, &ciphertext)
                    .expect("ML-KEM-512 decapsulation should succeed"),
            )
        })
    });

    group.finish();
}

fn bench_mldsa_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("FIPS 204 ML-DSA Operations");

    group.bench_function("mldsa65_keygen", |b| b.iter(|| black_box(mldsa65_keygen())));

    group.bench_function("mldsa65_sign", |b| {
        let keypair = mldsa65_keygen();
        let secret_key = keypair.secret_key();
        let message = b"Criterion benchmark message for FIPS 204 ML-DSA";

        b.iter(|| {
            black_box(mldsa65_sign(&secret_key, message).expect("ML-DSA-65 signing should succeed"))
        })
    });

    group.bench_function("mldsa65_verify", |b| {
        let keypair = mldsa65_keygen();
        let public_key = keypair.public_key();
        let secret_key = keypair.secret_key();
        let message = b"Criterion benchmark message for FIPS 204 ML-DSA";
        let signature =
            mldsa65_sign(&secret_key, message).expect("ML-DSA-65 signing should succeed");

        b.iter(|| black_box(mldsa65_verify(&public_key, message, &signature)))
    });

    group.finish();
}

fn bench_fndsa_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("FIPS 206 FN-DSA Operations");

    group.bench_function("fndsa512_keygen", |b| {
        b.iter(|| black_box(fndsa512_keygen()))
    });

    group.bench_function("fndsa512_sign", |b| {
        let keypair = fndsa512_keygen();
        let secret_key = keypair.secret_key();
        let message = b"Criterion benchmark message for FIPS 206 FN-DSA";

        b.iter(|| {
            black_box(
                fndsa512_sign(&secret_key, message).expect("FN-DSA-512 signing should succeed"),
            )
        })
    });

    group.bench_function("fndsa512_verify", |b| {
        let keypair = fndsa512_keygen();
        let public_key = keypair.public_key();
        let secret_key = keypair.secret_key();
        let message = b"Criterion benchmark message for FIPS 206 FN-DSA";
        let signature =
            fndsa512_sign(&secret_key, message).expect("FN-DSA-512 signing should succeed");

        b.iter(|| black_box(fndsa512_verify(&public_key, message, &signature)))
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_mlkem_operations,
    bench_mldsa_operations,
    bench_fndsa_operations
);
criterion_main!(benches);
