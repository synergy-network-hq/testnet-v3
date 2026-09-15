#[allow(unused_imports)]
use criterion::{criterion_group, criterion_main, Criterion};
#[allow(unused_imports)]
use std::hint::black_box;

#[cfg(feature = "classicmceliece")]
use aegis_crypto_core::{
    classicmceliece_decapsulate, classicmceliece_encapsulate, classicmceliece_keygen,
};

#[cfg(feature = "classicmceliece")]
fn bench_classicmceliece_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("Classic McEliece KEM Operations (Experimental)");

    // Key generation benchmark (with larger stack)
    group.bench_function("classicmceliece_keygen", |b| {
        b.iter(|| {
            let keypair = black_box(classicmceliece_keygen());
            black_box(keypair)
        })
    });

    // Encapsulation benchmark
    group.bench_function("classicmceliece_encapsulate", |b| {
        let keypair = classicmceliece_keygen();
        let public_key = keypair.public_key();
        b.iter(|| {
            let encapsulated = black_box(classicmceliece_encapsulate(&public_key));
            black_box(encapsulated)
        })
    });

    // Decapsulation benchmark
    group.bench_function("classicmceliece_decapsulate", |b| {
        let keypair = classicmceliece_keygen();
        let public_key = keypair.public_key();
        let secret_key = keypair.secret_key();
        let encapsulated =
            classicmceliece_encapsulate(&public_key).expect("Encapsulation should succeed");
        let ciphertext = encapsulated.ciphertext();

        b.iter(|| {
            let decapsulated = black_box(classicmceliece_decapsulate(&secret_key, &ciphertext));
            black_box(decapsulated)
        })
    });

    group.finish();
}

#[cfg(feature = "classicmceliece")]
criterion_group!(classicmceliece_benches, bench_classicmceliece_operations);

#[cfg(feature = "classicmceliece")]
criterion_main!(classicmceliece_benches);

#[cfg(not(feature = "classicmceliece"))]
fn main() {
    println!("Classic McEliece benchmarks are disabled by default.");
    println!(
        "Enable with: cargo bench --features classicmceliece --bench classicmceliece_benchmarks"
    );
}
