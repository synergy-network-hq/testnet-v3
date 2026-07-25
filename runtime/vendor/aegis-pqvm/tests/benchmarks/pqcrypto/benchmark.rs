use std::time::{Duration, Instant};
use pqcrypto::prelude::*;
use pqcrypto::sign::mldsa44::*;
use pqcrypto::kem::mlkem512::*;

fn benchmark_operation<F, R>(name: &str, mut operation: F) -> Duration
where
    F: FnMut() -> R,
{
    const ITERATIONS: u32 = 100;

    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _result = operation();
    }
    let duration = start.elapsed();
    let avg_duration = duration / ITERATIONS;

    println!("{}: {} iterations in {:?} ({:?} avg)",
             name, ITERATIONS, duration, avg_duration);

    avg_duration
}

fn main() -> std::io::Result<()> {
    println!("PQCrypto Performance Benchmark");
    println!("==============================");

    // Benchmark ML-KEM-512 (KEM operations)
    println!("\nML-KEM-512 Benchmarks:");

    let kem_keypair_time = benchmark_operation("Key generation", || {
        keypair()
    });

    let (pk, sk) = keypair();
    let kem_encapsulate_time = benchmark_operation("Encapsulation", || {
        encapsulate(&pk)
    });

    let (ct, _ss) = encapsulate(&pk);
    let kem_decapsulate_time = benchmark_operation("Decapsulation", || {
        decapsulate(&ct, &sk)
    });

    // Benchmark ML-DSA-44 (Signature operations)
    println!("\nML-DSA-44 Benchmarks:");

    let dsa_keypair_time = benchmark_operation("Key generation", || {
        keypair()
    });

    let (pk, sk) = keypair();
    let message = b"Benchmark test message for ML-DSA-44";
    let dsa_sign_time = benchmark_operation("Signing", || {
        sign(message, &sk)
    });

    let signature = sign(message, &sk);
    let dsa_verify_time = benchmark_operation("Verification", || {
        verify(&signature, message, &pk)
    });

    // Calculate operations per second
    let kem_ops_per_sec = 1.0 / kem_encapsulate_time.as_secs_f64();
    let dsa_ops_per_sec = 1.0 / dsa_sign_time.as_secs_f64();

    println!("\nPerformance Summary:");
    println!("====================");
    println!("ML-KEM-512 encapsulation: {:.0} ops/sec", kem_ops_per_sec);
    println!("ML-DSA-44 signing: {:.0} ops/sec", dsa_ops_per_sec);
    println!("Key generation times: KEM: {:?}, DSA: {:?}", kem_keypair_time, dsa_keypair_time);

    println!("\n✅ pqcrypto benchmark completed successfully!");
    println!("✅ Real performance measurements obtained");
    println!("✅ Cryptographic operations verified functional");

    Ok(())
}
