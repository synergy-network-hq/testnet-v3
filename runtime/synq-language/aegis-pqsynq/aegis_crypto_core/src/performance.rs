//! Performance measurement utilities for cryptographic operations.

use std::time::{Duration, Instant};

/// Performance measurement results
#[derive(Debug, Clone)]
pub struct PerformanceResult {
    pub operation: String,
    pub algorithm: String,
    pub variant: String,
    pub duration: Duration,
    pub iterations: usize,
    pub average_duration: Duration,
}

/// Performance targets from the specification
pub const PERFORMANCE_TARGETS: &[(&str, Duration)] = &[
    ("key_generation", Duration::from_millis(100)),
    ("encapsulation", Duration::from_millis(50)),
    ("decapsulation", Duration::from_millis(50)),
    ("signature_generation", Duration::from_millis(100)),
    ("signature_verification", Duration::from_millis(50)),
];

/// Measure performance of a cryptographic operation
pub fn measure_performance<F, T>(
    operation_name: &str,
    algorithm: &str,
    variant: &str,
    iterations: usize,
    operation: F,
) -> PerformanceResult
where
    F: Fn() -> T,
{
    let start = Instant::now();

    for _ in 0..iterations {
        let _result = operation();
    }

    let total_duration = start.elapsed();
    let average_duration = total_duration / (iterations as u32);

    PerformanceResult {
        operation: operation_name.to_string(),
        algorithm: algorithm.to_string(),
        variant: variant.to_string(),
        duration: total_duration,
        iterations,
        average_duration,
    }
}

/// Check if performance meets target
pub fn meets_target(result: &PerformanceResult, target: Duration) -> bool {
    result.average_duration <= target
}

/// Format duration for display
pub fn format_duration(duration: Duration) -> String {
    let millis = duration.as_millis();
    if millis > 0 {
        format!("{}ms", millis)
    } else {
        let micros = duration.as_micros();
        format!("{}μs", micros)
    }
}

/// Run comprehensive performance tests
#[cfg(all(
    feature = "mlkem",
    feature = "hqc",
    feature = "mldsa",
    feature = "fndsa"
))]
pub fn run_performance_tests() -> Vec<PerformanceResult> {
    use crate::{
        fndsa_keygen, fndsa_sign, fndsa_verify, hqc_decapsulate, hqc_encapsulate, hqc_keygen,
        mldsa_keygen, mldsa_sign, mldsa_verify, mlkem_decapsulate, mlkem_encapsulate, mlkem_keygen,
    };

    let mut results = Vec::new();
    let iterations = 10; // Number of iterations for averaging (reduced for testing)

    // Test FIPS 203 ML-KEM operations
    results.push(measure_performance(
        "key_generation",
        "ML-KEM",
        "ML-KEM-768",
        iterations,
        mlkem_keygen,
    ));

    let mlkem_keypair = mlkem_keygen();
    let mlkem_pk = mlkem_keypair.public_key();
    let mlkem_sk = mlkem_keypair.secret_key();

    results.push(measure_performance(
        "encapsulation",
        "ML-KEM",
        "ML-KEM-768",
        iterations,
        || mlkem_encapsulate(&mlkem_pk),
    ));

    let mlkem_encapsulated = mlkem_encapsulate(&mlkem_pk).expect("encapsulation should succeed");
    let mlkem_ct = mlkem_encapsulated.ciphertext();

    results.push(measure_performance(
        "decapsulation",
        "ML-KEM",
        "ML-KEM-768",
        iterations,
        || mlkem_decapsulate(&mlkem_sk, &mlkem_ct),
    ));

    // Test HQC operations
    results.push(measure_performance(
        "key_generation",
        "HQC",
        "HQC-256",
        iterations,
        hqc_keygen,
    ));

    let hqc_keypair = hqc_keygen();
    let hqc_pk = hqc_keypair.public_key();
    let hqc_sk = hqc_keypair.secret_key();

    results.push(measure_performance(
        "encapsulation",
        "HQC",
        "HQC-256",
        iterations,
        || hqc_encapsulate(&hqc_pk),
    ));

    let hqc_encapsulated = hqc_encapsulate(&hqc_pk).expect("Encapsulation should succeed");
    let hqc_ct = hqc_encapsulated.ciphertext();

    results.push(measure_performance(
        "decapsulation",
        "HQC",
        "HQC-256",
        iterations,
        || hqc_decapsulate(&hqc_sk, &hqc_ct),
    ));

    // Test FIPS 204 ML-DSA operations
    results.push(measure_performance(
        "key_generation",
        "ML-DSA",
        "ML-DSA-65",
        iterations,
        mldsa_keygen,
    ));

    let mldsa_keypair = mldsa_keygen();
    let mldsa_pk = mldsa_keypair.public_key();
    let mldsa_sk = mldsa_keypair.secret_key();
    let message = b"Performance test message for ML-DSA";

    results.push(measure_performance(
        "signature_generation",
        "ML-DSA",
        "ML-DSA-65",
        iterations,
        || mldsa_sign(&mldsa_sk, message),
    ));

    let mldsa_signature = mldsa_sign(&mldsa_sk, message).expect("ML-DSA signing should succeed");

    results.push(measure_performance(
        "signature_verification",
        "ML-DSA",
        "ML-DSA-65",
        iterations,
        || mldsa_verify(&mldsa_pk, message, &mldsa_signature),
    ));

    // Test FIPS 206 / Falcon FN-DSA operations
    results.push(measure_performance(
        "key_generation",
        "FN-DSA",
        "FN-DSA-512",
        iterations,
        fndsa_keygen,
    ));

    let fndsa_keypair = fndsa_keygen();
    let fndsa_pk = fndsa_keypair.public_key();
    let fndsa_sk = fndsa_keypair.secret_key();
    let message = b"Performance test message for FN-DSA";

    results.push(measure_performance(
        "signature_generation",
        "FN-DSA",
        "FN-DSA-512",
        iterations,
        || fndsa_sign(&fndsa_sk, message),
    ));

    let fndsa_signature = fndsa_sign(&fndsa_sk, message).expect("FN-DSA signing should succeed");

    results.push(measure_performance(
        "signature_verification",
        "FN-DSA",
        "FN-DSA-512",
        iterations,
        || fndsa_verify(&fndsa_pk, message, &fndsa_signature),
    ));

    results
}

/// Print performance report
pub fn print_performance_report(results: &[PerformanceResult]) {
    println!("=== PERFORMANCE BENCHMARK REPORT ===");
    println!("Targets:");
    for (operation, target) in PERFORMANCE_TARGETS {
        println!("  {}: {}", operation, format_duration(*target));
    }
    println!();

    println!("Results:");
    for result in results {
        let target = PERFORMANCE_TARGETS
            .iter()
            .find(|(op, _)| *op == result.operation)
            .map(|(_, duration)| *duration)
            .unwrap_or(Duration::from_millis(100));

        let meets = meets_target(result, target);
        let status = if meets { "✅" } else { "❌" };

        println!(
            "{} {} {} {}: {} (target: {})",
            status,
            result.algorithm,
            result.variant,
            result.operation,
            format_duration(result.average_duration),
            format_duration(target)
        );
    }

    println!();
    println!("Summary:");
    let total_tests = results.len();
    let passed_tests = results
        .iter()
        .filter(|result| {
            let target = PERFORMANCE_TARGETS
                .iter()
                .find(|(op, _)| *op == result.operation)
                .map(|(_, duration)| *duration)
                .unwrap_or(Duration::from_millis(100));
            meets_target(result, target)
        })
        .count();

    println!("  Tests: {}/{} passed", passed_tests, total_tests);
    println!(
        "  Success rate: {:.1}%",
        ((passed_tests as f64) / (total_tests as f64)) * 100.0
    );
}
