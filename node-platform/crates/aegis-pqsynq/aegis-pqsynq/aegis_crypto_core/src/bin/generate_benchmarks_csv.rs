use std::fs::{create_dir_all, File};
use std::hint::black_box;
use std::io::Write;
use std::time::Instant;

use aegis_crypto_core::{
    fndsa::{fndsa1024_keygen, fndsa512_keygen, fndsa512_sign, fndsa512_verify},
    mldsa::{mldsa44_keygen, mldsa65_keygen, mldsa65_sign, mldsa65_verify},
    mlkem::{mlkem512_decapsulate, mlkem512_encapsulate, mlkem512_keygen, mlkem768_keygen},
};

type BenchmarkRow = (String, String, String, f64, f64, u64);

fn main() {
    let iterations = std::env::args()
        .nth(1)
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(1_000);

    let mut results = Vec::new();

    push_mlkem_results(&mut results, iterations);
    push_mldsa_results(&mut results, iterations);
    push_fndsa_results(&mut results, iterations);

    create_dir_all("../../performance_results").expect("create performance_results directory");
    write_csv(
        &results,
        "../../performance_results/pqrust_fips_benchmarks.csv",
    );

    println!("Generated FIPS benchmark CSV for ML-KEM, ML-DSA, and FN-DSA.");
}

fn push_mlkem_results(results: &mut Vec<BenchmarkRow>, iterations: u64) {
    let (mean, std_dev) = measure_time(
        || {
            black_box(mlkem512_keygen());
        },
        iterations,
    );
    results.push(row("ML-KEM", "512", "keygen", mean, std_dev, iterations));

    let keypair = mlkem512_keygen();
    let public_key = keypair.public_key();
    let secret_key = keypair.secret_key();
    let encapsulated =
        mlkem512_encapsulate(&public_key).expect("ML-KEM-512 encapsulation should succeed");
    let ciphertext = encapsulated.ciphertext();

    let (mean, std_dev) = measure_time(
        || {
            black_box(
                mlkem512_encapsulate(&public_key).expect("ML-KEM-512 encapsulation should succeed"),
            );
        },
        iterations,
    );
    results.push(row(
        "ML-KEM",
        "512",
        "encapsulate",
        mean,
        std_dev,
        iterations,
    ));

    let (mean, std_dev) = measure_time(
        || {
            black_box(
                mlkem512_decapsulate(&secret_key, &ciphertext)
                    .expect("ML-KEM-512 decapsulation should succeed"),
            );
        },
        iterations,
    );
    results.push(row(
        "ML-KEM",
        "512",
        "decapsulate",
        mean,
        std_dev,
        iterations,
    ));

    let (mean, std_dev) = measure_time(
        || {
            black_box(mlkem768_keygen());
        },
        iterations,
    );
    results.push(row("ML-KEM", "768", "keygen", mean, std_dev, iterations));
}

fn push_mldsa_results(results: &mut Vec<BenchmarkRow>, iterations: u64) {
    let (mean, std_dev) = measure_time(
        || {
            black_box(mldsa44_keygen());
        },
        iterations,
    );
    results.push(row("ML-DSA", "44", "keygen", mean, std_dev, iterations));

    let keypair = mldsa65_keygen();
    let public_key = keypair.public_key();
    let secret_key = keypair.secret_key();
    let message = b"Aegis benchmark message for FIPS 204 ML-DSA";
    let signature = mldsa65_sign(&secret_key, message).expect("ML-DSA-65 signing should succeed");

    let (mean, std_dev) = measure_time(
        || {
            black_box(
                mldsa65_sign(&secret_key, message).expect("ML-DSA-65 signing should succeed"),
            );
        },
        iterations,
    );
    results.push(row("ML-DSA", "65", "sign", mean, std_dev, iterations));

    let (mean, std_dev) = measure_time(
        || {
            black_box(mldsa65_verify(&public_key, message, &signature));
        },
        iterations,
    );
    results.push(row("ML-DSA", "65", "verify", mean, std_dev, iterations));
}

fn push_fndsa_results(results: &mut Vec<BenchmarkRow>, iterations: u64) {
    let (mean, std_dev) = measure_time(
        || {
            black_box(fndsa1024_keygen());
        },
        iterations,
    );
    results.push(row("FN-DSA", "1024", "keygen", mean, std_dev, iterations));

    let keypair = fndsa512_keygen();
    let public_key = keypair.public_key();
    let secret_key = keypair.secret_key();
    let message = b"Aegis benchmark message for FIPS 206 FN-DSA";
    let signature = fndsa512_sign(&secret_key, message).expect("FN-DSA-512 signing should succeed");

    let (mean, std_dev) = measure_time(
        || {
            black_box(
                fndsa512_sign(&secret_key, message).expect("FN-DSA-512 signing should succeed"),
            );
        },
        iterations,
    );
    results.push(row("FN-DSA", "512", "sign", mean, std_dev, iterations));

    let (mean, std_dev) = measure_time(
        || {
            black_box(fndsa512_verify(&public_key, message, &signature));
        },
        iterations,
    );
    results.push(row("FN-DSA", "512", "verify", mean, std_dev, iterations));
}

fn measure_time<F>(mut f: F, iterations: u64) -> (f64, f64)
where
    F: FnMut(),
{
    let mut times = Vec::with_capacity(iterations as usize);
    for _ in 0..iterations {
        let start = Instant::now();
        f();
        times.push(start.elapsed().as_nanos() as f64);
    }

    let mean = times.iter().sum::<f64>() / times.len() as f64;
    let variance = times.iter().map(|time| (time - mean).powi(2)).sum::<f64>() / times.len() as f64;
    (mean, variance.sqrt())
}

fn row(
    algorithm: &str,
    variant: &str,
    operation: &str,
    mean: f64,
    std_dev: f64,
    iterations: u64,
) -> BenchmarkRow {
    (
        algorithm.to_string(),
        variant.to_string(),
        operation.to_string(),
        mean,
        std_dev,
        iterations,
    )
}

fn write_csv(results: &[BenchmarkRow], path: &str) {
    let mut file = File::create(path).expect("create benchmark CSV");
    writeln!(
        file,
        "implementation,algorithm,variant,operation,mean_time_ns,std_dev_ns,iterations"
    )
    .expect("write benchmark CSV header");

    for (algorithm, variant, operation, mean, std_dev, iterations) in results {
        writeln!(
            file,
            "pqrust,{algorithm},{variant},{operation},{mean:.2},{std_dev:.2},{iterations}"
        )
        .expect("write benchmark CSV row");
    }
}
