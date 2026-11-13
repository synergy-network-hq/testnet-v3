use serde::Serialize;
use std::env;
use std::fs;
use std::hint::black_box;
use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use synergy_testnet::crypto::pqc::{PQCAlgorithm, PQCManager};
use synergy_testnet::transaction::Transaction;

#[derive(Debug)]
struct Args {
    keygen_rounds: usize,
    operation_rounds: usize,
    invalid_rounds: usize,
    source_commit: String,
    output: PathBuf,
}

#[derive(Debug, Serialize)]
struct Distribution {
    average_microseconds: f64,
    p50_microseconds: f64,
    p95_microseconds: f64,
    p99_microseconds: f64,
    max_microseconds: f64,
    operations_per_second: f64,
}

#[derive(Debug, Serialize)]
struct Report {
    benchmark: &'static str,
    runtime_version: &'static str,
    source_commit: String,
    build_profile: &'static str,
    captured_at_epoch: u64,
    operating_system: &'static str,
    architecture: &'static str,
    workload: Workload,
    result: ResultSummary,
    scope: Scope,
}

#[derive(Debug, Serialize)]
struct Workload {
    algorithm: &'static str,
    message_bytes: usize,
    keygen_rounds: usize,
    signing_rounds: usize,
    verification_rounds: usize,
    invalid_signature_rounds: usize,
}

#[derive(Debug, Serialize)]
struct ResultSummary {
    key_generation: Distribution,
    signature_generation: Distribution,
    signature_verification: Distribution,
    transaction_hash: Distribution,
    public_key_bytes: usize,
    private_key_bytes: usize,
    signature_bytes_sample: usize,
    signature_bytes_average: f64,
    signature_bytes_min: usize,
    signature_bytes_p50: f64,
    signature_bytes_p95: f64,
    signature_bytes_p99: f64,
    signature_bytes_max: usize,
    unsigned_transaction_json_bytes: usize,
    signed_transaction_json_bytes: usize,
    signed_transaction_json_overhead_bytes: usize,
    signed_transaction_json_overhead_percent: f64,
    signing_to_hash_cpu_time_ratio: f64,
    sequential_verification_throughput_per_second: f64,
    valid_verifications: usize,
    invalid_signature_rejections: usize,
    integrity_pass: bool,
}

#[derive(Debug, Serialize)]
struct Scope {
    included: Vec<&'static str>,
    excluded: Vec<&'static str>,
    interpretation: &'static str,
}

fn parse_args() -> Result<Args, String> {
    let mut keygen_rounds = 20usize;
    let mut operation_rounds = 1_000usize;
    let mut invalid_rounds = 100usize;
    let mut source_commit = "unknown".to_string();
    let mut output = None;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--keygen-rounds" => {
                keygen_rounds = args
                    .next()
                    .ok_or("--keygen-rounds requires a value")?
                    .parse()
                    .map_err(|_| "invalid --keygen-rounds")?;
            }
            "--operation-rounds" => {
                operation_rounds = args
                    .next()
                    .ok_or("--operation-rounds requires a value")?
                    .parse()
                    .map_err(|_| "invalid --operation-rounds")?;
            }
            "--invalid-rounds" => {
                invalid_rounds = args
                    .next()
                    .ok_or("--invalid-rounds requires a value")?
                    .parse()
                    .map_err(|_| "invalid --invalid-rounds")?;
            }
            "--source-commit" => {
                source_commit = args.next().ok_or("--source-commit requires a value")?;
            }
            "--output" => {
                output = Some(PathBuf::from(
                    args.next().ok_or("--output requires a value")?,
                ));
            }
            "--help" | "-h" => {
                println!(
                    "pqc-benchmark --output PATH [--keygen-rounds N] [--operation-rounds N] [--invalid-rounds N] [--source-commit SHA]"
                );
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    let output = output.ok_or("--output is required")?;
    if keygen_rounds == 0 || operation_rounds == 0 || invalid_rounds == 0 {
        return Err("all round counts must be positive".to_string());
    }
    Ok(Args {
        keygen_rounds,
        operation_rounds,
        invalid_rounds,
        source_commit,
        output,
    })
}

fn percentile(values: &[f64], quantile: f64) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let rank = (sorted.len() - 1) as f64 * quantile;
    let lower = rank.floor() as usize;
    let upper = rank.ceil() as usize;
    if lower == upper {
        sorted[lower]
    } else {
        sorted[lower] + (sorted[upper] - sorted[lower]) * (rank - lower as f64)
    }
}

fn distribution(microseconds: &[f64]) -> Distribution {
    let total: f64 = microseconds.iter().sum();
    let average = total / microseconds.len() as f64;
    Distribution {
        average_microseconds: average,
        p50_microseconds: percentile(microseconds, 0.50),
        p95_microseconds: percentile(microseconds, 0.95),
        p99_microseconds: percentile(microseconds, 0.99),
        max_microseconds: microseconds.iter().copied().fold(0.0, f64::max),
        operations_per_second: 1_000_000.0 / average,
    }
}

fn elapsed_microseconds(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1_000_000.0
}

fn main() -> Result<(), String> {
    let args = parse_args()?;
    let message = vec![0xA5; 256];
    let mut manager = PQCManager::new();

    let (warm_public, warm_private) = manager.generate_keypair(PQCAlgorithm::FNDSA)?;
    let warm_signature = manager.sign(&warm_private, &message)?;
    if !manager.verify(&warm_public, &warm_signature, &message)? {
        return Err("warm-up FN-DSA verification returned false".to_string());
    }

    let mut keygen_times = Vec::with_capacity(args.keygen_rounds);
    let mut last_keypair = None;
    for _ in 0..args.keygen_rounds {
        let started = Instant::now();
        let keypair = manager.generate_keypair(PQCAlgorithm::FNDSA)?;
        keygen_times.push(elapsed_microseconds(started));
        last_keypair = Some(keypair);
    }
    let (public_key, private_key) = last_keypair.ok_or("key generation produced no keypair")?;

    let mut signing_times = Vec::with_capacity(args.operation_rounds);
    let mut signatures = Vec::with_capacity(args.operation_rounds);
    for _ in 0..args.operation_rounds {
        let started = Instant::now();
        let signature = manager.sign(&private_key, black_box(&message))?;
        signing_times.push(elapsed_microseconds(started));
        signatures.push(signature);
    }

    let signature = signatures
        .last()
        .cloned()
        .ok_or("signature generation produced no signature")?;
    let signature_sizes: Vec<usize> = signatures
        .iter()
        .map(|item| item.signature_data.len())
        .collect();
    let signature_sizes_f64: Vec<f64> = signature_sizes.iter().map(|size| *size as f64).collect();
    let mut verification_times = Vec::with_capacity(args.operation_rounds);
    let mut valid_verifications = 0usize;
    for _ in 0..args.operation_rounds {
        let started = Instant::now();
        let verified = manager.verify(&public_key, &signature, black_box(&message))?;
        verification_times.push(elapsed_microseconds(started));
        valid_verifications += usize::from(verified);
    }

    let mut invalid_signature = signature.clone();
    invalid_signature.signature_data[0] ^= 0x01;
    let mut invalid_rejections = 0usize;
    for _ in 0..args.invalid_rounds {
        let rejected = manager
            .verify(&public_key, &invalid_signature, &message)
            .is_err();
        invalid_rejections += usize::from(rejected);
    }

    let mut unsigned_transaction = Transaction::new(
        "synw1pqcbenchmarksender000000000000000000000".to_string(),
        "synw1pqcbenchmarkreceiver000000000000000000".to_string(),
        1,
        0,
        Vec::new(),
        1_000,
        21_000,
        None,
        "fndsa".to_string(),
    );
    let unsigned_bytes = serde_json::to_vec(&unsigned_transaction)
        .map_err(|error| format!("serialize unsigned transaction: {error}"))?;
    let mut hash_times = Vec::with_capacity(args.operation_rounds);
    for _ in 0..args.operation_rounds {
        let started = Instant::now();
        black_box(unsigned_transaction.raw_hash());
        hash_times.push(elapsed_microseconds(started));
    }
    unsigned_transaction.sign_with_public_key(&public_key, &private_key, &mut manager)?;
    let signed_bytes = serde_json::to_vec(&unsigned_transaction)
        .map_err(|error| format!("serialize signed transaction: {error}"))?;

    let key_generation = distribution(&keygen_times);
    let signature_generation = distribution(&signing_times);
    let signature_verification = distribution(&verification_times);
    let transaction_hash = distribution(&hash_times);
    let overhead_bytes = signed_bytes.len().saturating_sub(unsigned_bytes.len());
    let integrity_pass = valid_verifications == args.operation_rounds
        && invalid_rejections == args.invalid_rounds
        && unsigned_transaction.verify_signature(&public_key, &manager);

    let report = Report {
        benchmark: "Synergy FN-DSA-1024 cryptographic operation microbenchmark",
        runtime_version: env!("CARGO_PKG_VERSION"),
        source_commit: args.source_commit,
        build_profile: if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
        captured_at_epoch: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| format!("system clock: {error}"))?
            .as_secs(),
        operating_system: env::consts::OS,
        architecture: env::consts::ARCH,
        workload: Workload {
            algorithm: "FN-DSA-1024",
            message_bytes: message.len(),
            keygen_rounds: args.keygen_rounds,
            signing_rounds: args.operation_rounds,
            verification_rounds: args.operation_rounds,
            invalid_signature_rounds: args.invalid_rounds,
        },
        result: ResultSummary {
            key_generation,
            signature_generation: Distribution {
                operations_per_second: signature_generation.operations_per_second,
                ..signature_generation
            },
            signature_verification: Distribution {
                operations_per_second: signature_verification.operations_per_second,
                ..signature_verification
            },
            transaction_hash,
            public_key_bytes: public_key.key_data.len(),
            private_key_bytes: private_key.key_data.len(),
            signature_bytes_sample: signature.signature_data.len(),
            signature_bytes_average: signature_sizes.iter().sum::<usize>() as f64
                / signature_sizes.len() as f64,
            signature_bytes_min: *signature_sizes.iter().min().unwrap_or(&0),
            signature_bytes_p50: percentile(&signature_sizes_f64, 0.50),
            signature_bytes_p95: percentile(&signature_sizes_f64, 0.95),
            signature_bytes_p99: percentile(&signature_sizes_f64, 0.99),
            signature_bytes_max: *signature_sizes.iter().max().unwrap_or(&0),
            unsigned_transaction_json_bytes: unsigned_bytes.len(),
            signed_transaction_json_bytes: signed_bytes.len(),
            signed_transaction_json_overhead_bytes: overhead_bytes,
            signed_transaction_json_overhead_percent: overhead_bytes as f64
                / unsigned_bytes.len() as f64
                * 100.0,
            signing_to_hash_cpu_time_ratio: signing_times.iter().sum::<f64>()
                / hash_times.iter().sum::<f64>(),
            sequential_verification_throughput_per_second: args.operation_rounds as f64
                / (verification_times.iter().sum::<f64>() / 1_000_000.0),
            valid_verifications,
            invalid_signature_rejections: invalid_rejections,
            integrity_pass,
        },
        scope: Scope {
            included: vec![
                "FN-DSA-1024 key generation",
                "detached signature generation",
                "detached signature verification",
                "invalid signature rejection",
                "actual Synergy transaction JSON serialization overhead",
                "sequential verification throughput",
            ],
            excluded: vec![
                "network submission",
                "consensus",
                "state execution",
                "parallel batch verification",
                "hybrid classical-plus-PQ signatures",
                "energy or hardware performance counters",
            ],
            interpretation: "Single-process release-build cryptographic microbenchmark; not end-to-end network TPS.",
        },
    };

    if let Some(parent) = args.output.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create output directory {}: {error}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(&report)
        .map_err(|error| format!("serialize report: {error}"))?;
    fs::write(&args.output, format!("{json}\n"))
        .map_err(|error| format!("write {}: {error}", args.output.display()))?;
    println!("{json}");
    if !report.result.integrity_pass {
        return Err("PQC integrity checks failed".to_string());
    }
    Ok(())
}
