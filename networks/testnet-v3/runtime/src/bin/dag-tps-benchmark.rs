use serde::Serialize;
use serde_json::json;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use synergy_testnet::dag::DagState;
use synergy_testnet::transaction::Transaction;

const DEFAULT_TRANSACTIONS: usize = 100_000;
const DEFAULT_BATCH_SIZE: usize = 1_000;
const DEFAULT_ROUNDS: usize = 5;
const DEFAULT_TARGET_TPS: f64 = 100_000.0;

#[derive(Debug)]
struct Args {
    transactions: usize,
    batch_size: usize,
    rounds: usize,
    target_tps: f64,
    source_commit: String,
    output: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
struct RoundResult {
    round: usize,
    transactions: usize,
    vertices: usize,
    indexed_transactions: usize,
    elapsed_seconds: f64,
    throughput_tps: f64,
    batch_latency_ms_avg: f64,
    batch_latency_ms_p50: f64,
    batch_latency_ms_p95: f64,
    batch_latency_ms_p99: f64,
    batch_latency_ms_max: f64,
    peak_batch_tps: f64,
    sampled_lookup_microseconds: f64,
    sampled_lookup_found: bool,
    integrity_pass: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        transactions: DEFAULT_TRANSACTIONS,
        batch_size: DEFAULT_BATCH_SIZE,
        rounds: DEFAULT_ROUNDS,
        target_tps: DEFAULT_TARGET_TPS,
        source_commit: "unknown".to_string(),
        output: None,
    };
    let values = env::args().skip(1).collect::<Vec<_>>();
    let mut index = 0usize;
    while index < values.len() {
        let flag = &values[index];
        let value = values
            .get(index + 1)
            .ok_or_else(|| format!("{flag} requires a value"))?;
        match flag.as_str() {
            "--transactions" => {
                args.transactions = value
                    .parse()
                    .map_err(|_| "--transactions must be a positive integer".to_string())?;
            }
            "--batch-size" => {
                args.batch_size = value
                    .parse()
                    .map_err(|_| "--batch-size must be a positive integer".to_string())?;
            }
            "--rounds" => {
                args.rounds = value
                    .parse()
                    .map_err(|_| "--rounds must be a positive integer".to_string())?;
            }
            "--target-tps" => {
                args.target_tps = value
                    .parse()
                    .map_err(|_| "--target-tps must be a positive number".to_string())?;
            }
            "--source-commit" => args.source_commit = value.to_string(),
            "--output" => args.output = Some(PathBuf::from(value)),
            _ => return Err(format!("unknown argument: {flag}")),
        }
        index += 2;
    }
    if args.transactions == 0 || args.batch_size == 0 || args.rounds == 0 || args.target_tps <= 0.0
    {
        return Err(
            "transactions, batch size, rounds, and target TPS must be positive".to_string(),
        );
    }
    Ok(args)
}

fn percentile(values: &[f64], fraction: f64) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    if sorted.len() == 1 {
        return sorted[0];
    }
    let position = (sorted.len() - 1) as f64 * fraction;
    let lower = position.floor() as usize;
    let upper = position.ceil() as usize;
    if lower == upper {
        sorted[lower]
    } else {
        let weight = position - lower as f64;
        sorted[lower] + ((sorted[upper] - sorted[lower]) * weight)
    }
}

fn mean(values: &[f64]) -> f64 {
    values.iter().sum::<f64>() / values.len() as f64
}

fn benchmark_transaction(nonce: u64) -> Transaction {
    let mut tx = Transaction::new(
        "synw17nh265ug2fgc8guv2ad7tt8kv0wlhesxndl8".to_string(),
        "synw1zp7cxme7xm838663yrd43lxtxlw0ck90z4am".to_string(),
        1,
        nonce,
        vec![0xA5; 1_280],
        1_000,
        21_000,
        Some(format!("dag-benchmark-independent-{nonce}")),
        "mldsa87".to_string(),
    );
    tx.signer_public_key = vec![0x5A; 1_793];
    tx.timestamp = 1_784_321_600 + nonce;
    tx
}

fn main() -> Result<(), String> {
    let args = parse_args()?;
    let transactions = (0..args.transactions)
        .map(|nonce| benchmark_transaction(nonce as u64))
        .collect::<Vec<_>>();
    let sample_transaction_json_bytes = serde_json::to_vec(&transactions[0])
        .map_err(|error| format!("serialize sample transaction: {error}"))?
        .len();
    let mut rounds = Vec::with_capacity(args.rounds);

    for round in 1..=args.rounds {
        let mut dag = DagState::default();
        let mut batch_latency_ms = Vec::new();
        let mut peak_batch_tps = 0.0f64;
        let started = Instant::now();
        for (batch_index, batch) in transactions.chunks(args.batch_size).enumerate() {
            let batch_started = Instant::now();
            dag.create_proposal_vertex(
                batch,
                "synv11cl92kxcx4jyzusecqydrxc8aj3hsgscrvtu",
                (batch_index + 1) as u64,
            )
            .ok_or_else(|| format!("round {round} batch {batch_index} produced no DAG vertex"))?;
            let batch_seconds = batch_started.elapsed().as_secs_f64();
            batch_latency_ms.push(batch_seconds * 1_000.0);
            peak_batch_tps = peak_batch_tps.max(batch.len() as f64 / batch_seconds.max(1e-9));
        }
        let elapsed_seconds = started.elapsed().as_secs_f64();
        let sample_hash = transactions[args.transactions / 2].hash();
        let lookup_started = Instant::now();
        let lookup = dag.transaction_status_json(&sample_hash);
        let sampled_lookup_microseconds = lookup_started.elapsed().as_secs_f64() * 1_000_000.0;
        let sampled_lookup_found = lookup
            .get("found")
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
        let expected_vertices = args.transactions.div_ceil(args.batch_size);
        let integrity_pass = dag.transaction_index.len() == args.transactions
            && dag.vertices.len() == expected_vertices
            && sampled_lookup_found;
        let result = RoundResult {
            round,
            transactions: args.transactions,
            vertices: dag.vertices.len(),
            indexed_transactions: dag.transaction_index.len(),
            elapsed_seconds,
            throughput_tps: args.transactions as f64 / elapsed_seconds.max(1e-9),
            batch_latency_ms_avg: mean(&batch_latency_ms),
            batch_latency_ms_p50: percentile(&batch_latency_ms, 0.50),
            batch_latency_ms_p95: percentile(&batch_latency_ms, 0.95),
            batch_latency_ms_p99: percentile(&batch_latency_ms, 0.99),
            batch_latency_ms_max: batch_latency_ms.iter().copied().fold(0.0, f64::max),
            peak_batch_tps,
            sampled_lookup_microseconds,
            sampled_lookup_found,
            integrity_pass,
        };
        eprintln!(
            "round={} tx={} vertices={} elapsed={:.6}s throughput={:.2} tx/s integrity={}",
            result.round,
            result.transactions,
            result.vertices,
            result.elapsed_seconds,
            result.throughput_tps,
            result.integrity_pass
        );
        rounds.push(result);
    }

    let throughputs = rounds
        .iter()
        .map(|round| round.throughput_tps)
        .collect::<Vec<_>>();
    let lookup_us = rounds
        .iter()
        .map(|round| round.sampled_lookup_microseconds)
        .collect::<Vec<_>>();
    let average_tps = mean(&throughputs);
    let median_tps = percentile(&throughputs, 0.50);
    let sustained_min_tps = throughputs.iter().copied().fold(f64::INFINITY, f64::min);
    let integrity_pass = rounds.iter().all(|round| round.integrity_pass);
    let pass = integrity_pass && median_tps >= args.target_tps;
    let captured_at_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock error: {error}"))?
        .as_secs();
    let report = json!({
        "benchmark": "Synergy DAG prevalidated vertex construction and transaction indexing",
        "captured_at_epoch": captured_at_epoch,
        "runtime_version": env!("CARGO_PKG_VERSION"),
        "source_commit": args.source_commit,
        "build_profile": if cfg!(debug_assertions) { "debug" } else { "release" },
        "architecture": env::consts::ARCH,
        "operating_system": env::consts::OS,
        "logical_parallelism": std::thread::available_parallelism().map(|value| value.get()).unwrap_or(1),
        "workload": {
            "transactions_per_round": args.transactions,
            "batch_size": args.batch_size,
            "rounds": args.rounds,
            "independent_transactions": true,
            "signature_algorithm_shape": "FN-DSA-1024 sized placeholder: 1280-byte signature and 1793-byte public key",
            "sample_transaction_json_bytes": sample_transaction_json_bytes,
            "estimated_transaction_json_bytes_per_round": sample_transaction_json_bytes.saturating_mul(args.transactions),
        },
        "scope": {
            "included": ["legacy transaction hash", "DAG vertex construction", "availability certificate", "full transaction clone into vertex", "transaction hash index insertion", "sample transaction lookup"],
            "excluded": ["PQC signature generation", "PQC signature verification", "RPC/TLS", "network gossip", "consensus quorum", "state execution", "disk persistence"],
            "interpretation": "Component capacity for prevalidated transactions entering the in-memory proposal DAG; not end-to-end network TPS.",
        },
        "target_tps": args.target_tps,
        "result": {
            "average_tps": average_tps,
            "p50_tps": median_tps,
            "p95_tps": percentile(&throughputs, 0.95),
            "p99_tps": percentile(&throughputs, 0.99),
            "peak_tps": throughputs.iter().copied().fold(0.0, f64::max),
            "sustained_min_tps": sustained_min_tps,
            "lookup_microseconds_avg": mean(&lookup_us),
            "lookup_microseconds_p95": percentile(&lookup_us, 0.95),
            "integrity_pass": integrity_pass,
            "pass": pass,
            "pass_criterion": "release build, all integrity checks pass, and median throughput >= target TPS",
        },
        "rounds": rounds,
    });
    let encoded = serde_json::to_string_pretty(&report)
        .map_err(|error| format!("serialize benchmark report: {error}"))?
        + "\n";
    if let Some(path) = args.output {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                format!("create output directory {}: {error}", parent.display())
            })?;
        }
        fs::write(&path, encoded.as_bytes())
            .map_err(|error| format!("write report {}: {error}", path.display()))?;
    }
    print!("{encoded}");
    if pass {
        Ok(())
    } else {
        Err(format!(
            "DAG benchmark did not meet {:.0} TPS target (median {:.2} TPS, integrity={integrity_pass})",
            args.target_tps, median_tps
        ))
    }
}
