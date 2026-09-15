use std::env;
use std::fs::{self, File};
use std::hint::black_box;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use aegis_pqvm::pqc::signatures::fndsa::fndsa1024;
use aegis_pqvm::pqc::signatures::mldsa::{mldsa65, mldsa87};
use pqrust_traits::sign::{
    DetachedSignature as DirectDetachedSignature, PublicKey as DirectPublicKey,
    SecretKey as DirectSecretKey,
};
use synergy_testnet::aegis_tx_tool::{
    sign_with_new_aegis_transaction_key, validate_legacy_aegis_carrier_transaction,
    verify_aegis_submission_envelope, AegisTxBuildOptions, AegisTxSubmissionEnvelope,
};
use synergy_testnet::consensus::coordinated_admission::{
    coordinated_dag_frontier_root, coordinated_transaction_admission_root,
    coordinated_transaction_ids,
};
use synergy_testnet::consensus::coordinated_round_robin::{
    CoordinatedConsensusVerifier, CoordinatedProposal, CoordinatedRoundRobinConfig,
    CoordinatorCommit, ProducerAssignment, COORDINATED_ASSIGNMENT_DOMAIN,
    COORDINATED_COMMIT_DOMAIN, COORDINATED_ROUND_ROBIN_V1,
};
use synergy_testnet::consensus_parameters::ConsensusParameterRoot;
use synergy_testnet::crypto::aegis_pqvm::{
    AegisPqvmSigner, AegisPqvmVerifier, SYNERGY_BLOCK_V1, SYNERGY_P2P_HANDSHAKE_V1, SYNERGY_TX_V1,
};
use synergy_testnet::crypto::pqc::{PQCAlgorithm, PQCManager};
use synergy_testnet::dag_mempool::compute_tx_order_root;
use synergy_testnet::p2p::messages::{
    validate_coordinated_consensus_message_size, CoordinatedCommittedBlockPackage,
    CoordinatedConsensusMessage, NetworkMessage,
    MAX_COORDINATED_CONSENSUS_BLOCK_PACKAGE_FRAME_BYTES,
};
use synergy_testnet::synergy_types::{
    AegisPqKeyId, AegisPqKeyRole, AegisPqSignature, Block as TypedBlock, BlockHeader,
    CanonicalSerialize, ChainId, ClusterId, Epoch, Hash, Height, NetworkId, PeerHello, Round,
    Transaction as TypedTransaction, UmaId, ValidatorId, ValidatorRecord, ValidatorSet,
    ValidatorStatus,
};
use synergy_testnet::transaction::Transaction as LegacyTransaction;

#[derive(Debug)]
struct Args {
    suite: String,
    output: PathBuf,
    environment_id: String,
    source_commit: String,
    keygen_iterations: usize,
    operation_iterations: usize,
    warmup_iterations: usize,
}

#[derive(Debug)]
struct Observation {
    valid: bool,
    result: String,
    public_key_bytes: usize,
    private_key_bytes: usize,
    signature_bytes: usize,
    ciphertext_bytes: usize,
    shared_secret_bytes: usize,
    unsigned_serialized_bytes: usize,
    serialized_bytes: usize,
    authentication_bytes: usize,
    item_count: usize,
    work_units: usize,
    notes: String,
}

impl Default for Observation {
    fn default() -> Self {
        Self {
            valid: false,
            result: String::new(),
            public_key_bytes: 0,
            private_key_bytes: 0,
            signature_bytes: 0,
            ciphertext_bytes: 0,
            shared_secret_bytes: 0,
            unsigned_serialized_bytes: 0,
            serialized_bytes: 0,
            authentication_bytes: 0,
            item_count: 0,
            work_units: 1,
            notes: String::new(),
        }
    }
}

struct SampleWriter {
    writer: BufWriter<File>,
    run_id: String,
    environment_id: String,
    source_commit: String,
}

#[derive(Clone, Copy)]
struct ResourceSnapshot {
    cpu_ns: u64,
    max_rss_bytes: u64,
}

fn parse_args() -> Result<Args, String> {
    let mut suite = "all".to_string();
    let mut output = None;
    let mut environment_id = None;
    let mut source_commit = None;
    let mut keygen_iterations = 30usize;
    let mut operation_iterations = 200usize;
    let mut warmup_iterations = 10usize;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--suite" => suite = args.next().ok_or("--suite requires a value")?,
            "--output" => {
                output = Some(PathBuf::from(
                    args.next().ok_or("--output requires a value")?,
                ))
            }
            "--environment-id" => {
                environment_id = Some(args.next().ok_or("--environment-id requires a value")?)
            }
            "--source-commit" => {
                source_commit = Some(args.next().ok_or("--source-commit requires a value")?)
            }
            "--keygen-iterations" => {
                keygen_iterations =
                    parse_positive(&args.next().ok_or("--keygen-iterations requires a value")?)?;
            }
            "--operation-iterations" => {
                operation_iterations = parse_positive(
                    &args
                        .next()
                        .ok_or("--operation-iterations requires a value")?,
                )?;
            }
            "--warmup-iterations" => {
                warmup_iterations =
                    parse_positive(&args.next().ok_or("--warmup-iterations requires a value")?)?;
            }
            "--help" | "-h" => {
                println!("synergy-aegis-bench --output FILE --environment-id ID --source-commit SHA [--suite all|primitive|aegis|lifecycle|protocol|load] [--keygen-iterations N] [--operation-iterations N] [--warmup-iterations N]");
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    let suite_is_valid = matches!(
        suite.as_str(),
        "all" | "primitive" | "aegis" | "lifecycle" | "protocol" | "load"
    );
    if !suite_is_valid {
        return Err(format!("unsupported suite: {suite}"));
    }
    Ok(Args {
        suite,
        output: output.ok_or("--output is required")?,
        environment_id: environment_id.ok_or("--environment-id is required")?,
        source_commit: source_commit.ok_or("--source-commit is required")?,
        keygen_iterations,
        operation_iterations,
        warmup_iterations,
    })
}

fn parse_positive(value: &str) -> Result<usize, String> {
    let parsed = value
        .parse::<usize>()
        .map_err(|_| format!("invalid positive integer: {value}"))?;
    if parsed == 0 {
        Err("iteration counts must be positive".to_string())
    } else {
        Ok(parsed)
    }
}

fn unix_nanos() -> Result<u128, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .map_err(|error| format!("system clock: {error}"))
}

#[cfg(unix)]
fn resources() -> ResourceSnapshot {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    let status = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    if status != 0 {
        return ResourceSnapshot {
            cpu_ns: 0,
            max_rss_bytes: 0,
        };
    }
    let usage = unsafe { usage.assume_init() };
    let user_ns = usage.ru_utime.tv_sec.max(0) as u64 * 1_000_000_000
        + usage.ru_utime.tv_usec.max(0) as u64 * 1_000;
    let system_ns = usage.ru_stime.tv_sec.max(0) as u64 * 1_000_000_000
        + usage.ru_stime.tv_usec.max(0) as u64 * 1_000;
    #[cfg(target_os = "macos")]
    let max_rss_bytes = usage.ru_maxrss.max(0) as u64;
    #[cfg(not(target_os = "macos"))]
    let max_rss_bytes = usage.ru_maxrss.max(0) as u64 * 1_024;
    ResourceSnapshot {
        cpu_ns: user_ns.saturating_add(system_ns),
        max_rss_bytes,
    }
}

#[cfg(not(unix))]
fn resources() -> ResourceSnapshot {
    ResourceSnapshot {
        cpu_ns: 0,
        max_rss_bytes: 0,
    }
}

fn catch_unwind_silent<F, T>(operation: F) -> Result<T, ()>
where
    F: FnOnce() -> T,
{
    let prior_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation));
    std::panic::set_hook(prior_hook);
    result.map_err(|_| ())
}

fn csv_field(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

impl SampleWriter {
    fn create(args: &Args) -> Result<Self, String> {
        if let Some(parent) = args.output.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("create {}: {error}", parent.display()))?;
        }
        let file = File::create(&args.output)
            .map_err(|error| format!("create {}: {error}", args.output.display()))?;
        let mut writer = BufWriter::new(file);
        writeln!(writer, "run_id,environment_id,source_commit,classification,sample_recorded_unix_ns,suite,layer,algorithm,operation,payload_profile,message_bytes,iteration,warmup_iterations,wall_ns,cpu_ns,max_rss_bytes,valid,result,work_units,item_count,public_key_bytes,private_key_bytes,signature_bytes,ciphertext_bytes,shared_secret_bytes,unsigned_serialized_bytes,serialized_bytes,authentication_bytes,notes")
            .map_err(|error| format!("write CSV header: {error}"))?;
        Ok(Self {
            writer,
            run_id: format!("local-{}", unix_nanos()?),
            environment_id: args.environment_id.clone(),
            source_commit: args.source_commit.clone(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn measure<F>(
        &mut self,
        suite: &str,
        layer: &str,
        algorithm: &str,
        operation: &str,
        payload_profile: &str,
        message_bytes: usize,
        iteration: usize,
        warmup_iterations: usize,
        operation_fn: F,
    ) -> Result<(), String>
    where
        F: FnOnce() -> Result<Observation, String>,
    {
        let before = resources();
        let started = Instant::now();
        let observation = operation_fn()?;
        let wall_ns = started.elapsed().as_nanos();
        let after = resources();
        let sample_recorded_unix_ns = unix_nanos()?;
        let values = [
            csv_field(&self.run_id),
            csv_field(&self.environment_id),
            csv_field(&self.source_commit),
            "MEASURED".to_string(),
            sample_recorded_unix_ns.to_string(),
            csv_field(suite),
            csv_field(layer),
            csv_field(algorithm),
            csv_field(operation),
            csv_field(payload_profile),
            message_bytes.to_string(),
            iteration.to_string(),
            warmup_iterations.to_string(),
            wall_ns.to_string(),
            after.cpu_ns.saturating_sub(before.cpu_ns).to_string(),
            after.max_rss_bytes.to_string(),
            observation.valid.to_string(),
            csv_field(&observation.result),
            observation.work_units.to_string(),
            observation.item_count.to_string(),
            observation.public_key_bytes.to_string(),
            observation.private_key_bytes.to_string(),
            observation.signature_bytes.to_string(),
            observation.ciphertext_bytes.to_string(),
            observation.shared_secret_bytes.to_string(),
            observation.unsigned_serialized_bytes.to_string(),
            observation.serialized_bytes.to_string(),
            observation.authentication_bytes.to_string(),
            csv_field(&observation.notes),
        ];
        writeln!(self.writer, "{}", values.join(","))
            .map_err(|error| format!("write sample: {error}"))
    }

    fn flush(&mut self) -> Result<(), String> {
        self.writer
            .flush()
            .map_err(|error| format!("flush samples: {error}"))
    }
}

fn algorithm_name(algorithm: &PQCAlgorithm) -> &'static str {
    match algorithm {
        PQCAlgorithm::MLKEM1024 => "ML-KEM-1024",
        PQCAlgorithm::MLDSA65 => "ML-DSA-65",
        PQCAlgorithm::MLDSA87 => "ML-DSA-87",
        PQCAlgorithm::FNDSA => "FN-DSA-1024",
        PQCAlgorithm::SLHDSA => "SLH-DSA-SHAKE-128f-simple",
        PQCAlgorithm::HQCKEM => "HQC-256",
    }
}

fn signature_algorithm(algorithm: &PQCAlgorithm) -> bool {
    matches!(
        algorithm,
        PQCAlgorithm::MLDSA65 | PQCAlgorithm::MLDSA87 | PQCAlgorithm::FNDSA | PQCAlgorithm::SLHDSA
    )
}

fn slow_iteration_cap(algorithm: &PQCAlgorithm, requested: usize) -> usize {
    match algorithm {
        PQCAlgorithm::SLHDSA => requested.min(30),
        PQCAlgorithm::HQCKEM => requested.min(50),
        _ => requested,
    }
}

fn payload_profiles() -> [(&'static str, usize); 9] {
    [
        ("digest32", 32),
        ("small64", 64),
        ("small128", 128),
        ("vote192", 192),
        ("medium256", 256),
        ("transaction512", 512),
        ("kilobyte1024", 1_024),
        ("block4096", 4_096),
        ("large16384", 16_384),
    ]
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[(byte >> 4) as usize] as char);
        encoded.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn ascii_payload(size: usize, iteration: usize) -> String {
    (0..size)
        .map(|index| (b'a' + ((index + iteration) % 26) as u8) as char)
        .collect()
}

fn payload(profile: &str, size: usize, iteration: usize) -> Vec<u8> {
    let seed = profile.as_bytes();
    (0..size)
        .map(|index| seed[index % seed.len()] ^ ((index + iteration) & 0xff) as u8)
        .collect()
}

fn benchmark_primitive(args: &Args, samples: &mut SampleWriter) -> Result<(), String> {
    benchmark_underlying_signature_primitives(args, samples)?;
    let algorithms = [
        PQCAlgorithm::MLDSA65,
        PQCAlgorithm::MLDSA87,
        PQCAlgorithm::FNDSA,
        PQCAlgorithm::SLHDSA,
        PQCAlgorithm::MLKEM1024,
        PQCAlgorithm::HQCKEM,
    ];
    for algorithm in algorithms {
        let name = algorithm_name(&algorithm);
        let keygen_iterations = slow_iteration_cap(&algorithm, args.keygen_iterations);
        let mut keygen_manager = PQCManager::new();
        for _ in 0..args.warmup_iterations.min(3) {
            black_box(keygen_manager.generate_keypair(algorithm.clone())?);
        }
        for iteration in 0..keygen_iterations {
            samples.measure(
                "primitive",
                "runtime_pqc_manager",
                name,
                "keygen",
                "none",
                0,
                iteration,
                args.warmup_iterations.min(3),
                || {
                    let (public_key, private_key) =
                        keygen_manager.generate_keypair(algorithm.clone())?;
                    Ok(Observation {
                        valid: !public_key.key_data.is_empty() && !private_key.key_data.is_empty(),
                        result: "keypair_generated".to_string(),
                        public_key_bytes: public_key.key_data.len(),
                        private_key_bytes: private_key.key_data.len(),
                        ..Observation::default()
                    })
                },
            )?;
        }
        if signature_algorithm(&algorithm) {
            benchmark_signature_primitive(args, samples, algorithm.clone())?;
            benchmark_signature_batches(args, samples, algorithm)?;
        } else {
            benchmark_kem_primitive(args, samples, algorithm)?;
        }
    }
    Ok(())
}

fn benchmark_underlying_signature_primitives(
    args: &Args,
    samples: &mut SampleWriter,
) -> Result<(), String> {
    benchmark_direct_signature_variant(
        args,
        samples,
        "ML-DSA-65",
        mldsa65::keypair,
        mldsa65::detached_sign,
        |signature, message, public_key| {
            mldsa65::verify_detached_signature(signature, message, public_key).is_ok()
        },
    )?;
    benchmark_direct_signature_variant(
        args,
        samples,
        "ML-DSA-87",
        mldsa87::keypair,
        mldsa87::detached_sign,
        |signature, message, public_key| {
            mldsa87::verify_detached_signature(signature, message, public_key).is_ok()
        },
    )?;
    benchmark_direct_signature_variant(
        args,
        samples,
        "FN-DSA-1024",
        fndsa1024::keypair,
        fndsa1024::detached_sign,
        |signature, message, public_key| {
            fndsa1024::verify_detached_signature(signature, message, public_key).is_ok()
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn benchmark_direct_signature_variant<PK, SK, Signature, Keypair, Sign, Verify>(
    args: &Args,
    samples: &mut SampleWriter,
    algorithm: &str,
    keypair: Keypair,
    sign: Sign,
    verify: Verify,
) -> Result<(), String>
where
    PK: DirectPublicKey,
    SK: DirectSecretKey,
    Signature: DirectDetachedSignature,
    Keypair: Fn() -> (PK, SK) + Copy,
    Sign: Fn(&[u8], &SK) -> Signature + Copy,
    Verify: Fn(&Signature, &[u8], &PK) -> bool + Copy,
{
    let keygen_warmups = args.warmup_iterations.min(3);
    for _ in 0..keygen_warmups {
        black_box(keypair());
    }
    for iteration in 0..args.keygen_iterations {
        samples.measure(
            "primitive",
            "underlying_primitive_direct",
            algorithm,
            "keygen",
            "none",
            0,
            iteration,
            keygen_warmups,
            || {
                let (public_key, private_key) = keypair();
                Ok(Observation {
                    valid: !public_key.as_bytes().is_empty() && !private_key.as_bytes().is_empty(),
                    result: "keypair_generated".to_string(),
                    public_key_bytes: public_key.as_bytes().len(),
                    private_key_bytes: private_key.as_bytes().len(),
                    notes: "direct portable primitive call; excludes PQCManager parsing, timestamping, allocations around key records, and registries".to_string(),
                    ..Observation::default()
                })
            },
        )?;
    }

    for (profile, size) in payload_profiles() {
        let message = payload(profile, size, 0);
        let (public_key, private_key) = keypair();
        let mut warm_signature = sign(&message, &private_key);
        if !verify(&warm_signature, &message, &public_key) {
            return Err(format!(
                "{algorithm} direct initial verification returned false"
            ));
        }
        for _ in 0..args.warmup_iterations {
            warm_signature = sign(black_box(&message), &private_key);
            if !verify(&warm_signature, black_box(&message), &public_key) {
                return Err(format!(
                    "{algorithm} direct warm-up verification returned false"
                ));
            }
        }
        black_box(&warm_signature);

        for iteration in 0..args.operation_iterations {
            samples.measure(
                "primitive",
                "underlying_primitive_direct",
                algorithm,
                "sign",
                profile,
                size,
                iteration,
                args.warmup_iterations,
                || {
                    let signature = sign(black_box(&message), &private_key);
                    Ok(Observation {
                        valid: !signature.as_bytes().is_empty(),
                        result: "signature_generated".to_string(),
                        public_key_bytes: public_key.as_bytes().len(),
                        private_key_bytes: private_key.as_bytes().len(),
                        signature_bytes: signature.as_bytes().len(),
                        notes: "direct portable primitive call; excludes PQCManager and Aegis policy/transcript work".to_string(),
                        ..Observation::default()
                    })
                },
            )?;
        }

        let signature = sign(&message, &private_key);
        for iteration in 0..args.operation_iterations {
            samples.measure(
                "primitive",
                "underlying_primitive_direct",
                algorithm,
                "verify_valid",
                profile,
                size,
                iteration,
                args.warmup_iterations,
                || {
                    let valid = verify(&signature, black_box(&message), &public_key);
                    Ok(Observation {
                        valid,
                        result: if valid { "accepted" } else { "unexpected_rejection" }.to_string(),
                        public_key_bytes: public_key.as_bytes().len(),
                        private_key_bytes: private_key.as_bytes().len(),
                        signature_bytes: signature.as_bytes().len(),
                        notes: "direct portable primitive call; excludes PQCManager and Aegis policy/transcript work".to_string(),
                        ..Observation::default()
                    })
                },
            )?;
        }
    }
    Ok(())
}

fn benchmark_signature_batches(
    args: &Args,
    samples: &mut SampleWriter,
    algorithm: PQCAlgorithm,
) -> Result<(), String> {
    let name = algorithm_name(&algorithm);
    let batch_sizes: &[usize] = if matches!(algorithm, PQCAlgorithm::SLHDSA) {
        &[10]
    } else {
        &[10, 100, 1_000]
    };
    let largest_batch = *batch_sizes.last().ok_or("empty batch size list")?;
    let mut manager = PQCManager::new();
    let (public_key, private_key) = manager.generate_keypair(algorithm)?;
    let mut signed_messages = Vec::with_capacity(largest_batch);
    for index in 0..largest_batch {
        let message = payload("transaction512-batch", 512, index);
        let signature = manager.sign(&private_key, &message)?;
        signed_messages.push((message, signature));
    }
    for &batch_size in batch_sizes {
        for _ in 0..args.warmup_iterations.min(3) {
            for (message, signature) in &signed_messages[..batch_size] {
                if !manager.verify(&public_key, signature, black_box(message))? {
                    return Err(format!(
                        "{name} batch warm-up unexpectedly rejected a signature"
                    ));
                }
            }
        }
        let iterations = slow_iteration_cap(&private_key.algorithm, args.operation_iterations)
            .min(if batch_size >= 1_000 { 30 } else { 100 });
        for iteration in 0..iterations {
            samples.measure(
                "primitive",
                "runtime_pqc_manager_batch",
                name,
                "verify_batch",
                &format!("transaction512_batch{batch_size}"),
                512,
                iteration,
                args.warmup_iterations.min(3),
                || {
                    let mut valid = true;
                    for (message, signature) in &signed_messages[..batch_size] {
                        valid &= manager.verify(&public_key, signature, black_box(message))?;
                    }
                    Ok(Observation {
                        valid,
                        result: if valid { "batch_accepted" } else { "unexpected_rejection" }.to_string(),
                        work_units: batch_size,
                        public_key_bytes: public_key.key_data.len(),
                        private_key_bytes: private_key.key_data.len(),
                        signature_bytes: signed_messages[0].1.signature_data.len(),
                        notes: "work_units is the number of sequential production-abstraction verifications inside the timed batch".to_string(),
                        ..Observation::default()
                    })
                },
            )?;
        }
    }
    Ok(())
}

fn benchmark_signature_primitive(
    args: &Args,
    samples: &mut SampleWriter,
    algorithm: PQCAlgorithm,
) -> Result<(), String> {
    let name = algorithm_name(&algorithm);
    let iterations = slow_iteration_cap(&algorithm, args.operation_iterations);
    for (profile, size) in payload_profiles() {
        let message = payload(profile, size, 0);
        let mut manager = PQCManager::new();
        let (public_key, private_key) = manager.generate_keypair(algorithm.clone())?;
        let mut warm_signature = manager.sign(&private_key, &message)?;
        if !manager.verify(&public_key, &warm_signature, &message)? {
            return Err(format!(
                "{name} initial warm-up verification returned false"
            ));
        }
        for _ in 0..args.warmup_iterations {
            warm_signature = manager.sign(&private_key, black_box(&message))?;
            if !manager.verify(&public_key, &warm_signature, black_box(&message))? {
                return Err(format!("{name} warm-up verification returned false"));
            }
        }
        for iteration in 0..iterations {
            samples.measure(
                "primitive",
                "runtime_pqc_manager",
                name,
                "sign",
                profile,
                size,
                iteration,
                args.warmup_iterations,
                || {
                    let signature = manager.sign(&private_key, black_box(&message))?;
                    Ok(Observation {
                        valid: !signature.signature_data.is_empty(),
                        result: "signature_generated".to_string(),
                        public_key_bytes: public_key.key_data.len(),
                        private_key_bytes: private_key.key_data.len(),
                        signature_bytes: signature.signature_data.len(),
                        notes: "PQCManager includes key parsing, timestamping, allocation, and signature-registry insertion".to_string(),
                        ..Observation::default()
                    })
                },
            )?;
        }
        let signature = manager.sign(&private_key, &message)?;
        for iteration in 0..iterations {
            samples.measure(
                "primitive",
                "runtime_pqc_manager",
                name,
                "verify_valid",
                profile,
                size,
                iteration,
                args.warmup_iterations,
                || {
                    let valid = manager.verify(&public_key, &signature, black_box(&message))?;
                    Ok(Observation {
                        valid,
                        result: if valid {
                            "accepted"
                        } else {
                            "unexpected_rejection"
                        }
                        .to_string(),
                        public_key_bytes: public_key.key_data.len(),
                        private_key_bytes: private_key.key_data.len(),
                        signature_bytes: signature.signature_data.len(),
                        ..Observation::default()
                    })
                },
            )?;
        }
        let mut tampered_signature = signature.clone();
        let tamper_index = tampered_signature.signature_data.len() / 2;
        tampered_signature.signature_data[tamper_index] ^= 1;
        for iteration in 0..iterations.min(50) {
            samples.measure(
                "negative",
                "runtime_pqc_manager",
                name,
                "verify_tampered_signature",
                profile,
                size,
                iteration,
                0,
                || {
                    let rejected =
                        match manager.verify(&public_key, &tampered_signature, black_box(&message))
                        {
                            Ok(valid) => !valid,
                            Err(_) => true,
                        };
                    Ok(Observation {
                        valid: rejected,
                        result: if rejected {
                            "rejected"
                        } else {
                            "unexpected_acceptance"
                        }
                        .to_string(),
                        public_key_bytes: public_key.key_data.len(),
                        signature_bytes: tampered_signature.signature_data.len(),
                        ..Observation::default()
                    })
                },
            )?;
        }
    }
    Ok(())
}

fn benchmark_kem_primitive(
    args: &Args,
    samples: &mut SampleWriter,
    algorithm: PQCAlgorithm,
) -> Result<(), String> {
    let name = algorithm_name(&algorithm);
    let iterations = slow_iteration_cap(&algorithm, args.operation_iterations);
    let mut manager = PQCManager::new();
    let (public_key, private_key) = manager.generate_keypair(algorithm)?;
    let (mut ciphertext, mut expected_secret) = manager.encapsulate(&public_key)?;
    for _ in 0..args.warmup_iterations {
        (ciphertext, expected_secret) = manager.encapsulate(&public_key)?;
        let actual_secret = manager.decapsulate(&private_key, &ciphertext)?;
        if actual_secret.secret != expected_secret.secret {
            return Err(format!("{name} warm-up shared secrets differ"));
        }
    }
    for iteration in 0..iterations {
        samples.measure(
            "primitive",
            "runtime_pqc_manager",
            name,
            "encapsulate",
            "kem",
            0,
            iteration,
            args.warmup_iterations,
            || {
                let (ciphertext, secret) = manager.encapsulate(&public_key)?;
                Ok(Observation {
                    valid: !ciphertext.ciphertext.is_empty() && !secret.secret.is_empty(),
                    result: "encapsulated".to_string(),
                    public_key_bytes: public_key.key_data.len(),
                    private_key_bytes: private_key.key_data.len(),
                    ciphertext_bytes: ciphertext.ciphertext.len(),
                    shared_secret_bytes: secret.secret.len(),
                    notes: "PQCManager includes allocation and ciphertext/shared-secret registry insertion".to_string(),
                    ..Observation::default()
                })
            },
        )?;
    }
    for iteration in 0..iterations {
        samples.measure(
            "primitive",
            "runtime_pqc_manager",
            name,
            "decapsulate",
            "kem",
            0,
            iteration,
            args.warmup_iterations,
            || {
                let actual_secret = manager.decapsulate(&private_key, black_box(&ciphertext))?;
                let valid = actual_secret.secret == expected_secret.secret;
                Ok(Observation {
                    valid,
                    result: if valid {
                        "shared_secret_match"
                    } else {
                        "shared_secret_mismatch"
                    }
                    .to_string(),
                    public_key_bytes: public_key.key_data.len(),
                    private_key_bytes: private_key.key_data.len(),
                    ciphertext_bytes: ciphertext.ciphertext.len(),
                    shared_secret_bytes: actual_secret.secret.len(),
                    ..Observation::default()
                })
            },
        )?;
    }
    let mut tampered = ciphertext.clone();
    let tamper_index = tampered.ciphertext.len() / 2;
    tampered.ciphertext[tamper_index] ^= 1;
    for iteration in 0..iterations.min(50) {
        samples.measure(
            "negative",
            "runtime_pqc_manager",
            name,
            "decapsulate_tampered_ciphertext",
            "kem",
            0,
            iteration,
            0,
            || {
                match catch_unwind_silent(|| manager.decapsulate(&private_key, black_box(&tampered))) {
                    Ok(Ok(actual_secret)) => {
                        let differs = actual_secret.secret != expected_secret.secret;
                        Ok(Observation {
                            valid: differs,
                            result: if differs { "implicit_rejection_secret_differs" } else { "unexpected_original_secret" }.to_string(),
                            public_key_bytes: public_key.key_data.len(),
                            private_key_bytes: private_key.key_data.len(),
                            ciphertext_bytes: tampered.ciphertext.len(),
                            shared_secret_bytes: actual_secret.secret.len(),
                            notes: "CCA KEM decapsulation returned a secret; correctness requires it to differ from the original secret".to_string(),
                            ..Observation::default()
                        })
                    }
                    Ok(Err(_)) => Ok(Observation {
                        valid: true,
                        result: "explicit_rejection".to_string(),
                        public_key_bytes: public_key.key_data.len(),
                        private_key_bytes: private_key.key_data.len(),
                        ciphertext_bytes: tampered.ciphertext.len(),
                        notes: "decapsulation returned an explicit error".to_string(),
                        ..Observation::default()
                    }),
                    Err(()) => Ok(Observation {
                        valid: false,
                        result: "panic_caught".to_string(),
                        public_key_bytes: public_key.key_data.len(),
                        private_key_bytes: private_key.key_data.len(),
                        ciphertext_bytes: tampered.ciphertext.len(),
                        notes: "library panicked on malformed ciphertext; harness caught unwind to preserve the remaining measurement matrix".to_string(),
                        ..Observation::default()
                    }),
                }
            },
        )?;
    }
    Ok(())
}

#[derive(Clone)]
struct AegisProfile {
    algorithm: &'static str,
    domain: &'static str,
    layer: &'static str,
    role: AegisPqKeyRole,
}

fn benchmark_aegis(args: &Args, samples: &mut SampleWriter) -> Result<(), String> {
    let profiles = [
        AegisProfile {
            algorithm: "ML-DSA-65",
            domain: SYNERGY_BLOCK_V1,
            layer: "aegis_domain_wrapper_block",
            role: AegisPqKeyRole::ConsensusProposer,
        },
        AegisProfile {
            algorithm: "ML-DSA-65",
            domain: SYNERGY_TX_V1,
            layer: "aegis_domain_wrapper_transaction",
            role: AegisPqKeyRole::Transaction,
        },
        AegisProfile {
            algorithm: "ML-DSA-87",
            domain: SYNERGY_TX_V1,
            layer: "aegis_domain_wrapper_transaction",
            role: AegisPqKeyRole::Transaction,
        },
        AegisProfile {
            algorithm: "FN-DSA-1024",
            domain: SYNERGY_P2P_HANDSHAKE_V1,
            layer: "aegis_domain_wrapper_p2p",
            role: AegisPqKeyRole::PeerIdentity,
        },
    ];
    for (profile_index, profile) in profiles.into_iter().enumerate() {
        let uma_id = format!("aegis-benchmark-{profile_index}");
        let (mut signer, key_id) = aegis_signer_for_profile(&profile, &uma_id)?;
        let verifier = signer.verifier();
        for (payload_profile, size) in payload_profiles() {
            let message = payload(payload_profile, size, 0);
            let mut signature = signer
                .sign_domain(profile.domain, &message, &key_id)
                .map_err(|error| error.to_string())?;
            verifier
                .verify_domain_signature(
                    profile.domain,
                    &message,
                    &uma_id,
                    &key_id,
                    Epoch(0),
                    profile.role.clone(),
                    &signature,
                )
                .map_err(|error| error.to_string())?;
            for _ in 0..args.warmup_iterations {
                signature = signer
                    .sign_domain(profile.domain, black_box(&message), &key_id)
                    .map_err(|error| error.to_string())?;
                verifier
                    .verify_domain_signature(
                        profile.domain,
                        &message,
                        &uma_id,
                        &key_id,
                        Epoch(0),
                        profile.role.clone(),
                        &signature,
                    )
                    .map_err(|error| error.to_string())?;
            }
            let iterations = args.operation_iterations;
            for iteration in 0..iterations {
                samples.measure(
                    "aegis",
                    profile.layer,
                    profile.algorithm,
                    "sign_domain",
                    payload_profile,
                    size,
                    iteration,
                    args.warmup_iterations,
                    || {
                        let signature = signer
                            .sign_domain(profile.domain, black_box(&message), &key_id)
                            .map_err(|error| error.to_string())?;
                        Ok(Observation {
                            valid: signature.is_present(),
                            result: "domain_signature_generated".to_string(),
                            signature_bytes: signature.signature_bytes.len(),
                            notes: format!("domain={}", profile.domain),
                            ..Observation::default()
                        })
                    },
                )?;
            }
            let fixed_signature = signer
                .sign_domain(profile.domain, &message, &key_id)
                .map_err(|error| error.to_string())?;
            let cold_verifier = signer.verifier();
            for iteration in 0..iterations {
                let unique_message = payload(payload_profile, size, iteration + 1);
                let unique_signature = signer
                    .sign_domain(profile.domain, &unique_message, &key_id)
                    .map_err(|error| error.to_string())?;
                samples.measure(
                    "aegis",
                    profile.layer,
                    profile.algorithm,
                    "verify_cache_miss",
                    payload_profile,
                    size,
                    iteration,
                    0,
                    || {
                        cold_verifier.verify_domain_signature(profile.domain, black_box(&unique_message), &uma_id, &key_id, Epoch(0), profile.role.clone(), &unique_signature).map_err(|error| error.to_string())?;
                        Ok(Observation {
                            valid: true,
                            result: "accepted_cache_miss".to_string(),
                            signature_bytes: unique_signature.signature_bytes.len(),
                            notes: format!("domain={}; policy checks + transcript hash + bounded worker + primitive", profile.domain),
                            ..Observation::default()
                        })
                    },
                )?;
            }
            for _ in 0..args.warmup_iterations {
                verifier
                    .verify_domain_signature(
                        profile.domain,
                        &message,
                        &uma_id,
                        &key_id,
                        Epoch(0),
                        profile.role.clone(),
                        &fixed_signature,
                    )
                    .map_err(|error| error.to_string())?;
            }
            for iteration in 0..iterations {
                samples.measure(
                    "aegis",
                    profile.layer,
                    profile.algorithm,
                    "verify_cache_hit",
                    payload_profile,
                    size,
                    iteration,
                    args.warmup_iterations,
                    || {
                        verifier
                            .verify_domain_signature(
                                profile.domain,
                                black_box(&message),
                                &uma_id,
                                &key_id,
                                Epoch(0),
                                profile.role.clone(),
                                &fixed_signature,
                            )
                            .map_err(|error| error.to_string())?;
                        Ok(Observation {
                            valid: true,
                            result: "accepted_cache_hit".to_string(),
                            signature_bytes: fixed_signature.signature_bytes.len(),
                            notes: format!(
                                "domain={}; policy checks + transcript hash + positive cache",
                                profile.domain
                            ),
                            ..Observation::default()
                        })
                    },
                )?;
            }
            let mut tampered = fixed_signature.clone();
            let tamper_index = tampered.signature_bytes.len() / 2;
            tampered.signature_bytes[tamper_index] ^= 1;
            for iteration in 0..iterations.min(50) {
                samples.measure(
                    "negative",
                    profile.layer,
                    profile.algorithm,
                    "verify_tampered_signature",
                    payload_profile,
                    size,
                    iteration,
                    0,
                    || {
                        let rejected = verifier
                            .verify_domain_signature(
                                profile.domain,
                                &message,
                                &uma_id,
                                &key_id,
                                Epoch(0),
                                profile.role.clone(),
                                &tampered,
                            )
                            .is_err();
                        Ok(Observation {
                            valid: rejected,
                            result: if rejected {
                                "rejected"
                            } else {
                                "unexpected_acceptance"
                            }
                            .to_string(),
                            signature_bytes: tampered.signature_bytes.len(),
                            notes: format!("domain={}", profile.domain),
                            ..Observation::default()
                        })
                    },
                )?;
            }
        }
    }
    Ok(())
}

fn aegis_signer_for_profile(
    profile: &AegisProfile,
    uma_id: &str,
) -> Result<
    (
        AegisPqvmSigner,
        synergy_testnet::synergy_types::AegisPqKeyId,
    ),
    String,
> {
    let mut signer = AegisPqvmSigner::initialize_required().map_err(|error| error.to_string())?;
    let key_id = match profile.algorithm {
        "ML-DSA-65" => signer
            .generate_and_register_key(uma_id, vec![profile.role.clone()], Epoch(0))
            .map_err(|error| error.to_string())?,
        "FN-DSA-1024" => signer
            .generate_and_register_fndsa_peer_identity(uma_id, Epoch(0))
            .map_err(|error| error.to_string())?,
        "ML-DSA-87" => {
            let mut manager = PQCManager::new();
            let (public_key, private_key) = manager.generate_keypair(PQCAlgorithm::MLDSA87)?;
            signer
                .register_existing_keypair(
                    uma_id,
                    public_key,
                    private_key,
                    vec![profile.role.clone()],
                    Epoch(0),
                )
                .map_err(|error| error.to_string())?
        }
        other => return Err(format!("unsupported Aegis profile algorithm: {other}")),
    };
    Ok((signer, key_id))
}

fn benchmark_lifecycle(args: &Args, samples: &mut SampleWriter) -> Result<(), String> {
    let uma_id = "aegis-lifecycle-benchmark";
    let mut signer = AegisPqvmSigner::initialize_required().map_err(|error| error.to_string())?;
    let mut current_key = signer
        .generate_and_register_key(
            uma_id,
            vec![
                AegisPqKeyRole::Transaction,
                AegisPqKeyRole::ConsensusProposer,
            ],
            Epoch(0),
        )
        .map_err(|error| error.to_string())?;
    let iterations = args.operation_iterations;
    let verifier = signer.verifier();
    for _ in 0..args.warmup_iterations {
        black_box(
            signer
                .public_key_record(&current_key)
                .map_err(|error| error.to_string())?,
        );
        black_box(verifier.key_is_authorized_for_role(
            uma_id,
            &current_key,
            AegisPqKeyRole::Transaction,
        ));
        black_box(verifier.key_is_active_for_epoch(
            uma_id,
            &current_key,
            Epoch(0),
            AegisPqKeyRole::Transaction,
        ));
        black_box(verifier.key_is_revoked(uma_id, &current_key, Epoch(0)));
    }
    for iteration in 0..iterations {
        samples.measure(
            "lifecycle",
            "aegis_key_registry",
            "ML-DSA-65",
            "public_key_lookup",
            "registry1",
            0,
            iteration,
            args.warmup_iterations,
            || {
                let record = signer
                    .public_key_record(black_box(&current_key))
                    .map_err(|error| error.to_string())?;
                Ok(Observation {
                    valid: !record.key_bytes.is_empty(),
                    result: "found".to_string(),
                    public_key_bytes: record.key_bytes.len(),
                    ..Observation::default()
                })
            },
        )?;
        samples.measure(
            "lifecycle",
            "aegis_key_registry",
            "ML-DSA-65",
            "role_authorization_check",
            "registry1",
            0,
            iteration,
            args.warmup_iterations,
            || {
                let authorized = verifier.key_is_authorized_for_role(
                    uma_id,
                    black_box(&current_key),
                    AegisPqKeyRole::Transaction,
                );
                Ok(Observation {
                    valid: authorized,
                    result: if authorized {
                        "authorized"
                    } else {
                        "unexpected_denial"
                    }
                    .to_string(),
                    ..Observation::default()
                })
            },
        )?;
        samples.measure(
            "lifecycle",
            "aegis_key_registry",
            "ML-DSA-65",
            "active_key_check",
            "registry1",
            0,
            iteration,
            args.warmup_iterations,
            || {
                let active = verifier.key_is_active_for_epoch(
                    uma_id,
                    black_box(&current_key),
                    Epoch(0),
                    AegisPqKeyRole::Transaction,
                );
                Ok(Observation {
                    valid: active,
                    result: if active {
                        "active"
                    } else {
                        "unexpected_inactive"
                    }
                    .to_string(),
                    ..Observation::default()
                })
            },
        )?;
        samples.measure(
            "lifecycle",
            "aegis_key_registry",
            "ML-DSA-65",
            "revocation_check",
            "registry1",
            0,
            iteration,
            args.warmup_iterations,
            || {
                let revoked = verifier.key_is_revoked(uma_id, black_box(&current_key), Epoch(0));
                Ok(Observation {
                    valid: !revoked,
                    result: if revoked {
                        "unexpected_revocation"
                    } else {
                        "not_revoked"
                    }
                    .to_string(),
                    ..Observation::default()
                })
            },
        )?;
    }

    for registry_size in [1usize, 10, 100, 1_000, 10_000] {
        let mut root_signer =
            AegisPqvmSigner::initialize_required().map_err(|error| error.to_string())?;
        for index in 0..registry_size {
            root_signer
                .generate_and_register_key(
                    &format!("lifecycle-root-{index:04}"),
                    vec![AegisPqKeyRole::Transaction],
                    Epoch(0),
                )
                .map_err(|error| error.to_string())?;
        }
        let verifier = root_signer.verifier();
        for _ in 0..args.warmup_iterations {
            black_box(
                verifier
                    .key_lifecycle_root(Epoch(0))
                    .map_err(|error| error.to_string())?,
            );
        }
        for iteration in 0..iterations.min(100) {
            samples.measure(
                "lifecycle",
                "aegis_key_lifecycle",
                "ML-DSA-65",
                "lifecycle_root",
                &format!("registry{registry_size}"),
                0,
                iteration,
                args.warmup_iterations,
                || {
                    let root = verifier.key_lifecycle_root(Epoch(0)).map_err(|error| error.to_string())?;
                    Ok(Observation {
                        valid: !root.is_zero(),
                        result: "root_computed".to_string(),
                        serialized_bytes: registry_size,
                        notes: "serialized_bytes column stores lifecycle record count for this scaling operation".to_string(),
                        ..Observation::default()
                    })
                },
            )?;
        }
    }

    let mut public_key_manager = PQCManager::new();
    let mut public_registry_signer =
        AegisPqvmSigner::initialize_required().map_err(|error| error.to_string())?;
    for iteration in 0..args.keygen_iterations {
        let (mut public_key, _) = public_key_manager.generate_keypair(PQCAlgorithm::MLDSA65)?;
        public_key.key_id = format!("aegis-public-registration-{iteration}");
        samples.measure(
            "lifecycle",
            "aegis_key_registry",
            "ML-DSA-65",
            "register_public_key",
            "growing_registry",
            0,
            iteration,
            0,
            || {
                let key_id = public_registry_signer.registry.register_public_key(
                    &format!("public-registration-{iteration}"),
                    public_key.clone(),
                    vec![AegisPqKeyRole::Transaction],
                    Epoch(0),
                );
                let registered = public_registry_signer
                    .registry
                    .public_key(&key_id)
                    .is_some();
                Ok(Observation {
                    valid: registered,
                    result: if registered {
                        "registered"
                    } else {
                        "unexpected_missing"
                    }
                    .to_string(),
                    public_key_bytes: public_key.key_data.len(),
                    ..Observation::default()
                })
            },
        )?;
    }

    for iteration in 0..args.keygen_iterations {
        let prior_key = current_key.clone();
        samples.measure(
            "lifecycle",
            "aegis_key_registry",
            "ML-DSA-65",
            "rotate_generate_register_revoke",
            "growing_registry",
            0,
            iteration,
            0,
            || {
                let next_key = signer
                    .generate_and_register_key(
                        uma_id,
                        vec![AegisPqKeyRole::Transaction],
                        Epoch(iteration as u64 + 1),
                    )
                    .map_err(|error| error.to_string())?;
                signer
                    .registry
                    .revoke_key(uma_id, &prior_key, Epoch(iteration as u64 + 1));
                current_key = next_key;
                Ok(Observation {
                    valid: signer.registry.key_is_revoked(
                        uma_id,
                        &prior_key,
                        Epoch(iteration as u64 + 1),
                    ),
                    result: "new_key_registered_old_key_revoked".to_string(),
                    notes: "includes ML-DSA-65 keygen, lifecycle sort, and revocation mutation"
                        .to_string(),
                    ..Observation::default()
                })
            },
        )?;
    }

    benchmark_lifecycle_negative(args, samples)?;
    Ok(())
}

fn benchmark_lifecycle_negative(args: &Args, samples: &mut SampleWriter) -> Result<(), String> {
    let cases = [
        "wrong_role",
        "wrong_public_key",
        "missing_key",
        "not_yet_active",
        "revoked",
        "expired",
        "wrong_domain",
        "missing_signature",
        "unknown_algorithm",
        "invalid_algorithm_identifier",
        "malformed_signature",
        "malformed_key",
    ];
    for case in cases {
        let uma_id = format!("negative-policy-{case}");
        let mut signer =
            AegisPqvmSigner::initialize_required().map_err(|error| error.to_string())?;
        let active_from = if case == "not_yet_active" {
            Epoch(10)
        } else {
            Epoch(0)
        };
        let key_id = signer
            .generate_and_register_key(&uma_id, vec![AegisPqKeyRole::Transaction], active_from)
            .map_err(|error| error.to_string())?;
        let message = payload("negative-policy", 256, 0);
        let mut signature = signer
            .sign_domain(SYNERGY_TX_V1, &message, &key_id)
            .map_err(|error| error.to_string())?;
        let mut epoch = Epoch(0);
        let mut domain = SYNERGY_TX_V1;
        let mut role = AegisPqKeyRole::Transaction;
        let mut verification_key_id = key_id.clone();
        let mut malformed_key_verifier = None;
        match case {
            "wrong_role" => role = AegisPqKeyRole::EpochTransition,
            "wrong_public_key" => {
                verification_key_id = signer
                    .generate_and_register_key(&uma_id, vec![AegisPqKeyRole::Transaction], Epoch(0))
                    .map_err(|error| error.to_string())?;
            }
            "missing_key" => {
                verification_key_id = AegisPqKeyId("aegis-benchmark-missing-key".to_string());
            }
            "revoked" => signer.registry.revoke_key(&uma_id, &key_id, Epoch(0)),
            "expired" => {
                signer
                    .registry
                    .lifecycle
                    .record_for(&uma_id, &key_id)
                    .ok_or("missing lifecycle record")?;
                let record = signer
                    .registry
                    .lifecycle
                    .records
                    .iter_mut()
                    .find(|record| record.uma_id == uma_id && record.key_id == key_id)
                    .ok_or("missing mutable lifecycle record")?;
                record.active_until_epoch = Some(Epoch(0));
                epoch = Epoch(1);
            }
            "wrong_domain" => domain = SYNERGY_BLOCK_V1,
            "missing_signature" => {
                signature = AegisPqSignature {
                    algorithm: String::new(),
                    signature_bytes: Vec::new(),
                }
            }
            "unknown_algorithm" => signature.algorithm = "unknown-pqc".to_string(),
            "invalid_algorithm_identifier" => {
                signature.algorithm = "mldsa65/../../unsupported".to_string()
            }
            "malformed_signature" => {
                signature.signature_bytes.pop();
            }
            "malformed_key" => {
                let mut public_key = signer
                    .public_key_record(&key_id)
                    .map_err(|error| error.to_string())?;
                public_key.key_bytes.pop();
                let lifecycle_record = signer
                    .registry
                    .lifecycle
                    .record_for(&uma_id, &key_id)
                    .ok_or("missing malformed-key lifecycle record")?
                    .clone();
                malformed_key_verifier = Some(
                    AegisPqvmVerifier::initialize_required_for_public_key(
                        public_key,
                        lifecycle_record,
                    )
                    .map_err(|error| error.to_string())?,
                );
            }
            "not_yet_active" => {}
            _ => unreachable!(),
        }
        let verifier = malformed_key_verifier.unwrap_or_else(|| signer.verifier());
        for iteration in 0..args.operation_iterations.min(50) {
            samples.measure(
                "negative",
                "aegis_lifecycle_policy",
                "ML-DSA-65",
                case,
                "policy256",
                message.len(),
                iteration,
                0,
                || {
                    let rejected = verifier
                        .verify_domain_signature(
                            domain,
                            &message,
                            &uma_id,
                            &verification_key_id,
                            epoch,
                            role.clone(),
                            &signature,
                        )
                        .is_err();
                    Ok(Observation {
                        valid: rejected,
                        result: if rejected {
                            "rejected"
                        } else {
                            "unexpected_acceptance"
                        }
                        .to_string(),
                        signature_bytes: signature.signature_bytes.len(),
                        ..Observation::default()
                    })
                },
            )?;
        }
    }
    Ok(())
}

fn benchmark_protocol(args: &Args, samples: &mut SampleWriter) -> Result<(), String> {
    benchmark_public_transaction_protocol(args, samples)?;
    benchmark_aegis_transaction_protocol(args, samples)?;
    benchmark_peer_handshake_protocol(args, samples)?;
    benchmark_coordinated_envelopes(args, samples)?;
    Ok(())
}

fn benchmark_public_transaction_protocol(
    args: &Args,
    samples: &mut SampleWriter,
) -> Result<(), String> {
    let mut manager = PQCManager::new();
    let (public_key, private_key) = manager.generate_keypair(PQCAlgorithm::MLDSA87)?;
    let sender =
        synergy_testnet::address::generate_wallet_address(&lowercase_hex(&public_key.key_data));
    let receiver = synergy_testnet::address::generate_wallet_address("aegis-benchmark-receiver");
    let operation_iterations = args.operation_iterations;
    for (profile, size) in payload_profiles() {
        for iteration in 0..operation_iterations {
            let data = Some(ascii_payload(size, iteration));
            samples.measure(
                "protocol",
                "public_rpc_transaction",
                "ML-DSA-87",
                "build_hash_sign_serialize",
                profile,
                size,
                iteration,
                0,
                || {
                    let mut transaction = LegacyTransaction::new(
                        sender.clone(),
                        receiver.clone(),
                        1,
                        iteration as u64,
                        Vec::new(),
                        1_000,
                        21_000,
                        data.clone(),
                        "mldsa87".to_string(),
                    );
                    let unsigned_serialized = serde_json::to_vec(&transaction).map_err(|error| error.to_string())?;
                    transaction.sign_with_public_key(&public_key, &private_key, &mut manager)?;
                    let serialized = serde_json::to_vec(&transaction).map_err(|error| error.to_string())?;
                    Ok(Observation {
                        valid: transaction.validate_for_admission().is_valid,
                        result: "signed_serialized_admission_valid".to_string(),
                        public_key_bytes: public_key.key_data.len(),
                        private_key_bytes: private_key.key_data.len(),
                        signature_bytes: transaction.signature.len(),
                        unsigned_serialized_bytes: unsigned_serialized.len(),
                        serialized_bytes: serialized.len(),
                        authentication_bytes: serialized.len().saturating_sub(unsigned_serialized.len()),
                        item_count: 1,
                        notes: "includes raw BLAKE3 transaction hash, PQCManager signing, embedded public key, JSON, and admission verification".to_string(),
                        ..Observation::default()
                    })
                },
            )?;
        }
        let mut transaction = LegacyTransaction::new(
            sender.clone(),
            receiver.clone(),
            1,
            0,
            Vec::new(),
            1_000,
            21_000,
            Some(ascii_payload(size, 0)),
            "mldsa87".to_string(),
        );
        transaction.sign_with_public_key(&public_key, &private_key, &mut manager)?;
        let mut unsigned_transaction = transaction.clone();
        unsigned_transaction.signature.clear();
        unsigned_transaction.signer_public_key.clear();
        let unsigned_serialized_bytes = serde_json::to_vec(&unsigned_transaction)
            .map_err(|error| error.to_string())?
            .len();
        let signed_serialized =
            serde_json::to_vec(&transaction).map_err(|error| error.to_string())?;
        for _ in 0..args.warmup_iterations {
            black_box(transaction.raw_hash());
            black_box(serde_json::to_vec(&transaction).map_err(|error| error.to_string())?);
            black_box(
                serde_json::from_slice::<LegacyTransaction>(&signed_serialized)
                    .map_err(|error| error.to_string())?,
            );
            transaction.verify_embedded_signature()?;
            if !black_box(transaction.validate_for_admission()).is_valid {
                return Err("legacy transaction warm-up unexpectedly failed admission".to_string());
            }
        }
        for iteration in 0..operation_iterations {
            samples.measure(
                "protocol",
                "public_rpc_transaction_component",
                "BLAKE3",
                "raw_hash",
                profile,
                size,
                iteration,
                args.warmup_iterations,
                || {
                    let hash = transaction.raw_hash();
                    Ok(Observation {
                        valid: hash.len() == 64,
                        result: "raw_hash_computed".to_string(),
                        serialized_bytes: hash.len(),
                        item_count: 1,
                        notes: "production legacy transaction raw_hash; excludes prefix formatting and signature verification".to_string(),
                        ..Observation::default()
                    })
                },
            )?;
            samples.measure(
                "protocol",
                "public_rpc_transaction_component",
                "JSON",
                "serialize_signed_json",
                profile,
                size,
                iteration,
                args.warmup_iterations,
                || {
                    let serialized =
                        serde_json::to_vec(&transaction).map_err(|error| error.to_string())?;
                    Ok(Observation {
                        valid: serialized == signed_serialized,
                        result: "serialized".to_string(),
                        serialized_bytes: serialized.len(),
                        item_count: 1,
                        ..Observation::default()
                    })
                },
            )?;
            samples.measure(
                "protocol",
                "public_rpc_transaction_component",
                "JSON",
                "deserialize_signed_json",
                profile,
                size,
                iteration,
                args.warmup_iterations,
                || {
                    let decoded: LegacyTransaction =
                        serde_json::from_slice(black_box(&signed_serialized))
                            .map_err(|error| error.to_string())?;
                    let valid = decoded.signature == transaction.signature
                        && decoded.signer_public_key == transaction.signer_public_key
                        && decoded.raw_hash() == transaction.raw_hash();
                    Ok(Observation {
                        valid,
                        result: if valid {
                            "deserialized_equal_auth_and_hash"
                        } else {
                            "unexpected_decode_mismatch"
                        }
                        .to_string(),
                        serialized_bytes: signed_serialized.len(),
                        item_count: 1,
                        ..Observation::default()
                    })
                },
            )?;
            samples.measure(
                "protocol",
                "public_rpc_transaction_component",
                "ML-DSA-87",
                "verify_embedded_signature",
                profile,
                size,
                iteration,
                args.warmup_iterations,
                || {
                    transaction.verify_embedded_signature()?;
                    Ok(Observation {
                        valid: true,
                        result: "accepted".to_string(),
                        public_key_bytes: transaction.signer_public_key.len(),
                        signature_bytes: transaction.signature.len(),
                        serialized_bytes: signed_serialized.len(),
                        item_count: 1,
                        notes: "includes sender/public-key binding, algorithm dispatch, raw hash, key parsing, and primitive verification".to_string(),
                        ..Observation::default()
                    })
                },
            )?;
            samples.measure(
                "protocol",
                "public_rpc_transaction",
                "ML-DSA-87",
                "validate_for_admission",
                profile,
                size,
                iteration,
                args.warmup_iterations,
                || {
                    let result = transaction.validate_for_admission();
                    Ok(Observation {
                        valid: result.is_valid,
                        result: if result.is_valid {
                            "accepted"
                        } else {
                            "unexpected_rejection"
                        }
                        .to_string(),
                        public_key_bytes: transaction.signer_public_key.len(),
                        signature_bytes: transaction.signature.len(),
                        unsigned_serialized_bytes,
                        serialized_bytes: serde_json::to_vec(&transaction)
                            .map_err(|error| error.to_string())?
                            .len(),
                        authentication_bytes: serde_json::to_vec(&transaction)
                            .map_err(|error| error.to_string())?
                            .len()
                            .saturating_sub(unsigned_serialized_bytes),
                        item_count: 1,
                        ..Observation::default()
                    })
                },
            )?;
        }

        let mut modified_payload = transaction.clone();
        modified_payload
            .data
            .get_or_insert_with(String::new)
            .push_str("-modified-after-signing");
        let mut malformed_public_key = transaction.clone();
        malformed_public_key.signer_public_key.pop();
        let mut wrong_chain = transaction.clone();
        wrong_chain.chain_id = wrong_chain.chain_id.saturating_add(1);
        let mut unknown_algorithm = transaction.clone();
        unknown_algorithm.signature_algorithm = "unknown-pqc".to_string();
        let malformed_json = &signed_serialized[..signed_serialized.len().saturating_sub(1)];
        for iteration in 0..operation_iterations.min(50) {
            for (operation, candidate) in [
                ("reject_modified_signed_payload", &modified_payload),
                ("reject_malformed_public_key", &malformed_public_key),
                ("reject_wrong_chain_id", &wrong_chain),
                ("reject_unknown_algorithm", &unknown_algorithm),
            ] {
                samples.measure(
                    "negative",
                    "public_rpc_transaction",
                    "ML-DSA-87",
                    operation,
                    profile,
                    size,
                    iteration,
                    0,
                    || {
                        let rejected = !candidate.validate_for_admission().is_valid;
                        Ok(Observation {
                            valid: rejected,
                            result: if rejected {
                                "rejected"
                            } else {
                                "unexpected_acceptance"
                            }
                            .to_string(),
                            public_key_bytes: candidate.signer_public_key.len(),
                            signature_bytes: candidate.signature.len(),
                            item_count: 1,
                            ..Observation::default()
                        })
                    },
                )?;
            }
            samples.measure(
                "negative",
                "public_rpc_transaction_component",
                "JSON",
                "reject_malformed_json",
                profile,
                size,
                iteration,
                0,
                || {
                    let rejected =
                        serde_json::from_slice::<LegacyTransaction>(black_box(malformed_json))
                            .is_err();
                    Ok(Observation {
                        valid: rejected,
                        result: if rejected {
                            "rejected"
                        } else {
                            "unexpected_acceptance"
                        }
                        .to_string(),
                        serialized_bytes: malformed_json.len(),
                        item_count: 1,
                        ..Observation::default()
                    })
                },
            )?;
        }
    }
    Ok(())
}

fn benchmark_aegis_transaction_protocol(
    args: &Args,
    samples: &mut SampleWriter,
) -> Result<(), String> {
    for (profile, size) in payload_profiles() {
        let options = AegisTxBuildOptions {
            payload: payload(profile, size, 0),
            ..AegisTxBuildOptions::default()
        };
        for iteration in 0..args.keygen_iterations {
            let mut iteration_options = options.clone();
            iteration_options.nonce = iteration as u64;
            samples.measure(
                "protocol",
                "aegis_typed_transaction",
                "ML-DSA-65",
                "build_sign_verify_admit_carrier",
                profile,
                size,
                iteration,
                0,
                || {
                    let report = sign_with_new_aegis_transaction_key(iteration_options)?;
                    let envelope_bytes = serde_json::to_vec(&report.submission_envelope).map_err(|error| error.to_string())?;
                    let carrier_bytes = serde_json::to_vec(&report.rpc_transaction).map_err(|error| error.to_string())?;
                    let unsigned_bytes = report.transaction.signing_bytes()?.len();
                    Ok(Observation {
                        valid: report.signature_verification_result == "verified_through_aegis_pqvm",
                        result: "signed_verified_admitted_carrier_built".to_string(),
                        public_key_bytes: report.public_key.key_bytes.len(),
                        signature_bytes: report.transaction.aegis_pq_signature.signature_bytes.len(),
                        unsigned_serialized_bytes: unsigned_bytes,
                        serialized_bytes: envelope_bytes.len() + carrier_bytes.len(),
                        authentication_bytes: envelope_bytes.len().saturating_sub(unsigned_bytes),
                        item_count: 1,
                        notes: format!("envelope_json_bytes={}; carrier_json_bytes={}; authentication_bytes compares the submitted envelope with the canonical unsigned signing payload and does not include the duplicated legacy carrier", envelope_bytes.len(), carrier_bytes.len()),
                        ..Observation::default()
                    })
                },
            )?;
        }
        let report = sign_with_new_aegis_transaction_key(options)?;
        let signing_bytes = report.transaction.signing_bytes()?;
        let unsigned_bytes = signing_bytes.len();
        let canonical_bytes = report.transaction.canonical_bytes()?;
        let envelope_serialized =
            serde_json::to_vec(&report.submission_envelope).map_err(|error| error.to_string())?;
        let envelope_serialized_bytes = envelope_serialized.len();
        let carrier_serialized =
            serde_json::to_vec(&report.rpc_transaction).map_err(|error| error.to_string())?;
        for _ in 0..args.warmup_iterations {
            black_box(report.transaction.signing_bytes()?);
            black_box(report.transaction.canonical_bytes()?);
            black_box(report.transaction.canonical_tx_bytes_hash()?);
            black_box(
                serde_json::to_vec(&report.submission_envelope)
                    .map_err(|error| error.to_string())?,
            );
            black_box(
                serde_json::from_slice::<AegisTxSubmissionEnvelope>(&envelope_serialized)
                    .map_err(|error| error.to_string())?,
            );
            black_box(
                serde_json::to_vec(&report.rpc_transaction).map_err(|error| error.to_string())?,
            );
            verify_aegis_submission_envelope(black_box(&report.submission_envelope))?;
            validate_legacy_aegis_carrier_transaction(black_box(&report.rpc_transaction))?;
        }
        for iteration in 0..args.operation_iterations {
            samples.measure(
                "protocol",
                "aegis_typed_transaction_component",
                "canonical-json",
                "serialize_signing_payload",
                profile,
                size,
                iteration,
                args.warmup_iterations,
                || {
                    let serialized = report.transaction.signing_bytes()?;
                    Ok(Observation {
                        valid: serialized == signing_bytes,
                        result: "serialized".to_string(),
                        unsigned_serialized_bytes: serialized.len(),
                        serialized_bytes: serialized.len(),
                        item_count: 1,
                        notes: "exact production TransactionSigningPayload JSON used before Aegis domain transcript construction".to_string(),
                        ..Observation::default()
                    })
                },
            )?;
            samples.measure(
                "protocol",
                "aegis_typed_transaction_component",
                "canonical-json",
                "canonical_serialize_transaction",
                profile,
                size,
                iteration,
                args.warmup_iterations,
                || {
                    let serialized = report.transaction.canonical_bytes()?;
                    Ok(Observation {
                        valid: serialized == canonical_bytes,
                        result: "serialized".to_string(),
                        serialized_bytes: serialized.len(),
                        item_count: 1,
                        ..Observation::default()
                    })
                },
            )?;
            samples.measure(
                "protocol",
                "aegis_typed_transaction_component",
                "BLAKE3",
                "hash_canonical_transaction",
                profile,
                size,
                iteration,
                args.warmup_iterations,
                || {
                    let hash = report.transaction.canonical_tx_bytes_hash()?;
                    Ok(Observation {
                        valid: !hash.is_zero(),
                        result: "canonical_hash_computed".to_string(),
                        serialized_bytes: canonical_bytes.len(),
                        item_count: 1,
                        notes: "includes canonical transaction serialization plus domain-separated Hash construction".to_string(),
                        ..Observation::default()
                    })
                },
            )?;
            samples.measure(
                "protocol",
                "aegis_submission_envelope_component",
                "JSON",
                "serialize_submission_envelope",
                profile,
                size,
                iteration,
                args.warmup_iterations,
                || {
                    let serialized = serde_json::to_vec(&report.submission_envelope)
                        .map_err(|error| error.to_string())?;
                    Ok(Observation {
                        valid: serialized == envelope_serialized,
                        result: "serialized".to_string(),
                        unsigned_serialized_bytes: unsigned_bytes,
                        serialized_bytes: serialized.len(),
                        authentication_bytes: serialized.len().saturating_sub(unsigned_bytes),
                        item_count: 1,
                        ..Observation::default()
                    })
                },
            )?;
            samples.measure(
                "protocol",
                "aegis_submission_envelope_component",
                "JSON",
                "deserialize_submission_envelope",
                profile,
                size,
                iteration,
                args.warmup_iterations,
                || {
                    let decoded: AegisTxSubmissionEnvelope =
                        serde_json::from_slice(black_box(&envelope_serialized))
                            .map_err(|error| error.to_string())?;
                    let valid = decoded == report.submission_envelope;
                    Ok(Observation {
                        valid,
                        result: if valid {
                            "deserialized_equal"
                        } else {
                            "unexpected_decode_mismatch"
                        }
                        .to_string(),
                        serialized_bytes: envelope_serialized.len(),
                        item_count: 1,
                        ..Observation::default()
                    })
                },
            )?;
            samples.measure(
                "protocol",
                "aegis_typed_transaction",
                "ML-DSA-65",
                "verify_submission_envelope",
                profile,
                size,
                iteration,
                args.warmup_iterations,
                || {
                    verify_aegis_submission_envelope(black_box(&report.submission_envelope))?;
                    Ok(Observation {
                        valid: true,
                        result: "accepted".to_string(),
                        public_key_bytes: report.public_key.key_bytes.len(),
                        signature_bytes: report.transaction.aegis_pq_signature.signature_bytes.len(),
                        unsigned_serialized_bytes: unsigned_bytes,
                        serialized_bytes: envelope_serialized_bytes,
                        authentication_bytes: envelope_serialized_bytes.saturating_sub(unsigned_bytes),
                        item_count: 1,
                        notes: "constructs a fresh Aegis verifier for the envelope public key and lifecycle witness".to_string(),
                        ..Observation::default()
                    })
                },
            )?;
            samples.measure(
                "protocol",
                "aegis_legacy_carrier_component",
                "JSON",
                "serialize_carrier",
                profile,
                size,
                iteration,
                args.warmup_iterations,
                || {
                    let serialized = serde_json::to_vec(&report.rpc_transaction)
                        .map_err(|error| error.to_string())?;
                    Ok(Observation {
                        valid: serialized == carrier_serialized,
                        result: "serialized".to_string(),
                        serialized_bytes: serialized.len(),
                        item_count: 1,
                        ..Observation::default()
                    })
                },
            )?;
            samples.measure(
                "protocol",
                "aegis_legacy_carrier",
                "ML-DSA-65",
                "validate_carrier",
                profile,
                size,
                iteration,
                args.warmup_iterations,
                || {
                    validate_legacy_aegis_carrier_transaction(black_box(&report.rpc_transaction))?;
                    Ok(Observation {
                        valid: true,
                        result: "accepted".to_string(),
                        public_key_bytes: report.rpc_transaction.signer_public_key.len(),
                        signature_bytes: report.rpc_transaction.signature.len(),
                        serialized_bytes: serde_json::to_vec(&report.rpc_transaction)
                            .map_err(|error| error.to_string())?
                            .len(),
                        item_count: 1,
                        ..Observation::default()
                    })
                },
            )?;
        }

        let mut modified_payload = report.submission_envelope.clone();
        modified_payload.transaction.payload.push(0xff);
        let mut wrong_key_id = report.submission_envelope.clone();
        wrong_key_id.transaction.aegis_pq_key_id =
            AegisPqKeyId("aegis-benchmark-wrong-key-id".to_string());
        let mut malformed_public_key = report.submission_envelope.clone();
        malformed_public_key.public_key.key_bytes.pop();
        let mut wrong_lifecycle_role = report.submission_envelope.clone();
        wrong_lifecycle_role
            .lifecycle_record
            .roles
            .retain(|role| role != &AegisPqKeyRole::Transaction);
        let mut unknown_algorithm = report.submission_envelope.clone();
        unknown_algorithm.transaction.aegis_pq_signature.algorithm = "unknown-pqc".to_string();
        let malformed_json = &envelope_serialized[..envelope_serialized.len().saturating_sub(1)];
        let mut modified_carrier = report.rpc_transaction.clone();
        modified_carrier
            .data
            .get_or_insert_with(String::new)
            .push_str("-modified-after-envelope-validation");
        for iteration in 0..args.operation_iterations.min(50) {
            for (operation, candidate) in [
                ("reject_modified_payload", &modified_payload),
                ("reject_wrong_key_id", &wrong_key_id),
                ("reject_malformed_public_key", &malformed_public_key),
                ("reject_wrong_lifecycle_role", &wrong_lifecycle_role),
                ("reject_unknown_algorithm", &unknown_algorithm),
            ] {
                samples.measure(
                    "negative",
                    "aegis_submission_envelope",
                    "ML-DSA-65",
                    operation,
                    profile,
                    size,
                    iteration,
                    0,
                    || {
                        let rejected = verify_aegis_submission_envelope(candidate).is_err();
                        Ok(Observation {
                            valid: rejected,
                            result: if rejected {
                                "rejected"
                            } else {
                                "unexpected_acceptance"
                            }
                            .to_string(),
                            public_key_bytes: candidate.public_key.key_bytes.len(),
                            signature_bytes: candidate
                                .transaction
                                .aegis_pq_signature
                                .signature_bytes
                                .len(),
                            item_count: 1,
                            ..Observation::default()
                        })
                    },
                )?;
            }
            samples.measure(
                "negative",
                "aegis_submission_envelope_component",
                "JSON",
                "reject_malformed_json",
                profile,
                size,
                iteration,
                0,
                || {
                    let rejected = serde_json::from_slice::<AegisTxSubmissionEnvelope>(black_box(
                        malformed_json,
                    ))
                    .is_err();
                    Ok(Observation {
                        valid: rejected,
                        result: if rejected {
                            "rejected"
                        } else {
                            "unexpected_acceptance"
                        }
                        .to_string(),
                        serialized_bytes: malformed_json.len(),
                        item_count: 1,
                        ..Observation::default()
                    })
                },
            )?;
            samples.measure(
                "negative",
                "aegis_legacy_carrier",
                "ML-DSA-65",
                "reject_modified_carrier",
                profile,
                size,
                iteration,
                0,
                || {
                    let rejected =
                        validate_legacy_aegis_carrier_transaction(&modified_carrier).is_err();
                    Ok(Observation {
                        valid: rejected,
                        result: if rejected {
                            "rejected"
                        } else {
                            "unexpected_acceptance"
                        }
                        .to_string(),
                        serialized_bytes: serde_json::to_vec(&modified_carrier)
                            .map_err(|error| error.to_string())?
                            .len(),
                        item_count: 1,
                        ..Observation::default()
                    })
                },
            )?;
        }
    }
    Ok(())
}

#[derive(serde::Serialize)]
struct BenchmarkHandshakePqSigningPayload {
    node_id: String,
    version: String,
    capabilities: Vec<String>,
    chain_id: Option<u64>,
    chain_incarnation: Option<u64>,
    consensus_state_schema_version: Option<u32>,
    network_id: Option<u64>,
    network_id_text: Option<String>,
    genesis_hash: String,
    network_magic_bytes: String,
    protocol_version: Option<String>,
    consensus_version: Option<String>,
    native_caip2: Option<String>,
    reserved_eip155: Option<String>,
    public_address: Option<String>,
    validator_address: Option<String>,
    role: Option<String>,
    active_validator_set_hash: Option<String>,
    cluster_map_hash: Option<String>,
    protocol_config_hash: Option<String>,
    aegis_pqvm_version: Option<String>,
    aegis_pq_public_key_id: Option<String>,
    aegis_pq_public_key_algorithm: Option<String>,
    aegis_pq_public_key: Vec<u8>,
}

fn benchmark_handshake_signing_payload(message: &NetworkMessage) -> Result<Vec<u8>, String> {
    let NetworkMessage::Handshake {
        node_id,
        version,
        capabilities,
        chain_id,
        chain_incarnation,
        consensus_state_schema_version,
        network_id,
        network_id_text,
        genesis_hash,
        network_magic_bytes,
        protocol_version,
        consensus_version,
        native_caip2,
        reserved_eip155,
        public_address,
        validator_address,
        role,
        active_validator_set_hash,
        cluster_map_hash,
        protocol_config_hash,
        aegis_pqvm_version,
        aegis_pq_public_key_id,
        aegis_pq_public_key_algorithm,
        aegis_pq_public_key,
        ..
    } = message
    else {
        return Err("benchmark handshake payload requested for non-handshake".to_string());
    };
    serde_json::to_vec(&BenchmarkHandshakePqSigningPayload {
        node_id: node_id.clone(),
        version: version.clone(),
        capabilities: capabilities.clone(),
        chain_id: *chain_id,
        chain_incarnation: *chain_incarnation,
        consensus_state_schema_version: *consensus_state_schema_version,
        network_id: *network_id,
        network_id_text: network_id_text.clone(),
        genesis_hash: genesis_hash.clone(),
        network_magic_bytes: network_magic_bytes.clone(),
        protocol_version: protocol_version.clone(),
        consensus_version: consensus_version.clone(),
        native_caip2: native_caip2.clone(),
        reserved_eip155: reserved_eip155.clone(),
        public_address: public_address.clone(),
        validator_address: validator_address.clone(),
        role: role.clone(),
        active_validator_set_hash: active_validator_set_hash.clone(),
        cluster_map_hash: cluster_map_hash.clone(),
        protocol_config_hash: protocol_config_hash.clone(),
        aegis_pqvm_version: aegis_pqvm_version.clone(),
        aegis_pq_public_key_id: aegis_pq_public_key_id.clone(),
        aegis_pq_public_key_algorithm: aegis_pq_public_key_algorithm.clone(),
        aegis_pq_public_key: aegis_pq_public_key.clone(),
    })
    .map_err(|error| error.to_string())
}

fn benchmark_peer_handshake_protocol(
    args: &Args,
    samples: &mut SampleWriter,
) -> Result<(), String> {
    for (algorithm, validator) in [("ML-DSA-65", true), ("FN-DSA-1024", false)] {
        let uma_id = if validator { "Val1" } else { "rpc-gateway" };
        let mut signer =
            AegisPqvmSigner::initialize_required().map_err(|error| error.to_string())?;
        let key_id = if validator {
            signer
                .generate_and_register_key(
                    uma_id,
                    vec![
                        AegisPqKeyRole::PeerIdentity,
                        AegisPqKeyRole::ConsensusProposer,
                    ],
                    Epoch(0),
                )
                .map_err(|error| error.to_string())?
        } else {
            signer
                .generate_and_register_fndsa_peer_identity(uma_id, Epoch(0))
                .map_err(|error| error.to_string())?
        };
        let mut hello = benchmark_peer_hello(&key_id, validator);
        let mut hello_bytes = serde_json::to_vec(&hello).map_err(|error| error.to_string())?;
        let mut signature = signer
            .sign_peer_hello(&hello_bytes, &key_id)
            .map_err(|error| error.to_string())?;
        let verifier = signer.verifier();
        for _ in 0..args.warmup_iterations {
            signature = signer
                .sign_peer_hello(black_box(&hello_bytes), &key_id)
                .map_err(|error| error.to_string())?;
            verifier
                .verify_peer_identity_checked(black_box(&hello), &signature)
                .map_err(|error| error.to_string())?;
        }
        for iteration in 0..args.operation_iterations {
            hello.latest_finalized_height = Height(iteration as u64);
            hello_bytes = serde_json::to_vec(&hello).map_err(|error| error.to_string())?;
            samples.measure(
                "protocol",
                "p2p_peer_hello",
                algorithm,
                "sign_pre_serialized_handshake",
                if validator { "validator" } else { "support" },
                hello_bytes.len(),
                iteration,
                args.warmup_iterations,
                || {
                    signature = signer
                        .sign_peer_hello(black_box(&hello_bytes), &key_id)
                        .map_err(|error| error.to_string())?;
                    Ok(Observation {
                        valid: signature.is_present(),
                        result: "signed".to_string(),
                        signature_bytes: signature.signature_bytes.len(),
                        serialized_bytes: hello_bytes.len() + signature.signature_bytes.len(),
                        ..Observation::default()
                    })
                },
            )?;
            samples.measure(
                "protocol",
                "p2p_peer_hello",
                algorithm,
                "verify_handshake",
                if validator { "validator" } else { "support" },
                hello_bytes.len(),
                iteration,
                args.warmup_iterations,
                || {
                    verifier.verify_peer_identity_checked(black_box(&hello), &signature).map_err(|error| error.to_string())?;
                    Ok(Observation {
                        valid: true,
                        result: "accepted".to_string(),
                        signature_bytes: signature.signature_bytes.len(),
                        serialized_bytes: hello_bytes.len() + signature.signature_bytes.len(),
                        notes: "includes PeerHello JSON serialization inside verifier and Aegis policy/domain verification".to_string(),
                        ..Observation::default()
                    })
                },
            )?;
        }
        benchmark_network_handshake_source_equivalent(
            args,
            samples,
            algorithm,
            validator,
            uma_id,
            &mut signer,
            &key_id,
        )?;
    }
    Ok(())
}

fn benchmark_peer_hello(key_id: &AegisPqKeyId, validator: bool) -> PeerHello {
    PeerHello {
        node_id: if validator {
            "validator-node-01"
        } else {
            "rpc-gateway"
        }
        .to_string(),
        validator_id_optional: validator
            .then(|| synergy_testnet::synergy_types::ValidatorId("Val1".to_string())),
        role: if validator {
            "VALIDATOR"
        } else {
            "RPC_GATEWAY"
        }
        .to_string(),
        chain_id: ChainId::synergy_testnet_v3(),
        network_id: NetworkId::synergy_testnet_v3(),
        genesis_hash: Hash::from_domain_bytes("AEGIS_BENCH_GENESIS", b"chain1266"),
        protocol_version: "20.0.0".to_string(),
        consensus_version: COORDINATED_ROUND_ROBIN_V1.to_string(),
        execution_version: "testnet-v3".to_string(),
        dag_version: "etdag-v1".to_string(),
        aegis_pqvm_version: "0.1.0".to_string(),
        latest_finalized_height: Height(1),
        latest_finalized_hash: Hash::from_domain_bytes("AEGIS_BENCH_FINALIZED", b"block"),
        latest_state_root: Hash::from_domain_bytes("AEGIS_BENCH_STATE", b"state"),
        active_validator_set_hash: Hash::from_domain_bytes("AEGIS_BENCH_VALIDATORS", b"six"),
        cluster_map_hash: Hash::from_domain_bytes("AEGIS_BENCH_CLUSTER", b"map"),
        protocol_config_hash: ConsensusParameterRoot::from_canonical_manifest_bytes(
            b"aegis-bench-protocol-config",
        ),
        aegis_pq_public_key_id: key_id.clone(),
    }
}

fn benchmark_network_handshake_source_equivalent(
    args: &Args,
    samples: &mut SampleWriter,
    algorithm: &str,
    validator: bool,
    uma_id: &str,
    signer: &mut AegisPqvmSigner,
    key_id: &AegisPqKeyId,
) -> Result<(), String> {
    let public_key = signer
        .public_key_record(key_id)
        .map_err(|error| error.to_string())?;
    let lifecycle_record = signer
        .registry
        .lifecycle
        .record_for(uma_id, key_id)
        .ok_or("missing peer handshake lifecycle record")?
        .clone();
    let genesis = synergy_testnet::genesis::canonical_genesis()?;
    let profile = if validator { "validator" } else { "support" };
    let mut handshake = NetworkMessage::Handshake {
        node_id: uma_id.to_string(),
        version: "1.0.0".to_string(),
        capabilities: if validator {
            vec![
                "blocks".to_string(),
                "transactions".to_string(),
                "coordinated-round-robin-v1-validator".to_string(),
            ]
        } else {
            vec!["blocks".to_string(), "transactions".to_string()]
        },
        chain_id: Some(genesis.chain_id()),
        chain_incarnation: Some(synergy_testnet::synergy_types::TESTNET_V3_CHAIN_INCARNATION),
        consensus_state_schema_version: Some(
            synergy_testnet::synergy_types::TESTNET_V3_CONSENSUS_STATE_SCHEMA_VERSION,
        ),
        network_id: Some(genesis.network_id()),
        network_id_text: Some("synergy-testnet-v3".to_string()),
        genesis_hash: genesis.hash().to_string(),
        network_magic_bytes: genesis.network_magic_bytes().to_string(),
        protocol_version: Some("20.0.0".to_string()),
        consensus_version: Some(COORDINATED_ROUND_ROBIN_V1.to_string()),
        native_caip2: Some("synergy:testnet".to_string()),
        reserved_eip155: Some("eip155:1266".to_string()),
        public_address: Some("benchmark-not-routable".to_string()),
        validator_address: validator.then(|| "Val1".to_string()),
        role: Some(
            if validator {
                "VALIDATOR"
            } else {
                "RPC_GATEWAY"
            }
            .to_string(),
        ),
        active_validator_set_hash: Some(
            Hash::from_domain_bytes("AEGIS_BENCH_VALIDATORS", b"six").to_hex(),
        ),
        cluster_map_hash: Some(Hash::from_domain_bytes("AEGIS_BENCH_CLUSTER", b"map").to_hex()),
        protocol_config_hash: Some(
            ConsensusParameterRoot::from_canonical_manifest_bytes(b"aegis-bench-protocol-config")
                .to_hex(),
        ),
        aegis_pqvm_version: Some("aegis-pqvm".to_string()),
        aegis_pq_public_key_id: Some(key_id.0.clone()),
        aegis_pq_public_key_algorithm: Some(public_key.algorithm.clone()),
        aegis_pq_public_key: public_key.key_bytes.clone(),
        aegis_pq_handshake_signature: None,
    };
    let mut payload = benchmark_handshake_signing_payload(&handshake)?;
    let mut signature = signer
        .sign_peer_hello(&payload, key_id)
        .map_err(|error| error.to_string())?;
    if let NetworkMessage::Handshake {
        aegis_pq_handshake_signature,
        ..
    } = &mut handshake
    {
        *aegis_pq_handshake_signature = Some(signature.clone());
    }
    let mut frame = serde_json::to_vec(&handshake).map_err(|error| error.to_string())?;

    for _ in 0..args.warmup_iterations {
        payload = benchmark_handshake_signing_payload(&handshake)?;
        signature = signer
            .sign_peer_hello(&payload, key_id)
            .map_err(|error| error.to_string())?;
        if let NetworkMessage::Handshake {
            aegis_pq_handshake_signature,
            ..
        } = &mut handshake
        {
            *aegis_pq_handshake_signature = Some(signature.clone());
        }
        frame = serde_json::to_vec(&handshake).map_err(|error| error.to_string())?;
        black_box(
            serde_json::from_slice::<NetworkMessage>(&frame).map_err(|error| error.to_string())?,
        );
        let verifier = AegisPqvmVerifier::initialize_required_for_public_key(
            public_key.clone(),
            lifecycle_record.clone(),
        )
        .map_err(|error| error.to_string())?;
        verifier
            .verify_domain_signature(
                SYNERGY_P2P_HANDSHAKE_V1,
                &payload,
                uma_id,
                key_id,
                Epoch(0),
                AegisPqKeyRole::PeerIdentity,
                &signature,
            )
            .map_err(|error| error.to_string())?;
    }

    for iteration in 0..args.operation_iterations {
        samples.measure(
            "protocol",
            "p2p_network_handshake_source_equivalent",
            "JSON",
            "serialize_signing_payload",
            profile,
            0,
            iteration,
            args.warmup_iterations,
            || {
                payload = benchmark_handshake_signing_payload(&handshake)?;
                Ok(Observation {
                    valid: !payload.is_empty(),
                    result: "serialized".to_string(),
                    public_key_bytes: public_key.key_bytes.len(),
                    unsigned_serialized_bytes: payload.len(),
                    serialized_bytes: payload.len(),
                    item_count: 1,
                    notes: "field-for-field mirror of private production HandshakePqSigningPayload at the recorded source SHA".to_string(),
                    ..Observation::default()
                })
            },
        )?;
        samples.measure(
            "protocol",
            "p2p_network_handshake_source_equivalent",
            algorithm,
            "sign_handshake_payload",
            profile,
            payload.len(),
            iteration,
            args.warmup_iterations,
            || {
                signature = signer
                    .sign_peer_hello(black_box(&payload), key_id)
                    .map_err(|error| error.to_string())?;
                if let NetworkMessage::Handshake {
                    aegis_pq_handshake_signature,
                    ..
                } = &mut handshake
                {
                    *aegis_pq_handshake_signature = Some(signature.clone());
                }
                Ok(Observation {
                    valid: signature.is_present(),
                    result: "signed".to_string(),
                    public_key_bytes: public_key.key_bytes.len(),
                    signature_bytes: signature.signature_bytes.len(),
                    unsigned_serialized_bytes: payload.len(),
                    item_count: 1,
                    notes: "validator uses a local ephemeral ML-DSA-65 key of the deployed type; this does not measure Genesis key loading or identity authorization".to_string(),
                    ..Observation::default()
                })
            },
        )?;
        samples.measure(
            "protocol",
            "p2p_network_handshake_source_equivalent",
            "JSON",
            "serialize_signed_network_frame",
            profile,
            payload.len(),
            iteration,
            args.warmup_iterations,
            || {
                frame = serde_json::to_vec(&handshake).map_err(|error| error.to_string())?;
                let frame_bytes = frame
                    .len()
                    .checked_add(4)
                    .ok_or("P2P handshake frame length overflow")?;
                Ok(Observation {
                    valid: frame_bytes > payload.len(),
                    result: "serialized_with_four_byte_prefix".to_string(),
                    public_key_bytes: public_key.key_bytes.len(),
                    signature_bytes: signature.signature_bytes.len(),
                    unsigned_serialized_bytes: payload.len(),
                    serialized_bytes: frame_bytes,
                    authentication_bytes: frame_bytes.saturating_sub(payload.len()),
                    item_count: 1,
                    notes: "exact NetworkMessage JSON representation plus the production four-byte frame prefix; representative non-secret address and state-hash values".to_string(),
                    ..Observation::default()
                })
            },
        )?;
        samples.measure(
            "protocol",
            "p2p_network_handshake_source_equivalent",
            "JSON",
            "deserialize_signed_network_message",
            profile,
            frame.len(),
            iteration,
            args.warmup_iterations,
            || {
                let decoded: NetworkMessage =
                    serde_json::from_slice(black_box(&frame)).map_err(|error| error.to_string())?;
                let valid = matches!(decoded, NetworkMessage::Handshake { .. });
                Ok(Observation {
                    valid,
                    result: if valid {
                        "deserialized_handshake"
                    } else {
                        "unexpected_variant"
                    }
                    .to_string(),
                    serialized_bytes: frame.len(),
                    item_count: 1,
                    ..Observation::default()
                })
            },
        )?;
        samples.measure(
            "protocol",
            "p2p_network_handshake_source_equivalent",
            algorithm,
            "initialize_and_verify_handshake_authentication",
            profile,
            payload.len(),
            iteration,
            args.warmup_iterations,
            || {
                let verifier = AegisPqvmVerifier::initialize_required_for_public_key(
                    public_key.clone(),
                    lifecycle_record.clone(),
                )
                .map_err(|error| error.to_string())?;
                verifier
                    .verify_domain_signature(
                        SYNERGY_P2P_HANDSHAKE_V1,
                        black_box(&payload),
                        uma_id,
                        key_id,
                        Epoch(0),
                        AegisPqKeyRole::PeerIdentity,
                        &signature,
                    )
                    .map_err(|error| error.to_string())?;
                Ok(Observation {
                    valid: true,
                    result: "authentication_accepted".to_string(),
                    public_key_bytes: public_key.key_bytes.len(),
                    signature_bytes: signature.signature_bytes.len(),
                    unsigned_serialized_bytes: payload.len(),
                    serialized_bytes: frame.len().saturating_add(4),
                    item_count: 1,
                    notes: "includes fresh Aegis verifier initialization, required primitive smoke check, advertised-key lifecycle registration, policy/transcript checks, and primitive verification; excludes private networking function chain/Genesis/capability checks and validator Genesis key equality".to_string(),
                    ..Observation::default()
                })
            },
        )?;
    }
    Ok(())
}

fn benchmark_coordinated_envelopes(args: &Args, samples: &mut SampleWriter) -> Result<(), String> {
    let config = CoordinatedRoundRobinConfig {
        chain_id: 1266,
        network_id: "synergy-testnet-v3".to_string(),
        consensus_version: COORDINATED_ROUND_ROBIN_V1.to_string(),
        coordinator_id: "Val1".to_string(),
        producer_ids: (2..=6).map(|index| format!("Val{index}")).collect(),
        target_block_interval_ms: 2_000,
        producer_turn_timeout_ms: 10_000,
    };
    config.validate()?;
    let mut signer = AegisPqvmSigner::initialize_required().map_err(|error| error.to_string())?;
    let mut key_ids = Vec::new();
    let mut validators = Vec::new();
    for index in 1..=6 {
        let validator_id = format!("Val{index}");
        let key_id = signer
            .generate_and_register_key(
                &validator_id,
                vec![AegisPqKeyRole::ConsensusProposer],
                Epoch(0),
            )
            .map_err(|error| error.to_string())?;
        let public_key = signer
            .public_key_record(&key_id)
            .map_err(|error| error.to_string())?;
        validators.push(ValidatorRecord {
            validator_id: ValidatorId(validator_id.clone()),
            validator_uma_id: UmaId(validator_id),
            consensus_public_key: public_key.clone(),
            peer_public_key: public_key.clone(),
            operator_public_key: public_key,
            voting_weight: 1,
            status: ValidatorStatus::Active,
            cluster_id: ClusterId(0),
            activation_epoch: Epoch(0),
        });
        key_ids.push(key_id);
    }
    let key_id = key_ids[0].clone();
    let producer_key_id = key_ids[1].clone();
    let coordinated_verifier = CoordinatedConsensusVerifier::new(
        config.clone(),
        &ValidatorSet {
            epoch: Epoch(0),
            validators,
        },
        signer.verifier(),
    )?;
    let verifier = signer.verifier();
    for iteration in 0..args.operation_iterations {
        let mut assignment = ProducerAssignment {
            chain_id: 1266,
            network_id: "synergy-testnet-v3".to_string(),
            consensus_version: COORDINATED_ROUND_ROBIN_V1.to_string(),
            epoch: 0,
            height: iteration as u64 + 1,
            producer_round: 0,
            parent_block_hash: Hash::from_domain_bytes(
                "AEGIS_BENCH_PARENT",
                &(iteration as u64).to_be_bytes(),
            ),
            prior_finality_reference: Hash::from_domain_bytes(
                "AEGIS_BENCH_PRIOR_FINALITY",
                &(iteration as u64).to_be_bytes(),
            ),
            assigned_producer_id: format!("Val{}", iteration % 5 + 2),
            coordinator_id: "Val1".to_string(),
            assignment_sequence: iteration as u64,
            intended_block_timestamp_ms: 1_800_000_000_000 + iteration as u64 * 2_000,
            coordinator_signature: AegisPqSignature {
                algorithm: String::new(),
                signature_bytes: Vec::new(),
            },
        };
        samples.measure(
            "protocol",
            "coordinated_round_robin_v1",
            "ML-DSA-65",
            "assignment_hash_sign_serialize",
            "producer_assignment",
            0,
            iteration,
            0,
            || {
                let signing_hash = assignment.signing_hash()?;
                assignment.coordinator_signature = signer
                    .sign_domain(COORDINATED_ASSIGNMENT_DOMAIN, &signing_hash.0, &key_id)
                    .map_err(|error| error.to_string())?;
                assignment.validate_shape(&config)?;
                let serialized =
                    serde_json::to_vec(&assignment).map_err(|error| error.to_string())?;
                Ok(Observation {
                    valid: assignment.coordinator_signature.is_present(),
                    result: "signed_shape_valid".to_string(),
                    signature_bytes: assignment.coordinator_signature.signature_bytes.len(),
                    serialized_bytes: serialized.len(),
                    ..Observation::default()
                })
            },
        )?;
        samples.measure(
            "protocol",
            "coordinated_round_robin_v1",
            "ML-DSA-65",
            "verify_assignment_crypto",
            "producer_assignment",
            0,
            iteration,
            0,
            || {
                assignment.validate_shape(&config)?;
                verifier.verify_domain_signature(
                    COORDINATED_ASSIGNMENT_DOMAIN,
                    &assignment.signing_hash()?.0,
                    "Val1",
                    &key_id,
                    Epoch(0),
                    AegisPqKeyRole::ConsensusProposer,
                    &assignment.coordinator_signature,
                ).map_err(|error| error.to_string())?;
                Ok(Observation {
                    valid: true,
                    result: "accepted".to_string(),
                    signature_bytes: assignment.coordinator_signature.signature_bytes.len(),
                    serialized_bytes: serde_json::to_vec(&assignment).map_err(|error| error.to_string())?.len(),
                    notes: "measures assignment shape plus exact Aegis crypto; full finalized-validator-set package verification is a separate operation".to_string(),
                    ..Observation::default()
                })
            },
        )?;

        let assignment_hash = assignment.signing_hash()?;
        let mut commit = CoordinatorCommit {
            chain_id: 1266,
            network_id: "synergy-testnet-v3".to_string(),
            consensus_version: COORDINATED_ROUND_ROBIN_V1.to_string(),
            epoch: 0,
            height: assignment.height,
            producer_round: 0,
            parent_block_hash: assignment.parent_block_hash,
            prior_finality_reference: assignment.prior_finality_reference,
            block_hash: Hash::from_domain_bytes(
                "AEGIS_BENCH_BLOCK",
                &(iteration as u64).to_be_bytes(),
            ),
            transaction_root: Hash::from_domain_bytes(
                "AEGIS_BENCH_TX_ROOT",
                &(iteration as u64).to_be_bytes(),
            ),
            transaction_admission_root: Hash::from_domain_bytes(
                "AEGIS_BENCH_ADMISSION",
                &(iteration as u64).to_be_bytes(),
            ),
            receipt_root: Hash::from_domain_bytes(
                "AEGIS_BENCH_RECEIPT",
                &(iteration as u64).to_be_bytes(),
            ),
            state_root: Hash::from_domain_bytes(
                "AEGIS_BENCH_STATE",
                &(iteration as u64).to_be_bytes(),
            ),
            producer_id: assignment.assigned_producer_id.clone(),
            coordinator_id: "Val1".to_string(),
            assignment_hash,
            coordinator_signature: AegisPqSignature {
                algorithm: String::new(),
                signature_bytes: Vec::new(),
            },
        };
        samples.measure(
            "protocol",
            "coordinated_round_robin_v1",
            "ML-DSA-65",
            "commit_hash_sign_serialize",
            "coordinator_commit",
            0,
            iteration,
            0,
            || {
                commit.coordinator_signature = signer
                    .sign_domain(
                        COORDINATED_COMMIT_DOMAIN,
                        &commit.signing_hash()?.0,
                        &key_id,
                    )
                    .map_err(|error| error.to_string())?;
                commit.validate_shape(&config)?;
                let serialized = serde_json::to_vec(&commit).map_err(|error| error.to_string())?;
                Ok(Observation {
                    valid: commit.coordinator_signature.is_present(),
                    result: "signed_shape_valid".to_string(),
                    signature_bytes: commit.coordinator_signature.signature_bytes.len(),
                    serialized_bytes: serialized.len(),
                    ..Observation::default()
                })
            },
        )?;
        samples.measure(
            "protocol",
            "coordinated_round_robin_v1",
            "ML-DSA-65",
            "verify_commit_crypto",
            "coordinator_commit",
            0,
            iteration,
            0,
            || {
                commit.validate_shape(&config)?;
                verifier
                    .verify_domain_signature(
                        COORDINATED_COMMIT_DOMAIN,
                        &commit.signing_hash()?.0,
                        "Val1",
                        &key_id,
                        Epoch(0),
                        AegisPqKeyRole::ConsensusProposer,
                        &commit.coordinator_signature,
                    )
                    .map_err(|error| error.to_string())?;
                Ok(Observation {
                    valid: true,
                    result: "accepted".to_string(),
                    signature_bytes: commit.coordinator_signature.signature_bytes.len(),
                    serialized_bytes: serde_json::to_vec(&commit)
                        .map_err(|error| error.to_string())?
                        .len(),
                    ..Observation::default()
                })
            },
        )?;
    }

    for iteration in 0..args.operation_iterations {
        let package_iteration = iteration as u64 + 1_000_000;
        let mut package = None;
        samples.measure(
            "protocol",
            "coordinated_round_robin_v1_full_package",
            "ML-DSA-65",
            "build_sign_serialize_committed_package",
            "empty_block_three_authentications",
            0,
            iteration,
            0,
            || {
                let built = build_coordinated_package(
                    package_iteration,
                    &config,
                    &mut signer,
                    &key_id,
                    &producer_key_id,
                    Vec::new(),
                    Vec::new(),
                )?;
                let serialized_bytes = coordinated_package_frame_bytes(&built)?;
                let (unsigned_serialized_bytes, authentication_bytes) = coordinated_package_authentication_sizes(&built)?;
                let signature_bytes = built.block.proposer_signature.signature_bytes.len();
                let item_count = built.block.transactions.len();
                package = Some(built);
                Ok(Observation {
                    valid: true,
                    result: "three_signatures_built_and_serialized".to_string(),
                    work_units: 3,
                    item_count,
                    signature_bytes,
                    unsigned_serialized_bytes,
                    serialized_bytes,
                    authentication_bytes,
                    notes: "one Val1 assignment signature, one producer block signature, and one Val1 commit signature; no QC exists in coordinated_round_robin_v1".to_string(),
                    ..Observation::default()
                })
            },
        )?;
        let package = package.ok_or("full coordinated package was not constructed")?;
        samples.measure(
            "protocol",
            "coordinated_round_robin_v1_full_package",
            "ML-DSA-65",
            "verify_committed_block_package",
            "empty_block_three_authentications",
            0,
            iteration,
            0,
            || {
                coordinated_verifier.verify_committed_block_package(black_box(&package))?;
                Ok(Observation {
                    valid: true,
                    result: "accepted".to_string(),
                    work_units: 3,
                    item_count: package.block.transactions.len(),
                    signature_bytes: package.block.proposer_signature.signature_bytes.len(),
                    unsigned_serialized_bytes: coordinated_package_authentication_sizes(&package)?.0,
                    serialized_bytes: coordinated_package_frame_bytes(&package)?,
                    authentication_bytes: coordinated_package_authentication_sizes(&package)?.1,
                    notes: "exact finalized-set verifier performs assignment, producer-block, and coordinator-commit authentication plus structural bindings".to_string(),
                    ..Observation::default()
                })
            },
        )?;
    }
    benchmark_block_overhead(
        args,
        samples,
        &config,
        &mut signer,
        &key_id,
        &producer_key_id,
        &coordinated_verifier,
    )?;
    Ok(())
}

fn benchmark_block_overhead(
    args: &Args,
    samples: &mut SampleWriter,
    config: &CoordinatedRoundRobinConfig,
    signer: &mut AegisPqvmSigner,
    coordinator_key_id: &AegisPqKeyId,
    producer_key_id: &AegisPqKeyId,
    coordinated_verifier: &CoordinatedConsensusVerifier,
) -> Result<(), String> {
    const MAX_TRANSACTIONS: usize = 1_000;
    let mut reports = Vec::with_capacity(MAX_TRANSACTIONS);
    for index in 0..MAX_TRANSACTIONS {
        let report = sign_with_new_aegis_transaction_key(AegisTxBuildOptions {
            signer_uma_id: format!("block-overhead-signer-{index}"),
            nonce: index as u64,
            ttl_height: 10_000_000,
            write_set_hint: vec![format!("block-overhead-resource-{index}")],
            payload: payload("block-overhead-transaction512", 512, index),
            ..AegisTxBuildOptions::default()
        })?;
        reports.push(report);
    }

    for transaction_count in [
        1usize, 10, 100, 200, 225, 230, 231, 232, 233, 234, 235, 250, 500, 1_000,
    ] {
        let transactions = reports[..transaction_count]
            .iter()
            .map(|report| report.transaction.clone())
            .collect::<Vec<_>>();
        let admissions = reports[..transaction_count]
            .iter()
            .map(|report| report.submission_envelope.clone())
            .collect::<Vec<_>>();
        let iterations = args.keygen_iterations.min(10);
        for iteration in 0..iterations {
            let package_iteration = 2_000_000u64
                .saturating_add((transaction_count as u64).saturating_mul(100))
                .saturating_add(iteration as u64);
            let mut package = None;
            samples.measure(
                "protocol",
                "coordinated_block_authentication",
                "ML-DSA-65",
                "build_sign_serialize_block_package",
                &format!("transactions{transaction_count}_payload512"),
                512,
                iteration,
                0,
                || {
                    let built = build_coordinated_package(
                        package_iteration,
                        config,
                        signer,
                        coordinator_key_id,
                        producer_key_id,
                        transactions.clone(),
                        admissions.clone(),
                    )?;
                    let serialized_bytes = coordinated_package_frame_bytes(&built)?;
                    let (unsigned_serialized_bytes, authentication_bytes) =
                        coordinated_package_authentication_sizes(&built)?;
                    let signature_bytes = built.block.proposer_signature.signature_bytes.len();
                    package = Some(built);
                    Ok(Observation {
                        valid: true,
                        result: "actual_signed_package_serialized".to_string(),
                        work_units: 3,
                        item_count: transaction_count,
                        signature_bytes,
                        unsigned_serialized_bytes,
                        serialized_bytes,
                        authentication_bytes,
                        notes: "authentication_bytes is the exact JSON-size delta after clearing transaction key IDs, transaction signatures, public-key witnesses, lifecycle witness identity/roles, and the three consensus signatures; structural field names remain".to_string(),
                        ..Observation::default()
                    })
                },
            )?;
            let package = package.ok_or("coordinated block package was not built")?;
            samples.measure(
                "protocol",
                "coordinated_block_authentication",
                "ML-DSA-65",
                "verify_block_package_authentication",
                &format!("transactions{transaction_count}_payload512"),
                512,
                iteration,
                0,
                || {
                    coordinated_verifier.verify_committed_block_package(black_box(&package))?;
                    let serialized_bytes = coordinated_package_frame_bytes(&package)?;
                    let (unsigned_serialized_bytes, authentication_bytes) =
                        coordinated_package_authentication_sizes(&package)?;
                    Ok(Observation {
                        valid: true,
                        result: "accepted".to_string(),
                        work_units: transaction_count + 3,
                        item_count: transaction_count,
                        signature_bytes: package.block.proposer_signature.signature_bytes.len(),
                        unsigned_serialized_bytes,
                        serialized_bytes,
                        authentication_bytes,
                        notes: "work_units counts one Aegis transaction-envelope verification per transaction plus assignment, producer-block, and commit verification".to_string(),
                        ..Observation::default()
                    })
                },
            )?;
            for (message_kind, message) in [
                (
                    "assignment",
                    CoordinatedConsensusMessage::ProducerAssignment {
                        assignment: package.assignment.clone(),
                    },
                ),
                (
                    "proposal",
                    CoordinatedConsensusMessage::ProposedBlock {
                        assignment: package.assignment.clone(),
                        proposal: package.proposal.clone(),
                        block: package.block.clone(),
                    },
                ),
                (
                    "committed",
                    CoordinatedConsensusMessage::CommittedBlock {
                        package: package.clone(),
                    },
                ),
            ] {
                samples.measure(
                    "protocol",
                    "coordinated_p2p_frame",
                    "ML-DSA-65",
                    &format!("serialize_{message_kind}_network_frame"),
                    &format!("transactions{transaction_count}_payload512"),
                    512,
                    iteration,
                    0,
                    || {
                        let serialized_bytes = coordinated_message_frame_bytes(&message)?;
                        let (unsigned_serialized_bytes, authentication_bytes) =
                            coordinated_message_authentication_sizes(&message)?;
                        Ok(Observation {
                            valid: true,
                            result: "exact_network_frame_serialized".to_string(),
                            item_count: transaction_count,
                            unsigned_serialized_bytes,
                            serialized_bytes,
                            authentication_bytes,
                            notes: "exact NetworkMessage JSON plus four-byte length prefix; authentication delta clears key IDs, signatures, public-key witnesses, and lifecycle identity/role witnesses while retaining structure".to_string(),
                            ..Observation::default()
                        })
                    },
                )?;
            }
            samples.measure(
                "protocol",
                "coordinated_p2p_frame_guard",
                "ML-DSA-65",
                "validate_exact_frame_size",
                &format!("transactions{transaction_count}_payload512"),
                512,
                iteration,
                0,
                || {
                    let frame_bytes = coordinated_package_frame_bytes(&package)?;
                    let message = CoordinatedConsensusMessage::CommittedBlock {
                        package: package.clone(),
                    };
                    let result = validate_coordinated_consensus_message_size(&message);
                    let expected_acceptance =
                        frame_bytes <= MAX_COORDINATED_CONSENSUS_BLOCK_PACKAGE_FRAME_BYTES;
                    let behavior_matches_limit = result.is_ok() == expected_acceptance;
                    Ok(Observation {
                        valid: behavior_matches_limit,
                        result: match (result.is_ok(), expected_acceptance) {
                            (true, true) => "accepted_within_8mib_limit",
                            (false, false) => "rejected_above_8mib_limit",
                            (true, false) => "unexpected_oversize_acceptance",
                            (false, true) => "unexpected_in_limit_rejection",
                        }
                        .to_string(),
                        item_count: transaction_count,
                        serialized_bytes: frame_bytes,
                        notes: format!("exact NetworkMessage JSON plus four-byte length prefix; configured limit={MAX_COORDINATED_CONSENSUS_BLOCK_PACKAGE_FRAME_BYTES}"),
                        ..Observation::default()
                    })
                },
            )?;
        }
    }
    Ok(())
}

fn coordinated_package_authentication_sizes(
    package: &CoordinatedCommittedBlockPackage,
) -> Result<(usize, usize), String> {
    let serialized_bytes = coordinated_package_frame_bytes(package)?;
    let mut unsigned = package.clone();
    clear_coordinated_package_authentication(&mut unsigned);
    let unsigned_serialized_bytes = coordinated_package_frame_bytes(&unsigned)?;
    Ok((
        unsigned_serialized_bytes,
        serialized_bytes.saturating_sub(unsigned_serialized_bytes),
    ))
}

fn clear_signature(signature: &mut AegisPqSignature) {
    *signature = AegisPqSignature {
        algorithm: String::new(),
        signature_bytes: Vec::new(),
    };
}

fn clear_typed_transaction_authentication(transaction: &mut TypedTransaction) {
    transaction.aegis_pq_key_id = AegisPqKeyId(String::new());
    clear_signature(&mut transaction.aegis_pq_signature);
}

fn clear_submission_envelope_authentication(admission: &mut AegisTxSubmissionEnvelope) {
    clear_typed_transaction_authentication(&mut admission.transaction);
    admission.public_key.key_id = AegisPqKeyId(String::new());
    admission.public_key.algorithm.clear();
    admission.public_key.key_bytes.clear();
    admission.lifecycle_record.uma_id.clear();
    admission.lifecycle_record.key_id = AegisPqKeyId(String::new());
    admission.lifecycle_record.roles.clear();
}

fn clear_coordinated_package_authentication(package: &mut CoordinatedCommittedBlockPackage) {
    clear_signature(&mut package.assignment.coordinator_signature);
    clear_signature(&mut package.block.proposer_signature);
    clear_signature(&mut package.proposal.producer_signature);
    clear_signature(&mut package.coordinator_commit.coordinator_signature);
    for transaction in &mut package.block.transactions {
        transaction.aegis_pq_key_id = AegisPqKeyId(String::new());
        clear_signature(&mut transaction.aegis_pq_signature);
    }
    for admission in &mut package.proposal.transaction_admissions {
        clear_submission_envelope_authentication(admission);
    }
}

fn coordinated_package_frame_bytes(
    package: &CoordinatedCommittedBlockPackage,
) -> Result<usize, String> {
    coordinated_message_frame_bytes(&CoordinatedConsensusMessage::CommittedBlock {
        package: package.clone(),
    })
}

fn coordinated_message_frame_bytes(message: &CoordinatedConsensusMessage) -> Result<usize, String> {
    let genesis_hash = synergy_testnet::genesis::canonical_genesis()?
        .hash()
        .to_string();
    let network_message = NetworkMessage::CoordinatedConsensus {
        chain_incarnation: synergy_testnet::synergy_types::TESTNET_V3_CHAIN_INCARNATION,
        genesis_hash,
        message: message.clone(),
    };
    serde_json::to_vec(&network_message)
        .map_err(|error| error.to_string())?
        .len()
        .checked_add(4)
        .ok_or_else(|| "coordinated frame length overflow".to_string())
}

fn coordinated_message_authentication_sizes(
    message: &CoordinatedConsensusMessage,
) -> Result<(usize, usize), String> {
    let serialized_bytes = coordinated_message_frame_bytes(message)?;
    let mut unsigned = message.clone();
    match &mut unsigned {
        CoordinatedConsensusMessage::ProducerAssignment { assignment } => {
            clear_signature(&mut assignment.coordinator_signature);
        }
        CoordinatedConsensusMessage::ProposedBlock {
            assignment,
            proposal,
            block,
        } => {
            clear_signature(&mut assignment.coordinator_signature);
            clear_signature(&mut proposal.producer_signature);
            clear_signature(&mut block.proposer_signature);
            for transaction in &mut block.transactions {
                clear_typed_transaction_authentication(transaction);
            }
            for admission in &mut proposal.transaction_admissions {
                clear_submission_envelope_authentication(admission);
            }
        }
        CoordinatedConsensusMessage::CoordinatorCommit { package }
        | CoordinatedConsensusMessage::CommittedBlock { package } => {
            clear_coordinated_package_authentication(package);
        }
        _ => {}
    }
    let unsigned_serialized_bytes = coordinated_message_frame_bytes(&unsigned)?;
    Ok((
        unsigned_serialized_bytes,
        serialized_bytes.saturating_sub(unsigned_serialized_bytes),
    ))
}

fn build_coordinated_package(
    iteration: u64,
    config: &CoordinatedRoundRobinConfig,
    signer: &mut AegisPqvmSigner,
    coordinator_key_id: &AegisPqKeyId,
    producer_key_id: &AegisPqKeyId,
    transactions: Vec<TypedTransaction>,
    transaction_admissions: Vec<AegisTxSubmissionEnvelope>,
) -> Result<CoordinatedCommittedBlockPackage, String> {
    let parent_block_hash = Hash::from_domain_bytes("AEGIS_BENCH_PARENT", &iteration.to_be_bytes());
    let prior_finality_reference =
        Hash::from_domain_bytes("AEGIS_BENCH_PRIOR_FINALITY", &iteration.to_be_bytes());
    let parent_state_root =
        Hash::from_domain_bytes("AEGIS_BENCH_PARENT_STATE", &iteration.to_be_bytes());
    let state_root = Hash::from_domain_bytes("AEGIS_BENCH_STATE", &iteration.to_be_bytes());
    let receipt_root = Hash::from_domain_bytes("AEGIS_BENCH_RECEIPT", &iteration.to_be_bytes());
    let transaction_ids = coordinated_transaction_ids(&transactions)?;
    let transaction_root = compute_tx_order_root(&transaction_ids)?;
    let transaction_admission_root =
        coordinated_transaction_admission_root(&transaction_admissions)?;
    let mut assignment = ProducerAssignment {
        chain_id: config.chain_id,
        network_id: config.network_id.clone(),
        consensus_version: config.consensus_version.clone(),
        epoch: 0,
        height: iteration + 1,
        producer_round: 0,
        parent_block_hash,
        prior_finality_reference,
        assigned_producer_id: "Val2".to_string(),
        coordinator_id: "Val1".to_string(),
        assignment_sequence: iteration,
        intended_block_timestamp_ms: 1_800_000_000_000 + iteration.saturating_mul(2_000),
        coordinator_signature: AegisPqSignature {
            algorithm: String::new(),
            signature_bytes: Vec::new(),
        },
    };
    assignment.coordinator_signature = signer
        .sign_domain(
            COORDINATED_ASSIGNMENT_DOMAIN,
            &assignment.signing_hash()?.0,
            coordinator_key_id,
        )
        .map_err(|error| error.to_string())?;
    let mut block = TypedBlock {
        header: BlockHeader {
            version: 1,
            chain_id: ChainId::synergy_testnet_v3(),
            network_id: NetworkId::synergy_testnet_v3(),
            protocol_version: COORDINATED_ROUND_ROBIN_V1.to_string(),
            height: Height(assignment.height),
            round: Round(0),
            epoch: Epoch(0),
            cluster_id: ClusterId(0),
            height_context_root: Hash::from_domain_bytes(
                "AEGIS_BENCH_HEIGHT_CONTEXT",
                &iteration.to_be_bytes(),
            ),
            parent_block_hash,
            parent_state_root,
            last_finalized_qc_hash: Hash::zero(),
            proposer_validator_id: ValidatorId("Val2".to_string()),
            proposer_uma_id: UmaId("Val2".to_string()),
            proposer_key_id: producer_key_id.clone(),
            active_validator_set_hash: Hash::from_domain_bytes("AEGIS_BENCH_VALIDATOR_SET", b"six"),
            eligible_validator_set_hash: Hash::from_domain_bytes(
                "AEGIS_BENCH_ELIGIBLE_SET",
                b"six",
            ),
            validator_consensus_key_root: Hash::from_domain_bytes(
                "AEGIS_BENCH_CONSENSUS_KEYS",
                b"six",
            ),
            frozen_bonded_weight_root: Hash::from_domain_bytes("AEGIS_BENCH_WEIGHTS", b"six"),
            cluster_schedule_version: "coordinated-v1".to_string(),
            cluster_map_hash: Hash::from_domain_bytes("AEGIS_BENCH_CLUSTER_MAP", b"single"),
            assigned_cluster_membership_root: Hash::from_domain_bytes(
                "AEGIS_BENCH_CLUSTER_MEMBERS",
                b"six",
            ),
            assigned_cluster_validator_count: 6,
            assigned_cluster_total_voting_weight: 6,
            proposer_schedule_hash: Hash::from_domain_bytes(
                "AEGIS_BENCH_PRODUCER_SCHEDULE",
                b"round-robin",
            ),
            protocol_config_hash: ConsensusParameterRoot::from_canonical_manifest_bytes(
                b"aegis-bench-coordinated-parameters",
            ),
            cryptographic_profile_root: Hash::from_domain_bytes(
                "AEGIS_BENCH_CRYPTO_PROFILE",
                b"aegis",
            ),
            dag_frontier_root: coordinated_dag_frontier_root(
                parent_block_hash,
                transaction_root,
                transaction_admission_root,
            ),
            tx_order_root: transaction_root,
            tx_count: transactions.len() as u64,
            protected_batch: None,
            evidence_root: prior_finality_reference,
            state_root_before: parent_state_root,
            state_root_after: state_root,
            receipt_root,
            app_version: 1,
            execution_version: 1,
            dag_version: 1,
            aegis_pqvm_version: "aegis-pqvm".to_string(),
            timestamp_ms_consensus_bounded: assignment.intended_block_timestamp_ms,
        },
        transactions,
        proposer_signature: AegisPqSignature {
            algorithm: String::new(),
            signature_bytes: Vec::new(),
        },
    };
    block.proposer_signature = signer
        .sign_domain(
            SYNERGY_BLOCK_V1,
            &block.header.canonical_bytes()?,
            producer_key_id,
        )
        .map_err(|error| error.to_string())?;
    let block_hash = Hash::from_hex(&block.block_id()?.0)?;
    let proposal = CoordinatedProposal {
        epoch: 0,
        height: assignment.height,
        producer_round: 0,
        parent_block_hash,
        prior_finality_reference,
        block_hash,
        transaction_root,
        transaction_admission_root,
        transaction_admissions,
        receipt_root,
        state_root,
        producer_id: "Val2".to_string(),
        assignment_hash: assignment.signing_hash()?,
        producer_signature: block.proposer_signature.clone(),
    };
    let mut coordinator_commit = CoordinatorCommit {
        chain_id: config.chain_id,
        network_id: config.network_id.clone(),
        consensus_version: config.consensus_version.clone(),
        epoch: 0,
        height: assignment.height,
        producer_round: 0,
        parent_block_hash,
        prior_finality_reference,
        block_hash,
        transaction_root,
        transaction_admission_root,
        receipt_root,
        state_root,
        producer_id: "Val2".to_string(),
        coordinator_id: "Val1".to_string(),
        assignment_hash: assignment.signing_hash()?,
        coordinator_signature: AegisPqSignature {
            algorithm: String::new(),
            signature_bytes: Vec::new(),
        },
    };
    coordinator_commit.coordinator_signature = signer
        .sign_domain(
            COORDINATED_COMMIT_DOMAIN,
            &coordinator_commit.signing_hash()?.0,
            coordinator_key_id,
        )
        .map_err(|error| error.to_string())?;
    Ok(CoordinatedCommittedBlockPackage {
        block,
        assignment,
        proposal,
        coordinator_commit,
    })
}

fn benchmark_controlled_verification_load(
    args: &Args,
    samples: &mut SampleWriter,
) -> Result<(), String> {
    let configured_workers =
        env::var("SYNERGY_PQC_VERIFY_WORKERS").unwrap_or_else(|_| "default".to_string());
    let uma_id = "aegis-controlled-load";
    let mut signer = AegisPqvmSigner::initialize_required().map_err(|error| error.to_string())?;
    let key_id = signer
        .generate_and_register_key(uma_id, vec![AegisPqKeyRole::Transaction], Epoch(0))
        .map_err(|error| error.to_string())?;
    let verifier = signer.verifier();
    for concurrency in [1usize, 2, 4, 8, 16, 64, 65, 128] {
        let load_seed = format!("controlled-concurrent-verification-{concurrency}");
        let iterations = args.operation_iterations.min(100);
        for iteration in 0..iterations {
            let mut inputs = Vec::with_capacity(concurrency);
            for index in 0..concurrency {
                let message = payload(
                    &load_seed,
                    512,
                    iteration.saturating_mul(concurrency).saturating_add(index),
                );
                let signature = signer
                    .sign_domain(SYNERGY_TX_V1, &message, &key_id)
                    .map_err(|error| error.to_string())?;
                inputs.push((message, signature));
            }
            samples.measure(
                "load",
                "aegis_bounded_verification_pool",
                "ML-DSA-65",
                "concurrent_verify_burst",
                &format!("workers{configured_workers}_concurrency{concurrency}"),
                512,
                iteration,
                0,
                || {
                    let barrier = Arc::new(Barrier::new(concurrency + 1));
                    let outcomes = thread::scope(|scope| {
                        let mut handles = Vec::with_capacity(concurrency);
                        for (message, signature) in &inputs {
                            let verifier = verifier.clone();
                            let barrier = Arc::clone(&barrier);
                            let key_id = key_id.clone();
                            handles.push(scope.spawn(move || {
                                barrier.wait();
                                verifier
                                    .verify_domain_signature(
                                        SYNERGY_TX_V1,
                                        message,
                                        uma_id,
                                        &key_id,
                                        Epoch(0),
                                        AegisPqKeyRole::Transaction,
                                        signature,
                                    )
                                    .map_err(|error| error.to_string())
                            }));
                        }
                        barrier.wait();
                        handles
                            .into_iter()
                            .map(|handle| {
                                handle
                                    .join()
                                    .map_err(|_| "controlled verification worker panicked".to_string())?
                            })
                            .collect::<Vec<Result<(), String>>>()
                    });
                    let accepted = outcomes.iter().filter(|outcome| outcome.is_ok()).count();
                    let saturated = outcomes
                        .iter()
                        .filter(|outcome| {
                            outcome
                                .as_ref()
                                .err()
                                .is_some_and(|error| error.contains("verification pool is saturated"))
                        })
                        .count();
                    let unexpected = outcomes.len().saturating_sub(accepted + saturated);
                    Ok(Observation {
                        valid: unexpected == 0,
                        result: format!("accepted={accepted};saturated={saturated};unexpected={unexpected}"),
                        work_units: accepted,
                        item_count: concurrency,
                        signature_bytes: inputs.first().map(|input| input.1.signature_bytes.len()).unwrap_or(0),
                        notes: "controlled local burst; wall time includes scoped-thread creation, Aegis policy/transcript processing, bounded-pool admission, primitive verification, and joins; work_units counts accepted verifications only".to_string(),
                        ..Observation::default()
                    })
                },
            )?;
        }
    }
    Ok(())
}

fn main() -> Result<(), String> {
    let args = parse_args()?;
    let mut samples = SampleWriter::create(&args)?;
    if matches!(args.suite.as_str(), "all" | "primitive") {
        benchmark_primitive(&args, &mut samples)?;
    }
    if matches!(args.suite.as_str(), "all" | "aegis") {
        benchmark_aegis(&args, &mut samples)?;
    }
    if matches!(args.suite.as_str(), "all" | "lifecycle") {
        benchmark_lifecycle(&args, &mut samples)?;
    }
    if matches!(args.suite.as_str(), "all" | "protocol") {
        benchmark_protocol(&args, &mut samples)?;
    }
    if matches!(args.suite.as_str(), "all" | "load") {
        benchmark_controlled_verification_load(&args, &mut samples)?;
    }
    samples.flush()?;
    eprintln!("wrote measured raw samples to {}", args.output.display());
    Ok(())
}
