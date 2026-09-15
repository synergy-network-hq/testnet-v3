use std::env;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use synergy_testnet::crypto::aegis_pqvm::{AegisPqvmSigner, SYNERGY_TX_V1};
use synergy_testnet::synergy_types::{AegisPqKeyRole, Epoch};

#[derive(Clone, Copy)]
struct ResourceSnapshot {
    cpu_ns: u64,
    max_rss_bytes: u64,
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
    let cpu_ns = usage.ru_utime.tv_sec.max(0) as u64 * 1_000_000_000
        + usage.ru_utime.tv_usec.max(0) as u64 * 1_000
        + usage.ru_stime.tv_sec.max(0) as u64 * 1_000_000_000
        + usage.ru_stime.tv_usec.max(0) as u64 * 1_000;
    #[cfg(target_os = "macos")]
    let max_rss_bytes = usage.ru_maxrss.max(0) as u64;
    #[cfg(not(target_os = "macos"))]
    let max_rss_bytes = usage.ru_maxrss.max(0) as u64 * 1_024;
    ResourceSnapshot {
        cpu_ns,
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

fn csv_field(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

struct Args {
    output: PathBuf,
    environment_id: String,
    source_commit: String,
    iteration: usize,
}

fn parse_args() -> Result<Args, String> {
    let mut output = None;
    let mut environment_id = None;
    let mut source_commit = None;
    let mut iteration = None;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
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
            "--iteration" => {
                iteration = Some(
                    args.next()
                        .ok_or("--iteration requires a value")?
                        .parse::<usize>()
                        .map_err(|_| "invalid --iteration".to_string())?,
                )
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(Args {
        output: output.ok_or("--output is required")?,
        environment_id: environment_id.ok_or("--environment-id is required")?,
        source_commit: source_commit.ok_or("--source-commit is required")?,
        iteration: iteration.ok_or("--iteration is required")?,
    })
}

struct ColdWriter {
    writer: BufWriter<File>,
    run_id: String,
    args: Args,
}

impl ColdWriter {
    fn create(args: Args) -> Result<Self, String> {
        if let Some(parent) = args.output.parent() {
            fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let file = File::create(&args.output).map_err(|error| error.to_string())?;
        let mut writer = BufWriter::new(file);
        writeln!(writer, "run_id,environment_id,source_commit,classification,sample_recorded_unix_ns,suite,layer,algorithm,operation,payload_profile,message_bytes,iteration,warmup_iterations,wall_ns,cpu_ns,max_rss_bytes,valid,result,work_units,item_count,public_key_bytes,private_key_bytes,signature_bytes,ciphertext_bytes,shared_secret_bytes,unsigned_serialized_bytes,serialized_bytes,authentication_bytes,notes").map_err(|error| error.to_string())?;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_nanos();
        Ok(Self {
            writer,
            run_id: format!("cold-{}-{nanos}", std::process::id()),
            args,
        })
    }

    fn row(
        &mut self,
        operation: &str,
        wall_ns: u128,
        before: ResourceSnapshot,
        after: ResourceSnapshot,
        valid: bool,
        result: &str,
        public_key_bytes: usize,
        private_key_bytes: usize,
        signature_bytes: usize,
        notes: &str,
    ) -> Result<(), String> {
        let sample_recorded_unix_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_nanos();
        let values = [
            csv_field(&self.run_id),
            csv_field(&self.args.environment_id),
            csv_field(&self.args.source_commit),
            "MEASURED".to_string(),
            sample_recorded_unix_ns.to_string(),
            "cold_start".to_string(),
            "fresh_process_aegis".to_string(),
            "ML-DSA-65".to_string(),
            csv_field(operation),
            "transaction512".to_string(),
            "512".to_string(),
            self.args.iteration.to_string(),
            "0".to_string(),
            wall_ns.to_string(),
            after.cpu_ns.saturating_sub(before.cpu_ns).to_string(),
            after.max_rss_bytes.to_string(),
            valid.to_string(),
            csv_field(result),
            "1".to_string(),
            "0".to_string(),
            public_key_bytes.to_string(),
            private_key_bytes.to_string(),
            signature_bytes.to_string(),
            "0".to_string(),
            "0".to_string(),
            "0".to_string(),
            "0".to_string(),
            "0".to_string(),
            csv_field(notes),
        ];
        writeln!(self.writer, "{}", values.join(",")).map_err(|error| error.to_string())
    }
}

fn main() -> Result<(), String> {
    let args = parse_args()?;
    let mut output = ColdWriter::create(args)?;
    let message = vec![0x41; 512];

    let before = resources();
    let started = Instant::now();
    let mut signer = AegisPqvmSigner::initialize_required().map_err(|error| error.to_string())?;
    let elapsed = started.elapsed().as_nanos();
    let after = resources();
    output.row(
        "first_signer_initialize",
        elapsed,
        before,
        after,
        true,
        "initialized",
        0,
        0,
        0,
        "includes the process-local required ML-DSA-65 smoke check",
    )?;

    let before = resources();
    let started = Instant::now();
    let key_id = signer
        .generate_and_register_key(
            "cold-start-signer",
            vec![AegisPqKeyRole::Transaction],
            Epoch(0),
        )
        .map_err(|error| error.to_string())?;
    let elapsed = started.elapsed().as_nanos();
    let after = resources();
    let public_key = signer
        .public_key_record(&key_id)
        .map_err(|error| error.to_string())?;
    output.row(
        "first_keygen_register",
        elapsed,
        before,
        after,
        true,
        "registered",
        public_key.key_bytes.len(),
        0,
        0,
        "ML-DSA-65 key generation plus Aegis lifecycle registration",
    )?;

    let before = resources();
    let started = Instant::now();
    let first_signature = signer
        .sign_domain(SYNERGY_TX_V1, &message, &key_id)
        .map_err(|error| error.to_string())?;
    let elapsed = started.elapsed().as_nanos();
    let after = resources();
    output.row(
        "first_domain_sign",
        elapsed,
        before,
        after,
        first_signature.is_present(),
        "signed",
        public_key.key_bytes.len(),
        0,
        first_signature.signature_bytes.len(),
        "first production-domain signature after initialization",
    )?;

    let before = resources();
    let started = Instant::now();
    let verifier = signer.verifier();
    let elapsed = started.elapsed().as_nanos();
    let after = resources();
    output.row(
        "first_verifier_initialize",
        elapsed,
        before,
        after,
        true,
        "initialized",
        public_key.key_bytes.len(),
        0,
        0,
        "includes the process-local required verifier smoke check and registry clone",
    )?;

    let before = resources();
    let started = Instant::now();
    verifier
        .verify_domain_signature(
            SYNERGY_TX_V1,
            &message,
            "cold-start-signer",
            &key_id,
            Epoch(0),
            AegisPqKeyRole::Transaction,
            &first_signature,
        )
        .map_err(|error| error.to_string())?;
    let elapsed = started.elapsed().as_nanos();
    let after = resources();
    output.row(
        "first_domain_verify",
        elapsed,
        before,
        after,
        true,
        "accepted_cache_miss",
        public_key.key_bytes.len(),
        0,
        first_signature.signature_bytes.len(),
        "first production-domain verification after verifier initialization",
    )?;

    let warm_message = vec![0x42; 512];
    let before = resources();
    let started = Instant::now();
    let warm_signature = signer
        .sign_domain(SYNERGY_TX_V1, &warm_message, &key_id)
        .map_err(|error| error.to_string())?;
    let elapsed = started.elapsed().as_nanos();
    let after = resources();
    output.row(
        "second_domain_sign",
        elapsed,
        before,
        after,
        warm_signature.is_present(),
        "signed",
        public_key.key_bytes.len(),
        0,
        warm_signature.signature_bytes.len(),
        "warm process-local domain signature",
    )?;

    let before = resources();
    let started = Instant::now();
    verifier
        .verify_domain_signature(
            SYNERGY_TX_V1,
            &warm_message,
            "cold-start-signer",
            &key_id,
            Epoch(0),
            AegisPqKeyRole::Transaction,
            &warm_signature,
        )
        .map_err(|error| error.to_string())?;
    let elapsed = started.elapsed().as_nanos();
    let after = resources();
    output.row(
        "second_domain_verify",
        elapsed,
        before,
        after,
        true,
        "accepted_cache_miss",
        public_key.key_bytes.len(),
        0,
        warm_signature.signature_bytes.len(),
        "warm process-local cache-miss verification",
    )?;

    output.writer.flush().map_err(|error| error.to_string())
}
