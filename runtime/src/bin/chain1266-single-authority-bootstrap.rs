//! Chain 1266 incarnation-5 single-authority bootstrap authorization.
//!
//! `DesiredStateV2` is the authoritative consensus/start parameter document for
//! this temporary incarnation. This tool does not touch the legacy PoSy
//! `ConsensusParameterManifest`, the historic Governance Authority, or the
//! Genesis contract-deployment ceremony.
//!
//! Subcommands:
//!   generate-bootstrap-identity  create the local ML-DSA-87 bootstrap key
//!   build                        emit the canonical unsigned DesiredStateV2
//!   sign                         sign it under SYNERGY_CHAIN1266_START_CONSENSUS_V2
//!   verify                       re-verify a signed activation end to end
//!
//! The bootstrap private key never leaves the local custody directory. It is
//! never printed, never copied to the authority host, and never staged into a
//! release archive.

use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use synergy_testnet::crypto::pqc::{PQCAlgorithm, PQCManager, PQCPrivateKey, PQCPublicKey};
use synergy_testnet::desired_state_v2::{
    canonical_signing_payload, sha256_hex, ConsensusBindingV2, DesiredStateV2,
    SignedDesiredStateV2, CHAIN1266_START_SIGNATURE_DOMAIN_V2,
    DESIRED_STATE_SCHEMA_VERSION_V2, MLDSA87_PUBLIC_KEY_LEN, START_AUTHORIZATION_ALGORITHM,
};
use synergy_testnet::desired_state_v2_canonical::{canonical_bytes, parse_strict_canonical};

const ROLE_ID: &str = "SNRG-TESTNET-V3-SINGLE-AUTHORITY-BOOTSTRAP";
const CHAIN_ID: u64 = 1266;
const CHAIN_INCARNATION: u64 = 5;
const NETWORK_ID: &str = "synergy-testnet-v3";
const AUTHORITY_ID: &str = "authority-node-01";
const TARGET_BLOCK_TIME_MS: u64 = 1_000;

fn fail(message: impl AsRef<str>) -> ! {
    eprintln!("chain1266-single-authority-bootstrap: {}", message.as_ref());
    std::process::exit(1);
}

/// Public, exportable description of the bootstrap authorization identity.
/// Deliberately carries no private material.
#[derive(Debug, Serialize, Deserialize)]
struct BootstrapPublicIdentity {
    role_id: String,
    algorithm: String,
    key_id: String,
    public_key_base64: String,
    public_key_fingerprint: String,
    public_key_length: usize,
    chain_id: u64,
    chain_incarnation: u64,
    network_id: String,
    purpose: String,
    authorizes_only: Vec<String>,
    prohibited_roles: Vec<String>,
    created_at_unix: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct BootstrapPrivateKeyFile {
    role_id: String,
    algorithm: String,
    key_id: String,
    public_key_fingerprint: String,
    private_key: PQCPrivateKey,
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

fn fingerprint(public_key_bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(public_key_bytes))
}

#[cfg(unix)]
fn harden(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let permissions = fs::Permissions::from_mode(mode);
    fs::set_permissions(path, permissions)
        .map_err(|error| format!("set mode {mode:o} on {}: {error}", path.display()))
}

#[cfg(not(unix))]
fn harden(_path: &Path, _mode: u32) -> Result<(), String> {
    Err("this custody workflow requires a Unix host".to_string())
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    fs::write(path, bytes).map_err(|error| format!("write {}: {error}", path.display()))?;
    harden(path, 0o600)
}

fn write_public(path: &Path, bytes: &[u8]) -> Result<(), String> {
    fs::write(path, bytes).map_err(|error| format!("write {}: {error}", path.display()))?;
    harden(path, 0o644)
}

fn generate_bootstrap_identity(custody_dir: &Path) {
    if custody_dir.join("bootstrap.key.json").exists() {
        fail(format!(
            "{} already holds a bootstrap identity; refusing to overwrite custody material",
            custody_dir.display()
        ));
    }
    fs::create_dir_all(custody_dir)
        .unwrap_or_else(|error| fail(format!("create custody directory: {error}")));
    harden(custody_dir, 0o700).unwrap_or_else(|error| fail(error));

    let mut manager = PQCManager::new();
    let (public, private) = manager
        .generate_keypair(PQCAlgorithm::MLDSA87)
        .unwrap_or_else(|error| fail(format!("generate ML-DSA-87 bootstrap key: {error}")));
    if public.key_data.len() != MLDSA87_PUBLIC_KEY_LEN {
        fail(format!(
            "generated bootstrap public key is {} bytes, expected {MLDSA87_PUBLIC_KEY_LEN}",
            public.key_data.len()
        ));
    }
    let public_key_fingerprint = fingerprint(&public.key_data);

    // Prove the freshly generated pair actually signs and verifies before it is
    // ever recorded as an authorization identity.
    let probe = b"chain1266-incarnation5-bootstrap-selftest";
    let signature = manager
        .sign(&private, probe)
        .unwrap_or_else(|error| fail(format!("bootstrap key self-test signing failed: {error}")));
    let verified = manager
        .verify(&public, &signature, probe)
        .unwrap_or_else(|error| fail(format!("bootstrap key self-test verify failed: {error}")));
    if !verified {
        fail("bootstrap key self-test signature did not verify");
    }

    let identity = BootstrapPublicIdentity {
        role_id: ROLE_ID.to_string(),
        algorithm: START_AUTHORIZATION_ALGORITHM.to_string(),
        key_id: public.key_id.clone(),
        public_key_base64: general_purpose::STANDARD.encode(&public.key_data),
        public_key_fingerprint: public_key_fingerprint.clone(),
        public_key_length: public.key_data.len(),
        chain_id: CHAIN_ID,
        chain_incarnation: CHAIN_INCARNATION,
        network_id: NETWORK_ID.to_string(),
        purpose:
            "authorize only the initial start of Chain 1266 incarnation 5 under single_authority_v1"
                .to_string(),
        authorizes_only: vec![
            format!("chain:{CHAIN_ID}"),
            format!("incarnation:{CHAIN_INCARNATION}"),
            "protocol:single_authority_v1".to_string(),
            "the exact signed Genesis hash".to_string(),
            "the exact initial release id".to_string(),
        ],
        prohibited_roles: vec![
            "validator-block-signing".to_string(),
            "governance-authority".to_string(),
            "mainnet-governance".to_string(),
            "token-account".to_string(),
            "posy-validator".to_string(),
            "consensus-transition-authorization".to_string(),
            "balance-or-supply-modification".to_string(),
            "validator-membership".to_string(),
        ],
        created_at_unix: now_unix(),
    };

    let private_file = BootstrapPrivateKeyFile {
        role_id: ROLE_ID.to_string(),
        algorithm: START_AUTHORIZATION_ALGORITHM.to_string(),
        key_id: public.key_id.clone(),
        public_key_fingerprint: public_key_fingerprint.clone(),
        private_key: private,
    };

    let public_path = custody_dir.join("bootstrap.pub.json");
    let private_path = custody_dir.join("bootstrap.key.json");
    let mut public_bytes = serde_json::to_vec_pretty(&identity)
        .unwrap_or_else(|error| fail(format!("encode public identity: {error}")));
    public_bytes.push(b'\n');
    write_public(&public_path, &public_bytes).unwrap_or_else(|error| fail(error));
    let private_bytes = serde_json::to_vec(&private_file)
        .unwrap_or_else(|error| fail(format!("encode private custody file: {error}")));
    write_private(&private_path, &private_bytes).unwrap_or_else(|error| fail(error));

    // Only public material is reported.
    println!("role_id                  : {ROLE_ID}");
    println!("algorithm                : {START_AUTHORIZATION_ALGORITHM}");
    println!("key_id                   : {}", identity.key_id);
    println!("public_key_fingerprint   : {public_key_fingerprint}");
    println!("public_key_length        : {}", identity.public_key_length);
    println!("public_key_base64_sha256 : {}", sha256_hex(identity.public_key_base64.as_bytes()));
    println!("custody_dir              : {}", custody_dir.display());
    println!("public_identity          : {}", public_path.display());
    println!("self_test                : ML-DSA-87 sign/verify OK");
}

fn load_bootstrap_public(custody_dir: &Path) -> BootstrapPublicIdentity {
    let path = custody_dir.join("bootstrap.pub.json");
    let bytes = fs::read(&path)
        .unwrap_or_else(|error| fail(format!("read {}: {error}", path.display())));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| fail(format!("parse {}: {error}", path.display())))
}

fn build_desired_state(
    genesis_hash: &str,
    release_id: &str,
    authority_fingerprint: &str,
    execution_fingerprint: &str,
) -> DesiredStateV2 {
    DesiredStateV2 {
        schema_version: DESIRED_STATE_SCHEMA_VERSION_V2,
        chain_id: CHAIN_ID,
        chain_incarnation: CHAIN_INCARNATION,
        network_id: NETWORK_ID.to_string(),
        directory_namespace: format!("chain-{CHAIN_ID}/incarnation-{CHAIN_INCARNATION}"),
        release_id: release_id.to_string(),
        genesis_hash: genesis_hash.to_string(),
        consensus_binding: ConsensusBindingV2::SingleAuthority {
            authority_id: AUTHORITY_ID.to_string(),
            authority_public_key_fingerprint: authority_fingerprint.to_string(),
            target_block_time_ms: TARGET_BLOCK_TIME_MS,
            authority_start_height: 1,
            authority_end_height: None,
            pending_consensus_transition: None,
        },
        authority_public_key_fingerprint: authority_fingerprint.to_string(),
        execution_configuration_fingerprint: execution_fingerprint.to_string(),
    }
}

fn emit_unsigned(
    output: &Path,
    genesis_hash: &str,
    release_id: &str,
    authority_fingerprint: &str,
    execution_fingerprint: &str,
) {
    let state = build_desired_state(
        genesis_hash,
        release_id,
        authority_fingerprint,
        execution_fingerprint,
    );
    state
        .validate()
        .unwrap_or_else(|error| fail(format!("desired state is invalid: {error}")));
    let bytes = canonical_bytes(&state)
        .unwrap_or_else(|error| fail(format!("canonicalize desired state: {error}")));
    // Round-trip through the strict parser so what is written is exactly what a
    // verifier will accept.
    parse_strict_canonical(&bytes)
        .unwrap_or_else(|error| fail(format!("strict canonical round-trip failed: {error}")));
    write_public(output, &bytes).unwrap_or_else(|error| fail(error));

    let payload = canonical_signing_payload(&state)
        .unwrap_or_else(|error| fail(format!("canonical signing payload: {error}")));
    println!("desired_state_path       : {}", output.display());
    println!("desired_state_sha256     : {}", sha256_hex(&bytes));
    println!("canonical_bytes          : {}", bytes.len());
    println!("signing_domain           : {CHAIN1266_START_SIGNATURE_DOMAIN_V2}");
    println!("signing_payload_sha256   : {}", sha256_hex(&payload));
    println!("genesis_hash             : {genesis_hash}");
    println!("release_id               : {release_id}");
    println!("authority_fingerprint    : {authority_fingerprint}");
    println!("chain_incarnation        : {CHAIN_INCARNATION}");
    println!("pending_transition       : null");
}

fn sign(custody_dir: &Path, desired_state_path: &Path, output: &Path) {
    let identity = load_bootstrap_public(custody_dir);
    let private_path = custody_dir.join("bootstrap.key.json");
    let private_file: BootstrapPrivateKeyFile = serde_json::from_slice(
        &fs::read(&private_path)
            .unwrap_or_else(|error| fail(format!("read custody key: {error}"))),
    )
    .unwrap_or_else(|error| fail(format!("parse custody key: {error}")));
    if private_file.public_key_fingerprint != identity.public_key_fingerprint {
        fail("custody private key does not correspond to the recorded public identity");
    }

    let supplied = fs::read(desired_state_path)
        .unwrap_or_else(|error| fail(format!("read desired state: {error}")));
    let state = parse_strict_canonical(&supplied)
        .unwrap_or_else(|error| fail(format!("desired state is not canonical: {error}")));
    let payload = canonical_signing_payload(&state)
        .unwrap_or_else(|error| fail(format!("canonical signing payload: {error}")));

    let public_key_bytes = general_purpose::STANDARD
        .decode(&identity.public_key_base64)
        .unwrap_or_else(|error| fail(format!("decode bootstrap public key: {error}")));
    let public = PQCPublicKey {
        algorithm: PQCAlgorithm::MLDSA87,
        key_data: public_key_bytes,
        key_id: identity.key_id.clone(),
        created_at: identity.created_at_unix,
    };

    let mut manager = PQCManager::new();
    let signature = manager
        .sign(&private_file.private_key, &payload)
        .unwrap_or_else(|error| fail(format!("ML-DSA-87 signing failed: {error}")));

    let signed = SignedDesiredStateV2 {
        desired_state: state.clone(),
        signature_algorithm: START_AUTHORIZATION_ALGORITHM.to_string(),
        signature_domain: CHAIN1266_START_SIGNATURE_DOMAIN_V2.to_string(),
        start_authority_public_key_base64: identity.public_key_base64.clone(),
        start_authority_fingerprint: identity.public_key_fingerprint.clone(),
        signature_base64: general_purpose::STANDARD.encode(&signature.signature_data),
    };
    let mut bytes = serde_json::to_vec_pretty(&signed)
        .unwrap_or_else(|error| fail(format!("encode signed activation: {error}")));
    bytes.push(b'\n');
    write_public(output, &bytes).unwrap_or_else(|error| fail(error));

    // Immediate positive verification, then the required negative checks.
    let negative = negative_checks(&manager, &public, &signature.signature_data, &state);
    let positive = manager
        .verify(&public, &signature, &payload)
        .unwrap_or_else(|error| fail(format!("verify generated signature: {error}")));
    if !positive {
        fail("generated ML-DSA-87 signature did not verify against its own payload");
    }

    println!("signed_activation_path   : {}", output.display());
    println!("signing_domain           : {CHAIN1266_START_SIGNATURE_DOMAIN_V2}");
    println!("bootstrap_fingerprint    : {}", identity.public_key_fingerprint);
    println!("desired_state_sha256     : {}", sha256_hex(&supplied));
    println!("signature_sha256         : {}", sha256_hex(&signature.signature_data));
    println!("signature_verification   : OK");
    for (label, rejected) in negative {
        println!("negative_check           : {label} => {}", if rejected { "REJECTED (correct)" } else { "ACCEPTED (FAULT)" });
        if !rejected {
            fail(format!("negative check {label} did not reject; refusing to publish"));
        }
    }
}

/// Each mutation must fail verification against the original signature.
fn negative_checks(
    manager: &PQCManager,
    public: &PQCPublicKey,
    signature_bytes: &[u8],
    state: &DesiredStateV2,
) -> Vec<(&'static str, bool)> {
    let signature = synergy_testnet::crypto::pqc::PQCSignature {
        algorithm: PQCAlgorithm::MLDSA87,
        signature_data: signature_bytes.to_vec(),
        message_hash: Vec::new(),
        public_key_id: public.key_id.clone(),
        created_at: 0,
    };
    let rejects = |payload: &[u8]| -> bool {
        !manager.verify(public, &signature, payload).unwrap_or(false)
    };

    let mut results = Vec::new();

    // V1 domain: the V1 payload has no V2 domain prefix.
    let v1_payload = serde_json::to_vec(state).unwrap_or_default();
    results.push(("v1_domain_payload", rejects(&v1_payload)));

    // Modified canonical bytes.
    let mut mutated = canonical_signing_payload(state).unwrap_or_default();
    if let Some(last) = mutated.last_mut() {
        *last ^= 0x01;
    }
    results.push(("modified_canonical_bytes", rejects(&mutated)));

    let mut other = state.clone();
    other.genesis_hash = "00".repeat(32);
    results.push((
        "another_genesis_hash",
        rejects(&canonical_signing_payload(&other).unwrap_or_default()),
    ));

    let mut other = state.clone();
    other.release_id = format!("{}-tampered", state.release_id);
    results.push((
        "another_release_id",
        rejects(&canonical_signing_payload(&other).unwrap_or_default()),
    ));

    let mut other = state.clone();
    other.chain_incarnation = state.chain_incarnation.saturating_add(1);
    other.directory_namespace = format!("chain-{CHAIN_ID}/incarnation-{}", other.chain_incarnation);
    results.push((
        "another_incarnation",
        rejects(&canonical_signing_payload(&other).unwrap_or_default()),
    ));

    results
}

fn verify(signed_path: &Path, desired_state_path: &Path) {
    let signed: SignedDesiredStateV2 = serde_json::from_slice(
        &fs::read(signed_path)
            .unwrap_or_else(|error| fail(format!("read signed activation: {error}"))),
    )
    .unwrap_or_else(|error| fail(format!("parse signed activation: {error}")));
    let supplied = fs::read(desired_state_path)
        .unwrap_or_else(|error| fail(format!("read desired state: {error}")));

    let public_key_bytes = general_purpose::STANDARD
        .decode(&signed.start_authority_public_key_base64)
        .unwrap_or_else(|error| fail(format!("decode authorization public key: {error}")));
    if public_key_bytes.len() != MLDSA87_PUBLIC_KEY_LEN {
        fail("authorization public key is not ML-DSA-87 sized");
    }
    if fingerprint(&public_key_bytes) != signed.start_authority_fingerprint {
        fail("authorization fingerprint does not match its public key");
    }
    let signature_bytes = general_purpose::STANDARD
        .decode(&signed.signature_base64)
        .unwrap_or_else(|error| fail(format!("decode signature: {error}")));

    let public = PQCPublicKey {
        algorithm: PQCAlgorithm::MLDSA87,
        key_data: public_key_bytes,
        key_id: signed.start_authority_fingerprint.clone(),
        created_at: 0,
    };
    let manager = PQCManager::new();

    let state = synergy_testnet::desired_state_v2_canonical::verify_canonical_and_signature(
        &supplied,
        &signed,
        |payload, sig| {
            let signature = synergy_testnet::crypto::pqc::PQCSignature {
                algorithm: PQCAlgorithm::MLDSA87,
                signature_data: sig.to_vec(),
                message_hash: Vec::new(),
                public_key_id: public.key_id.clone(),
                created_at: 0,
            };
            manager
                .verify(&public, &signature, payload)
                .map_err(|error| format!("{error}"))
        },
        &signature_bytes,
    )
    .unwrap_or_else(|error| fail(format!("activation verification failed: {error}")));

    println!("signed_activation        : {}", signed_path.display());
    println!("bootstrap_fingerprint    : {}", signed.start_authority_fingerprint);
    println!("signing_domain           : {}", signed.signature_domain);
    println!("desired_state_sha256     : {}", sha256_hex(&supplied));
    println!("chain_id                 : {}", state.chain_id);
    println!("chain_incarnation        : {}", state.chain_incarnation);
    println!("directory_namespace      : {}", state.directory_namespace);
    println!("protocol                 : {}", state.consensus_binding.protocol());
    println!("release_id               : {}", state.release_id);
    println!("genesis_hash             : {}", state.genesis_hash);
    println!("authority_fingerprint    : {}", state.authority_public_key_fingerprint);
    println!("signature_verification   : OK");
}

fn arg(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|value| value == flag)
        .and_then(|index| args.get(index + 1))
        .cloned()
}

fn required(args: &[String], flag: &str) -> String {
    arg(args, flag).unwrap_or_else(|| fail(format!("{flag} is required")))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("generate-bootstrap-identity") => {
            generate_bootstrap_identity(&PathBuf::from(required(&args, "--custody-dir")));
        }
        Some("build") => emit_unsigned(
            &PathBuf::from(required(&args, "--output")),
            &required(&args, "--genesis-hash"),
            &required(&args, "--release-id"),
            &required(&args, "--authority-fingerprint"),
            &required(&args, "--execution-fingerprint"),
        ),
        Some("sign") => sign(
            &PathBuf::from(required(&args, "--custody-dir")),
            &PathBuf::from(required(&args, "--desired-state")),
            &PathBuf::from(required(&args, "--output")),
        ),
        Some("verify") => verify(
            &PathBuf::from(required(&args, "--signed")),
            &PathBuf::from(required(&args, "--desired-state")),
        ),
        _ => fail(
            "usage: chain1266-single-authority-bootstrap \
             <generate-bootstrap-identity|build|sign|verify> [flags]",
        ),
    }
}
