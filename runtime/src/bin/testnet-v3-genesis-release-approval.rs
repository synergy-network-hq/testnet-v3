//! Generates and verifies offline Testnet-v3 Genesis release-approval evidence.
//!
//! This binary intentionally has no signing mode or custody dependency.  It
//! emits the canonical request that the frozen governance authority must sign
//! elsewhere, and verifies a supplied ML-DSA-87 detached signature before the
//! finalizer can apply the staged candidate.

use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use synergy_testnet::testnet_v3_release_approval::{
    build_release_approval_request, verify_release_approval_file,
    TESTNET_V3_GENESIS_RELEASE_APPROVAL_DOMAIN,
};

const DEFAULT_CANDIDATE: &str =
    "launch/production-genesis-ceremony/genesis.testnet-v3.final-candidate.json";
/// Retained solely for reproducible verification of the superseded launch
/// ceremony.  A caller must opt into it with `--legacy-authorities`; new P3
/// release work must name the dated, fresh authority record explicitly.
const LEGACY_AUTHORITIES: &str = "launch/TESTNET_V3_PRODUCTION_AUTHORITIES.json";
const DEFAULT_REQUEST: &str =
    "launch/production-genesis-ceremony/testnet-v3-genesis-release-approval-request.json";

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn usage() -> ! {
    eprintln!(
        "usage:\n  testnet-v3-genesis-release-approval --write-request --desired-state PATH (--authorities PATH | --legacy-authorities) [--candidate PATH] [--output PATH]\n  testnet-v3-genesis-release-approval --verify --approval PATH --desired-state PATH (--authorities PATH | --legacy-authorities) [--candidate PATH]\n\nNew P3 work must pass the dated fresh V4 authority record explicitly. --legacy-authorities is only for reproducing the superseded launch ceremony. The request is the exact payload for ML-DSA-87 context signing. This tool never decrypts, signs, or loads private material. Signature context: {TESTNET_V3_GENESIS_RELEASE_APPROVAL_DOMAIN}"
    );
    std::process::exit(2);
}

fn fail(message: impl AsRef<str>) -> ! {
    eprintln!("testnet-v3-genesis-release-approval: {}", message.as_ref());
    std::process::exit(1);
}

fn resolve(root: &Path, path: &str) -> PathBuf {
    let path = PathBuf::from(path);
    if path.is_absolute() {
        path
    } else {
        root.join(path)
    }
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn write_request(
    root: &Path,
    candidate: &Path,
    authorities: &Path,
    desired_state: &Path,
    output: &Path,
) {
    let request = build_release_approval_request(root, candidate, authorities, desired_state)
        .unwrap_or_else(|error| fail(format!("build canonical request: {error}")));
    let canonical = request
        .canonical_bytes()
        .unwrap_or_else(|error| fail(format!("canonicalize request: {error}")));
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .unwrap_or_else(|error| fail(format!("create {}: {error}", parent.display())));
    }
    let temporary = output.with_extension(format!("tmp-{}", std::process::id()));
    fs::write(&temporary, &canonical)
        .unwrap_or_else(|error| fail(format!("write {}: {error}", temporary.display())));
    fs::rename(&temporary, output)
        .unwrap_or_else(|error| fail(format!("publish {}: {error}", output.display())));
    println!(
        "{{\n  \"result\": \"UNSIGNED_CANONICAL_REQUEST_WRITTEN\",\n  \"request_path\": \"{}\",\n  \"request_sha256\": \"{}\",\n  \"candidate_sha256\": \"{}\",\n  \"genesis_hash\": \"{}\",\n  \"signature_algorithm\": \"{}\",\n  \"signature_domain\": \"{}\"\n}}",
        output.display(),
        hex::encode(Sha256::digest(&canonical)),
        request.candidate_sha256,
        request.genesis_hash,
        request.signature_algorithm,
        request.signature_domain,
    );
}

fn verify(
    root: &Path,
    candidate: &Path,
    authorities: &Path,
    desired_state: &Path,
    approval: &Path,
) {
    let request =
        verify_release_approval_file(root, candidate, authorities, desired_state, approval)
            .unwrap_or_else(|error| fail(format!("release approval rejected: {error}")));
    let approval_sha256 =
        sha256_file(approval).unwrap_or_else(|error| fail(format!("hash approval: {error}")));
    println!(
        "{{\n  \"result\": \"RELEASE_APPROVAL_VERIFIED\",\n  \"approval_path\": \"{}\",\n  \"approval_sha256\": \"{}\",\n  \"candidate_sha256\": \"{}\",\n  \"genesis_hash\": \"{}\",\n  \"governance_authority_role\": \"{}\",\n  \"governance_standard_account_address\": \"{}\"\n}}",
        approval.display(),
        approval_sha256,
        request.candidate_sha256,
        request.genesis_hash,
        request.governance_authority_role,
        request.governance_standard_account_address,
    );
}

fn main() {
    let root = repo();
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        usage();
    }
    let mut write = false;
    let mut verify_mode = false;
    let mut candidate = root.join(DEFAULT_CANDIDATE);
    let mut authorities = None;
    let mut legacy_authorities = false;
    let mut output = root.join(DEFAULT_REQUEST);
    let mut approval = None;
    let mut desired_state = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--write-request" => {
                write = true;
                index += 1;
            }
            "--verify" => {
                verify_mode = true;
                index += 1;
            }
            "--candidate" => {
                candidate = resolve(&root, args.get(index + 1).unwrap_or_else(|| usage()));
                index += 2;
            }
            "--authorities" => {
                if legacy_authorities || authorities.is_some() {
                    usage();
                }
                authorities = Some(resolve(
                    &root,
                    args.get(index + 1).unwrap_or_else(|| usage()),
                ));
                index += 2;
            }
            "--legacy-authorities" => {
                if legacy_authorities || authorities.is_some() {
                    usage();
                }
                legacy_authorities = true;
                index += 1;
            }
            "--output" => {
                output = resolve(&root, args.get(index + 1).unwrap_or_else(|| usage()));
                index += 2;
            }
            "--approval" => {
                approval = Some(resolve(
                    &root,
                    args.get(index + 1).unwrap_or_else(|| usage()),
                ));
                index += 2;
            }
            "--desired-state" => {
                desired_state = Some(resolve(
                    &root,
                    args.get(index + 1).unwrap_or_else(|| usage()),
                ));
                index += 2;
            }
            _ => usage(),
        }
    }
    if write == verify_mode {
        usage();
    }
    let authorities = if legacy_authorities {
        root.join(LEGACY_AUTHORITIES)
    } else {
        authorities.unwrap_or_else(|| usage())
    };
    let desired_state = desired_state.unwrap_or_else(|| usage());
    if write {
        if approval.is_some() {
            usage();
        }
        write_request(&root, &candidate, &authorities, &desired_state, &output);
    } else {
        let approval = approval.unwrap_or_else(|| usage());
        verify(&root, &candidate, &authorities, &desired_state, &approval);
    }
}
