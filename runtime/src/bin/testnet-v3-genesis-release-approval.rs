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
    build_local_r11_qualification_release_approval_request, build_release_approval_request,
    verify_local_r11_qualification_release_approval_file_public, verify_release_approval_file,
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
        "usage:\n  testnet-v3-genesis-release-approval --write-request --desired-state PATH (--authorities PATH | --legacy-authorities) [--candidate PATH] [--output PATH]\n  testnet-v3-genesis-release-approval --verify --approval PATH --desired-state PATH (--authorities PATH | --legacy-authorities) [--candidate PATH]\n\nLocal R11 mode additionally requires --local-r11-qualification --execution-snapshot PATH. PATH is the strict Genesis execution-bundle envelope whose exact bytes are approval-bound. New P3 work must pass the dated fresh V4 authority record explicitly. --legacy-authorities is only for reproducing the superseded launch ceremony. The request is the exact payload for ML-DSA-87 context signing. This tool never decrypts, signs, or loads private material. Signature context: {TESTNET_V3_GENESIS_RELEASE_APPROVAL_DOMAIN}"
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
    execution_bundle: Option<&Path>,
    output: &Path,
    local_qualification: bool,
) {
    let request = if local_qualification {
        build_local_r11_qualification_release_approval_request(
            root,
            candidate,
            authorities,
            desired_state,
            execution_bundle.unwrap_or_else(|| usage()),
        )
    } else {
        build_release_approval_request(root, candidate, authorities, desired_state)
    }
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
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "result": "UNSIGNED_CANONICAL_REQUEST_WRITTEN",
            "request_path": output.display().to_string(),
            "request_sha256": hex::encode(Sha256::digest(&canonical)),
            "candidate_sha256": request.candidate_sha256,
            "genesis_hash": request.genesis_hash,
            "execution_snapshot_sha256": request.execution_snapshot_sha256,
            "execution_state_canonical_sha256": request.execution_state_canonical_sha256,
            "execution_snapshot_schema_version": request.execution_snapshot_schema_version,
            "execution_snapshot_artifact_type": request.execution_snapshot_artifact_type,
            "signature_algorithm": request.signature_algorithm,
            "signature_domain": request.signature_domain,
        }))
        .unwrap_or_else(|error| fail(format!("encode result: {error}")))
    );
}

fn verify(
    root: &Path,
    candidate: &Path,
    authorities: &Path,
    desired_state: &Path,
    execution_bundle: Option<&Path>,
    approval: &Path,
    local_qualification: bool,
) {
    let request = if local_qualification {
        verify_local_r11_qualification_release_approval_file_public(
            root,
            candidate,
            authorities,
            desired_state,
            execution_bundle.unwrap_or_else(|| usage()),
            approval,
        )
    } else {
        verify_release_approval_file(root, candidate, authorities, desired_state, approval)
    }
    .unwrap_or_else(|error| fail(format!("release approval rejected: {error}")));
    let approval_sha256 =
        sha256_file(approval).unwrap_or_else(|error| fail(format!("hash approval: {error}")));
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "result": "RELEASE_APPROVAL_VERIFIED",
            "approval_path": approval.display().to_string(),
            "approval_sha256": approval_sha256,
            "candidate_sha256": request.candidate_sha256,
            "genesis_hash": request.genesis_hash,
            "execution_snapshot_sha256": request.execution_snapshot_sha256,
            "execution_state_canonical_sha256": request.execution_state_canonical_sha256,
            "execution_snapshot_schema_version": request.execution_snapshot_schema_version,
            "execution_snapshot_artifact_type": request.execution_snapshot_artifact_type,
            "governance_authority_role": request.governance_authority_role,
            "governance_standard_account_address": request.governance_standard_account_address,
        }))
        .unwrap_or_else(|error| fail(format!("encode result: {error}")))
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
    let mut local_qualification = false;
    let mut execution_bundle = None;
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
            "--local-r11-qualification" => {
                local_qualification = true;
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
            "--execution-snapshot" => {
                execution_bundle = Some(resolve(
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
    if local_qualification != execution_bundle.is_some() {
        usage();
    }
    if write {
        if approval.is_some() {
            usage();
        }
        write_request(
            &root,
            &candidate,
            &authorities,
            &desired_state,
            execution_bundle.as_deref(),
            &output,
            local_qualification,
        );
    } else {
        let approval = approval.unwrap_or_else(|| usage());
        verify(
            &root,
            &candidate,
            &authorities,
            &desired_state,
            execution_bundle.as_deref(),
            &approval,
            local_qualification,
        );
    }
}
