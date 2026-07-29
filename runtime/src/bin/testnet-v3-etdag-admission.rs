//! Offline Testnet-v3 ETDAG target-admission request/package utility.
//!
//! No mode decrypts or signs a validator key.  `prepare` derives the exact
//! H=3 request from applied Genesis; `verify` accepts detached custody votes
//! only after reconstructing and validating the runtime package.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use synergy_testnet::testnet_v3_etdag_admission::{
    verify_first_target_admission_votes, write_first_target_admission_request,
    write_verified_first_target_admission_package,
};

const DEFAULT_GENESIS: &str = "genesis.testnet-v3.identity-assigned.json";
const DEFAULT_INGRESS: &str = "launch/TESTNET_V3_ETDAG_INGRESS_KEY_RECORDS.json";
const DEFAULT_REQUEST: &str = "launch/TESTNET_V3_ETDAG_TARGET_ADMISSION_REQUEST.json";
const DEFAULT_PACKAGE: &str = "launch/TESTNET_V3_ETDAG_TARGET_ADMISSION_PACKAGE.json";

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn usage() -> ! {
    eprintln!(
        "usage:\n  testnet-v3-etdag-admission --prepare [--genesis PATH] [--ingress-records PATH] [--output PATH]\n  testnet-v3-etdag-admission --verify --votes PATH [--genesis PATH] [--ingress-records PATH] [--request PATH] [--output PATH]\n\nprepare writes the runtime-derived H=3 ML-DSA-65 admission request. verify reconstructs that request from the applied Genesis, verifies exactly five detached votes using the runtime verifier, and writes a package only after success."
    );
    std::process::exit(2);
}

fn fail(message: impl AsRef<str>) -> ! {
    eprintln!("testnet-v3-etdag-admission: {}", message.as_ref());
    std::process::exit(1);
}

fn resolve(root: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        root.join(path)
    }
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn main() {
    let root = repo();
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        usage();
    }
    let mut prepare = false;
    let mut verify = false;
    let mut genesis = root.join(DEFAULT_GENESIS);
    let mut ingress = root.join(DEFAULT_INGRESS);
    let mut request = root.join(DEFAULT_REQUEST);
    let mut votes = None;
    let mut output = root.join(DEFAULT_PACKAGE);
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--prepare" => {
                prepare = true;
                index += 1;
            }
            "--verify" => {
                verify = true;
                index += 1;
            }
            "--genesis" => {
                genesis = resolve(&root, args.get(index + 1).unwrap_or_else(|| usage()));
                index += 2;
            }
            "--ingress-records" => {
                ingress = resolve(&root, args.get(index + 1).unwrap_or_else(|| usage()));
                index += 2;
            }
            "--request" => {
                request = resolve(&root, args.get(index + 1).unwrap_or_else(|| usage()));
                index += 2;
            }
            "--votes" => {
                votes = Some(resolve(
                    &root,
                    args.get(index + 1).unwrap_or_else(|| usage()),
                ));
                index += 2;
            }
            "--output" => {
                output = resolve(&root, args.get(index + 1).unwrap_or_else(|| usage()));
                index += 2;
            }
            _ => usage(),
        }
    }
    if prepare == verify {
        usage();
    }
    if prepare {
        if votes.is_some() {
            usage();
        }
        let (request, request_sha256) =
            write_first_target_admission_request(&genesis, &ingress, &output)
                .unwrap_or_else(|error| fail(error));
        println!(
            "{{\n  \"result\": \"TARGET_ADMISSION_REQUEST_WRITTEN\",\n  \"request_path\": \"{}\",\n  \"request_sha256\": \"{}\",\n  \"applied_genesis_hash\": \"{}\",\n  \"target_height\": {},\n  \"signature_algorithm\": \"{}\",\n  \"signature_domain\": \"{}\",\n  \"required_signers\": 5\n}}",
            output.display(),
            request_sha256,
            request.applied_genesis_hash,
            request.target_height.0,
            request.signature_algorithm,
            request.signature_domain,
        );
        return;
    }
    let votes = votes.unwrap_or_else(|| usage());
    let (artifact, artifact_sha256) = write_verified_first_target_admission_package(
        &genesis, &ingress, &request, &votes, &output,
    )
    .unwrap_or_else(|error| fail(error));
    let request_sha256 = sha256_file(&request).unwrap_or_else(|error| fail(error));
    let package_sha256 = sha256_file(&output).unwrap_or_else(|error| fail(error));
    if artifact_sha256 != package_sha256 {
        fail("written package digest changed after publication");
    }
    // Call the public verifier once more after publication.  This keeps the
    // evidence path identical to the in-memory verification above and catches
    // a storage fault before reporting success.
    let (_, replay_request_sha256) =
        verify_first_target_admission_votes(&genesis, &ingress, &request, &votes)
            .unwrap_or_else(|error| fail(error));
    if replay_request_sha256 != request_sha256 || artifact.request_sha256 != request_sha256 {
        fail("target admission request binding changed during verification");
    }
    println!(
        "{{\n  \"result\": \"TARGET_ADMISSION_PACKAGE_VERIFIED\",\n  \"package_path\": \"{}\",\n  \"package_sha256\": \"{}\",\n  \"request_sha256\": \"{}\",\n  \"package_digest\": \"{}\",\n  \"target_height\": {},\n  \"verified_signers\": {}\n}}",
        output.display(),
        package_sha256,
        request_sha256,
        artifact.package_digest.0,
        artifact.package.context.target_height.0,
        artifact.package.certificate.signer_count,
    );
}
