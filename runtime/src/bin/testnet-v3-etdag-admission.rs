//! Offline Testnet-v3 ETDAG target-admission request/package utility.
//!
//! No mode decrypts or signs a validator key.  `prepare` derives the exact
//! H=3 request from applied Genesis; `verify` accepts detached custody votes
//! only after reconstructing and validating the runtime package.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use synergy_testnet::consensus::simplified_posy::write_simplified_ingress_kem_registry_artifact;
use synergy_testnet::synergy_types::Hash;
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
        "usage:\n  testnet-v3-etdag-admission --prepare --epoch-context-root HEX --durable-output PATH [--genesis PATH] [--ingress-records PATH] [--output PATH]\n  testnet-v3-etdag-admission --verify --votes PATH [--genesis PATH] [--ingress-records PATH] [--request PATH] [--output PATH]\n\nprepare writes both the runtime-derived H=3 ML-DSA-65 admission request and the exact canonical public ingress-registry artifact consumed by validators. durable-output must end in <epoch-context-root>/epoch-0-height-3-cluster-0.json. verify reconstructs that request from the applied Genesis, verifies exactly four detached votes using the runtime verifier, and writes a package only after success."
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
    let mut output = None;
    let mut epoch_context_root = None;
    let mut durable_output = None;
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
                output = Some(resolve(
                    &root,
                    args.get(index + 1).unwrap_or_else(|| usage()),
                ));
                index += 2;
            }
            "--epoch-context-root" => {
                epoch_context_root =
                    Some(args.get(index + 1).unwrap_or_else(|| usage()).to_string());
                index += 2;
            }
            "--durable-output" => {
                durable_output = Some(resolve(
                    &root,
                    args.get(index + 1).unwrap_or_else(|| usage()),
                ));
                index += 2;
            }
            _ => usage(),
        }
    }
    if prepare == verify {
        usage();
    }
    if verify && (epoch_context_root.is_some() || durable_output.is_some()) {
        usage();
    }
    if prepare {
        if votes.is_some() || epoch_context_root.is_none() || durable_output.is_none() {
            usage();
        }
        let output = output.unwrap_or_else(|| root.join(DEFAULT_REQUEST));
        let epoch_context_root_hex = epoch_context_root.unwrap();
        let epoch_context_root = Hash::from_hex(&epoch_context_root_hex)
            .unwrap_or_else(|error| fail(format!("invalid epoch context root: {error}")));
        if epoch_context_root.is_zero() || epoch_context_root_hex != epoch_context_root.to_hex() {
            fail("epoch context root must be exactly 64 lowercase hexadecimal characters");
        }
        let durable_output = durable_output.unwrap();
        let expected_filename = "epoch-0-height-3-cluster-0.json";
        let output_parent_name = durable_output
            .parent()
            .and_then(Path::file_name)
            .and_then(|value| value.to_str());
        if durable_output.file_name().and_then(|value| value.to_str()) != Some(expected_filename)
            || output_parent_name != Some(epoch_context_root_hex.as_str())
        {
            fail(format!(
                "durable output must end in {}/{}",
                epoch_context_root_hex, expected_filename
            ));
        }
        if output == durable_output {
            fail("request output and durable registry output must be different files");
        }
        if durable_output.exists() {
            fail(format!(
                "refusing to overwrite {}",
                durable_output.display()
            ));
        }
        if !durable_output
            .parent()
            .is_some_and(|parent| parent.is_dir())
        {
            fail(format!(
                "durable output directory does not exist: {}",
                durable_output.parent().map_or_else(
                    || durable_output.display().to_string(),
                    |path| path.display().to_string()
                )
            ));
        }
        let (request, request_sha256) =
            write_first_target_admission_request(&genesis, &ingress, &output)
                .unwrap_or_else(|error| fail(error));
        let durable_artifact = match write_simplified_ingress_kem_registry_artifact(
            &durable_output,
            epoch_context_root,
            &request.ingress_kem_registry,
        ) {
            Ok(artifact) => artifact,
            Err(error) => {
                let _ = std::fs::remove_file(&output);
                fail(error)
            }
        };
        let durable_sha256 = sha256_file(&durable_output).unwrap_or_else(|error| fail(error));
        println!(
            "{{\n  \"result\": \"TARGET_ADMISSION_REQUEST_AND_DURABLE_REGISTRY_WRITTEN\",\n  \"request_path\": \"{}\",\n  \"request_sha256\": \"{}\",\n  \"durable_registry_path\": \"{}\",\n  \"durable_registry_sha256\": \"{}\",\n  \"epoch_context_root\": \"{}\",\n  \"ingress_kem_registry_root\": \"{}\",\n  \"applied_genesis_hash\": \"{}\",\n  \"target_height\": {},\n  \"signature_algorithm\": \"{}\",\n  \"signature_domain\": \"{}\",\n  \"required_signers\": 4\n}}",
            output.display(),
            request_sha256,
            durable_output.display(),
            durable_sha256,
            epoch_context_root.to_hex(),
            durable_artifact.registry_root.to_hex(),
            request.applied_genesis_hash,
            request.target_height.0,
            request.signature_algorithm,
            request.signature_domain,
        );
        return;
    }
    let output = output.unwrap_or_else(|| root.join(DEFAULT_PACKAGE));
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
