use synergy_genesis::{builder, signing};

use std::fs::{self, File};
use std::io::{Read, Take};
use std::path::Path;

use builder::UnsignedGenesis;
use signing::SignedGenesis;
use synergy_aegis::{AegisPolicy, KeyId, PqvmSigner, PqvmVerifier, SignatureAlgorithm};
use synergy_storage::{
    AtomicStore, GuardedTransactionBackend, RequiredRecord, StoragePrecondition, StorageWrite,
};

const MAX_GENESIS_BYTES: u64 = 16 * 1024 * 1024;
const MAX_KEY_BYTES: u64 = 8 * 1024;

fn main() {
    if let Err(error) = run() {
        eprintln!("synergy-genesis: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    run_arguments(&std::env::args().skip(1).collect::<Vec<_>>())
}

type ProviderArguments<'a> = (&'a [String], Option<(&'a str, &'a str)>);
fn provider_arguments(arguments: &[String]) -> Result<ProviderArguments<'_>, String> {
    if arguments.first().is_some_and(|s| s == "hash") {
        return Ok((arguments, None));
    }
    if arguments.len() < 4 {
        return Err("cryptographic commands require --apqe-report ABSOLUTE_PATH --apqe-report-sha256 AUTHENTICATED_LOWERHEX".into());
    }
    let split = arguments.len() - 4;
    match &arguments[split..] {
        [report_flag, report, digest_flag, digest] if report_flag == "--apqe-report" && digest_flag == "--apqe-report-sha256" => Ok((&arguments[..split], Some((report, digest)))),
        _ => Err("cryptographic commands require trailing --apqe-report ABSOLUTE_PATH --apqe-report-sha256 AUTHENTICATED_LOWERHEX".into()),
    }
}
fn policy() -> AegisPolicy {
    AegisPolicy {
        allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
        maximum_message_bytes: MAX_GENESIS_BYTES as usize,
        maximum_signature_bytes: 16 * 1024,
    }
}
fn run_arguments(arguments: &[String]) -> Result<(), String> {
    let (arguments, provider) = provider_arguments(arguments)?;
    // Validate the command shape before reading any provider or private material.
    let requires_provider = matches!(arguments, [c,_,_,_,_,_] if c == "sign")
        || matches!(arguments, [c,_,_] if c == "verify")
        || matches!(arguments, [c,_,_,_] if c == "verify-binding");
    if !requires_provider && !matches!(arguments, [c,_] if c == "hash") {
        return Err("usage: synergy-genesis <hash UNSIGNED|sign UNSIGNED KEY_ID SECRET_KEY TRUST_PUBLIC_KEY OUTPUT|verify SIGNED TRUST_PUBLIC_KEY|verify-binding SIGNED TRUST_PUBLIC_KEY AUTHORITY> [--apqe-report ABS --apqe-report-sha256 HEX]".into());
    }
    let engine = provider
        .map(|(report, digest)| {
            synergy_aegis::load_authenticated_native_engine(Path::new(report), digest)
        })
        .transpose()?;
    match arguments {
        [command, input] if command == "hash" => {
            let unsigned: UnsignedGenesis = decode(input, MAX_GENESIS_BYTES)?;
            println!("{}", unsigned.genesis_hash()?);
        }
        [command, input, key_id, secret_key, trust_key, output] if command == "sign" => {
            ensure_private(Path::new(secret_key))?;
            let unsigned: UnsignedGenesis = decode(input, MAX_GENESIS_BYTES)?;
            let public = read_bounded(trust_key, MAX_KEY_BYTES)?;
            let engine = engine.clone().ok_or("explicit APQE provider required")?;
            let signer = PqvmSigner::with_apqe(
                policy(),
                KeyId::new(key_id.clone()).map_err(|error| error.to_string())?,
                &public,
                read_bounded(secret_key, MAX_KEY_BYTES)?,
                engine,
            )
            .map_err(|error| error.to_string())?;
            let signed = signing::sign(
                unsigned,
                &signer,
                KeyId::new(key_id.clone()).map_err(|error| error.to_string())?,
            )?;
            write_new(
                output,
                &serde_json::to_vec_pretty(&signed).map_err(|error| error.to_string())?,
            )?;
        }
        [command, input, trust_key, authority_path] if command == "verify-binding" => {
            let signed: synergy_genesis::signing::SignedGenesis = decode(input, MAX_GENESIS_BYTES)?;
            let binding: synergy_genesis::authority::SignedAuthorityBinding =
                decode(authority_path, 1024 * 1024)?;
            let verifier = PqvmVerifier::with_apqe(
                policy(),
                engine.clone().ok_or("explicit APQE provider required")?,
            )
            .map_err(|error| error.to_string())?;
            synergy_genesis::verify_binding_with_verifier(
                &signed,
                &read_bounded(trust_key, MAX_KEY_BYTES)?,
                &binding,
                &verifier,
            )?;
            println!(
                "verified Genesis/authority binding genesis_hash={}",
                signed.genesis_hash
            );
        }
        [command, input, trust_key] if command == "verify" => {
            let signed: SignedGenesis = decode(input, MAX_GENESIS_BYTES)?;
            let verifier = PqvmVerifier::with_apqe(
                policy(),
                engine.clone().ok_or("explicit APQE provider required")?,
            )
            .map_err(|error| error.to_string())?;
            signing::verify(&signed, &verifier, &read_bounded(trust_key, MAX_KEY_BYTES)?)?;
            println!("verified genesis_hash={}", signed.genesis_hash);
        }
        _ => unreachable!("command shape checked before provider loading"),
    }
    Ok(())
}

fn decode<T: serde::de::DeserializeOwned>(path: &str, maximum: u64) -> Result<T, String> {
    serde_json::from_slice(&read_bounded(path, maximum)?)
        .map_err(|error| format!("decode {}: {error}", path))
}

fn read_bounded(path: &str, maximum: u64) -> Result<Vec<u8>, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("inspect {path}: {error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(format!("{path} must be a bounded regular non-symlink file"));
    }
    let file = File::open(path).map_err(|error| format!("open {path}: {error}"))?;
    let mut reader: Take<File> = file.take(maximum.saturating_add(1));
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    reader
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read {path}: {error}"))?;
    if bytes.is_empty() || bytes.len() as u64 > maximum {
        return Err(format!(
            "{path} changed outside its permitted size while reading"
        ));
    }
    Ok(bytes)
}

fn ensure_private(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata =
            fs::symlink_metadata(path).map_err(|error| format!("inspect private key: {error}"))?;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("private key is accessible to group or others".into());
        }
    }
    Ok(())
}

fn write_new(path: &str, bytes: &[u8]) -> Result<(), String> {
    if Path::new(path).exists() {
        return Err("output already exists".into());
    }
    let target = Path::new(path);
    let parent = target
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or("output must have an explicit parent directory")?;
    let file_name = target.file_name().ok_or("output has no file name")?;
    let mut store =
        AtomicStore::new(parent, MAX_GENESIS_BYTES as usize).map_err(|error| error.to_string())?;
    store
        .commit_atomic_if(
            &[StoragePrecondition {
                relative_path: file_name.into(),
                required: RequiredRecord::Missing,
            }],
            &[StorageWrite {
                relative_path: file_name.into(),
                bytes: bytes.to_vec(),
            }],
        )
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| s.to_string()).collect()
    }
    #[test]
    fn cryptographic_cli_requires_explicit_provider_and_hash_remains_offline() {
        for values in [
            vec!["sign", "u", "id", "s", "p", "o"],
            vec!["verify", "s", "p"],
            vec!["verify-binding", "s", "p", "a"],
        ] {
            assert!(provider_arguments(&args(&values)).is_err());
        }
        assert!(provider_arguments(&args(&["hash", "u"]))
            .unwrap()
            .1
            .is_none());
        assert!(run_arguments(&args(&[
            "verify",
            "s",
            "p",
            "--apqe-report",
            "relative",
            "--apqe-report-sha256",
            "bad"
        ]))
        .unwrap_err()
        .contains("digest"));
        assert!(run_arguments(&args(&[
            "verify",
            "s",
            "p",
            "--apqe-report-sha256",
            "bad",
            "--apqe-report",
            "relative"
        ]))
        .is_err());
    }

    #[test]
    #[ignore = "requires explicitly authenticated immutable APQE native artifacts"]
    fn native_cli_sign_verify_preserves_v1_v2_and_refuses_overwrite() {
        use synergy_address_engine::types::Algorithm;
        use synergy_genesis::{
            etdag::GenesisEtdag, network::GenesisNetwork, validator_set::GenesisValidator,
        };
        let report = std::env::var("APQE_TRUSTED_NATIVE_REPORT").unwrap();
        let digest = std::env::var("APQE_AUTHENTICATED_REPORT_SHA256").unwrap();
        let engine =
            synergy_aegis::load_authenticated_native_engine(Path::new(&report), &digest).unwrap();
        let pair = engine
            .lock()
            .unwrap()
            .generate_keypair(Algorithm::MlDsa65)
            .unwrap();
        let root = std::env::temp_dir().join(format!(
            "genesis-native-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(root.clone());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let public = root.join("trust.pub");
        let secret = root.join("secret.key");
        fs::write(&public, &pair.public_key).unwrap();
        fs::write(&secret, pair.private_key.as_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).unwrap();
        }
        for version in [1, 2] {
            let unsigned = UnsignedGenesis {
                format_version: version,
                network: GenesisNetwork {
                    chain_id: 1266,
                    network_id: "genesis-offline-test".into(),
                    protocol_version: "posy/3.0".into(),
                    activation_unix: 1,
                },
                validators: (0..synergy_posy::POSY_MIN_VALIDATOR_COUNT)
                    .map(|i| GenesisValidator {
                        record: synergy_posy::ValidatorRecord {
                            validator_id: format!("v{i}"),
                            consensus_key_id: format!("k{i}"),
                            frozen_voting_weight: 1,
                            status: synergy_posy::ValidatorStatus::Active,
                        },
                        algorithm: SignatureAlgorithm::MlDsa65,
                        public_key: pair.public_key.clone(),
                    })
                    .collect(),
                etdag: GenesisEtdag {
                    parameters: synergy_etdag::EtdagParameters::default(),
                    cryptographic_profile_root: "profile".into(),
                    ingress_kem_registry_root: synergy_etdag::EtdagDigest::from_domain_bytes(
                        "test",
                        b"registry",
                    ),
                },
                initial_state_root: "initial-state".into(),
                authority_trust_key_id: "test-authority".into(),
            };
            let input = root.join(format!("unsigned-{version}.json"));
            let output = root.join(format!("signed-{version}.json"));
            fs::write(&input, serde_json::to_vec(&unsigned).unwrap()).unwrap();
            let sign = vec![
                "sign".into(),
                input.to_str().unwrap().into(),
                "test-authority".into(),
                secret.to_str().unwrap().into(),
                public.to_str().unwrap().into(),
                output.to_str().unwrap().into(),
                "--apqe-report".into(),
                report.clone(),
                "--apqe-report-sha256".into(),
                digest.clone(),
            ];
            run_arguments(&sign).unwrap();
            let original = fs::read(&output).unwrap();
            let signed: SignedGenesis = serde_json::from_slice(&original).unwrap();
            assert_eq!(
                signed.unsigned.canonical_bytes().unwrap(),
                unsigned.canonical_bytes().unwrap()
            );
            assert!(
                synergy_genesis::verify::verify_signed_genesis(&signed, &pair.public_key).is_err(),
                "legacy constructor cannot bypass mandatory APQE"
            );
            let verify = vec![
                "verify".into(),
                output.to_str().unwrap().into(),
                public.to_str().unwrap().into(),
                "--apqe-report".into(),
                report.clone(),
                "--apqe-report-sha256".into(),
                digest.clone(),
            ];
            run_arguments(&verify).unwrap();
            assert!(run_arguments(&sign).unwrap_err().contains("exists"));
            assert_eq!(fs::read(&output).unwrap(), original);
            let mut altered = signed;
            altered.unsigned.network.network_id.push_str("-wrong");
            fs::write(&output, serde_json::to_vec(&altered).unwrap()).unwrap();
            assert!(run_arguments(&verify).is_err());
            let mut wrong_report = verify.clone();
            *wrong_report.last_mut().unwrap() = "0".repeat(64);
            assert!(run_arguments(&wrong_report).is_err());
        }
        // Possession fails before creating a new output.
        fs::write(&public, vec![0u8; pair.public_key.len()]).unwrap();
        let input = root.join("unsigned-2.json");
        let output = root.join("must-not-exist.json");
        let sign = vec![
            "sign".into(),
            input.to_str().unwrap().into(),
            "test-authority".into(),
            secret.to_str().unwrap().into(),
            public.to_str().unwrap().into(),
            output.to_str().unwrap().into(),
            "--apqe-report".into(),
            report,
            "--apqe-report-sha256".into(),
            digest,
        ];
        assert!(run_arguments(&sign).is_err());
        assert!(!output.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&secret, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(run_arguments(&sign).unwrap_err().contains("group"));
        }
    }
}
