mod builder;
mod etdag;
mod network;
mod signing;
mod validator_set;
mod verify;

use std::fs::{self, File};
use std::io::{Read, Take};
use std::path::Path;

use builder::UnsignedGenesis;
use signing::SignedGenesis;
use synergy_aegis::{AegisPolicy, KeyId, PqvmSigner, SignatureAlgorithm};
use synergy_storage::AtomicStore;

const MAX_GENESIS_BYTES: u64 = 16 * 1024 * 1024;
const MAX_KEY_BYTES: u64 = 8 * 1024;

fn main() {
    if let Err(error) = run() {
        eprintln!("synergy-genesis: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    match arguments.as_slice() {
        [command, input] if command == "hash" => {
            let unsigned: UnsignedGenesis = decode(input, MAX_GENESIS_BYTES)?;
            println!("{}", unsigned.genesis_hash()?);
        }
        [command, input, key_id, secret_key, output] if command == "sign" => {
            ensure_private(Path::new(secret_key))?;
            let unsigned: UnsignedGenesis = decode(input, MAX_GENESIS_BYTES)?;
            let signer = PqvmSigner::from_secret_key_bytes(
                AegisPolicy {
                    allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
                    maximum_message_bytes: MAX_GENESIS_BYTES as usize,
                    maximum_signature_bytes: 16 * 1024,
                },
                KeyId::new(key_id.clone()).map_err(|error| error.to_string())?,
                read_bounded(secret_key, MAX_KEY_BYTES)?,
            ).map_err(|error| error.to_string())?;
            let signed = signing::sign(
                unsigned,
                &signer,
                KeyId::new(key_id.clone()).map_err(|error| error.to_string())?,
            )?;
            write_new(output, &serde_json::to_vec_pretty(&signed).map_err(|error| error.to_string())?)?;
        }
        [command, input, trust_key] if command == "verify" => {
            let signed: SignedGenesis = decode(input, MAX_GENESIS_BYTES)?;
            verify::verify_signed_genesis(&signed, &read_bounded(trust_key, MAX_KEY_BYTES)?)?;
            println!("verified genesis_hash={}", signed.genesis_hash);
        }
        _ => return Err("usage: synergy-genesis <hash UNSIGNED|sign UNSIGNED KEY_ID SECRET_KEY OUTPUT|verify SIGNED TRUST_PUBLIC_KEY>".into()),
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
    let store =
        AtomicStore::new(parent, MAX_GENESIS_BYTES as usize).map_err(|error| error.to_string())?;
    store
        .write_atomic(file_name, bytes)
        .map_err(|error| error.to_string())
}
