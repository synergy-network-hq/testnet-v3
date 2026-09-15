mod build;
mod diff;
mod inspect;
mod sign;
mod verify;

use std::path::Path;

use build::{UnsignedManifest, MAX_KEY_BYTES, MAX_MANIFEST_BYTES};
use sign::SignedManifest;
use synergy_aegis::{AegisPolicy, KeyId, PqvmSigner, SignatureAlgorithm};

fn main() {
    if let Err(error) = run() {
        eprintln!("synergy-manifest: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    match arguments.as_slice() {
        [command, input, output] if command == "build" => {
            let manifest: UnsignedManifest = build::decode(Path::new(input), MAX_MANIFEST_BYTES)?;
            manifest.validate()?;
            build::write_new(Path::new(output), &manifest)?;
            println!("built manifest_hash={}", manifest.manifest_hash()?);
        }
        [command, input, key_id, secret_key, output] if command == "sign" => {
            build::ensure_private(Path::new(secret_key))?;
            let unsigned: UnsignedManifest = build::decode(Path::new(input), MAX_MANIFEST_BYTES)?;
            let signer_key_id = KeyId::new(key_id.clone()).map_err(|error| error.to_string())?;
            let signer = PqvmSigner::from_secret_key_bytes(
                AegisPolicy {
                    allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
                    maximum_message_bytes: MAX_MANIFEST_BYTES as usize,
                    maximum_signature_bytes: 64 * 1024,
                },
                signer_key_id.clone(),
                build::read_bounded(Path::new(secret_key), MAX_KEY_BYTES)?,
            )
            .map_err(|error| error.to_string())?;
            let signed = sign::sign(unsigned, &signer, signer_key_id)?;
            build::write_new(Path::new(output), &signed)?;
            println!("signed manifest_hash={}", signed.manifest_hash);
        }
        [command, input, public_key] if command == "verify" => {
            let signed: SignedManifest = build::decode(Path::new(input), MAX_MANIFEST_BYTES)?;
            verify::verify_signed_manifest(
                &signed,
                &build::read_bounded(Path::new(public_key), MAX_KEY_BYTES)?,
            )?;
            println!("verified manifest_hash={}", signed.manifest_hash);
        }
        [command, input] if command == "inspect" => {
            let signed: SignedManifest = build::decode(Path::new(input), MAX_MANIFEST_BYTES)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&inspect::inspect(&signed)?)
                    .map_err(|error| format!("encode inspection: {error}"))?
            );
        }
        [command, left, right] if command == "diff" => {
            let left: SignedManifest = build::decode(Path::new(left), MAX_MANIFEST_BYTES)?;
            let right: SignedManifest = build::decode(Path::new(right), MAX_MANIFEST_BYTES)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&diff::diff(&left, &right)?)
                    .map_err(|error| format!("encode manifest diff: {error}"))?
            );
        }
        _ => {
            return Err(
                "usage: synergy-manifest <build INPUT OUTPUT|sign UNSIGNED KEY_ID SECRET_KEY OUTPUT|verify SIGNED PUBLIC_KEY|inspect SIGNED|diff LEFT RIGHT>"
                    .into(),
            );
        }
    }
    Ok(())
}
