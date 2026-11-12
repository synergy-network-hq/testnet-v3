//! Bounded, read-only crypto interoperability inspection. This command produces
//! no reveal share, signature, plaintext or protocol authorization.
use serde::Deserialize;
use std::{io::Read, path::Path};
use synergy_etdag::{
    crypto::{
        decrypt_historical_share_capsule_diagnostic, decrypt_share_capsule_diagnostic,
        IngressKemKeyRecord, ML_KEM_1024_SECRET_KEY_BYTES,
    },
    ProcessingEnvelope,
};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    envelope: ProcessingEnvelope,
    record: IngressKemKeyRecord,
}
pub fn verify(secret_path: &Path, input: impl Read, historical: bool) -> Result<(), String> {
    let mut bytes = Vec::new();
    input
        .take(2 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "read capsule input")?;
    if bytes.len() > 2 * 1024 * 1024 {
        return Err("capsule input exceeds bound".into());
    }
    let input: Input =
        serde_json::from_slice(&bytes).map_err(|_| "invalid bounded capsule input")?;
    let metadata = std::fs::symlink_metadata(secret_path).map_err(|_| "inspect custody")?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() != ML_KEM_1024_SECRET_KEY_BYTES as u64
    {
        return Err("invalid custody shape".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("custody must be owner-only".into());
        }
    }
    let capsule = input
        .envelope
        .share_capsules
        .iter()
        .find(|c| {
            c.validator_id == input.record.validator_id
                && c.ingress_kem_key_id == input.record.key_id
        })
        .ok_or("selected capsule absent")?;
    let file = std::fs::File::open(secret_path).map_err(|_| "open custody")?;
    let opened = file.metadata().map_err(|_| "inspect opened custody")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
            return Err("custody changed while opening".into());
        }
    }
    if !opened.is_file() || opened.len() != metadata.len() {
        return Err("custody changed shape".into());
    }
    let mut secret = Vec::new();
    file.take(ML_KEM_1024_SECRET_KEY_BYTES as u64 + 1)
        .read_to_end(&mut secret)
        .map_err(|_| "read bounded custody")?;
    if secret.len() != ML_KEM_1024_SECRET_KEY_BYTES {
        secret.fill(0);
        return Err("custody changed length".into());
    }
    let result = if historical {
        decrypt_historical_share_capsule_diagnostic(
            &input.envelope,
            capsule,
            &input.record,
            &secret,
        )
    } else {
        decrypt_share_capsule_diagnostic(&input.envelope, capsule, &input.record, &secret)
    };
    secret.fill(0);
    match result {
        Ok(mut share) => {
            share.value.fill(0);
            println!("{{\"capsule_verified\":true}}");
        }
        Err(failure) => {
            let stage = failure.stage;
            println!("{{\"capsule_verified\":false,\"stage\":\"{stage:?}\"}}");
        }
    }
    Ok(())
}
