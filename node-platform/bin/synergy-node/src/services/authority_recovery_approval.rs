//! Recovery approvals use existing opaque APQE custody and a separate immutable
//! transcript reservation. They never consume or rewrite consensus signing slots.
use super::*;
use std::io::Write;
use synergy_aegis::{AegisPolicy, KeyId, SignatureAlgorithm, SigningContext};

fn reserve(path: &Path, transcript: &[u8]) -> Result<(), String> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    match options.open(path) {
        Ok(mut file) => {
            // A truncated reservation is deliberately fail-closed. Never delete
            // it automatically: a signature might already have escaped.
            file.write_all(transcript)
                .and_then(|_| file.sync_all())
                .map_err(|e| format!("persist recovery reservation: {e}"))?;
            fs::File::open(path.parent().ok_or("missing reservation parent")?)
                .and_then(|f| f.sync_all())
                .map_err(|e| e.to_string())?;
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            use std::io::Read;
            let mut options = fs::OpenOptions::new();
            options.read(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
            }
            let file = options.open(path).map_err(|e| e.to_string())?;
            let metadata = file.metadata().map_err(|e| e.to_string())?;
            if !metadata.is_file() || metadata.len() > 1024 * 1024 {
                return Err("invalid recovery reservation shape".into());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                if metadata.uid() != unsafe { libc::geteuid() }
                    || metadata.permissions().mode() & 0o777 != 0o600
                {
                    return Err("unsafe recovery reservation ownership or permissions".into());
                }
            }
            let mut prior = Vec::new();
            (&file)
                .take(1024 * 1024 + 1)
                .read_to_end(&mut prior)
                .map_err(|e| e.to_string())?;
            if prior != transcript {
                return Err("validator already reserved a different recovery transcript; refusing equivocation".into());
            }
            file.sync_all().map_err(|e| e.to_string())?;
            fs::File::open(path.parent().ok_or("missing reservation parent")?)
                .and_then(|f| f.sync_all())
                .map_err(|e| e.to_string())?;
            Ok(())
        }
        Err(e) => Err(format!("reserve recovery approval: {e}")),
    }
}

pub(super) fn approve(
    config: &str,
    witness: &str,
    candidate: &str,
    root: &str,
) -> Result<(), String> {
    let config_path = Path::new(config);
    let _exclusive = crate::services::checkpoint::lock_configuration(config_path)?;
    let configuration = synergy_config::load(config_path).map_err(|e| e.to_string())?;
    let previous_path = configuration
        .consensus
        .authority_binding
        .as_deref()
        .ok_or("missing existing signed authority")?;
    let verified = prepare_verified(
        &configuration,
        input(witness, MAX_CONSENSUS_MESSAGE_BYTES as u64)?,
        input(candidate, MAX_AUTHORITY_BYTES)?,
        input(root, MAX_TRUST_KEY_BYTES)?,
        input(
            previous_path.to_str().ok_or("non UTF8 authority path")?,
            MAX_AUTHORITY_BYTES,
        )?,
    )?;
    let inputs =
        crate::services::apqe_provider::custody_inputs(&configuration, &verified.previous)?;
    let validator_id = inputs.request.payload.identity.address.clone();
    drop(inputs);
    let (key_id, _) = verified.previous.consensus_binding(&validator_id)?;
    let signer = crate::services::apqe_provider::consensus_signer(
        &configuration,
        &verified.previous,
        &validator_id,
        AegisPolicy {
            allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
            maximum_message_bytes: MAX_CONSENSUS_MESSAGE_BYTES,
            maximum_signature_bytes: 16 * 1024,
        },
    )?;
    let layout = NodeStorageLayout::new(configuration.storage.data_directory.clone())
        .map_err(|e| e.to_string())?;
    let parent = layout.consensus();
    let metadata = fs::symlink_metadata(&parent).map_err(|e| e.to_string())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("existing consensus directory required for recovery reservation".into());
    }
    reserve(
        &parent.join(format!(
            "authority-recovery-epoch-{}.approval",
            verified.previous.epoch.epoch
        )),
        &verified.signing_bytes,
    )?;
    let signature = signer
        .sign(
            &KeyId::new(key_id.to_owned()).map_err(|e| e.to_string())?,
            &SigningContext {
                domain: DOMAIN.into(),
                chain_id: configuration.chain_id,
                epoch: Some(verified.previous.epoch.epoch),
                height: None,
            },
            &verified.signing_bytes,
        )
        .map_err(|e| e.to_string())?;
    let attestation = Attestation {
        validator_id,
        key_id: key_id.to_owned(),
        signature: signature.bytes,
    };
    let validator = verified
        .previous
        .registry
        .active_validator(&attestation.validator_id)
        .map_err(|e| e.to_string())?;
    verified
        .previous
        .verify_consensus_signature(
            DOMAIN,
            &verified.signing_bytes,
            validator,
            &attestation.key_id,
            verified.previous.epoch.epoch,
            &attestation.signature,
        )
        .map_err(|e| format!("verify locally generated approval: {e}"))?;
    println!(
        "{}",
        serde_json::to_string(&attestation).map_err(|e| e.to_string())?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reservation_rejects_conflicting_partial_and_symlinked_approvals() {
        let dir = std::env::temp_dir().join(format!(
            "synergy-recovery-reservation-{}",
            std::process::id()
        ));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("approval");
        reserve(&path, b"bound transcript").unwrap();
        reserve(&path, b"bound transcript").unwrap();
        assert!(reserve(&path, b"another root").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"bound transcript");
        fs::write(&path, b"bound").unwrap();
        assert!(reserve(&path, b"bound transcript").is_err());
        #[cfg(unix)]
        {
            let alias = dir.join("alias");
            std::os::unix::fs::symlink(&path, &alias).unwrap();
            assert!(reserve(&alias, b"bound").is_err());
        }
        fs::remove_dir_all(dir).unwrap();
    }
}
