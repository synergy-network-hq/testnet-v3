//! Offline same-root registry continuation, authorized by the verified recovery
//! certificate. This never installs files or alters live authority/state.
use super::*;
use crate::services::apqe_transport::{
    self as transport, RegistryPayload, SignedRegistry, Snapshot, Stamp, REGISTRY_CONTEXT,
};
use std::io::{self, IsTerminal, Read, Write};
use synergy_address_engine::{
    apqe::{crypto_engine::CryptoEngine, provider::SignOptions, Primitives, SecretBytes},
    encrypt::{decrypt_with_passphrase, EncryptedEnvelope},
    types::Algorithm,
};

fn advance_payload(
    prior: &RegistryPayload,
    previous_epoch: u64,
    previous_digest: &str,
    next_epoch: u64,
    next_digest: &str,
    now: u64,
) -> Result<RegistryPayload, String> {
    // This helper cannot establish authority: the caller supplies these values
    // only after configured_certificate and Snapshot independently authenticate
    // the original authority, quorum successor and transport trust boundary.
    if prior.epoch != previous_epoch
        || prior.authority_binding_sha256 != previous_digest
        || previous_epoch.checked_add(1) != Some(next_epoch)
        || prior.valid_from_unix > now
        || prior.expires_at_unix <= now
        || prior.generation == 0
        || [previous_digest, next_digest].iter().any(|value| {
            value.len() != 64
                || !value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
    {
        return Err("registry does not continue the authenticated recovery predecessor".into());
    }
    let mut next = prior.clone();
    next.epoch = next_epoch;
    next.authority_binding_sha256 = next_digest.to_owned();
    next.generation = prior
        .generation
        .checked_add(1)
        .ok_or("registry generation overflow")?;
    // Keep the previously issued window. Epoch recovery is not a validity
    // extension, endpoint change, credential rotation or membership operation.
    Ok(next)
}

fn sign_registry(
    engine: &CryptoEngine,
    root: &[u8],
    envelope: &EncryptedEnvelope,
    passphrase: &str,
    payload: RegistryPayload,
) -> Result<SignedRegistry, String> {
    let signer = SecretBytes::from_bytes(decrypt_with_passphrase(
        engine,
        &Primitives,
        envelope,
        passphrase,
    )?);
    if root.len() != 2592
        || !engine
            .keypair_corresponds(Algorithm::MlDsa87, root, signer.as_bytes())
            .map_err(|e| e.to_string())?
    {
        return Err("registry custody does not match the existing pinned ML-DSA-87 root".into());
    }
    let signing = transport::signing_bytes(&payload)?;
    let signature = engine
        .sign(
            Algorithm::MlDsa87,
            signer.as_bytes(),
            &signing,
            SignOptions::Pure {
                context: REGISTRY_CONTEXT,
            },
        )
        .map_err(|e| e.to_string())?;
    if !engine
        .verify(
            Algorithm::MlDsa87,
            root,
            &signing,
            &signature,
            SignOptions::Pure {
                context: REGISTRY_CONTEXT,
            },
        )
        .map_err(|e| e.to_string())?
    {
        return Err("new registry failed native APQE signature verification".into());
    }
    Ok(SignedRegistry { payload, signature })
}

fn read_passphrase(mut reader: impl Read) -> Result<SecretBytes, String> {
    let mut bytes = Vec::with_capacity(66);
    reader
        .by_ref()
        .take(66)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read private registry unlock")?;
    let mut secret = SecretBytes::from_bytes(bytes);
    // Strip one newline without leaving an unowned passphrase allocation.
    if secret.as_bytes().last() == Some(&b'\n') {
        secret = SecretBytes::from_bytes(secret.as_bytes()[..secret.as_bytes().len() - 1].to_vec());
    }
    if secret.as_bytes().len() != 64
        || !secret
            .as_bytes()
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        return Err("registry unlock requires 64 lowercase hexadecimal characters".into());
    }
    Ok(secret)
}

fn write_public(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o644)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options.open(path).map_err(|e| e.to_string())?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| e.to_string())
}

pub(super) fn cli(config: &str, custody: &str, output: &str) -> Result<(), String> {
    issue(Path::new(config), custody, output, None)
}

pub(super) fn issue_successor(
    config: &Path,
    custody: &str,
    output: &str,
    proposal: &Path,
    previous: &VerifiedAuthority,
    next: &VerifiedAuthority,
) -> Result<(), String> {
    issue(config, custody, output, Some((Stamp::capture(proposal)?, previous, next)))
}

fn issue(
    config: &Path,
    custody: &str,
    output: &str,
    successor: Option<(Stamp, &VerifiedAuthority, &VerifiedAuthority)>,
) -> Result<(), String> {
    if io::stdin().is_terminal() {
        return Err("registry unlock must arrive through a private stdin pipe".into());
    }
    let [config_path, custody_path, output] = [config, Path::new(custody), Path::new(output)];
    if [config_path, custody_path, output].iter().any(|p| {
        !p.is_absolute()
            || p.components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
    }) {
        return Err("registry issuance requires absolute non-traversing paths".into());
    }
    if fs::symlink_metadata(output).is_ok() {
        return Err("registry public output already exists".into());
    }
    let configuration = synergy_config::load(config_path).map_err(|e| e.to_string())?;
    let selected = configuration
        .apqe_transport
        .as_ref()
        .ok_or("explicit APQE transport required")?;
    let certificate_path = configuration
        .consensus
        .authority_recovery_certificate_path
        .as_deref()
        .ok_or("explicit recovery certificate required")?;
    let certificate_stamp = Stamp::capture(certificate_path)?;
    let (_, recovery) = configured_certificate(&configuration)?;
    let base = Snapshot::load(
        &configuration,
        &[
            selected.registry_trust_key_sha256.clone(),
            selected.genesis_trust_key_sha256.clone(),
        ],
    )?;
    let (previous, next) = successor.as_ref()
        .map(|(_, previous, next)| (*previous, *next))
        .unwrap_or((&recovery.previous, &recovery.next));
    let payload = advance_payload(
        &base.payload,
        previous.epoch.epoch,
        &sha256(previous.binding_bytes()),
        next.epoch.epoch,
        &sha256(next.binding_bytes()),
        transport::clock()?,
    )?;
    let root = transport::read(&selected.registry_trust_key_path, 8192, false)?;
    if sha256(&root) != selected.registry_trust_key_sha256 {
        return Err("registry root changed during issuance".into());
    }
    let envelope: EncryptedEnvelope =
        serde_json::from_slice(&transport::read(custody_path, 256 * 1024, true)?)
            .map_err(|_| "invalid encrypted registry custody")?;
    let passphrase = read_passphrase(io::stdin().lock())?;
    let engine = crate::services::apqe_provider::load(&configuration)?;
    let engine = engine
        .try_lock()
        .map_err(|_| "registry APQE provider unavailable")?;
    let signed = sign_registry(
        &engine,
        &root,
        &envelope,
        std::str::from_utf8(passphrase.as_bytes()).map_err(|_| "invalid unlock encoding")?,
        payload,
    )?;
    let bytes = serde_json::to_vec(&signed).map_err(|e| e.to_string())?;
    if !certificate_stamp.unchanged()
        || !base.stamps.iter().all(Stamp::unchanged)
        || successor.as_ref().is_some_and(|(stamp, _, _)| !stamp.unchanged())
    {
        return Err("authenticated recovery or transport inputs changed during issuance".into());
    }
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(output).map_err(|e| e.to_string())?;
    let result = write_public(&output.join("transport-root.pub"), &root)
        .and_then(|_| write_public(&output.join("transport-registry.json"), &bytes))
        .and_then(|_| {
            fs::File::open(output)
                .and_then(|f| f.sync_all())
                .map_err(|e| e.to_string())
        })
        .and_then(|_| {
            fs::File::open(output.parent().ok_or("output parent required")?)
                .and_then(|f| f.sync_all())
                .map_err(|e| e.to_string())
        });
    if result.is_err() {
        let _ = fs::remove_file(output.join("transport-root.pub"));
        let _ = fs::remove_file(output.join("transport-registry.json"));
        let _ = fs::remove_dir(output);
    }
    result?;
    println!(
        "{}",
        serde_json::json!({"status":"registry-issued-offline", "epoch":signed.payload.epoch,
        "generation":signed.payload.generation, "registry_sha256":sha256(&bytes),
        "root_sha256":sha256(&root), "authority_binding_sha256":signed.payload.authority_binding_sha256,
        "expires_at_unix":signed.payload.expires_at_unix})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use synergy_address_engine::encrypt::encrypt_with_passphrase;

    fn prior() -> RegistryPayload {
        serde_json::from_value(serde_json::json!({"schema_version":1,"scope":"isolated-development-canary",
            "chain_id":99999,"network_id":"disposable-registry-recovery","protocol":"posy/3.0",
            "genesis_hash":"a".repeat(64),"genesis_artifact_sha256":"b".repeat(64),
            "authority_binding_sha256":"c".repeat(64),"epoch":1,"generation":7,
            "valid_from_unix":10,"expires_at_unix":100,
            "validators":[{"node_address":"fixture","dial_address":"127.0.0.1:9000",
                "transport_key_id":"transport-fixture","transport_key_version":3,
                "transport_public_key":[1,2,3],"enrollment_sha256":"e".repeat(64),"revoked":false}]})).unwrap()
    }
    #[test]
    fn registry_successor_preserves_every_field_except_epoch_authority_and_generation() {
        let prior = prior();
        let next = advance_payload(&prior, 1, &"c".repeat(64), 2, &"d".repeat(64), 20).unwrap();
        let mut restored = next.clone();
        restored.epoch = prior.epoch;
        restored.authority_binding_sha256 = prior.authority_binding_sha256.clone();
        restored.generation = prior.generation;
        assert_eq!(
            serde_json::to_vec(&restored).unwrap(),
            serde_json::to_vec(&prior).unwrap()
        );
        assert!(advance_payload(&prior, 1, &"0".repeat(64), 2, &"d".repeat(64), 20).is_err());
        assert!(advance_payload(&prior, 1, &"c".repeat(64), 3, &"d".repeat(64), 20).is_err());
        assert!(advance_payload(&prior, 1, &"c".repeat(64), 2, &"d".repeat(64), 100).is_err());
        assert!(advance_payload(&prior, 1, &"c".repeat(64), 2, &"d".repeat(64), 9).is_err());
        let mut overflow = prior;
        overflow.generation = u64::MAX;
        assert!(advance_payload(&overflow, 1, &"c".repeat(64), 2, &"d".repeat(64), 20).is_err());
        assert!(read_passphrase(&b"not-an-unlock"[..]).is_err());
        assert!(read_passphrase(&vec![b'a'; 65][..]).is_err());
    }

    #[test]
    #[ignore = "requires pinned native APQE"]
    fn native_registry_successor_signing_rejects_wrong_custody_and_tampering() {
        let (directory, configuration) =
            crate::services::socket_qualification::sync_poll_native_test_configuration();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(directory);
        let engine = crate::services::apqe_provider::load(&configuration).unwrap();
        let engine = engine.lock().unwrap();
        let pair = engine.generate_keypair(Algorithm::MlDsa87).unwrap();
        let other = engine.generate_keypair(Algorithm::MlDsa87).unwrap();
        let passphrase = "a".repeat(64);
        let envelope = encrypt_with_passphrase(
            &engine,
            &Primitives,
            pair.private_key.as_bytes(),
            &passphrase,
        )
        .unwrap();
        let payload =
            advance_payload(&prior(), 1, &"c".repeat(64), 2, &"d".repeat(64), 20).unwrap();
        assert!(sign_registry(
            &engine,
            &other.public_key,
            &envelope,
            &passphrase,
            payload.clone()
        )
        .is_err());
        assert!(sign_registry(
            &engine,
            &pair.public_key,
            &envelope,
            &"b".repeat(64),
            payload.clone()
        )
        .is_err());
        let signed =
            sign_registry(&engine, &pair.public_key, &envelope, &passphrase, payload).unwrap();
        let mut tampered = signed.payload.clone();
        tampered.epoch += 1;
        assert!(!engine
            .verify(
                Algorithm::MlDsa87,
                &pair.public_key,
                &transport::signing_bytes(&tampered).unwrap(),
                &signed.signature,
                SignOptions::Pure {
                    context: REGISTRY_CONTEXT
                }
            )
            .unwrap());
        assert!(!engine
            .verify(
                Algorithm::MlDsa87,
                &pair.public_key,
                &transport::signing_bytes(&signed.payload).unwrap(),
                &signed.signature,
                SignOptions::default()
            )
            .unwrap());
    }
}
