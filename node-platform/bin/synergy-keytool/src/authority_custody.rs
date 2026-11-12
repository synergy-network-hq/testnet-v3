//! Encrypted, role-restricted authority custody. Does not grant runtime trust.
use crate::aegis_keys::{read_bounded, MAX_METADATA_BYTES};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    path::Path,
};
use synergy_address_engine::{
    apqe::{Primitives, SecretBytes},
    encrypt::{decrypt_with_passphrase, encrypt_with_passphrase, EncryptedEnvelope},
    types::Algorithm,
};
use synergy_aegis::{AegisPolicy, AegisSigner, KeyId, SignatureAlgorithm, SigningContext};
use synergy_genesis::authority::{
    AuthorityPayload, SignedAuthorityBinding, AUTHORITY_SIGNING_DOMAIN,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Custody {
    version: u32,
    role: String,
    key_id: String,
    chain_id: u64,
    network_id: String,
    genesis_artifact_sha256: String,
    public_key: Vec<u8>,
    envelope: EncryptedEnvelope,
}
fn passphrase() -> Result<SecretBytes, String> {
    let mut input = Vec::new();
    std::io::stdin()
        .lock()
        .take(130)
        .read_to_end(&mut input)
        .map_err(|_| "cannot read custody unlock input")?;
    let input = SecretBytes::from_bytes(input);
    if input.as_bytes().len() != 64
        || !input
            .as_bytes()
            .iter()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(
            "authority custody requires exactly 64 lowercase hex characters via stdin".into(),
        );
    }
    Ok(input)
}
fn private_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut f = options
        .open(path)
        .map_err(|_| "refusing unsafe or existing custody output")?;
    f.write_all(bytes)
        .and_then(|_| f.sync_all())
        .map_err(|_| "cannot persist authority custody".into())
}
fn policy() -> AegisPolicy {
    AegisPolicy {
        allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
        maximum_message_bytes: MAX_METADATA_BYTES as usize,
        maximum_signature_bytes: 16 * 1024,
    }
}
fn check(c: &Custody) -> Result<(), String> {
    KeyId::new(c.key_id.clone()).map_err(|e| e.to_string())?;
    if c.version != 1
        || c.role != "posy-authority-ml-dsa-65"
        || c.chain_id == 0
        || c.network_id.is_empty()
        || c.network_id.len() > 256
        || c.genesis_artifact_sha256.len() != 64
        || !c
            .genesis_artifact_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || c.public_key.len() != 1952
    {
        return Err("authority custody has an incompatible role or network binding".into());
    }
    Ok(())
}
pub fn generate(
    id: KeyId,
    chain: u64,
    network: &str,
    genesis_sha256: &str,
    directory: &Path,
    engine: crate::provider::Engine,
) -> Result<(), String> {
    if !directory.is_absolute() {
        return Err("absolute new authority custody directory required".into());
    }
    let password = passphrase()?;
    let password =
        std::str::from_utf8(password.as_bytes()).map_err(|_| "invalid custody unlock input")?;
    let engine_guard = engine.lock().map_err(|_| "APQE provider poisoned")?;
    let pair = engine_guard
        .generate_keypair(Algorithm::MlDsa65)
        .map_err(|e| e.to_string())?;
    let envelope = encrypt_with_passphrase(
        &engine_guard,
        &Primitives,
        pair.private_key.as_bytes(),
        password,
    )?;
    let recovered = SecretBytes::from_bytes(decrypt_with_passphrase(
        &engine_guard,
        &Primitives,
        &envelope,
        password,
    )?);
    if recovered.as_bytes() != pair.private_key.as_bytes() {
        return Err("authority custody roundtrip mismatch".into());
    }
    drop(engine_guard);
    let custody = Custody {
        version: 1,
        role: "posy-authority-ml-dsa-65".into(),
        key_id: id.as_str().into(),
        chain_id: chain,
        network_id: network.into(),
        genesis_artifact_sha256: genesis_sha256.into(),
        public_key: pair.public_key.clone(),
        envelope,
    };
    check(&custody)?;
    let signer = crate::provider::signer(
        policy(),
        id.clone(),
        &pair.public_key,
        recovered.as_bytes().to_vec(),
        Some(engine.clone()),
    )?;
    let challenge = format!(
        "SYNERGY-AUTHORITY-CUSTODY-POSSESSION-V1\0{chain}\0{network}\0{genesis_sha256}\0{}",
        id.as_str()
    );
    let context = SigningContext {
        domain: "SYNERGY-AUTHORITY-CUSTODY-POSSESSION-V1".into(),
        chain_id: chain,
        epoch: None,
        height: None,
    };
    let signature = signer
        .sign(&id, &context, challenge.as_bytes())
        .map_err(|e| e.to_string())?;
    use synergy_aegis::AegisVerifier;
    crate::provider::verifier(policy(), Some(engine))?
        .verify(&context, challenge.as_bytes(), &signature, &pair.public_key)
        .map_err(|e| e.to_string())?;
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(directory)
        .map_err(|_| "authority custody directory must be new under a trusted existing parent")?;
    // Never write a plaintext secret. Refuse overwrite and retain any partial
    // encrypted output for explicit recovery if public-output creation fails.
    private_write(
        &directory.join("authority.enc.json"),
        &serde_json::to_vec(&custody).map_err(|e| e.to_string())?,
    )?;
    private_write(&directory.join("authority-root.pub"), &pair.public_key)?;
    fs::File::open(directory)
        .and_then(|d| d.sync_all())
        .map_err(|_| "cannot sync authority custody directory")?;
    Ok(())
}
pub fn sign(
    input: &Path,
    custody_path: &Path,
    output: &Path,
    engine: crate::provider::Engine,
) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let m = fs::symlink_metadata(custody_path).map_err(|_| "missing authority custody")?;
        if m.permissions().mode() & 0o077 != 0 || m.uid() != unsafe { libc::geteuid() } {
            return Err("authority custody must be private and owned by the signer".into());
        }
    }
    let custody: Custody = serde_json::from_slice(&read_bounded(
        custody_path,
        128 * 1024,
        "authority custody",
    )?)
    .map_err(|_| "invalid encrypted authority custody")?;
    check(&custody)?;
    let payload: AuthorityPayload = serde_json::from_slice(&read_bounded(
        input,
        MAX_METADATA_BYTES,
        "unsigned authority",
    )?)
    .map_err(|_| "invalid authority payload")?;
    payload.validate()?;
    if payload.chain_id != custody.chain_id
        || payload.network_id != custody.network_id
        || payload.protected.is_none()
    {
        return Err("authority payload differs from custody network or protected profile".into());
    }
    let password = passphrase()?;
    let password = std::str::from_utf8(password.as_bytes()).map_err(|_| "invalid unlock input")?;
    let guard = engine.lock().map_err(|_| "APQE provider poisoned")?;
    let secret = SecretBytes::from_bytes(decrypt_with_passphrase(
        &guard,
        &Primitives,
        &custody.envelope,
        password,
    )?);
    drop(guard);
    let id = KeyId::new(custody.key_id.clone()).map_err(|e| e.to_string())?;
    let signer = crate::provider::signer(
        policy(),
        id.clone(),
        &custody.public_key,
        secret.as_bytes().to_vec(),
        Some(engine.clone()),
    )?;
    let context = SigningContext {
        domain: AUTHORITY_SIGNING_DOMAIN.into(),
        chain_id: payload.chain_id,
        epoch: Some(payload.epoch),
        height: None,
    };
    let signature = signer
        .sign(&id, &context, &payload.signing_bytes()?)
        .map_err(|e| e.to_string())?;
    use synergy_aegis::AegisVerifier;
    crate::provider::verifier(policy(), Some(engine))?
        .verify(
            &context,
            &payload.signing_bytes()?,
            &signature,
            &custody.public_key,
        )
        .map_err(|e| e.to_string())?;
    crate::aegis_keys::write_public_json(
        output,
        &SignedAuthorityBinding {
            payload,
            signer_key_id: id.as_str().into(),
            signature: signature.bytes,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires authenticated native APQE artifacts"]
    fn native_encrypted_authority_custody_roundtrip_and_role_binding() {
        let engine = crate::provider::native_test_engine();
        let guard = engine.lock().unwrap();
        let pair = guard.generate_keypair(Algorithm::MlDsa65).unwrap();
        let password = "0".repeat(64);
        let envelope =
            encrypt_with_passphrase(&guard, &Primitives, pair.private_key.as_bytes(), &password)
                .unwrap();
        let recovered = SecretBytes::from_bytes(
            decrypt_with_passphrase(&guard, &Primitives, &envelope, &password).unwrap(),
        );
        assert_eq!(recovered.as_bytes(), pair.private_key.as_bytes());
        assert!(decrypt_with_passphrase(&guard, &Primitives, &envelope, &"1".repeat(64)).is_err());
        let mut custody = Custody {
            version: 1,
            role: "posy-authority-ml-dsa-65".into(),
            key_id: "test-authority-custody".into(),
            chain_id: 99999,
            network_id: "disposable-canary".into(),
            genesis_artifact_sha256: "a".repeat(64),
            public_key: pair.public_key,
            envelope,
        };
        check(&custody).unwrap();
        custody.role = "transport".into();
        assert!(check(&custody).is_err());
        custody.role = "posy-authority-ml-dsa-65".into();
        custody.public_key.pop();
        assert!(check(&custody).is_err());
    }
}
