//! Canonical signed release metadata, verified against explicit pinned trust.
use std::fs;
use std::path::Path;

use synergy_aegis::{AegisPolicy, AegisSigner, KeyId, SignatureAlgorithm, SigningContext};
use synergy_updater::{verify_release, ReleaseMetadata, SignedReleaseMetadata};

use crate::aegis_keys::{read_bounded, write_public_json, MAX_KEY_BYTES, MAX_METADATA_BYTES};

const MAX_BINARY_BYTES: u64 = 256 * 1024 * 1024;
const PLATFORM: &str = "x86_64-unknown-linux-gnu";

fn policy() -> AegisPolicy {
    AegisPolicy {
        allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
        maximum_message_bytes: MAX_METADATA_BYTES as usize,
        maximum_signature_bytes: 16 * 1024,
    }
}

fn artifact(path: &Path, release: &ReleaseMetadata) -> Result<Vec<u8>, String> {
    let bytes = read_bounded(path, MAX_BINARY_BYTES, "release binary")?;
    if release.artifact.platform != PLATFORM
        || bytes.len() < 64
        || &bytes[..7] != b"\x7fELF\x02\x01\x01"
        || bytes[18..20] != [0x3e, 0]
        || !matches!(u16::from_le_bytes([bytes[16], bytes[17]]), 2 | 3)
        || bytes[20..24] != [1, 0, 0, 0]
    {
        return Err("release requires signed Linux x86-64 platform and matching ELF binary".into());
    }
    Ok(bytes)
}

#[cfg(test)]
fn check(
    chain_id: u64,
    key_id: &KeyId,
    trust: &[u8],
    installed_sequence: u64,
    signed: SignedReleaseMetadata,
    binary: &[u8],
    engine: &crate::provider::Engine,
) -> Result<(), String> {
    check_with_provider(
        chain_id,
        key_id,
        trust,
        installed_sequence,
        signed,
        binary,
        Some(engine.clone()),
    )
}

fn check_with_provider(
    chain_id: u64,
    key_id: &KeyId,
    trust: &[u8],
    installed_sequence: u64,
    signed: SignedReleaseMetadata,
    binary: &[u8],
    engine: Option<crate::provider::Engine>,
) -> Result<(), String> {
    let verifier = crate::provider::verifier(policy(), engine).map_err(|e| e.to_string())?;
    verify_release(
        &verifier,
        chain_id,
        installed_sequence,
        key_id,
        trust,
        signed,
        binary,
    )
    .map(|_| ())
    .map_err(|e| format!("release verification refused: {e:?}"))
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub fn sign(
    metadata: &Path,
    binary: &Path,
    chain_id: u64,
    key_id: KeyId,
    secret: &Path,
    public: &Path,
    output: &Path,
    engine: &crate::provider::Engine,
) -> Result<(), String> {
    sign_with_provider(
        metadata,
        binary,
        chain_id,
        key_id,
        secret,
        public,
        output,
        Some(engine.clone()),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn sign_with_provider(
    metadata: &Path,
    binary: &Path,
    chain_id: u64,
    key_id: KeyId,
    secret: &Path,
    public: &Path,
    output: &Path,
    engine: Option<crate::provider::Engine>,
) -> Result<(), String> {
    let bytes = read_bounded(metadata, MAX_METADATA_BYTES, "unsigned release metadata")?;
    let release: ReleaseMetadata =
        serde_json::from_slice(&bytes).map_err(|e| format!("decode release metadata: {e}"))?;
    release.validate().map_err(str::to_string)?;
    let binary = artifact(binary, &release)?;
    let trust = read_bounded(public, MAX_KEY_BYTES, "pinned release public key")?;
    let permissions =
        fs::symlink_metadata(secret).map_err(|e| format!("inspect release secret: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if permissions.permissions().mode() & 0o077 != 0 {
            return Err("release signing secret must be accessible only to its owner".into());
        }
    }
    let signer = crate::provider::signer(
        policy(),
        key_id.clone(),
        &trust,
        read_bounded(secret, MAX_KEY_BYTES, "release signing secret")?,
        engine.clone(),
    )
    .map_err(|e| e.to_string())?;
    let signature = signer
        .sign(
            &key_id,
            &SigningContext {
                domain: "synergy.software.release.v2".into(),
                chain_id,
                epoch: None,
                height: None,
            },
            &release.signing_bytes(chain_id).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
    let signed = SignedReleaseMetadata {
        release,
        signature,
        public_key: trust.clone(),
    };
    check_with_provider(
        chain_id,
        &key_id,
        &trust,
        0,
        signed.clone(),
        &binary,
        engine,
    )?;
    write_public_json(output, &signed)
}

#[cfg(test)]
pub fn verify(
    metadata: &Path,
    binary: &Path,
    chain_id: u64,
    key_id: KeyId,
    trust: &Path,
    installed_sequence: u64,
    engine: &crate::provider::Engine,
) -> Result<(), String> {
    verify_with_provider(
        metadata,
        binary,
        chain_id,
        key_id,
        trust,
        installed_sequence,
        Some(engine.clone()),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn verify_with_provider(
    metadata: &Path,
    binary: &Path,
    chain_id: u64,
    key_id: KeyId,
    trust: &Path,
    installed_sequence: u64,
    engine: Option<crate::provider::Engine>,
) -> Result<(), String> {
    let bytes = read_bounded(metadata, MAX_METADATA_BYTES, "signed release metadata")?;
    let signed: SignedReleaseMetadata = serde_json::from_slice(&bytes)
        .map_err(|e| format!("decode signed release metadata: {e}"))?;
    let binary = artifact(binary, &signed.release)?;
    let trust = read_bounded(trust, MAX_KEY_BYTES, "pinned release public key")?;
    check_with_provider(
        chain_id,
        &key_id,
        &trust,
        installed_sequence,
        signed,
        &binary,
        engine,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::{Digest, Sha3_256};
    use synergy_address_engine::types::Algorithm;

    fn fixture() -> (ReleaseMetadata, Vec<u8>) {
        let mut binary = vec![0; 64];
        binary[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        binary[16] = 2;
        binary[18] = 0x3e;
        binary[20] = 1;
        let release = serde_json::from_value(serde_json::json!({
            "format_version": 2, "release_id": "qualification", "version": {"major": 0, "minor": 1, "patch": 0},
            "channel": "candidate", "sequence": 1, "published_at_unix_seconds": 1,
            "artifact": {"platform": PLATFORM, "length": binary.len(),
                "sha3_256": format!("{:x}", Sha3_256::digest(&binary)), "source": "synergy-node"},
            "protocols": [], "config_schema": 1, "database_schema": 1,
            "protocol_activation_commitment": null,
        })).unwrap();
        (release, binary)
    }

    #[test]
    #[ignore = "requires explicitly authenticated immutable APQE native artifacts"]
    fn native_apqe_release_verifier_preserves_exact_signed_metadata_and_rejects_substitution() {
        use synergy_address_engine::{apqe::provider::SignOptions, types::Algorithm};
        let engine = crate::provider::native_test_engine();
        let pair = engine
            .lock()
            .unwrap()
            .generate_keypair(Algorithm::MlDsa65)
            .unwrap();
        let (release, binary) = fixture();
        let key_id = KeyId::new("release-root").unwrap();
        let bytes = engine
            .lock()
            .unwrap()
            .sign(
                Algorithm::MlDsa65,
                pair.private_key.as_bytes(),
                &release.signing_bytes(1266).unwrap(),
                SignOptions::default(),
            )
            .unwrap();
        let signed = SignedReleaseMetadata {
            release,
            signature: synergy_aegis::Signature {
                algorithm: SignatureAlgorithm::MlDsa65,
                key_id: key_id.clone(),
                bytes,
            },
            public_key: pair.public_key.clone(),
        };
        check_with_provider(
            1266,
            &key_id,
            &pair.public_key,
            0,
            signed.clone(),
            &binary,
            Some(engine.clone()),
        )
        .unwrap();
        assert!(check_with_provider(
            1267,
            &key_id,
            &pair.public_key,
            0,
            signed.clone(),
            &binary,
            Some(engine.clone())
        )
        .is_err());
        let mut changed = signed.clone();
        changed.signature.bytes[0] ^= 1;
        assert!(check_with_provider(
            1266,
            &key_id,
            &pair.public_key,
            0,
            changed,
            &binary,
            Some(engine.clone())
        )
        .is_err());
        let mut changed = signed;
        changed.signature.algorithm = SignatureAlgorithm::MlDsa87;
        assert!(check_with_provider(
            1266,
            &key_id,
            &pair.public_key,
            0,
            changed,
            &binary,
            Some(engine)
        )
        .is_err());
    }
    #[test]
    fn real_release_signature_rejects_tamper_wrong_key_chain_domain_and_legacy() {
        let (release, binary) = fixture();
        let key_id = KeyId::new("release-root").unwrap();
        let engine = crate::provider::native_test_engine();
        let pair = engine
            .lock()
            .unwrap()
            .generate_keypair(Algorithm::MlDsa65)
            .unwrap();
        let public = pair.public_key;
        let signer = crate::provider::signer(
            policy(),
            key_id.clone(),
            &public,
            pair.private_key.as_bytes().to_vec(),
            Some(engine.clone()),
        )
        .unwrap();
        let context = SigningContext {
            domain: "synergy.software.release.v2".into(),
            chain_id: 1266,
            epoch: None,
            height: None,
        };
        let signature = signer
            .sign(&key_id, &context, &release.signing_bytes(1266).unwrap())
            .unwrap();
        let signed = SignedReleaseMetadata {
            release,
            signature,
            public_key: public.as_slice().to_vec(),
        };
        assert!(check(
            1266,
            &key_id,
            public.as_slice(),
            0,
            signed.clone(),
            &binary,
            &engine
        )
        .is_ok());
        assert!(check(
            1267,
            &key_id,
            public.as_slice(),
            0,
            signed.clone(),
            &binary,
            &engine
        )
        .is_err());
        assert!(check(
            1266,
            &key_id,
            public.as_slice(),
            1,
            signed.clone(),
            &binary,
            &engine
        )
        .is_err());
        let wrong_key = engine
            .lock()
            .unwrap()
            .generate_keypair(Algorithm::MlDsa65)
            .unwrap()
            .public_key;
        assert!(check(
            1266,
            &key_id,
            wrong_key.as_slice(),
            0,
            signed.clone(),
            &binary,
            &engine
        )
        .is_err());
        let mut changed = signed.clone();
        changed.release.release_id.push('x');
        assert!(check(
            1266,
            &key_id,
            public.as_slice(),
            0,
            changed,
            &binary,
            &engine
        )
        .is_err());
        let mut changed_binary = binary.clone();
        changed_binary[63] = 1;
        assert!(check(
            1266,
            &key_id,
            public.as_slice(),
            0,
            signed.clone(),
            &changed_binary,
            &engine
        )
        .is_err());
        let mut wrong_domain = signed.clone();
        let transcript = serde_json::to_vec(&("another.domain", 1266u64, &signed.release)).unwrap();
        wrong_domain.signature = signer.sign(&key_id, &context, &transcript).unwrap();
        assert!(check(
            1266,
            &key_id,
            public.as_slice(),
            0,
            wrong_domain,
            &binary,
            &engine
        )
        .is_err());
        let mut legacy = signed;
        legacy.release.format_version = 1;
        legacy.signature = signer
            .sign(
                &key_id,
                &context,
                &serde_json::to_vec(&legacy.release).unwrap(),
            )
            .unwrap();
        assert!(check(
            1266,
            &key_id,
            public.as_slice(),
            0,
            legacy,
            &binary,
            &engine
        )
        .is_err());
    }

    #[test]
    fn release_files_are_verified_before_create_new_output() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "synergy-release-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(directory.clone());
        let (release, binary) = fixture();
        let metadata = directory.join("unsigned.json");
        let binary_path = directory.join("synergy-node");
        let public_path = directory.join("trust.key");
        let secret_path = directory.join("secret.key");
        let output = directory.join("release-metadata.json");
        let engine = crate::provider::native_test_engine();
        let pair = engine
            .lock()
            .unwrap()
            .generate_keypair(Algorithm::MlDsa65)
            .unwrap();
        let public = pair.public_key;
        fs::write(&metadata, serde_json::to_vec(&release).unwrap()).unwrap();
        fs::write(&binary_path, &binary).unwrap();
        fs::write(&public_path, public.as_slice()).unwrap();
        fs::write(&secret_path, pair.private_key.as_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(sign(
                &metadata,
                &binary_path,
                1266,
                KeyId::new("root").unwrap(),
                &secret_path,
                &public_path,
                &output,
                &engine
            )
            .is_err());
            assert!(!output.exists());
            fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let key = KeyId::new("root").unwrap();
        sign(
            &metadata,
            &binary_path,
            1266,
            key.clone(),
            &secret_path,
            &public_path,
            &output,
            &engine,
        )
        .unwrap();
        verify(
            &output,
            &binary_path,
            1266,
            key.clone(),
            &public_path,
            0,
            &engine,
        )
        .unwrap();
        let signed_bytes = fs::read(&output).unwrap();
        assert!(sign(
            &metadata,
            &binary_path,
            1266,
            key.clone(),
            &secret_path,
            &public_path,
            &output,
            &engine
        )
        .is_err());
        assert_eq!(fs::read(&output).unwrap(), signed_bytes);
        let mut wrong_architecture = binary;
        wrong_architecture[18] = 0xb7;
        fs::write(&binary_path, wrong_architecture).unwrap();
        assert!(verify(&output, &binary_path, 1266, key, &public_path, 0, &engine).is_err());
        fs::remove_dir_all(directory).unwrap();
    }
}
