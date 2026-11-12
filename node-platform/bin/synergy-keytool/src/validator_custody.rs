//! Noninteractive, host-local APQE validator enrollment request. The caller
//! must authenticate the Genesis artifact independently before using its digest.
//! This operation does not admit a validator or create consensus state.
use std::path::Path;

#[cfg(not(unix))]
pub use provision as verify;

#[cfg(unix)]
pub(crate) fn runtime_identity(
    request: &synergy_address_engine::validator_provisioning::EnrollmentRequest,
) -> Result<synergy_identity::PublicNodeIdentity, String> {
    use synergy_address_engine::{snts07::decode_lower_hex, types::Algorithm};
    use synergy_identity::{NodeAddress, PublicNodeIdentity};

    let identity = &request.payload.identity;
    let algorithm = Algorithm::MlDsa65;
    if identity.node_identity_key.algorithm != algorithm.display_name() {
        return Err("Unexpected validator transport key profile".into());
    }
    let key = decode_lower_hex(
        "validator transport public key",
        &identity.node_identity_key.public_key,
        1952,
    )?;
    let address = NodeAddress::parse(identity.address.clone()).map_err(|e| e.to_string())?;
    PublicNodeIdentity::new(address, crate::aegis_keys::fingerprint(&key))
        .validate()
        .map_err(|e| e.to_string())
}

#[cfg(not(unix))]
pub fn provision(
    _: &str,
    _: &str,
    _: &Path,
    _: crate::provider::Engine,
) -> Result<serde_json::Value, String> {
    Err("Managed validator custody requires private Unix storage".into())
}

#[cfg(unix)]
pub fn provision(
    chain: &str,
    genesis: &str,
    directory: &Path,
    engine: crate::provider::Engine,
) -> Result<serde_json::Value, String> {
    use std::{
        fs::{self, DirBuilder, File, OpenOptions},
        io::Write,
        os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    };
    use synergy_address_engine::{
        apqe::{Primitives, SecretBytes},
        types::AddressType,
        validator_provisioning::{self, NetworkBinding},
    };
    let binding = || NetworkBinding {
        chain_id_hex: chain.into(),
        genesis_sha256: genesis.into(),
    };
    binding().validate()?;
    let parent = directory
        .parent()
        .ok_or("Private custody parent required")?;
    let metadata = fs::symlink_metadata(parent).map_err(|_| "Private custody parent is absent")?;
    if !directory.is_absolute()
        || parent.canonicalize().ok().as_deref() != Some(parent)
        || !directory
            .file_name()
            .is_some_and(|name| parent.join(name) == directory)
        || !metadata.is_dir()
        || metadata.mode() & 0o777 != 0o700
        || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err("Custody requires a direct path inside an owned mode-0700 directory".into());
    }
    // An interrupted operation retains its directory and refuses replay, even
    // if only some of its files reached durable storage.
    DirBuilder::new()
        .mode(0o700)
        .create(directory)
        .map_err(|_| "Fresh custody path unavailable; inspect existing state before retrying")?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| "Cannot make custody intent durable")?;
    let mut entropy = vec![0; 32];
    let random = Primitives.random_bytes(&mut entropy);
    let entropy = SecretBytes::from_bytes(entropy);
    random.map_err(|_| "APQE secure randomness unavailable")?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let unlock = SecretBytes::from_bytes(
        entropy
            .as_bytes()
            .iter()
            .flat_map(|byte| [HEX[(byte >> 4) as usize], HEX[(byte & 15) as usize]])
            .collect(),
    );
    let pass = std::str::from_utf8(unlock.as_bytes()).map_err(|_| "APQE unlock encoding failed")?;
    let engine = engine.lock().map_err(|_| "APQE provider unavailable")?;
    let (request, encrypted) =
        validator_provisioning::provision(&engine, AddressType::NodeClass1, binding(), pass)?;
    validator_provisioning::verify_enrollment(&engine, &request, &binding())?;
    validator_provisioning::verify_custody(&engine, &request, &binding(), &encrypted, pass)?;
    validator_provisioning::write_new_bundle(&directory.join("bundle"), &request, &encrypted)?;
    let mut public_file = OpenOptions::new()
        .mode(0o600)
        .create_new(true)
        .write(true)
        .open(directory.join("node-identity.json"))
        .map_err(|_| "Cannot create the host-local public identity file")?;
    serde_json::to_writer(&mut public_file, &runtime_identity(&request)?)
        .map_err(|_| "Cannot write the host-local public identity file")?;
    public_file
        .sync_all()
        .map_err(|_| "Cannot persist host-local public identity")?;
    let mut file = OpenOptions::new()
        .mode(0o600)
        .create_new(true)
        .write(true)
        .open(directory.join("unlock"))
        .map_err(|_| "Cannot create the host-local unlock file")?;
    if file
        .metadata()
        .map_err(|_| "Cannot inspect unlock file")?
        .mode()
        & 0o777
        != 0o600
    {
        return Err("Private unlock permissions unavailable".into());
    }
    file.write_all(unlock.as_bytes())
        .and_then(|_| file.sync_all())
        .and_then(|_| File::open(directory)?.sync_all())
        .map_err(|_| "Custody synchronization failed; inspect state before retrying")?;
    Ok(serde_json::json!({
        "address": request.payload.identity.address,
        "genesis_sha256": genesis,
        "chain_id_hex": chain,
        "possession_verified": true,
        "membership_granted": false
    }))
}

/// Reconcile an interrupted response without writing or generating any keys.
#[cfg(unix)]
pub fn verify(
    chain: &str,
    genesis: &str,
    directory: &Path,
    engine: crate::provider::Engine,
) -> Result<serde_json::Value, String> {
    verify_artifact(chain, genesis, directory, engine).map(|(result, _, _)| result)
}

#[cfg(unix)]
pub(crate) fn verify_artifact(
    chain: &str,
    genesis: &str,
    directory: &Path,
    engine: crate::provider::Engine,
) -> Result<
    (
        serde_json::Value,
        synergy_address_engine::validator_provisioning::EnrollmentRequest,
        synergy_address_engine::apqe::SecretBytes,
    ),
    String,
> {
    use std::{
        fs::{self, OpenOptions},
        io::Read,
        os::unix::fs::{MetadataExt, OpenOptionsExt},
    };
    use synergy_address_engine::{
        apqe::SecretBytes,
        validator_provisioning::{self, EnrollmentRequest, NetworkBinding},
    };
    let expected = NetworkBinding {
        chain_id_hex: chain.into(),
        genesis_sha256: genesis.into(),
    };
    expected.validate()?;
    let owner = unsafe { libc::geteuid() };
    for path in [directory, &directory.join("bundle")] {
        let metadata = fs::symlink_metadata(path).map_err(|_| "Incomplete custody directory")?;
        if !path.is_absolute()
            || path.canonicalize().ok().as_deref() != Some(path)
            || !metadata.is_dir()
            || metadata.mode() & 0o777 != 0o700
            || metadata.uid() != owner
        {
            return Err("Unsafe private custody directory".into());
        }
    }
    let read = |name: &str, max: u64| -> Result<SecretBytes, String> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(directory.join(name))
            .map_err(|_| "Incomplete custody file")?;
        let metadata = file.metadata().map_err(|_| "Cannot inspect custody file")?;
        if !metadata.is_file()
            || metadata.uid() != owner
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
            || metadata.len() == 0
            || metadata.len() > max
        {
            return Err("Unsafe private custody file".into());
        }
        let mut data = vec![0; metadata.len() as usize];
        let mut file = file.take(max + 1);
        let result = file.read_exact(&mut data);
        let data = SecretBytes::from_bytes(data);
        result.map_err(|_| "Cannot read complete custody file")?;
        if file
            .read(&mut [0u8; 1])
            .map_err(|_| "Cannot inspect custody file size")?
            != 0
        {
            return Err("Custody file changed during verification".into());
        }
        Ok(data)
    };
    let unlock = read("unlock", 64)?;
    let pass = std::str::from_utf8(unlock.as_bytes()).map_err(|_| "Invalid custody unlock")?;
    if pass.len() != 64
        || !pass
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("Invalid custody unlock".into());
    }
    let request_raw = read("bundle/enrollment-request.json", 256 * 1024)?;
    let request: EnrollmentRequest =
        serde_json::from_slice(request_raw.as_bytes()).map_err(|_| "Invalid enrollment request")?;
    let envelope =
        serde_json::from_slice(read("bundle/validator.enc.json", 256 * 1024)?.as_bytes())
            .map_err(|_| "Invalid encrypted custody")?;
    let public: serde_json::Value =
        serde_json::from_slice(read("bundle/validator.pub.json", 256 * 1024)?.as_bytes())
            .map_err(|_| "Invalid public custody identity")?;
    if public != serde_json::to_value(&request.payload.identity).map_err(|_| "Invalid identity")? {
        return Err("Public custody identity differs from enrollment request".into());
    }
    let engine = engine.lock().map_err(|_| "APQE provider unavailable")?;
    validator_provisioning::verify_custody(&engine, &request, &expected, &envelope, pass)?;
    let runtime: synergy_identity::PublicNodeIdentity =
        serde_json::from_slice(read("node-identity.json", 4096)?.as_bytes())
            .map_err(|_| "Invalid runtime public identity")?;
    if runtime != runtime_identity(&request)? {
        return Err("Runtime public identity differs from verified custody".into());
    }
    let result = serde_json::json!({
        "address": request.payload.identity.address,
        "genesis_sha256": genesis,
        "chain_id_hex": chain,
        "possession_verified": true,
        "membership_granted": false
    });
    Ok((result, request, request_raw))
}

#[cfg(all(unix, test))]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{DirBuilderExt, MetadataExt},
    };

    #[test]
    #[ignore = "requires the independently authenticated native APQE engineering provider"]
    fn generates_private_network_bound_custody_and_refuses_replay() {
        use synergy_address_engine::validator_provisioning::{
            verify_enrollment, EnrollmentRequest, NetworkBinding,
        };
        let dir = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("nodenetwork-custody-{}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(dir.clone());
        let destination = dir.join("pending");
        let engine = crate::provider::native_test_engine();
        let chain = format!("{:064x}", 999999);
        let genesis = "ab".repeat(32);
        let result = provision(&chain, &genesis, &destination, engine.clone()).unwrap();
        assert!(result["address"].as_str().unwrap().starts_with("synv1"));
        assert_eq!(result["membership_granted"], false);
        assert_eq!(result["possession_verified"], true);
        let unlock = destination.join("unlock");
        assert_eq!(fs::metadata(&unlock).unwrap().mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(&unlock).unwrap().len(), 64);
        let encrypted = destination.join("bundle/validator.enc.json");
        let original = fs::read(&encrypted).unwrap();
        assert_eq!(
            verify(&chain, &genesis, &destination, engine.clone()).unwrap(),
            result
        );
        assert!(verify(&chain, &"cd".repeat(32), &destination, engine.clone()).is_err());
        assert!(provision(&chain, &genesis, &destination, engine.clone()).is_err());
        assert_eq!(original, fs::read(encrypted).unwrap());
        let runtime = destination.join("node-identity.json");
        let public = fs::read(&runtime).unwrap();
        let mut tampered: serde_json::Value = serde_json::from_slice(&public).unwrap();
        tampered["public_key_fingerprint"] = "a".repeat(64).into();
        fs::write(&runtime, serde_json::to_vec(&tampered).unwrap()).unwrap();
        assert!(verify(&chain, &genesis, &destination, engine.clone()).is_err());
        fs::write(&runtime, public).unwrap();
        let request: EnrollmentRequest = serde_json::from_slice(
            &fs::read(destination.join("bundle/enrollment-request.json")).unwrap(),
        )
        .unwrap();
        assert!(verify_enrollment(
            &engine.lock().unwrap(),
            &request,
            &NetworkBinding {
                chain_id_hex: chain,
                genesis_sha256: "cd".repeat(32),
            }
        )
        .is_err());
        fs::remove_file(&unlock).unwrap();
        assert!(verify(
            &request.payload.network.chain_id_hex,
            &genesis,
            &destination,
            engine
        )
        .is_err());
    }
}
