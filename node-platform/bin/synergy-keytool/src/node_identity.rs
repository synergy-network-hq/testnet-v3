use std::path::{Path, PathBuf};

use aegis_pqvm::pqc::{
    kem::mlkem::{mlkem1024, mlkem768},
    signatures::{fndsa::fndsa1024, mldsa::mldsa65},
};
use pqrust_traits::sign::{PublicKey as _, SecretKey as _};
use synergy_aegis::{KeyId, KeyPurpose, KeyRecord, KeyState};
use synergy_identity::{NodeAddress, NodeClass, PublicNodeIdentity};

use crate::aegis_keys::{
    fingerprint, read_bounded, write_bundle, write_public_json, KeyMetadata, WrittenBundle,
};

const MAX_IDENTITY_PUBLIC_JSON_BYTES: u64 = 64 * 1024;
const FRESH_ROOT_SCHEMA: &str = "synergy-validator-identity-root-v1";

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FreshValidatorIdentityRoot {
    schema_version: String,
    binary_encoding: String,
    address: String,
    public_key: String,
    algorithm: String,
    address_type: String,
    key_id: String,
    network_id: String,
}

impl FreshValidatorIdentityRoot {
    fn public_key(&self) -> Result<Vec<u8>, String> {
        if self.schema_version != FRESH_ROOT_SCHEMA
            || self.binary_encoding != "lowercase-hex"
            || self.algorithm != "FN-DSA-1024"
            || self.address_type != "NodeClass1"
            || self.network_id.trim().is_empty()
            || self.network_id.len() > 128
        {
            return Err("invalid fresh validator identity root metadata".into());
        }
        KeyId::new(self.key_id.clone()).map_err(|error| error.to_string())?;
        let root = decode_root_hex(&self.public_key)?;
        if self.address != synergy_address::derive_key_controlled_address("synv1", &root)? {
            return Err("fresh validator identity differs from its FN-DSA root".into());
        }
        Ok(root)
    }
}

fn decode_root_hex(value: &str) -> Result<Vec<u8>, String> {
    if value.len() != synergy_address::FN_DSA_1024_PUBLIC_KEY_BYTES * 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("identity root must contain exactly 1793 bytes of lowercase hex".into());
    }
    Ok(value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
            digit(pair[0]) * 16 + digit(pair[1])
        })
        .collect())
}

fn private_directory(path: &Path) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("inspect custody directory: {error}"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("custody directory must be an existing non-symlink directory".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o700 {
            return Err("validator identity-root custody directory must have mode 0700".into());
        }
    }
    Ok(())
}

fn private_secret(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("inspect private custody: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let parent = path
            .parent()
            .ok_or("private custody requires an explicit directory")?;
        let directory = std::fs::symlink_metadata(parent)
            .map_err(|error| format!("inspect custody owner: {error}"))?;
        if directory.file_type().is_symlink()
            || !directory.is_dir()
            || metadata.permissions().mode() & 0o777 != 0o600
            || metadata.uid() != directory.uid()
        {
            return Err("private custody must have mode 0600 and its directory owner".into());
        }
    }
    crate::aegis_keys::read_bounded(path, crate::aegis_keys::MAX_KEY_BYTES, "private custody")
}

fn verify_root_pair(public: &FreshValidatorIdentityRoot, secret: &[u8]) -> Result<(), String> {
    let root = public.public_key()?;
    let public_key =
        fndsa1024::PublicKey::from_bytes(&root).map_err(|_| "invalid FN-DSA public key")?;
    let secret_key =
        fndsa1024::SecretKey::from_bytes(secret).map_err(|_| "invalid FN-DSA private key")?;
    let mut challenge = b"SYNERGY_VALIDATOR_CUSTODY_POSSESSION_V1".to_vec();
    challenge.extend(serde_json::to_vec(public).map_err(|error| error.to_string())?);
    let signature = fndsa1024::detached_sign(&challenge, &secret_key);
    fndsa1024::verify_detached_signature(&signature, &challenge, &public_key)
        .map_err(|_| "FN-DSA validator identity-root possession verification failed".into())
}

/// Generates fresh address-root custody only; operational role keys remain separate.
pub fn generate_validator_root(
    key_id: KeyId,
    network_id: &str,
    directory: &Path,
) -> Result<String, String> {
    private_directory(directory)?;
    if network_id.trim().is_empty() || network_id.len() > 128 {
        return Err("explicit bounded new network incarnation required".into());
    }
    let stem = crate::aegis_keys::file_stem(&key_id);
    let secret_path = directory.join(format!("{stem}.secret.key"));
    let public_path = directory.join(format!("{stem}.identity-root.json"));
    for path in [&secret_path, &public_path] {
        if std::fs::symlink_metadata(path).is_ok() {
            return Err("refusing to overwrite validator identity-root custody".into());
        }
    }
    let (public_key, secret_key) = fndsa1024::keypair();
    let root = FreshValidatorIdentityRoot {
        schema_version: FRESH_ROOT_SCHEMA.into(),
        binary_encoding: "lowercase-hex".into(),
        address: synergy_address::derive_key_controlled_address("synv1", public_key.as_bytes())?,
        public_key: public_key
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        algorithm: "FN-DSA-1024".into(),
        address_type: "NodeClass1".into(),
        key_id: key_id.as_str().into(),
        network_id: network_id.into(),
    };
    let mut secret = secret_key.as_bytes().to_vec();
    let result = (|| {
        verify_root_pair(&root, &secret)?;
        crate::aegis_keys::write_new(&secret_path, &secret, true)?;
        if let Err(error) = write_public_json(&public_path, &root) {
            let _ = std::fs::remove_file(&secret_path);
            return Err(error);
        }
        // Verify the persisted bytes, rather than relying on the generator's pair.
        if let Err(error) = verify_validator_root(&public_path, &secret_path, network_id) {
            let _ = std::fs::remove_file(&public_path);
            let _ = std::fs::remove_file(&secret_path);
            return Err(error);
        }
        Ok(root.address)
    })();
    crate::aegis_keys::wipe(&mut secret);
    result
}

pub fn verify_validator_root(
    public_path: &Path,
    secret_path: &Path,
    network_id: &str,
) -> Result<(), String> {
    private_directory(
        secret_path
            .parent()
            .ok_or("identity-root custody directory absent")?,
    )?;
    let bytes = read_bounded(
        public_path,
        MAX_IDENTITY_PUBLIC_JSON_BYTES,
        "fresh validator identity root",
    )?;
    let root: FreshValidatorIdentityRoot =
        serde_json::from_slice(&bytes).map_err(|error| format!("decode identity root: {error}"))?;
    if root.network_id != network_id {
        return Err("identity root belongs to another network incarnation".into());
    }
    let mut secret = private_secret(secret_path)?;
    let result = verify_root_pair(&root, &secret);
    crate::aegis_keys::wipe(&mut secret);
    result
}

/// Verifies exact public role metadata and native private-key possession.
pub fn verify_key_pair(
    metadata_path: &Path,
    public_path: &Path,
    secret_path: &Path,
    address: &str,
    key_id: &KeyId,
) -> Result<(), String> {
    use pqrust_traits::kem::{PublicKey as _, SecretKey as _, SharedSecret as _};
    let metadata = crate::aegis_keys::read_metadata(metadata_path)?;
    let public = read_bounded(
        public_path,
        crate::aegis_keys::MAX_KEY_BYTES,
        "role public key",
    )?;
    if metadata.node_address.as_str() != address
        || &metadata.record.id != key_id
        || metadata.record.public_key != public
    {
        return Err("role public metadata differs from the intended validator binding".into());
    }
    let mut secret = private_secret(secret_path)?;
    let result = (|| match (metadata.record.purpose, metadata.algorithm.as_str()) {
        (KeyPurpose::PosyConsensus | KeyPurpose::P2pIdentity, "ML-DSA-65") => {
            let public_key =
                mldsa65::PublicKey::from_bytes(&public).map_err(|_| "invalid ML-DSA public key")?;
            let secret_key = mldsa65::SecretKey::from_bytes(&secret)
                .map_err(|_| "invalid ML-DSA private key")?;
            let mut challenge = b"SYNERGY_VALIDATOR_ROLE_CUSTODY_POSSESSION_V1".to_vec();
            challenge.extend(serde_json::to_vec(&metadata).map_err(|error| error.to_string())?);
            let signature = mldsa65::detached_sign(&challenge, &secret_key);
            mldsa65::verify_detached_signature(&signature, &challenge, &public_key)
                .map_err(|_| "ML-DSA role custody possession verification failed".to_string())
        }
        (KeyPurpose::EtdagDecryption, "ML-KEM-1024") => {
            let public_key = mlkem1024::PublicKey::from_bytes(&public)
                .map_err(|_| "invalid ML-KEM public key")?;
            let secret_key = mlkem1024::SecretKey::from_bytes(&secret)
                .map_err(|_| "invalid ML-KEM private key")?;
            let (expected, ciphertext) = mlkem1024::encapsulate(&public_key);
            if mlkem1024::decapsulate(&ciphertext, &secret_key).as_bytes() != expected.as_bytes() {
                return Err("ML-KEM role custody possession verification failed".into());
            }
            Ok(())
        }
        (KeyPurpose::EtdagDecryption, "ML-KEM-768") => {
            let public_key = mlkem768::PublicKey::from_bytes(&public)
                .map_err(|_| "invalid ML-KEM public key")?;
            let secret_key = mlkem768::SecretKey::from_bytes(&secret)
                .map_err(|_| "invalid ML-KEM private key")?;
            let (expected, ciphertext) = mlkem768::encapsulate(&public_key);
            if mlkem768::decapsulate(&ciphertext, &secret_key).as_bytes() != expected.as_bytes() {
                return Err("ML-KEM role custody possession verification failed".into());
            }
            Ok(())
        }
        _ => Err("unsupported validator role custody purpose".into()),
    })();
    crate::aegis_keys::wipe(&mut secret);
    result
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPublicIdentityRoot {
    schema_version: String,
    binary_encoding: String,
    address: String,
    public_key: String,
    algorithm: String,
    address_type: String,
    #[serde(rename = "created_at")]
    _created_at: String,
    #[serde(rename = "consensus_key")]
    _consensus_key: CanonicalPublicKey,
    #[serde(rename = "node_identity_key")]
    _node_identity_key: CanonicalNodePublicKey,
    #[serde(rename = "account_key")]
    _account_key: CanonicalPublicKey,
    #[serde(rename = "entropy_contribution_key")]
    _entropy_contribution_key: CanonicalPublicKey,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPublicKey {
    #[serde(rename = "algorithm")]
    _algorithm: String,
    #[serde(rename = "public_key")]
    _public_key: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CanonicalNodePublicKey {
    #[serde(rename = "algorithm")]
    _algorithm: String,
    #[serde(rename = "public_key")]
    _public_key: String,
    #[serde(rename = "peer_id")]
    _peer_id: String,
}

/// Reads only an existing public root; never emits a plaintext root copy.
pub(crate) fn load_identity_root_public_key(
    path: &Path,
    class: NodeClass,
) -> Result<Vec<u8>, String> {
    let bytes = read_bounded(
        path,
        MAX_IDENTITY_PUBLIC_JSON_BYTES,
        "FN-DSA-1024 identity root public source",
    )?;
    if bytes.len() == synergy_address::FN_DSA_1024_PUBLIC_KEY_BYTES {
        return Ok(bytes);
    }
    let schema: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("decode identity-root public JSON: {error}"))?;
    if schema
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
        == Some(FRESH_ROOT_SCHEMA)
    {
        if class != NodeClass::ConsensusAndChainIntegrity {
            return Err("fresh validator identity root cannot authorize another node class".into());
        }
        let root: FreshValidatorIdentityRoot = serde_json::from_value(schema)
            .map_err(|error| format!("decode fresh validator identity root: {error}"))?;
        return root.public_key();
    }
    let source: CanonicalPublicIdentityRoot = serde_json::from_slice(&bytes)
        .map_err(|e| format!("decode canonical public identity root: {e}"))?;
    if source.schema_version != "synergy-validator-public-identity-v3"
        || source.binary_encoding != "lowercase-hex"
        || source.algorithm != "FN-DSA-1024"
        || source.address_type != format!("NodeClass{}", class.digit())
    {
        return Err(
            "public identity root schema, encoding, algorithm or class is incompatible".into(),
        );
    }
    if source.public_key.len() != synergy_address::FN_DSA_1024_PUBLIC_KEY_BYTES * 2
        || !source
            .public_key
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(
            "public identity root must contain exactly 1793 bytes of canonical lowercase hex"
                .into(),
        );
    }
    let root = source
        .public_key
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
            digit(pair[0]) * 16 + digit(pair[1])
        })
        .collect::<Vec<_>>();
    let derived =
        synergy_address::derive_key_controlled_address(&format!("synv{}", class.digit()), &root)?;
    if source.address != derived {
        return Err("claimed public identity address differs from its FN-DSA root".into());
    }
    Ok(root)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrittenNodeIdentity {
    pub bundle: WrittenBundle,
    pub identity_path: PathBuf,
    pub node_address: NodeAddress,
}

pub fn generate(
    key_id: KeyId,
    identity_root_public_key: &Path,
    output_directory: &Path,
    validator: bool,
) -> Result<WrittenNodeIdentity, String> {
    let node_class = if validator {
        NodeClass::ConsensusAndChainIntegrity
    } else {
        NodeClass::ServiceAndAccess
    };
    // The FN-DSA identity root remains under separate encrypted custody. An
    // operational P2P key must not silently invent or change the node address.
    let root = load_identity_root_public_key(identity_root_public_key, node_class)?;
    let derived = synergy_address::derive_key_controlled_address(
        &format!("synv{}", node_class.digit()),
        &root,
    )?;
    let node_address = NodeAddress::parse(derived)
        .map_err(|error| format!("derive canonical node address: {error}"))?;
    let stem = crate::aegis_keys::file_stem(&key_id);
    let identity_path = output_directory.join(format!("{stem}.identity.json"));
    if identity_path.exists() {
        return Err(format!("refusing to overwrite {}", identity_path.display()));
    }
    let (public_key, secret_key) = mldsa65::keypair();
    let public_key = public_key.as_bytes().to_vec();
    let mut secret_key = secret_key.as_bytes().to_vec();
    let public_fingerprint = fingerprint(&public_key);
    let identity = PublicNodeIdentity::new(node_address.clone(), public_fingerprint)
        .validate()
        .map_err(|error| format!("validate generated node identity: {error}"))?;
    let metadata = KeyMetadata::new(
        node_address.clone(),
        KeyRecord {
            id: key_id,
            purpose: KeyPurpose::P2pIdentity,
            state: KeyState::Generated,
            public_key: public_key.clone(),
        },
        "ML-DSA-65",
    )?;
    let bundle = write_bundle(output_directory, &metadata, &public_key, &mut secret_key)?;
    if let Err(error) = write_public_json(&identity_path, &identity) {
        for path in [
            &bundle.secret_key_path,
            &bundle.public_key_path,
            &bundle.metadata_path,
        ] {
            let _ = std::fs::remove_file(path);
        }
        return Err(error);
    }
    Ok(WrittenNodeIdentity {
        bundle,
        identity_path,
        node_address,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn private_test_directory(label: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("synergy-keytool-{label}-{}", std::process::id()));
        fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        path
    }

    #[test]
    fn fresh_validator_root_proves_persisted_possession_and_rejects_other_incarnations() {
        let directory = private_test_directory("fresh-validator-root");
        let address =
            generate_validator_root(KeyId::new("root").unwrap(), "fresh-network", &directory)
                .unwrap();
        let public = directory.join("root.identity-root.json");
        let secret = directory.join("root.secret.key");
        let original = fs::read(&secret).unwrap();
        assert_eq!(
            load_identity_root_public_key(&public, NodeClass::ConsensusAndChainIntegrity)
                .unwrap()
                .len(),
            1793
        );
        verify_validator_root(&public, &secret, "fresh-network").unwrap();
        assert!(verify_validator_root(&public, &secret, "retired-network").is_err());
        assert!(load_identity_root_public_key(&public, NodeClass::ServiceAndAccess).is_err());
        assert!(
            generate_validator_root(KeyId::new("root").unwrap(), "fresh-network", &directory)
                .is_err()
        );
        assert_eq!(fs::read(&secret).unwrap(), original);
        let operational = generate(KeyId::new("p2p").unwrap(), &public, &directory, true).unwrap();
        assert_eq!(operational.node_address.as_str(), address);
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&public).unwrap()).unwrap();
        value["address"] = serde_json::json!(synergy_address::derive_key_controlled_address(
            "synv1",
            &vec![43; 1793]
        )
        .unwrap());
        fs::write(&public, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(verify_validator_root(&public, &secret, "fresh-network").is_err());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn native_role_possession_rejects_mismatched_private_keys_and_public_bindings() {
        let directory = private_test_directory("native-role-possession");
        let root = directory.join("root.public.key");
        fs::write(&root, vec![42; 1793]).unwrap();
        let p2p = generate(KeyId::new("p2p").unwrap(), &root, &directory, true).unwrap();
        let address = p2p.node_address.as_str();
        let consensus = crate::consensus_keys::generate(
            address.into(),
            KeyId::new("consensus").unwrap(),
            &directory,
        )
        .unwrap();
        let ingress = crate::etdag_keys::generate_1024(
            address.into(),
            KeyId::new("ingress").unwrap(),
            &directory,
        )
        .unwrap();
        for (bundle, id) in [
            (&p2p.bundle, "p2p"),
            (&consensus, "consensus"),
            (&ingress, "ingress"),
        ] {
            verify_key_pair(
                &bundle.metadata_path,
                &bundle.public_key_path,
                &bundle.secret_key_path,
                address,
                &KeyId::new(id).unwrap(),
            )
            .unwrap();
            assert!(verify_key_pair(
                &bundle.metadata_path,
                &bundle.public_key_path,
                &bundle.secret_key_path,
                address,
                &KeyId::new("wrong-id").unwrap()
            )
            .is_err());
        }
        assert!(verify_key_pair(
            &consensus.metadata_path,
            &consensus.public_key_path,
            &p2p.bundle.secret_key_path,
            address,
            &KeyId::new("consensus").unwrap()
        )
        .is_err());
        let other = crate::etdag_keys::generate_1024(
            address.into(),
            KeyId::new("other-ingress").unwrap(),
            &directory,
        )
        .unwrap();
        assert!(verify_key_pair(
            &ingress.metadata_path,
            &ingress.public_key_path,
            &other.secret_key_path,
            address,
            &KeyId::new("ingress").unwrap()
        )
        .is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                &consensus.secret_key_path,
                fs::Permissions::from_mode(0o640),
            )
            .unwrap();
            assert!(verify_key_pair(
                &consensus.metadata_path,
                &consensus.public_key_path,
                &consensus.secret_key_path,
                address,
                &KeyId::new("consensus").unwrap()
            )
            .is_err());
        }
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn fresh_root_refuses_public_directory_and_symlink_outputs_before_key_generation() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let directory = private_test_directory("fresh-root-path-guards");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(generate_validator_root(KeyId::new("root").unwrap(), "fresh", &directory).is_err());
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 0);
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        symlink(directory.join("absent"), directory.join("root.secret.key")).unwrap();
        assert!(generate_validator_root(KeyId::new("root").unwrap(), "fresh", &directory).is_err());
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn generated_p2p_key_preserves_the_canonical_identity_root_address() {
        let directory =
            std::env::temp_dir().join(format!("synergy-keytool-root-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let root = vec![42; synergy_address::FN_DSA_1024_PUBLIC_KEY_BYTES];
        let root_path = directory.join("root.public.key");
        fs::write(&root_path, &root).unwrap();
        let result = generate(KeyId::new("p2p").unwrap(), &root_path, &directory, true).unwrap();
        let expected = synergy_address::derive_key_controlled_address("synv1", &root).unwrap();
        assert_eq!(result.node_address.as_str(), expected);
        let public =
            mldsa65::PublicKey::from_bytes(&fs::read(&result.bundle.public_key_path).unwrap())
                .unwrap();
        let secret =
            mldsa65::SecretKey::from_bytes(&fs::read(&result.bundle.secret_key_path).unwrap())
                .unwrap();
        let challenge = b"synergy-keytool-custody-correspondence-test";
        let signature = mldsa65::detached_sign(challenge, &secret);
        assert!(mldsa65::verify_detached_signature(&signature, challenge, &public).is_ok());
        let original = fs::read(&result.bundle.secret_key_path).unwrap();
        assert!(generate(KeyId::new("p2p").unwrap(), &root_path, &directory, true).is_err());
        assert_eq!(fs::read(&result.bundle.secret_key_path).unwrap(), original);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&result.bundle.secret_key_path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o077,
                0
            );
        }
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn invalid_identity_root_is_rejected_before_writing_a_bundle() {
        let directory = std::env::temp_dir().join(format!(
            "synergy-keytool-invalid-root-{}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        let root_path = directory.join("root.public.key");
        fs::write(&root_path, [42; 32]).unwrap();
        assert!(generate(KeyId::new("p2p").unwrap(), &root_path, &directory, true).is_err());
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
        fs::remove_dir_all(directory).unwrap();
    }
    fn canonical_public_fixture(root: &[u8]) -> serde_json::Value {
        let key = serde_json::json!({"algorithm":"fixture-public", "public_key":"00"});
        serde_json::json!({
            "schema_version":"synergy-validator-public-identity-v3", "binary_encoding":"lowercase-hex",
            "algorithm":"FN-DSA-1024", "address_type":"NodeClass1", "created_at":"fixture",
            "address":synergy_address::derive_key_controlled_address("synv1", root).unwrap(),
            "public_key":root.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "consensus_key":key.clone(), "account_key":key.clone(), "entropy_contribution_key":key,
            "node_identity_key":{"algorithm":"fixture-public", "public_key":"00", "peer_id":"fixture"}
        })
    }

    #[test]
    fn canonical_public_json_loads_same_root_and_rejects_forged_claims_without_writes() {
        let directory = std::env::temp_dir().join(format!(
            "synergy-keytool-public-loader-{}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("identity.pub.json");
        let root = vec![42; synergy_address::FN_DSA_1024_PUBLIC_KEY_BYTES];
        let canonical = canonical_public_fixture(&root);
        let bytes = serde_json::to_vec(&canonical).unwrap();
        fs::write(&path, &bytes).unwrap();
        assert_eq!(
            load_identity_root_public_key(&path, NodeClass::ConsensusAndChainIntegrity).unwrap(),
            root
        );
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
        for (field, value) in [
            (
                "address",
                serde_json::json!(synergy_address::derive_key_controlled_address(
                    "synv1",
                    &vec![43; 1793]
                )
                .unwrap()),
            ),
            ("algorithm", serde_json::json!("ML-DSA-65")),
            ("binary_encoding", serde_json::json!("hex")),
            ("schema_version", serde_json::json!("unknown")),
            ("public_key", serde_json::json!("2A".repeat(1793))),
            ("public_key", serde_json::json!("2g".repeat(1793))),
            ("public_key", serde_json::json!("2a".repeat(1792))),
        ] {
            let mut invalid = canonical.clone();
            invalid[field] = value;
            let invalid_bytes = serde_json::to_vec(&invalid).unwrap();
            fs::write(&path, &invalid_bytes).unwrap();
            assert!(
                load_identity_root_public_key(&path, NodeClass::ConsensusAndChainIntegrity)
                    .is_err(),
                "field {field}"
            );
            assert_eq!(fs::read(&path).unwrap(), invalid_bytes);
            assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
        }
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn canonical_public_source_and_existing_output_are_never_overwritten() {
        let directory = std::env::temp_dir().join(format!(
            "synergy-keytool-public-nooverwrite-{}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("identity.pub.json");
        let bytes = serde_json::to_vec(&canonical_public_fixture(&vec![42; 1793])).unwrap();
        fs::write(&path, &bytes).unwrap();
        let output = directory.join("p2p.identity.json");
        fs::write(&output, b"existing canonical output").unwrap();
        assert!(generate(KeyId::new("p2p").unwrap(), &path, &directory, true).is_err());
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(fs::read(&output).unwrap(), b"existing canonical output");
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 2);
        fs::remove_dir_all(directory).unwrap();
    }
}
