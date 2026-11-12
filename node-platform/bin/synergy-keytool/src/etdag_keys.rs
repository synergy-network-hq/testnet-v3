use std::path::Path;

#[cfg(test)]
use aegis_pqvm::pqc::kem::mlkem::mlkem1024;
use aegis_pqvm::pqc::kem::mlkem::mlkem768;
use pqrust_traits::kem::{PublicKey as _, SecretKey as _};
use synergy_aegis::{KeyId, KeyPurpose, KeyRecord, KeyState};

use crate::aegis_keys::{valid_consensus_node_address, write_bundle, KeyMetadata, WrittenBundle};

/// Historical ML-KEM-768 generation remains explicit for legacy consumers.
pub fn generate(
    node_address: String,
    key_id: KeyId,
    output_directory: &Path,
) -> Result<WrittenBundle, String> {
    if !valid_consensus_node_address(&node_address) {
        return Err("ETDAG key requires a canonical synv1 validator identity".into());
    }
    let (public_key, secret_key) = mlkem768::keypair();
    let public_key = public_key.as_bytes().to_vec();
    let mut secret_key = secret_key.as_bytes().to_vec();
    let metadata = KeyMetadata::new(
        synergy_identity::NodeAddress::parse(node_address)
            .map_err(|error| format!("invalid canonical node address: {error}"))?,
        KeyRecord {
            id: key_id,
            purpose: KeyPurpose::EtdagDecryption,
            state: KeyState::Generated,
            public_key: public_key.clone(),
        },
        "ML-KEM-768",
    )?;
    write_bundle(output_directory, &metadata, &public_key, &mut secret_key)
}

/// Generates the governed ML-KEM-1024 ingress key without replacing existing custody.
#[cfg(test)]
pub fn generate_1024(
    node_address: String,
    key_id: KeyId,
    output_directory: &Path,
) -> Result<WrittenBundle, String> {
    if !valid_consensus_node_address(&node_address) {
        return Err("ETDAG key requires a canonical synv1 validator identity".into());
    }
    let address = synergy_identity::NodeAddress::parse(node_address)
        .map_err(|error| format!("invalid canonical node address: {error}"))?;
    let (public_key, secret_key) = mlkem1024::keypair();
    let public_key = public_key.as_bytes().to_vec();
    let mut secret_key = secret_key.as_bytes().to_vec();
    let result = (|| {
        let metadata = KeyMetadata::new(
            address,
            KeyRecord {
                id: key_id,
                purpose: KeyPurpose::EtdagDecryption,
                state: KeyState::Generated,
                public_key: public_key.clone(),
            },
            "ML-KEM-1024",
        )?;
        write_bundle(output_directory, &metadata, &public_key, &mut secret_key)
    })();
    crate::aegis_keys::wipe(&mut secret_key);
    result
}

pub fn generate_1024_with_provider(
    node_address: String,
    key_id: KeyId,
    output_directory: &Path,
    engine: crate::provider::Engine,
) -> Result<WrittenBundle, String> {
    if !valid_consensus_node_address(&node_address) {
        return Err("ingress key requires a canonical synv1 validator identity".into());
    }
    let pair = engine
        .lock()
        .map_err(|_| "APQE provider poisoned")?
        .generate_keypair(synergy_address_engine::types::Algorithm::MlKem1024)
        .map_err(|e| e.to_string())?;
    let metadata = KeyMetadata::new(
        synergy_identity::NodeAddress::parse(node_address).map_err(|e| e.to_string())?,
        KeyRecord {
            id: key_id,
            purpose: KeyPurpose::EtdagDecryption,
            state: KeyState::Generated,
            public_key: pair.public_key.clone(),
        },
        "ML-KEM-1024",
    )?;
    let mut secret = pair.private_key.as_bytes().to_vec();
    let result = write_bundle(output_directory, &metadata, &pair.public_key, &mut secret);
    crate::aegis_keys::wipe(&mut secret);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aegis_keys::{fingerprint, read_metadata};
    use pqrust_traits::kem::SharedSecret as _;
    use std::fs;

    fn validator_address() -> String {
        synergy_address::derive_key_controlled_address(
            "synv1",
            &vec![42; synergy_address::FN_DSA_1024_PUBLIC_KEY_BYTES],
        )
        .unwrap()
    }

    #[test]
    fn governed_1024_bundle_proves_possession_and_preserves_existing_custody() {
        let directory =
            std::env::temp_dir().join(format!("synergy-keytool-etdag1024-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let address = validator_address();
        let key_id = KeyId::new("ingress-1024").unwrap();
        let bundle = generate_1024(address.clone(), key_id.clone(), &directory).unwrap();
        let metadata = read_metadata(&bundle.metadata_path).unwrap();
        assert_eq!(metadata.algorithm, "ML-KEM-1024");
        assert_eq!(metadata.node_address.as_str(), address);
        assert_eq!(metadata.record.purpose, KeyPurpose::EtdagDecryption);
        let original = fs::read(&bundle.secret_key_path).unwrap();
        assert_eq!(original.len(), mlkem1024::secret_key_bytes());
        let public_bytes = fs::read(&bundle.public_key_path).unwrap();
        assert_eq!(public_bytes.len(), mlkem1024::public_key_bytes());
        let public = mlkem1024::PublicKey::from_bytes(&public_bytes).unwrap();
        let secret = mlkem1024::SecretKey::from_bytes(&original).unwrap();
        let (expected, ciphertext) = mlkem1024::encapsulate(&public);
        assert_eq!(
            mlkem1024::decapsulate(&ciphertext, &secret).as_bytes(),
            expected.as_bytes()
        );
        assert!(generate_1024(address, key_id, &directory).is_err());
        assert_eq!(fs::read(&bundle.secret_key_path).unwrap(), original);
        assert_eq!(fs::read(&bundle.public_key_path).unwrap(), public_bytes);
        assert_eq!(read_metadata(&bundle.metadata_path).unwrap(), metadata);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&bundle.secret_key_path)
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
    fn ingress_metadata_rejects_algorithm_and_length_mismatches() {
        let address = synergy_identity::NodeAddress::parse(validator_address()).unwrap();
        for (algorithm, length) in [
            ("ML-KEM-768", mlkem768::public_key_bytes()),
            ("ML-KEM-1024", mlkem1024::public_key_bytes()),
        ] {
            let result = KeyMetadata::new(
                address.clone(),
                KeyRecord {
                    id: KeyId::new("ingress").unwrap(),
                    purpose: KeyPurpose::EtdagDecryption,
                    state: KeyState::Generated,
                    public_key: vec![42; length],
                },
                algorithm,
            );
            if algorithm == "ML-KEM-768" {
                assert!(result.is_err());
                continue;
            }
            let mut metadata = result.unwrap();
            metadata.algorithm = if algorithm == "ML-KEM-768" {
                "ML-KEM-1024"
            } else {
                "ML-KEM-768"
            }
            .into();
            assert!(metadata.validate().is_err());
            metadata.algorithm = algorithm.into();
            metadata.record.public_key.pop();
            metadata.public_key_fingerprint = fingerprint(&metadata.record.public_key);
            assert!(metadata.validate().is_err());
            metadata.algorithm = "ML-KEM-512".into();
            assert!(metadata.validate().is_err());
        }
    }
}
