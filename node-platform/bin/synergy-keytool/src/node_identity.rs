use std::path::{Path, PathBuf};

use aegis_pqvm::pqc::signatures::mldsa::mldsa65;
use pqrust_traits::sign::{PublicKey as _, SecretKey as _};
use synergy_aegis::{KeyId, KeyPurpose, KeyRecord, KeyState};
use synergy_identity::{NodeAddress, NodeClass, PublicNodeIdentity};

use crate::aegis_keys::{fingerprint, write_bundle, write_public_json, KeyMetadata, WrittenBundle};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrittenNodeIdentity {
    pub bundle: WrittenBundle,
    pub identity_path: PathBuf,
    pub node_address: NodeAddress,
}

pub fn generate(
    key_id: KeyId,
    output_directory: &Path,
    validator: bool,
) -> Result<WrittenNodeIdentity, String> {
    let (public_key, secret_key) = mldsa65::keypair();
    let public_key = public_key.as_bytes().to_vec();
    let mut secret_key = secret_key.as_bytes().to_vec();
    let public_fingerprint = fingerprint(&public_key);
    let node_class = if validator {
        NodeClass::ConsensusAndChainIntegrity
    } else {
        NodeClass::ServiceAndAccess
    };
    let node_address = NodeAddress::parse(format!(
        "synv{}{}",
        node_class.digit(),
        &public_fingerprint[..40]
    ))
    .map_err(|error| format!("derive canonical node address: {error}"))?;
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
    let stem = crate::aegis_keys::file_stem(&metadata.record.id);
    let identity_path = output_directory.join(format!("{stem}.identity.json"));
    if identity_path.exists() {
        return Err(format!("refusing to overwrite {}", identity_path.display()));
    }
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
