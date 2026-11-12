use std::path::Path;

#[cfg(test)]
use aegis_pqvm::pqc::signatures::mldsa::mldsa65;
#[cfg(test)]
use pqrust_traits::sign::{PublicKey as _, SecretKey as _};
use synergy_aegis::{KeyId, KeyPurpose, KeyRecord, KeyState};

use crate::aegis_keys::{valid_consensus_node_address, write_bundle, KeyMetadata, WrittenBundle};

#[cfg(test)]
pub fn generate(
    node_address: String,
    key_id: KeyId,
    output_directory: &Path,
) -> Result<WrittenBundle, String> {
    if !valid_consensus_node_address(&node_address) {
        return Err("consensus key requires a canonical synv1 validator identity".into());
    }
    let (public_key, secret_key) = mldsa65::keypair();
    let public_key = public_key.as_bytes().to_vec();
    let mut secret_key = secret_key.as_bytes().to_vec();
    let metadata = KeyMetadata::new(
        synergy_identity::NodeAddress::parse(node_address)
            .map_err(|error| format!("invalid canonical node address: {error}"))?,
        KeyRecord {
            id: key_id,
            purpose: KeyPurpose::PosyConsensus,
            state: KeyState::Generated,
            public_key: public_key.clone(),
        },
        "ML-DSA-65",
    )?;
    write_bundle(output_directory, &metadata, &public_key, &mut secret_key)
}

pub fn generate_with_provider(
    node_address: String,
    key_id: KeyId,
    output_directory: &Path,
    engine: crate::provider::Engine,
) -> Result<WrittenBundle, String> {
    if !valid_consensus_node_address(&node_address) {
        return Err("consensus key requires a canonical synv1 validator identity".into());
    }
    let pair = engine
        .lock()
        .map_err(|_| "APQE provider poisoned")?
        .generate_keypair(synergy_address_engine::types::Algorithm::MlDsa65)
        .map_err(|e| e.to_string())?;
    let metadata = KeyMetadata::new(
        synergy_identity::NodeAddress::parse(node_address).map_err(|e| e.to_string())?,
        KeyRecord {
            id: key_id,
            purpose: KeyPurpose::PosyConsensus,
            state: KeyState::Generated,
            public_key: pair.public_key.clone(),
        },
        "ML-DSA-65",
    )?;
    let mut secret = pair.private_key.as_bytes().to_vec();
    let result = write_bundle(output_directory, &metadata, &pair.public_key, &mut secret);
    crate::aegis_keys::wipe(&mut secret);
    result
}
