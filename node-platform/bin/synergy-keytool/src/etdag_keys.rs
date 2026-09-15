use std::path::Path;

use aegis_pqvm::pqc::kem::mlkem::mlkem768;
use pqrust_traits::kem::{PublicKey as _, SecretKey as _};
use synergy_aegis::{KeyId, KeyPurpose, KeyRecord, KeyState};

use crate::aegis_keys::{valid_consensus_node_address, write_bundle, KeyMetadata, WrittenBundle};

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
