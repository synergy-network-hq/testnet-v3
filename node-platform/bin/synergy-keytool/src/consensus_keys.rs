use std::path::Path;

use aegis_pqvm::pqc::signatures::mldsa::mldsa65;
use pqrust_traits::sign::{PublicKey as _, SecretKey as _};
use synergy_aegis::{KeyId, KeyPurpose, KeyRecord, KeyState};

use crate::aegis_keys::{valid_consensus_node_address, write_bundle, KeyMetadata, WrittenBundle};

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
